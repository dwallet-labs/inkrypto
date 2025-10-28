// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::Odd;
use crypto_primes::Flavor;
use subtle::{Choice, CtOption};

use group::{CsRng, GroupElement};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};

use crate::{
    encryption_key::PublicParameters, CiphertextSpaceGroupElement, EncryptionKey,
    LargeBiPrimeSizedNumber, LargePrimeSizedNumber, PaillierModulusSizedNumber,
    PlaintextSpaceGroupElement, PlaintextSpacePublicParameters, PLAINTEXT_SPACE_SCALAR_LIMBS,
};

/// A paillier decryption key.
/// Holds both the `secret_key` and its corresponding `encryption_key`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKey {
    pub encryption_key: EncryptionKey,
    pub secret_key: PaillierModulusSizedNumber,
}

impl DecryptionKey {
    /// Generates a new Paillier Key Pair.
    pub fn generate_keypair(
        rng: &mut impl CsRng,
    ) -> crate::Result<(PublicParameters, DecryptionKey)> {
        let p: LargePrimeSizedNumber = crypto_primes::random_prime(rng, Flavor::Safe, 1024);
        let q: LargePrimeSizedNumber = crypto_primes::random_prime(rng, Flavor::Safe, 1024);

        let n: LargeBiPrimeSizedNumber = p.concatenating_mul(&q);
        // phi = (p-1)(q-1)
        let phi: LargeBiPrimeSizedNumber = (p.wrapping_sub(&LargePrimeSizedNumber::ONE))
            .concatenating_mul(&(q.wrapping_sub(&LargePrimeSizedNumber::ONE)));
        // With safe primes this can never fail since we have gcd(pq,4p'q') where p,q,p',q' are all
        // odd primes. So the only option is that p'=q or q'=p. 2p+1 has 1025 bits.
        let phi_inv = phi.invert_odd_mod(&Odd::new(n).unwrap()).unwrap();
        let secret_key = phi.widening_mul(&phi_inv);
        let public_parameters = PublicParameters::new(n)?;
        let encryption_key = PaillierModulusSizedNumber::from(secret_key);

        let decryption_key = Self::new(encryption_key, &public_parameters)?;

        Ok((public_parameters, decryption_key))
    }
}

impl AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>
    for DecryptionKey
{
    type SecretKey = PaillierModulusSizedNumber;

    /// Create a `DecryptionKey` from a previously generated `secret_key` and its corresponding
    /// `encryption_key`. Performs no validations.
    fn new(
        secret_key: Self::SecretKey,
        public_parameters: &PublicParameters,
    ) -> homomorphic_encryption::Result<Self> {
        let encryption_key = EncryptionKey::new(public_parameters)?;

        Ok(DecryptionKey {
            encryption_key,
            secret_key,
        })
    }

    fn generate(
        _plaintext_space_public_parameters: PlaintextSpacePublicParameters,
        rng: &mut impl CsRng,
    ) -> homomorphic_encryption::Result<Self> {
        let (_, decryption_key) = Self::generate_keypair(rng)
            .map_err(|_| homomorphic_encryption::Error::InternalError)?;

        Ok(decryption_key)
    }

    fn decrypt(
        &self,
        ciphertext: &CiphertextSpaceGroupElement,
        public_parameters: &PublicParameters,
    ) -> CtOption<PlaintextSpaceGroupElement> {
        let n = *public_parameters
            .plaintext_space_public_parameters()
            .modulus
            .resize()
            .as_nz_ref();

        // $D(c,d)=\left(\frac{(c^{d}\mod(N^{2}))-1}{N}\right)\mod(N)$
        let plaintext: PaillierModulusSizedNumber =
            (crate::PaillierModulusSizedNumber::from(ciphertext.scale(&self.secret_key))
                .wrapping_sub(&PaillierModulusSizedNumber::ONE)
                / n)
                % n;

        CtOption::new(
            PlaintextSpaceGroupElement::new(
                (&plaintext).into(),
                public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap(),
            Choice::from(1u8),
        )
    }
}

impl AsRef<EncryptionKey> for DecryptionKey {
    fn as_ref(&self) -> &EncryptionKey {
        &self.encryption_key
    }
}

#[cfg(test)]
mod tests {

    use group::{secp256k1, GroupElement, OsCsRng};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
    };

    use crate::{
        encryption_key::PublicParameters,
        test_helpers::{CIPHERTEXT, N, PLAINTEXT, SECRET_KEY},
        CiphertextSpaceGroupElement, CiphertextSpaceValue, LargeBiPrimeSizedNumber,
        PlaintextSpaceGroupElement,
    };

    use super::*;

    #[test]
    fn decrypts() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let decryption_key = DecryptionKey::new(SECRET_KEY, &public_parameters).unwrap();

        let plaintext = PlaintextSpaceGroupElement::new(
            PLAINTEXT,
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                CIPHERTEXT,
                public_parameters.ciphertext_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        assert_eq!(
            decryption_key
                .decrypt(&ciphertext, &public_parameters)
                .unwrap(),
            plaintext
        );

        let plaintext = PlaintextSpaceGroupElement::new(
            LargeBiPrimeSizedNumber::from(42u8),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, ciphertext) = decryption_key
            .encryption_key
            .encrypt(&plaintext, &public_parameters, false, &mut OsCsRng)
            .unwrap();

        assert_eq!(
            decryption_key
                .decrypt(&ciphertext, &public_parameters)
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn encrypt_decrypts() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let decryption_key = DecryptionKey::new(SECRET_KEY, &public_parameters).unwrap();

        homomorphic_encryption::test_helpers::encrypt_decrypts(
            decryption_key,
            &public_parameters,
            &mut OsCsRng,
        );
    }

    #[test]
    fn evaluates() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let decryption_key = DecryptionKey::new(SECRET_KEY, &public_parameters).unwrap();

        homomorphic_encryption::test_helpers::evaluates::<
            { secp256k1::SCALAR_LIMBS },
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            secp256k1::Scalar,
            EncryptionKey,
            DecryptionKey,
        >(
            decryption_key,
            &secp256k1::scalar::PublicParameters::default(),
            &public_parameters,
            &mut OsCsRng,
        );
    }

    #[test]
    fn generated_key_encrypts_decrypts() {
        let rng = &mut OsCsRng;
        let (public_parameters, decryption_key) = DecryptionKey::generate_keypair(rng).unwrap();

        let plaintext = PlaintextSpaceGroupElement::new(
            LargeBiPrimeSizedNumber::from(42u8),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, ciphertext) = decryption_key
            .encryption_key
            .encrypt(&plaintext, &public_parameters, false, rng)
            .unwrap();

        assert_eq!(
            decryption_key
                .decrypt(&ciphertext, &public_parameters)
                .unwrap(),
            plaintext
        );
    }
}
