// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::{
    error::SanityCheckError,
    group::{CiphertextSpaceGroupElement, PlaintextSpaceGroupElement, RandomnessSpaceGroupElement},
    CiphertextSpacePublicParameters, CiphertextSpaceValue, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber, PlaintextSpacePublicParameters, RandomnessSpacePublicParameters,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
};
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{CheckedAdd, CheckedMul, NonZero, Odd, RandomMod, Uint};
use group::{GroupElement, KnownOrderGroupElement, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{
    AdditivelyHomomorphicEncryptionKey, Error, GroupsPublicParametersAccessors,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::BitAnd;
use subtle::{Choice, ConstantTimeLess};

/// A Paillier public encryption key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionKey;

impl AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS> for EncryptionKey {
    type PlaintextSpaceGroupElement = PlaintextSpaceGroupElement;
    type RandomnessSpaceGroupElement = RandomnessSpaceGroupElement;
    type CiphertextSpaceGroupElement = CiphertextSpaceGroupElement;
    type PublicParameters = PublicParameters;

    /// Create a new `EncryptionKey` Object.
    /// Parameter `public_parameters` is here for legacy reasons.
    fn new(_public_parameters: &Self::PublicParameters) -> homomorphic_encryption::Result<Self> {
        // Public Parameters are passed during each encryption operation.
        Ok(EncryptionKey {})
    }

    fn encrypt_with_randomness(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &PublicParameters,
    ) -> Self::CiphertextSpaceGroupElement {
        // Validity checks are performed in public parameter instantiation, given correct public
        // parameters Paillier encryption is a bijection and thus always succeeds, so `.unwrap()`s

        // are safe here $ c1 = (m*N + 1) * $
        let ciphertext_first_part = plaintext
            .value()
            .widening_mul(
                &*public_parameters
                    .plaintext_space_public_parameters()
                    .modulus,
            )
            .wrapping_add(&PaillierModulusSizedNumber::ONE);
        let ciphertext_first_part = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                ciphertext_first_part,
                public_parameters.ciphertext_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        // $ c2 = (r^N) $
        let randomness = CiphertextSpaceGroupElement::new(
            CiphertextSpaceValue::new(
                (&LargeBiPrimeSizedNumber::from(randomness)).into(),
                public_parameters.ciphertext_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.ciphertext_space_public_parameters(),
        )
        .unwrap();

        let ciphertext_second_part = randomness.scale(
            &public_parameters
                .plaintext_space_public_parameters()
                .modulus,
        );

        // $ c = c1 * c2 = (m*N + 1) * (r^N) mod N^2 $ [Note that the equation is translated into
        // additive notation, to work with the group traits]
        ciphertext_first_part + ciphertext_second_part
    }

    fn sample_mask_for_secure_function_evaluation<
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
    >(
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        ciphertexts_and_encoded_messages_upper_bounds: &[(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> homomorphic_encryption::Result<Self::PlaintextSpaceGroupElement> {
        if MESSAGE_LIMBS != PLAINTEXT_SPACE_SCALAR_LIMBS {
            return Err(Error::SecureFunctionEvaluation);
        }

        // First, verify that each coefficient $a_i$ is smaller than the modulus $q$.
        // This is required for circuit privacy, particularly it ensures `mask` will statistically hide the coefficients.
        if !bool::from(
            coefficients
                .iter()
                .fold(Choice::from(1u8), |choice, coefficient| {
                    choice.bitand(
                        Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(coefficient).ct_lt(modulus),
                    )
                }),
        ) {
            return Err(Error::SecureFunctionEvaluation);
        }

        let upper_bounds_sum = ciphertexts_and_encoded_messages_upper_bounds
            .iter()
            .map(|(_, upper_bound)| Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(upper_bound))
            .try_fold(
                Uint::ZERO,
                |sum, upper_bound| -> Option<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>> {
                    sum.checked_add(&upper_bound).into()
                },
            )
            .ok_or(Error::SecureFunctionEvaluation)?;

        let mask_upper_bound = upper_bounds_sum.checked_mul(
            &(Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::ONE << StatisticalSecuritySizedNumber::BITS),
        );

        let mask_upper_bound = Option::<NonZero<_>>::from(mask_upper_bound.and_then(NonZero::new))
            .ok_or(Error::SecureFunctionEvaluation)?;

        let mask = Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::random_mod(rng, &mask_upper_bound);

        Ok(Self::PlaintextSpaceGroupElement::new(
            mask,
            public_parameters.plaintext_space_public_parameters(),
        )?)
    }

    fn securely_evaluate_linear_combination_with_randomness<
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
    >(
        &self,
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        ciphertexts_and_encoded_messages_upper_bounds: [(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        mask: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
    ) -> homomorphic_encryption::Result<Self::CiphertextSpaceGroupElement> {
        if DIMENSION == 0 {
            return Err(Error::ZeroDimension);
        }

        if MESSAGE_LIMBS != PLAINTEXT_SPACE_SCALAR_LIMBS {
            return Err(Error::SecureFunctionEvaluation);
        }

        let plaintext_order: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            PlaintextSpaceGroupElement::order_from_public_parameters(
                public_parameters.plaintext_space_public_parameters(),
            );

        let ciphertexts =
            ciphertexts_and_encoded_messages_upper_bounds.map(|(ciphertext, _)| ciphertext);

        // Now verify that the secure evaluation upper bound $\textsf{pt}_{\sf eval}$ is smaller than the
        // plaintext modulus $N$.
        // This is done first by multiplying each of the coefficients by the corresponding upper
        // bound:
        let evaluation_upper_bound: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            ciphertexts_and_encoded_messages_upper_bounds
                .iter()
                .map(|(_, upper_bound)| Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(upper_bound))
                .zip(coefficients.iter())
                .map(|(upper_bound, coefficient)| upper_bound.checked_mul(coefficient))
                .reduce(|a, b| a.and_then(|a| b.and_then(|b| a.checked_add(&b))))
                .and_then(|evaluation_upper_bound| evaluation_upper_bound.into())
                .ok_or(Error::SecureFunctionEvaluation)?;

        // And then adding the mask by modulus $ \omega q $, to result with the secure
        // evaluation upper bound $\textsf{pt}_{\sf eval}$:
        let secure_evaluation_upper_bound = Option::<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>::from(
            mask.value()
                .checked_mul(modulus)
                .and_then(|mask_by_modulus| evaluation_upper_bound.checked_add(&mask_by_modulus)),
        )
        .ok_or(Error::SecureFunctionEvaluation)?;

        // And finally, checking that it is smaller than the plaintext order
        // $ $\textsf{pt}_{\sf eval}$ < N $:
        if secure_evaluation_upper_bound >= plaintext_order {
            return Err(Error::SecureFunctionEvaluation);
        }

        let modulus =
            Self::PlaintextSpaceGroupElement::new(modulus.into(), &mask.public_parameters())?;

        let linear_combination = Self::evaluate_linear_combination(coefficients, &ciphertexts)?;

        // Re-randomize and add a masked multiplication of the modulus to the evaluated ciphertext.
        let encryption_with_fresh_randomness =
            self.encrypt_with_randomness(&(modulus * mask), randomness, public_parameters);

        Ok(linear_combination + encryption_with_fresh_randomness)
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PublicParameters(
    homomorphic_encryption::GroupsPublicParameters<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    >,
);

impl PublicParameters {
    pub fn new(paillier_associate_bi_prime: LargeBiPrimeSizedNumber) -> crate::Result<Self> {
        let paillier_associate_bi_prime_modulus: Odd<LargeBiPrimeSizedNumber> =
            Option::from(Odd::new(paillier_associate_bi_prime)).ok_or(
                crate::Error::SanityCheckError(SanityCheckError::InvalidParameters),
            )?;

        Ok(Self(homomorphic_encryption::GroupsPublicParameters {
            plaintext_space_public_parameters: PlaintextSpacePublicParameters::from(
                paillier_associate_bi_prime_modulus,
            ),
            randomness_space_public_parameters: RandomnessSpacePublicParameters::new(
                paillier_associate_bi_prime,
            )?,
            ciphertext_space_public_parameters: CiphertextSpacePublicParameters::new(
                paillier_associate_bi_prime.square(),
            )?,
        }))
    }
}

impl Serialize for PublicParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.plaintext_space_public_parameters()
            .modulus
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let paillier_associate_bi_prime = LargeBiPrimeSizedNumber::deserialize(deserializer)?;

        PublicParameters::new(paillier_associate_bi_prime)
            .map_err(|_| serde::de::Error::custom("invalid paillier associate bi-prime"))
    }
}

impl
    AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
        >,
    > for PublicParameters
{
    fn as_ref(
        &self,
    ) -> &homomorphic_encryption::GroupsPublicParameters<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    > {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        test_helpers::{CIPHERTEXT, N, PLAINTEXT, RANDOMNESS},
        RandomnessSpaceValue,
    };

    use super::*;

    #[test]
    fn encrypts() {
        let public_parameters = PublicParameters::new(N).unwrap();
        let encryption_key = EncryptionKey::new(&public_parameters).unwrap();

        let plaintext = PlaintextSpaceGroupElement::new(
            PLAINTEXT,
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let randomness = RandomnessSpaceGroupElement::new(
            RandomnessSpaceValue::new(
                RANDOMNESS,
                public_parameters.randomness_space_public_parameters(),
            )
            .unwrap(),
            public_parameters.randomness_space_public_parameters(),
        )
        .unwrap();

        assert_eq!(
            PaillierModulusSizedNumber::from(encryption_key.encrypt_with_randomness(
                &plaintext,
                &randomness,
                &public_parameters,
            )),
            CIPHERTEXT
        )
    }
}
