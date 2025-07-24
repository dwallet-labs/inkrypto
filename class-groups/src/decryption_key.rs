// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;
use std::ops::Neg;

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::subtle::{Choice, CtOption};
use crypto_bigint::{Concat, ConstantTimeSelect, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};
use serde::{Deserialize, Serialize};

use group::{bounded_natural_numbers_group, GroupElement as _, PrimeGroupElement, Samplable};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};

use crate::encryption_key::{Ciphertext, EncryptionKey, Plaintext, PublicParameters};
use crate::equivalence_class::EquivalenceClass;
use crate::helpers::math;
use crate::setup::SetupParameters;
use crate::{equivalence_class, CompactIbqf, Error};

pub type SecretKey<const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize> =
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>;

#[derive(Clone, Debug, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub struct DecryptionKey<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> where
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    pub encryption_key: EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    pub decryption_key: SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    neutral: GroupElement::Scalar,
    _group_choice: PhantomData<GroupElement>,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    DecryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding
        + InvMod<
            Modulus = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
            Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + InvMod<
            Modulus = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + InvMod<
            Modulus = NonZero<Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + InvMod<
            Modulus = NonZero<Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Decrypt a ciphertext `(c1, c2)` using `self` as decryption key.
    ///
    /// To decrypt, one performs the following two steps:
    /// 1. remove randomness: map `(c1, c2) = (h^r, f^m * pk^r)` to `(0, c2 / c1^sk) = (*, f^m)`. Note that `pk = h^sk`.
    /// 2. decode message: map `(*, f^m)` to `m` by computing the discrete log of `f^m`.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 3.
    fn decrypt_internal(
        &self,
        ciphertext: &Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    ) -> Result<Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>, Error> {
        let (c1, c2) = ciphertext;

        // TODO(#46): make const-time; replace pow_vartime by pow_bounded(..., bit_bound);
        // let bit_bound = public_parameters.decryption_key_bits_bound();
        let encoded_message = c2.mul(&c1.pow_vartime(&self.decryption_key).neg())?;

        Self::discrete_log_in_F(&encoded_message, &public_parameters.setup_parameters)
    }

    /// Randomly generate a new decryption key, given the public setup parameters of the
    /// scheme instance.
    #[allow(clippy::type_complexity)]
    pub fn generate(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            <GroupElement::Scalar as group::GroupElement>::PublicParameters,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        (
            PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                <GroupElement::Scalar as group::GroupElement>::PublicParameters,
            >,
            Self,
        ),
        Error,
    > {
        let secret_key = bounded_natural_numbers_group::GroupElement::sample(
            setup_parameters.decryption_key_group_public_parameters(),
            rng,
        )?
        .value();

        let pp = PublicParameters::new_from_secret_key(setup_parameters, secret_key)?;

        let neutral = <EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement::neutral_from_public_parameters(
            pp.plaintext_space_public_parameters()
        )?;

        let encryption_key = EncryptionKey::new(&pp)?;

        Ok((
            pp,
            Self {
                encryption_key,
                decryption_key: secret_key,
                neutral,
                _group_choice: PhantomData,
            },
        ))
    }
}

pub trait DiscreteLogInF<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    #[allow(non_snake_case)]
    /// Given $fm := f^m$ with $f$ the generator of $F$, compute $m := log_f(fm)$.
    fn discrete_log_in_F(
        fm: &EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        setup_parameters: &SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    ) -> Result<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>, Error>;
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    DiscreteLogInF<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
    for DecryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding
        + InvMod<
            Modulus = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
            Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + InvMod<
            Modulus = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + InvMod<
            Modulus = NonZero<Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + InvMod<
            Modulus = NonZero<Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    fn discrete_log_in_F(
        fm: &EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        setup_parameters: &SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    ) -> Result<Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>, Error> {
        let class_group_parameters = &setup_parameters.class_group_parameters;

        let q = class_group_parameters.q;
        let delta_k_ = class_group_parameters
            .delta_k
            .resize::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>();

        let decoding = if setup_parameters.large_message_variant {
            fm.kernel_representative(&q, &delta_k_)?
        } else {
            // safe to unwrap; q is non-zero and resize is an expansion.
            let q_ = q
                .resize::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>()
                .to_nz()
                .unwrap();

            // safe to vartime; the function `factor_mod_vartime` runs in time variable in the size
            // of `q` only; it behaves independently of `b`. Given that `q` is public information,
            // it is safe to use this vartime function here.
            let (u, _) = math::factor_mod_vartime(*fm.representative().b(), &q_);
            if u.abs() > *q_ {
                return Err(Error::InternalError);
            }

            // Move `u` to lie in [0, q)
            let u = math::representative_mod(&u, &q_);

            // Safe to resize; u lies in [0, q)
            let u = u.resize::<PLAINTEXT_SPACE_SCALAR_LIMBS>();

            // TODO(#17): use u.inv_mod(q_exp_k) instead of u.inv_mod(q)
            u.inv_mod(&q).into_option().ok_or(Error::NoModInverse)?
        };

        Ok(Uint::ct_select(&decoding, &Uint::ZERO, fm.is_unit()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DecryptionKeyPublicParameters();

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    AsRef<
        EncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >
    for DecryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > {
        &self.encryption_key
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    AdditivelyHomomorphicDecryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >
    for DecryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding
        + InvMod<
            Modulus = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
            Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + InvMod<
            Modulus = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + InvMod<
            Modulus = NonZero<Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + InvMod<
            Modulus = NonZero<Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    group::PublicParameters<GroupElement::Scalar>: Eq,
{
    type SecretKey = SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>;

    fn new(
        secret_key: Self::SecretKey,
        public_parameters: &<EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PublicParameters,
    ) -> homomorphic_encryption::Result<Self> {
        if !public_parameters.belongs_to_secret_key(&secret_key) {
            return Err(homomorphic_encryption::Error::Group(
                group::Error::InvalidParameters,
            ));
        }

        let neutral = <EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement::neutral_from_public_parameters(
            public_parameters.plaintext_space_public_parameters())?;

        Ok(Self {
            encryption_key: EncryptionKey::new(public_parameters)?,
            decryption_key: secret_key,
            neutral,
            _group_choice: PhantomData,
        })
    }

    fn decrypt(
        &self,
        ciphertext: &<EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::CiphertextSpaceGroupElement,
        public_parameters: &<EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PublicParameters,
    ) -> CtOption<<EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement,
    >{
        let [ct1, ct2]: [EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; 2] =
            (*ciphertext).into();
        let decryption = self.decrypt_internal(&(ct1, ct2), public_parameters);
        let successful_decryption = Choice::from(decryption.is_ok() as u8);

        CtOption::new(
            <EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement::new(
                decryption.unwrap_or(Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::ZERO).into(),
                public_parameters.plaintext_space_public_parameters(),
            ).unwrap_or(self.neutral),
            successful_decryption,
        )
    }
}

#[cfg(test)]
mod tests {
    mod ristretto {
        use crypto_bigint::Uint;
        use rand::rngs::OsRng;

        use group::ristretto;
        use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;

        use crate::test_helpers::get_setup_parameters_ristretto_112_bits_deterministic;
        use crate::{RistrettoDecryptionKey, RistrettoEncryptionKey, RISTRETTO_SCALAR_LIMBS};

        #[test]
        fn test_new_invalid() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, _) = RistrettoDecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

            let wrong_key = Uint::ONE;
            assert!(RistrettoDecryptionKey::new(wrong_key, &pp).is_err());
        }

        #[test]
        fn test_generate() {
            let cp = get_setup_parameters_ristretto_112_bits_deterministic();
            RistrettoDecryptionKey::generate(cp, &mut OsRng).unwrap();
        }

        #[test]
        fn test_encrypt_decrypt() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, decryption_key) =
                RistrettoDecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();
            homomorphic_encryption::test_helpers::encrypt_decrypts(decryption_key, &pp, &mut OsRng);
        }

        #[test]
        fn test_evaluates() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, decryption_key) =
                RistrettoDecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

            homomorphic_encryption::test_helpers::evaluates::<
                RISTRETTO_SCALAR_LIMBS,
                RISTRETTO_SCALAR_LIMBS,
                ristretto::Scalar,
                RistrettoEncryptionKey,
                RistrettoDecryptionKey,
            >(
                decryption_key,
                &ristretto::scalar::PublicParameters::default(),
                &pp,
                &mut OsRng,
            );
        }
    }

    mod secp256k1 {
        use crate::decryption_key::DiscreteLogInF;
        use crypto_bigint::{Uint, U256};
        use group::secp256k1;
        use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;
        use rand_core::OsRng;
        use rstest::rstest;

        use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
        use crate::{Secp256k1DecryptionKey, Secp256k1EncryptionKey, SECP256K1_SCALAR_LIMBS};

        #[test]
        fn test_new_invalid() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, _) = Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

            let wrong_key = Uint::ONE;
            assert!(Secp256k1DecryptionKey::new(wrong_key, &pp).is_err());
        }

        #[test]
        fn test_generate() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();
        }

        #[test]
        fn test_encrypt_decrypt() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, decryption_key) =
                Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

            homomorphic_encryption::test_helpers::encrypt_decrypts(decryption_key, &pp, &mut OsRng);
        }

        #[test]
        fn test_evaluates() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, decryption_key) =
                Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

            homomorphic_encryption::test_helpers::evaluates::<
                SECP256K1_SCALAR_LIMBS,
                SECP256K1_SCALAR_LIMBS,
                secp256k1::Scalar,
                Secp256k1EncryptionKey,
                Secp256k1DecryptionKey,
            >(
                decryption_key,
                &secp256k1::scalar::PublicParameters::default(),
                &pp,
                &mut OsRng,
            );
        }

        #[rstest]
        #[case(U256::ZERO)]
        #[case(U256::ONE)]
        #[case(U256::from(42u32))]
        #[case(U256::from_be_hex(
            "11B04441048A097858486532D29E4C761B1A2628CB362E2DA5035EA9D6781A63"
        ))]
        #[case(U256::from_be_hex(
            "11B04441048A097858486532D29E4C761B1A2628CB362E2DA5035EA9D6781A64"
        ))]
        fn test_encode_decode(#[case] m: U256) {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let class_group_parameters = &setup_parameters.class_group_parameters;
            let encoding = Secp256k1EncryptionKey::encode_plaintext(&m, class_group_parameters);
            let decoding = Secp256k1DecryptionKey::discrete_log_in_F(&encoding, &setup_parameters);

            assert!(decoding.is_ok());
            assert_eq!(decoding.unwrap(), m);
        }
    }

    mod large_message_variant {
        use crate::decryption_key::DiscreteLogInF;
        use crypto_bigint::{impl_modulus, U1536, U2048, U4096, U8192};
        use group::const_additive::{PrimeConstMontyParams, PublicParameters};
        use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;
        use rand_core::OsRng;
        use rstest::rstest;

        use crate::setup::SetupParameters;
        use crate::test_helpers::get_setup_parameters_lmv_112_bits_deterministic;
        use crate::{DecryptionKey, EncryptionKey};

        const M1348_PLAINTEXT_LIMBS: usize = U1536::LIMBS;
        const M1348_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U1536::LIMBS;
        const M1348_HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U2048::LIMBS;
        const M1348_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U4096::LIMBS;
        const M1348_DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U8192::LIMBS;

        // A 1348-bit modulus.
        // Smallest modulus that triggers the large_message_variant that achieves 112-bit security.
        impl_modulus!(
            M1348,
            U1536,
            concat![
                "0000000000000000000000000000000000000000000366A3AA22C61AD3B92F64",
                "16274050E61DA17FD9B990D7E648363D282823380987B898A3003434D4955AEB",
                "957E58DF4762474AFD698EEB1E496D54F312171DFDD97098929E676450E9DB7C",
                "B52FFB54CB3D9325ADC994022984756C8DB36570D1525F2F8F17A9004F8C39C1",
                "811EBBFCAC4105B7BE66C884B3733BE21C3232EC910E8AF605D1E4C8BBF08425",
                "0BB7506EE7D25F5388B351084F4F2A436D6E2FDF376193B69B318ACB6C01758F"
            ]
        );

        impl PrimeConstMontyParams<M1348_PLAINTEXT_LIMBS> for M1348 {}

        type M1348GroupElement = group::const_additive::GroupElement<M1348, M1348_PLAINTEXT_LIMBS>;

        type M1348EncryptionKey = EncryptionKey<
            M1348_PLAINTEXT_LIMBS,
            M1348_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            M1348_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            M1348GroupElement,
        >;

        type M1348DecryptionKey = DecryptionKey<
            M1348_PLAINTEXT_LIMBS,
            M1348_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            M1348_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            M1348GroupElement,
        >;

        fn setup() -> SetupParameters<
            M1348_PLAINTEXT_LIMBS,
            M1348_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            M1348_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            PublicParameters<M1348, M1348_PLAINTEXT_LIMBS>,
        > {
            get_setup_parameters_lmv_112_bits_deterministic::<
                M1348_PLAINTEXT_LIMBS,
                M1348_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                M1348_HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                M1348_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                M1348_DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                M1348,
                M1348GroupElement,
            >()
        }

        #[ignore]
        #[test]
        fn test_generate() {
            let setup_parameters = setup();
            M1348DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();
        }

        #[ignore]
        #[test]
        fn test_new_invalid() {
            let setup_parameters = setup();
            let (pp, _) = M1348DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

            let wrong_key = U1536::ONE;
            assert!(M1348DecryptionKey::new(wrong_key, &pp).is_err());
        }

        #[ignore]
        #[test]
        fn test_encrypt_decrypt() {
            let setup_parameters = setup();
            let (pp, decryption_key) =
                M1348DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();
            homomorphic_encryption::test_helpers::encrypt_decrypts(decryption_key, &pp, &mut OsRng);
        }

        #[ignore]
        #[test]
        fn test_evaluates() {
            let setup_parameters = setup();
            let (pp, decryption_key) =
                M1348DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

            homomorphic_encryption::test_helpers::evaluates::<
                M1348_PLAINTEXT_LIMBS,
                M1348_PLAINTEXT_LIMBS,
                M1348GroupElement,
                M1348EncryptionKey,
                M1348DecryptionKey,
            >(
                decryption_key,
                &PublicParameters::<M1348, M1348_PLAINTEXT_LIMBS>::default(),
                &pp,
                &mut OsRng,
            );
        }

        #[rstest]
        #[ignore]
        #[case(U1536::ZERO)]
        #[ignore]
        #[case(U1536::ONE)]
        #[ignore]
        #[case(U1536::from(42u32))]
        #[ignore]
        #[case(U1536::from_be_hex(concat! [
            "0000000000000000000000000000000000000000000078AC1643738708DF587C",
            "6D5EBCE7989E6723FF81E37266B81AE33EE937C2EDEE33549A0EA96E8C2D379C",
            "0556BE4F348B1EDC8B4A833A54C99B78828EF48A4F5B7A7B2DE77ED42FD6D875",
            "A1DBDF618DBE4BC3BD82215085B36D4651B66CD9B9BC5D2B1BA268BA25597119",
            "0B0F73562DD3D25C97B702642B2A271E5963D33F3F19D285473B8249CFC7199C",
            "286D349C9EEBAB7B954D4C92E126D5E7B94C1832BCAF2CFC22277FBD1320DE79"
            ]))]
        fn test_discrete_log_in_f(#[case] m: U1536) {
            let setup_parameters = setup();
            let encoding =
                M1348EncryptionKey::encode_plaintext(&m, &setup_parameters.class_group_parameters);
            let decoding =
                M1348DecryptionKey::discrete_log_in_F(&encoding, &setup_parameters).unwrap();
            assert_eq!(decoding, m);
        }
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{BenchmarkGroup, Criterion};
    use crypto_bigint::Uint;
    use rand_core::{CryptoRngCore, OsRng};

    use group::GroupElement;
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };

    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };
    use crate::{RistrettoDecryptionKey, Secp256k1DecryptionKey};

    pub fn benchmark_encrypt<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        g: &mut BenchmarkGroup<WallTime>,
        encryption_key: &EncryptionKey,
        public_parameters: &EncryptionKey::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) {
        let plaintext: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            (&Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(42424242424242u128)).into();
        let plaintext: EncryptionKey::PlaintextSpaceGroupElement =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                plaintext.into(),
                public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap();

        g.bench_function("encrypt", |b| {
            b.iter(|| {
                let _ = encryption_key
                    .encrypt(&plaintext, public_parameters, rng)
                    .unwrap();
            })
        });
    }

    pub fn benchmark_decrypt<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKey: AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        g: &mut BenchmarkGroup<WallTime>,
        decryption_key: &DecryptionKey,
        public_parameters: &EncryptionKey::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) {
        let encryption_key = decryption_key.as_ref();

        let plaintext: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            (&Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(42424242424242u128)).into();
        let plaintext: EncryptionKey::PlaintextSpaceGroupElement =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                plaintext.into(),
                public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap();

        let (_, ciphertext) = encryption_key
            .encrypt(&plaintext, public_parameters, rng)
            .unwrap();

        g.bench_function("decrypt", |b| {
            b.iter(|| decryption_key.decrypt(&ciphertext, public_parameters))
        });
    }

    fn bench_secp256k1(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (pp, decryption_key) =
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

        benchmark_encrypt(group, decryption_key.as_ref(), &pp, &mut OsRng);
        benchmark_decrypt(group, &decryption_key, &pp, &mut OsRng);
    }

    fn bench_ed25519(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let (pp, decryption_key) =
            RistrettoDecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

        benchmark_encrypt(group, decryption_key.as_ref(), &pp, &mut OsRng);
        benchmark_decrypt(group, &decryption_key, &pp, &mut OsRng);
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        bench_secp256k1(&mut _c.benchmark_group("decryption_key/secp256k1"));
        bench_ed25519(&mut _c.benchmark_group("decryption_key/ed25519"));
    }
}
