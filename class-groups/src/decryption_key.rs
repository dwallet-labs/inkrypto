// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;

use crypto_bigint::subtle::{Choice, ConstantTimeLess, CtOption};
use crypto_bigint::{Concat, ConstantTimeSelect, Encoding, Int, InvertMod, Split, Uint};
use serde::{Deserialize, Serialize};

use group::{
    bounded_natural_numbers_group, CsRng, GroupElement as _, PrimeGroupElement, Samplable,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::encryption_key::public_parameters::Instantiate;
use crate::encryption_key::{Ciphertext, EncryptionKey, Plaintext, PublicParameters};
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::helpers::math;
use crate::setup::SetupParameters;
use crate::{equivalence_class, CompactIbqf, Error};

pub type SecretKey<const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize> =
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>;

/// TODO(#300): the serialization of this object should not be sent over a wire.
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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Decrypt a ciphertext `(c1, c2)` using `self` as decryption key.
    ///
    /// ### Decryption
    /// Decryption involves the following two steps:
    /// 1. remove randomness: map `(c1, c2) = (h^r, f^m * pk^r)` to `c2 / c1^sk = f^m`. Note that `pk = h^sk`.
    /// 2. decode message: map `f^m` to `m` by computing the discrete log of `f^m`.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 3.
    ///
    /// ### Randomized
    /// It is assumed that the two components of the ciphertext `(c1, c2)` are random classes.
    /// As a result, the faster `*_randomized` operations can be used during decryption. Note that
    /// execution still occurs in constant time.
    ///
    /// If, for any reason, the caller is unsure whether the ciphertext is randomized, they can
    /// 1. vartime-compute the encryption 0,
    /// 2. add it to the cipher-text
    ///
    /// to make it random. Hereafter, it should be safe to execute randomized decryption.
    pub fn decrypt_randomized(
        &self,
        ciphertext: &Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    ) -> CtOption<Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>> {
        let (c1, c2) = ciphertext;

        // Illegal ciphertext
        if !c1.is_from_the_same_class_as(c2) {
            return CtOption::new(Uint::MAX, Choice::from(0));
        }

        let c1_exp_sk = c1.pow_public_base_bounded_randomized(
            &self.decryption_key,
            public_parameters.setup_parameters.decryption_key_bits(),
        );
        let encoded_message = c2
            .div(&c1_exp_sk)
            .expect("successful division; same discriminant");
        Self::discrete_log_in_F(&encoded_message, &public_parameters.setup_parameters)
    }

    /// Decrypt a ciphertext `(c1, c2)` using `self` as decryption key.
    ///
    /// ### Decryption
    /// Decryption involves the following two steps:
    /// 1. remove randomness: map `(c1, c2) = (h^r, f^m * pk^r)` to `c2 / c1^sk = f^m`. Note that `pk = h^sk`.
    /// 2. decode message: map `f^m` to `m` by computing the discrete log of `f^m`.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 3.
    ///
    /// ### Constant time
    /// This algorithm executes in constant time.
    pub fn decrypt_constant_time(
        &self,
        ciphertext: &Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    ) -> CtOption<Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>> {
        let (c1, c2) = ciphertext;

        // Illegal ciphertext
        if !c1.is_from_the_same_class_as(c2) {
            return CtOption::new(Uint::MAX, Choice::from(0));
        }

        let c1_exp_sk = c1.pow_public_base_bounded(
            &self.decryption_key,
            public_parameters.setup_parameters.decryption_key_bits(),
        );
        let encoded_message = c2
            .div(&c1_exp_sk)
            .expect("successful division; same discriminant");
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
        rng: &mut impl CsRng,
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
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
    ) -> CtOption<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>;
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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    #[allow(clippy::useless_conversion)]
    fn discrete_log_in_F(
        fm: &EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        setup_parameters: &SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    ) -> CtOption<Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>> {
        let class_group_parameters = &setup_parameters.class_group_parameters;
        let q = class_group_parameters.q;

        let decoding = if setup_parameters.large_message_variant {
            unimplemented!(
                "TODO(#220); this operation is not supported for the large message variant"
            )
        } else {
            let q_ = q
                .resize::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>()
                .to_nz()
                .expect("q_ is non-zero; q is non-zero and resize is an expansion");

            // safe to vartime; the function `factor_mod_vartime` runs in time variable in the size
            // of `q` only; it behaves independently of `b`. Given that `q` is public information,
            // it is safe to use this vartime function here.
            let (u, _) = math::factor_mod_vartime(*fm.representative().b(), &q_);
            let u = CtOption::new(u, u.abs().ct_lt(&q_));

            // Move `u` to lie in [0, q)
            u.map(|u| math::representative_mod(&u, &q_))
                .map(|u| {
                    u.resize::<PLAINTEXT_SPACE_SCALAR_LIMBS>() // Safe to resize; u lies in [0, q)
                })
                .and_then(|u| {
                    u.invert_mod(&q).into() // TODO(#17): use u.invert_mod(q_exp_k) instead of u.invert_mod(q)
                })
        };

        decoding.map(|decoding| Uint::ct_select(&decoding, &Uint::ZERO, fm.is_unit()))
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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    group::PublicParameters<GroupElement::Scalar>: Eq,
{
    type SecretKey = SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>;

    fn new(
        secret_key: Self::SecretKey,
        public_parameters: &<EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PublicParameters,
    ) -> homomorphic_encryption::Result<Self> {
        let key_matches_pp = public_parameters.belongs_to_secret_key(
            &secret_key,
            public_parameters.setup_parameters.decryption_key_bits(),
        );
        if !key_matches_pp {
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

        #[cfg(feature = "randomized_decryption")]
        let decryption_result = self.decrypt_randomized(&(ct1, ct2), public_parameters);
        #[cfg(not(feature = "randomized_decryption"))]
        let decryption_result = self.decrypt_constant_time(&(ct1, ct2), public_parameters);

        decryption_result.map(|decryption| {
                <EncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement> as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement::new(
                    decryption.into(),
                    public_parameters.plaintext_space_public_parameters(),
                ).unwrap_or(self.neutral)
            })
    }
}

#[cfg(test)]
mod tests {
    mod ristretto {
        use crypto_bigint::Uint;

        use group::{ristretto, OsCsRng};
        use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;

        use crate::test_helpers::get_setup_parameters_ristretto_112_bits_deterministic;
        use crate::{RistrettoDecryptionKey, RistrettoEncryptionKey, RISTRETTO_SCALAR_LIMBS};

        #[test]
        fn test_new_invalid() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, _) = RistrettoDecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

            let wrong_key = Uint::ONE;
            assert!(RistrettoDecryptionKey::new(wrong_key, &pp).is_err());
        }

        #[test]
        fn test_generate() {
            let cp = get_setup_parameters_ristretto_112_bits_deterministic();
            RistrettoDecryptionKey::generate(cp, &mut OsCsRng).unwrap();
        }

        #[test]
        fn test_encrypt_decrypt() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, decryption_key) =
                RistrettoDecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();
            homomorphic_encryption::test_helpers::encrypt_decrypts(
                decryption_key,
                &pp,
                &mut OsCsRng,
            );
        }

        #[test]
        fn test_evaluates() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, decryption_key) =
                RistrettoDecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

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
                &mut OsCsRng,
            );
        }
    }

    mod secp256k1 {
        use crypto_bigint::{Uint, U256};
        use rstest::rstest;

        use group::{secp256k1, OsCsRng};
        use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;

        use crate::decryption_key::DiscreteLogInF;
        use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
        use crate::{Secp256k1DecryptionKey, Secp256k1EncryptionKey, SECP256K1_SCALAR_LIMBS};

        #[test]
        fn test_new_invalid() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, _) = Secp256k1DecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

            let wrong_key = Uint::ONE;
            assert!(Secp256k1DecryptionKey::new(wrong_key, &pp).is_err());
        }

        #[test]
        fn test_generate() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();
        }

        #[test]
        fn test_encrypt_decrypt() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, decryption_key) =
                Secp256k1DecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

            homomorphic_encryption::test_helpers::encrypt_decrypts(
                decryption_key,
                &pp,
                &mut OsCsRng,
            );
        }

        #[test]
        fn test_evaluates() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, decryption_key) =
                Secp256k1DecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

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
                &mut OsCsRng,
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

            assert!(bool::from(decoding.is_some()));
            assert_eq!(decoding.unwrap(), m);
        }
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{BenchmarkGroup, Criterion};
    use crypto_bigint::Uint;

    use group::{CsRng, GroupElement, OsCsRng};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };

    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };
    use crate::{RistrettoDecryptionKey, Secp256k1DecryptionKey};

    pub fn benchmark_decrypt<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKey: AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        g: &mut BenchmarkGroup<WallTime>,
        decryption_key: &DecryptionKey,
        public_parameters: &EncryptionKey::PublicParameters,
        rng: &mut impl CsRng,
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
            .encrypt(&plaintext, public_parameters, true, rng)
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
            Secp256k1DecryptionKey::generate(setup_parameters.clone(), &mut OsCsRng).unwrap();

        benchmark_decrypt(group, &decryption_key, &pp, &mut OsCsRng);
    }

    fn bench_ed25519(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let (pp, decryption_key) =
            RistrettoDecryptionKey::generate(setup_parameters.clone(), &mut OsCsRng).unwrap();

        benchmark_decrypt(group, &decryption_key, &pp, &mut OsCsRng);
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        bench_secp256k1(&mut _c.benchmark_group("decryption_key/secp256k1"));
        bench_ed25519(&mut _c.benchmark_group("decryption_key/ed25519"));
    }
}
