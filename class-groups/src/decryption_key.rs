// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;

use crypto_bigint::subtle::{Choice, ConstantTimeLess, CtOption};
use crypto_bigint::{Concat, ConstantTimeSelect, Encoding, Int, InvertMod, NonZero, Split, Uint};
use serde::{Deserialize, Serialize};

use group::{
    bounded_natural_numbers_group, CsRng, GroupElement as _, PrimeGroupElement, Samplable,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};

use group::sampling::legacy_random_mod;
use rand_chacha::ChaCha20Rng;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::encryption_key::public_parameters::Instantiate;
use crate::encryption_key::{Ciphertext, EncryptionKey, Plaintext, PublicParameters};
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::helpers::math;
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use crate::{equivalence_class, CompactIbqf, Error, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER};

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
    pub fn generate_with_setup_parameters(
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

        Self::new_from_secret_key_with_setup_parameters(setup_parameters, secret_key)
    }

    /// Reproduce a decryption key that was derived from its seed with the deployed crypto-bigint
    /// revision, before the library's sampler changed.
    ///
    /// This is the backward-compatibility pathway, for keys that already exist: it draws with
    /// [`sample_secret_key_legacy`], the deployed crypto-bigint sampler, from `rng`, the ChaCha20
    /// RNG built by [`group::sampling::legacy_seeded_rng`], fresh from the seed or advanced only
    /// by earlier legacy draws (the CRT keypairs are drawn one after another from one RNG). It is otherwise identical to [`Self::generate_with_setup_parameters`]. Every new
    /// key, seeded or not, must use that function and the current sampler.
    ///
    /// Not compatible between 32-bit and 64-bit targets: the legacy sampler draws whole
    /// machine words, so the same seed gives a different key on `wasm32` than on native, and a
    /// key is reproduced only on a target with the same word width as the one that first derived
    /// it.
    #[allow(clippy::type_complexity)]
    pub fn generate_with_setup_parameters_legacy(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            <GroupElement::Scalar as group::GroupElement>::PublicParameters,
        >,
        rng: &mut ChaCha20Rng,
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
        let secret_key = sample_secret_key_legacy(setup_parameters.decryption_key_bits(), rng);

        Self::new_from_secret_key_with_setup_parameters(setup_parameters, secret_key)
    }

    #[allow(clippy::type_complexity)]
    fn new_from_secret_key_with_setup_parameters(
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            <GroupElement::Scalar as group::GroupElement>::PublicParameters,
        >,
        secret_key: SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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

/// Draw a decryption key of `decryption_key_bits` bits exactly as the deployed crypto-bigint
/// revision drew it, on this target, from the ChaCha20 RNG of
/// [`group::sampling::legacy_seeded_rng`]: the backward-compatibility sampler behind [`DecryptionKey::generate_with_setup_parameters_legacy`]. Use only to
/// reproduce a key that was derived from its seed before the sampler changed; see
/// [`group::sampling::legacy_random_mod`]. Every new key uses the current sampler.
///
/// Not compatible between 32-bit and 64-bit targets: the legacy sampler draws whole
/// machine words, so the same seed gives a different key on `wasm32` than on native, and a
/// key is reproduced only on a target with the same word width as the one that first derived
/// it.
pub fn sample_secret_key_legacy<const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize>(
    decryption_key_bits: u32,
    rng: &mut ChaCha20Rng,
) -> SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS> {
    let upper_bound =
        NonZero::new(Uint::<FUNDAMENTAL_DISCRIMINANT_LIMBS>::ONE << decryption_key_bits).unwrap();

    legacy_random_mod::<FUNDAMENTAL_DISCRIMINANT_LIMBS>(rng, &upper_bound)
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

#[allow(dead_code)]
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

    SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: DeriveFromPlaintextPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,

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
            return Err(homomorphic_encryption::Error::from(
                homomorphic_encryption::ErrorKind::Group(group::Error::from(
                    group::ErrorKind::InvalidParameters,
                )),
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

    fn generate(
        plaintext_space_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        rng: &mut impl CsRng,
    ) -> homomorphic_encryption::Result<Self> {
        let setup_parameters = SetupParameters::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >::derive_from_plaintext_parameters::<GroupElement::Scalar>(
            plaintext_space_public_parameters,
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
        .map_err(|_| {
            homomorphic_encryption::Error::from(homomorphic_encryption::ErrorKind::InternalError)
        })?;

        let (_, decryption_key) = Self::generate_with_setup_parameters(setup_parameters, rng)
            .map_err(|_| {
                homomorphic_encryption::Error::from(
                    homomorphic_encryption::ErrorKind::InternalError,
                )
            })?;

        Ok(decryption_key)
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
    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::{
        Curve25519DecryptionKey, Curve25519SetupParameters, RistrettoDecryptionKey,
        RistrettoSetupParameters, Secp256k1DecryptionKey, Secp256k1SetupParameters,
        Secp256r1DecryptionKey, Secp256r1SetupParameters, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    };
    use group::sampling::legacy_seeded_rng;
    use group::{
        ristretto as ristretto_group, secp256k1 as secp256k1_group, secp256r1 as secp256r1_group,
        PublicParameters,
    };
    use sha2::{Digest, Sha256};

    // Native 64-bit BCS fingerprints captured with crypto-bigint fork 8aabcee5 and rand_chacha
    // 0.9.0 from the seed `[42; 32]`.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn seeded_wire_serialization_compatibility() {
        let mut rng = legacy_seeded_rng([42u8; 32]);
        let (_, key) = Secp256k1DecryptionKey::generate_with_setup_parameters_legacy(
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1_group::Scalar>(
                PublicParameters::<secp256k1_group::Scalar>::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.decryption_key).unwrap()).as_slice(),
            &[
                166, 5, 114, 250, 84, 162, 79, 102, 254, 192, 67, 229, 244, 196, 125, 101, 33, 99,
                219, 253, 21, 104, 103, 16, 98, 40, 140, 90, 214, 235, 170, 204
            ]
        );
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.encryption_key).unwrap()).as_slice(),
            &[
                99, 82, 152, 160, 63, 44, 40, 112, 76, 104, 29, 214, 43, 124, 135, 171, 206, 241,
                202, 132, 49, 88, 152, 101, 158, 175, 166, 147, 243, 77, 95, 59
            ]
        );
        let mut rng = legacy_seeded_rng([42u8; 32]);
        let (_, key) = Secp256r1DecryptionKey::generate_with_setup_parameters_legacy(
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1_group::Scalar>(
                PublicParameters::<secp256r1_group::Scalar>::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.decryption_key).unwrap()).as_slice(),
            &[
                166, 5, 114, 250, 84, 162, 79, 102, 254, 192, 67, 229, 244, 196, 125, 101, 33, 99,
                219, 253, 21, 104, 103, 16, 98, 40, 140, 90, 214, 235, 170, 204
            ]
        );
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.encryption_key).unwrap()).as_slice(),
            &[
                172, 12, 205, 94, 113, 0, 224, 24, 200, 13, 199, 226, 198, 136, 111, 246, 242, 11,
                13, 127, 46, 249, 111, 127, 82, 91, 53, 31, 193, 234, 197, 118
            ]
        );
        let mut rng = legacy_seeded_rng([42u8; 32]);
        let (_, key) = RistrettoDecryptionKey::generate_with_setup_parameters_legacy(
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto_group::Scalar>(
                PublicParameters::<ristretto_group::Scalar>::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.decryption_key).unwrap()).as_slice(),
            &[
                166, 5, 114, 250, 84, 162, 79, 102, 254, 192, 67, 229, 244, 196, 125, 101, 33, 99,
                219, 253, 21, 104, 103, 16, 98, 40, 140, 90, 214, 235, 170, 204
            ]
        );
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.encryption_key).unwrap()).as_slice(),
            &[
                154, 18, 98, 49, 127, 109, 231, 203, 129, 135, 43, 219, 197, 11, 113, 121, 200,
                233, 146, 217, 166, 47, 206, 246, 246, 35, 17, 53, 79, 102, 238, 106
            ]
        );
        let mut rng = legacy_seeded_rng([42u8; 32]);
        let (_, key) = Curve25519DecryptionKey::generate_with_setup_parameters_legacy(
            Curve25519SetupParameters::derive_from_plaintext_parameters::<ristretto_group::Scalar>(
                PublicParameters::<ristretto_group::Scalar>::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap(),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.decryption_key).unwrap()).as_slice(),
            &[
                166, 5, 114, 250, 84, 162, 79, 102, 254, 192, 67, 229, 244, 196, 125, 101, 33, 99,
                219, 253, 21, 104, 103, 16, 98, 40, 140, 90, 214, 235, 170, 204
            ]
        );
        assert_eq!(
            Sha256::digest(bcs::to_bytes(&key.encryption_key).unwrap()).as_slice(),
            &[
                154, 18, 98, 49, 127, 109, 231, 203, 129, 135, 43, 219, 197, 11, 113, 121, 200,
                233, 146, 217, 166, 47, 206, 246, 246, 35, 17, 53, 79, 102, 238, 106
            ]
        );
    }
    mod ristretto {
        use crypto_bigint::Uint;

        use group::{ristretto, OsCsRng};
        use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;

        use crate::test_helpers::get_setup_parameters_ristretto_112_bits_deterministic;
        use crate::{RistrettoDecryptionKey, RistrettoEncryptionKey, RISTRETTO_SCALAR_LIMBS};

        #[test]
        fn test_new_invalid() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, _) = RistrettoDecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                &mut OsCsRng,
            )
            .unwrap();

            let wrong_key = Uint::ONE;
            assert!(RistrettoDecryptionKey::new(wrong_key, &pp).is_err());
        }

        #[test]
        fn test_generate() {
            let cp = get_setup_parameters_ristretto_112_bits_deterministic();
            RistrettoDecryptionKey::generate_with_setup_parameters(cp, &mut OsCsRng).unwrap();
        }

        #[test]
        fn test_encrypt_decrypt() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, decryption_key) = RistrettoDecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                &mut OsCsRng,
            )
            .unwrap();
            homomorphic_encryption::test_helpers::encrypt_decrypts(
                decryption_key,
                &pp,
                &mut OsCsRng,
            );
        }

        #[test]
        fn test_evaluates() {
            let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
            let (pp, decryption_key) = RistrettoDecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                &mut OsCsRng,
            )
            .unwrap();

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
            let (pp, _) = Secp256k1DecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                &mut OsCsRng,
            )
            .unwrap();

            let wrong_key = Uint::ONE;
            assert!(Secp256k1DecryptionKey::new(wrong_key, &pp).is_err());
        }

        #[test]
        fn test_generate() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            Secp256k1DecryptionKey::generate_with_setup_parameters(setup_parameters, &mut OsCsRng)
                .unwrap();
        }

        #[test]
        fn test_encrypt_decrypt() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, decryption_key) = Secp256k1DecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                &mut OsCsRng,
            )
            .unwrap();

            homomorphic_encryption::test_helpers::encrypt_decrypts(
                decryption_key,
                &pp,
                &mut OsCsRng,
            );
        }

        #[test]
        fn test_evaluates() {
            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let (pp, decryption_key) = Secp256k1DecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                &mut OsCsRng,
            )
            .unwrap();

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
        let (pp, decryption_key) = Secp256k1DecryptionKey::generate_with_setup_parameters(
            setup_parameters.clone(),
            &mut OsCsRng,
        )
        .unwrap();

        benchmark_decrypt(group, &decryption_key, &pp, &mut OsCsRng);
    }

    fn bench_ed25519(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let (pp, decryption_key) = RistrettoDecryptionKey::generate_with_setup_parameters(
            setup_parameters.clone(),
            &mut OsCsRng,
        )
        .unwrap();

        benchmark_decrypt(group, &decryption_key, &pp, &mut OsCsRng);
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        bench_secp256k1(&mut _c.benchmark_group("decryption_key/secp256k1"));
        bench_ed25519(&mut _c.benchmark_group("decryption_key/ed25519"));
    }
}
