// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::cmp::min;

use crypto_bigint::rand_core::{CryptoRngCore, SeedableRng};
use crypto_bigint::{Concat, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};
use rand_chacha::{ChaCha20Core, ChaCha20Rng};
use serde::{Deserialize, Serialize};

use group::{ristretto, secp256k1, KnownOrderGroupElement, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{GroupsPublicParameters, GroupsPublicParametersAccessors};

use crate::discriminant::Discriminant;
use crate::equivalence_class::EquivalenceClass;
use crate::parameters::Parameters;
use crate::randomizer::ScalingRandomizer;
use crate::{equivalence_class, helpers, Error, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER};
use crate::{CiphertextSpacePublicParameters, RandomnessSpacePublicParameters};
use crate::{
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
};

/// Set of public parameters required to set up the class-group encryption scheme.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters,
> where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    pub(crate) groups_public_parameters: GroupsPublicParameters<
        ScalarPublicParameters,
        RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,

    // Parameters relating to the class group this instance of the encryption scheme works with.
    pub(crate) class_group_parameters: Parameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,

    // Parameters relating to encryption. In encryption,
    // - the message is composed with `f` (known order = q^k),
    // - the randomness is composed with `h` (unknown order).
    pub(crate) f: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub h: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,

    // Parameters relating to decryption
    pub large_message_variant: bool,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

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

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Construct new public setup parameters, given the
    /// - class group parameters, and
    /// - plaintext space parameters.
    pub(crate) fn new(
        class_group_parameters: Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        plaintext_space_public_parameters: ScalarPublicParameters,
    ) -> Result<Self, Error> {
        let groups_public_parameters = Self::construct_groups_public_parameters(
            &class_group_parameters,
            plaintext_space_public_parameters,
        )?;

        let large_message_variant = Self::use_large_message_variant(&class_group_parameters);

        let f = class_group_parameters.f()?;
        let mut h = class_group_parameters.h()?;
        // Safe to vartime; this acceleration is in time variable in `h` and `sample_bits`, which
        // are both public.
        h.accelerate_vartime(
            groups_public_parameters
                .randomness_space_public_parameters
                .sample_bits,
        )?;

        Ok(Self {
            groups_public_parameters,
            class_group_parameters,
            f,
            h,
            large_message_variant,
        })
    }

    /// Construct the groups public parameters, given the
    /// - class-group parameters, and
    /// - plaintext space public parameters.
    pub(crate) fn construct_groups_public_parameters(
        class_group_parameters: &Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        plaintext_space_public_parameters: ScalarPublicParameters,
    ) -> Result<
        GroupsPublicParameters<
            ScalarPublicParameters,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        Error,
    > {
        let ec_pp = equivalence_class::PublicParameters {
            discriminant: *class_group_parameters.delta_qk,
        };
        let ciphertext_space_public_parameters = CiphertextSpacePublicParameters::new(ec_pp);

        let sample_bits = Self::compute_randomness_bits(&class_group_parameters.delta_k)?;

        // Note that here we are constructing the public parameters for the randomness size
        // as such that they will accommodate the intermediate values used in computation of Maurer proofs.
        // In practice, this should never fail and there should always be enough space to accommodate that computation:
        // We have `FUNDAMENTAL_DISCRIMINANT_LIMBS > 21` for the security of the class-group primitive.
        // On the other hand the randomness is taken to be `FUNDAMENTAL_DISCRIMINANT_LIMBS/2 + 4` (for computational soundness) `+ 2` (for statistical zk).
        // This is always smaller than `FUNDAMENTAL_DISCRIMINANT_LIMBS`.
        let randomness_space_public_parameters =
            RandomnessSpacePublicParameters::new_with_randomizer_upper_bound(sample_bits)
                .map_err(|_| Error::InvalidPublicParameters)?;

        Ok(GroupsPublicParameters {
            plaintext_space_public_parameters,
            randomness_space_public_parameters,
            ciphertext_space_public_parameters,
        })
    }

    /// Compute the bit size of a randomizer for a class group induced by the given `discriminant`.
    ///
    /// Computed as `class_number_upper_bound::BITS + StatisticalSecuritySizedNumber::BITS`
    fn compute_randomness_bits(
        discriminant: &Discriminant<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<u32, Error> {
        let class_number_bound = discriminant.class_number_upper_bound();
        Ok(class_number_bound.bits() + StatisticalSecuritySizedNumber::BITS)
    }

    /// Determine whether to enable large message variant.
    ///
    /// This should be enabled when `4*q^{2k} + 1 > ∆_k`.
    fn use_large_message_variant(
        class_group_parameters: &Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> bool {
        // safe to wrapping_mul; q * q^2k > 4*q^2k fits in DISCRIMINANT_LIMBS.
        let four_q_exp_2k_plus_one = class_group_parameters
            .q_exp_2k
            .shl_vartime(2)
            .wrapping_add(&Uint::ONE);

        four_q_exp_2k_plus_one > class_group_parameters.delta_k.abs().resize()
    }

    /// Compute `h^exponent`.
    pub(crate) fn power_of_h<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.h.pow(exponent)
    }

    /// Compute `h^e`, with `e := exponent % 2^exponent_bits`.
    pub(crate) fn power_of_h_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.h.pow_bounded(exponent, exponent_bits)
    }

    /// Compute `h^exponent`.
    ///
    /// Function runs in time variable in `h` and `exponent`.
    pub(crate) fn power_of_h_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.h.pow_vartime(exponent)
    }

    /// Construct a triple that can be used to randomize scaling an [EquivalenceClass].
    pub(crate) fn sample_scaling_randomizer<const EXPONENT_LIMBS: usize>(
        &self,
        scalar: Uint<EXPONENT_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ScalingRandomizer<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<EXPONENT_LIMBS>: Encoding,
    {
        self.sample_bounded_scaling_randomizer(scalar, Uint::<EXPONENT_LIMBS>::BITS, rng)
    }

    /// Construct a triple that can be used to randomize bounded scaling an [EquivalenceClass].
    pub(crate) fn sample_bounded_scaling_randomizer<const EXPONENT_LIMBS: usize>(
        &self,
        scalar: Uint<EXPONENT_LIMBS>,
        scalar_bits_bound: u32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ScalingRandomizer<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<EXPONENT_LIMBS>: Encoding,
    {
        let scalar_bits_bound = min(scalar_bits_bound, Uint::<EXPONENT_LIMBS>::BITS);
        ScalingRandomizer::new(
            self.h,
            scalar,
            scalar_bits_bound,
            self.randomness_space_public_parameters(),
            rng,
        )
    }

    /// Construct a triple that can be used to randomize vartime scaling an [EquivalenceClass].
    pub(crate) fn sample_vartime_scaling_randomizer<const EXPONENT_LIMBS: usize>(
        &self,
        scalar: Uint<EXPONENT_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ScalingRandomizer<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<EXPONENT_LIMBS>: Encoding,
    {
        self.sample_bounded_scaling_randomizer(scalar, scalar.bits(), rng)
    }
}

pub trait DeriveFromPlaintextPublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters,
>: Sized
{
    /// Construct new public setup parameters, given a
    /// - plaintext element, and
    /// - computational security parameter
    ///
    /// This function selects a `p` deterministically; the output will be identical each time
    /// for the same input parameters.
    fn derive_from_plaintext_parameters<Scalar>(
        plaintext_space_parameters: ScalarPublicParameters,
        computational_security_parameter: u32,
    ) -> Result<Self, Error>
    where
        Scalar: KnownOrderGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = ScalarPublicParameters,
        >;

    /// Construct new public setup parameters given a
    /// - plaintext element, and
    /// - computational security parameter.
    ///
    /// This function selects a random `p`; the output will be different each time.
    fn derive_from_plaintext_parameters_random<Scalar>(
        plaintext_space_parameters: ScalarPublicParameters,
        computational_security_parameter: u32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error>
    where
        Scalar: KnownOrderGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = ScalarPublicParameters,
        >;
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    DeriveFromPlaintextPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
    for SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

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

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    fn derive_from_plaintext_parameters<Scalar>(
        plaintext_space_parameters: ScalarPublicParameters,
        computational_security_parameter: u32,
    ) -> Result<Self, Error>
    where
        Scalar: KnownOrderGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = ScalarPublicParameters,
        >,
    {
        let order = Scalar::order_from_public_parameters(&plaintext_space_parameters);
        let seed = helpers::sha3_256_hash(order.to_be_bytes());
        let mut rng = ChaCha20Rng::from(ChaCha20Core::from_seed(seed));

        Self::derive_from_plaintext_parameters_random::<Scalar>(
            plaintext_space_parameters,
            computational_security_parameter,
            &mut rng,
        )
    }

    fn derive_from_plaintext_parameters_random<Scalar>(
        plaintext_space_parameters: ScalarPublicParameters,
        computational_security_parameter: u32,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, Error>
    where
        Scalar: KnownOrderGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = ScalarPublicParameters,
        >,
    {
        let order = Scalar::order_from_public_parameters(&plaintext_space_parameters);
        let q = NonZero::new(order)
            .into_option()
            .ok_or(Error::InvalidParameters)?;

        // TODO(#17): quit hardcoding for k > 1
        let class_group_parameters =
            Parameters::new_random_vartime(q, 1, computational_security_parameter, rng)?;

        Self::new(class_group_parameters, plaintext_space_parameters)
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    /// The public parameters of a scalar of the same group as the decryption key.
    pub fn equivalence_class_public_parameters(
        &self,
    ) -> &equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        &self.ciphertext_space_public_parameters().public_parameters
    }

    /// The public parameters of a scalar of the same group as the decryption key.
    pub fn scalar_group_public_parameters(
        &self,
    ) -> &RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.decryption_key_group_public_parameters()
    }

    /// The bit size of a scalar of the same group as the decryption key.
    pub fn scalar_bits(&self) -> u32 {
        self.scalar_group_public_parameters().sample_bits
    }

    /// Upperbound on the bit size of a scalar of the same group as the decryption key.
    pub fn scalar_upper_bound_bits(&self) -> u32 {
        self.scalar_group_public_parameters().upper_bound_bits
    }

    /// The public parameters of the decryption key.
    /// In class-group cryptography, the decryption key is
    /// sampled from the same distribution as the encryption randomness.
    pub fn decryption_key_group_public_parameters(
        &self,
    ) -> &RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.randomness_space_public_parameters()
    }

    /// The bit size of the decryption key.
    pub fn decryption_key_bits(&self) -> u32 {
        self.decryption_key_group_public_parameters().sample_bits
    }

    /// Upperbound on the bit size of the decryption key.
    pub fn decryption_key_upper_bound_bits(&self) -> u32 {
        self.decryption_key_group_public_parameters()
            .upper_bound_bits
    }

    /// The bit size of the encryption randomness.
    pub fn encryption_randomness_bits(&self) -> u32 {
        self.randomness_space_public_parameters().sample_bits
    }

    /// Upperbound on the bit size of the encryption randomness.
    ///
    /// In class-group cryptography, the encryption randomness lives in a hidden-order group.
    /// We sample it from a known distribution (see: `encryption_randomness_bits()`) but when we
    /// perform homomorphic operations on encryptions, the size increases and modulates at an
    /// unknown point (as the order is hidden).
    ///
    /// For this, we use the`bounded_natural_numbers_group::GroupElement` for randomness elements,
    /// and it specifies an upper-bound on the computation over the naturals. We instantiate that
    /// upper-bound to support the maximum operations we anticipate in the protocol, which for us
    /// is during `maurer` zero-knowledge proofs. This function returns this upper-bound, which
    /// should never be reached.
    pub fn encryption_randomness_upper_bound_bits(&self) -> u32 {
        self.randomness_space_public_parameters().upper_bound_bits
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            ScalarPublicParameters,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >
    for SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        ScalarPublicParameters,
        RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    > {
        &self.groups_public_parameters
    }
}

/// TODO(#89): make generic over COMPUTATIONAL_SECURITY_PARAMETER
impl Default
    for SetupParameters<
        SECP256K1_SCALAR_LIMBS,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        secp256k1::scalar::PublicParameters,
    >
{
    fn default() -> Self {
        // Safe to unwrap, as this is deterministic and would fail tests if it fails; so no risk in production.
        Self::derive_from_plaintext_parameters::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
        .unwrap()
    }
}

/// TODO(#89): make generic over COMPUTATIONAL_SECURITY_PARAMETER
impl Default
    for SetupParameters<
        RISTRETTO_SCALAR_LIMBS,
        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ristretto::scalar::PublicParameters,
    >
{
    fn default() -> Self {
        // Safe to unwrap, as this is deterministic and would fail tests if it fails; so no risk in production.
        Self::derive_from_plaintext_parameters::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
        .unwrap()
    }
}

pub fn get_setup_parameters_secp256k1() -> SetupParameters<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::scalar::PublicParameters,
> {
    SetupParameters::<
        SECP256K1_SCALAR_LIMBS,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        _,
    >::derive_from_plaintext_parameters::<<group::secp256k1::GroupElement as KnownOrderGroupElement<SECP256K1_SCALAR_LIMBS>>::Scalar>(
        group::PublicParameters::<<group::secp256k1::GroupElement as KnownOrderGroupElement<SECP256K1_SCALAR_LIMBS>>::Scalar>::default(),
        DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    ).unwrap()
}

#[allow(dead_code)]
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use crypto_bigint::{Concat, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};
    use rand_core::{CryptoRngCore, OsRng};

    use group::const_additive::PrimeConstMontyParams;
    use group::{ristretto, secp256k1, KnownOrderGroupElement};

    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::{
        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
    };

    use super::SetupParameters;

    /// Deterministic; the `p` selected for the scheme is the same every time.
    pub fn get_setup_parameters_secp256k1_112_bits_deterministic() -> SetupParameters<
        SECP256K1_SCALAR_LIMBS,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        secp256k1::scalar::PublicParameters,
    > {
        SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            112,
        )
        .unwrap()
    }

    /// Random; the `p` selected for the scheme is different every time.
    pub fn get_setup_parameters_secp256k1_112_bits_random(
        rng: &mut OsRng,
    ) -> SetupParameters<
        SECP256K1_SCALAR_LIMBS,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        secp256k1::scalar::PublicParameters,
    > {
        SetupParameters::derive_from_plaintext_parameters_random::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            112,
            rng,
        )
        .unwrap()
    }

    /// Deterministic; the `p` selected for the scheme is the same every time.
    pub fn get_setup_parameters_ristretto_112_bits_deterministic() -> SetupParameters<
        RISTRETTO_SCALAR_LIMBS,
        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ristretto::scalar::PublicParameters,
    > {
        SetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            112,
        )
        .unwrap()
    }

    /// Random; the `p` selected for the scheme is different every time.
    pub fn get_setup_parameters_ristretto_112_bits_random(
        rng: &mut impl CryptoRngCore,
    ) -> SetupParameters<
        RISTRETTO_SCALAR_LIMBS,
        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ristretto::scalar::PublicParameters,
    > {
        SetupParameters::derive_from_plaintext_parameters_random::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            112,
            rng,
        )
        .unwrap()
    }

    /// Deterministic; the `p` selected for the scheme is the same every time.
    pub fn get_setup_parameters_lmv_112_bits_deterministic<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        MOD: PrimeConstMontyParams<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        Scalar,
    >() -> SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::const_additive::PublicParameters<MOD, PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    where
        Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

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

        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
            + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
            + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
            + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

        Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
            Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

        Scalar: KnownOrderGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = group::const_additive::PublicParameters<
                MOD,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
            >,
        >,
    {
        SetupParameters::derive_from_plaintext_parameters::<Scalar>(
            group::const_additive::PublicParameters::<MOD, PLAINTEXT_SPACE_SCALAR_LIMBS>::default(),
            112,
        )
        .unwrap()
    }

    /// Random; the `p` selected for the scheme is the different every time.
    pub fn get_setup_parameters_lmv_112_bits_random<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        MOD: PrimeConstMontyParams<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        Scalar,
    >(
        rng: &mut impl CryptoRngCore,
    ) -> SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::const_additive::PublicParameters<MOD, PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    where
        Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

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

        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
            + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
            + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
            + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

        Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
            Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

        Scalar: KnownOrderGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = group::const_additive::PublicParameters<
                MOD,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
            >,
        >,
    {
        SetupParameters::derive_from_plaintext_parameters_random::<Scalar>(
            group::const_additive::PublicParameters::<MOD, PLAINTEXT_SPACE_SCALAR_LIMBS>::default(),
            112,
            rng,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{NonZero, U1280, U2048, U320, U64};
    use rand_core::OsRng;

    use group::{ristretto, secp256k1};

    use crate::randomizer::ScalingRandomizer;
    use crate::setup::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::SetupParameters;
    use crate::{
        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
    };

    #[test]
    fn test_derive_from_plaintext_parameters_random_secp256k1() {
        SetupParameters::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::scalar::PublicParameters,
        >::derive_from_plaintext_parameters_random::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            112,
            &mut OsRng,
        )
        .unwrap();
    }

    #[test]
    fn test_derive_from_plaintext_parameters_random_ristretto() {
        SetupParameters::<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::scalar::PublicParameters,
        >::derive_from_plaintext_parameters_random::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            112,
            &mut OsRng,
        )
        .unwrap();
    }

    /// Snapshot test: the output to this function should be identical each time.
    #[test]
    fn snapshot_test_derive_from_plaintext_parameters_deterministic_secp256k1() {
        let setup = SetupParameters::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::scalar::PublicParameters,
        >::derive_from_plaintext_parameters::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            112,
        )
        .unwrap();

        assert_eq!(
            setup.class_group_parameters.q,
            NonZero::new(secp256k1::ORDER).unwrap()
        );

        let target_p = U1280::from_be_hex(concat![
            "00000000000000000000000000000000000000000000000DF6079F147372B293",
            "35E4B8960D19D3DA8200C254DB693354909B31706E870D1652C936FC056CD56C",
            "121646AA923E40D548081A0976992D12C714547EC87B198C1877FF854D634B1F",
            "D1D39A2AF56CC6B97E734CCDF495AA10B2C27BF1F3D4D17AEBCD370C9908F1E1",
            "0E4A4989FF6AFA2FC2AB643175B09D9C6B824C690DAF68E056F6B5FF47940F37"
        ])
        .resize();

        assert_eq!(
            setup.class_group_parameters.p,
            NonZero::new(target_p).unwrap()
        );
    }

    /// Snapshot test: the output to this function should be identical each time.
    #[test]
    fn snapshot_test_derive_from_plaintext_parameters_deterministic_ristretto() {
        let setup = SetupParameters::<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::scalar::PublicParameters,
        >::derive_from_plaintext_parameters::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            112,
        )
        .unwrap();

        assert_eq!(
            setup.class_group_parameters.q,
            NonZero::new(ristretto::ORDER).unwrap()
        );

        let target_p = U1280::from_be_hex(concat![
            "00000000000000000000000000000000000000000000005C9E289D20203557D5",
            "DE12A35F8C61AE52D33699ABF57D736D3FCB4E294D6BA90D00AABB311BA915BA",
            "D7C8DAD7FC845DC205ECE90BCAA95D9A20E74B1F395139C948D381C6647B0715",
            "30451B667C37452EA8FAB96C9BF8E84752E7EF9BFB44593438A82D9B0C6ACCAA",
            "13484879313E503DF9B9CFDD8C2392F63FE8ECF8745D6EA90F4CD816609288DF"
        ])
        .resize();

        assert_eq!(
            setup.class_group_parameters.p,
            NonZero::new(target_p).unwrap()
        );
    }

    #[test]
    /// regression test
    fn test_power_of_h() {
        let sk = U320::from_be_hex(
            "2B3C901E8F2016B01DD917911C4EA3FD48EA06668EB7D2DAB2E051B9D82FB2D55D7B3F8471A2622D",
        )
        .resize::<{ U2048::LIMBS }>();

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        assert_eq!(
            setup_parameters.power_of_h_vartime(&sk),
            setup_parameters.h.pow_vartime(&sk)
        );
    }

    #[test]
    /// regression test
    fn test_decryption_key_bits() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        assert_eq!(
            sp.decryption_key_bits(),
            sp.groups_public_parameters
                .randomness_space_public_parameters
                .sample_bits
        );

        assert_eq!(
            sp.decryption_key_upper_bound_bits(),
            sp.groups_public_parameters
                .randomness_space_public_parameters
                .upper_bound_bits
        );
    }

    #[test]
    /// regression test
    fn test_scalar_bits() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();

        assert_eq!(
            sp.scalar_bits(),
            sp.groups_public_parameters
                .randomness_space_public_parameters
                .sample_bits
        );

        assert_eq!(
            sp.scalar_upper_bound_bits(),
            sp.groups_public_parameters
                .randomness_space_public_parameters
                .upper_bound_bits
        );
    }

    #[test]
    fn test_sample_scaling_randomizer() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let exponent = U64::from_u64(42);
        let randomizer = sp.sample_scaling_randomizer(exponent, &mut OsRng).unwrap();

        // Check that the randomizer is valid
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = randomizer;
        assert_eq!(scalar_bits_bound, U64::BITS);
        assert_eq!(
            m3,
            m1.pow_randomized_bounded_with_base(m2, &exponent, scalar_bits_bound)
                .unwrap()
        );

        // Check that subsequent randomizers are different.
        let randomizer2 = sp.sample_scaling_randomizer(exponent, &mut OsRng).unwrap();
        let ScalingRandomizer {
            m1: r2m1,
            m2: r2m2,
            m3: r2m3,
            ..
        } = randomizer2;
        assert_ne!(m1, r2m1);
        assert_ne!(m2, r2m2);
        assert_ne!(m3, r2m3);
    }

    #[test]
    fn test_sample_bounded_scaling_randomizer() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let exponent = U64::from_u64(42);
        let randomizer = sp
            .sample_bounded_scaling_randomizer(exponent, exponent.bits(), &mut OsRng)
            .unwrap();

        // Check that the randomizer is valid
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = randomizer;
        assert_eq!(scalar_bits_bound, exponent.bits());
        assert_eq!(
            m3,
            m1.pow_randomized_bounded_with_base(m2, &exponent, scalar_bits_bound)
                .unwrap()
        );

        // Check that subsequent randomizers are different.
        let randomizer2 = sp
            .sample_bounded_scaling_randomizer(exponent, exponent.bits(), &mut OsRng)
            .unwrap();
        let ScalingRandomizer {
            m1: r2m1,
            m2: r2m2,
            m3: r2m3,
            ..
        } = randomizer2;
        assert_ne!(m1, r2m1);
        assert_ne!(m2, r2m2);
        assert_ne!(m3, r2m3);
    }

    #[test]
    fn test_sample_scaling_randomizer_vartime() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let exponent = U64::from_u64(42);
        let randomizer = sp
            .sample_vartime_scaling_randomizer(exponent, &mut OsRng)
            .unwrap();

        // Check that the randomizer is valid
        let ScalingRandomizer {
            m1,
            m2,
            m3,
            scalar_bits_bound,
        } = randomizer;
        assert_eq!(scalar_bits_bound, exponent.bits());
        assert_eq!(
            m3,
            m1.pow_randomized_bounded_with_base(m2, &exponent, scalar_bits_bound)
                .unwrap()
        );

        // Check that subsequent randomizers are different.
        let randomizer2 = sp.sample_scaling_randomizer(exponent, &mut OsRng).unwrap();
        let ScalingRandomizer {
            m1: r2m1,
            m2: r2m2,
            m3: r2m3,
            ..
        } = randomizer2;
        assert_ne!(m1, r2m1);
        assert_ne!(m2, r2m2);
        assert_ne!(m3, r2m3);
    }
}
