// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::cmp::min;
use std::collections::HashMap;

use crypto_bigint::{Concat, Encoding, Int, NonZero, Split, Uint};
use rand_chacha::{ChaCha20Core, ChaCha20Rng};
use serde::{Deserialize, Serialize};

use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
use group::{ristretto, secp256k1, CsRng, KnownOrderGroupElement};
use group::{SeedableRng, Transcribeable};
use homomorphic_encryption::{
    CanonicalGroupsPublicParameters, GroupsPublicParameters, GroupsPublicParametersAccessors,
};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::parameters::{minimum_discriminant_bits, Parameters};
use crate::randomizer::ScalingRandomizer;
use crate::{
    decryption_key_size_from_fundamental_discriminant_size, equivalence_class, helpers,
    CompactIbqf, Error, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    HIGHEST_ACCELERATOR_FOLDING_DEGREE, SECRET_KEY_SHARE_SIZE_UPPER_BOUND,
};
use crate::{CiphertextSpacePublicParameters, RandomnessSpacePublicParameters};
use crate::{
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
};

/// Set of public parameters required to set up the class-group encryption scheme.
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
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
    pub(crate) decryption_key_public_parameters:
        DecryptionKeySpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,

    // Parameters relating to the class group this instance of the encryption scheme works with.
    pub(crate) class_group_parameters: Parameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,

    // Parameters relating to encryption.
    // In encryption, the randomness is composed with `h` (unknown order).
    pub h: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,

    // Parameters relating to decryption
    pub large_message_variant: bool,
}

type DecryptionKeySpacePublicParameters<const LIMBS: usize> =
    RandomnessSpacePublicParameters<LIMBS>;

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

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Construct new public setup parameters, given the
    /// - class group parameters,
    /// - plaintext space parameters,
    /// - `h` folding degree, and
    /// - a source of randomness `rng`.
    pub(crate) fn new(
        class_group_parameters: Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        plaintext_space_public_parameters: ScalarPublicParameters,
        folding_degree: u32,
        rng: &mut impl CsRng,
    ) -> Result<Self, Error> {
        let (groups_public_parameters, decryption_key_public_parameters, h) =
            Self::construct_groups_public_parameters(
                &class_group_parameters,
                plaintext_space_public_parameters,
                folding_degree,
                rng,
            )?;

        let large_message_variant = Self::use_large_message_variant(&class_group_parameters);

        Ok(Self {
            groups_public_parameters,
            class_group_parameters,
            h,
            large_message_variant,
            decryption_key_public_parameters,
        })
    }

    /// Construct the groups public parameters, given the
    /// - class-group parameters, and
    /// - plaintext space public parameters.
    #[allow(clippy::type_complexity)]
    pub(crate) fn construct_groups_public_parameters(
        class_group_parameters: &Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        plaintext_space_public_parameters: ScalarPublicParameters,
        folding_degree: u32,
        rng: &mut impl CsRng,
    ) -> Result<
        (
            GroupsPublicParameters<
                ScalarPublicParameters,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
            DecryptionKeySpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ),
        Error,
    > {
        let randomness_sample_bits = Self::compute_randomness_bits(class_group_parameters)?;
        // Note that here we are constructing the public parameters for the randomness size
        // as such that they will accommodate the intermediate values used in computation of Maurer proofs.
        // In practice, this should never fail and there should always be enough space to accommodate that computation:
        // We have `FUNDAMENTAL_DISCRIMINANT_LIMBS > 21` for the security of the class-group primitive.
        // On the other hand the randomness is taken to be `FUNDAMENTAL_DISCRIMINANT_LIMBS/2 + 4` (for computational soundness) `+ 2` (for statistical zk).
        // This is always smaller than `FUNDAMENTAL_DISCRIMINANT_LIMBS`.
        let randomness_space_public_parameters =
            RandomnessSpacePublicParameters::new_with_randomizer_upper_bound(
                randomness_sample_bits,
            )
            .map_err(|_| Error::InvalidPublicParameters)?;

        let decryption_key_sample_bits = Self::compute_decryption_key_bits(class_group_parameters)?;
        let decryption_key_public_parameters =
            DecryptionKeySpacePublicParameters::new_with_randomizer_upper_bound(
                decryption_key_sample_bits,
            )
            .map_err(|_| Error::InvalidPublicParameters)?;

        let h = class_group_parameters.h(rng)?;

        let h_accelerators = [
            randomness_space_public_parameters.sample_bits,
            randomness_space_public_parameters.sample_bits + MAURER_RANDOMIZER_DIFF_BITS,
            SECRET_KEY_SHARE_SIZE_UPPER_BOUND,
            SECRET_KEY_SHARE_SIZE_UPPER_BOUND + MAURER_RANDOMIZER_DIFF_BITS,
        ]
        .into_iter()
        .map(|target_bits| h.get_multifold_accelerator_vartime(folding_degree, target_bits))
        .collect::<crate::Result<_>>()?;

        let ec_pp = equivalence_class::PublicParameters::new_accelerated(
            class_group_parameters.delta_qk,
            HashMap::from([(*h.representative(), h_accelerators)]),
        )?;
        let ciphertext_space_public_parameters = CiphertextSpacePublicParameters::new(ec_pp);

        Ok((
            GroupsPublicParameters {
                plaintext_space_public_parameters,
                randomness_space_public_parameters,
                ciphertext_space_public_parameters,
            },
            decryption_key_public_parameters,
            h,
        ))
    }

    /// Compute the bit size of a randomizer for a class group induced by the given `discriminant`.
    ///
    /// Computed as `class_number_upper_bound::BITS + StatisticalSecuritySizedNumber::BITS + POSSIBLE_BITLOSS_FROM_TIMES_MEASUREMENTS_UPPERBOUND`
    fn compute_randomness_bits(
        class_group_parameters: &Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> Result<u32, Error> {
        Self::compute_decryption_key_bits(class_group_parameters)
    }

    /// Compute the bit size of a decryption key for a class group induced by the given `discriminant`.
    ///
    /// Computed as `class_number_upper_bound::BITS + StatisticalSecuritySizedNumber::BITS`
    fn compute_decryption_key_bits(
        class_group_parameters: &Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> Result<u32, Error> {
        minimum_discriminant_bits(class_group_parameters.computational_security_parameter)
            .map(decryption_key_size_from_fundamental_discriminant_size)
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
        let exponent_bits = Uint::<EXPONENT_LIMBS>::BITS;
        let acc = self.get_h_accelerator(exponent_bits);

        EquivalenceClass::pow_multifold_accelerated(acc, exponent)
    }

    /// Compute `h^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`.
    pub(crate) fn power_of_h_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let acc = self.get_h_accelerator(exponent_bits);

        EquivalenceClass::pow_bounded_multifold_accelerated(acc, exponent, exponent_bits)
    }

    /// Compute `h^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`.
    pub(crate) fn power_of_h_bounded_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let acc = self.get_h_accelerator(exponent_bits);

        EquivalenceClass::pow_bounded_multifold_accelerated_randomized(acc, exponent, exponent_bits)
    }

    /// Compute `h^exponent`.
    ///
    /// Function runs in time variable in `h` and `exponent`.
    pub(crate) fn power_of_h_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let exponent_bits = exponent.bits();
        let acc = self.get_h_accelerator(exponent_bits);

        EquivalenceClass::pow_multifold_accelerated_vartime(acc, exponent)
    }

    /// Compute `h^e`, with `e` the exponent represented by the `exponent_bits` least significant
    /// bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. both `h` and `exponent`.
    pub(crate) fn power_of_h_bounded_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let acc = self.get_h_accelerator(exponent_bits);

        EquivalenceClass::pow_bounded_multifold_accelerated_vartime(acc, exponent, exponent_bits)
    }

    /// Construct a triple that can be used to randomize scaling an [EquivalenceClass].
    pub(crate) fn sample_scaling_randomizer<const EXPONENT_LIMBS: usize>(
        &self,
        scalar: Uint<EXPONENT_LIMBS>,
        rng: &mut impl CsRng,
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
        rng: &mut impl CsRng,
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
        rng: &mut impl CsRng,
    ) -> Result<ScalingRandomizer<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<EXPONENT_LIMBS>: Encoding,
    {
        self.sample_bounded_scaling_randomizer(scalar, scalar.bits(), rng)
    }

    /// Obtain read-only access to the `accelerator` for `h`, or `None` if it does not exist.
    pub(crate) fn get_h_accelerator(
        &self,
        exp_bits: u32,
    ) -> &MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.equivalence_class_public_parameters()
            .get_accelerator_for(self.h.representative(), exp_bits)
            .unwrap()
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
        rng: &mut impl CsRng,
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

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
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
        rng: &mut impl CsRng,
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

        Self::new(
            class_group_parameters,
            plaintext_space_parameters,
            HIGHEST_ACCELERATOR_FOLDING_DEGREE,
            rng,
        )
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
        &self.ciphertext_space_public_parameters().0
    }

    /// The public parameters of a scalar of the same group as the decryption key.
    pub fn equivalence_class_public_parameters_mut(
        &mut self,
    ) -> &mut equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        &mut self
            .groups_public_parameters
            .ciphertext_space_public_parameters
            .0
    }

    /// The public parameters of a scalar of the same group as the decryption key.
    pub fn scalar_group_public_parameters(
        &self,
    ) -> &DecryptionKeySpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS> {
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
    ) -> &DecryptionKeySpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        &self.decryption_key_public_parameters
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
        self.randomness_space_public_parameters().sample_bits + MAURER_RANDOMIZER_DIFF_BITS
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

#[derive(Serialize)]
pub struct CanonicalSetupParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters: Transcribeable + Serialize,
> where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    pub(crate) canonical_groups_public_parameters: CanonicalGroupsPublicParameters<
        ScalarPublicParameters,
        RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    pub(crate) canonical_decryption_key_public_parameters: <DecryptionKeySpacePublicParameters<
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
    > as Transcribeable>::CanonicalRepresentation,

    // Parameters relating to the class group this instance of the encryption scheme works with.
    pub(crate) class_group_parameters: <Parameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    > as Transcribeable>::CanonicalRepresentation,

    // Parameters relating to encryption.
    // In encryption, the randomness is composed with `h` (unknown order).
    pub(crate) h: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,

    // Parameters relating to decryption
    pub(crate) large_message_variant: bool,
}

#[allow(dead_code)]
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use group::{ristretto, secp256k1, secp256r1, CsRng, OsCsRng};

    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::{
        Curve25519SetupParameters, RistrettoSetupParameters, Secp256k1SetupParameters,
        Secp256r1SetupParameters,
    };

    use super::SetupParameters;

    /// Deterministic; the `p` selected for the scheme is the same every time.
    pub fn get_setup_parameters_secp256r1_112_bits_deterministic() -> Secp256r1SetupParameters {
        SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
            secp256r1::scalar::PublicParameters::default(),
            112,
        )
        .unwrap()
    }

    /// Deterministic; the `p` selected for the scheme is the same every time.
    pub fn get_setup_parameters_secp256k1_112_bits_deterministic() -> Secp256k1SetupParameters {
        SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            112,
        )
        .unwrap()
    }

    /// Random; the `p` selected for the scheme is different every time.
    pub fn get_setup_parameters_secp256k1_112_bits_random(
        rng: &mut OsCsRng,
    ) -> Secp256k1SetupParameters {
        SetupParameters::derive_from_plaintext_parameters_random::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            112,
            rng,
        )
        .unwrap()
    }

    /// Deterministic; the `p` selected for the scheme is the same every time.
    pub fn get_setup_parameters_curve25519_112_bits_deterministic() -> Curve25519SetupParameters {
        get_setup_parameters_ristretto_112_bits_deterministic()
    }

    /// Deterministic; the `p` selected for the scheme is the same every time.
    pub fn get_setup_parameters_ristretto_112_bits_deterministic() -> RistrettoSetupParameters {
        SetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            112,
        )
        .unwrap()
    }

    /// Random; the `p` selected for the scheme is different every time.
    pub fn get_setup_parameters_ristretto_112_bits_random(
        rng: &mut impl CsRng,
    ) -> RistrettoSetupParameters {
        SetupParameters::derive_from_plaintext_parameters_random::<ristretto::Scalar>(
            ristretto::scalar::PublicParameters::default(),
            112,
            rng,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{NonZero, U1280, U2048, U320, U64};

    use group::{ristretto, secp256k1, OsCsRng};

    use crate::randomizer::ScalingRandomizer;
    use crate::setup::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::test_helpers::get_setup_parameters_ristretto_112_bits_deterministic;
    use crate::{SetupParameters, DECRYPTION_KEY_BITS_112BIT_SECURITY};
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
            &mut OsCsRng,
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
            &mut OsCsRng,
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
            "00000000000000000000000000000000000000000000000D2BB1F3C5DC9F51F3",
            "83756E9D0464477FE01B325DA603A754B2037B5303A9A0082494478C471C6975",
            "804CC0E754918F43A265EFF1AB83AF22BC037AEF7FCC34C558E38F9230CB58EC",
            "29D42226C7466BAD7490746DB9C6492CCE819F4CAD8A0D07D84C9BC42EAC0AF0",
            "F6EFB6866F87C6D56B262215C3DEF83DA9E3CA0BB069F4CE9F7C80F523264CDF"
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
            "00000000000000000000000000000000000000000000004AF663EEABD09DFD50",
            "6A9953372B3425C4DFBCD5166C42795FEAF08717409B37C2E21CC02D79D15C18",
            "1159239A9B9032353155272A35D0B5621CD541709F9915269C1B7A1FDC599628",
            "018B88A7D721108901A7BDA787D82B9ED82CFFF1F55496B7FCD3FBBB31EDDB27",
            "39032A260FF6F65A92E13595F26AA171F6AB11640A0C612244977F2B647758E7"
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
    fn test_power_of_h_bounded_vartime() {
        let sk = U320::from_be_hex(
            "2B3C901E8F2016B01DD917911C4EA3FD48EA06668EB7D2DAB2E051B9D82FB2D55D7B3F8471A2622D",
        )
        .resize::<{ U2048::LIMBS }>();
        let bound = 210;
        let bounded_sk = sk.bitand(&U2048::MAX.shr_vartime(1838));

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        assert_eq!(
            setup_parameters.power_of_h_bounded_vartime(&sk, bound),
            setup_parameters.h.pow_vartime(&bounded_sk)
        );
    }

    #[test]
    /// regression test
    fn test_power_of_h_bounded_randomized() {
        let sk = U320::from_be_hex(
            "2B3C901E8F2016B01DD917911C4EA3FD48EA06668EB7D2DAB2E051B9D82FB2D55D7B3F8471A2622D",
        )
        .resize::<{ U2048::LIMBS }>();

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        assert_eq!(
            setup_parameters.power_of_h_bounded_randomized(&sk, 320),
            setup_parameters.h.pow_vartime(&sk)
        );
    }

    #[test]
    /// regression test
    fn test_decryption_key_bits() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        assert_eq!(
            sp.decryption_key_bits(),
            sp.decryption_key_public_parameters.sample_bits
        );

        assert_eq!(
            sp.decryption_key_upper_bound_bits(),
            sp.decryption_key_public_parameters.upper_bound_bits
        );
    }

    #[test]
    fn test_decryption_key_bits_for_secp256k1() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        assert_eq!(
            sp.decryption_key_bits(),
            DECRYPTION_KEY_BITS_112BIT_SECURITY
        );
    }

    #[test]
    fn test_decryption_key_bits_for_ristretto() {
        let sp = get_setup_parameters_ristretto_112_bits_deterministic();
        assert_eq!(
            sp.decryption_key_bits(),
            DECRYPTION_KEY_BITS_112BIT_SECURITY,
        );
    }

    #[test]
    /// regression test
    fn test_scalar_bits() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();

        assert_eq!(
            sp.scalar_bits(),
            sp.decryption_key_public_parameters.sample_bits
        );

        assert_eq!(
            sp.scalar_upper_bound_bits(),
            sp.decryption_key_public_parameters.upper_bound_bits
        );
    }

    #[test]
    fn test_sample_scaling_randomizer() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let exponent = U64::from_u64(42);
        let randomizer = sp
            .sample_scaling_randomizer(exponent, &mut OsCsRng)
            .unwrap();

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
            m1.pow_bounded_with_base_randomized(m2, &exponent, scalar_bits_bound)
                .unwrap()
        );

        // Check that subsequent randomizers are different.
        let randomizer2 = sp
            .sample_scaling_randomizer(exponent, &mut OsCsRng)
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
    fn test_sample_bounded_scaling_randomizer() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let exponent = U64::from_u64(42);
        let randomizer = sp
            .sample_bounded_scaling_randomizer(exponent, exponent.bits(), &mut OsCsRng)
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
            m1.pow_bounded_with_base_randomized(m2, &exponent, scalar_bits_bound)
                .unwrap()
        );

        // Check that subsequent randomizers are different.
        let randomizer2 = sp
            .sample_bounded_scaling_randomizer(exponent, exponent.bits(), &mut OsCsRng)
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
            .sample_vartime_scaling_randomizer(exponent, &mut OsCsRng)
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
            m1.pow_bounded_with_base_randomized(m2, &exponent, scalar_bits_bound)
                .unwrap()
        );

        // Check that subsequent randomizers are different.
        let randomizer2 = sp
            .sample_scaling_randomizer(exponent, &mut OsCsRng)
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
}
