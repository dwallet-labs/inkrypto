// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use core::{array, marker::PhantomData};

use crypto_bigint::{rand_core::CryptoRngCore, CheckedMul, Uint, U64};
use serde::Serialize;

use commitment::{GroupsPublicParametersAccessors as _, HomomorphicCommitmentScheme};
use group::{
    direct_product, helpers::FlatMapResults, self_product, BoundedGroupElement,
    ComputationalSecuritySizedNumber, GroupElement, KnownOrderGroupElement, KnownOrderScalar,
    PartyID, Samplable, StatisticalSecuritySizedNumber,
};
use mpc::secret_sharing::shamir::Polynomial;
use proof::range::{
    CommitmentSchemeCommitmentSpaceGroupElement, CommitmentSchemeCommitmentSpacePublicParameters,
    CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemePublicParameters,
    CommitmentSchemeRandomnessSpaceGroupElement, CommitmentSchemeRandomnessSpacePublicParameters,
    PublicParametersAccessors,
};
use proof::{GroupsPublicParameters, GroupsPublicParametersAccessors};

use crate::{Error, Result};

/// An Enhanced Maurer Zero-Knowledge Proof Language.
///
/// Can be generically used to generate a batched Maurer zero-knowledge `Proof` with range claims.
/// As defined in Section 4. Enhanced Batch Schnorr Protocols in the paper "2PC-MPC: Threshold ECDSA
/// with Thousands of Parties".
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnhancedLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> {
    _unbounded_witness_choice: PhantomData<UnboundedWitnessSpaceGroupElement>,
    _language_choice: PhantomData<Language>,
    _range_proof_choice: PhantomData<RangeProof>,
}

/// An Enhanceable Maurer Language.
///
/// By itself implements the `maurer::Language` trait, although it might not be a valid
/// language with no range claims. Defines transition methods to compose and decompose its witness
/// from and to what we call a _decomposed witness_, which is a list of range claims over the range
/// proof's commitment scheme message space.
///
/// Essentially, if a witness is bigger than the size of the range-proof commitment scheme
/// message space; it is broken-down (decomposed) into multiple smaller range claims that do fit in
/// the commitment. This is done by viewing the witness w in base \Delta such that
/// w=\sum_{i}{w_i}\Delta^i, with /// \Delta \ll \abs{\calM_\pp}.
/// The decomposed witness (w_i)_i can then be composed back into w.
pub trait EnhanceableLanguage<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    UnboundedWitnessSpaceGroupElement: GroupElement + Samplable,
>: maurer::Language<REPETITIONS>
{
    /// Compose a language witness from the message of a corresponding commitment.
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        unbounded_witness: UnboundedWitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<Self::WitnessSpaceGroupElement>;

    /// Decompose a language witness to a message of a commitment on which a range proof can be
    /// formed.
    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        UnboundedWitnessSpaceGroupElement,
    )>;

    /// A helper function for validation of the group element order, that should occur inside
    /// `compose_witness` and `decompose_witness`. The group element order isn't available to the
    /// enhanced language, as it is language dependent, but in practice some enhanceable languages
    /// require this check for correctness, so we provide this helper function.
    fn valid_group_order<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    >(
        range_claim_bits: u32,
        group_public_parameters: &GroupElement::PublicParameters,
    ) -> maurer::Result<()> {
        let commitment_message_space_lower_bound = commitment_message_space_lower_bound::<
            RANGE_CLAIMS_PER_SCALAR,
            SCALAR_LIMBS,
        >(true, range_claim_bits)
        .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let order = GroupElement::order_from_public_parameters(group_public_parameters);

        if order <= commitment_message_space_lower_bound {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        Ok(())
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    > maurer::Language<REPETITIONS>
    for EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
{
    type WitnessSpaceGroupElement = direct_product::ThreeWayGroupElement<
        CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        CommitmentSchemeRandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        UnboundedWitnessSpaceGroupElement,
    >;

    type StatementSpaceGroupElement = direct_product::GroupElement<
        CommitmentSchemeCommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        Language::StatementSpaceGroupElement,
    >;

    type PublicParameters = PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        group::PublicParameters<RangeProof::RangeClaimGroupElement>,
        CommitmentSchemeRandomnessSpacePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        CommitmentSchemeCommitmentSpacePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
        RangeProof::PublicParameters<NUM_RANGE_CLAIMS>,
        UnboundedWitnessSpaceGroupElement::PublicParameters,
        group::PublicParameters<Language::StatementSpaceGroupElement>,
        Language::PublicParameters,
    >;

    const NAME: &'static str = Language::NAME;

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &Self::PublicParameters,
    ) -> maurer::Result<Self::StatementSpaceGroupElement> {
        let decomposed_witness: [_; NUM_RANGE_CLAIMS] =
            (*witness.range_proof_commitment_message()).into();

        let decomposed_witness = decomposed_witness
            .map(Into::<Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::into);

        let language_witness = Language::compose_witness(
            decomposed_witness,
            *witness.unbounded_witness(),
            &enhanced_language_public_parameters.language_public_parameters,
            RangeProof::RANGE_CLAIM_BITS,
        )?;

        let language_statement = Language::homomorphose(
            &language_witness,
            &enhanced_language_public_parameters.language_public_parameters,
        )?;

        let commitment_scheme = RangeProof::CommitmentScheme::new(
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters(),
        )
        .map_err(|_| maurer::Error::InvalidPublicParameters)?;

        let commitment_message_value =
            <[_; NUM_RANGE_CLAIMS]>::from(witness.range_proof_commitment_message().value()).into();

        let commitment_message = CommitmentSchemeMessageSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::new(
            commitment_message_value,
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .message_space_public_parameters(),
        )?;

        let range_proof_commitment = commitment_scheme.commit(
            &commitment_message,
            witness.range_proof_commitment_randomness(),
        );

        Ok((range_proof_commitment, language_statement).into())
    }
}

/// Compute the upper bound over the composed witness for which we proved range claims:
/// $$ \log_2(\hat{\delta}) + (d-1) \cdot \log_2(\delta) + 1 $$
pub fn composed_witness_upper_bound<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const UPPER_BOUND_LIMBS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
>() -> Result<Uint<UPPER_BOUND_LIMBS>> {
    let delta_bits = RangeProof::RANGE_CLAIM_BITS;

    // Account for aggregation: $$ \hat{\Delta} = \Delta \cdot n_{max} $$.
    let delta_hat_bits = PartyID::BITS.checked_add(delta_bits);

    // $$ (d-1) \cdot \log_2(\delta) $$
    let num_range_claims_minus_one_by_delta_bits = (RANGE_CLAIMS_PER_SCALAR as u32)
        .checked_sub(1)
        .and_then(|num_range_claims_minus_one| num_range_claims_minus_one.checked_mul(delta_bits))
        .ok_or(Error::InvalidPublicParameters)?;

    let upper_bound_bits = delta_hat_bits
        .and_then(|bits| bits.checked_add(num_range_claims_minus_one_by_delta_bits))
        .and_then(|bits| bits.checked_add(1))
        .ok_or(Error::InvalidPublicParameters)?;

    if upper_bound_bits >= Uint::<UPPER_BOUND_LIMBS>::BITS {
        return Err(Error::InvalidPublicParameters);
    }

    Ok(Uint::<UPPER_BOUND_LIMBS>::ONE << upper_bound_bits)
}

/// Compute $$\Delta \cdot n_{max} \cdot d \cdot (\ell + \ell_\omega)
/// \cdot 2^{\kappa+s+1} $$.
pub(crate) fn commitment_message_space_lower_bound<
    const NUM_RANGE_CLAIMS: usize,
    const SCALAR_LIMBS: usize,
>(
    account_for_aggregation: bool,
    range_claim_bits: u32,
) -> Result<Uint<SCALAR_LIMBS>> {
    let delta_hat_bits = if account_for_aggregation {
        PartyID::BITS
            .checked_add(range_claim_bits)
            .ok_or(Error::InvalidPublicParameters)?
    } else {
        range_claim_bits
    };

    if SCALAR_LIMBS <= ComputationalSecuritySizedNumber::LIMBS
        || SCALAR_LIMBS <= StatisticalSecuritySizedNumber::LIMBS
        || range_claim_bits == 0
        || Uint::<SCALAR_LIMBS>::BITS <= delta_hat_bits
    {
        return Err(Error::InvalidPublicParameters);
    }

    // $$ \hat{\Delta} = \Delta \cdot n_{max} $$.
    let delta_hat: Uint<SCALAR_LIMBS> = Uint::<SCALAR_LIMBS>::ONE << delta_hat_bits;

    let number_of_range_claims =
        U64::from(u64::try_from(NUM_RANGE_CLAIMS).map_err(|_| Error::InvalidPublicParameters)?);

    Option::from(
        delta_hat
            .checked_mul(&number_of_range_claims)
            .and_then(|bound| {
                bound.checked_mul(
                    &(Uint::<SCALAR_LIMBS>::ONE << ComputationalSecuritySizedNumber::BITS),
                )
            })
            .and_then(|bound| {
                bound.checked_mul(
                    &(Uint::<SCALAR_LIMBS>::ONE << StatisticalSecuritySizedNumber::BITS),
                )
            })
            .and_then(|bound| {
                // Account for the $$ +1 $$ in $$ 2^{\kappa+s+1} $$.
                bound.checked_mul(&Uint::<SCALAR_LIMBS>::from(2u8))
            }),
    )
    .ok_or(Error::InvalidPublicParameters)
}

pub trait DecomposableWitness<
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const WITNESS_LIMBS: usize,
>: KnownOrderScalar<WITNESS_LIMBS>
{
    fn valid_parameters(range_claim_bits: u32) -> maurer::Result<()> {
        if range_claim_bits == 0 || RANGE_CLAIMS_PER_SCALAR == 0 {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        // Check that the witness is big enough to hold the range claim representation of the
        // scalar, which is the number of range claims per scalar times the number of bits per
        // claim.
        let witness_too_small_for_scalar_range_claim_representation = range_claim_bits
            .checked_mul(RANGE_CLAIMS_PER_SCALAR as u32)
            .map(|witness_in_range_claims_bits| {
                Uint::<WITNESS_LIMBS>::BITS <= witness_in_range_claims_bits
            })
            .unwrap_or(true);

        if witness_too_small_for_scalar_range_claim_representation
            || Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS <= range_claim_bits
        {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        if WITNESS_LIMBS <= COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        Ok(())
    }

    fn decompose(
        self,
        range_claim_bits: u32,
    ) -> maurer::Result<[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR]>
    {
        Self::valid_parameters(range_claim_bits)?;

        let witness: Uint<WITNESS_LIMBS> = self.into();

        let mask = (Uint::<WITNESS_LIMBS>::ONE << range_claim_bits)
            .wrapping_sub(&Uint::<WITNESS_LIMBS>::ONE);

        Ok(array::from_fn(|i| {
            Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::from(
                &((witness >> ((i as u32) * range_claim_bits)) & mask),
            )
        }))
    }

    fn compose(
        decomposed_witness: &[Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
             RANGE_CLAIMS_PER_SCALAR],
        public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<Self> {
        Self::valid_parameters(range_claim_bits)?;

        let delta: Uint<WITNESS_LIMBS> = Uint::<WITNESS_LIMBS>::ONE << range_claim_bits;
        let delta = Self::new(delta.into(), public_parameters)?;

        let decomposed_witness = decomposed_witness
            .iter()
            .map(|witness| {
                Self::new(
                    Uint::<WITNESS_LIMBS>::from(&Uint::<
                        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    >::from(witness))
                    .into(),
                    public_parameters,
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        // Check that the polynomial evaluation will not go through a modulation.
        // We check against an upper bound, computed in logarithmic form to get an upper bound on
        // the bits. The upper bound logic is as follows: for $P(x) = a_0 + ... + a_l * x^l$,
        // $P(x)$ is bounded by $2 * a_l * x^l$, and the log of that is $1 + log(a_l) + l*log(x)$.
        // For $x = \Delta$, $log(\Delta)$ is range_claim_bits. The coefficients $a_i$ are bounded
        // by `Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS`.

        // $$ (d-1) \cdot \log_2(\delta) $$
        let num_range_claims_minus_one_by_delta_bits = (RANGE_CLAIMS_PER_SCALAR as u32)
            .checked_sub(1)
            .and_then(|num_range_claims_minus_one| {
                num_range_claims_minus_one.checked_mul(range_claim_bits)
            })
            .ok_or(maurer::Error::InvalidPublicParameters)?;

        let upper_bound_bits = num_range_claims_minus_one_by_delta_bits
            .checked_add(Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS)
            .and_then(|bits| bits.checked_add(1))
            .ok_or(maurer::Error::InvalidPublicParameters)?;

        if Uint::<WITNESS_LIMBS>::BITS <= upper_bound_bits {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        let polynomial = Polynomial::try_from(decomposed_witness)
            .map_err(|_| maurer::Error::InvalidParameters)?;

        Ok(polynomial.evaluate(&delta))
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const WITNESS_LIMBS: usize,
        Witness: KnownOrderScalar<WITNESS_LIMBS>,
    >
    DecomposableWitness<
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        WITNESS_LIMBS,
    > for Witness
{
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    >
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >
{
    pub fn generate_witness(
        witness: Language::WitnessSpaceGroupElement,
        enhanced_language_public_parameters: &maurer::language::PublicParameters<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        maurer::language::WitnessSpaceGroupElement<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    > {
        let (decomposed_witness, unbounded_element) = Language::decompose_witness(
            witness,
            &enhanced_language_public_parameters.language_public_parameters,
            RangeProof::RANGE_CLAIM_BITS,
        )?;

        let range_proof_commitment_message = decomposed_witness
            .map(group::Value::<RangeProof::RangeClaimGroupElement>::from)
            .map(|value| {
                RangeProof::RangeClaimGroupElement::new(
                    value,
                    enhanced_language_public_parameters
                        .range_proof_public_parameters
                        .range_claim_public_parameters(),
                )
            })
            .flat_map_results()?
            .into();

        let commitment_randomness = CommitmentSchemeRandomnessSpaceGroupElement::<
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::sample(
            enhanced_language_public_parameters
                .range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .randomness_space_public_parameters(),
            rng,
        )?;

        Ok((
            range_proof_commitment_message,
            commitment_randomness,
            unbounded_element,
        )
            .into())
    }

    pub fn generate_witnesses(
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        enhanced_language_public_parameters: &maurer::language::PublicParameters<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        Vec<
            maurer::language::WitnessSpaceGroupElement<
                REPETITIONS,
                EnhancedLanguage<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Language,
                >,
            >,
        >,
    > {
        witnesses
            .into_iter()
            .map(|witness| {
                Self::generate_witness(witness, enhanced_language_public_parameters, rng)
            })
            .collect::<Result<Vec<_>>>()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Eq)]
pub struct PublicParameters<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeClaimPublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    RangeProofPublicParameters,
    UnboundedWitnessSpacePublicParameters,
    LanguageStatementSpacePublicParameters,
    LanguagePublicParameters,
> {
    groups_public_parameters: GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CommitmentSpacePublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    >,
    pub range_proof_public_parameters: RangeProofPublicParameters,
    pub language_public_parameters: LanguagePublicParameters,
    // This is just a string saying "enhanced", the idea is we want to add that to the transcript.
    enhanced_string_for_fiat_shamir: String,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeClaimPublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CommitmentSpacePublicParameters: Clone,
        RangeProofPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters: Clone,
        LanguagePublicParameters,
    >
    PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        RangeProofPublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
{
    pub fn new<RangeProof, UnboundedWitnessSpaceGroupElement, Language>(
        unbounded_witness_public_parameters: UnboundedWitnessSpacePublicParameters,
        range_proof_public_parameters: RangeProofPublicParameters,
        language_public_parameters: LanguagePublicParameters,
    ) -> Result<Self>
    where
        RangeProof: proof::RangeProof<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            PublicParameters<NUM_RANGE_CLAIMS> = RangeProofPublicParameters,
        >,
        CommitmentSchemeRandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentSchemeCommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        RangeProof::RangeClaimGroupElement:
            GroupElement<PublicParameters = RangeClaimPublicParameters>,
        CommitmentSchemePublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >: AsRef<
            commitment::GroupsPublicParameters<
                self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
        RangeProofPublicParameters: AsRef<
            CommitmentSchemePublicParameters<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >,
        >,
        UnboundedWitnessSpaceGroupElement:
            GroupElement<PublicParameters = UnboundedWitnessSpacePublicParameters>,
        Language: maurer::Language<REPETITIONS, PublicParameters = LanguagePublicParameters>,
        LanguagePublicParameters: AsRef<
            GroupsPublicParameters<
                group::PublicParameters<Language::WitnessSpaceGroupElement>,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    {
        // We require $$ |\calM_\pp| > \Delta \cdot n_{max} \cdot d \cdot (\ell + \ell_\omega)
        //     // \cdot 2^{\kappa+s+1} $$.
        //
        // In practice, we allow working over bounded groups of unknown order, in which case we use
        // a lower bound on the group order to perform this check.

        let order_lower_bound = CommitmentSchemeMessageSpaceGroupElement::<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >::lower_bound(
            range_proof_public_parameters
                .commitment_scheme_public_parameters()
                .message_space_public_parameters(),
        );

        let commitment_message_space_lower_bound = commitment_message_space_lower_bound::<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        >(true, RangeProof::RANGE_CLAIM_BITS)?;

        if order_lower_bound <= commitment_message_space_lower_bound {
            return Err(Error::InvalidPublicParameters);
        }

        Ok(Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .message_space_public_parameters()
                        .clone(),
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .randomness_space_public_parameters()
                        .clone(),
                    unbounded_witness_public_parameters,
                )
                    .into(),
                statement_space_public_parameters: (
                    range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .commitment_space_public_parameters()
                        .clone(),
                    language_public_parameters
                        .statement_space_public_parameters()
                        .clone(),
                )
                    .into(),
            },
            range_proof_public_parameters,
            language_public_parameters,
            enhanced_string_for_fiat_shamir: "enhanced".to_string(),
        })
    }

    pub fn unbounded_witness_public_parameters(&self) -> &UnboundedWitnessSpacePublicParameters {
        let (_, _, unbounded_witness_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        unbounded_witness_public_parameters
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::ThreeWayPublicParameters<
                self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
                RandomnessSpacePublicParameters,
                UnboundedWitnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CommitmentSpacePublicParameters,
                LanguageStatementSpacePublicParameters,
            >,
        >,
    >
    for PublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
        UnboundedWitnessSpacePublicParameters,
        LanguageStatementSpacePublicParameters,
        LanguagePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::ThreeWayPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            UnboundedWitnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CommitmentSpacePublicParameters,
            LanguageStatementSpacePublicParameters,
        >,
    > {
        &self.groups_public_parameters
    }
}

pub trait EnhancedLanguageWitnessAccessors<
    MessageSpaceGroupElement: GroupElement,
    RandomnessSpaceGroupElement: GroupElement,
    UnboundedWitnessSpaceGroupElement: GroupElement,
>
{
    fn range_proof_commitment_message(&self) -> &MessageSpaceGroupElement;

    fn range_proof_commitment_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement;
}

impl<
        MessageSpaceGroupElement: GroupElement,
        RandomnessSpaceGroupElement: GroupElement,
        UnboundedWitnessSpaceGroupElement: GroupElement,
    >
    EnhancedLanguageWitnessAccessors<
        MessageSpaceGroupElement,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
    for direct_product::ThreeWayGroupElement<
        MessageSpaceGroupElement,
        RandomnessSpaceGroupElement,
        UnboundedWitnessSpaceGroupElement,
    >
{
    fn range_proof_commitment_message(&self) -> &MessageSpaceGroupElement {
        let (range_proof_commitment_message, ..): (_, _, _) = self.into();

        range_proof_commitment_message
    }

    fn range_proof_commitment_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness, _) = self.into();

        randomness
    }

    fn unbounded_witness(&self) -> &UnboundedWitnessSpaceGroupElement {
        let (_, _, unbounded_witness) = self.into();

        unbounded_witness
    }
}

pub trait EnhancedLanguageStatementAccessors<
    CommitmentSpaceGroupElement: GroupElement,
    LanguageStatementSpaceGroupElement: GroupElement,
>
{
    fn range_proof_commitment(&self) -> &CommitmentSpaceGroupElement;

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement;
}

impl<
        CommitmentSpaceGroupElement: GroupElement,
        LanguageStatementSpaceGroupElement: GroupElement,
    >
    EnhancedLanguageStatementAccessors<
        CommitmentSpaceGroupElement,
        LanguageStatementSpaceGroupElement,
    >
    for direct_product::GroupElement<
        CommitmentSpaceGroupElement,
        LanguageStatementSpaceGroupElement,
    >
{
    fn range_proof_commitment(&self) -> &CommitmentSpaceGroupElement {
        let (range_proof_commitment, _) = self.into();

        range_proof_commitment
    }

    fn language_statement(&self) -> &LanguageStatementSpaceGroupElement {
        let (_, language_statement) = self.into();

        language_statement
    }
}

pub type EnhancedPublicParameters<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = maurer::language::PublicParameters<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

pub type WitnessSpaceGroupElement<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = maurer::language::WitnessSpaceGroupElement<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

pub type StatementSpaceGroupElement<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
> = maurer::language::StatementSpaceGroupElement<
    REPETITIONS,
    EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >,
>;

#[cfg(test)]
pub(crate) mod tests {
    use crypto_bigint::U256;
    use rand_core::OsRng;

    use group::secp256k1;
    use homomorphic_encryption::GroupsPublicParametersAccessors;
    use proof::{
        range,
        range::bulletproofs::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS},
    };
    use tiresias::test_helpers::N;

    use super::*;

    pub const RANGE_CLAIMS_PER_SCALAR: usize =
        Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS as usize / RANGE_CLAIM_BITS;

    pub(super) type EnhancedLang<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement,
        Lang,
    > = EnhancedLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
        range::bulletproofs::RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Lang,
    >;

    pub(crate) fn generate_scalar_plaintext() -> tiresias::PlaintextSpaceGroupElement {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let scalar =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        tiresias::PlaintextSpaceGroupElement::new(
            Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(&U256::from(scalar.value())),
            paillier_public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap()
    }

    pub(crate) fn enhanced_language_public_parameters<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
    ) -> maurer::language::PublicParameters<
        REPETITIONS,
        EnhancedLang<REPETITIONS, NUM_RANGE_CLAIMS, UnboundedWitnessSpaceGroupElement, Lang>,
    > {
        PublicParameters::new::<
            range::bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            range::bulletproofs::PublicParameters::default(),
            language_public_parameters,
        )
        .unwrap()
    }
}
