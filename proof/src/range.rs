// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;

use merlin::Transcript;

use serde::{Deserialize, Serialize};

use commitment::{GroupsPublicParametersAccessors, HomomorphicCommitmentScheme};
use group::{self_product, CsRng, NumbersGroupElement, Transcribeable};

#[cfg(feature = "bulletproofs")]
pub mod bulletproofs;

/// A range proof over `Self::CommitmentScheme`, capable of proving `Self::RANGE_CLAIM_BITS` bits.
pub trait RangeProof<
    // The commitment scheme's message space scalar size in limbs
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
>: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Debug + Eq + Send + Sync
{
    /// A unique string representing the name of this range proof; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// The number of bits this proof proves for every witness.
    const RANGE_CLAIM_BITS: u32;

    /// An element of the group from which the range proof's commitment scheme message space is composed,
    /// used to prove a single range claim.
    type RangeClaimGroupElement: NumbersGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS> + Copy;

    /// The commitment scheme used for the range proof
    type CommitmentScheme<const NUM_RANGE_CLAIMS: usize>: HomomorphicCommitmentScheme<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, MessageSpaceGroupElement=self_product::GroupElement<NUM_RANGE_CLAIMS, Self::RangeClaimGroupElement>>;

    /// The public parameters of the range proof.
    ///
    /// Includes the public parameters of the commitment scheme,
    /// and any range of claims if the scheme permits such.
    ///
    /// SECURITY NOTE: Needs to be inserted to the Fiat-Shamir Transcript of the proof protocol.
    type PublicParameters<const NUM_RANGE_CLAIMS: usize>: AsRef<
        commitment::PublicParameters<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme<NUM_RANGE_CLAIMS>>
    > + Transcribeable + Serialize
    + for<'r> Deserialize<'r>
    + Clone
    + PartialEq + Eq + Debug + Send + Sync;

    /// Proves in zero-knowledge that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn prove<const NUM_RANGE_CLAIMS: usize>(
        public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        witnesses: Vec<CommitmentSchemeMessageSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        commitments_randomness: Vec<CommitmentSchemeRandomnessSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        transcript: Transcript,
        rng: &mut impl CsRng,
    ) -> crate::Result<(Self, Vec<commitment::CommitmentSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, Self::CommitmentScheme<NUM_RANGE_CLAIMS>>>)>;

    /// Verifies that all witnesses committed in `commitment` are bounded by their corresponding
    /// range upper bound in range_claims.
    fn verify<const NUM_RANGE_CLAIMS: usize>(
        &self,
        public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        commitments: Vec<CommitmentSchemeCommitmentSpaceGroupElement<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, NUM_RANGE_CLAIMS, Self>>,
        transcript: Transcript,
        rng: &mut impl CsRng,
    ) -> crate::Result<()>;
}

pub trait PublicParametersAccessors<
    'a,
    const NUM_RANGE_CLAIMS: usize,
    RangeClaimPublicParameters: 'a,
    RandomnessSpacePublicParameters: 'a,
    CommitmentSpacePublicParameters: 'a,
    CommitmentSchemePublicParameters: 'a,
>: AsRef<CommitmentSchemePublicParameters> where
    CommitmentSchemePublicParameters: AsRef<
        commitment::GroupsPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    >,
{
    fn commitment_scheme_public_parameters(&'a self) -> &'a CommitmentSchemePublicParameters {
        self.as_ref()
    }

    fn range_claim_public_parameters(&'a self) -> &'a RangeClaimPublicParameters {
        &self
            .commitment_scheme_public_parameters()
            .message_space_public_parameters()
            .0
    }
}

impl<
        'a,
        const NUM_RANGE_CLAIMS: usize,
        RangeClaimPublicParameters: 'a,
        RandomnessSpacePublicParameters: 'a,
        CommitmentSpacePublicParameters: 'a,
        CommitmentSchemePublicParameters: 'a,
        T: AsRef<CommitmentSchemePublicParameters>,
    >
    PublicParametersAccessors<
        'a,
        NUM_RANGE_CLAIMS,
        RangeClaimPublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
        CommitmentSchemePublicParameters,
    > for T
where
    CommitmentSchemePublicParameters: AsRef<
        commitment::GroupsPublicParameters<
            self_product::PublicParameters<NUM_RANGE_CLAIMS, RangeClaimPublicParameters>,
            RandomnessSpacePublicParameters,
            CommitmentSpacePublicParameters,
        >,
    >,
{
}

pub type PublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::PublicParameters<
    NUM_RANGE_CLAIMS,
>;

pub type CommitmentScheme<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
    NUM_RANGE_CLAIMS,
>;

pub type RangeClaimGroupElement<const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize, Proof> =
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::RangeClaimGroupElement;

pub type CommitmentSchemePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::PublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::MessageSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::MessageSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeMessageSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::MessageSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::RandomnessSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::RandomnessSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeRandomnessSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::RandomnessSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpaceGroupElement<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::CommitmentSpaceGroupElement<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpacePublicParameters<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::CommitmentSpacePublicParameters<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;

pub type CommitmentSchemeCommitmentSpaceValue<
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    Proof,
> = commitment::CommitmentSpaceValue<
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    <Proof as RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentScheme<
        NUM_RANGE_CLAIMS,
    >,
>;
