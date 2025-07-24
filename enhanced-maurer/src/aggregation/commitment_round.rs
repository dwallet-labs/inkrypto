// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashSet;
use std::fmt::Debug;

use serde::Serialize;

use commitment::Commitment;
use group::{CsRng, PartyID, Samplable};
use proof::{range, AggregatableRangeProof};

use crate::{
    aggregation::{decommitment_round, Output},
    language::{
        EnhancedLanguageWitnessAccessors, EnhancedPublicParameters, WitnessSpaceGroupElement,
    },
    EnhanceableLanguage, EnhancedLanguage, Error, Proof, Result,
};

pub struct Party<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
    UnboundedWitnessSpaceGroupElement: Samplable,
    Language: EnhanceableLanguage<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        UnboundedWitnessSpaceGroupElement,
    >,
    ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
> {
    party_id: PartyID,
    maurer_commitment_round_party: maurer::aggregation::commitment_round::Party<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >,
    pub(super) range_proof_commitment_round_party:
        RangeProof::AggregationCommitmentRoundParty<NUM_RANGE_CLAIMS>,
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    >
    proof::aggregation::CommitmentRoundParty<
        Output<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >,
    >
    for Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
where
    Error: From<
        range::AggregationError<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >,
    >,
{
    type Error = Error;
    type Commitment = (
        Commitment,
        range::Commitment<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >,
    );

    type DecommitmentRoundParty = decommitment_round::Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >;

    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CsRng,
    ) -> Result<(Self::Commitment, Self::DecommitmentRoundParty)> {
        let (maurer_commitment, maurer_decommitment_round_party) = self
            .maurer_commitment_round_party
            .commit_statements_and_statement_mask(rng)?;

        let (range_proof_commitment, range_proof_decommitment_round_party) = self
            .range_proof_commitment_round_party
            .commit_statements_and_statement_mask(rng)?;

        let decommitment_round_party = decommitment_round::Party {
            party_id: self.party_id,
            maurer_decommitment_round_party,
            range_proof_decommitment_round_party,
        };

        Ok((
            (maurer_commitment, range_proof_commitment),
            decommitment_round_party,
        ))
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        UnboundedWitnessSpaceGroupElement: Samplable,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    >
    Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    pub fn new_session(
        party_id: PartyID,
        provers: HashSet<PartyID>,
        language_public_parameters: EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        protocol_context: ProtocolContext,
        witnesses: Vec<
            WitnessSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<Self> {
        let (commitment_messages, commitment_randomnesses): (Vec<_>, Vec<_>) = witnesses
            .clone()
            .into_iter()
            .map(|witness| {
                (
                    *witness.range_proof_commitment_message(),
                    *witness.range_proof_commitment_randomness(),
                )
            })
            .unzip();

        let initial_transcript = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >::setup_range_proof(
            &protocol_context,
            &language_public_parameters.range_proof_public_parameters,
        )?;

        let range_proof_commitment_round_party = RangeProof::new_session(
            party_id,
            provers.clone(),
            initial_transcript,
            &language_public_parameters.range_proof_public_parameters,
            commitment_messages,
            commitment_randomnesses,
        );

        let (randomizers, statement_masks) =
            Proof::<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
                ProtocolContext,
            >::sample_randomizers_and_statement_masks(&language_public_parameters, rng)?;

        let maurer_commitment_round_party = maurer::aggregation::commitment_round::Party {
            party_id,
            provers,
            language_public_parameters,
            protocol_context,
            witnesses,
            randomizers,
            statement_masks,
        };

        Ok(Self {
            party_id,
            maurer_commitment_round_party,
            range_proof_commitment_round_party,
        })
    }
}

#[cfg(test)]
impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > Clone
    for Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
where
    RangeProof::AggregationCommitmentRoundParty<NUM_RANGE_CLAIMS>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            maurer_commitment_round_party: self.maurer_commitment_round_party.clone(),
            range_proof_commitment_round_party: self.range_proof_commitment_round_party.clone(),
        }
    }
}
