// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;
use std::fmt::Debug;

use crypto_bigint::rand_core::CryptoRngCore;
use serde::Serialize;

use commitment::Commitment;
use group::{PartyID, Samplable};
use proof::{range, AggregatableRangeProof};

use crate::{
    aggregation::{proof_share_round, Output},
    EnhanceableLanguage, EnhancedLanguage, Error, Result,
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
    pub(super) party_id: PartyID,
    pub(super) maurer_decommitment_round_party: maurer::aggregation::decommitment_round::Party<
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
    pub(super) range_proof_decommitment_round_party: range::DecommitmentRoundParty<
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
    >,
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
    proof::aggregation::DecommitmentRoundParty<
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

    type Decommitment = (
        maurer::aggregation::Decommitment<
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
        range::Decommitment<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >,
    );

    type ProofShareRoundParty = proof_share_round::Party<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >;

    fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Self::Commitment>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Decommitment, Self::ProofShareRoundParty)> {
        let (maurer_commitments, range_proof_commitments) = commitments
            .into_iter()
            .map(|(party_id, (maurer_commitment, range_proof_commitment))| {
                (
                    (party_id, maurer_commitment),
                    (party_id, range_proof_commitment),
                )
            })
            .unzip();

        let (maurer_decommitment, maurer_proof_share_round_party) = self
            .maurer_decommitment_round_party
            .decommit_statements_and_statement_mask(maurer_commitments, rng)?;

        let (range_proof_decommitment, range_proof_proof_share_round_party) = self
            .range_proof_decommitment_round_party
            .decommit_statements_and_statement_mask(range_proof_commitments, rng)?;

        let proof_share_round_party = proof_share_round::Party {
            party_id: self.party_id,
            maurer_proof_share_round_party,
            range_proof_proof_share_round_party,
        };

        Ok((
            (maurer_decommitment, range_proof_decommitment),
            proof_share_round_party,
        ))
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
    range::DecommitmentRoundParty<
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
    >: Clone,
{
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            maurer_decommitment_round_party: self.maurer_decommitment_round_party.clone(),
            range_proof_decommitment_round_party: self.range_proof_decommitment_round_party.clone(),
        }
    }
}
