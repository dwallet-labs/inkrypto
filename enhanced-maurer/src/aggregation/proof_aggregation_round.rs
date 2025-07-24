// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;
use std::fmt::Debug;

use serde::Serialize;

use group::helpers::DeduplicateAndSort;
use group::{CsRng, PartyID, Samplable};
use proof::{aggregation, range, AggregatableRangeProof};

use crate::{
    aggregation::Output, language::EnhancedLanguageStatementAccessors, EnhanceableLanguage,
    EnhancedLanguage, Error, Proof,
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
    pub maurer_proof_aggregation_round_party: maurer::aggregation::proof_aggregation_round::Party<
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
    pub(super) range_proof_proof_aggregation_round_party: range::ProofAggregationRoundParty<
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
    proof::aggregation::ProofAggregationRoundParty<
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

    type ProofShare = (
        maurer::aggregation::ProofShare<
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
        range::ProofShare<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >,
    );

    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        rng: &mut impl CsRng,
    ) -> Result<
        Output<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
            ProtocolContext,
        >,
        Self::Error,
    > {
        let (maurer_proof_shares, range_proof_proof_shares): (HashMap<_, _>, HashMap<_, _>) =
            proof_shares
                .into_iter()
                .map(
                    |(party_id, (maurer_proof_share, range_proof_proof_share))| {
                        (
                            (party_id, maurer_proof_share),
                            (party_id, range_proof_proof_share),
                        )
                    },
                )
                .unzip();

        let maurer_individual_commitments: HashMap<_, Vec<_>> = self
            .maurer_proof_aggregation_round_party
            .statements
            .clone()
            .into_iter()
            .map(|(party_id, statements)| {
                (
                    party_id,
                    statements
                        .into_iter()
                        .map(|statement| *statement.range_proof_commitment())
                        .collect(),
                )
            })
            .collect();

        let (maurer_proof, maurer_statements) = self
            .maurer_proof_aggregation_round_party
            .aggregate_proof_shares(maurer_proof_shares.clone(), rng)?;

        let range_proof_individual_commitments = RangeProof::individual_commitments(
            &self.range_proof_proof_aggregation_round_party,
            maurer_statements.len(),
        )?;

        let (range_proof, range_proof_commitments) = self
            .range_proof_proof_aggregation_round_party
            .aggregate_proof_shares(range_proof_proof_shares, rng)?;

        let maurer_range_proof_commitments: Vec<_> = maurer_statements
            .iter()
            .map(|statement| *statement.range_proof_commitment())
            .collect();

        if range_proof_commitments != maurer_range_proof_commitments {
            let malicious_parties: Vec<_> = range_proof_individual_commitments
                .into_iter()
                .filter(|(party_id, _)| *party_id != self.party_id)
                .filter(|(party_id, range_proof_commitments)| {
                    // Same parties participating in all rounds in both protocols, safe to
                    // `.unwrap()`.
                    maurer_individual_commitments
                        .get(party_id)
                        .map(|maurer_commitments| range_proof_commitments != maurer_commitments)
                        .unwrap()
                })
                .map(|(party_id, _)| party_id)
                .deduplicate_and_sort();

            let malicious_parties = if malicious_parties.is_empty() {
                vec![self.party_id]
            } else {
                malicious_parties
            };

            return Err(Error::MismatchingRangeProofMaurerCommitments(
                malicious_parties,
            ));
        }

        // Range check:
        // Z < delta_hat * NUM_CONSTRAINED_WITNESS * (2^(kappa+s+1)
        // $$ Z < \Delta \cdot n_{max} \cdot d \cdot (\ell + \ell_\omega) \cdot 2^{\kappa+s+1} $$
        let aggregated_bound = crate::language::commitment_message_space_lower_bound::<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        >(true, RangeProof::RANGE_CLAIM_BITS)?;

        if !maurer_proof.responses.into_iter().all(|response| {
            let (commitment_message, ..): (_, _) = response.into();
            let (commitment_message, _) = commitment_message.into();

            <[_; NUM_RANGE_CLAIMS]>::from(commitment_message)
                .into_iter()
                .all(|range_claim| range_claim.into() < aggregated_bound)
        }) {
            let proof_share_bound = crate::language::commitment_message_space_lower_bound::<
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            >(false, RangeProof::RANGE_CLAIM_BITS)?;

            let malicious_parties: Vec<_> = maurer_proof_shares
                .into_iter()
                .filter(|(_, proof_share)| {
                    !(<[_; REPETITIONS]>::from(proof_share.clone())
                        .into_iter()
                        .all(|response| {
                            let (commitment_message, ..): (_, _) = response.into();
                            let (commitment_message, _) = commitment_message.into();

                            <[_; NUM_RANGE_CLAIMS]>::from(commitment_message)
                                .into_iter()
                                .all(|range_claim| range_claim.into() < proof_share_bound)
                        }))
                })
                .map(|(party_id, _)| party_id)
                .collect();

            return Err(proof::Error::Aggregation(
                aggregation::Error::ProofShareVerification(malicious_parties),
            ))?;
        }

        let proof = Proof {
            maurer_proof,
            range_proof,
        };

        Ok((proof, maurer_statements))
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
    range::ProofAggregationRoundParty<
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
    >: Clone,
{
    fn clone(&self) -> Self {
        Self {
            party_id: self.party_id,
            maurer_proof_aggregation_round_party: self.maurer_proof_aggregation_round_party.clone(),
            range_proof_proof_aggregation_round_party: self
                .range_proof_proof_aggregation_round_party
                .clone(),
        }
    }
}
