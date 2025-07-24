// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::{
    aggregation::{
        commitment_round::COMMITMENT_LABEL, decommitment_round::Decommitment,
        proof_aggregation_round,
    },
    language::WitnessSpaceValue,
    Error, Proof, Result,
};
use commitment::Commitment;
use group::helpers::DeduplicateAndSort;
use group::{helpers::FlatMapResults, CsRng, GroupElement, PartyID};
use mpc::HandleInvalidMessages;
use proof::aggregation::{process_incoming_messages, ProofShareRoundParty};
use proof::GroupsPublicParametersAccessors;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProofShare<const REPETITIONS: usize, Language: crate::Language<REPETITIONS>>(
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super)  [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS],
);

#[cfg_attr(any(test, feature = "test_helpers"), derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The language we are proving
    Language: crate::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    pub(super) party_id: PartyID,
    pub(crate) provers: HashSet<PartyID>,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) commitments: HashMap<PartyID, Commitment>,
}

impl<
        const REPETITIONS: usize,
        Language: crate::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > ProofShareRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type Decommitment = Decommitment<REPETITIONS, Language>;
    type ProofShare = ProofShare<REPETITIONS, Language>;
    type ProofAggregationRoundParty =
        proof_aggregation_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Self::Decommitment>,
        _rng: &mut impl CsRng,
    ) -> Result<(Self::ProofShare, Self::ProofAggregationRoundParty)> {
        let decommitments =
            process_incoming_messages(self.party_id, self.provers.clone(), decommitments, true)?;

        let reconstructed_commitments: Result<HashMap<PartyID, Commitment>> = decommitments
            .iter()
            .map(|(party_id, decommitment)| {
                Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
                    &self.protocol_context,
                    &self.language_public_parameters,
                    decommitment.statements.clone(),
                    &decommitment.statement_masks,
                )
                .map(|mut transcript| {
                    (
                        *party_id,
                        Commitment::commit_transcript(
                            *party_id,
                            COMMITMENT_LABEL.to_string(),
                            &mut transcript,
                            &decommitment.commitment_randomness,
                        ),
                    )
                })
            })
            .collect();

        let reconstructed_commitments: HashMap<PartyID, Commitment> = reconstructed_commitments?;

        let miscommitting_parties: Vec<PartyID> = decommitments
            .keys()
            .cloned()
            .filter(|party_id| reconstructed_commitments[party_id] != self.commitments[party_id])
            .deduplicate_and_sort();

        if !miscommitting_parties.is_empty() {
            return Err(proof::aggregation::Error::WrongDecommitment(
                miscommitting_parties,
            ))?;
        }

        let statement_masks: HashMap<PartyID, group::Result<_>> = decommitments
            .iter()
            .map(|(party_id, decommitment)| {
                (
                    *party_id,
                    decommitment
                        .statement_masks
                        .map(|statement_mask| {
                            Language::StatementSpaceGroupElement::new(
                                statement_mask,
                                self.language_public_parameters
                                    .statement_space_public_parameters(),
                            )
                        })
                        .flat_map_results(),
                )
            })
            .collect();

        let parties_sending_invalid_statement_masks: Vec<PartyID> = statement_masks
            .iter()
            .filter(|(_, statement_masks)| statement_masks.is_err())
            .map(|(party_id, _)| *party_id)
            .deduplicate_and_sort();

        if !parties_sending_invalid_statement_masks.is_empty() {
            return Err(proof::aggregation::Error::InvalidDecommitment(
                parties_sending_invalid_statement_masks,
            ))?;
        }

        let statement_masks: HashMap<_, _> = statement_masks
            .into_iter()
            .map(|(party_id, statement_masks)| (party_id, statement_masks.unwrap()))
            .collect();

        let number_of_statements = self.statements.len();

        let parties_committed_on_wrong_number_of_statements: Vec<PartyID> = decommitments
            .iter()
            .filter(|(_, decommitment)| decommitment.statements.len() != number_of_statements)
            .map(|(party_id, _)| *party_id)
            .collect();

        if !parties_committed_on_wrong_number_of_statements.is_empty() {
            return Err(
                proof::aggregation::Error::WrongNumberOfDecommittedStatements(
                    miscommitting_parties,
                ),
            )?;
        }

        let aggregated_statement_masks = statement_masks.into_values().try_fold(
            self.statement_masks,
            |aggregated_statement_masks, statement_masks| {
                aggregated_statement_masks
                    .into_iter()
                    .zip(statement_masks)
                    .map(|(aggregated_statement_mask, statement_mask)| {
                        aggregated_statement_mask + statement_mask
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| Error::InternalError)
            },
        )?;

        let statements: HashMap<PartyID, Vec<_>> = decommitments
            .clone()
            .into_iter()
            .map(|(party_id, decommitment)| {
                (
                    party_id,
                    decommitment
                        .statements
                        .into_iter()
                        .map(|statement_value| {
                            Language::StatementSpaceGroupElement::new(
                                statement_value,
                                self.language_public_parameters
                                    .statement_space_public_parameters(),
                            )
                        })
                        .collect(),
                )
            })
            .handle_invalid_messages()?;

        let aggregated_statements: Vec<Language::StatementSpaceGroupElement> = (0
            ..number_of_statements)
            .map(|i| {
                statements
                    .values()
                    .map(|statements| statements[i])
                    .fold(self.statements[i], |aggregated_group_element, statement| {
                        aggregated_group_element + statement
                    })
            })
            .collect();

        let responses = Proof::<REPETITIONS, Language, ProtocolContext>::prove_inner(
            &self.protocol_context,
            &self.language_public_parameters,
            self.witnesses,
            aggregated_statements.clone(),
            self.randomizers,
            aggregated_statement_masks,
        )?
        .responses;

        let proof_share = ProofShare(responses);

        let responses = responses
            .map(|value| {
                Language::WitnessSpaceGroupElement::new(
                    value,
                    self.language_public_parameters
                        .witness_space_public_parameters(),
                )
            })
            .flat_map_results()?;

        let statement_masks = decommitments
            .into_iter()
            .map(|(party_id, decommitment)| (party_id, decommitment.statement_masks))
            .collect();

        let proof_aggregation_round_party =
            proof_aggregation_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                provers: self.provers,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                statements,
                statement_masks,
                aggregated_statements,
                aggregated_statement_masks,
                responses,
            };

        Ok((proof_share, proof_aggregation_round_party))
    }
}

impl<const REPETITIONS: usize, Language: crate::Language<REPETITIONS>>
    From<ProofShare<REPETITIONS, Language>>
    for [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS]
{
    fn from(value: ProofShare<REPETITIONS, Language>) -> Self {
        value.0
    }
}
