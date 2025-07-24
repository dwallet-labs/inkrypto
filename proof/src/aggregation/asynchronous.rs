// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::PartyID;
use group::{CsRng, GroupElement};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use crate::aggregation::OutputValue;
use crate::GroupsPublicParametersAccessors;
use crate::Proof;

/// Proof aggregation error.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("parties {:?} sent an invalid statement value", .0)]
    InvalidStatement(Vec<PartyID>),
    #[error("parties {:?} sent a proof that does not pass verification", .0)]
    ProofVerification(Vec<PartyID>),
    #[error("mpc error")]
    MPC(#[from] mpc::Error),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

impl From<Error> for mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::InvalidStatement(parties) => mpc::Error::InvalidMessage(parties),
            Error::ProofVerification(parties) => mpc::Error::MaliciousMessage(parties),
            Error::MPC(e) => e,
            Error::InternalError => mpc::Error::InternalError,
        }
    }
}

/// The public input for an asynchronous (statement) aggregation session.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<ProtocolContext, PublicParameters> {
    pub protocol_context: ProtocolContext,
    pub public_parameters: PublicParameters,
    pub batch_size: usize,
}

/// A party of an asynchronous (statement) aggregation protocol.
pub struct Party<P: Proof>(PhantomData<P>);

/// A message of an asynchronous (statement) aggregation protocol.
pub type Message<P> = (
    <P as Proof>::ProofWithAggregationProtocolContext,
    Vec<group::Value<<P as Proof>::StatementSpaceGroupElement>>,
);

impl<P: Proof> mpc::Party for Party<P> {
    type Error = Error;
    type PublicInput = PublicInput<P::ProtocolContext, P::PublicParameters>;
    type PrivateOutput = ();
    type PublicOutputValue = OutputValue<P, P::AggregationStatementSpaceValue>;
    type PublicOutput = Vec<P::StatementSpaceGroupElement>;
    type Message = Message<P>;
}

impl<P: Proof> AsynchronouslyAdvanceable for Party<P>
where
    CommitmentSizedNumber: From<P::ProtocolContext>,
{
    type PrivateInput = Vec<P::WitnessSpaceGroupElement>;

    fn advance(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        if CommitmentSizedNumber::from(public_input.protocol_context.clone()) != session_id {
            return Err(Error::MPC(mpc::Error::InvalidParameters));
        }

        match &messages[..] {
            [] => {
                let witnesses = private_input.ok_or(Error::MPC(mpc::Error::InvalidParameters))?;
                if public_input.batch_size != witnesses.len() || public_input.batch_size == 0 {
                    return Err(Error::MPC(mpc::Error::InvalidParameters));
                }

                let aggregation_protocol_context = super::ProtocolContext {
                    party_id,
                    protocol_context: public_input.protocol_context.clone(),
                };

                let (proof, statements) = P::ProofWithAggregationProtocolContext::prove(
                    &aggregation_protocol_context,
                    &public_input.public_parameters,
                    witnesses.clone(),
                    rng,
                )
                .map_err(|e| {
                    mpc::Error::Consumer(format!("asynchronous proof aggregation {e:?}"))
                })?;

                let statement_values =
                    <P::StatementSpaceGroupElement as GroupElement>::batch_normalize(statements);

                Ok(AsynchronousRoundResult::Advance {
                    malicious_parties: vec![],
                    message: (proof, statement_values),
                })
            }
            [proofs_and_statements] => {
                // First mark parties that sent wrong number of statements as malicious.
                let malicious_parties: Vec<PartyID> = proofs_and_statements
                    .iter()
                    .filter(|(_, (_, statements))| statements.len() != public_input.batch_size)
                    .map(|(tangible_party_id, _)| *tangible_party_id)
                    .deduplicate_and_sort();

                // Filter those out, and instantiate the statements as group elements.
                let proofs_and_statements: HashMap<PartyID, (_, Vec<_>)> = proofs_and_statements
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| !malicious_parties.contains(party_id))
                    .map(|(party_id, (proof, statements))| {
                        (
                            party_id,
                            (
                                proof,
                                statements
                                    .into_iter()
                                    .map(|statement_value| {
                                        P::StatementSpaceGroupElement::new(
                                            statement_value,
                                            public_input
                                                .public_parameters
                                                .statement_space_public_parameters(),
                                        )
                                    })
                                    .collect(),
                            ),
                        )
                    })
                    .collect();

                let parties_sending_invalid_statements: Vec<PartyID> = proofs_and_statements
                    .iter()
                    .filter(|(_, (_, statements))| {
                        statements.iter().any(|statement| statement.is_err())
                    })
                    .map(|(party_id, _)| *party_id)
                    .collect();

                // Next add the parties that sent invalid statements to the malicious parties.
                let malicious_parties = malicious_parties
                    .into_iter()
                    .chain(parties_sending_invalid_statements)
                    .deduplicate_and_sort();

                // Filter those out, and prepare to verify the proofs.
                let proofs_and_protocol_contexts_and_statements: HashMap<_, Vec<(_, (_, Vec<_>))>> =
                    proofs_and_statements
                        .into_iter()
                        .filter(|(party_id, _)| !malicious_parties.contains(party_id))
                        .map(|(party_id, (proof, statements))| {
                            let aggregation_protocol_context = super::ProtocolContext {
                                party_id,
                                protocol_context: public_input.protocol_context.clone(),
                            };

                            (
                                party_id,
                                vec![(
                                    proof,
                                    (
                                        aggregation_protocol_context,
                                        statements
                                            .into_iter()
                                            .map(|statement| statement.unwrap())
                                            .collect(),
                                    ),
                                )],
                            )
                        })
                        .collect();

                // Verify the proofs. Note that `verified_statements` is already filtered and does not contain malicious parties.
                let (parties_sending_invalid_proofs, verified_statements) =
                    Proof::verify_batch_asynchronously(
                        proofs_and_protocol_contexts_and_statements.clone(),
                        &public_input.public_parameters,
                        rng,
                    );

                // Add those parties that sent invalid proofs to the malicious parties.
                let malicious_parties = malicious_parties
                    .into_iter()
                    .chain(parties_sending_invalid_proofs)
                    .deduplicate_and_sort();

                // Check that the set of the honest provers is authorized.
                let provers = verified_statements.keys().copied().collect();
                access_structure.is_authorized_subset(&provers)?;

                // In order to aggregate, we must give `fold` an initial element, which should be the
                // neutral element, so we compute it here, taking any statement group element as an input.
                // All `unwrap`s and dereferences are safe, as we performed the corresponding sanity-checks that assure the
                // collections are non-empty.
                let neutral_statement = verified_statements.values().next().unwrap().clone()[0]
                    .first()
                    .unwrap()
                    .neutral();

                let aggregated_statements: Vec<_> = (0..public_input.batch_size)
                    .map(|i| {
                        verified_statements
                            .values()
                            .map(|verified_statements| {
                                // Safe to dereference, we constructed it to hold exactly one element.
                                verified_statements[0][i]
                            })
                            .fold(neutral_statement, |aggregated_group_element, statement| {
                                aggregated_group_element.add_vartime(&statement)
                            })
                    })
                    .collect();

                Ok(AsynchronousRoundResult::Finalize {
                    malicious_parties,
                    private_output: (),
                    public_output: aggregated_statements,
                })
            }
            _ => Err(mpc::Error::InvalidParameters)?,
        }
    }

    fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
        match failed_round {
            2 => Some(1),
            _ => None,
        }
    }
}
