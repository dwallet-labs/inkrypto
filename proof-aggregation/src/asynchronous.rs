// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use mpc::ContributionBlending;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;

use commitment::CommitmentSizedNumber;
use group::helpers::{DeduplicateAndSort, TryCollectHashMap};
use group::PartyID;
use group::{CsRng, GroupElement};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use crate::Proof;
use crate::{AggregateableProof, OutputValue};
use proof::GroupsPublicParametersAccessors;

/// Asynchronous-aggregation error wrapper that carries a backtrace captured at construction.
#[derive(thiserror::Error, Clone, Debug)]
#[error("{kind}\n{backtrace}")]
pub struct Error {
    pub kind: ErrorKind,
    pub backtrace: std::sync::Arc<std::backtrace::Backtrace>,
}

impl<E> From<E> for Error
where
    ErrorKind: From<E>,
{
    fn from(value: E) -> Self {
        Self {
            kind: ErrorKind::from(value),
            backtrace: std::sync::Arc::new(std::backtrace::Backtrace::capture()),
        }
    }
}

/// Asynchronous-aggregation error kind.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ErrorKind {
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
        match value.kind {
            ErrorKind::InvalidStatement(parties) => {
                mpc::Error::from(mpc::ErrorKind::InvalidMessage(parties))
            }
            ErrorKind::ProofVerification(parties) => {
                mpc::Error::from(mpc::ErrorKind::MaliciousMessage(parties))
            }
            ErrorKind::MPC(e) => e,
            ErrorKind::InternalError => mpc::Error::from(mpc::ErrorKind::InternalError),
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
    <P as AggregateableProof>::ProofWithAggregationProtocolContext,
    Vec<group::Value<<P as Proof>::StatementSpaceGroupElement>>,
);

impl<P: AggregateableProof> mpc::Party for Party<P> {
    type Error = Error;
    type PublicInput = PublicInput<P::ProtocolContext, P::PublicParameters>;
    type PrivateOutput = ();
    type PublicOutputValue = OutputValue<P, P::AggregationStatementSpaceValue>;
    type PublicOutput = Vec<P::StatementSpaceGroupElement>;
    type Message = Message<P>;
}

impl<P: AggregateableProof> AsynchronouslyAdvanceable for Party<P>
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
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        match &messages[..] {
            [] => Self::advance_first_round(session_id, party_id, private_input, public_input, rng)
                .map(|message| AsynchronousRoundResult::Advance {
                    malicious_parties: vec![],
                    message,
                }),
            [proofs_and_statements] => Self::advance_second_round(
                session_id,
                access_structure,
                public_input,
                proofs_and_statements.clone(),
                rng,
            )
            .map(
                |(malicious_parties, aggregated_statements)| AsynchronousRoundResult::Finalize {
                    malicious_parties,
                    private_output: (),
                    public_output: aggregated_statements,
                },
            ),
            _ => Err(mpc::Error::from(mpc::ErrorKind::InvalidParameters))?,
        }
    }

    fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
        match failed_round {
            2 => Some(1),
            _ => None,
        }
    }
}

impl<P: AggregateableProof> Party<P>
where
    CommitmentSizedNumber: From<P::ProtocolContext>,
{
    pub fn advance_first_round(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        private_input: Option<<Self as AsynchronouslyAdvanceable>::PrivateInput>,
        public_input: &<Self as mpc::Party>::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<Message<P>, <Self as mpc::Party>::Error> {
        if CommitmentSizedNumber::from(public_input.protocol_context.clone()) != session_id {
            return Err(Error::from(ErrorKind::MPC(mpc::Error::from(
                mpc::ErrorKind::InvalidParameters,
            ))));
        }

        let witnesses = private_input.ok_or_else(|| {
            Error::from(ErrorKind::MPC(mpc::Error::from(
                mpc::ErrorKind::InvalidParameters,
            )))
        })?;
        if public_input.batch_size != witnesses.len() || public_input.batch_size == 0 {
            return Err(Error::from(ErrorKind::MPC(mpc::Error::from(
                mpc::ErrorKind::InvalidParameters,
            ))));
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
            mpc::Error::from(mpc::ErrorKind::Consumer(format!(
                "asynchronous proof aggregation {e:?}"
            )))
        })?;

        let statement_values =
            <P::StatementSpaceGroupElement as GroupElement>::batch_normalize(statements);

        Ok((proof, statement_values))
    }

    #[allow(clippy::type_complexity)]
    pub fn advance_second_round(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &<Self as mpc::Party>::PublicInput,
        proofs_and_statements: HashMap<PartyID, Message<P>>,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Vec<P::StatementSpaceGroupElement>), <Self as mpc::Party>::Error>
    {
        let (malicious_parties, verified_statements) = Self::advance_second_round_internal(
            session_id,
            access_structure,
            public_input,
            proofs_and_statements,
            rng,
        )?;

        // In order to aggregate, we must give `fold` an initial element, which should be the
        // neutral element, so we compute it here, taking any statement group element as an input.
        // All `unwrap`s and dereferences are safe, as we performed the corresponding sanity-checks that assure the
        // collections are non-empty.
        let neutral_statement = verified_statements
            .values()
            .next()
            .unwrap()
            .clone()
            .first()
            .unwrap()
            .neutral();

        let aggregated_statements: Vec<_> = (0..public_input.batch_size)
            .map(|i| {
                verified_statements
                    .values()
                    .map(|verified_statements| verified_statements[i].clone())
                    .fold(
                        neutral_statement.clone(),
                        |aggregated_group_element, statement| {
                            aggregated_group_element.add_vartime(
                                &statement,
                                public_input
                                    .public_parameters
                                    .statement_space_public_parameters(),
                            )
                        },
                    )
            })
            .collect();

        Ok((malicious_parties, aggregated_statements))
    }

    // TODO: name, doc
    #[allow(clippy::type_complexity)]
    pub fn advance_second_round_with_blending(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &<Self as mpc::Party>::PublicInput,
        proofs_and_statements: HashMap<PartyID, Message<P>>,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Vec<Vec<P::StatementSpaceGroupElement>>), <Self as mpc::Party>::Error>
    {
        let (malicious_parties, verified_statements) = Self::advance_second_round_internal(
            session_id,
            access_structure,
            public_input,
            proofs_and_statements,
            rng,
        )?;

        let blended_statements: Vec<_> = (0..public_input.batch_size)
            .map(|i| {
                let statements = verified_statements
                    .iter()
                    .map(|(&party_id, statements)| {
                        statements
                            .get(i)
                            .map(|statement| (party_id, statement.clone()))
                            .ok_or_else(|| {
                                <Self as mpc::Party>::Error::from(mpc::Error::from(
                                    mpc::ErrorKind::InternalError,
                                ))
                            })
                    })
                    .try_collect_hash_map()?;

                P::StatementSpaceGroupElement::blend_contributions(
                    access_structure,
                    statements,
                    public_input
                        .public_parameters
                        .statement_space_public_parameters(),
                )
            })
            .collect::<Result<_, _>>()?;

        let number_of_blended_statements = blended_statements[0].len();
        if blended_statements
            .iter()
            .any(|statements| statements.len() != number_of_blended_statements)
        {
            return Err(mpc::Error::from(mpc::ErrorKind::InternalError))?;
        }

        let blended_statements = (0..number_of_blended_statements)
            .map(|i| {
                blended_statements
                    .iter()
                    .map(|statements| statements[i].clone())
                    .collect()
            })
            .collect();

        Ok((malicious_parties, blended_statements))
    }

    #[allow(clippy::type_complexity)]
    fn advance_second_round_internal(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &<Self as mpc::Party>::PublicInput,
        proofs_and_statements: HashMap<PartyID, Message<P>>,
        rng: &mut impl CsRng,
    ) -> Result<
        (
            Vec<PartyID>,
            HashMap<PartyID, Vec<P::StatementSpaceGroupElement>>,
        ),
        <Self as mpc::Party>::Error,
    > {
        if CommitmentSizedNumber::from(public_input.protocol_context.clone()) != session_id {
            return Err(Error::from(ErrorKind::MPC(mpc::Error::from(
                mpc::ErrorKind::InvalidParameters,
            ))));
        }

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
            .filter(|(_, (_, statements))| statements.iter().any(|statement| statement.is_err()))
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

        let verified_statements = verified_statements
            .into_iter()
            .map(|(party_id, statements)| {
                // We constructed the vector to be with exactly one element to suit the batch verification API, here we undo that.
                statements
                    .first()
                    .ok_or_else(|| mpc::Error::from(mpc::ErrorKind::InternalError))
                    .map(|statements| (party_id, statements.clone()))
            })
            .try_collect_hash_map()?;

        Ok((malicious_parties, verified_statements))
    }
}
