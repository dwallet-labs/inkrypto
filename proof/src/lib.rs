// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;
use std::fmt::Debug;

use crypto_bigint::rand_core::CryptoRngCore;
#[cfg(feature = "parallel")]
use crypto_bigint::rand_core::OsRng;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use group::{GroupElement, PartyID, Samplable};
pub use range::{AggregatableRangeProof, RangeProof};
pub use transcript_protocol::TranscriptProtocol;

mod transcript_protocol;

pub mod aggregation;
pub mod range;

/// Proof error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters")]
    InvalidParameters,

    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,

    #[error("aggregation error")]
    Aggregation(#[from] aggregation::Error),

    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid proof: did not satisfy the verification equation")]
    ProofVerification,

    #[error("group error")]
    Group(#[from] group::Error),

    #[error("at least one of the witnesses is out of range")]
    OutOfRange,
}

/// Proof result.
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Aggregation(e) => e.into(),
            Error::Group(e) => mpc::Error::Group(e),
            Error::InternalError => mpc::Error::InternalError,
            Error::InvalidParameters => mpc::Error::InvalidParameters,
            e => mpc::Error::Consumer(format!("proof error {:?}", e)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
    pub witness_space_public_parameters: WitnessSpacePublicParameters,
    pub statement_space_public_parameters: StatementSpacePublicParameters,
}

/// An (Aggregateable) Proof.
pub trait Proof:
    Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq + Send + Sync
{
    /// Proof error.
    type Error: Debug + From<Error> + TryInto<Error, Error = Self::Error> + Send + Sync;

    /// A struct used by the protocol using this proof,
    /// used to provide extra necessary context that will parameterize the proof (and thus verifier
    /// code) and be inserted to the Fiat-Shamir transcript.
    type ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync;

    /// The proof but with the protocol context used for aggregation.
    /// A patch used by the generic asynchronous aggregation code,
    /// which requires inserting the party ID into the transcript.
    type ProofWithAggregationProtocolContext: Proof<
        Error = Self::Error,
        ProtocolContext = aggregation::ProtocolContext<Self::ProtocolContext>,
        PublicParameters = Self::PublicParameters,
        WitnessSpaceGroupElement = Self::WitnessSpaceGroupElement,
        StatementSpaceGroupElement = Self::StatementSpaceGroupElement,
        AggregationStatementSpaceValue = Self::AggregationStatementSpaceValue,
    >;

    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$.
    ///
    /// Includes the public parameters of the witness and statement groups.
    ///
    /// Group public parameters are encoded separately in
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `StatementSpaceGroupElement::PublicParameters`.
    type PublicParameters: AsRef<
            GroupsPublicParameters<
                group::PublicParameters<Self::WitnessSpaceGroupElement>,
                group::PublicParameters<Self::StatementSpaceGroupElement>,
            >,
        > + Serialize
        + PartialEq
        + Eq
        + Debug
        + Clone
        + Send
        + Sync;

    /// An element of the witness space $(\HH_\pp, +)$
    type WitnessSpaceGroupElement: GroupElement + Samplable;

    /// An element in the associated statement space $(\GG_\pp, \cdot)$,
    type StatementSpaceGroupElement: GroupElement;

    /// The value of the statement space used as the output value (`OutputValue`) for aggregation.
    type AggregationStatementSpaceValue: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// Prove a batched zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    fn prove(
        protocol_context: &Self::ProtocolContext,
        public_parameters: &Self::PublicParameters,
        witnesses: Vec<Self::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<(Self, Vec<Self::StatementSpaceGroupElement>), Self::Error>;

    /// Verify a batched zero-knowledge proof.
    fn verify(
        &self,
        protocol_context: &Self::ProtocolContext,
        public_parameters: &Self::PublicParameters,
        statements: Vec<Self::StatementSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<(), Self::Error>;

    /// Verify a batch of batched zero-knowledge proofs.
    fn verify_batch(
        proofs: Vec<Self>,
        protocol_contexts: Vec<Self::ProtocolContext>,
        public_parameters: &Self::PublicParameters,
        statements: Vec<Vec<Self::StatementSpaceGroupElement>>,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<(), Self::Error> {
        let batch_size = statements.first().ok_or(Error::InvalidParameters)?.len();
        if proofs.len() != statements.len()
            || proofs.len() != protocol_contexts.len()
            || statements.iter().any(|v| v.len() != batch_size)
        {
            return Err(Error::InvalidParameters)?;
        }

        proofs
            .into_iter()
            .zip(protocol_contexts.iter().zip(statements))
            .try_for_each(|(proof, (protocol_context, statements))| {
                proof.verify(protocol_context, public_parameters, statements, rng)
            })
    }

    /// Verify proofs sent by different parties within an asynchronous protocol.
    ///
    /// Returns the list of malicious parties, and a filtered mapping of the statements of each proof that passed verification.
    /// This list is empty in the happy-flow where batch verification passed, and there are no malicious parties.
    ///
    /// Note: `rng` can only be used when `parallel` is opt-out. Otherwise, `OsRng` is used for random generation.
    #[allow(unused_variables)]
    #[allow(clippy::type_complexity)]
    fn verify_batch_asynchronously(
        proofs_and_protocol_contexts_and_statements: HashMap<
            PartyID,
            Vec<(
                Self,
                (Self::ProtocolContext, Vec<Self::StatementSpaceGroupElement>),
            )>,
        >,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> (
        Vec<PartyID>,
        HashMap<PartyID, Vec<Vec<Self::StatementSpaceGroupElement>>>,
    ) {
        let (proofs, contexts_and_statements): (Vec<_>, Vec<_>) =
            proofs_and_protocol_contexts_and_statements
                .clone()
                .into_values()
                .flatten()
                .unzip();

        let (protocol_contexts, statements): (Vec<_>, Vec<_>) =
            contexts_and_statements.into_iter().unzip();

        // Try first to perform batch verification.
        let parties_sending_invalid_proofs = if Self::verify_batch(
            proofs,
            protocol_contexts.clone(),
            public_parameters,
            statements.clone(),
            rng,
        )
        .is_err()
        {
            #[cfg(not(feature = "parallel"))]
            let iter = proofs_and_protocol_contexts_and_statements.iter();
            #[cfg(feature = "parallel")]
            let iter = proofs_and_protocol_contexts_and_statements.par_iter();

            // In case it fails, we need to verify proofs individually.
            let parties_sending_invalid_proofs: Vec<PartyID> = iter
                .filter(|(_, proofs_and_protocol_contexts_and_statements)| {
                    proofs_and_protocol_contexts_and_statements.iter().any(
                        |(proof, (protocol_context, statements))| {
                            proof
                                .verify(
                                    protocol_context,
                                    public_parameters,
                                    statements.clone(),
                                    #[cfg(not(feature = "parallel"))]
                                    rng,
                                    #[cfg(feature = "parallel")]
                                    &mut OsRng,
                                )
                                .is_err()
                        },
                    )
                })
                .map(|(party_id, _)| *party_id)
                .collect();

            // We successfully verified the proofs, but some of them failed: report the malicious parties that failed them.
            parties_sending_invalid_proofs
        } else {
            // We're in the happy-flow: batch verification passed, so we succeed without reporting any malicious parties.
            vec![]
        };

        // Filter out all malicious parties, and keep only the statements.
        let verified_statements: HashMap<_, _> = proofs_and_protocol_contexts_and_statements
            .into_iter()
            .filter(|(party_id, _)| !parties_sending_invalid_proofs.contains(party_id))
            .map(|(party_id, proofs_and_protocol_contexts_and_statements)| {
                let statements = proofs_and_protocol_contexts_and_statements
                    .into_iter()
                    .map(|(_, (_, statements))| statements)
                    .collect();

                (party_id, statements)
            })
            .collect();

        (parties_sending_invalid_proofs, verified_statements)
    }

    /// Convert a batch of statements to the value of the statement space used as the output value (`OutputValue`) for aggregation.
    fn statements_to_output_value(
        statements: Vec<Self::StatementSpaceGroupElement>,
    ) -> Vec<Self::AggregationStatementSpaceValue>;
}

pub trait GroupsPublicParametersAccessors<
    'a,
    WitnessSpacePublicParameters: 'a,
    StatementSpacePublicParameters: 'a,
>:
    AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
{
    fn witness_space_public_parameters(&'a self) -> &'a WitnessSpacePublicParameters {
        &self.as_ref().witness_space_public_parameters
    }

    fn statement_space_public_parameters(&'a self) -> &'a StatementSpacePublicParameters {
        &self.as_ref().statement_space_public_parameters
    }
}

impl<
        'a,
        WitnessSpacePublicParameters: 'a,
        StatementSpacePublicParameters: 'a,
        T: AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>,
    >
    GroupsPublicParametersAccessors<
        'a,
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
    > for T
{
}

impl TryInto<aggregation::Error> for Error {
    type Error = Self;

    fn try_into(self) -> std::result::Result<aggregation::Error, Self::Error> {
        match self {
            Error::Aggregation(e) => Ok(e),
            e => Err(e),
        }
    }
}
