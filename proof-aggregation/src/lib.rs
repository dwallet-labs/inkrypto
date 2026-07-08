// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use group::PartyID;

use std::fmt::Debug;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use proof::Proof;
pub use range::AggregatableRangeProof;

pub mod asynchronous;
pub mod range;
pub mod synchronous;

/// Proof-aggregation error wrapper that carries a backtrace captured at construction.
///
/// See `group::Error` for details.
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

/// Proof-aggregation error kind.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ErrorKind {
    #[error("invalid parameters")]
    InvalidParameters,

    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,

    #[error("aggregation error")]
    SynchronousAggregation(#[from] synchronous::Error),

    #[error("serialization/deserialization error: {0:?}")]
    Serialization(String),

    #[error("invalid proof: did not satisfy the verification equation")]
    ProofVerification,

    #[error("proof error")]
    Proof(#[from] proof::Error),

    #[error("group error")]
    Group(#[from] group::Error),

    #[error("at least one of the witnesses is out of range")]
    OutOfRange,
}

/// Proof aggregation result.
pub type Result<T> = std::result::Result<T, Error>;

impl TryInto<synchronous::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<synchronous::Error, Self::Error> {
        match self.kind {
            ErrorKind::SynchronousAggregation(e) => Ok(e),
            kind => Err(Error {
                kind,
                backtrace: self.backtrace,
            }),
        }
    }
}

/// The protocol context used for aggregation, with the added `party_id` field which must be put on the transcript.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolContext<Context: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync> {
    party_id: PartyID,
    protocol_context: Context,
}

/// An Aggregateable Zero-Knowledge Proof.
pub trait AggregateableProof: Proof {
    /// The proof but with the protocol context used for aggregation.
    /// A patch used by the generic asynchronous aggregation code,
    /// which requires inserting the party ID into the transcript.
    type ProofWithAggregationProtocolContext: Proof<
        Error = Self::Error,
        ProtocolContext = ProtocolContext<Self::ProtocolContext>,
        PublicParameters = Self::PublicParameters,
        WitnessSpaceGroupElement = Self::WitnessSpaceGroupElement,
        StatementSpaceGroupElement = Self::StatementSpaceGroupElement,
        AggregationStatementSpaceValue = Self::AggregationStatementSpaceValue,
    >;
}

impl<
        const REPETITIONS: usize,
        Language: maurer::language::Language<REPETITIONS>,
        Context: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
    > AggregateableProof for maurer::Proof<REPETITIONS, Language, Context>
{
    type ProofWithAggregationProtocolContext =
        maurer::Proof<REPETITIONS, Language, ProtocolContext<Context>>;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OutputValue<P, V>(Vec<V>, PhantomData<P>);

impl<P, V> OutputValue<P, V> {
    pub fn new(output_value: Vec<V>) -> Self {
        Self(output_value, PhantomData)
    }
}

impl<P: Proof> From<Vec<P::StatementSpaceGroupElement>>
    for OutputValue<P, P::AggregationStatementSpaceValue>
{
    fn from(value: Vec<P::StatementSpaceGroupElement>) -> Self {
        Self::new(P::statements_to_output_value(value))
    }
}

impl<P: Proof> From<(P, Vec<P::StatementSpaceGroupElement>)>
    for OutputValue<P, P::AggregationStatementSpaceValue>
{
    fn from((_, statements): (P, Vec<P::StatementSpaceGroupElement>)) -> Self {
        Self::from(statements)
    }
}

impl<P, V> AsRef<Vec<V>> for OutputValue<P, V> {
    fn as_ref(&self) -> &Vec<V> {
        &self.0
    }
}

impl<P, V> From<OutputValue<P, V>> for Vec<V> {
    fn from(value: OutputValue<P, V>) -> Self {
        value.0
    }
}

#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    pub use crate::synchronous::test_helpers::*;
}
