// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use group::PartyID;
pub use synchronous::{
    process_incoming_messages, CommitmentRoundParty, DecommitmentRoundParty, Error,
    ProofAggregationRoundParty, ProofShareRoundParty, Result,
};

use crate::Proof;

pub mod asynchronous;
pub mod synchronous;

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

/// The protocol context used for aggregation, with the added `party_id` field which must be put on the transcript.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolContext<Context: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync> {
    party_id: PartyID,
    protocol_context: Context,
}

#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    pub use crate::aggregation::synchronous::test_helpers::*;
}
