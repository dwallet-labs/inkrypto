// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;

use crypto_bigint::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RoundResult<OutgoingMessage, PrivateOutput, PublicOutput> {
    pub outgoing_message: OutgoingMessage,
    // SECURITY WARNING: keep private, don't send to anyone!
    pub private_output: PrivateOutput,
    pub public_output: PublicOutput,
}

/// A round in a Two-Party Computation (2PC) Protocol.
pub trait Round: Sized {
    /// An error in the protocol.
    type Error: Send + Sync + Debug + Into<Error>;

    /// The private input of the party for this round.
    type PrivateInput: Clone + Debug + PartialEq + Eq + Send + Sync;

    /// The public input of the party.
    /// Holds together all public information that is required for the round.
    type PublicInput: Clone + Debug + PartialEq + Eq + Send + Sync;

    /// The private output of the protocol.
    /// NOTICE: the private output is serializable for the sake of backing up *your own private data*.
    /// NOTICE: NEVER SEND/BROADCAST THIS VALUE TO ANY UNTRUSTED ENTITY.
    type PrivateOutput: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The serialized public output of the protocol.
    type PublicOutputValue: From<Self::PublicOutput>
        + Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The public output of the protocol.
    type PublicOutput: Clone + Debug + PartialEq + Eq + Send + Sync;

    /// The incoming message the other party sent in their previous round.
    type IncomingMessage: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The outgoing message to send to the other party.
    type OutgoingMessage: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// Advance the current round.
    #[allow(clippy::type_complexity)]
    fn advance(
        message: Self::IncomingMessage,
        private_input: &Self::PrivateInput,
        public_input: &Self::PublicInput,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        RoundResult<Self::OutgoingMessage, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    >;
}
