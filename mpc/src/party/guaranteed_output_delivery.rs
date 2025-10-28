// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

use crate::{
    AsynchronousRoundResult, AsynchronouslyAdvanceable, Error, HandleInvalidMessages,
    WeightedThresholdAccessStructure,
};
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::{CsRng, PartyID};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry::Vacant;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::marker::PhantomData;

/// The result of an asynchronous MPC session round transition with guaranteed output delivery.
/// Messages and outputs are serialized.
/// Captures a potential list of malicious parties alongside the result:
/// `malicious_parties` can be non-empty, signifying that malicious behavior was identified and attended to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RoundResult {
    /// Advance to the next round, by sending a message to the other parties.
    Advance { message: Vec<u8> },
    /// Finalize the session and record private and public outputs.
    Finalize {
        malicious_parties: Vec<PartyID>,
        private_output: Vec<u8>,
        public_output_value: Vec<u8>,
    },
}

/// A wrapper around the inner protocol message `M` used by `advance_with_guaranteed_output()` to guarantee output delivery.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Message<M> {
    MessageWithMetadata(MessageWithMetadata<M>),
    // Signifies a threshold not reached occurred, holding metadata used mostly for sanity checks.
    ThresholdNotReached {
        // The consensus round number at which we attempted to advance and failed.
        consensus_round_number: u64,
    },
}

/// A wrapper around the inner protocol message `M` with extra management metadata used to guarantee output delivery.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MessageWithMetadata<M> {
    // The round number in which this message was computed.
    mpc_round_number: u64,
    // The list of parties whose messages were unaccounted for because they were unavailable at the time of advancing,
    // or weren't needed to guarantee output delivery.
    inactive_or_ignored_senders_by_round: HashMap<u64, Vec<PartyID>>,
    // The list of malicious parties identified by the current party as part of this round.
    malicious_parties: Vec<PartyID>,
    // The actual message of the MPC protocol.
    message: M,
}

/// The result of a ready to advance check.
#[derive(Debug)]
pub enum ReadyToAdvanceResult<M> {
    /// Signals that round `mpc_round_number` is ready to advance,
    /// and holds the advance request that is used to `advance_with_guaranteed_output()`.
    ReadyToAdvance(AdvanceRequest<M>),
    /// Signals that we are not ready to advance, and we should wait for more messages.
    WaitForMoreMessages {
        mpc_round_number: u64,
        attempt_number: u64,
    },
}

/// A request to advance a session.
/// Captures the required information in order to advance.
///
/// Used to assure the inner logic of `ready_to_advance()` is only called once,
/// and if we know we can advance we will use that result in order to advance.
#[derive(Debug)]
pub struct AdvanceRequest<M> {
    /// Holds all the malicious parties before advancing, including both all `malicious_parties_by_round` and the malicious serializers.
    malicious_parties_pre_advance: Vec<PartyID>,
    /// The consensus round at which we were ready to advance.
    pub consensus_round_at_advance: Option<u64>,
    /// The MPC round we are advancing.
    pub mpc_round_number: u64,
    /// The total attempt number, starting from `1` and increasing for each failed attempt on [`Error::ThresholdNotReached`], for any MPC round.
    pub attempt_number: u64,
    /// The messages to pass to `advance()`.
    messages_to_advance: Vec<HashMap<PartyID, M>>,
}

impl<M> AdvanceRequest<M> {
    pub fn senders_for_round(&self, round: usize) -> crate::Result<HashSet<PartyID>> {
        let messages_of_round = self
            .messages_to_advance
            .get(round - 1)
            .ok_or(Error::InvalidParameters)?;

        Ok(messages_of_round.keys().copied().collect())
    }
}

/// A wrapper over an asynchronous MPC party `P` that guarantees output delivery for an asynchronous MPC session.
pub trait GuaranteesOutputDelivery<P: AsynchronouslyAdvanceable>: Sized {
    /// Check whether the session is ready to advance,
    /// and return an `AdvanceRequest` in case that it is, to later be used to call [`Self::advance_with_guaranteed_output()`].
    fn ready_to_advance(
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        current_consensus_round: u64,
        mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
        serialized_messages_by_consensus_round: &HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> Result<ReadyToAdvanceResult<P::Message>, P::Error>;

    /// Advance to the next round using the inner `P::advance()` logic whilst:
    ///  - guaranteeing output delivery.
    ///  - handling malicious reporting internally, by adding the malicious parties reported in between rounds,
    ///    and ignoring malicious parties' messages when possible.
    ///  - working with serialized messages and outputs: the caller may simply broadcast results.
    ///
    /// In an asynchronous protocol, a [`asynchronous::Party`] party advances to the next round by calling [`Self::advance()`].
    /// Since it cannot know in advance which messages are valid (i.e. without calling `advance()` and checking if it succeeded),
    /// and since in an asynchronous protocol we cannot expect a particular set of parties to be online,
    /// we can never know in advance when to call [`Self::advance()`].
    ///
    /// In practice, we must have some kind of measure of passed time (e.g., the amount of consensus rounds passed),
    /// after which all parties decide to advance (thus giving the same `messages` as argument to `advance()`).
    /// This introduces a trade-off between latency and output guarantee, as the longer we wait for messages,
    /// we have a better chance at succeeding in that attempt to advance.
    ///
    /// Since malicious behavior is the infrequent event, and malicious actors can be ignored once identified,
    /// we opt to advance on the first agreed-upon consensus round in which we see messages
    /// coming from an authorized subset of parties, plus an optional pre-defined delay.
    ///
    /// A small or zero delay might increase the chance of encountering a session that failed to `advance()` due to insufficient honest parties.
    /// For example, let's say we have `4` parties, each with one weight, with a threshold of `3`.
    /// Now let's say that at time `T1` we got messages from parties `1, 2, 4`.
    /// This seems like it is enough, since their total weight is `3`, and so we call `advance()`.
    /// However, let's say that party `2` was malicious and sent a wrong proof.
    /// Then, `advance()` would verify the proofs, and filter the malicious parties,
    /// and call `WeightedThresholdAccessStructure::is_authorized_subset()` with the now-honest subset of `1, 4`,
    /// which would fail, as `2 < 3`. In this scenario, an [`Error::ThresholdNotReached`] is returned by `is_authorized_subset()`
    /// and later by the inner `advance()` function that we wrap.
    ///
    /// Upon [`Error::ThresholdNotReached`], we send a [`Message::ThresholdNotReached`]
    /// to signify that we have to wait for more messages to be sent from a previous round and retry
    /// (in our example: until a time `T2` in which the slow party `3` sends its message.)
    ///
    /// Sending this message will make this error case oblivious to the caller,
    /// and lets us handle it internally in a completely transparent manner: when we see a `Message::ThresholdNotReached { consensus_round_number }` message from ourselves,
    /// we don't retry advancing at `consensus_round_number`, and instead wait for more messages.
    ///
    /// Note: there will be such messages eventually, as the adversary statically corrupts up to f<=n-t parties
    /// (above that, it can trivially DOS the system by not participating).
    /// For GOD in the async setting we need f<n/3.
    ///
    /// This function offers a clear and simple API to tackle this issue generically,
    /// for every asynchronous MPC protocol with guaranteed output,
    /// so long that either:
    /// - The round that caused the threshold not reached,
    ///   i.e. the round from which more messages are needed,
    ///   is always the previous round (which is the "naive" and commonplace case.) or:
    /// - The round(s) in between the round that caused the threshold not reached and the round
    ///   at which we encountered the threshold not reached error, do not depend on the round that caused the error.
    ///   For example, in our `class_groups::dkg` (and `reconfiguration`) protocols, we have the following structure:
    ///    * round 1: prove something for every party
    ///    * round 2 (optimization, optional): verify the proofs sent to you (from everyone that sent a first round message at *T1*.)
    ///    * round 3: verify proofs (from everyone that sent a first round message at *T2*) for everyone that wasn't online during round 2.
    ///
    ///   Since the optimization is optional, and we will end up verifying everyone that wasn't online in round 2 at round 3 anyways,
    ///   its safe for second round messages to be computed on first round messages seen at time *T1*,
    ///   whilst round 3 computes on messages seen at *T2*, so long as the change is additive
    ///   (we require that messages for a specific round are only added by different parties, never removed or changed.)
    ///
    /// REQUIREMENTS:
    ///   1. The caller should always receive and store messages for all rounds, even after the round has advanced.
    ///   2. Parties cannot re-send or replace a message for a round if they already sent a message for this round.
    ///   3. Once a message has been stored, it can never be filtered by the caller, even if the party became malicious in the middle of the session.
    ///      It is safe, however, to ignore messages in the first place when they are stored, if the sender is malicious (and the fact they are malicious has been established in agreement.)
    ///   4. Rounds must be executed in order for a given session by a given party.
    ///      This doesn't break asynchronicity, as this is relative only to the timeline of that party,
    ///      and other parties can proceed with the MPC session independently and without waiting for our messages, so long they receive message from a quorum of other honest parties.
    ///   5. The returned advance requests (`AdvanceRequest`) from [`Self::ready_to_advance()`] must be used to [`Self::advance_with_guaranteed_output()`] in order and without tempering.
    ///
    ///      In practice, calling [`Self::ready_to_advance()`] twice without advancing in between will return the same result,
    ///      as we always advance in relative to our own state, which is determined by our previously sent messages.
    ///
    /// Given these, we operate as follows to guarantee output:
    ///  - The inner protocol messages (i.e. [`P::Message`]) are wrapped by `Message` which also
    ///    holds management metadata required for the operation of this logic,
    ///    such as the previous rounds messages were accounted for to compute that message, which we take from our own previous messages.
    ///  - We begin by performing a majority vote to decide which messages were being used in every round and filter these before
    ///    calling the actual protocol logic with [`Self::advance()`].
    ///    We do not filter messages if they can cause an [`Error::ThresholdNotReached`] error,
    ///    i.e. *we add messages if available as long as they can potentially help guarantee output delivery.*
    ///
    ///    This *guarantees that subsequent rounds see the same messages for every round, unless it is safe given the above requirement*.
    fn advance_with_guaranteed_output(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        advance_request: AdvanceRequest<P::Message>,
        private_input: Option<P::PrivateInput>,
        public_input: &P::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<RoundResult, P::Error>;
}

pub struct Party<P: AsynchronouslyAdvanceable> {
    _party_choice: PhantomData<P>,
}

impl<P: AsynchronouslyAdvanceable> GuaranteesOutputDelivery<P> for Party<P> {
    fn ready_to_advance(
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        current_consensus_round: u64,
        mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
        serialized_messages_by_consensus_round: &HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> Result<ReadyToAdvanceResult<P::Message>, P::Error> {
        let (malicious_serializers_by_consensus_round, messages_by_consensus_round): (
            HashMap<_, _>,
            HashMap<_, HashMap<_, _>>,
        ) = Self::deserialize_messages(serialized_messages_by_consensus_round);

        // Get the consensus rounds at which we've advanced and got a threshold not reached attempt.
        let threshold_not_reached_consensus_rounds: HashSet<_> = messages_by_consensus_round
            .values()
            .flat_map(|messages| {
                messages.get(&party_id).and_then(|message| match message {
                    Message::ThresholdNotReached {
                        consensus_round_number,
                    } => Some(consensus_round_number),
                    Message::MessageWithMetadata { .. } => None,
                })
            })
            .copied()
            .collect();

        let messages_with_metadata_by_consensus_round = messages_by_consensus_round
            .into_iter()
            .map(|(consensus_round, messages)| {
                let messages_with_metadata = messages
                    .into_iter()
                    .filter_map(|(sender_party_id, message)| match message {
                        Message::ThresholdNotReached { .. } => None,
                        Message::MessageWithMetadata(m) => Some((sender_party_id, m)),
                    })
                    .collect();

                (consensus_round, messages_with_metadata)
            })
            .collect();

        let current_mpc_round: u64 =
            Self::current_mpc_round(party_id, &messages_with_metadata_by_consensus_round);

        // The first round needs no messages as input, and is always ready to advance.
        if current_mpc_round == 1 {
            // Can never get a threshold not reached error in first round
            let attempt_number = 1;

            // The consensus round at advance is undefined for the first round, as advance request might be out of sync with the consensus and be received in other ways.
            // Only messages are in sync with the consensus, and all subsequent rounds will have `consensus_round_at_advance` synced and set.
            let consensus_round_at_advance = None;

            return Ok(ReadyToAdvanceResult::ReadyToAdvance(AdvanceRequest {
                malicious_parties_pre_advance: Vec::new(),
                consensus_round_at_advance,
                mpc_round_number: current_mpc_round,
                attempt_number,
                messages_to_advance: Vec::new(),
            }));
        }

        let rounds_to_delay: u64 = mpc_round_to_consensus_rounds_delay
            .get(&current_mpc_round)
            .copied()
            .unwrap_or_default();

        // Deduce `malicious_parties_by_round` and `inactive_or_ignored_senders_by_round` from our own messages.
        let own_messages_by_mpc_round: HashMap<_, _> = messages_with_metadata_by_consensus_round
            .values()
            .flat_map(|messages| {
                messages
                    .get(&party_id)
                    .map(|message| (message.mpc_round_number, message))
            })
            .collect();

        let malicious_parties_by_round: HashMap<_, _> = own_messages_by_mpc_round
            .iter()
            .map(|(&mpc_round, message)| (mpc_round, message.malicious_parties.to_vec()))
            .collect();

        let inactive_or_ignored_senders_by_round: HashMap<_, _> = if let Some(last_round_message) =
            own_messages_by_mpc_round.get(&(current_mpc_round - 1))
        {
            last_round_message
                .inactive_or_ignored_senders_by_round
                .clone()
                .into_iter()
                .sorted_by(|(round_number, _), (other_round_number, _)| {
                    other_round_number.cmp(round_number)
                })
                .map(|(round_number, inactive_or_ignored_senders)| {
                    (
                        round_number,
                        inactive_or_ignored_senders.deduplicate_and_sort(),
                    )
                })
                .collect()
        } else {
            // For the first round there is no previous rounds messages to ignore.
            HashMap::new()
        };

        let malicious_parties_from_previous_rounds: HashSet<_> = malicious_parties_by_round
            .values()
            .flatten()
            .copied()
            .collect();

        // First find the `consensus_round_at_advance` and build all messages up to `current_mpc_round` whilst ignoring malicious parties as needed.
        let Some((consensus_round_at_advance, messages_with_metadata_candidate)) =
            Self::build_messages_with_metadata(
                current_mpc_round,
                current_consensus_round,
                rounds_to_delay,
                threshold_not_reached_consensus_rounds.clone(),
                messages_with_metadata_by_consensus_round,
                &malicious_serializers_by_consensus_round,
                &malicious_parties_from_previous_rounds,
                access_structure,
            )
        else {
            // Not ready to advance, but could be in the future.
            let attempt_number = Self::attempt_number(
                current_consensus_round,
                threshold_not_reached_consensus_rounds,
            );

            return Ok(ReadyToAdvanceResult::WaitForMoreMessages {
                mpc_round_number: current_mpc_round,
                attempt_number,
            });
        };

        let malicious_serializers = malicious_serializers_by_consensus_round
            .iter()
            .flat_map(|(&consensus_round, malicious_serializers)| {
                if consensus_round <= consensus_round_at_advance {
                    malicious_serializers.to_vec()
                } else {
                    Vec::new()
                }
            })
            .deduplicate_and_sort();

        let malicious_parties_pre_advance = malicious_parties_from_previous_rounds
            .into_iter()
            .chain(malicious_serializers)
            .deduplicate_and_sort();

        let attempt_number = Self::attempt_number(
            consensus_round_at_advance,
            threshold_not_reached_consensus_rounds,
        );

        // Finally ignore the inactive/ignored senders and convert the messages to the format `advance()` expects.
        let messages_to_advance = Self::build_messages_to_advance(
            inactive_or_ignored_senders_by_round,
            current_mpc_round,
            messages_with_metadata_candidate,
            access_structure,
        )?;

        Ok(ReadyToAdvanceResult::ReadyToAdvance(AdvanceRequest {
            malicious_parties_pre_advance,
            consensus_round_at_advance: Some(consensus_round_at_advance),
            mpc_round_number: current_mpc_round,
            attempt_number,
            messages_to_advance,
        }))
    }

    fn advance_with_guaranteed_output(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        advance_request: AdvanceRequest<P::Message>,
        private_input: Option<P::PrivateInput>,
        public_input: &P::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<RoundResult, P::Error> {
        // Update `inactive_or_ignored_senders_by_round` including the last round,
        // and any modifications that occurred due to the self-heal process,
        // by taking the complimentary set of the parties who sent
        // messages that were accounted for in the latest `advance()` call for each round.
        let inactive_or_ignored_senders_by_round = advance_request
            .messages_to_advance
            .iter()
            .enumerate()
            .map(|(round_index, messages)| {
                // The vector starts from index `0`, but the first round in the map is `1`.
                // Safe to cast, as there are never more than 2^64 entries in a vector.
                let round_number = (round_index + 1) as u64;

                let inactive_or_ignored_senders = access_structure
                    .party_to_weight
                    .keys()
                    .filter(|party_id| !messages.contains_key(party_id))
                    .copied()
                    .deduplicate_and_sort();

                (round_number, inactive_or_ignored_senders)
            })
            .collect();

        let last_round_senders: Option<HashSet<_>> = advance_request
            .messages_to_advance
            .last()
            .map(|last_round_messages| {
                // Unless we are at the first round, double-check that we had enough honest parties to advance.
                last_round_messages.keys().copied().collect()
            });

        // Wrap the inner protocol result with the inactive or ignored senders,
        // and account for the malicious voters as well.
        match P::advance(
            session_id,
            party_id,
            access_structure,
            advance_request.messages_to_advance,
            private_input.clone(),
            public_input,
            rng,
        ) {
            Ok(res) => {
                // Report the parties that were filtered before we advanced
                // joined with the parties that were identified as malicious during advancing this round.
                let malicious_parties: Vec<_> = advance_request
                    .malicious_parties_pre_advance
                    .into_iter()
                    .chain(res.malicious_parties())
                    .deduplicate_and_sort();

                if let Some(last_round_senders) = last_round_senders {
                    // Unless we are at the first round, double-check that we had enough honest parties to advance.
                    let honest_parties = last_round_senders
                        .into_iter()
                        .filter(|party_id| !malicious_parties.contains(party_id))
                        .collect();

                    if access_structure
                        .is_authorized_subset(&honest_parties)
                        .is_err()
                    {
                        return Self::advance_threshold_not_reached_message(
                            advance_request.consensus_round_at_advance,
                        );
                    }
                }

                match res {
                    AsynchronousRoundResult::Advance {
                        // We already accounted for the malicious parties above.
                        malicious_parties: _,
                        message,
                    } => {
                        // Serialize the message and wrap it with the required management metadata.
                        let message = MessageWithMetadata {
                            inactive_or_ignored_senders_by_round,
                            malicious_parties,
                            mpc_round_number: advance_request.mpc_round_number,
                            message,
                        };

                        let message = bcs::to_bytes(&Message::MessageWithMetadata(message))
                            .map_err(Error::from)?;

                        Ok(RoundResult::Advance { message })
                    }
                    AsynchronousRoundResult::Finalize {
                        // We already accounted for the malicious parties above.
                        malicious_parties: _,
                        private_output,
                        public_output,
                    } => {
                        // Serialize the outputs and return.
                        let private_output = bcs::to_bytes(&private_output).map_err(Error::from)?;
                        let public_output_value: P::PublicOutputValue = public_output.into();
                        let public_output_value =
                            bcs::to_bytes(&public_output_value).map_err(Error::from)?;

                        Ok(RoundResult::Finalize {
                            malicious_parties,
                            private_output,
                            public_output_value,
                        })
                    }
                }
            }

            Err(e) => {
                let mpc_error: Error = e.clone().into();
                match mpc_error {
                    Error::ThresholdNotReached => Self::advance_threshold_not_reached_message(
                        advance_request.consensus_round_at_advance,
                    ),
                    _ => Err(e),
                }
            }
        }
    }
}

impl<P: AsynchronouslyAdvanceable> Party<P> {
    /// Handle `Error::ThresholdNotReached` errors by sending a `Message::ThresholdNotReached` message.
    fn advance_threshold_not_reached_message(
        consensus_round_at_advance: Option<u64>,
    ) -> Result<RoundResult, P::Error> {
        let consensus_round_number = consensus_round_at_advance.ok_or(Error::InternalError)?;

        let message: Message<P::Message> = Message::ThresholdNotReached {
            consensus_round_number,
        };

        let message = bcs::to_bytes(&message).map_err(Error::from)?;

        Ok(RoundResult::Advance { message })
    }

    /// Deserializes the wrapped messages for each consensus round, reporting malicious deserializers.
    fn deserialize_messages(
        serialized_messages_by_consensus_round: &HashMap<u64, HashMap<PartyID, Vec<u8>>>,
    ) -> (
        HashMap<u64, Vec<PartyID>>,
        HashMap<u64, HashMap<PartyID, Message<P::Message>>>,
    ) {
        serialized_messages_by_consensus_round
            .iter()
            .map(|(&consensus_round_number, messages)| {
                let (malicious_serializers, messages) = messages
                    .iter()
                    .map(|(&party_id, message)| {
                        let message = bcs::from_bytes::<Message<P::Message>>(message);

                        (party_id, message)
                    })
                    .handle_invalid_messages_async();

                (
                    (consensus_round_number, malicious_serializers),
                    (consensus_round_number, messages),
                )
            })
            .unzip()
    }

    /// Deduces the current round for this session given a map of the messages sent in each consensus round
    /// by returning the latest round for which we have sent a message, defaulting to the first round.
    fn current_mpc_round(
        party_id: PartyID,
        messages_by_reliable_broadcast_round: &HashMap<
            u64,
            HashMap<PartyID, MessageWithMetadata<P::Message>>,
        >,
    ) -> u64 {
        if let Some(latest_outgoing_message_round) = messages_by_reliable_broadcast_round
            .values()
            .flat_map(|wrapped_messages| {
                wrapped_messages
                    .get(&party_id)
                    .map(|wrapped_message| wrapped_message.mpc_round_number)
            })
            .max()
        {
            latest_outgoing_message_round + 1
        } else {
            1
        }
    }

    /// Computes the current *total* attempt number, meaning the number of thresholds
    /// not reached from any mpc round in this session up until the current advance, plus 1.
    fn attempt_number(
        consensus_round_at_advance: u64,
        threshold_not_reached_consensus_rounds: HashSet<u64>,
    ) -> u64 {
        let threshold_not_reached_consensus_rounds_till_advance: Vec<_> =
            threshold_not_reached_consensus_rounds
                .into_iter()
                .filter(|consensus_round| *consensus_round < consensus_round_at_advance)
                .collect();

        let threshold_not_reached_count_till_advance =
            threshold_not_reached_consensus_rounds_till_advance.len();

        // Safe to cast here, as each threshold not reached must be unique for a consensus round, which is `u64` itself.
        (threshold_not_reached_count_till_advance + 1) as u64
    }

    /// This function iterates over the messages from different parties sent for
    /// different MPC rounds, ordered by the consensus round they were received.
    ///
    /// It builds a map of messages by round, from which the messages to advance the current round `current_mpc_round` can be created by ignoring the inactive/ignored senders,
    /// using all the messages from the first consensus round to the first that satisfies the
    /// following conditions:
    /// - malicious serializers are filtered per-consensus round,
    ///   and malicious parties from previous rounds are filtered for last round messages (see [`Self::is_malicious_sender_at_current_rounds()`]).
    /// - a quorum of messages from the previous round `current_mpc_round — 1` must exist.
    ///   Note: the first round is always ready to advance requiring no messages as input,
    ///   and as such isn't handled by this function which *assumes current_mpc_round >= 2*.
    /// - a minimum number of consensus rounds that was required to delay the execution
    ///   (to allow more messages to come in before advancing)
    ///   has passed since the first consensus round where we got a quorum for this round.
    /// - This quorum must be "fresh", in the sense we never tried to advance with it before.
    ///   There is only one case in which we attempt to advance the same round twice:
    ///   when we get a threshold not reached error.
    ///   Therefore, if such an error occurred for a consensus round, we don't stop the search,
    ///   and wait for at least one new message to come in a later consensus round before returning
    ///   the messages to advance with.
    ///
    /// Duplicate messages are ignored — the first message a party has sent for an MPC round
    /// is always used.
    fn build_messages_with_metadata(
        current_mpc_round: u64,
        current_consensus_round: u64,
        rounds_to_delay: u64,
        threshold_not_reached_consensus_rounds: HashSet<u64>,
        mut messages_with_metadata_by_consensus_round: HashMap<
            u64,
            HashMap<PartyID, MessageWithMetadata<P::Message>>,
        >,
        malicious_serializers_by_consensus_round: &HashMap<u64, Vec<PartyID>>,
        malicious_parties_from_previous_rounds: &HashSet<PartyID>,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Option<(
        u64,
        HashMap<u64, HashMap<PartyID, MessageWithMetadata<P::Message>>>,
    )> {
        let mut delayed_rounds = 0;
        let mut got_new_messages_since_last_threshold_not_reached = false;
        let mut messages_with_metadata: HashMap<u64, HashMap<PartyID, _>> = HashMap::new();

        let last_mpc_round = current_mpc_round - 1;

        // Make sure the messages are consecutive by inserting the default value (i.e. empty message map) for missing rounds.
        if let Some(&first_consensus_round) = messages_with_metadata_by_consensus_round.keys().min()
        {
            for consensus_round in first_consensus_round..=current_consensus_round {
                messages_with_metadata_by_consensus_round
                    .entry(consensus_round)
                    .or_default();
            }
        }

        let sorted_messages_by_consensus_round = messages_with_metadata_by_consensus_round
            .clone()
            .into_iter()
            .sorted_by(|(first_consensus_round, _), (second_consensus_round, _)| {
                first_consensus_round.cmp(second_consensus_round)
            });

        for (consensus_round, consensus_round_messages) in sorted_messages_by_consensus_round {
            // Update messages to advance the current round by joining the messages
            // received at the current consensus round
            // with the ones we collected so far, ignoring duplicates.
            for (sender_party_id, message) in consensus_round_messages {
                let is_malicious_sender = Self::is_malicious_sender_at_current_rounds(
                    sender_party_id,
                    message.mpc_round_number,
                    last_mpc_round,
                    consensus_round,
                    malicious_serializers_by_consensus_round,
                    malicious_parties_from_previous_rounds,
                );

                if message.mpc_round_number < current_mpc_round && !is_malicious_sender {
                    let mpc_round_messages_map = messages_with_metadata
                        .entry(message.mpc_round_number)
                        .or_default();

                    // Always take the first message sent in consensus by a
                    // particular party for a particular round.
                    if let Vacant(e) = mpc_round_messages_map.entry(sender_party_id) {
                        e.insert(message);
                        got_new_messages_since_last_threshold_not_reached = true;
                    }
                }
            }

            // Check if we have the threshold of messages for the previous round
            // to advance to the next round.
            let is_quorum_reached = if let Some(previous_round_messages) =
                messages_with_metadata.get(&(current_mpc_round - 1))
            {
                let previous_round_message_senders: HashSet<PartyID> =
                    previous_round_messages.keys().cloned().collect();

                access_structure
                    .is_authorized_subset(&previous_round_message_senders)
                    .is_ok()
            } else {
                false
            };

            if is_quorum_reached {
                if delayed_rounds != rounds_to_delay {
                    // Wait for the delay.
                    // We set the map of messages by consensus round at each consensus round for
                    // each session, even if no messages were received, so this count is
                    // accurate as iterating the messages by consensus round goes through all
                    // consensus rounds to date.
                    //
                    // Note that if we got a threshold not reached, we must have already waited for the delay;
                    // not possible for a consensus round to be in both the "wait for delay" and "threshold not reached" states,
                    // so we continue without checking.

                    delayed_rounds += 1;
                } else if threshold_not_reached_consensus_rounds.contains(&consensus_round) {
                    // We already tried advancing at the current consensus round, no point in trying again.
                    // Wait for new messages in later rounds before retrying.
                    got_new_messages_since_last_threshold_not_reached = false;
                } else if got_new_messages_since_last_threshold_not_reached {
                    // We have a quorum of previous round messages,
                    // we delayed the execution as and if required,
                    // and we know we haven't tried to advance the current MPC round with this
                    // set of messages, so we have a chance at advancing (and reaching threshold):
                    // Let's try advancing with this set of messages!
                    return Some((consensus_round, messages_with_metadata));
                }
            }
        }

        // If we reached here, we either got no quorum of previous round messages,
        // or we need to delay execution further,
        // or we need to wait for more messages before retrying after a threshold not reached has occurred.
        // This session is not ready to advance.
        None
    }

    /// Reports malicious parties for the `last_mpc_round` only,
    /// as previous rounds already executed and their result might have dependent on a
    /// then-honest-now-malicious party.
    ///
    /// By induction this would always assure we filter all the malicious parties up to any round,
    /// and that will be reflected in the `inactive_or_ignored_senders_by_round` which will be filtered later on.
    ///
    /// Malicious serializers for messages for any MPC round can be filtered up to the current `consensus_round`.
    fn is_malicious_sender_at_current_rounds(
        sender_party_id: PartyID,
        message_mpc_round: u64,
        last_mpc_round: u64,
        consensus_round: u64,
        malicious_serializers_by_consensus_round: &HashMap<u64, Vec<PartyID>>,
        malicious_parties_from_previous_rounds: &HashSet<PartyID>,
    ) -> bool {
        let is_malicious_serializer = malicious_serializers_by_consensus_round.iter().any(
            |(round, malicious_serializers)| {
                *round <= consensus_round && malicious_serializers.contains(&sender_party_id)
            },
        );

        let is_malicious_party_to_ignore = message_mpc_round == last_mpc_round
            && malicious_parties_from_previous_rounds.contains(&sender_party_id);

        is_malicious_serializer || is_malicious_party_to_ignore
    }

    /// Builds messages to `P::advance()` a session additively
    /// using the messages used to compute previous rounds (see [`GuaranteesOutputDelivery::advance_with_guaranteed_output()`].
    fn build_messages_to_advance(
        inactive_or_ignored_senders_by_round: HashMap<u64, Vec<PartyID>>,
        current_mpc_round: u64,
        messages_with_metadata_candidate: HashMap<
            u64,
            HashMap<PartyID, MessageWithMetadata<P::Message>>,
        >,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<Vec<HashMap<PartyID, P::Message>>, P::Error> {
        let parties: HashSet<_> = access_structure.party_to_weight.keys().copied().collect();

        let round_number_to_take_all_messages_from =
            P::round_causing_threshold_not_reached(current_mpc_round);

        // Safe to subtract, won't overflow due to sanity checks
        let last_mpc_round = current_mpc_round - 1;

        // Make sure we have an entry for each round up (and not including) the last round (sanity check).
        if inactive_or_ignored_senders_by_round
            .keys()
            .copied()
            .deduplicate_and_sort()
            != (1..(current_mpc_round - 1)).collect::<Vec<_>>()
        {
            Err(Error::InternalError)?;
        }

        // Sort the messages by the round number, ignore the inactive/ignored senders,
        // and then collect into a vector (sorted by the round number) to comply with the API of `Self::advance()`.
        let messages_to_advance: Vec<HashMap<_, _>> = messages_with_metadata_candidate
            .into_iter()
            .sorted_by(|(round_number, _), (other_round_number, _)| {
                round_number.cmp(other_round_number)
            })
            .map(|(round_number, messages)| {
                let messages: HashMap<_, _> = messages
                    .into_iter()
                    .filter(|(party_id, _)| {
                        if round_number == last_mpc_round
                            || Some(round_number) == round_number_to_take_all_messages_from
                        {
                            // Nothing to ignore from the last round messages, as they haven't yet to be processed and are unaccounted.\
                            // Also, don't ignore any messages that can cause a `ThresholdNotReached` error.
                            true
                        } else {
                            // Safe to `unwrap` due to above sanity check.
                            let inactive_or_ignored_senders = inactive_or_ignored_senders_by_round
                                .get(&round_number)
                                .unwrap();

                            !inactive_or_ignored_senders.contains(party_id)
                        }
                    })
                    .map(|(party_id, message)| (party_id, message.message))
                    .collect();

                let non_ignored_senders: HashSet<_> = messages.keys().copied().collect();

                // Make sure requirement (3) holds: if we saw a message at the time of advancing a previous round, we must see it now.
                if let Some(inactive_or_ignored_senders) =
                    inactive_or_ignored_senders_by_round.get(&round_number)
                {
                    let non_ignored_senders_at_advance: HashSet<_> = parties
                        .difference(&inactive_or_ignored_senders.iter().copied().collect())
                        .copied()
                        .collect();

                    if !non_ignored_senders.is_superset(&non_ignored_senders_at_advance) {
                        Err(Error::InvalidParameters)?;
                    }
                }

                // Sanity check: make sure we have enough messages to advance.
                //
                // This must be the case, as we checked for a quorum in [`Self::build_messages_with_metadata()`]
                // and we only filtered ignored or inactive senders in this function for previous rounds,
                // which were already filtered and quorum checked at the time of that round's [`GuaranteesOutputDelivery::advance_with_guaranteed_output()`].
                //
                // We trust `inactive_or_ignored_senders_by_round` was constructed correctly as it was taken from our own message.
                if access_structure
                    .is_authorized_subset(&non_ignored_senders)
                    .is_ok()
                {
                    Ok(messages)
                } else {
                    // Can only happen in case of a bug.
                    Err(Error::InternalError)
                }
            })
            .collect::<Result<_, Error>>()?;

        Ok(messages_to_advance)
    }
}

// Since exporting rust `#[cfg(test)]` is impossible, these test helpers exist in a dedicated feature-gated
// module.
#[cfg(any(test, feature = "test_helpers"))]
#[allow(clippy::too_many_arguments)]
pub mod test_helpers {
    use super::*;
    use group::OsCsRng;

    pub fn asynchronous_session_guarantees_output<P: AsynchronouslyAdvanceable>(
        session_id: CommitmentSizedNumber,
        private_inputs: HashMap<PartyID, P::PrivateInput>,
        public_inputs: HashMap<PartyID, P::PublicInput>,
        access_structure: &WeightedThresholdAccessStructure,
        mpc_round_to_consensus_rounds_delay: HashMap<u64, u64>,
        timeline: HashMap<u64, HashMap<PartyID, (u64, bool, bool, bool, Option<u64>)>>,
        check_outputs: bool,
    ) -> (
        HashMap<u64, HashMap<PartyID, Vec<u8>>>,
        HashMap<PartyID, (Vec<PartyID>, Vec<u8>, Vec<u8>)>,
    ) {
        let mut messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>> =
            HashMap::new();
        let mut outputs: HashMap<_, (Vec<PartyID>, Vec<u8>, Vec<u8>)> = HashMap::new();

        for (consensus_round_number, events) in timeline.into_iter().sorted_by(
            |(first_consensus_round, _), (second_consensus_round, _)| {
                first_consensus_round.cmp(second_consensus_round)
            },
        ) {
            let mut current_consensus_round_messages = HashMap::new();

            for (
                party_id,
                (
                    mpc_round,
                    is_ready_to_advance,
                    is_finalize,
                    is_malicious_serializer,
                    threshold_not_reached_consesnsus_round,
                ),
            ) in events
                .into_iter()
                .sorted_by(|(first_party_id, _), (second_party_id, _)| {
                    first_party_id.cmp(second_party_id)
                })
            {
                match Party::<P>::ready_to_advance(
                    party_id,
                    access_structure,
                    consensus_round_number,
                    mpc_round_to_consensus_rounds_delay.clone(),
                    &messages_by_consensus_round,
                )
                .unwrap()
                {
                    ReadyToAdvanceResult::ReadyToAdvance(advance_request) => {
                        let mpc_round_number = advance_request.mpc_round_number;
                        let attempt_number = advance_request.attempt_number;
                        assert!(is_ready_to_advance, "Party {party_id} is ready to advance round #{mpc_round_number} attempt #{attempt_number} at consensus round #{consensus_round_number} when the timeline says it isn't");
                        assert_eq!(mpc_round_number, mpc_round, "Party {party_id} is ready to advance round #{mpc_round_number} attempt #{attempt_number} at consensus round #{consensus_round_number} when the timeline says it should advance round #{mpc_round}");

                        if is_malicious_serializer {
                            assert!(!is_finalize);

                            let maliciously_serialized_message = vec![42; 42];
                            current_consensus_round_messages
                                .insert(party_id, maliciously_serialized_message);

                            continue;
                        }

                        match Party::<P>::advance_with_guaranteed_output(
                            session_id,
                            party_id,
                            access_structure,
                            advance_request,
                            private_inputs.get(&party_id).cloned(),
                            public_inputs.get(&party_id).unwrap(),
                            &mut OsCsRng,
                        )
                        .unwrap()
                        {
                            RoundResult::Advance { message } => {
                                assert!(!is_finalize, "Party {party_id} advanced round #{mpc_round_number} attempt #{attempt_number} at consensus round #{consensus_round_number} when the timeline says it should have finalized");

                                if let Some(threshold_not_reached_consensus_round) =
                                    threshold_not_reached_consesnsus_round
                                {
                                    assert_eq!(
                                        message[0],
                                        1,
                                        "Party {party_id} advanced round #{mpc_round_number} attempt #{attempt_number} at consensus round #{consensus_round_number} successfully when the timeline says it should have gotten a threshold not reached in consensus round #{threshold_not_reached_consensus_round}",
                                    );

                                    assert_eq!(
                                        message,
                                        bcs::to_bytes::<Message<usize>>(
                                            &Message::ThresholdNotReached {
                                                consensus_round_number: threshold_not_reached_consensus_round
                                            }
                                        )
                                            .unwrap(),
                                        "Party {party_id} reported a threshold not reached in a wrong consensus round as by the timeline",
                                    );
                                }

                                current_consensus_round_messages.insert(party_id, message);
                            }
                            RoundResult::Finalize {
                                malicious_parties,
                                private_output,
                                public_output_value,
                            } => {
                                assert!(is_finalize, "Party {party_id} finalized at round #{mpc_round_number} attempt #{attempt_number} at consensus round #{consensus_round_number} when the timeline says it should have advanced");

                                if check_outputs && !outputs.is_empty() {
                                    assert_eq!(
                                        outputs.values().next().unwrap().clone(),
                                        (
                                            malicious_parties.clone(),
                                            private_output.clone(),
                                            public_output_value.clone()
                                        ),
                                        "Party {party_id} sent a non-matching output"
                                    );
                                }

                                outputs.insert(
                                    party_id,
                                    (malicious_parties, private_output, public_output_value),
                                );
                            }
                        };
                    }
                    ReadyToAdvanceResult::WaitForMoreMessages {
                        mpc_round_number,
                        attempt_number,
                    } => {
                        assert!(!is_ready_to_advance, "Party {party_id} is not ready to advance round #{mpc_round_number} attempt #{attempt_number} at consensus round #{consensus_round_number} when the timeline says it is");
                    }
                };
            }

            messages_by_consensus_round
                .insert(consensus_round_number, current_consensus_round_messages);
        }

        if check_outputs {
            let consensus_output_parties = outputs.keys().copied().collect();

            assert!(
                access_structure
                    .is_authorized_subset(&consensus_output_parties)
                    .is_ok(),
                "No quorum on outputs achieved"
            )
        }

        (messages_by_consensus_round, outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guaranteed_output_delivery::test_helpers::asynchronous_session_guarantees_output;
    use crate::HandleInvalidMessages;
    use crypto_bigint::{Random, Uint, U256};
    use group::helpers::DeduplicateAndSort;
    use group::OsCsRng;
    use rand::Rng;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn builds_messages_for_round2() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let threshold_not_reached_consensus_rounds = HashSet::new();
        let current_mpc_round = 2;
        let rounds_to_delay = 0;
        let round1_messages = HashMap::from([(1u16, 0), (2u16, 42), (3, 43), (4u16, 42)]);

        let round1_messages: HashMap<_, _> = round1_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 1,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();

        let messages_by_consensus_round: HashMap<
            u64,
            HashMap<PartyID, MessageWithMetadata<usize>>,
        > = HashMap::from([
            (
                3,
                HashMap::from([
                    (1, round1_messages.get(&1).unwrap().clone()),
                    (3, round1_messages.get(&3).unwrap().clone()),
                ]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
            ),
        ]);

        let current_consensus_round = *messages_by_consensus_round.keys().max().unwrap();

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round,
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );

        let expected_messages = HashMap::from([(
            1,
            round1_messages
                .clone()
                .into_iter()
                .filter(|(pid, _)| *pid != 2)
                .collect(),
        )]);

        assert_eq!(messages, Some((5, expected_messages)));
    }

    #[test]
    fn doesnt_build_messages_for_round2_no_quorum() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 2;
        let rounds_to_delay = 0;

        let round1_messages = HashMap::from([(1u16, 8), (3, 42)]);
        let round1_messages: HashMap<_, _> = round1_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 1,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();
        let messages_by_consensus_round =
            HashMap::from([(3, round1_messages), (4, HashMap::new())]);

        let current_consensus_round = *messages_by_consensus_round.keys().max().unwrap();

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            HashSet::new(),
            messages_by_consensus_round,
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );

        assert_eq!(messages, None);
    }

    #[test]
    fn doesnt_build_messages_for_round2_insufficent_delay() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 2;
        let rounds_to_delay = 3;
        let threshold_not_reached_consensus_rounds = HashSet::new();
        let round1_messages = HashMap::from([(1u16, 42), (2u16, 0), (3, 43), (4u16, 42)]);
        let round1_messages: HashMap<_, _> = round1_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 1,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([
                    (1, round1_messages.get(&1).unwrap().clone()),
                    (3, round1_messages.get(&3).unwrap().clone()),
                ]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
            ),
        ]);

        let current_consensus_round = *messages_by_consensus_round.keys().max().unwrap();

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round,
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );

        assert_eq!(messages, None);
    }

    #[test]
    fn delays_and_builds_messages_for_round2() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 2;
        let threshold_not_reached_consensus_rounds = HashSet::new();
        let round1_messages = HashMap::from([(1u16, 42), (2u16, 0), (3, 43), (4u16, 42)]);
        let round1_messages: HashMap<_, _> = round1_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 1,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();
        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([
                    (1, round1_messages.get(&1).unwrap().clone()),
                    (3, round1_messages.get(&3).unwrap().clone()),
                ]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([(2, round1_messages.get(&2).unwrap().clone())]),
            ),
            (8, HashMap::new()),
        ]);

        let rounds_to_delay = 1;
        let current_consensus_round = *messages_by_consensus_round.keys().max().unwrap();

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );

        let expected_messages = HashMap::from([(
            1,
            round1_messages
                .clone()
                .into_iter()
                .filter(|(pid, _)| *pid != 2)
                .collect(),
        )]);

        assert_eq!(messages, Some((6, expected_messages)));

        let rounds_to_delay = 2;
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );

        assert_eq!(
            messages,
            Some((7, HashMap::from([(1, round1_messages.clone())])))
        );

        let rounds_to_delay = 3;
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );

        assert_eq!(messages, Some((8, HashMap::from([(1, round1_messages)]))));

        let rounds_to_delay = 4;
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round,
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );

        assert_eq!(messages, None);
    }

    #[test]
    fn builds_messages_for_round3() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let current_mpc_round = 3;
        let rounds_to_delay = 0;
        let threshold_not_reached_consensus_rounds = HashSet::new();
        let round1_messages = HashMap::from([(1u16, 42), (2u16, 0), (3, 43), (4u16, 42)]);
        let round1_messages: HashMap<_, _> = round1_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 1,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();

        let round2_messages = HashMap::from([(1u16, 42), (2u16, 0), (4u16, 42)]);
        let round2_messages: HashMap<_, _> = round2_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 2,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();

        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([
                    (1, round1_messages.get(&1).unwrap().clone()),
                    (3, round1_messages.get(&3).unwrap().clone()),
                ]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([
                    (1, round2_messages.get(&1).unwrap().clone()),
                    (2, round1_messages.get(&2).unwrap().clone()),
                    (4, round2_messages.get(&4).unwrap().clone()),
                ]),
            ),
            (
                8,
                HashMap::from([(2, round2_messages.get(&2).unwrap().clone())]),
            ),
        ]);

        let current_consensus_round = *messages_by_consensus_round.keys().max().unwrap();

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );
        let expected_messages = HashMap::from([(1, round1_messages), (2, round2_messages)]);

        assert_eq!(messages, Some((8, expected_messages)));
    }

    #[test]
    fn builds_messages_with_threshold_not_reached() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 4, 4, &mut OsCsRng).unwrap();

        let rounds_to_delay = 0;
        let round1_messages = HashMap::from([(1u16, 42), (2u16, 0), (3, 43), (4u16, 42)]);
        let round1_messages: HashMap<_, _> = round1_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 1,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();

        let round2_messages = HashMap::from([(1u16, 42), (2u16, 0), (3u16, 0), (4u16, 42)]);
        let round2_messages: HashMap<_, _> = round2_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 2,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();

        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([
                    (1, round1_messages.get(&1).unwrap().clone()),
                    (3, round1_messages.get(&3).unwrap().clone()),
                ]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([
                    (2, round1_messages.get(&2).unwrap().clone()),
                    // 3 was malicious, sent round 2 even though threshold not reached
                    (3, round2_messages.get(&3).unwrap().clone()),
                ]),
            ),
            (
                8,
                HashMap::from([
                    (1, round2_messages.get(&1).unwrap().clone()),
                    (4, round2_messages.get(&4).unwrap().clone()),
                ]),
            ),
            (
                9,
                HashMap::from([(2, round2_messages.get(&2).unwrap().clone())]),
            ),
        ]);

        let current_mpc_round = 2;
        let current_consensus_round = *messages_by_consensus_round.keys().max().unwrap();
        let threshold_not_reached_consensus_rounds = HashSet::from([5]);

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round
                .clone()
                .into_iter()
                .filter(|(consensus_round, _)| *consensus_round <= 6)
                .collect(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );
        assert_eq!(messages, None);

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );
        let expected_messages = HashMap::from([(1, round1_messages.clone())]);
        assert_eq!(messages, Some((7, expected_messages)));

        let current_mpc_round = 3;
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );
        let expected_messages = HashMap::from([
            (1, round1_messages.clone()),
            (
                2,
                round2_messages
                    .clone()
                    .into_iter()
                    .filter(|(pid, _)| *pid != 2)
                    .collect(),
            ),
        ]);

        assert_eq!(messages, Some((8, expected_messages)));

        let current_mpc_round = 3;
        let threshold_not_reached_consensus_rounds = HashSet::from([5, 8]);
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );
        let expected_messages = HashMap::from([(1, round1_messages), (2, round2_messages)]);

        assert_eq!(messages, Some((9, expected_messages)));
    }

    #[test]
    fn builds_messages_with_threshold_not_reached_delay_and_malicious_parties_when_possible() {
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 5, 5, &mut OsCsRng).unwrap();

        let round1_messages = HashMap::from([(1u16, 42), (2u16, 0), (3, 43), (4u16, 42), (5, 99)]);
        let round1_messages: HashMap<_, _> = round1_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 1,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();

        let round2_messages =
            HashMap::from([(1u16, 42), (2u16, 0), (3u16, 0), (4u16, 42), (5, 98)]);
        let round2_messages: HashMap<_, _> = round2_messages
            .into_iter()
            .map(|(party_id, message)| {
                (
                    party_id,
                    MessageWithMetadata {
                        mpc_round_number: 2,
                        message,
                        // All other fields are ignored by `build_messages_with_metadata()`, only `mpc_round_number` and `message` are used.
                        inactive_or_ignored_senders_by_round: HashMap::new(),
                        malicious_parties: vec![],
                    },
                )
            })
            .collect();

        let messages_by_consensus_round = HashMap::from([
            (
                3,
                HashMap::from([
                    (1, round1_messages.get(&1).unwrap().clone()),
                    (3, round1_messages.get(&3).unwrap().clone()),
                    (5, round1_messages.get(&5).unwrap().clone()),
                ]),
            ),
            (4, HashMap::new()),
            (
                5,
                HashMap::from([(4, round1_messages.get(&4).unwrap().clone())]),
            ),
            (6, HashMap::new()),
            (
                7,
                HashMap::from([
                    (2, round1_messages.get(&2).unwrap().clone()),
                    // 3 was malicious, sent round 2 even though threshold not reached
                    (3, round2_messages.get(&3).unwrap().clone()),
                ]),
            ),
            (
                8,
                HashMap::from([
                    (1, round2_messages.get(&1).unwrap().clone()),
                    (4, round2_messages.get(&4).unwrap().clone()),
                ]),
            ),
            (9, HashMap::new()),
            (
                10,
                HashMap::from([(2, round2_messages.get(&2).unwrap().clone())]),
            ),
            (
                11,
                HashMap::from([(5, round2_messages.get(&5).unwrap().clone())]),
            ),
        ]);

        let current_consensus_round = *messages_by_consensus_round.keys().max().unwrap();

        // Test a combination of delay and threshold not reached
        let current_mpc_round = 3;
        let threshold_not_reached_consensus_rounds = HashSet::from([5, 9]);

        let rounds_to_delay = 1;
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );
        let expected_messages = HashMap::from([
            (1, round1_messages.clone()),
            (
                2,
                round2_messages
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| *party_id != 5)
                    .collect(),
            ),
        ]);
        assert_eq!(messages, Some((10, expected_messages)));

        let malicious_serializers_by_consensus_round = HashMap::from([(7, vec![3])]);
        let malicious_parties_from_previous_rounds = HashSet::new();
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &malicious_serializers_by_consensus_round,
            &malicious_parties_from_previous_rounds,
            &access_structure,
        );
        let expected_messages = HashMap::from([
            (1, round1_messages.clone()),
            (
                2,
                round2_messages
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| *party_id != 3)
                    .collect(),
            ),
        ]);
        assert_eq!(messages, Some((11, expected_messages)));

        let malicious_serializers_by_consensus_round = HashMap::new();
        let malicious_parties_from_previous_rounds = HashSet::from([2]);
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &malicious_serializers_by_consensus_round,
            &malicious_parties_from_previous_rounds,
            &access_structure,
        );
        let expected_messages = HashMap::from([
            (1, round1_messages.clone()),
            (
                2,
                round2_messages
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| *party_id != 2)
                    .collect(),
            ),
        ]);
        assert_eq!(messages, Some((11, expected_messages)));

        let malicious_serializers_by_consensus_round = HashMap::from([(7, vec![3]), (10, vec![2])]);
        let malicious_parties_from_previous_rounds = HashSet::new();
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &malicious_serializers_by_consensus_round,
            &malicious_parties_from_previous_rounds,
            &access_structure,
        );
        assert_eq!(messages, None);

        let malicious_serializers_by_consensus_round = HashMap::from([(7, vec![3])]);
        let malicious_parties_from_previous_rounds = HashSet::from([2]);
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &malicious_serializers_by_consensus_round,
            &malicious_parties_from_previous_rounds,
            &access_structure,
        );
        assert_eq!(messages, None);

        let rounds_to_delay = 2;
        let threshold_not_reached_consensus_rounds = HashSet::from([5, 10]);

        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &HashMap::new(),
            &HashSet::new(),
            &access_structure,
        );
        let expected_messages =
            HashMap::from([(1, round1_messages.clone()), (2, round2_messages.clone())]);
        assert_eq!(messages, Some((11, expected_messages)));

        let malicious_serializers_by_consensus_round = HashMap::from([(7, vec![3]), (11, vec![5])]);
        let malicious_parties_from_previous_rounds = HashSet::new();
        let messages = Party::<MathParty>::build_messages_with_metadata(
            current_mpc_round,
            current_consensus_round,
            rounds_to_delay,
            threshold_not_reached_consensus_rounds.clone(),
            messages_by_consensus_round.clone(),
            &malicious_serializers_by_consensus_round,
            &malicious_parties_from_previous_rounds,
            &access_structure,
        );
        assert_eq!(messages, None);
    }

    struct MathParty {}

    impl crate::Party for MathParty {
        type Error = Error;
        type PublicInput = ();
        type PrivateOutput = ();
        type PublicOutputValue = usize;
        type PublicOutput = usize;
        type Message = usize;
    }

    impl AsynchronouslyAdvanceable for MathParty {
        type PrivateInput = ();

        fn advance(
            _session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            _private_input: Option<Self::PrivateInput>,
            _public_input: &Self::PublicInput,
            _rng: &mut impl CsRng,
        ) -> Result<
            AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
            Self::Error,
        > {
            match &messages[..] {
                [] => {
                    let message = match party_id {
                        1 => 101, // malicious
                        2 => 88,
                        3 => 7,
                        4 => 1,
                        5 => 2,
                        6 => 3,
                        _ => panic!(),
                    };

                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties: vec![],
                        message,
                    })
                }
                [_] => {
                    // Note: we ignore first round messages here, so its safe to add them at any time before we compute on them at round 4.
                    let message = match party_id {
                        1 => 7,
                        2 => 11,
                        3 => 3,
                        4 => 2,
                        5 => 2,
                        6 => 5,
                        _ => panic!(),
                    };

                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties: vec![],
                        message,
                    })
                }
                [first_round_messages, _] => {
                    let first_round_senders: HashSet<_> =
                        first_round_messages.keys().copied().collect();
                    let (malicious_parties, first_round_messages) = first_round_messages
                        .iter()
                        .map(|(&other_party_id, &number_smaller_than_100)| {
                            let m = if number_smaller_than_100 < 100 {
                                Ok(number_smaller_than_100)
                            } else {
                                Err(Error::InvalidParameters)
                            };

                            (other_party_id, m)
                        })
                        .handle_invalid_messages_async();

                    let honest_parties = first_round_senders
                        .difference(&malicious_parties.iter().copied().collect())
                        .copied()
                        .collect();
                    access_structure.is_authorized_subset(&honest_parties)?;

                    let first_round_messages_sum: usize = first_round_messages.values().sum();

                    let factor = match party_id {
                        1 => 3,
                        2 => 6, // malicious
                        3 => 5,
                        4 => 2,
                        5 => 2,
                        6 => 1,
                        _ => panic!(),
                    };
                    let message = first_round_messages_sum * factor;

                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message,
                    })
                }
                [first_round_messages, second_round_messages, third_round_messages] => {
                    let (malicious_parties, first_round_messages) = first_round_messages
                        .iter()
                        .map(|(&other_party_id, &number_smaller_than_100)| {
                            let m = if number_smaller_than_100 < 100 {
                                Ok(number_smaller_than_100)
                            } else {
                                Err(Error::InvalidParameters)
                            };

                            (other_party_id, m)
                        })
                        .handle_invalid_messages_async();

                    let first_round_messages_sum: usize = first_round_messages.values().sum();
                    let second_round_messages_product: usize =
                        second_round_messages.values().product();

                    let third_round_senders: HashSet<_> =
                        third_round_messages.keys().copied().collect();

                    let (third_round_malicious_parties, third_round_messages) =
                        third_round_messages
                            .iter()
                            .map(|(&other_party_id, &message)| {
                                let m = if message <= (5 * first_round_messages_sum) {
                                    Ok(message)
                                } else {
                                    Err(Error::InvalidParameters)
                                };

                                (other_party_id, m)
                            })
                            .handle_invalid_messages_async();

                    let malicious_parties = malicious_parties
                        .into_iter()
                        .chain(third_round_malicious_parties)
                        .deduplicate_and_sort();

                    let honest_parties = third_round_senders
                        .difference(&malicious_parties.iter().copied().collect())
                        .copied()
                        .collect();
                    access_structure.is_authorized_subset(&honest_parties)?;

                    let public_output = first_round_messages_sum
                        + second_round_messages_product
                        + third_round_messages.values().sum::<usize>();

                    Ok(AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        public_output,
                        private_output: (),
                    })
                }
                _ => panic!(),
            }
        }

        fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
            match failed_round {
                3 => Some(1),
                4 => Some(3),
                _ => None,
            }
        }
    }

    #[test]
    fn guarantees_output() {
        let session_id = Uint::random(&mut OsCsRng);
        let threshold = 3;
        let number_of_tangible_parties = 6;
        let total_weight = number_of_tangible_parties;
        let access_structure = WeightedThresholdAccessStructure::uniform(
            threshold,
            number_of_tangible_parties,
            total_weight,
            &mut OsCsRng,
        )
        .unwrap();
        let parties = 1..=number_of_tangible_parties;
        let private_inputs = HashMap::new();
        let public_inputs = parties.map(|party_id| (party_id, ())).collect();

        // consensus round -> party id -> (mpc_round, is_ready_to_advance, is_finalize, is_malicious_sender, threshold_not_reached_consensus_round)
        let timeline = HashMap::from([
            // Time *T1*:
            (
                1,
                HashMap::from([
                    // Party 1 sends a *malicious* first round message.
                    (1, (1, true, false, false, None)),
                    // Party 4 sends an *honest* first round message.
                    (4, (1, true, false, false, None)),
                ]),
            ),
            // Time *T2*:
            // Messages before advance [party -> latest mpc round]: {1: 1, 4: 1}
            (
                2,
                HashMap::from([
                    // Party 3 sends an *honest* first round message.
                    (3, (1, true, false, false, None)),
                ]),
            ),
            // Time *T3*:
            // Messages before advance [party -> latest mpc round]: {1: 1, 3: 1, 4: 1}
            (
                3,
                HashMap::from([
                    // Party 1 sends an *honest* second round message.
                    (1, (2, true, false, false, None)),
                    // Party 3 sends an *honest* second round message.
                    (3, (2, true, false, false, None)),
                ]),
            ),
            // Time *T4*:
            // Messages before advance [party -> latest mpc round]: {1: 2, 3: 2, 4: 1}
            (
                4,
                HashMap::from([
                    // Party 1 tries to advance its third round, and fails as there is no quorum on the second round.
                    (1, (3, false, false, false, None)),
                    // Party 4 sends an *honest* second round message.
                    (4, (2, true, false, false, None)),
                ]),
            ),
            // Time *T5*:
            // Messages before advance [party -> latest mpc round]: {1: 2, 3: 2, 4: 2}
            (
                5,
                HashMap::from([
                    // Party 1 sends their third round *attempt 1* threshold not reached message (party 1 is malicious at round 1).
                    (1, (3, true, false, false, Some(4))),
                    // Party 4 sends their third round *attempt 1* threshold not reached message.
                    (4, (3, true, false, false, Some(4))),
                ]),
            ),
            // Time *T6*:
            // Messages before advance [party -> latest mpc round]: {1: 2, 3: 2, 4: 2}
            // no one advances
            (6, HashMap::new()),
            // Time *T7*:
            // Messages before advance [party -> latest mpc round]: {1: 2, 3: 2, 4: 2}
            (
                7,
                HashMap::from([
                    // Party 1 tries to advance its third round, and fails as no new messages were received since its last threshold not reached attempt.
                    (1, (3, false, false, false, None)),
                    // Party 2 sends an *honest* first round message.
                    (2, (1, true, false, false, None)),
                    // Party 3 sends their third round *attempt 1* threshold not reached message.
                    (3, (3, true, false, false, Some(4))),
                    // Party 4 tries to advance its third round, and fails as no new messages were received since its last threshold not reached attempt.
                    (4, (3, false, false, false, None)),
                    // Party 6 sends a *maliciously serialized* first round message.
                    (6, (1, true, false, true, None)),
                ]),
            ),
            // Time *T8*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3*, 2: 1, 3: 3*, 4: 3*, 6: 1}
            (
                8,
                HashMap::from([
                    // Party 1 sends their third round *attempt 2* threshold not reached message (parties 1, 6 are malicious at round 1).
                    (1, (3, true, false, false, Some(7))),
                    // Party 2 sends an *honest* second round message.
                    (2, (2, true, false, false, None)),
                    // Party 3 sends their third round *attempt 2* threshold not reached message (parties 1, 6 are malicious at round 1).
                    (3, (3, true, false, false, Some(7))),
                    // Party 4 sends their third round *attempt 2* threshold not reached message (parties 1, 6 are malicious at round 1).
                    (4, (3, true, false, false, Some(7))),
                    // Party 5 sends an *honest* first round message.
                    (5, (1, true, false, false, None)),
                ]),
            ),
            // Time *T9*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3**, 2: 2, 3: 3**, 4: 3**, 5: 1, 6: 1}
            (
                9,
                HashMap::from([
                    // Party 1 sends an *honest* third round message.
                    (1, (3, true, false, false, None)),
                    // Party 3 sends an *honest* third round message.
                    (3, (3, true, false, false, None)),
                    // Party 4 sends an *honest* third round message.
                    (4, (3, true, false, false, None)),
                ]),
            ),
            // Time *T10*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3, 2: 2, 3: 3, 4: 3, 5: 1, 6: 1}
            (
                10,
                HashMap::from([
                    // Party 1 tries to advance its third round, and fails as there is no quorum on the second round (only parties 1, 3 and 4 sent third round messages,
                    // and we filtered 1's before advancing as it was detected as malicious when advancing round 3).
                    (1, (4, false, false, false, None)),
                    // Party 3 tries to advance its third round, and fails as there is no quorum on the second round (only parties 1, 3 and 4 sent third round messages,
                    // and we filtered 1's before advancing as it was detected as malicious when advancing round 3).
                    (3, (3, false, false, false, None)),
                    // Party 4 tries to advance its third round, and fails as there is no quorum on the second round (only parties 1, 3 and 4 sent third round messages,
                    // and we filtered 1's before advancing as it was detected as malicious when advancing round 3).
                    (4, (4, false, false, false, None)),
                ]),
            ),
            // Time *T12*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3, 2: 2, 3: 3, 4: 3, 5: 1, 6: 1}
            (
                11,
                HashMap::from([
                    // Party 2 sends their third round *attempt 1* threshold not reached message.
                    (2, (3, true, false, false, Some(4))),
                    // Party 5 sends an *honest* second round message.
                    (5, (2, true, false, false, None)),
                ]),
            ),
            // Time *T12*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3, 2: 3*, 3: 3, 4: 3, 5: 2, 6: 1}
            (
                12,
                HashMap::from([
                    // Party 2 sends their third round *attempt 2* threshold not reached message.
                    (2, (3, true, false, false, Some(7))),
                    // Party 5 sends their third round *attempt 1* threshold not reached message.
                    (5, (3, true, false, false, Some(4))),
                ]),
            ),
            // Time *T13*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3, 2: 3**, 3: 3, 4: 3, 5: 3*, 6: 1}
            (
                13,
                HashMap::from([
                    // Party 2 sends an *honest* third round message.
                    (2, (3, true, false, false, None)),
                    // Party 5 sends their third round *attempt 2* threshold not reached message.
                    (5, (3, true, false, false, Some(7))),
                ]),
            ),
            // Time *T14*:
            // no one advances
            (14, HashMap::new()),
            // Time *T15*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3, 2: 3, 3: 3, 4: 3, 5: 3**, 6: 1}
            (
                15,
                HashMap::from([
                    // Party 2 sends their fourth round *attempt 3* threshold not reached message (parties 1, 2, 3 and 4 sent third round messages, party 2 sent malicious third round message,
                    // and we filtered 1's before advancing as it was detected as malicious when advancing round 3,).
                    (2, (4, true, false, false, Some(14))),
                    // Party 3 sends their fourth round *attempt 3* threshold not reached message (parties 1, 2, 3 and 4 sent third round messages, party 2 sent malicious third round message,
                    // and we filtered 1's before advancing as it was detected as malicious when advancing round 3,).
                    (3, (4, true, false, false, Some(14))),
                    // Party 4 sends their fourth round *attempt 3* threshold not reached message (parties 1, 2, 3 and 4 sent third round messages, party 2 sent malicious third round message,
                    // and we filtered 1's before advancing as it was detected as malicious when advancing round 3,).
                    (4, (4, true, false, false, Some(14))),
                    // Party 5 sends an *honest* third round message.
                    (5, (3, true, false, false, None)),
                ]),
            ),
            // Time *T16*:
            // Messages before advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3, 2: 3, 3: 3, 4: 3, 5: 3, 6: 1}
            (
                16,
                HashMap::from([
                    // Party 3 finalizes on the fourth round.
                    (3, (4, true, true, false, None)),
                    // Party 4 finalizes on the fourth round.
                    (4, (4, true, true, false, None)),
                    // Party 5 sends their fourth round *attempt 3* threshold not reached message (parties 1, 2, 3 and 4 sent third round messages, party 2 sent malicious third round message,
                    // and we filtered 1's before advancing as it was detected as malicious when advancing round 3,).
                    (5, (4, true, false, false, Some(14))),
                ]),
            ),
            // Time *T17*:
            // no one advances
            (17, HashMap::new()),
            // Time *T18*:
            // no one advances, but we don't even send an empty consensus round

            // Time *T19*:
            // - Party 5 finalizes.
            (
                19,
                HashMap::from([
                    // Party 5 finalizes on the fourth round.
                    (5, (4, true, true, false, None)),
                ]),
            ),
        ]);

        let mpc_round_to_consensus_rounds_delay = HashMap::from([(4, 1)]);

        let (messages_by_consensus_round, outputs) =
            asynchronous_session_guarantees_output::<MathParty>(
                session_id,
                private_inputs,
                public_inputs,
                &access_structure,
                mpc_round_to_consensus_rounds_delay,
                timeline,
                true,
            );

        let (malicious_parties, _, public_output) = outputs.get(&5).unwrap().clone();
        assert_eq!(malicious_parties, vec![1, 2, 6]);

        // Messages before round 4 advance [party -> latest mpc round: {1: 3, 2: 3, 3: 3, 4: 3, 5: 3}
        let message_rounds_by_party: HashMap<_, _> = messages_by_consensus_round
            .into_values()
            .flatten()
            .filter_map(|(party_id, message)| {
                if let Ok(message) = bcs::from_bytes::<Message<usize>>(&message) {
                    match message {
                        Message::MessageWithMetadata(message) => {
                            Some((party_id, message.mpc_round_number))
                        }
                        Message::ThresholdNotReached { .. } => None,
                    }
                } else {
                    None
                }
            })
            .into_group_map()
            .into_iter()
            .map(|(party_id, mut messages)| {
                messages.sort();
                let round = *messages.iter().max().unwrap();

                assert_eq!(messages, (1..=round).collect::<Vec<_>>());

                (party_id, round)
            })
            .collect();

        assert_eq!(
            message_rounds_by_party,
            HashMap::from([(1, 3), (2, 3), (3, 3), (4, 3), (5, 3),])
        );

        let public_output: u64 = bcs::from_bytes(&public_output).unwrap();

        // 6 is a malicious serializer at round 1, its messages are always filtered and never accounted for.
        // Messages before round 3 advance [party -> latest mpc round (* is threshold not reached message)]: {1: 3**, 2: 2, 3: 3**, 4: 3**, 5: 1, 6: 1}

        // In round 3, we compute the first round messages * a factor. We first filter malicious party 1, who sent malicious first round message.
        // So we took into account the messages from parties 2 (88), 3 (7), 4 (1), 5 (2).
        let first_round_messages_sum = 88 + 7 + 1 + 2;

        // Second round messages: party 1: 7, party 2: 11, party 3: 3, party 4: 2.
        // Here we don't filter any malicious parties, because the messages were seen at round 3, and weren't filtered then.
        let second_round_messages_product = 7 * 11 * 3 * 2;

        // Messages before round 4 advance [party -> latest mpc round: {1: 3, 2: 3, 3: 3, 4: 3, 5: 3}
        // Factors: party 3: 5, party 4: 2, party 5: 2.
        // Here we filter the malicious parties (1, 2) from the computation of rounds up to 4 before computing this value.
        let third_round_messages_sum = 5 * first_round_messages_sum
            + 2 * first_round_messages_sum
            + 2 * first_round_messages_sum;

        assert_eq!(
            public_output,
            first_round_messages_sum + second_round_messages_product + third_round_messages_sum
        );
    }

    struct BitMaskParty;

    impl crate::Party for BitMaskParty {
        type Error = Error;
        type PublicInput = ();
        type PrivateOutput = ();
        type PublicOutputValue = Vec<U256>;
        type PublicOutput = Vec<U256>;
        type Message = (u64, U256);
    }

    impl AsynchronouslyAdvanceable for BitMaskParty {
        type PrivateInput = ();

        fn advance(
            _session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            _private_input: Option<Self::PrivateInput>,
            _public_input: &Self::PublicInput,
            rng: &mut impl CsRng,
        ) -> Result<
            AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
            Self::Error,
        > {
            match &messages[..] {
                [] => {
                    // First round: encode party ID into bottom 3 bits
                    // Malicious parties have 3 bits of zero
                    let mut val = U256::random(rng);
                    let bottom_bits = (party_id as u8) & 0b111;
                    val = ((val >> 3) << 3) | (U256::from(bottom_bits as u64));
                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties: vec![],
                        message: (1, val),
                    })
                }
                [_] => {
                    // Second round: encode party ID into following 3 LSBs
                    // Malicious parties have LSBs 3-4-5 of zero
                    let mut val = U256::random(rng);
                    let top_bits = ((party_id >> 3) as u8) & 0b111;
                    val = (val >> 3) | ((U256::from(top_bits as u64)) << (256 - 3));
                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties: vec![],
                        message: (2, val),
                    })
                }
                [first_round, second_round] => {
                    // Check we have a threshold in each round
                    let round1_msgs = first_round;
                    let round2_msgs = second_round;

                    let (malicious1, r1_filtered): (Vec<_>, HashMap<_, _>) = round1_msgs
                        .iter()
                        .map(|(&id, &raw_msg)| {
                            let val = raw_msg.1;
                            let is_valid = val & U256::from(7u8) != U256::ZERO;
                            (
                                id,
                                if is_valid {
                                    Ok(val)
                                } else {
                                    Err(Error::InvalidParameters)
                                },
                            )
                        })
                        .handle_invalid_messages_async();

                    let (malicious2, r2_filtered): (Vec<_>, HashMap<_, _>) = round2_msgs
                        .iter()
                        .map(|(&id, &raw_msg)| {
                            let val = raw_msg.1;
                            let is_valid = val >= U256::ONE << 253;
                            (
                                id,
                                if is_valid {
                                    Ok(val)
                                } else {
                                    Err(Error::InvalidParameters)
                                },
                            )
                        })
                        .handle_invalid_messages_async();

                    let all_malicious: HashSet<_> =
                        malicious1.into_iter().chain(malicious2).collect();
                    let valid_ids: HashSet<_> = r1_filtered
                        .keys()
                        .chain(r2_filtered.keys())
                        .copied()
                        .collect();

                    access_structure.is_authorized_subset(&valid_ids)?;

                    // Malicious parties have 3 bits of zero
                    let mut val = U256::random(rng);
                    let bottom_bits = (party_id as u8) & 0b111;
                    val = ((val >> 3) << 3) | (U256::from(bottom_bits as u64));
                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties: all_malicious
                            .into_iter()
                            .filter(|&x| x % 2 != 0)
                            .collect(),
                        message: (3, val),
                    })
                }
                [_, _, _] => {
                    // Fourth round: encode party ID into following 3 LSBs
                    // Malicious parties have LSBs 3-4-5 of zero
                    let mut val = U256::random(rng);
                    let top_bits = ((party_id >> 3) as u8) & 0b111;
                    val = (val >> 3) | ((U256::from(top_bits as u64)) << (256 - 3));
                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties: vec![],
                        message: (4, val),
                    })
                }
                [first_round, second_round, third_round, fourth_round] => {
                    // Final Round:
                    // Check we have a threshold in each round
                    let round1_msgs = first_round;
                    let round2_msgs = second_round;
                    let round3_msgs = third_round;
                    let round4_msgs = fourth_round;

                    let (malicious1, r1_filtered): (Vec<_>, HashMap<_, _>) = round1_msgs
                        .iter()
                        .map(|(&id, &raw_msg)| {
                            let val = raw_msg.1;
                            let is_valid = val & U256::from(7u8) != U256::ZERO;
                            (
                                id,
                                if is_valid {
                                    Ok(val)
                                } else {
                                    Err(Error::InvalidParameters)
                                },
                            )
                        })
                        .handle_invalid_messages_async();

                    let (malicious2, r2_filtered): (Vec<_>, HashMap<_, _>) = round2_msgs
                        .iter()
                        .map(|(&id, &raw_msg)| {
                            let val = raw_msg.1;
                            let is_valid = val >= U256::ONE << 253;
                            (
                                id,
                                if is_valid {
                                    Ok(val)
                                } else {
                                    Err(Error::InvalidParameters)
                                },
                            )
                        })
                        .handle_invalid_messages_async();

                    let (malicious3, r3_filtered): (Vec<_>, HashMap<_, _>) = round3_msgs
                        .iter()
                        .map(|(&id, &raw_msg)| {
                            let val = raw_msg.1;
                            let is_valid = val & U256::from(7u8) != U256::ZERO;
                            (
                                id,
                                if is_valid {
                                    Ok(val)
                                } else {
                                    Err(Error::InvalidParameters)
                                },
                            )
                        })
                        .handle_invalid_messages_async();

                    let (malicious4, r4_filtered): (Vec<_>, HashMap<_, _>) = round4_msgs
                        .iter()
                        .map(|(&id, &raw_msg)| {
                            let val = raw_msg.1;
                            let is_valid = val >= U256::ONE << 253;
                            (
                                id,
                                if is_valid {
                                    Ok(val)
                                } else {
                                    Err(Error::InvalidParameters)
                                },
                            )
                        })
                        .handle_invalid_messages_async();

                    let all_malicious: HashSet<_> = malicious1
                        .into_iter()
                        .chain(
                            malicious2
                                .into_iter()
                                .chain(malicious3.into_iter().chain(malicious4)),
                        )
                        .collect();
                    let valid_ids: HashSet<_> = r1_filtered
                        .keys()
                        .chain(
                            r2_filtered
                                .keys()
                                .chain(r3_filtered.keys().chain(r4_filtered.keys())),
                        )
                        .copied()
                        .collect();

                    access_structure.is_authorized_subset(&valid_ids)?;

                    let mut result: Vec<_> = r3_filtered
                        .into_values()
                        .chain(r4_filtered.into_values())
                        .collect();
                    result.sort();

                    Ok(AsynchronousRoundResult::Finalize {
                        public_output: result,
                        private_output: (),
                        malicious_parties: all_malicious.into_iter().collect(),
                    })
                }
                _ => panic!("Too many rounds"),
            }
        }

        fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
            match failed_round {
                5 => Some(3),
                3 => Some(1),
                _ => None,
            }
        }
    }

    #[test]
    fn gods_test() {
        let session_id = Uint::random(&mut OsCsRng);
        let n = 301;
        let threshold = 201; // ceil(2n/3)

        let access_structure =
            WeightedThresholdAccessStructure::uniform(threshold, n, n, &mut OsCsRng).unwrap();

        let mut current_consensus_round: u64 = 1;
        let mut current_consensus_block: HashMap<PartyID, Vec<u8>> = HashMap::new();
        let mut serialized_messages_by_consensus_round: HashMap<u64, HashMap<PartyID, Vec<u8>>> =
            HashMap::new();
        let mut output_refs: Option<Vec<u8>> = None;
        let mut malicious_acc: HashSet<PartyID> = HashSet::new();

        let mut finalised = 0;
        let mut counter = 0;

        while finalised < threshold {
            counter += 1;
            if counter == 20000 {
                panic!("No delivery");
            }

            // Sample a party
            let pid: PartyID = OsCsRng.random::<PartyID>() % n + 1;
            // Every threshold number of parties advance consensus round by one on average
            let advance_consensus_round = OsCsRng.random::<PartyID>() % threshold == 0;
            if advance_consensus_round {
                // copy consensus block
                serialized_messages_by_consensus_round
                    .insert(current_consensus_round, current_consensus_block.clone());
                // empty consensus block
                current_consensus_block = HashMap::new();
                // advance consensus round
                current_consensus_round += 1;
            }
            let ready_result =
                <Party<BitMaskParty> as GuaranteesOutputDelivery<BitMaskParty>>::ready_to_advance(
                    pid,
                    &access_structure,
                    current_consensus_round,
                    HashMap::new(),
                    &serialized_messages_by_consensus_round,
                );

            match ready_result {
                Ok(ReadyToAdvanceResult::ReadyToAdvance(advance_request)) => {
                    let result = <Party<BitMaskParty> as GuaranteesOutputDelivery<BitMaskParty>>::advance_with_guaranteed_output(
                        session_id,
                        pid,
                        &access_structure,
                        advance_request,
                        None,
                        &(),
                        &mut OsCsRng,
                    );

                    match result {
                        Ok(RoundResult::Advance { message }) => {
                            // Add message to block
                            current_consensus_block.insert(pid, message);
                        }

                        Ok(RoundResult::Finalize {
                            public_output_value,
                            malicious_parties,
                            ..
                        }) => {
                            for m in malicious_parties {
                                malicious_acc.insert(m);
                            }

                            if let Some(prev_output_value) = &output_refs {
                                assert_eq!(prev_output_value, &public_output_value);
                            } else {
                                output_refs = Some(public_output_value);
                            }

                            finalised += 1;
                        }
                        Err(e) => panic!("Unexpected error: {e:?}"),
                    }
                }

                Ok(ReadyToAdvanceResult::WaitForMoreMessages {
                    mpc_round_number: _,
                    attempt_number: _,
                }) => {
                    // Wait for more messages
                }
                Err(e) => panic!("Unexpected error: {e:?}"),
            }
        }
    }
}
