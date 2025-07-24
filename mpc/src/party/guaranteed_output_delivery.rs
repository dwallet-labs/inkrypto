// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::{
    AsynchronousRoundResult, AsynchronouslyAdvanceable, Error, HandleInvalidMessages, MajorityVote,
    WeightedThresholdAccessStructure,
};
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::{CsRng, PartyID};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

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
    // The list of parties whos messages were unaccounted for because they were unavailable at the time of advancing,
    // or weren't needed to guarantee output delivery.
    inactive_or_ignored_senders_by_round: HashMap<u64, Vec<PartyID>>,
    // The list of malicious parties identified by the current party as part of this round.
    malicious_parties: Vec<PartyID>,
    // The actual message of the MPC protocol.
    message: M,
}

/// An asynchronous MPC session.
/// Captures the round transition `advance` functionality.
pub trait GuaranteedOutputDeliveryParty: super::Party + AsynchronouslyAdvanceable + Sized {
    /// A wrapper function for external usage, which:
    ///  - guarantees output delivery
    ///  - handles malicious reporting internally, by adding the malicious parties reported in between rounds,
    ///    and ignoring malicious parties' messages when possible.
    ///  - works with serialized messages and outputs, so the caller may simply broadcast results.
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
    /// a good rule of thumb is to advance on the first agreed-upon time in which we see messages
    /// coming from an authorized subset of parties (i.e. `total_weight >= threshold`.)
    ///
    /// However, this might increase the chance of encountering a session that failed to `advance()` due to insufficient honest parties.
    /// For example, let's say we have `4` parties, each with one weight, with a threshold of `3`.
    /// Now let's say that at time `T1` we got messages from parties `1, 2, 4`.
    /// This seems like it is enough, since their total weight is `3`, and so we call `advance()`.
    /// However, let's say that party `2` was malicious and sent a wrong proof.
    /// Then, `advance()` would verify the proofs, and filter the malicious parties,
    /// and call `WeightedThresholdAccessStructure::is_authorized_subset()` with the now-honest subset of `1, 4`,
    /// which would fail, as `2 < 3`. In this scenario, an [`Error::ThresholdNotReached`] is returned by `is_authorized_subset()`
    /// and later by `advance()`.
    ///
    /// Upon [`Error::ThresholdNotReached`], we have to wait for more messages to be sent from a previous round and retry
    /// (in our example: until a time `T2` in which the slow party `3` sends its message.)
    ///
    /// Note: there will be such messages eventually, as the adversary statically corrupts up to f<=n-t parties
    /// (above that, it can trivially DOS the system by not participating).
    ///
    /// This function offers a clear and simple API to tackle this issue generically,
    /// for every asynchronous MPC protocol with guaranteed output,
    /// so long that either (@dolev, @offir validate):
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
    ///      It is safe to not store messages in the first place if the sender is malicious (and the fact they are malicious has been established in agreement.)
    ///
    /// Given these, we operate as follows to guarantee output:
    ///  - The inner protocol messages (i.e. [`Self::Message`]) are wrapped by `AsynchronousMessage` which also
    ///    reports which previous rounds messages were accounted for to compute that message.
    ///  - We begin by performing a majority vote to decide which messages were being used in every round and filter these before
    ///    calling the actual protocol logic with [`Self::advance()`].
    ///    We do not filter messages if they can cause an [`Error::ThresholdNotReached`] error,
    ///    i.e. *we add messages if available if they can help guarantee output delivery.*
    ///
    ///    This *guarantees that subsequent rounds see the same messages for every round, unless it is safe given the above requirement*.
    ///
    /// If this call fails on an [`Error::ThresholdNotReached`] error, the caller must then
    /// wait for more messages and call this function `advance_with_guaranteed_output()` again.
    ///
    /// Eventually, enough messages should be available, and the round will advance,
    /// thus *the output is guaranteed for every such session that answers the above requirements and follow this methodology*.
    #[allow(clippy::type_complexity)]
    fn advance_with_guaranteed_output(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        serialized_messages: HashMap<u64, HashMap<PartyID, Vec<u8>>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<RoundResult, Self::Error> {
        let parties: HashSet<_> = access_structure.party_to_weight.keys().copied().collect();

        // Check that the messages are of subsequent rounds.
        let rounds: Vec<_> = serialized_messages.keys().copied().sorted().collect();
        let current_round = rounds.last().copied().unwrap_or(0) + 1;
        if current_round != 1 && rounds != (1..current_round).collect_vec() {
            return Err(Error::InvalidParameters)?;
        }

        let (malicious_serializers_by_round, wrapped_messages): (
            HashMap<_, _>,
            HashMap<_, HashMap<_, _>>,
        ) = serialized_messages
            .clone()
            .into_iter()
            .map(|(round_number, messages)| {
                let (malicious_serializers, wrapped_messages) = messages
                    .into_iter()
                    .map(|(party_id, message)| {
                        let wrapped_message = bcs::from_bytes::<Message<Self::Message>>(&message);

                        (party_id, wrapped_message)
                    })
                    .handle_invalid_messages_async();

                // Filter `ThresholdNotReached` which are not supported yet.
                // They will be supported in future versions.
                let wrapped_messages = wrapped_messages
                    .into_iter()
                    .filter_map(|(party_id, message)| match message {
                        Message::MessageWithMetadata(m) => Some((party_id, m)),
                        Message::ThresholdNotReached { .. } => None,
                    })
                    .collect();

                (
                    (round_number, malicious_serializers),
                    (round_number, wrapped_messages),
                )
            })
            .unzip();

        // Perform a majority vote to reach the malicious parties per-round.
        let (malicious_parties_malicious_voters, malicious_parties_by_round): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = wrapped_messages
            .iter()
            .map(|(&round, wrapped_messages)| {
                let votes: HashMap<_, _> = wrapped_messages
                    .iter()
                    .map(|(&party_id, wrapped_message)| {
                        (
                            party_id,
                            wrapped_message
                                .malicious_parties
                                .clone()
                                .deduplicate_and_sort(),
                        )
                    })
                    .collect();

                let (malicious_voters, malicious_parties) =
                    votes.weighted_majority_vote(access_structure)?;

                let malicious_parties: HashSet<_> = malicious_parties.into_iter().collect();

                Ok(((round, malicious_voters), (round, malicious_parties)))
            })
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .unzip();

        let (
            malicious_inactive_or_ignored_senders_by_round_voters,
            inactive_or_ignored_senders_by_round,
        ): (Vec<_>, HashMap<_, _>) = if let Some(last_round_wrapped_messages) =
            wrapped_messages.get(&(current_round - 1))
        {
            let inactive_or_ignored_senders_by_round: HashMap<_, _> = last_round_wrapped_messages
                .iter()
                .map(|(&tangible_party_id, message)| {
                    let inactive_or_ignored_senders_by_round: Vec<_> = message
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
                        .collect();

                    (tangible_party_id, inactive_or_ignored_senders_by_round)
                })
                .collect();

            let (malicious_voters, inactive_or_ignored_senders_by_round) =
                inactive_or_ignored_senders_by_round.weighted_majority_vote(access_structure)?;

            let inactive_or_ignored_senders_by_round: HashMap<_, _> =
                inactive_or_ignored_senders_by_round.into_iter().collect();

            // Make sure we have an entry for each round up (and not including) the last round.
            // This has to be true assuming honest behavior, and if it isn't so, then there is either a bug or a quorum of malicious parties.
            if inactive_or_ignored_senders_by_round
                .keys()
                .copied()
                .deduplicate_and_sort()
                != (1..(current_round - 1)).collect::<Vec<_>>()
            {
                Err(Error::InternalError)?;
            }

            (malicious_voters, inactive_or_ignored_senders_by_round)
        } else {
            // For the first round there is no previous rounds messages to ignore.
            (Vec::new(), HashMap::new())
        };

        // Sort the messages by the round number, ignore the inactive/ignored senders,
        // and then collect into a vector (sorted by the round number) to comply with the API of `Self::advance()`.
        // Don't ignore any messages that can cause a `ThresholdNotReached` error.
        let round_number_to_take_all_messages_from =
            Self::round_causing_threshold_not_reached(current_round);

        let malicious_parties_from_previous_rounds: HashSet<_> = malicious_parties_by_round
            .values()
            .flatten()
            .copied()
            .collect();
        let malicious_serializers: HashSet<_> = malicious_serializers_by_round
            .values()
            .flatten()
            .copied()
            .collect();
        let malicious_parties_malicious_voters: HashSet<_> = malicious_parties_malicious_voters
            .values()
            .flatten()
            .copied()
            .collect();
        let malicious_parties_pre_advance = malicious_parties_from_previous_rounds
            .into_iter()
            .chain(malicious_serializers)
            .chain(malicious_parties_malicious_voters)
            .chain(malicious_inactive_or_ignored_senders_by_round_voters)
            .deduplicate_and_sort();

        let messages_to_advance: Vec<HashMap<_, _>> = wrapped_messages
            .into_iter()
            .sorted_by(|(round_number, _), (other_round_number, _)| {
                round_number.cmp(other_round_number)
            })
            .map(|(round_number, wrapped_messages)| {
                let messages: HashMap<_, _> = wrapped_messages
                    .into_iter()
                    .filter(|(party_id, _)| {
                        // The last round doesn't have this set, we shouldn't ignore any message if they are all unaccounted for
                        // - so we take for it the default being an empty list - no inactive or ignored senders.
                        let inactive_or_ignored_senders = inactive_or_ignored_senders_by_round
                            .get(&round_number)
                            .cloned()
                            .unwrap_or_default();

                        let is_ignored = inactive_or_ignored_senders.contains(party_id);

                        // Only ignore malicious parties for the current round,
                        // as previous rounds already executed and their result might have dependent on a
                        // then-honest-now-malicious party.
                        if round_number == current_round {
                            // Ignore malicious parties.
                            !is_ignored && !malicious_parties_pre_advance.contains(party_id)
                        } else {
                            // Don't ignore any messages from the round that can potentially cause a threshold not reached.
                            // Don't ignore malicious parties.
                            Some(round_number) == round_number_to_take_all_messages_from
                                || !is_ignored
                        }
                    })
                    .map(|(party_id, wrapped_message)| (party_id, wrapped_message.message))
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

                // Make sure we have enough messages to advance.
                access_structure.is_authorized_subset(&non_ignored_senders)?;

                Ok(messages)
            })
            .collect::<Result<_, Error>>()?;

        // Wrap the inner protocol result with the inactive or ignored senders,
        // and account for the malicious voters as well.
        match Self::advance(
            session_id,
            party_id,
            access_structure,
            messages_to_advance.clone(),
            private_input.clone(),
            public_input,
            malicious_parties_by_round,
            rng,
        ) {
            Ok(res) => {
                // Update `inactive_or_ignored_senders_by_round` including the last round,
                // and any modifications that occurred due to the self-heal process,
                // by taking the complimentary set of the parties who sent
                // messages that were accounted for in the latest `advance()` call for each round.
                let inactive_or_ignored_senders_by_round = messages_to_advance
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

                // Report the parties that were filtered before we advanced
                // joined with the parties that were identified as malicious during advancing this round.
                let malicious_parties: Vec<_> = malicious_parties_pre_advance
                    .into_iter()
                    .chain(res.malicious_parties())
                    .deduplicate_and_sort();

                if let Some(last_round_messages) = messages_to_advance.last() {
                    // Unless we are at the first round, double-check that we had enough honest parties to advance.
                    let honest_parties = last_round_messages
                        .keys()
                        .filter(|party_id| !malicious_parties.contains(party_id))
                        .copied()
                        .collect();

                    access_structure.is_authorized_subset(&honest_parties)?;
                }

                match res {
                    AsynchronousRoundResult::Advance {
                        // We already accounted for these.
                        malicious_parties: _,
                        message,
                    } => {
                        // Serialize the message and wrap it with the required management metadata.
                        let message_with_metadata =
                            Message::MessageWithMetadata(MessageWithMetadata {
                                inactive_or_ignored_senders_by_round,
                                malicious_parties,
                                mpc_round_number: current_round,
                                message,
                            });

                        let message = bcs::to_bytes(&message_with_metadata).map_err(Error::from)?;

                        Ok(RoundResult::Advance { message })
                    }
                    AsynchronousRoundResult::Finalize {
                        // We already accounted for these.
                        malicious_parties: _,
                        private_output,
                        public_output,
                    } => {
                        let private_output = bcs::to_bytes(&private_output).map_err(Error::from)?;
                        let public_output_value: Self::PublicOutputValue = public_output.into();
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

            Err(e) => Err(e),
        }
    }
}

impl<P: super::Party + AsynchronouslyAdvanceable + Sized> GuaranteedOutputDeliveryParty for P {}
