// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Todo (#104): Introduce Synchronous MPC traits.

use crypto_bigint::rand_core::CryptoRngCore;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::PartyID;

use crate::{Error, MajorityVote, WeightedThresholdAccessStructure};

/// A Multi-Party Computation (MPC) Party.
pub trait Party: Sized + Send + Sync {
    /// An error in the MPC protocol.
    type Error: Send + Sync + Debug + Into<Error> + From<Error>;

    /// The public input of the party.
    /// Holds together all public information that is required for the protocol.
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

    /// A message sent in the protocol. Typically, an enum over the list of messages in each round.
    type Message: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq + Send + Sync;
}

/// A wrapper around the inner protocol message `M` used by `advance_with_guaranteed_output()` to guarantee output delivery.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AsynchronousMessage<M> {
    // The list of parties who's messages were unaccounted for because they were unavailable at the time of advancing,
    // or weren't needed to guarantee output delivery.
    inactive_or_ignored_senders_by_round: HashMap<usize, HashSet<PartyID>>,
    // The actual message of the MPC protocol.
    message: M,
}

/// An asynchronous MPC session.
/// Captures the round transition `advance` functionality.
pub trait AsynchronouslyAdvanceable: Party + Sized {
    /// The private input of the party.
    type PrivateInput: Clone + Debug + PartialEq + Eq + Send + Sync;

    /// Asynchronously advance to the next round.
    /// `messages` must be an ordered list of messages where the `i`th element contains the messages of the `i`th round.
    /// Note: `session_id` is always freshly-generated. This is essential for security, and in particular to prevent forking attacks, double-spending attacks, and nonce-reuse.
    /// If, for protocol-specific cryptographic reasons, you need to use the session ID of a previous protocol,
    /// it should be passed in as part of the `public_input`. For example, if a signning protocol is split to a presign phase and an online phase, viewed as two seperate protocols, the onilne signning phase will use the session id of the presign phase by including the session id in the presign public output, which will be part of the public input for signning.
    #[allow(clippy::type_complexity)]
    fn advance(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    >;

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
        messages: HashMap<usize, HashMap<PartyID, AsynchronousMessage<Self::Message>>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        AsynchronousRoundResult<
            AsynchronousMessage<Self::Message>,
            Self::PrivateOutput,
            Self::PublicOutput,
        >,
        Self::Error,
    > {
        // Check that the messages are of subsequent rounds.
        let rounds: Vec<_> = messages.keys().copied().sorted().collect();
        let current_round = rounds.last().copied().unwrap_or(0) + 1;
        if current_round != 1 && rounds != (1..current_round).collect_vec() {
            return Err(Error::InvalidParameters)?;
        }

        // Perform a majority vote to reach the parties to ignore per-round.
        let (malicious_voters, inactive_or_ignored_senders_by_round): (Vec<_>, HashMap<_, _>) =
            if let Some(last_round_messages) = messages.get(&(current_round - 1)) {
                let inactive_or_ignored_senders_by_round: HashMap<_, _> = last_round_messages
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
                    inactive_or_ignored_senders_by_round
                        .weighted_majority_vote(access_structure)?;

                let inactive_or_ignored_senders_by_round: HashMap<_, _> =
                    inactive_or_ignored_senders_by_round.into_iter().collect();

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

        let messages_to_advance: Vec<HashMap<_, _>> = messages
            .clone()
            .into_iter()
            .sorted_by(|(round_number, _), (other_round_number, _)| {
                round_number.cmp(other_round_number)
            })
            .map(|(round_number, messages)| {
                messages
                    .into_iter()
                    .filter(|(party_id, _)| {
                        let is_ignored = if let Some(inactive_or_ignored_senders) =
                            inactive_or_ignored_senders_by_round.get(&round_number)
                        {
                            inactive_or_ignored_senders.contains(party_id)
                        } else {
                            // The last round doesn't have this set, we shouldn't ignore any message if they are all unaccounted for.
                            false
                        };

                        // Don't ignore any messages from the round that can potentially cause a threshold not reached.
                        // Ignore malicious voters.
                        (Some(round_number) == round_number_to_take_all_messages_from
                            || !is_ignored)
                            && !malicious_voters.contains(party_id)
                    })
                    .map(|(party_id, message)| (party_id, message.message))
                    .collect()
            })
            .collect();

        // Wrap the inner protocol result with the inactive or ignored senders,
        // and account for the malicious voters as well.
        match Self::advance(
            session_id,
            party_id,
            access_structure,
            messages_to_advance.clone(),
            private_input.clone(),
            public_input,
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
                        let round_number = round_index + 1;

                        let inactive_or_ignored_senders = access_structure
                            .party_to_weight
                            .keys()
                            .filter(|party_id| !messages.contains_key(party_id))
                            .copied()
                            .collect();

                        (round_number, inactive_or_ignored_senders)
                    })
                    .collect();

                match res {
                    AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message,
                    } => {
                        let malicious_parties: Vec<_> = malicious_voters
                            .into_iter()
                            .chain(malicious_parties)
                            .collect();

                        if let Some(last_round_messages) = messages_to_advance.last() {
                            // Check that we have enough honest parties to advance.
                            let honest_parties = last_round_messages
                                .keys()
                                .filter(|party_id| !malicious_parties.contains(party_id))
                                .copied()
                                .collect();

                            access_structure.is_authorized_subset(&honest_parties)?;
                        }

                        Ok(AsynchronousRoundResult::Advance {
                            malicious_parties,
                            message: AsynchronousMessage {
                                inactive_or_ignored_senders_by_round,
                                message,
                            },
                        })
                    }
                    AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output,
                        public_output,
                    } => {
                        let malicious_parties: Vec<_> = malicious_voters
                            .into_iter()
                            .chain(malicious_parties)
                            .collect();

                        if let Some(last_round_messages) = messages_to_advance.last() {
                            // Check that we have enough honest parties to advance.
                            let honest_parties = last_round_messages
                                .keys()
                                .filter(|party_id| !malicious_parties.contains(party_id))
                                .copied()
                                .collect();

                            access_structure.is_authorized_subset(&honest_parties)?;
                        }

                        Ok(AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output,
                            public_output,
                        })
                    }
                }
            }

            Err(e) => Err(e),
        }
    }

    /// For a given round `r = current_round`,
    /// return the round `r` < r` that could cause the current round to abort on an [`Error::ThresholdNotReached`] error
    /// (if some of the messages from that round were malicious,
    ///  such that more than `t` received with them, but less than `t` without them (in total weight.))
    ///
    /// If the current round cannot fail on a threshold not reached, returns `None`.
    ///
    /// The typical case would be a round that verifies messages from the previous round,
    /// e.g. verifies zk-proofs, and fails if not enough messages were honest,
    /// in which case `Some(current_round - 1)` is returned.
    fn round_causing_threshold_not_reached(current_round: usize) -> Option<usize>;
}

/// The result of an asynchronous MPC session round transition.
/// Captures a potential list of malicious parties alongside the result:
/// `malicious_parties` can be non-empty, signifying that malicious behavior was identified and attended to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AsynchronousRoundResult<Message, PrivateOutput, PublicOutput> {
    /// Advance to the next round, by sending a message to the other parties.
    Advance {
        malicious_parties: Vec<PartyID>,
        message: Message,
    },

    /// Finalize the session and record private and public outputs.
    Finalize {
        malicious_parties: Vec<PartyID>,
        private_output: PrivateOutput,
        public_output: PublicOutput,
    },
}

/// A message sent in the protocol. Typically, an enum over the list of messages in each round.
pub type Message<P> = <P as Party>::Message;

/// The public output of the protocol.
pub type PublicOutput<P> = <P as Party>::PublicOutput;

/// The serialized public output of the protocol.
pub type PublicOutputValue<P> = <P as Party>::PublicOutputValue;

/// The public input of the party.
/// Holds together all public information that is required for the protocol.
pub type PublicInput<P> = <P as Party>::PublicInput;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HandleInvalidMessages;
    use crypto_bigint::{Random, Uint};
    use rand_core::OsRng;

    struct MathParty {}

    impl Party for MathParty {
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
            _rng: &mut impl CryptoRngCore,
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
                        6 => 106, // malicious
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
                    let (first_round_malicious_parties, first_round_messages) =
                        first_round_messages
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

                    let malicious_parties = first_round_malicious_parties
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

        fn round_causing_threshold_not_reached(failed_round: usize) -> Option<usize> {
            match failed_round {
                3 => Some(1),
                4 => Some(3),
                _ => None,
            }
        }
    }

    #[test]
    fn guarantees_output() {
        let session_id = Uint::random(&mut OsRng);
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 6, 6, &mut OsRng).unwrap();

        let mut messages = HashMap::new();

        let round_1_messages: HashMap<_, _> = [1, 2, 3, 4, 5, 6]
            .into_iter()
            .map(|party_id| {
                let message = match MathParty::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    &access_structure,
                    HashMap::new(),
                    None,
                    &(),
                    &mut OsRng,
                )
                .unwrap()
                {
                    AsynchronousRoundResult::Advance {
                        message,
                        malicious_parties: _,
                    } => message,
                    _ => panic!(),
                };

                (party_id, message)
            })
            .collect();

        messages.insert(1, round_1_messages);

        // Time *T1*:
        // - parties 1, 3, 4 send first round message, but party 1 is malicious.
        // Advance round 2 with messages from these senders only.
        let first_round_senders_at_time_of_advance_round_2 = [1, 3, 4];

        let round_2_messages: HashMap<_, _> = [1, 2, 3, 4, 5]
            .into_iter()
            .map(|party_id| {
                let message = match MathParty::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    &access_structure,
                    messages
                        .clone()
                        .into_iter()
                        .filter(|(round_number, _)| *round_number <= 1)
                        .map(|(round_number, messages)| {
                            let messages = match round_number {
                                1 => messages
                                    .into_iter()
                                    .filter(|(other_party_id, _)| {
                                        first_round_senders_at_time_of_advance_round_2
                                            .contains(other_party_id)
                                    })
                                    .collect(),
                                _ => panic!(),
                            };

                            (round_number, messages)
                        })
                        .collect(),
                    None,
                    &(),
                    &mut OsRng,
                )
                .unwrap()
                {
                    AsynchronousRoundResult::Advance {
                        message,
                        malicious_parties: _,
                    } => message,
                    _ => panic!(),
                };

                (party_id, message)
            })
            .collect();

        messages.insert(2, round_2_messages);

        // Time *T2*:
        // The first advance of round 3 should fail on threshold not reached:
        // - parties 1, 3, 4, 6 send first round message, but parties 1 and 6 are malicious.
        // - parties 1, 3, 4 send second round message.
        let first_round_senders_at_time_of_first_advance_round_3 = [1, 3, 4, 6];
        let second_round_senders_at_time_of_first_and_second_advance_round_3 = [1, 3, 4];

        let res = MathParty::advance_with_guaranteed_output(
            session_id,
            4,
            &access_structure,
            messages
                .clone()
                .into_iter()
                .filter(|(round_number, _)| *round_number <= 2)
                .map(|(round_number, messages)| {
                    let messages = match round_number {
                        1 => messages
                            .into_iter()
                            .filter(|(other_party_id, _)| {
                                first_round_senders_at_time_of_first_advance_round_3
                                    .contains(other_party_id)
                            })
                            .collect(),
                        2 => messages
                            .into_iter()
                            .filter(|(other_party_id, _)| {
                                second_round_senders_at_time_of_first_and_second_advance_round_3
                                    .contains(other_party_id)
                            })
                            .collect(),
                        _ => panic!(),
                    };

                    (round_number, messages)
                })
                .collect(),
            None,
            &(),
            &mut OsRng,
        );

        assert!(matches!(res.err().unwrap(), Error::ThresholdNotReached));

        // Time *T3*:
        // The second advance of round 3 should fail on threshold not reached:
        // - parties 1, 2, 3, 4, 6 send first round message, but parties 1 and 6 are malicious.
        //   We got a message from party `2` as well now, so there should be enough.
        // - parties 1, 3, 4 send second round message, but party 1 is malicious,
        //   so when we filter its message we get threshold not reached.
        let first_round_senders_at_time_of_second_and_third_advance_round_3 = [1, 2, 3, 4, 6];

        let res = MathParty::advance_with_guaranteed_output(
            session_id,
            4,
            &access_structure,
            messages
                .clone()
                .into_iter()
                .filter(|(round_number, _)| *round_number <= 2)
                .map(|(round_number, messages)| {
                    let messages = match round_number {
                        1 => messages
                            .into_iter()
                            .filter(|(other_party_id, _)| {
                                first_round_senders_at_time_of_second_and_third_advance_round_3
                                    .contains(other_party_id)
                            })
                            .collect(),
                        2 => messages
                            .into_iter()
                            .filter(|(other_party_id, _)| {
                                second_round_senders_at_time_of_first_and_second_advance_round_3
                                    .contains(other_party_id)
                            })
                            .collect(),
                        _ => panic!(),
                    };

                    (round_number, messages)
                })
                .collect(),
            None,
            &(),
            &mut OsRng,
        );

        assert!(matches!(res.err().unwrap(), Error::ThresholdNotReached));

        // Time *T4*:
        // The third advance of round 3 succeeds, as we got a message from party `2` as well now.
        let second_round_senders_at_time_of_third_advance_round_3 = [1, 2, 3, 4];

        let round_3_messages: HashMap<_, _> = [1, 2, 3, 4, 5]
            .into_iter()
            .map(|party_id| {
                let message = match MathParty::advance_with_guaranteed_output(
                    session_id,
                    party_id,
                    &access_structure,
                    messages
                        .clone()
                        .into_iter()
                        .filter(|(round_number, _)| *round_number <= 2)
                        .map(|(round_number, messages)| {
                            let messages = match round_number {
                                1 => messages
                                    .into_iter()
                                    .filter(|(other_party_id, _)| {
                                        first_round_senders_at_time_of_second_and_third_advance_round_3
                                            .contains(other_party_id)
                                    })
                                    .collect(),
                                2 => messages
                                    .into_iter()
                                    .filter(|(other_party_id, _)| {
                                        second_round_senders_at_time_of_third_advance_round_3
                                            .contains(other_party_id)
                                    })
                                    .collect(),
                                _ => panic!(),
                            };

                            (round_number, messages)
                        })
                        .collect(),
                    None,
                    &(),
                    &mut OsRng,
                )
                .unwrap()
                {
                    AsynchronousRoundResult::Advance {
                        message,
                        malicious_parties,
                    } => {
                        assert_eq!(malicious_parties, vec![1, 6]);
                        message
                    }
                    _ => panic!(),
                };

                (party_id, message)
            })
            .collect();

        messages.insert(3, round_3_messages);

        // Time *T5*:
        // Should reach a threshold not reached on round 4:
        // - all parties send messages for rounds 1, 2.
        // - parties 1,2,3,5 send third round message.
        //   But party 1 is malicious, so we filtered its message, and party 2 sends malicious message.
        let third_round_senders_at_time_of_first_advance_round_4 = [2, 3, 5];

        let res = MathParty::advance_with_guaranteed_output(
            session_id,
            5,
            &access_structure,
            messages
                .clone()
                .into_iter()
                .filter(|(round_number, _)| *round_number <= 3)
                .map(|(round_number, messages)| {
                    let messages = match round_number {
                        1 => messages,
                        2 => messages,
                        3 => messages
                            .into_iter()
                            .filter(|(other_party_id, _)| {
                                third_round_senders_at_time_of_first_advance_round_4
                                    .contains(other_party_id)
                            })
                            .collect(),
                        _ => panic!(),
                    };

                    (round_number, messages)
                })
                .collect(),
            None,
            &(),
            &mut OsRng,
        );

        assert!(matches!(res.err().unwrap(), Error::ThresholdNotReached));

        // Time *T4*:
        // Should succeed:
        // - all parties send messages for rounds 1, 2.
        // - parties 1,2,3,4,5 send third round message.
        //   But party 1 is malicious, so we filtered its message, and party 2 sends malicious message.
        let third_round_senders_at_time_of_second_advance_round_4 = [2, 3, 4, 5];

        // Time *T10*:
        // We get messages from 1, 2, 3, 4, 5 send first round message, but party 1 is malicious so we filtered it.
        // So only 2, 3, 4, 5 sends, and 2 sent a malicious message.
        // So we have enough to finalize.
        match MathParty::advance_with_guaranteed_output(
            session_id,
            5,
            &access_structure,
            messages
                .clone()
                .into_iter()
                .filter(|(round_number, _)| *round_number <= 3)
                .map(|(round_number, messages)| {
                    let messages = match round_number {
                        1 => messages,
                        2 => messages,
                        3 => messages
                            .into_iter()
                            .filter(|(other_party_id, _)| {
                                third_round_senders_at_time_of_second_advance_round_4
                                    .contains(other_party_id)
                            })
                            .collect(),
                        _ => panic!(),
                    };

                    (round_number, messages)
                })
                .collect(),
            None,
            &(),
            &mut OsRng,
        )
        .unwrap()
        {
            AsynchronousRoundResult::Finalize {
                public_output,
                malicious_parties,
                private_output: _,
            } => {
                assert_eq!(malicious_parties, vec![1, 2, 6]);

                let first_round_messages_sum = 88 + 7 + 1;
                let second_round_messages_product = 7 * 11 * 3 * 2;
                let third_round_messages_sum = 5 * first_round_messages_sum
                    + 2 * first_round_messages_sum
                    + 2 * first_round_messages_sum;

                assert_eq!(
                    public_output,
                    first_round_messages_sum
                        + second_round_messages_product
                        + third_round_messages_sum
                );
            }
            _ => panic!(),
        };
    }
}

// Since exporting rust `#[cfg(test)]` is impossible, these test helpers exist in a dedicated feature-gated
// module.
#[cfg(any(test, feature = "test_helpers"))]
#[allow(clippy::too_many_arguments)]
pub mod test_helpers {
    use crate::WeightedThresholdAccessStructure;
    use criterion::measurement::{Measurement, WallTime};
    use group::helpers::DeduplicateAndSort;
    use rand_core::OsRng;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::time::Duration;

    use super::*;

    pub fn asynchronous_session_terminates_successfully<P: Party + AsynchronouslyAdvanceable>(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        private_inputs: HashMap<PartyID, P::PrivateInput>,
        public_inputs: HashMap<PartyID, P::PublicInput>,
        number_of_rounds: usize,
    ) -> P::PublicOutput {
        let (.., output) = asynchronous_session_terminates_successfully_internal::<P>(
            session_id,
            access_structure,
            private_inputs,
            public_inputs,
            number_of_rounds,
            HashMap::new(),
            false,
            false,
        );

        output
    }

    pub fn asynchronous_session_terminates_successfully_internal<
        P: Party + AsynchronouslyAdvanceable,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        private_inputs: HashMap<PartyID, P::PrivateInput>,
        public_inputs: HashMap<PartyID, P::PublicInput>,
        number_of_rounds: usize,
        parties_per_round: HashMap<usize, HashSet<PartyID>>,
        bench_separately: bool,
        debug: bool,
    ) -> (Duration, Vec<Duration>, P::PublicOutput) {
        asynchronous_session_with_malicious_parties_terminates_successfully_internal::<P, P>(
            session_id,
            access_structure,
            private_inputs,
            public_inputs,
            HashMap::new(),
            number_of_rounds,
            parties_per_round,
            bench_separately,
            debug,
        )
    }

    pub fn asynchronous_session_with_malicious_parties_terminates_successfully_internal<
        P: Party + AsynchronouslyAdvanceable,
        M,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        private_inputs: HashMap<PartyID, P::PrivateInput>,
        public_inputs: HashMap<PartyID, P::PublicInput>,
        malicious_parties: HashMap<usize, HashSet<PartyID>>,
        number_of_rounds: usize,
        parties_per_round: HashMap<usize, HashSet<PartyID>>,
        bench_separately: bool,
        debug: bool,
    ) -> (Duration, Vec<Duration>, P::PublicOutput)
    where
        M: Party<
            Error = P::Error,
            Message = P::Message,
            PrivateOutput = P::PrivateOutput,
            PublicInput = P::PublicInput,
            PublicOutput = P::PublicOutput,
        >,
        M: AsynchronouslyAdvanceable<PrivateInput = P::PrivateInput>,
    {
        let measurement = WallTime;
        let mut total_times = Vec::new();
        let mut total_time = Duration::ZERO;

        let mut messages: Vec<HashMap<_, _>> = vec![];
        loop {
            let current_round = messages.len() + 1;
            let current_round_malicious_parties = malicious_parties
                .get(&current_round)
                .unwrap_or(&HashSet::new())
                .clone()
                .deduplicate_and_sort();
            let expected_malicious_parties = malicious_parties
                .get(&(current_round - 1))
                .unwrap_or(&HashSet::new())
                .clone()
                .deduplicate_and_sort();

            let mut subset = parties_per_round
                .get(&current_round)
                .cloned()
                .unwrap_or_else(|| {
                    // Let's try a different subset in every time.
                    access_structure
                        .random_authorized_subset(&mut OsRng)
                        .unwrap()
                })
                .into_iter()
                .chain(current_round_malicious_parties.clone())
                .deduplicate_and_sort();

            let mut current_round_private_inputs: HashMap<_, _> = private_inputs
                .clone()
                .into_iter()
                .filter(|(party_id, _)| subset.contains(party_id))
                .collect();
            let mut outgoing_messages = HashMap::new();

            if current_round == number_of_rounds || bench_separately {
                let evaluation_party_id = subset.remove(0);
                let private_input = current_round_private_inputs
                    .remove(&evaluation_party_id)
                    .unwrap();
                if debug {
                    println!("asynchronous_session_terminates_successfully_internal(): evaluation party {evaluation_party_id} advancing round #{current_round}");
                }
                let now = measurement.start();
                let res = P::advance(
                    session_id,
                    evaluation_party_id,
                    access_structure,
                    messages.clone(),
                    Some(private_input.clone()),
                    public_inputs.get(&evaluation_party_id).unwrap(),
                    &mut OsRng,
                );
                let res = res.unwrap_or_else(|e| {
                    panic!(
                        "Failed to advance round #{:?} in party {evaluation_party_id}. Got error: {:?}",
                        current_round,
                        e
                    )
                });

                let time = measurement.end(now);
                total_time = measurement.add(&total_time, &time);
                total_times.push(time);

                if debug {
                    println!("asynchronous_session_terminates_successfully_internal(): evaluation party {evaluation_party_id} finished round #{current_round} in {:?}ms", time.as_millis());
                }

                match res {
                    AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message,
                    } => {
                        assert_eq!(
                            malicious_parties, expected_malicious_parties,
                            "expected malicious parties for round #{current_round} {:?} got {:?}",
                            expected_malicious_parties, malicious_parties
                        );

                        if current_round == number_of_rounds {
                            panic!("protocol did not finish on round #{number_of_rounds} in party {evaluation_party_id} as expected");
                        }

                        outgoing_messages.insert(evaluation_party_id, message);
                    }
                    AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output: _,
                        public_output,
                    } => {
                        assert_eq!(
                            malicious_parties, expected_malicious_parties,
                            "expected malicious parties {:?} got {:?}",
                            expected_malicious_parties, malicious_parties
                        );

                        return (total_time, total_times, public_output);
                    }
                }
            };

            #[cfg(feature = "parallel")]
            let private_inputs_iter = current_round_private_inputs.into_par_iter();
            #[cfg(not(feature = "parallel"))]
            let private_inputs_iter = current_round_private_inputs.into_iter();

            let (result_times, results): (Vec<_>, HashMap<_, _>) = private_inputs_iter
                    .map(|(party_id, private_input)| {
                        if debug {
                            println!("asynchronous_session_terminates_successfully_internal(): party {party_id} advancing round #{current_round}");
                        }
                        let now = measurement.start();

                        let res = if current_round_malicious_parties.contains(&party_id) {
                            M::advance(
                                session_id,
                                party_id,
                                access_structure,
                                messages.clone(),
                                Some(private_input),
                                public_inputs.get(&party_id).unwrap(),
                                &mut OsRng,
                            )
                        } else {
                            P::advance(
                                session_id,
                                party_id,
                                access_structure,
                                messages.clone(),
                                Some(private_input),
                                public_inputs.get(&party_id).unwrap(),
                                &mut OsRng,
                            )
                        };
                        let time = measurement.end(now);
                        if debug {
                            println!("asynchronous_session_terminates_successfully_internal(): party {party_id} finished round #{current_round} in {:?}ms", time.as_millis());
                        }

                        let res = res.unwrap_or_else(|e| {
                            panic!(
                                "Failed to advance round #{:?} in party {party_id}. Got error: {:?}",
                                current_round,
                                e
                            )
                        });

                        (time, (party_id, res))
                    })
                    .collect();

            if !bench_separately {
                total_time = measurement.add(&total_time, &result_times[0]);
                total_times.push(result_times[0]);
            }

            outgoing_messages = results
                    .into_iter()
                    .flat_map(|(party_id, res)| match res {
                        AsynchronousRoundResult::Advance {
                            malicious_parties,
                            message,
                        } => {
                            assert_eq!(malicious_parties, expected_malicious_parties,"expected malicious parties for round #{current_round} {:?} got {:?}", expected_malicious_parties, malicious_parties);

                            Some((party_id, message))
                        }
                        AsynchronousRoundResult::Finalize {
                            malicious_parties: _,
                            private_output: _,
                            public_output: _,
                        } => {
                            panic!("party {party_id} protocol finished early on round #{:?} instead of round #{number_of_rounds} as expected", current_round);
                        },
                    })
                    .chain(outgoing_messages)
                    .collect();

            messages.push(outgoing_messages);
        }
    }
}
