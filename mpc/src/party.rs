// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Todo (#104): Introduce Synchronous MPC traits.

pub mod guaranteed_output_delivery;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use commitment::CommitmentSizedNumber;
use group::{CsRng, PartyID};

use crate::{Error, WeightedThresholdAccessStructure};
pub use guaranteed_output_delivery::{
    GuaranteedOutputDeliveryParty, RoundResult as GuaranteedOutputDeliveryRoundResult,
};

/// A Multi-Party Computation (MPC) Party.
pub trait Party: Sized + Send + Sync {
    /// An error in the MPC protocol.
    type Error: Send + Sync + Debug + Into<Error> + From<Error> + Clone;

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

/// An asynchronous MPC session.
/// Captures the round transition `advance` functionality.
pub trait AsynchronouslyAdvanceable: Party + Sized {
    /// The private input of the party.
    type PrivateInput: Clone + Debug + PartialEq + Eq + Send + Sync;

    /// Asynchronously advance to the next round.
    /// `messages` must be an ordered list of messages where the `i`th element contains the messages of the `i`th round.
    /// Note: `session_id` is always freshly-generated. This is essential for security, and in particular to prevent forking attacks, double-spending attacks, and nonce-reuse.
    /// If, for protocol-specific cryptographic reasons, you need to use the session ID of a previous protocol,
    /// it should be passed in as part of the `public_input`. For example, if a signing protocol is split to a presign phase and an online phase, viewed as two seperate protocols, the onilne signning phase will use the session id of the presign phase by including the session id in the presign public output, which will be part of the public input for signing.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn advance(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    >;

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
    fn round_causing_threshold_not_reached(current_round: u64) -> Option<u64>;
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

impl<Message, PrivateOutput, PublicOutput>
    AsynchronousRoundResult<Message, PrivateOutput, PublicOutput>
{
    /// Returns the malicious parties that were reported as part of this asynchronous round result.
    pub fn malicious_parties(&self) -> Vec<PartyID> {
        match self {
            AsynchronousRoundResult::Advance {
                malicious_parties,
                message: _,
            } => malicious_parties.clone(),
            AsynchronousRoundResult::Finalize {
                malicious_parties,
                private_output: _,
                public_output: _,
            } => malicious_parties.clone(),
        }
    }
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
    use crypto_bigint::{Random, Uint, U256};
    use group::helpers::DeduplicateAndSort;
    use group::OsCsRng;
    use rand::Rng;
    use std::collections::hash_map::Entry;
    use std::collections::{HashMap, HashSet};

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
            _malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
            _rng: &mut impl CsRng,
        ) -> Result<
            AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
            Self::Error,
        > {
            println!("Party {party_id:?}: Messages {messages:?}");
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
        let access_structure =
            WeightedThresholdAccessStructure::uniform(3, 6, 6, &mut OsCsRng).unwrap();

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
                    &mut OsCsRng,
                )
                .unwrap()
                {
                    GuaranteedOutputDeliveryRoundResult::Advance { message } => message,
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
                    &mut OsCsRng,
                )
                .unwrap()
                {
                    GuaranteedOutputDeliveryRoundResult::Advance { message } => message,
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
            &mut OsCsRng,
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
            &mut OsCsRng,
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
                    &mut OsCsRng,
                )
                .unwrap()
                {
                    GuaranteedOutputDeliveryRoundResult::Advance{ message } => message,
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
            &mut OsCsRng,
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
            &mut OsCsRng,
        )
        .unwrap()
        {
            GuaranteedOutputDeliveryRoundResult::Finalize {
                public_output_value,
                malicious_parties,
                private_output: _,
            } => {
                assert_eq!(malicious_parties, vec![1, 2, 6]);

                let public_output: u64 = bcs::from_bytes(&public_output_value).unwrap();

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

    struct BitMaskParty;

    impl Party for BitMaskParty {
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
            _malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
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
    fn test_bitmask_protocol_termination_and_consistency() {
        let mut cs_rng = OsCsRng;
        let session_id = Uint::random(&mut cs_rng);
        let n = 301;
        let threshold = 201; // ceil(2n/3)

        let access_structure =
            WeightedThresholdAccessStructure::uniform(threshold, n, n, &mut cs_rng).unwrap();

        let mut all_messages: HashMap<u64, HashMap<PartyID, Vec<u8>>> = HashMap::new();
        let mut timeline_visible_messages: HashMap<u64, HashMap<u64, HashMap<_, _>>> =
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
            let pid: PartyID = cs_rng.random::<PartyID>() % n + 1;

            // Find max round where pid sent a message
            let round = all_messages
                .iter()
                .filter_map(|(round, pid_map)| {
                    if pid_map.contains_key(&pid) {
                        Some(*round)
                    } else {
                        None
                    }
                })
                .max()
                .unwrap_or(0)
                + 1;

            // Check if we can advance
            if round > 1
                && timeline_visible_messages
                    .get(&(round - 1))
                    .unwrap_or(&HashMap::new())
                    .get(&(round - 1))
                    .is_none_or(|round_map| {
                        access_structure
                            .is_authorized_subset(&round_map.keys().cloned().collect())
                            .is_err()
                    })
            {
                // Can't advance, we are not in the first round and didn't get a threshold of messages yet
                continue;
            }

            let result = BitMaskParty::advance_with_guaranteed_output(
                session_id,
                pid,
                &access_structure,
                timeline_visible_messages
                    .get(&(round - 1))
                    .unwrap_or(&HashMap::new())
                    .clone(),
                None,
                &(),
                &mut cs_rng,
            );

            match result {
                Ok(GuaranteedOutputDeliveryRoundResult::Advance { message }) => {
                    // Add message to all messages
                    match all_messages.entry(round) {
                        Entry::Occupied(mut entry) => {
                            entry.get_mut().insert(pid, message);
                        }
                        Entry::Vacant(entry) => {
                            let mut map = HashMap::new();
                            map.insert(pid, message);
                            entry.insert(map);
                        }
                    }

                    // If reached a threshold for the first time, copy into visible
                    match all_messages.entry(round) {
                        Entry::Occupied(mut entry) => {
                            let parties_in_round: HashSet<PartyID> = entry
                                .get_mut()
                                .keys()
                                .copied()
                                .filter(|party_id| !malicious_acc.contains(party_id))
                                .collect();

                            // Only add to visible messages if we have more than a threshold of round messages sent
                            // and this is the first time it happens, namely, we don't pass without pid
                            if access_structure
                                .is_authorized_subset(&parties_in_round)
                                .is_ok()
                            {
                                // Remove the pid from the set
                                let mut parties_without_pid = parties_in_round.clone();
                                parties_without_pid.remove(&pid);

                                // Check if the subset without the pid is not authorized
                                if access_structure
                                    .is_authorized_subset(&parties_without_pid)
                                    .is_err()
                                {
                                    // Insert the current round map into the timeline_visible_messages
                                    if let Some(round_map) = all_messages.get(&round) {
                                        timeline_visible_messages
                                            .entry(round)
                                            .or_insert_with(HashMap::new)
                                            .insert(round, round_map.clone());
                                    }
                                    // Now, for each previous round < current round, copy the round map
                                    if let Some(prev_round_map) =
                                        timeline_visible_messages.get(&(round - 1)).cloned()
                                    {
                                        // Get a mutable reference to the current round, or insert an empty HashMap if it doesn't exist
                                        let current_round_map = timeline_visible_messages
                                            .entry(round)
                                            .or_insert_with(HashMap::new);

                                        // Clone and extend the current round with the previous round's map
                                        for (key, value) in prev_round_map {
                                            current_round_map.insert(key, value);
                                        }
                                    }
                                }
                            }
                        }
                        Entry::Vacant(_) => panic!(),
                    }
                }

                Ok(GuaranteedOutputDeliveryRoundResult::Finalize {
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
                Err(Error::ThresholdNotReached) => {
                    // Need to get more messages.
                    // Extend the visible messages at previous round by copying from all messages received so far
                    // Then when it tries again, it will have more messages and will get a chance to pass threshold
                    timeline_visible_messages
                        .entry(round - 1)
                        .or_insert_with(HashMap::new)
                        .extend(all_messages.clone());
                }
                Err(e) => panic!("Unexpected error: {e:?}"),
            }
        }
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

    use super::*;
    use group::OsCsRng;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;
    use std::collections::HashSet;
    use std::time::Duration;

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
        parties_by_round: HashMap<u64, HashSet<PartyID>>,
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
            parties_by_round,
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
        malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
        number_of_rounds: usize,
        parties_by_round: HashMap<u64, HashSet<PartyID>>,
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
            let current_round_malicious_parties = malicious_parties_by_round
                .get(&(current_round as u64))
                .unwrap_or(&HashSet::new())
                .clone()
                .deduplicate_and_sort();
            let expected_malicious_parties = malicious_parties_by_round
                .get(&((current_round - 1) as u64))
                .unwrap_or(&HashSet::new())
                .clone()
                .deduplicate_and_sort();

            let current_malicious_parties_by_round: HashMap<_, _> = (1..current_round as u64)
                .map(|round| {
                    let malicious_parties = malicious_parties_by_round
                        .get(&(round - 1))
                        .cloned()
                        .unwrap_or_default();

                    (round, malicious_parties)
                })
                .collect();

            let mut subset = parties_by_round
                .get(&(current_round as u64))
                .cloned()
                .unwrap_or_else(|| {
                    // Let's try a different subset in every time.
                    access_structure
                        .random_authorized_subset(&mut OsCsRng)
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
                    current_malicious_parties_by_round.clone(),
                    &mut OsCsRng,
                );
                let res = res.unwrap_or_else(|e| {
                    panic!(
                        "Failed to advance round #{current_round:?} in party {evaluation_party_id}. Got error: {e:?}")
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
                            "expected malicious parties for round #{current_round} {expected_malicious_parties:?} got {malicious_parties:?}");

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
                            "expected malicious parties {expected_malicious_parties:?} got {malicious_parties:?}");

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
                                current_malicious_parties_by_round.clone(),
                                &mut OsCsRng,
                            )
                        } else {
                            P::advance(
                                session_id,
                                party_id,
                                access_structure,
                                messages.clone(),
                                Some(private_input),
                                public_inputs.get(&party_id).unwrap(),
                                current_malicious_parties_by_round.clone(),
                                &mut OsCsRng,
                            )
                        };
                        let time = measurement.end(now);
                        if debug {
                            println!("asynchronous_session_terminates_successfully_internal(): party {party_id} finished round #{current_round} in {:?}ms", time.as_millis());
                        }

                        let res = res.unwrap_or_else(|e| {
                            panic!("Failed to advance round #{current_round:?} in party {party_id}. Got error: {e:?}")
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
                            assert_eq!(malicious_parties, expected_malicious_parties,"expected malicious parties for round #{current_round} {expected_malicious_parties:?} got {malicious_parties:?}");

                            Some((party_id, message))
                        }
                        AsynchronousRoundResult::Finalize {
                            malicious_parties: _,
                            private_output: _,
                            public_output: _,
                        } => {
                            panic!("party {party_id} protocol finished early on round #{current_round:?} instead of round #{number_of_rounds} as expected");
                        },
                    })
                    .chain(outgoing_messages)
                    .collect();

            messages.push(outgoing_messages);
        }
    }
}
