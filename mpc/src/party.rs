// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Todo (#104): Introduce Synchronous MPC traits.

pub mod guaranteed_output_delivery;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

use commitment::CommitmentSizedNumber;
use group::{CsRng, PartyID};

use crate::{Error, WeightedThresholdAccessStructure};
pub use guaranteed_output_delivery::{
    GuaranteesOutputDelivery, RoundResult as GuaranteedOutputDeliveryRoundResult,
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
