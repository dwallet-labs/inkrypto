// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Proof Aggregation Traits.
//!
//! Each state of the MPC protocol is represented by a different Rust
//! type. The state transitions consume the previous state, making it
//! a compilation error to perform the steps out of order or to repeat a
//! step.

#![allow(clippy::type_complexity)]

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
};

use group::helpers::DeduplicateAndSort;
use group::{CsRng, PartyID};

use serde::{Deserialize, Serialize};

/// Proof aggregation error.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error(
        "this party was not selected as part of the participating parties in the current session"
    )]
    NonParticipatingParty,

    #[error(
        "parties {:?} participated in the previous round of the session but not in the current", .0
    )]
    UnresponsiveParties(Vec<PartyID>),

    #[error("parties {:?} sent an invalid commitment", .0)]
    InvalidCommitment(Vec<PartyID>),

    #[error("parties {:?} sent an invalid decommitment value", .0)]
    InvalidDecommitment(Vec<PartyID>),

    #[error(
        "parties {:?} maliciously attempted to bypass the commitment round by sending decommitment which does not match their commitment", .0
    )]
    WrongDecommitment(Vec<PartyID>),

    #[error("parties {:?} decommitted on a wrong number of statements", .0)]
    WrongNumberOfDecommittedStatements(Vec<PartyID>),

    #[error("parties {:?} sent an invalid proof share value", .0)]
    InvalidProofShare(Vec<PartyID>),

    #[error("parties {:?} sent a proof share that does not pass verification", .0)]
    ProofShareVerification(Vec<PartyID>),

    #[error("mpc error")]
    MPC(#[from] mpc::Error),
}

/// Proof aggregation result.
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::NonParticipatingParty => mpc::Error::NonParticipatingParty,
            Error::UnresponsiveParties(parties) => mpc::Error::UnresponsiveParties(parties),
            Error::InvalidCommitment(parties) => mpc::Error::InvalidMessage(parties),
            Error::InvalidDecommitment(parties) => mpc::Error::InvalidMessage(parties),
            Error::WrongDecommitment(parties) => mpc::Error::MaliciousMessage(parties),
            Error::WrongNumberOfDecommittedStatements(parties) => {
                mpc::Error::InvalidMessage(parties)
            }
            Error::InvalidProofShare(parties) => mpc::Error::InvalidMessage(parties),
            Error::ProofShareVerification(parties) => mpc::Error::MaliciousMessage(parties),
            Error::MPC(e) => e,
        }
    }
}

/// The commitment round party of a proof aggregation protocol.
pub trait CommitmentRoundParty<Output>: Sized + Send + Sync {
    /// Commitment error.
    type Error: Debug + TryInto<Error, Error = Self::Error> + From<Error> + Clone;

    /// The output of the commitment round.
    type Commitment: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The round following the commitment round.
    type DecommitmentRoundParty: DecommitmentRoundParty<
        Output,
        Error = Self::Error,
        Commitment = Self::Commitment,
    >;

    /// The commitment round of the proof aggregation protocol.
    /// Receives `self` and not `&self`, to enforce [`Self::DecommitmentRoundParty`] can be
    /// instantiated only via a valid state transition.
    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CsRng,
    ) -> std::result::Result<(Self::Commitment, Self::DecommitmentRoundParty), Self::Error>;
}

/// The decommitment round party of a proof aggregation protocol.
pub trait DecommitmentRoundParty<Output>: Sized + Send + Sync {
    /// Decommitment error.
    type Error: Debug + TryInto<Error, Error = Self::Error> + From<Error> + Clone;

    /// The output of the round preceding the decommitment round.
    type Commitment: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;
    /// The output of the decommitment round.
    type Decommitment: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;
    /// The round following the decommitment round.
    type ProofShareRoundParty: ProofShareRoundParty<
        Output,
        Error = Self::Error,
        Decommitment = Self::Decommitment,
    >;

    /// The decommitment round of the proof aggregation protocol.
    /// Receives `self` and not `&self`, to enforce [`Self::ProofShareRoundParty`] can be
    /// instantiated only via a valid state transition. Receives `commitments` the outputs of
    /// the preceding round from all parties.
    fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Self::Commitment>,
        rng: &mut impl CsRng,
    ) -> std::result::Result<(Self::Decommitment, Self::ProofShareRoundParty), Self::Error>;
}

/// The proof share round party of a proof aggregation protocol.
pub trait ProofShareRoundParty<Output>: Sized + Send + Sync {
    /// Proof share error.
    type Error: Debug + TryInto<Error, Error = Self::Error> + From<Error> + Clone;

    /// The output of the round preceding the proof share round.
    type Decommitment: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;
    /// The output of the proof share round.
    type ProofShare: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;
    /// The round following the proof share round.
    type ProofAggregationRoundParty: ProofAggregationRoundParty<
        Output,
        Error = Self::Error,
        ProofShare = Self::ProofShare,
    >;

    /// The decommitment round of the proof aggregation protocol.
    /// Receives `self` and not `&self`, to enforce [`Self::ProofAggregationRoundParty`] can be
    /// instantiated only via a valid state transition. Receives `decommitments` the outputs of
    /// the preceding round from all parties.
    fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Self::Decommitment>,
        rng: &mut impl CsRng,
    ) -> std::result::Result<(Self::ProofShare, Self::ProofAggregationRoundParty), Self::Error>;
}

/// The proof aggregation round party of a proof aggregation protocol.
pub trait ProofAggregationRoundParty<Output>: Sized + Send + Sync {
    /// Aggregation error.
    type Error: Debug + TryInto<Error, Error = Self::Error> + From<Error> + Clone;

    /// The output of the round preceding the proof aggregation round.
    type ProofShare: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The finalization logic of the aggregation protocol.
    /// Receives `proof_shares` the outputs of the preceding round from all parties.
    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        rng: &mut impl CsRng,
    ) -> std::result::Result<Output, Self::Error>;
}

pub fn process_incoming_messages<T>(
    party_id: PartyID,
    provers: HashSet<PartyID>,
    messages: HashMap<PartyID, T>,
    filter_self: bool,
) -> Result<HashMap<PartyID, T>> {
    // First remove parties that didn't participate in the previous round, as they shouldn't be
    // allowed to join the session half-way, and we can self-heal this malicious behaviour
    // without needing to stop the session and report.
    let messages: HashMap<PartyID, _> = messages
        .into_iter()
        .filter(|(pid, _)| !filter_self || *pid != party_id)
        .filter(|(pid, _)| provers.contains(pid))
        .collect();

    let current_round_party_ids: HashSet<PartyID> = messages.keys().copied().collect();

    let other_provers: HashSet<_> = provers
        .into_iter()
        .filter(|pid| !filter_self || *pid != party_id)
        .collect();

    let unresponsive_parties: Vec<PartyID> = other_provers
        .difference(&current_round_party_ids)
        .cloned()
        .deduplicate_and_sort();

    if !unresponsive_parties.is_empty() {
        return Err(Error::UnresponsiveParties(unresponsive_parties));
    }

    Ok(messages)
}

// Since exporting rust `#[cfg(test)]` is impossible, these test helpers exist in a dedicated feature-gated
// module.
#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use std::{collections::HashMap, time::Duration};

    use criterion::measurement::{Measurement, WallTime};
    use rand::seq::IteratorRandom;

    use super::*;
    use group::OsCsRng;

    pub fn commitment_round<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, P>,
    ) -> Result<(
        HashMap<PartyID, P::Commitment>,
        HashMap<PartyID, P::DecommitmentRoundParty>,
    )> {
        let commitments_and_decommitment_round_parties: HashMap<_, (_, _)> =
            commitment_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    party
                        .commit_statements_and_statement_mask(&mut OsCsRng)
                        .map(|res| (party_id, res))
                        .map_err(|e| e.try_into().unwrap())
                })
                .collect::<Result<_>>()?;

        Ok(commitments_and_decommitment_round_parties
            .into_iter()
            .map(|(party_id, (commitment, decommitment_round_party))| {
                ((party_id, commitment), (party_id, decommitment_round_party))
            })
            .unzip())
    }

    pub fn decommitment_round<Output, P: DecommitmentRoundParty<Output>>(
        commitments: HashMap<PartyID, P::Commitment>,
        decommitment_round_parties: HashMap<PartyID, P>,
    ) -> Result<(
        HashMap<PartyID, P::Decommitment>,
        HashMap<PartyID, P::ProofShareRoundParty>,
    )> {
        let decommitments_and_proof_share_round_parties: HashMap<_, (_, _)> =
            decommitment_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    party
                        .decommit_statements_and_statement_mask(commitments.clone(), &mut OsCsRng)
                        .map(|res| (party_id, res))
                        .map_err(|e| e.try_into().unwrap())
                })
                .collect::<Result<_>>()?;

        Ok(decommitments_and_proof_share_round_parties
            .into_iter()
            .map(|(party_id, (decommitment, proof_share_round_party))| {
                (
                    (party_id, decommitment),
                    (party_id, proof_share_round_party),
                )
            })
            .unzip())
    }

    pub fn proof_share_round<Output, P: ProofShareRoundParty<Output>>(
        decommitments: HashMap<PartyID, P::Decommitment>,
        proof_share_round_parties: HashMap<PartyID, P>,
    ) -> Result<(
        HashMap<PartyID, P::ProofShare>,
        HashMap<PartyID, P::ProofAggregationRoundParty>,
    )> {
        let proof_shares_and_proof_aggregation_round_parties: HashMap<_, (_, _)> =
            proof_share_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    party
                        .generate_proof_share(decommitments.clone(), &mut OsCsRng)
                        .map(|res| (party_id, res))
                        .map_err(|e| e.try_into().unwrap())
                })
                .collect::<Result<_>>()?;

        Ok(proof_shares_and_proof_aggregation_round_parties
            .into_iter()
            .map(|(party_id, (proof_share, proof_aggregation_round_party))| {
                (
                    (party_id, proof_share),
                    (party_id, proof_aggregation_round_party),
                )
            })
            .unzip())
    }

    /// Test identifiable abort of wrong decommitments.
    pub fn wrong_decommitment_aborts_session_identifiably<
        Output,
        P: CommitmentRoundParty<Output> + Clone,
    >(
        commitment_round_parties: HashMap<PartyID, P>,
    ) {
        let provers: Vec<_> = commitment_round_parties.keys().copied().collect();
        let (commitments, decommitment_round_parties) =
            commitment_round(commitment_round_parties.clone()).unwrap();

        let (decommitments, proof_share_round_parties) =
            decommitment_round(commitments.clone(), decommitment_round_parties).unwrap();

        let (wrong_commitments, wrong_decommitment_round_parties) =
            commitment_round(commitment_round_parties).unwrap();

        let (wrong_decommitments, _) =
            decommitment_round(wrong_commitments, wrong_decommitment_round_parties).unwrap();

        let number_of_miscommitting_parties = if provers.len() == 2 { 1 } else { 2 };
        let mut miscommitting_parties = provers
            .clone()
            .into_iter()
            .choose_multiple(&mut OsCsRng, number_of_miscommitting_parties);

        miscommitting_parties.sort();

        let decommitments: HashMap<_, _> = decommitments
            .clone()
            .into_iter()
            .map(|(party_id, decommitment)| {
                (
                    party_id,
                    if miscommitting_parties.contains(&party_id) {
                        if *miscommitting_parties.first().unwrap() == party_id {
                            // try decommitting to a wrong value and see if we get caught
                            wrong_decommitments.get(&party_id).cloned().unwrap()
                        } else {
                            // try a replay attack and see if we get caught
                            decommitments
                                .get(miscommitting_parties.first().unwrap())
                                .unwrap()
                                .clone()
                        }
                    } else {
                        decommitment
                    },
                )
            })
            .collect();

        assert!(proof_share_round_parties
            .into_iter()
            .all(|(party_id, party)| {
                if miscommitting_parties.contains(&party_id) {
                    // No reason to check malicious party reported malicious behavior.
                    true
                } else {
                    let res = party.generate_proof_share(decommitments.clone(), &mut OsCsRng);
                    matches!(
                        res.err().unwrap().try_into().unwrap(),
                        Error::WrongDecommitment(parties) if parties == miscommitting_parties
                    )
                }
            }));
    }

    /// Test identifiable abort of wrong proof shares.
    pub fn failed_proof_share_verification_aborts_session_identifiably<
        Output,
        P: CommitmentRoundParty<Output>,
    >(
        commitment_round_parties: HashMap<PartyID, P>,
        wrong_commitment_round_parties: HashMap<PartyID, P>,
    ) {
        let provers: Vec<_> = commitment_round_parties.keys().copied().collect();
        let (commitments, decommitment_round_parties) =
            commitment_round(commitment_round_parties).unwrap();

        let (decommitments, proof_share_round_parties) =
            decommitment_round(commitments, decommitment_round_parties).unwrap();

        let (proof_shares, proof_aggregation_round_parties) =
            proof_share_round(decommitments, proof_share_round_parties).unwrap();

        let (wrong_commitments, wrong_decommitment_round_parties) =
            commitment_round(wrong_commitment_round_parties).unwrap();

        let (wrong_decommitments, wrong_proof_share_round_parties) =
            decommitment_round(wrong_commitments, wrong_decommitment_round_parties).unwrap();

        let (wrong_proof_shares, _) =
            proof_share_round(wrong_decommitments, wrong_proof_share_round_parties).unwrap();

        let number_of_misproving_parties = if provers.len() == 2 { 1 } else { 2 };
        let mut misproving_parties = provers
            .clone()
            .into_iter()
            .choose_multiple(&mut OsCsRng, number_of_misproving_parties);

        misproving_parties.sort();

        let proof_shares: HashMap<_, _> = proof_shares
            .clone()
            .into_iter()
            .map(|(party_id, proof_share)| {
                (
                    party_id,
                    if misproving_parties.contains(&party_id) {
                        if *misproving_parties.first().unwrap() == party_id {
                            // try decommitting to a wrong value and see if we get caught
                            wrong_proof_shares.get(&party_id).cloned().unwrap()
                        } else {
                            // try a replay attack and see if we get caught
                            proof_shares
                                .get(misproving_parties.first().unwrap())
                                .unwrap()
                                .clone()
                        }
                    } else {
                        proof_share
                    },
                )
            })
            .collect();

        assert!(proof_aggregation_round_parties
            .into_iter()
            .all(|(party_id, party)| {
                if misproving_parties.contains(&party_id) {
                    // No reason to check malicious party reported malicious behavior.
                    true
                } else {
                    let res = party.aggregate_proof_shares(proof_shares.clone(), &mut OsCsRng);
                    matches!(
                        res.err().unwrap().try_into().unwrap(),
                        Error::ProofShareVerification(parties) if parties == misproving_parties
                    )
                }
            }));
    }

    /// Test identifiable abort of unresponsive parties.
    pub fn unresponsive_parties_aborts_session_identifiably<
        Output,
        P: CommitmentRoundParty<Output>,
    >(
        commitment_round_parties: HashMap<PartyID, P>,
    ) where
        P::DecommitmentRoundParty: Clone,
        <P::DecommitmentRoundParty as DecommitmentRoundParty<Output>>::ProofShareRoundParty: Clone,
    {
        let provers: Vec<_> = commitment_round_parties.keys().copied().collect();
        let (commitments, decommitment_round_parties) =
            commitment_round(commitment_round_parties).unwrap();

        let number_of_unresponsive_parties = if provers.len() == 2 { 1 } else { 2 };
        let mut unresponsive_parties = provers
            .clone()
            .into_iter()
            .choose_multiple(&mut OsCsRng, number_of_unresponsive_parties);

        unresponsive_parties.sort();

        // Simulate unresponsive parties by filtering out their messages, see if we identify them.
        let filtered_commitments: HashMap<_, _> = commitments
            .clone()
            .into_iter()
            .filter(|(party_id, _)| !unresponsive_parties.contains(party_id))
            .collect();

        assert!(decommitment_round_parties
            .clone()
            .into_iter()
            .all(|(party_id, party)| {
                if unresponsive_parties.contains(&party_id) {
                    // No reason that a party would proceed to the next round if it didn't send any
                    // message.
                    true
                } else {
                    let res = party.decommit_statements_and_statement_mask(
                        filtered_commitments.clone(),
                        &mut OsCsRng,
                    );
                    matches!(
                        res.err().unwrap().try_into().unwrap(),
                        Error::UnresponsiveParties(parties) if parties == unresponsive_parties
                    )
                }
            }));

        let (decommitments, proof_share_round_parties) =
            decommitment_round(commitments, decommitment_round_parties).unwrap();

        let filtered_decommitments: HashMap<_, _> = decommitments
            .clone()
            .into_iter()
            .filter(|(party_id, _)| !unresponsive_parties.contains(party_id))
            .collect();

        assert!(proof_share_round_parties
            .clone()
            .into_iter()
            .all(|(party_id, party)| {
                if unresponsive_parties.contains(&party_id) {
                    // No reason that a party would proceed to the next round if it didn't send any
                    // message.
                    true
                } else {
                    let res =
                        party.generate_proof_share(filtered_decommitments.clone(), &mut OsCsRng);
                    matches!(
                        res.err().unwrap().try_into().unwrap(),
                        Error::UnresponsiveParties(parties) if parties == unresponsive_parties
                    )
                }
            }));

        let (proof_shares, proof_aggregation_parties) =
            proof_share_round(decommitments, proof_share_round_parties).unwrap();

        let filtered_proof_shares: HashMap<_, _> = proof_shares
            .clone()
            .into_iter()
            .filter(|(party_id, _)| !unresponsive_parties.contains(party_id))
            .collect();

        assert!(proof_aggregation_parties
            .into_iter()
            .all(|(party_id, party)| {
                if unresponsive_parties.contains(&party_id) {
                    // No reason that a party would proceed to the next round if it didn't send any
                    // message.
                    true
                } else {
                    let res =
                        party.aggregate_proof_shares(filtered_proof_shares.clone(), &mut OsCsRng);
                    matches!(
                        res.err().unwrap().try_into().unwrap(),
                        Error::UnresponsiveParties(parties) if parties == unresponsive_parties
                    )
                }
            }));
    }

    /// Test aggregation.
    pub fn aggregates<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, P>,
    ) -> (Duration, Duration, Duration, Duration, Duration, Output) {
        let (
            commitment_round_time,
            decommitment_round_time,
            proof_share_round_time,
            proof_aggregation_round_time,
            total_time,
            outputs,
        ) = aggregates_multiple(
            commitment_round_parties
                .into_iter()
                .map(|(party_id, party)| (party_id, vec![party]))
                .collect(),
        );

        (
            commitment_round_time,
            decommitment_round_time,
            proof_share_round_time,
            proof_aggregation_round_time,
            total_time,
            outputs.into_iter().next().unwrap(),
        )
    }

    /// Test aggregation over multiple claims in parallel.
    pub fn aggregates_multiple<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, Vec<P>>,
    ) -> (
        Duration,
        Duration,
        Duration,
        Duration,
        Duration,
        Vec<Output>,
    ) {
        let measurement = WallTime;
        let mut commitment_round_time = Duration::default();
        let mut decommitment_round_time = Duration::default();
        let mut proof_share_round_time = Duration::default();

        let batch_size = commitment_round_parties.iter().next().unwrap().1.len();

        let commitments_and_decommitment_round_parties: HashMap<_, Vec<(_, _)>> =
            commitment_round_parties
                .into_iter()
                .map(|(party_id, parties)| {
                    let now = measurement.start();
                    let res = parties
                        .into_iter()
                        .map(|party| {
                            party
                                .commit_statements_and_statement_mask(&mut OsCsRng)
                                .unwrap()
                        })
                        .collect();
                    commitment_round_time = measurement.end(now);

                    (party_id, res)
                })
                .collect();

        let commitments: HashMap<_, Vec<_>> = commitments_and_decommitment_round_parties
            .iter()
            .map(|(party_id, v)| {
                (
                    *party_id,
                    v.iter().map(|(commitment, _)| commitment.clone()).collect(),
                )
            })
            .collect();

        let commitments: Vec<HashMap<_, _>> = (0..batch_size)
            .map(|i| {
                commitments
                    .iter()
                    .map(|(party_id, commitments)| (*party_id, commitments[i].clone()))
                    .collect()
            })
            .collect();

        let decommitments_and_proof_share_round_parties: HashMap<_, Vec<(_, _)>> =
            commitments_and_decommitment_round_parties
                .into_iter()
                .map(|(party_id, v)| {
                    let now = measurement.start();
                    let res = v
                        .into_iter()
                        .enumerate()
                        .map(|(i, (_, party))| {
                            party
                                .decommit_statements_and_statement_mask(
                                    commitments[i].clone(),
                                    &mut OsCsRng,
                                )
                                .unwrap()
                        })
                        .collect();
                    decommitment_round_time = measurement.end(now);

                    (party_id, res)
                })
                .collect();

        let decommitments_vecs: HashMap<_, Vec<_>> = decommitments_and_proof_share_round_parties
            .iter()
            .map(|(party_id, v)| {
                (
                    *party_id,
                    v.iter()
                        .map(|(decommitment, _)| decommitment.clone())
                        .collect(),
                )
            })
            .collect();

        let decommitments: Vec<HashMap<_, _>> = (0..batch_size)
            .map(|i| {
                decommitments_vecs
                    .iter()
                    .map(|(party_id, decommitments)| (*party_id, decommitments[i].clone()))
                    .collect()
            })
            .collect();

        let proof_shares_and_proof_aggregation_round_parties: HashMap<_, Vec<(_, _)>> =
            decommitments_and_proof_share_round_parties
                .into_iter()
                .map(|(party_id, v)| {
                    let now = measurement.start();
                    let res = v
                        .into_iter()
                        .enumerate()
                        .map(|(i, (_, party))| {
                            party
                                .generate_proof_share(decommitments[i].clone(), &mut OsCsRng)
                                .unwrap()
                        })
                        .collect();
                    proof_share_round_time = measurement.end(now);

                    (party_id, res)
                })
                .collect();

        let proof_shares: HashMap<_, Vec<_>> = proof_shares_and_proof_aggregation_round_parties
            .iter()
            .map(|(party_id, v)| {
                (
                    *party_id,
                    v.iter()
                        .map(|(proof_share, _)| proof_share.clone())
                        .collect(),
                )
            })
            .collect();

        let proof_shares: Vec<HashMap<_, _>> = (0..batch_size)
            .map(|i| {
                proof_shares
                    .iter()
                    .map(|(party_id, proof_shares)| (*party_id, proof_shares[i].clone()))
                    .collect()
            })
            .collect();

        let (_, proof_aggregation_round_parties) = proof_shares_and_proof_aggregation_round_parties
            .into_iter()
            .next()
            .unwrap();

        let (_, proof_aggregation_round_parties): (Vec<_>, Vec<_>) =
            proof_aggregation_round_parties.into_iter().unzip();

        let now = measurement.start();
        let outputs = proof_aggregation_round_parties
            .into_iter()
            .enumerate()
            .map(|(i, proof_aggregation_round_party)| {
                proof_aggregation_round_party
                    .aggregate_proof_shares(proof_shares[i].clone(), &mut OsCsRng)
                    .unwrap()
            })
            .collect();

        let proof_aggregation_round_time = measurement.end(now);
        let total_time = measurement.add(&commitment_round_time, &decommitment_round_time);
        let total_time = measurement.add(&total_time, &proof_share_round_time);
        let total_time = measurement.add(&total_time, &proof_aggregation_round_time);

        (
            commitment_round_time,
            decommitment_round_time,
            proof_share_round_time,
            proof_aggregation_round_time,
            total_time,
            outputs,
        )
    }
}
