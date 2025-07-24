// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub use access_structure::weighted::Threshold as WeightedThresholdAccessStructure;
pub use access_structure::weighted::Weight;
use group::helpers::DeduplicateAndSort;
pub use group::PartyID;
pub use party::{
    AsynchronousRoundResult, AsynchronouslyAdvanceable, Message, Party, PublicInput, PublicOutput,
    PublicOutputValue,
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Debug;
use std::hash::Hash;

mod access_structure;
mod party;
pub mod secret_sharing;
pub mod two_party;

#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub mod test_helpers {
    pub use crate::party::test_helpers::*;
    pub use crate::secret_sharing::shamir::over_the_integers::test_helpers::*;
}

/// MPC error.
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("invalid parameters")]
    InvalidParameters,
    #[error(
        "not enough honest parties to advance the session - wait for more messages and try again"
    )]
    ThresholdNotReached,
    #[error(
        "this party was not selected as part of the participating parties in the current session"
    )]
    NonParticipatingParty,
    #[error(
        "parties {:?} participated in the previous round of the session but not in the current", .0
    )]
    UnresponsiveParties(Vec<PartyID>),
    #[error("parties {:?} sent an invalid message", .0)]
    InvalidMessage(Vec<PartyID>),
    #[error("parties {:?} sent a malicious message", .0)]
    MaliciousMessage(Vec<PartyID>),
    #[error("cannot advance an inactive session that has been previously terminated")]
    InactiveSession,
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
    #[error("consumer crate error {:?}", .0)]
    Consumer(String),
}

/// MPC result.
pub type Result<T> = std::result::Result<T, Error>;

/// A helper trait for MPC protocols that abstracts away some handling of invalid messages parties sent.
pub trait HandleInvalidMessages<T> {
    /// Handle messages sent by parties in an MPC round by aborting with an error in case any invalid message was detected, and blaming the malicious parties.
    /// Used in synchronous protocols.
    fn handle_invalid_messages(self) -> Result<HashMap<PartyID, T>>;

    /// Handle message sent by parties in an MPC round by identifying and filtering all invalid messages, and blaming the malicious parties.
    /// Never aborts with an error, to allow for asynchronous protocols to recover and self-heal.
    fn handle_invalid_messages_async(self) -> (Vec<PartyID>, HashMap<PartyID, T>);
}

impl<T, E: fmt::Debug, I: IntoIterator<Item = (PartyID, std::result::Result<T, E>)>>
    HandleInvalidMessages<T> for I
{
    fn handle_invalid_messages(self) -> Result<HashMap<PartyID, T>> {
        let (malicious_parties, map) = self.handle_invalid_messages_async();

        if !malicious_parties.is_empty() {
            return Err(Error::InvalidMessage(malicious_parties))?;
        }

        Ok(map)
    }

    fn handle_invalid_messages_async(self) -> (Vec<PartyID>, HashMap<PartyID, T>) {
        let messages: HashMap<_, _> = self.into_iter().collect();
        let malicious_parties: Vec<PartyID> = messages
            .iter()
            .filter(|(_, res)| res.is_err())
            .map(|(party_id, _)| *party_id)
            .deduplicate_and_sort();

        // Safe to `unwrap` as we checked that none of these are errors.
        let messages: HashMap<PartyID, _> = messages
            .into_iter()
            .filter(|(party_id, _)| !malicious_parties.contains(party_id))
            .map(|(party_id, res)| (party_id, res.unwrap()))
            .collect();

        (malicious_parties, messages)
    }
}

/// A helper trait for MPC protocols in which parties need to agree on some value that was sent in a majority vote.
pub trait MajorityVote<T> {
    /// Handle messages sent by parties in an MPC round by identifying the majority vote, and blaming the malicious parties that voted otherwise.
    fn majority_vote(self) -> Result<(Vec<PartyID>, T)>;

    /// Handle messages sent by parties in an MPC round by identifying the majority vote by weight,
    /// and blaming the malicious parties that voted otherwise.
    fn weighted_majority_vote(
        self,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<(Vec<PartyID>, T)>;
}

impl<T: Eq + Hash + Clone> MajorityVote<T> for HashMap<PartyID, T> {
    fn majority_vote(self) -> Result<(Vec<PartyID>, T)> {
        let voters: HashSet<_> = self.keys().copied().collect();

        let mut candidates: HashMap<T, HashSet<PartyID>> = HashMap::new();

        self.into_iter().for_each(|(party_id, candidate)| {
            let mut parties_voting_candidate = candidates
                .get(&candidate)
                .cloned()
                .unwrap_or(HashSet::new());

            parties_voting_candidate.insert(party_id);

            candidates.insert(candidate, parties_voting_candidate);
        });

        let (majority_vote, majority_voters) = candidates
            .clone()
            .into_iter()
            .max_by(
                |(_, first_parties_verifying_candidate),
                 (_, second_parties_verifying_candidate)| {
                    first_parties_verifying_candidate
                        .len()
                        .cmp(&second_parties_verifying_candidate.len())
                },
            )
            .ok_or(Error::InvalidParameters)?;

        let malicious_voters: Vec<PartyID> = voters
            .symmetric_difference(&majority_voters)
            .copied()
            .deduplicate_and_sort();

        Ok((malicious_voters, majority_vote))
    }

    fn weighted_majority_vote(
        self,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<(Vec<PartyID>, T)> {
        let tangible_parties_that_voted: HashSet<PartyID> = self.keys().copied().collect();

        let votes_by_virtual_parties: HashMap<_, _> = self
            .into_iter()
            .map(|(tangible_party_id, vote)| {
                let virtual_subset =
                    access_structure.virtual_subset(HashSet::from([tangible_party_id]))?;

                Ok(virtual_subset
                    .into_iter()
                    .map(|virtual_party_id| (virtual_party_id, vote.clone()))
                    .collect::<Vec<_>>())
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        let (malicious_virtual_voters, majority_vote) = votes_by_virtual_parties.majority_vote()?;

        let malicious_tangible_voters = malicious_virtual_voters
            .into_iter()
            .flat_map(|virtual_party_id| access_structure.to_tangible_party_id(virtual_party_id))
            .collect();

        // Check that the parties that voted honestly form an authorized subset.
        let honest_tangible_parties = tangible_parties_that_voted
            .difference(&malicious_tangible_voters)
            .copied()
            .collect();

        access_structure.is_authorized_subset(&honest_tangible_parties)?;

        Ok((
            malicious_tangible_voters.deduplicate_and_sort(),
            majority_vote,
        ))
    }
}
