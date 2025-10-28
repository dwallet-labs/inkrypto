// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub use access_structure::weighted::Threshold as WeightedThresholdAccessStructure;
pub use access_structure::weighted::Weight;
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::CsRng;
pub use group::PartyID;
use merlin::Transcript;
pub use party::{
    guaranteed_output_delivery, AsynchronousRoundResult, AsynchronouslyAdvanceable,
    GuaranteedOutputDeliveryRoundResult, GuaranteesOutputDelivery, Message, Party, PublicInput,
    PublicOutput, PublicOutputValue,
};
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::{ChaCha20Core, ChaCha20Rng};
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
    #[error("bcs serialization error")]
    Bcs(#[from] bcs::Error),
    #[error("consumer crate error {:?}", .0)]
    Consumer(String),
}

/// MPC result.
pub type Result<T> = std::result::Result<T, Error>;

/// Derive a seed deterministically for advancing an MPC round.
///
/// This function derives a seed from a private `root_seed` alongside public information that uniquely-describes an attempt to `advance()`
/// a particular MPC session (with SID `session_identifier`) of a particular round (`current_round`) and `attempt_number`.
///
/// This guarantees that every time we derive this seed, for this session and round, we get the same output.
/// Using this seed with a cryptographically secure PRNG (like `ChaCha20`) will generate the exact-same messages and outputs for a given round.
///
/// We add the attempt number to distinguish between attempts when encountering an [`Error::ThresholdNotReached`]. It is safe to do so,
/// since when this error is generated no message or output is returned and thus never sent or broadcast.
pub fn derive_seed_for_round<const SEED_LENGTH: usize>(
    root_seed: &[u8; SEED_LENGTH],
    session_id: CommitmentSizedNumber,
    current_round: u64,
    attempt_number: u64,
) -> [u8; SEED_LENGTH] {
    // Add a distinct descriptive label, and the root seed itself.
    let mut transcript = Transcript::new(b"Round-Specific Seed");
    transcript.append_message(b"root seed", root_seed);

    // Add public fields that uniquely-describes an attempt to `advance()`
    // a particular MPC session of a particular round and attempt number.
    // This guarantees that the seed - and subsequently all random generation within that round - would be deterministic and unique.
    // If we attempt to run the round of a given session twice, the same message will be generated.
    transcript.append_message(b"$ sid $", &session_id.to_be_bytes());
    transcript.append_u64(b"$ current round $", current_round);
    // Safe to add the attempt number since previous failed attempts never generated a message and so
    // information derived from that seed never left the machine (and different messages for the same round will thus never be sent honestly).
    transcript.append_u64(b"$ attempts count $", attempt_number);

    // Generate a new seed (internally, it uses a hash function on all of these values and labels to pseudo-randomly generate it).
    let mut seed: [u8; SEED_LENGTH] = [0; SEED_LENGTH];
    transcript.challenge_bytes(b"seed", &mut seed);

    seed
}

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

/// A seedable collection.
pub trait SeedableCollection<T>: IntoIterator<Item = T> {
    /// Seed a collection with a unique `ChaCha20Rng` per-item.
    /// Useful for working with `rayon` and parallelism, where `rng` cannot be shared between threads,
    /// but each individual rng can be used for that thread normally.
    fn seed(self, rng: &mut impl CsRng) -> Vec<(T, ChaCha20Rng)>;
}

impl<T, I: IntoIterator<Item = T>> SeedableCollection<T> for I {
    fn seed(self, rng: &mut impl CsRng) -> Vec<(T, ChaCha20Rng)> {
        self.into_iter()
            .map(|item| {
                let seed = rng.random();

                let seeded_rng = ChaCha20Rng::from(ChaCha20Core::from_seed(seed));

                (item, seeded_rng)
            })
            .collect()
    }
}
