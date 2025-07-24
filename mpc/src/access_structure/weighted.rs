// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use rand::distributions::Distribution;
use rand::distributions::WeightedIndex;
use rand::Rng;
use serde::{Deserialize, Serialize};

use group::PartyID;

use crate::Error;

/// The weight of a player. Represents the number of `virtual players` this `tangible party` acts for.
pub type Weight = PartyID;

/// A Weighted Threshold Access Structure for a given configuration of parties, which specifies their individual weights.
/// A subset of parties form a valid subset if their overall weight surpasses `threshold`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Threshold {
    pub threshold: Weight,
    pub party_to_weight: HashMap<PartyID, Weight>,
    total_weight: Weight,
}

impl Threshold {
    /// Attempts to instantiate the Weighted Threshold Access Structure.
    /// Fails if `threshold` > total weight or if the tangible parties aren't ordered from `1` to `number_of_tangible_parties`.
    pub fn new(
        threshold: Weight,
        party_to_weight: HashMap<PartyID, Weight>,
    ) -> crate::Result<Self> {
        let total_weight = party_to_weight
            .values()
            .try_fold(0 as Weight, |acc, &x| acc.checked_add(x))
            .ok_or(Error::InvalidParameters)?;
        let number_of_tangible_parties: PartyID = party_to_weight
            .len()
            .try_into()
            .map_err(|_| Error::InvalidParameters)?;
        if threshold == 0
            || threshold > total_weight
            || party_to_weight.values().any(|&weight| weight == 0)
        {
            return Err(Error::InvalidParameters);
        }

        let tangible_parties: HashSet<PartyID> = party_to_weight.keys().copied().collect();
        if tangible_parties != (1..=number_of_tangible_parties).collect() {
            return Err(Error::InvalidParameters);
        }

        Ok(Self {
            threshold,
            party_to_weight,
            total_weight,
        })
    }

    /// Attempts to instantiate the Weighted Threshold Access Structure with randomly distributed weights.
    /// Fails if `threshold` > total weight or if the tangible parties aren't ordered from `1` to `number_of_tangible_parties`.
    pub fn random(
        threshold: Weight,
        number_of_tangible_parties: PartyID,
        total_weight: Weight,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        Self::random_with_initial_weight(
            threshold,
            number_of_tangible_parties,
            total_weight,
            1,
            rng,
        )
    }

    /// Attempts to instantiate the Weighted Threshold Access Structure with uniformly distributed weights.
    /// Fails if `threshold` > total weight or if the tangible parties aren't ordered from `1` to `number_of_tangible_parties`.
    pub fn uniform(
        threshold: Weight,
        number_of_tangible_parties: PartyID,
        total_weight: Weight,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        let weight_per_party = total_weight / number_of_tangible_parties;

        Self::random_with_initial_weight(
            threshold,
            number_of_tangible_parties,
            total_weight,
            weight_per_party,
            rng,
        )
    }

    /// Instantiate a Weighted Threshold Access Structure with at least `initial_weight` weight per-party.
    /// The remainder, if exists, is randomly distributed.
    fn random_with_initial_weight(
        threshold: Weight,
        number_of_tangible_parties: PartyID,
        total_weight: Weight,
        initial_weight: Weight,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        let mut party_to_weight: HashMap<_, _> = (1..=number_of_tangible_parties)
            .map(|party_id| (party_id, initial_weight))
            .collect();

        while total_weight
            != party_to_weight
                .values()
                .try_fold(0 as Weight, |acc, &x| acc.checked_add(x))
                .ok_or(Error::InternalError)?
        {
            let party_id = rng.gen_range(1..=number_of_tangible_parties);
            let new_weight = party_to_weight
                .get(&party_id)
                .and_then(|weight| weight.checked_add(1))
                .ok_or(Error::InternalError)?;
            party_to_weight.insert(party_id, new_weight);
        }

        Self::new(threshold, party_to_weight)
    }

    /// Returns the total weight of all parties.
    pub fn total_weight(&self) -> Weight {
        self.total_weight
    }

    /// Returns the number of virtual parties.
    pub fn number_of_virtual_parties(&self) -> Weight {
        self.total_weight
    }

    /// Returns the number of tangible parties.
    pub fn number_of_tangible_parties(&self) -> PartyID {
        // safe to cast as we checked this won't overflow in `new()`
        self.party_to_weight.len() as PartyID
    }

    /// Returns a mapping between a tangible party and a set of the IDs of the parties they virtualize.
    pub fn party_to_virtual_parties(&self) -> HashMap<PartyID, HashSet<PartyID>> {
        let mut parties: Vec<_> = self.party_to_weight.keys().cloned().collect();
        parties.sort();

        let mut current_party_id: PartyID = 1;
        parties
            .into_iter()
            .map(|party| {
                let weight = self.party_to_weight.get(&party).unwrap();
                let next_party_id = current_party_id + weight;
                let virtual_parties = current_party_id..next_party_id;
                current_party_id = next_party_id;

                (party, virtual_parties.collect())
            })
            .collect()
    }

    /// Returns the subset of virtual parties for a given subset of tangible parties.
    pub fn virtual_subset(
        &self,
        tangible_parties: HashSet<PartyID>,
    ) -> crate::Result<HashSet<PartyID>> {
        if !tangible_parties.is_subset(&self.party_to_weight.keys().copied().collect()) {
            return Err(Error::InvalidParameters);
        }

        let party_to_virtual_parties = self.party_to_virtual_parties();

        let virtual_parties = party_to_virtual_parties
            .into_iter()
            .filter(|(party_id, _)| tangible_parties.contains(party_id))
            .flat_map(|(_, virtual_parties)| virtual_parties)
            .collect();

        Ok(virtual_parties)
    }

    /// Determines whether a subset of tangible parties is authorized within the access structure, i.e. that its total weight meets the threshold.
    /// Check that $\forall \DistributedParty_\PartyIndexSecond\in \AuthorizedSubset_{\DistributedParty}$ and that $\AuthorizedSubset_{\DistributedParty}\in \calS_{\DistributedParty}$.
    /// If so outputs Ok, otherwise, aborts with an error.
    pub fn is_authorized_subset(&self, tangible_parties: &HashSet<PartyID>) -> crate::Result<()> {
        let known_parties = self.party_to_weight.keys().copied().collect();
        if !tangible_parties.is_subset(&known_parties) {
            return Err(Error::InvalidParameters);
        }

        let subset_total_weight: Weight = self
            .party_to_weight
            .iter()
            .filter(|(party, _)| tangible_parties.contains(party))
            .map(|(_, weight)| weight)
            .sum();

        if subset_total_weight < self.threshold {
            return Err(Error::ThresholdNotReached);
        }

        Ok(())
    }

    /// Generates a random subset of tangible parties which are authorized within the access structure.
    pub fn random_authorized_subset(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<HashSet<PartyID>> {
        self.random_authorized_subset_of_active_parties(
            &self.party_to_weight.keys().cloned().collect(),
            rng,
        )
    }

    /// Generates a random subset of tangible parties from a set of active parties, which form an authorized withing the access structure.
    pub fn random_authorized_subset_of_active_parties(
        &self,
        active_parties: &HashSet<PartyID>,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<HashSet<PartyID>> {
        self.is_authorized_subset(active_parties)?;
        let mut parties: Vec<_> = active_parties.iter().cloned().collect();
        parties.sort();

        // Safe to `.unwrap()` since the keys were retrieved from the same map.
        let weights: Vec<_> = parties
            .iter()
            .map(|party_id| *self.party_to_weight.get(party_id).unwrap())
            .collect();
        let distribution = WeightedIndex::new(weights).map_err(|_| Error::InternalError)?;
        let mut subset = HashSet::new();

        while self.is_authorized_subset(&subset).is_err() {
            let party_id = *parties
                .get(distribution.sample(rng))
                .ok_or(Error::InternalError)?;
            subset.insert(party_id);
        }

        Ok(subset)
    }

    /// Returns the tangible party ID for which this virtual party ID belongs to.
    pub fn to_tangible_party_id(&self, virtual_party_id: PartyID) -> Option<PartyID> {
        let party_to_virtual_parties = self.party_to_virtual_parties();

        party_to_virtual_parties
            .iter()
            .find(|(_, virtual_subset)| virtual_subset.contains(&virtual_party_id))
            .map(|(tangible_party_id, _)| *tangible_party_id)
    }
}
