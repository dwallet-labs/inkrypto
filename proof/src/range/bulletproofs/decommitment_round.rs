// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(non_snake_case)]

use std::{
    collections::{HashMap, HashSet},
    iter,
    ops::Neg,
};

use bulletproofs::{
    range_proof_mpc::{
        dealer::DealerAwaitingBitCommitments,
        messages::{BitCommitment, PolyCommitment},
        party::PartyAwaitingBitChallenge,
    },
    BulletproofGens,
};
use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use group::helpers::DeduplicateAndSort;
use group::{CsRng, PartyID};

use crate::{
    aggregation,
    aggregation::{process_incoming_messages, DecommitmentRoundParty},
    range::bulletproofs::{proof_share_round, RANGE_CLAIM_BITS},
    Error, Result,
};

#[cfg_attr(feature = "test_helpers", derive(Clone))]
pub struct Party<const NUM_RANGE_CLAIMS: usize> {
    pub(super) party_id: PartyID,
    pub(super) provers: HashSet<PartyID>,
    pub(super) sorted_provers: Vec<PartyID>,
    pub(super) batch_size: usize,
    pub(super) number_of_bulletproof_parties: usize,
    pub(super) number_of_padded_witnesses: usize,
    pub(super) dealer_awaiting_bit_commitments: DealerAwaitingBitCommitments,
    pub(super) parties_awaiting_bit_challenge: Vec<PartyAwaitingBitChallenge>,
    pub(super) bulletproofs_generators: BulletproofGens,
}

impl<const NUM_RANGE_CLAIMS: usize> DecommitmentRoundParty<super::Output<NUM_RANGE_CLAIMS>>
    for Party<NUM_RANGE_CLAIMS>
{
    type Error = Error;
    type Commitment = Vec<BitCommitment>;

    type Decommitment = Vec<PolyCommitment>;

    type ProofShareRoundParty = proof_share_round::Party<NUM_RANGE_CLAIMS>;

    fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Self::Commitment>,
        rng: &mut impl CsRng,
    ) -> Result<(Self::Decommitment, Self::ProofShareRoundParty)> {
        let commitments =
            process_incoming_messages(self.party_id, self.provers.clone(), commitments, false)?;

        let parties_sending_wrong_number_of_bitcommitments: Vec<PartyID> = commitments
            .iter()
            .filter(|(_, bitcommitments)| bitcommitments.len() != self.number_of_padded_witnesses)
            .map(|(party_id, _)| *party_id)
            .deduplicate_and_sort();

        if !parties_sending_wrong_number_of_bitcommitments.is_empty() {
            return Err(aggregation::Error::InvalidCommitment(
                parties_sending_wrong_number_of_bitcommitments,
            ))?;
        }

        let individual_commitments = commitments
            .iter()
            .map(|(party_id, bitcommitments)| {
                bitcommitments
                    .iter()
                    .map(|vc| Ok(vc.V_j.try_into()?))
                    .collect::<Result<Vec<_>>>()
                    .map(|commitments| (*party_id, commitments))
            })
            .collect::<Result<_>>()?;

        let mut bit_commitments: Vec<(_, _)> = commitments.into_iter().collect();

        bit_commitments.sort_by_key(|(party_id, _)| *party_id);

        let bit_commitments: Vec<_> = bit_commitments
            .into_iter()
            .flat_map(|(_, bit_commitments)| bit_commitments)
            .collect();

        // To support aggregation of an arbitrary number of parties (not necessarily a power of
        // two), Pad the provers list with artificial provers that have a witness and nonces
        // of zeros. Instead of creating the party structs for them and actually running the
        // protocol, simulate their output messages and pass them to the dealer.
        let mut j = bit_commitments.len();
        let mut iter = bit_commitments.into_iter();
        let bit_commitments = iter::repeat_with(|| {
            if let Some(bit_commitment) = iter.next() {
                Ok(bit_commitment)
            } else {
                // $ A_j =  (\pi_{i=0..n-1}{h_{j*n+i}})^{-1} $
                let H = self.bulletproofs_generators.share(j).H(RANGE_CLAIM_BITS);
                j += 1;
                H.copied()
                    .reduce(|a, b| a + b)
                    .map(|a| a.neg())
                    .map(|A_j| BitCommitment {
                        V_j: RistrettoPoint::identity().compress(),
                        A_j,
                        S_j: RistrettoPoint::identity(),
                    })
                    .ok_or(Error::InternalError)
            }
        })
        .take(self.number_of_bulletproof_parties)
        .collect::<Result<Vec<_>>>()?;

        let (dealer_awaiting_poly_commitments, bit_challenge) = self
            .dealer_awaiting_bit_commitments
            .receive_bit_commitments(bit_commitments)
            .map_err(|_| Error::InternalError)?;

        let (parties_awaiting_poly_challenge, poly_commitments): (Vec<_>, Vec<_>) = self
            .parties_awaiting_bit_challenge
            .into_iter()
            .map(|party| party.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let third_round_party = proof_share_round::Party {
            party_id: self.party_id,
            provers: self.provers,
            sorted_provers: self.sorted_provers,
            batch_size: self.batch_size,
            number_of_bulletproof_parties: self.number_of_bulletproof_parties,
            number_of_padded_witnesses: self.number_of_padded_witnesses,
            dealer_awaiting_poly_commitments,
            parties_awaiting_poly_challenge,
            individual_commitments,
            bit_challenge,
        };

        Ok((poly_commitments, third_round_party))
    }
}
