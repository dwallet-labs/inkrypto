// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::{
    collections::{HashMap, HashSet},
    iter,
    ops::Neg,
};

use super::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS};
use crate::{
    aggregation,
    aggregation::{process_incoming_messages, ProofAggregationRoundParty},
    range::CommitmentScheme,
    Error, Result,
};
use bulletproofs::{
    exp_iter,
    range_proof_mpc::{
        dealer::DealerAwaitingProofShares,
        messages::{BitChallenge, ProofShare},
        MPCError,
    },
};
use crypto_bigint::rand_core::CryptoRngCore;
use curve25519_dalek::scalar::Scalar;
use group::helpers::DeduplicateAndSort;
use group::{ristretto, PartyID};

#[cfg_attr(feature = "test_helpers", derive(Clone))]
pub struct Party<const NUM_RANGE_CLAIMS: usize> {
    pub(super) party_id: PartyID,
    pub(super) provers: HashSet<PartyID>,
    pub(super) sorted_provers: Vec<PartyID>,
    pub(super) batch_size: usize,
    pub(super) number_of_bulletproof_parties: usize,
    pub(super) number_of_padded_witnesses: usize,
    pub(super) dealer_awaiting_proof_shares: DealerAwaitingProofShares,
    pub(super) individual_commitments: HashMap<PartyID, Vec<ristretto::GroupElement>>,
    pub(super) bit_challenge: BitChallenge,
}

pub type Output<const NUM_RANGE_CLAIMS: usize> = (
    super::RangeProof,
    Vec<
        commitment::CommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            CommitmentScheme<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                super::RangeProof,
            >,
        >,
    >,
);

impl<const NUM_RANGE_CLAIMS: usize> ProofAggregationRoundParty<Output<NUM_RANGE_CLAIMS>>
    for Party<NUM_RANGE_CLAIMS>
{
    type Error = Error;

    type ProofShare = Vec<ProofShare>;

    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Output<NUM_RANGE_CLAIMS>> {
        let proof_shares =
            process_incoming_messages(self.party_id, self.provers.clone(), proof_shares, false)?;

        let parties_sending_wrong_number_of_proof_shares: Vec<PartyID> = proof_shares
            .iter()
            .filter(|(_, proof_shares)| proof_shares.len() != self.number_of_padded_witnesses)
            .map(|(party_id, _)| *party_id)
            .deduplicate_and_sort();

        if !parties_sending_wrong_number_of_proof_shares.is_empty() {
            return Err(aggregation::Error::InvalidProofShare(
                parties_sending_wrong_number_of_proof_shares,
            ))?;
        }

        let mut proof_shares: Vec<(_, _)> = proof_shares.into_iter().collect();

        proof_shares.sort_by_key(|(party_id, _)| *party_id);

        let proof_shares: Vec<_> = proof_shares
            .into_iter()
            .flat_map(|(_, proof_shares)| proof_shares)
            .collect();

        let l_vec: Vec<_> = iter::repeat(self.bit_challenge.z.neg())
            .take(RANGE_CLAIM_BITS)
            .collect();

        // Add simulated party's messages.
        let mut j = proof_shares.len();
        let mut iter = proof_shares.into_iter();
        let powers_of_z: Vec<Scalar> = exp_iter(self.bit_challenge.z)
            .take(self.number_of_bulletproof_parties + 2)
            .collect();
        let powers_of_y: Vec<Scalar> = exp_iter(self.bit_challenge.y)
            .take(self.number_of_bulletproof_parties * RANGE_CLAIM_BITS)
            .collect();
        let powers_of_2: Vec<Scalar> = exp_iter(Scalar::from(2u64))
            .take(RANGE_CLAIM_BITS)
            .collect();

        let proof_shares: Vec<_> = iter::repeat_with(|| {
            if let Some(proof_share) = iter.next() {
                proof_share
            } else {
                // $$ \vec{r}_j = ((z-1) y^{n\cdot j+0}+z^{2+j}2^0,\ldots,(z-1) y^{n\cdot
                // j+n-1}+z^{2+j}2^{n-1}) $$
                let r_vec: Vec<_> = (0..RANGE_CLAIM_BITS)
                    .map(|i| {
                        ((self.bit_challenge.z - Scalar::from(1u64))
                            * powers_of_y[j * RANGE_CLAIM_BITS + i])
                            + (powers_of_z[j + 2] * powers_of_2[i])
                    })
                    .collect();

                let t_x = r_vec
                    .clone()
                    .into_iter()
                    .zip(l_vec.clone())
                    .map(|(a, b)| a * b)
                    .reduce(|a, b| a + b)
                    .unwrap();

                let proof_share = ProofShare {
                    e_blinding: Scalar::zero(),
                    t_x_blinding: Scalar::zero(),
                    r_vec,
                    l_vec: l_vec.clone(),
                    t_x,
                };

                j += 1;
                proof_share
            }
        })
        .take(self.number_of_bulletproof_parties)
        .collect();

        let bulletproofs_commitments: Vec<_> = self
            .dealer_awaiting_proof_shares
            .bit_commitments
            .iter()
            .enumerate()
            .map(|(i, vc)| (i, vc.V_j.try_into()))
            .collect();

        let parties_sending_invalid_bit_commitments = bulletproofs_commitments
            .iter()
            .filter(|(_, commitment)| commitment.is_err())
            .map(|(i, _)| {
                i.checked_div(self.number_of_padded_witnesses)
                    .and_then(|i| self.sorted_provers.get(i).copied())
                    .ok_or(Error::InternalError)
            })
            .collect::<Result<Vec<_>>>()?;

        if !parties_sending_invalid_bit_commitments.is_empty() {
            return Err(aggregation::Error::InvalidProofShare(
                parties_sending_invalid_bit_commitments,
            ))?;
        }

        let bulletproofs_commitments: Vec<_> = bulletproofs_commitments
            .into_iter()
            .map(|(_, commitment)| commitment.unwrap())
            .collect();

        let proof = self
            .dealer_awaiting_proof_shares
            .receive_shares_with_rng(&proof_shares, rng)
            .map_err(|e| match e {
                MPCError::MalformedProofShares { bad_shares } => bad_shares
                    .into_iter()
                    .map(|i| {
                        i.checked_div(self.number_of_padded_witnesses)
                            .and_then(|i| self.sorted_provers.get(i).copied())
                    })
                    .collect::<Option<Vec<_>>>()
                    .map(|malicious_parties| {
                        Error::Aggregation(aggregation::Error::ProofShareVerification(
                            malicious_parties,
                        ))
                    })
                    .unwrap_or(Error::InternalError),
                _ => Error::InvalidParameters,
            })?;

        super::RangeProof::new_aggregated(proof, self.batch_size, bulletproofs_commitments.clone())
    }
}
