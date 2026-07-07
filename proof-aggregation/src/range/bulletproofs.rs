// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This module wraps around the `bulletproofs` crate, and implements the `RangeProof` and
//! `AggregatableRangeProof` traits.
//!
//! We extend `bulletproofs` to support aggregation of an arbitrary number of parties (not
//! necessarily a power of two),
//!
//! We do that by padding the provers list with artificial provers that have a witness of zeros.
//! They also use zero nonces. In this way, everyone can simulate them efficiently and pad the
//! proof.

use std::{
    array,
    collections::{HashMap, HashSet},
    iter,
};

use merlin::Transcript;

use group::{helpers::FlatMapResults, PartyID};
use proof::range::bulletproofs::{
    RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS,
};
pub use proof_aggregation_round::Output;

use crate::{
    range::{
        AggregatableRangeProof, CommitmentSchemeCommitmentSpaceGroupElement,
        CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement,
        ProofAggregationRoundParty,
    },
    Error, ErrorKind, Result,
};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_aggregation_round;
pub mod proof_share_round;

impl AggregatableRangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS> for RangeProof {
    type AggregationCommitmentRoundParty<const NUM_RANGE_CLAIMS: usize> =
        commitment_round::Party<NUM_RANGE_CLAIMS>;

    fn new_session<const NUM_RANGE_CLAIMS: usize>(
        party_id: PartyID,
        provers: HashSet<PartyID>,
        initial_transcript: Transcript,
        _public_parameters: &Self::PublicParameters<NUM_RANGE_CLAIMS>,
        witnesses: Vec<
            CommitmentSchemeMessageSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                Self,
            >,
        >,
        commitments_randomness: Vec<
            CommitmentSchemeRandomnessSpaceGroupElement<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                Self,
            >,
        >,
    ) -> Self::AggregationCommitmentRoundParty<NUM_RANGE_CLAIMS> {
        commitment_round::Party {
            party_id,
            provers,
            initial_transcript,
            witnesses,
            commitments_randomness,
        }
    }

    fn individual_commitments<const NUM_RANGE_CLAIMS: usize>(
        proof_aggregation_round_party: &ProofAggregationRoundParty<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            Self,
        >,
        batch_size: usize,
    ) -> Result<
        HashMap<
            PartyID,
            Vec<
                CommitmentSchemeCommitmentSpaceGroupElement<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    NUM_RANGE_CLAIMS,
                    Self,
                >,
            >,
        >,
    > {
        proof_aggregation_round_party
            .individual_commitments
            .clone()
            .into_iter()
            .map(|(party_id, commitments)| {
                let mut commitments_iter = commitments.into_iter();

                iter::repeat_with(|| {
                    array::from_fn(|_| {
                        commitments_iter
                            .next()
                            .ok_or_else(|| Error::from(ErrorKind::InternalError))
                    })
                    .flat_map_results()
                    .map(
                        CommitmentSchemeCommitmentSpaceGroupElement::<
                            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
                            NUM_RANGE_CLAIMS,
                            Self,
                        >::from,
                    )
                })
                .take(batch_size)
                .collect::<Result<Vec<_>>>()
                .map(|unflattened_commitments| (party_id, unflattened_commitments))
            })
            .collect()
    }
}

// Since exporting rust `#[cfg(test)]` is impossible, these test helpers exist in a dedicated
// feature-gated module.
#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use crate::range::bulletproofs::RangeProof;

    pub fn new_range_proof(proof: bulletproofs::RangeProof) -> RangeProof {
        RangeProof::new(proof)
    }
}

#[cfg(all(test, feature = "test_helpers"))]
mod tests {
    use std::collections::{HashMap, HashSet};

    use bulletproofs::range_proof_mpc::party;
    use bulletproofs::BulletproofGens;
    use bulletproofs::PedersenGens;
    use crypto_bigint::U64;
    use group::Samplable;
    use proof::range::bulletproofs::PublicParameters;
    use rand::{prelude::IteratorRandom, Rng};

    use rstest::rstest;

    use group::{ristretto, ristretto::Scalar, OsCsRng, PartyID};

    use crate::{
        range::{bulletproofs::tests::test_helpers::commitment_round, RangeProof},
        synchronous::{test_helpers, CommitmentRoundParty, ProofAggregationRoundParty},
    };

    use super::*;

    const NUM_RANGE_CLAIMS: usize = 4;

    fn generate_commitment_round_parties(
        threshold: usize,
        number_of_parties: usize,
        batch_size: usize,
    ) -> HashMap<PartyID, commitment_round::Party<NUM_RANGE_CLAIMS>> {
        let mut provers = HashSet::new();
        (1..=number_of_parties)
            .choose_multiple(&mut OsCsRng, threshold)
            .into_iter()
            .for_each(|i| {
                let party_id: u16 = i.try_into().unwrap();

                provers.insert(party_id);
            });

        let ristretto_scalar_public_parameters = ristretto::scalar::PublicParameters::default();

        provers
            .clone()
            .into_iter()
            .map(|party_id| {
                let transcript = Transcript::new("".as_bytes());
                let witnesses = (0..batch_size)
                    .map(|_| array::from_fn(|_| U64::from(OsCsRng.random::<u32>()).into()).into())
                    .collect();

                let commitments_randomness = (0..batch_size)
                    .map(|_| {
                        array::from_fn(|_| {
                            ristretto::Scalar::sample(
                                &ristretto_scalar_public_parameters,
                                &mut OsCsRng,
                            )
                            .unwrap()
                        })
                        .into()
                    })
                    .collect();

                (
                    party_id,
                    commitment_round::Party {
                        party_id,
                        provers: provers.clone(),
                        initial_transcript: transcript,
                        witnesses,
                        commitments_randomness,
                    },
                )
            })
            .collect()
    }

    #[rstest]
    #[case(2, 2, 1)]
    #[case(2, 4, 3)]
    #[case(6, 9, 2)]
    #[case(6, 9, 3)]
    fn aggregates(
        #[case] threshold: usize,
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let commitment_round_parties =
            generate_commitment_round_parties(threshold, number_of_parties, batch_size);

        let (_, _, _, _, _, (range_proof, commitments)) =
            test_helpers::aggregates(commitment_round_parties);

        let public_parameters = PublicParameters::default();
        let transcript = Transcript::new("".as_bytes());

        assert!(
            range_proof
                .verify(&public_parameters, commitments, transcript, &mut OsCsRng)
                .is_ok(),
            "aggregated range proof should verify"
        );
    }

    #[rstest]
    #[case(2, 2, 1)]
    #[case(2, 4, 3)]
    #[case(6, 9, 2)]
    #[case(6, 9, 3)]
    fn unresponsive_parties_aborts_session_identifiably(
        #[case] threshold: usize,
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let commitment_round_parties =
            generate_commitment_round_parties(threshold, number_of_parties, batch_size);

        test_helpers::unresponsive_parties_aborts_session_identifiably(commitment_round_parties);
    }

    #[rstest]
    #[case(2, 2, 1)]
    #[case(2, 4, 3)]
    #[case(6, 9, 2)]
    #[case(6, 9, 3)]
    fn out_of_range_witness_aborts_identifiably(
        #[case] threshold: usize,
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let commitment_round_parties =
            generate_commitment_round_parties(threshold, number_of_parties, batch_size);

        // first check that we can't assure honest parties witnesses are in range.
        let out_of_range_party_id = *commitment_round_parties.keys().next().unwrap();
        let out_of_range_witness: Scalar = (U64::ONE << RANGE_CLAIM_BITS).into();
        let in_range_witness: Scalar = (U64::ONE << (RANGE_CLAIM_BITS - 1)).into();
        let mut commitment_round_parties_with_out_of_range_witness =
            commitment_round_parties.clone();

        let mut out_of_range_party =
            commitment_round_parties_with_out_of_range_witness[&out_of_range_party_id].clone();

        out_of_range_party.witnesses[0] = [
            in_range_witness,
            out_of_range_witness,
            in_range_witness,
            in_range_witness,
        ]
        .into();

        commitment_round_parties_with_out_of_range_witness
            .insert(out_of_range_party_id, out_of_range_party);

        commitment_round_parties_with_out_of_range_witness
            .into_iter()
            .for_each(|(party_id, party)| {
                let res = party
                    .commit_statements_and_statement_mask(&mut OsCsRng)
                    .map(|res| (party_id, res));
                if party_id == out_of_range_party_id {
                    assert!(matches!(
                        res.err().unwrap(),
                        Error {
                            kind: ErrorKind::InvalidParameters,
                            ..
                        }
                    ));
                } else {
                    assert!(res.is_ok());
                }
            });

        // now check that malicious parties cannot prove out of range witnesses.
        let provers: Vec<_> = commitment_round_parties.keys().copied().collect();
        let number_of_malicious_parties = if provers.len() == 2 { 1 } else { 2 };
        let mut malicious_parties = provers
            .clone()
            .into_iter()
            .choose_multiple(&mut OsCsRng, number_of_malicious_parties);

        malicious_parties.sort();

        let (mut commitments, mut decommitment_round_parties) =
            commitment_round(commitment_round_parties).unwrap();

        let bulletproofs_generators =
            BulletproofGens::new(64, number_of_parties * NUM_RANGE_CLAIMS * batch_size);

        let commitment_generators = PedersenGens::default();

        for party_id in malicious_parties.clone() {
            let mut malicious_party = decommitment_round_parties.get(&party_id).unwrap().clone();
            let mut malicious_commitments = commitments.get(&party_id).unwrap().clone();

            // Just out of range by 1.
            let out_of_range_witness = (U64::ONE << RANGE_CLAIM_BITS).into();
            let malicious_subparty = party::Party::new(
                bulletproofs_generators.clone(),
                commitment_generators,
                out_of_range_witness,
                curve25519_dalek::scalar::Scalar::ZERO,
                64,
            )
            .unwrap();

            let position = (usize::from(party_id) - 1) * NUM_RANGE_CLAIMS * batch_size;

            let (malicious_subparty, commitment) = malicious_subparty
                .assign_position_with_rng(position, &mut OsCsRng)
                .unwrap();

            malicious_party.parties_awaiting_bit_challenge[0] = malicious_subparty;
            malicious_commitments[0] = commitment;

            decommitment_round_parties.insert(party_id, malicious_party);
            commitments.insert(party_id, malicious_commitments);
        }

        let (decommitments, proof_share_round_parties) =
            test_helpers::decommitment_round(commitments, decommitment_round_parties).unwrap();

        let (proof_shares, proof_aggregation_round_parties) =
            test_helpers::proof_share_round(decommitments, proof_share_round_parties).unwrap();

        assert!(proof_aggregation_round_parties
            .clone()
            .into_iter()
            .all(|(party_id, party)| {
                if malicious_parties.contains(&party_id) {
                    // No reason to check malicious party reported malicious behavior.
                    true
                } else {
                    let res =
                        party.aggregate_proof_shares(proof_shares.clone(), &mut OsCsRng);

                    matches!(
                        res.err().unwrap(),
                        Error { kind: ErrorKind::SynchronousAggregation(crate::synchronous::Error { kind: crate::synchronous::ErrorKind::ProofShareVerification(parties), .. }), .. } if parties == malicious_parties
                    )
                }
            }));
    }
}
