// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::array;
use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use group::helpers::{DeduplicateAndSort, FlatMapResults, GroupIntoNestedMap};
use group::{CsRng, PrimeGroupElement};
use mpc::PartyID;
use mpc::{HandleInvalidMessages, SeedableCollection};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::verify_encryptions_of_secrets_per_crt_prime;
use crate::encryption_key::public_parameters::Instantiate;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::*;
use crate::publicly_verifiable_secret_sharing::{DealtSecretShare, Party};
use crate::{encryption_key, equivalence_class, CompactIbqf, EquivalenceClass, Error, Result};

impl<
        const NUM_PRIMES: usize,
        const SECRET_SHARE_LIMBS: usize,
        const DISCRETE_LOG_WITNESS_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    Party<
        NUM_PRIMES,
        SECRET_SHARE_LIMBS,
        DISCRETE_LOG_WITNESS_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SECRET_SHARE_LIMBS>: Encoding,
    Uint<SECRET_SHARE_LIMBS>: Encoding,
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
{
    /// This function verifies using batch verification the $\textsf{EncDL}$ proofs for both
    /// 1. Parties which were not available to check their own, and
    /// 2. Parties which claim their share was malicious.
    ///
    /// This corresponds to the $\textsf{PVSS}.\textsf{DistVerify}$ in (https://eprint.iacr.org/2025/297.pdf)
    #[allow(unused_variables)]
    pub fn verify_encryptions_of_secrets_per_crt_prime(
        &self,
        reconstructed_commitments_to_sharing: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        encryptions_of_shares_and_proofs: HashMap<
            PartyID,
            HashMap<
                PartyID,
                HashMap<
                    Option<PartyID>,
                    HashMap<
                        PartyID,
                        DealtSecretShare<
                            NUM_PRIMES,
                            DISCRETE_LOG_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<HashSet<PartyID>> {
        let (
            parties_with_invalid_encryption_keys,
            encryption_scheme_public_parameters_per_crt_prime,
        ) = self
            .encryption_keys_per_crt_prime
            .clone()
            .into_iter()
            .map(
                |(participating_tangible_party_id, encryption_key_per_crt_prime)| {
                    let encryption_scheme_public_parameters_per_crt_prime: Result<[_; MAX_PRIMES]> =
                        array::from_fn(|i| {
                            encryption_key::PublicParameters::new(
                                self.setup_parameters_per_crt_prime[i].clone(),
                                encryption_key_per_crt_prime[i],
                            )
                        })
                        .flat_map_results();

                    (
                        participating_tangible_party_id,
                        encryption_scheme_public_parameters_per_crt_prime,
                    )
                },
            )
            .handle_invalid_messages_async();

        let seeded_encryptions_of_shares_and_proofs = encryptions_of_shares_and_proofs.seed(rng);

        #[cfg(not(feature = "parallel"))]
        let iter = seeded_encryptions_of_shares_and_proofs.into_iter();
        #[cfg(feature = "parallel")]
        let iter = seeded_encryptions_of_shares_and_proofs.into_par_iter();

        let parties_sending_invalid_proofs: Result<Vec<HashSet<PartyID>>> = iter
            .filter(|((participating_tangible_party_id, _), _)| {
                !parties_with_invalid_encryption_keys.contains(participating_tangible_party_id)
            })
            .map(
                |((participating_tangible_party_id, encryptions_of_shares_and_proofs), mut unique_rng)| {
                    // Safe to unwrap, as we filtered to guarantee that the key exists,
                    // and the size is MAX_PRIMES, so converting to an array of size NUM_PRIMES must succeed.
                    let encryption_scheme_public_parameters_per_crt_prime =
                        encryption_scheme_public_parameters_per_crt_prime
                            .get(&participating_tangible_party_id)
                            .unwrap()
                            .clone()
                            .into_iter()
                            .take(NUM_PRIMES)
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();

                    let virtual_subset =
                        self.participating_parties_access_structure.virtual_subset(HashSet::from([participating_tangible_party_id]))?;

                    let commitments = reconstructed_commitments_to_sharing
                        .iter()
                        .map(|(&dealer_tangible_party_id, commitments)| {
                            let commitments = commitments.iter().map(|(&dealer_virtual_party_id, commitments)| {
                                let commitments = commitments.iter()
                                    .filter(|(participating_virtual_party_id, _)| virtual_subset.contains(participating_virtual_party_id))
                                    .map(|(&participating_virtual_party_id, &commitment)| (Some(participating_virtual_party_id), commitment))
                                    .collect();

                                (dealer_virtual_party_id, commitments)
                            }).collect();

                            (dealer_tangible_party_id, commitments)
                        })
                        .collect();

                    let encryptions_of_shares_and_proofs =
                        encryptions_of_shares_and_proofs
                            .into_iter()
                            .map(
                                |(dealer_tangible_party_id, encryptions_of_shares_and_proofs)| {
                                    let encryptions_of_shares_and_proofs = encryptions_of_shares_and_proofs.into_iter().map(|(dealer_virtual_party_id, encryptions_of_shares_and_proofs)| {
                                        let encryptions_of_shares_and_proofs = encryptions_of_shares_and_proofs.into_iter()
                                            .map(
                                                |(
                                                     participating_virtual_party_id,
                                                     dealt_secret_share,
                                                 )| {
                                                    (Some(participating_virtual_party_id), dealt_secret_share)
                                                }).collect();

                                        (dealer_virtual_party_id, encryptions_of_shares_and_proofs)
                                    }).collect();

                                    (dealer_tangible_party_id, encryptions_of_shares_and_proofs)
                                }).collect();

                    verify_encryptions_of_secrets_per_crt_prime::<NUM_PRIMES,DISCRETE_LOG_WITNESS_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>(
                        Some(participating_tangible_party_id),
                        self.session_id,
                        encryption_scheme_public_parameters_per_crt_prime,
                        commitments,
                        encryptions_of_shares_and_proofs,
                        self.equivalence_class_public_parameters.clone(),
                        self.public_verification_key_base,
                        self.base_protocol_context.clone(),
                        self.discrete_log_witness_group_public_parameters.sample_bits,
                        &mut unique_rng
                    )
                },
            )
            .collect();

        Ok(parties_sending_invalid_proofs?
            .into_iter()
            .flatten()
            .chain(parties_with_invalid_encryption_keys)
            .collect())
    }

    /// Verifies encryptions of shared/dealt secret shares.
    pub fn verify_encryptions_of_secret_shares(
        &self,
        encryptions_of_secrets_and_proofs: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShare<
                            NUM_PRIMES,
                            DISCRETE_LOG_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
        verified_dealers: HashMap<PartyID, HashSet<PartyID>>,
        malicious_dealers: Vec<PartyID>,
        reconstructed_commitments_to_sharing: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<Vec<PartyID>> {
        // First filter verified dealers
        let encryptions_of_secrets_and_proofs: HashMap<_, _> = encryptions_of_secrets_and_proofs
            .into_iter()
            .map(
                |(dealer_tangible_party_id, encryptions_of_secrets_and_proofs)| {
                    let encryptions_of_secrets_and_proofs: HashMap<_, _> =
                        encryptions_of_secrets_and_proofs
                            .into_iter()
                            .map(
                                |(dealer_virtual_party_id, encryptions_of_secrets_and_proofs)| {
                                    let encryptions_of_secrets_and_proofs: HashMap<_, _> =
                                        encryptions_of_secrets_and_proofs
                                            .into_iter()
                                            .flat_map(
                                                |(
                                                    participating_tangible_party_id,
                                                    encryptions_of_secrets_and_proofs,
                                                )| {
                                                    if let Some(verified_dealers) = verified_dealers
                                                        .get(&participating_tangible_party_id)
                                                    {
                                                        if verified_dealers
                                                            .contains(&dealer_tangible_party_id)
                                                        {
                                                            // No need to verify shares that were verified by their owners.
                                                            return None;
                                                        }

                                                        // If the owner didn't verify this share, it means they claim it was invalid.
                                                        // We don't automatically trust the owner in this case, instead we verify the proof for that share.
                                                        // Assuming the owner is honest, the proof should fail and the sharer should be reported as malicious.
                                                    }

                                                    // We're here in one of two cases:
                                                    // 1. The receiving party wasn't online during the second round, and so it didn't attempt at verifying that share.
                                                    // 2. We fell-back from the above-mentioned case where the receiving party was online but this share wasn't verified.
                                                    //
                                                    // In the first case, we shouldn't verify our own proof as we know we are honest.
                                                    // Therefore, in both cases, we verify the share by verifying the proof for anyone except us.
                                                    // We don't verify proofs that were verified by their owners (i.e. the meaning of round 2) as an optimization.
                                                    if dealer_tangible_party_id
                                                        == self.dealer_tangible_party_id
                                                    {
                                                        return None;
                                                    }

                                                    Some((
                                                        participating_tangible_party_id,
                                                        encryptions_of_secrets_and_proofs,
                                                    ))
                                                },
                                            )
                                            .collect();

                                    (dealer_virtual_party_id, encryptions_of_secrets_and_proofs)
                                },
                            )
                            .collect();

                    (dealer_tangible_party_id, encryptions_of_secrets_and_proofs)
                },
            )
            .collect();

        // Flip the mapping so that it would be keyed by the receiving party
        // This is for batch verifications, which is done on the same public parameters (same encryption key shares are encrypted to).
        let encryptions_of_secrets_and_proofs = encryptions_of_secrets_and_proofs
            .into_iter()
            .flat_map(
                |(dealer_tangible_party_id, encryptions_of_secrets_and_proofs)| {
                    encryptions_of_secrets_and_proofs
                        .into_iter()
                        .flat_map(
                            |(dealer_virtual_party_id, encryptions_of_secrets_and_proofs)| {
                                encryptions_of_secrets_and_proofs
                                    .into_iter()
                                    .map(
                                        |(
                                            participating_tangible_party_id,
                                            encryptions_of_secrets_and_proofs,
                                        )| {
                                            (
                                                participating_tangible_party_id,
                                                (
                                                    dealer_tangible_party_id,
                                                    (
                                                        dealer_virtual_party_id,
                                                        encryptions_of_secrets_and_proofs,
                                                    ),
                                                ),
                                            )
                                        },
                                    )
                                    .collect::<Vec<_>>()
                            },
                        )
                        .collect::<Vec<_>>()
                },
            )
            .group_into_nested_map();

        let encryptions_of_secrets_and_proofs: HashMap<_, _> = encryptions_of_secrets_and_proofs
            .into_iter()
            .map(
                |(participating_party_id, encryptions_of_secrets_and_proofs)| {
                    (
                        participating_party_id,
                        encryptions_of_secrets_and_proofs.group_into_nested_map(),
                    )
                },
            )
            .collect();

        let parties_sending_invalid_proofs = self.verify_encryptions_of_secrets_per_crt_prime(
            reconstructed_commitments_to_sharing.clone(),
            encryptions_of_secrets_and_proofs.clone(),
            rng,
        )?;

        // Now get all the malicious parties, including all those that sent invalid proofs, and make sure the sharing party set without the malicious parties is authorized.
        let malicious_dealers: Vec<PartyID> = malicious_dealers
            .into_iter()
            .chain(parties_sending_invalid_proofs)
            .deduplicate_and_sort();

        let honest_dealers = reconstructed_commitments_to_sharing
            .keys()
            .copied()
            .filter(|party_id| !malicious_dealers.contains(party_id))
            .collect();

        self.dealer_access_structure
            .is_authorized_subset(&honest_dealers)?;

        if malicious_dealers.contains(&self.dealer_tangible_party_id) {
            // We cannot be a malicious party unless there is a bug.
            return Err(Error::InternalError);
        }

        Ok(malicious_dealers)
    }

    /// Implements the second round of the DKG protocol (Protocol F.1 in (https://eprint.iacr.org/2025/297.pdf): verify shares.
    /// This round is an optimization for two reasons:
    ///  1. verifying your own shares allows for faster verification in the exponent vs. verifying a zk-proof.
    ///  2. you are responsible for yourself, and self-reporting is O(1) vs agreement which is O(t).
    ///
    /// Honest (online) parties should perform this step and self-report they were dealt valid shares.
    /// If the verification fails, the message is ignored and dealer is marked malicious. There is no point in filling a complaint, as in both cases the proofs will be verified anyway by the rest of the parties, to detect whether it is the dealer or the receiver who is malicious.
    /// This would reduce the computational complexity of subsequent round, as every verified share can be ignored, saving a zk-proof verification for everyone else.
    pub fn verify_dealt_shares(
        &self,
        encryptions_of_secrets_and_proofs: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShare<
                            NUM_PRIMES,
                            DISCRETE_LOG_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
        reconstructed_commitments_to_sharing: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<Option<HashSet<PartyID>>> {
        match self.participating_tangible_party_id {
            Some(participating_tangible_party_id) => {
                let dealers: HashSet<_> =
                    encryptions_of_secrets_and_proofs.keys().copied().collect();

                // Keep just encryptions sent to us
                let encryptions_of_shares_and_proofs: HashMap<_, _> =
                    encryptions_of_secrets_and_proofs
                        .into_iter()
                        .filter(|(dealer_tangible_party_id, _)| {
                            // Don't verify our own proofs, we know we are honest.
                            *dealer_tangible_party_id != self.dealer_tangible_party_id
                        })
                        .map(|(dealer_tangible_party_id, deal_secret_messages)| {
                            let encryptions_of_shares_and_proofs: HashMap<_, _> =
                                deal_secret_messages
                                    .into_iter()
                                    .map(
                                        |(
                                            dealer_virtual_party_id,
                                            encryptions_of_shares_and_proofs,
                                        )| {
                                            // Safe to unwrap as we verified we are part of the consensus set of parties that were sent shares.
                                            let encryptions_of_shares_and_proofs =
                                                encryptions_of_shares_and_proofs
                                                    .get(&participating_tangible_party_id)
                                                    .unwrap()
                                                    .clone();

                                            (
                                                dealer_virtual_party_id,
                                                encryptions_of_shares_and_proofs,
                                            )
                                        },
                                    )
                                    .collect();

                            (dealer_tangible_party_id, encryptions_of_shares_and_proofs)
                        })
                        .collect();

                let parties_sending_invalid_proofs = self
                    .verify_encryptions_of_secrets_per_crt_prime(
                        reconstructed_commitments_to_sharing.clone(),
                        HashMap::from([(
                            participating_tangible_party_id,
                            encryptions_of_shares_and_proofs.clone(),
                        )]),
                        rng,
                    )?;

                // We verified all the dealers expect those that sent invalid proofs.
                let verified_dealers = dealers
                    .symmetric_difference(&parties_sending_invalid_proofs)
                    .copied()
                    .collect();

                Ok(Some(verified_dealers))
            }
            // No need to verify shares deal to us when we don't participate and no shares are dealt to us.
            None => Ok(None),
        }
    }
}
