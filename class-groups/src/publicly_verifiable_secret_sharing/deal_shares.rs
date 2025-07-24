// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{ConstChoice, Encoding, Int, Uint};
use std::array;
use std::collections::{HashMap, HashSet};

use group::helpers::{DeduplicateAndSort, FlatMapResults, TryCollectHashMap};
use group::{bounded_integers_group, GroupElement, PrimeGroupElement};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::secret_sharing::shamir::over_the_integers::deal_shares;
use mpc::HandleInvalidMessages;
use mpc::{MajorityVote, PartyID};

#[cfg(feature = "parallel")]
use crypto_bigint::rand_core::OsRng;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::*;
use crate::publicly_verifiable_secret_sharing::{
    DealSecretMessage, DealtSecretShare, DealtSecretShareMessage, Party,
};
use crate::{
    equivalence_class, CiphertextSpaceGroupElement, CompactIbqf, EquivalenceClass, Error, Result,
};

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
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    /// Deals PVSS shares:
    /// * verify proofs of encryption keys
    /// * deal and encrypt shares
    /// * prove encryption of shares
    ///
    /// Note: `preverified_parties` is a list of the pre-verified parties holding valid encryption keys.
    /// `verify_non_pre_verified` specifies if we need to verify proofs from parties that aren't pre-verified.
    pub fn deal_and_encrypt_shares_to_valid_encryption_key_holders<const SECRET_LIMBS: usize>(
        &self,
        dealer_virtual_party_id: Option<PartyID>,
        secret: Int<SECRET_LIMBS>,
        preverified_parties: HashSet<PartyID>,
        verify_non_pre_verified: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(
        Vec<PartyID>,
        DealSecretMessage<
            NUM_PRIMES,
            DISCRETE_LOG_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    )> {
        let language_public_parameters_per_crt_prime =
            construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                self.setup_parameters_per_crt_prime.each_ref(),
            )?;

        // Verify $\Pi_{\textsf{zk-uc}}^{L_{\textsf[DL]}[\mathbb{G}/\mathbb{H},\bar{g}_{q},\mathbb{Z}]}(\textsf{pk}_{\textsf{pid}}[1];\textsf{sk}_{\textsf{pid}})$.
        let (participating_malicious_parties, encryption_keys_per_crt_prime) =
            verify_knowledge_of_decryption_key_proofs(
                language_public_parameters_per_crt_prime,
                preverified_parties,
                self.parties_sending_invalid_encryption_keys.clone(),
                verify_non_pre_verified,
                self.encryption_keys_and_proofs_per_crt_prime.clone(),
            )?;

        // Check that the honest parties form an authorized subset, and combine their public contributions.
        // Note that `verify_knowledge_of_decryption_key_proofs()` already filters-out the malicious parties from `encryption_keys_per_crt_prime`.
        // If this fails, we have an irrecoverable error: we can't do PVSS.
        let participating_parties_with_valid_encryption_keys: HashSet<PartyID> =
            encryption_keys_per_crt_prime.keys().copied().collect();
        self.participating_parties_access_structure
            .is_authorized_subset(&participating_parties_with_valid_encryption_keys)
            .map_err(|_| Error::InternalError)?;

        // ($\bar{C}_{i}=\bar{g}_{q'}^{f(i)}$, $[s]_{{i}}=f(i)$)
        let (coefficients_contribution_commitments, secret_shares) = deal_shares::<
            SECRET_SHARE_LIMBS,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >(
            self.participating_parties_access_structure.threshold,
            self.participating_parties_access_structure
                .number_of_virtual_parties(),
            self.participating_parties_n_factorial,
            Int::<SECRET_SHARE_LIMBS>::from(&secret),
            self.public_verification_key_base,
            self.secret_bits,
            rng,
        )?;

        let coefficients_contribution_commitments = coefficients_contribution_commitments
            .iter()
            .map(<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> as group::GroupElement>::value)
            .collect();

        let secret_shares = secret_shares
            .into_iter()
            .map(|(party_id, secret_share)| {
                bounded_integers_group::GroupElement::<DISCRETE_LOG_WITNESS_LIMBS>::new(
                    Int::new_from_abs_sign(Uint::from(&secret_share), ConstChoice::FALSE).unwrap(),
                    &self.discrete_log_witness_group_public_parameters,
                )
                .map(|group_element| (party_id, group_element))
            })
            .try_collect_hash_map()?;

        #[cfg(not(feature = "parallel"))]
        let iter = participating_parties_with_valid_encryption_keys
            .deduplicate_and_sort()
            .into_iter();
        #[cfg(feature = "parallel")]
        let iter = participating_parties_with_valid_encryption_keys.into_par_iter();

        let encryptions_of_secret_shares_and_proofs = iter
            .map(|participating_tangible_party_id| {
                // $\textsf{ct}_{i}=\textsf{E}_{\textsf{pk}_{i}([s]_{i},\eta)$
                if let Ok(virtual_subset) = self
                    .participating_parties_access_structure
                    .virtual_subset(HashSet::from([participating_tangible_party_id]))
                {
                    let encryptions_of_secret_shares_and_proofs: Result<
                        HashMap<
                            _,
                            DealtSecretShareMessage<
                                NUM_PRIMES,
                                DISCRETE_LOG_WITNESS_LIMBS,
                                PLAINTEXT_SPACE_SCALAR_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            >,
                        >,
                    > = virtual_subset
                        .deduplicate_and_sort()
                        .iter()
                        .map(|&participating_virtual_party_id| {
                            if let Some(secret_share) =
                                secret_shares.get(&participating_virtual_party_id)
                            {
                                self.prove_encryption_of_discrete_log_per_crt_prime(
                                    dealer_virtual_party_id,
                                    participating_tangible_party_id,
                                    participating_virtual_party_id,
                                    *secret_share,
                                    #[cfg(not(feature = "parallel"))]
                                    rng,
                                    #[cfg(feature = "parallel")]
                                    &mut OsRng,
                                )
                                .map(|message| {
                                    (
                                        participating_virtual_party_id,
                                        DealtSecretShareMessage(message),
                                    )
                                })
                            } else {
                                Err(Error::InternalError)
                            }
                        })
                        .collect();

                    encryptions_of_secret_shares_and_proofs
                        .map(|value| (participating_tangible_party_id, value))
                } else {
                    Err(Error::InternalError)
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let malicious_parties = if self.participating_and_dealers_match {
            participating_malicious_parties
        } else {
            vec![]
        };

        Ok((
            malicious_parties,
            DealSecretMessage {
                coefficients_contribution_commitments,
                encryptions_of_secret_shares_and_proofs: encryptions_of_secret_shares_and_proofs
                    .into_iter()
                    .collect(),
            },
        ))
    }

    /// Instantiate group elements, filtering any dealer that sent wrong values or dealt to the wrong virtual subset.
    fn instantiate_dealt_secret_share_messages(
        &self,
        dealt_secret_share_messages: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShareMessage<
                            NUM_PRIMES,
                            DISCRETE_LOG_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        HashMap<
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
    )> {
        let party_to_virtual_parties = self
            .participating_parties_access_structure
            .party_to_virtual_parties();

        let (malicious_parties, dealt_secret_shares) = dealt_secret_share_messages.into_iter().map(|(dealer_tangible_party_id, dealt_secret_share_messages)| {
            let deal_secret_messages: Result<HashMap<_, _>> = dealt_secret_share_messages.into_iter().map(|(dealer_virtual_party_id, dealt_secret_share_message)| {
                let encryptions_of_shares_and_proofs: Result<Vec<_>> = dealt_secret_share_message.into_iter().map(|(participating_tangible_party_id, encryptions_of_shares_and_proofs)| {
                    let participant_virtual_subset: HashSet<_> = encryptions_of_shares_and_proofs.keys().copied().collect();

                    // Make sure shares were dealt to the correct virtual subset.
                    let encryptions_of_shares_and_proofs = if Some(&participant_virtual_subset) == party_to_virtual_parties.get(&participating_tangible_party_id) {
                        encryptions_of_shares_and_proofs.into_iter().map(|(participant_virtual_party_id, proofs_and_encryptions_of_share_per_crt_prime)| {
                            // Safe to dereference, same sized arrays.
                            array::from_fn(|i| {
                                let (proof, encryption_of_share) = proofs_and_encryptions_of_share_per_crt_prime.0[i].clone();

                                CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(encryption_of_share, self.setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters())
                                    .map(|ct| (proof, ct))
                            }).flat_map_results().map(|proofs_and_encryptions_of_share_per_crt_prime| (participant_virtual_party_id, proofs_and_encryptions_of_share_per_crt_prime))
                        }).try_collect_hash_map().map_err(Error::from)
                    } else {
                        Err(Error::InvalidMessage)
                    };

                    encryptions_of_shares_and_proofs.map(|encryptions_and_proofs| (participating_tangible_party_id, encryptions_and_proofs))
                }).collect();

                encryptions_of_shares_and_proofs.map(|encryptions_and_proofs| (dealer_virtual_party_id, encryptions_and_proofs.into_iter().collect::<HashMap<_, _>>()))
            }).collect();

            (dealer_tangible_party_id, deal_secret_messages)
        }).handle_invalid_messages_async();

        Ok((malicious_parties, dealt_secret_shares))
    }

    /// Instantiate group elements, filtering any dealer that sent wrong values or dealt to the wrong virtual subset.
    fn instantiate_deal_secret_messages(
        &self,
        deal_secret_messages: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                DealSecretMessage<
                    NUM_PRIMES,
                    DISCRETE_LOG_WITNESS_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        HashMap<
            PartyID,
            HashMap<Option<PartyID>, Vec<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        >,
        HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShareMessage<
                            NUM_PRIMES,
                            DISCRETE_LOG_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
    )> {
        let (parties_sending_invalid_coefficients, deal_secret_messages) = deal_secret_messages.into_iter().map(|(dealer_tangible_party_id, deal_secret_messages)| {
            let deal_secret_messages: Result<Vec<_>> = deal_secret_messages.into_iter().map(|(dealer_virtual_party_id, deal_secret_message)| {
                let coefficients_contribution_commitments: Result<Vec<_>> = deal_secret_message.coefficients_contribution_commitments.into_iter().map(|commitment| {
                    <EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> as group::GroupElement>::new(commitment, &self.equivalence_class_public_parameters).map_err(Error::from)
                }).collect();

                coefficients_contribution_commitments.map(|commitments| {
                    ((dealer_virtual_party_id, commitments), (dealer_virtual_party_id, deal_secret_message.encryptions_of_secret_shares_and_proofs))
                })
            }).collect();

            (dealer_tangible_party_id, deal_secret_messages)
        }).handle_invalid_messages_async();

        let (coefficients_contribution_commitments, dealt_secret_share_messages): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = deal_secret_messages
            .into_iter()
            .map(|(dealer_tangible_party_id, deal_secret_message)| {
                let (coefficients_contribution_commitments, dealt_secret_share_messages): (
                    HashMap<_, _>,
                    HashMap<_, _>,
                ) = deal_secret_message.into_iter().unzip();

                (
                    (
                        dealer_tangible_party_id,
                        coefficients_contribution_commitments,
                    ),
                    (dealer_tangible_party_id, dealt_secret_share_messages),
                )
            })
            .unzip();

        Ok((
            parties_sending_invalid_coefficients,
            coefficients_contribution_commitments,
            dealt_secret_share_messages,
        ))
    }

    /// Handle the first-round messages asynchronously, reporting malicious parties and filtering them out from the messages.
    ///
    /// Additionally, we instantiate the group values sent over the wire as group elements, and make sure no one sent wrong values.
    /// We also make sure everyone sent exactly `threshold` coefficient commitments.
    pub fn handle_deal_secret_messages(
        &self,
        deal_secret_messages: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                DealSecretMessage<
                    NUM_PRIMES,
                    DISCRETE_LOG_WITNESS_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        HashSet<PartyID>,
        HashMap<
            PartyID,
            HashMap<Option<PartyID>, Vec<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        >,
        HashMap<
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
    )> {
        let (
            parties_sending_invalid_coefficients,
            coefficients_contribution_commitments,
            dealt_secret_share_messages,
        ) = self.instantiate_deal_secret_messages(deal_secret_messages)?;

        // Additionally, mark any party that did not send exactly `threshold` coefficient commitments as malicious.
        let parties_sending_invalid_coefficients: HashSet<PartyID> =
            coefficients_contribution_commitments
                .iter()
                .filter(|(_, deal_secret_messages)| {
                    deal_secret_messages
                        .values()
                        .any(|coefficients_contribution_commitments| {
                            coefficients_contribution_commitments.len()
                                != self.participating_parties_access_structure.threshold as usize
                        })
                })
                .map(|(&dealer_tangible_party_id, _)| dealer_tangible_party_id)
                .chain(parties_sending_invalid_coefficients)
                .collect();

        let (malicious_dealers, parties_that_were_dealt_shares, deal_secret_shares) = self
            .handle_dealt_secret_share_messages(
                parties_sending_invalid_coefficients,
                dealt_secret_share_messages,
            )?;

        let coefficients_contribution_commitments = coefficients_contribution_commitments
            .into_iter()
            .filter(|(dealer_tangible_party_id, _)| {
                !malicious_dealers.contains(dealer_tangible_party_id)
            })
            .collect();

        Ok((
            malicious_dealers,
            parties_that_were_dealt_shares,
            coefficients_contribution_commitments,
            deal_secret_shares,
        ))
    }

    pub fn handle_dealt_secret_share_messages(
        &self,
        malicious_dealers: HashSet<PartyID>,
        dealt_secret_share_messages: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShareMessage<
                            NUM_PRIMES,
                            DISCRETE_LOG_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        HashSet<PartyID>,
        HashMap<
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
    )> {
        // This instantiates group elements and also makes ensures that shares were dealt to the correct virtual subsets.
        let (parties_sending_invalid_encryptions, deal_secret_shares) =
            self.instantiate_dealt_secret_share_messages(dealt_secret_share_messages)?;

        let (parties_encrypting_to_wrong_parties, parties_that_were_dealt_shares) =
            self.consensus_parties_holding_valid_encryption_keys(deal_secret_shares.clone())?;

        let malicious_dealers: Vec<PartyID> = malicious_dealers
            .into_iter()
            .chain(parties_sending_invalid_encryptions)
            .chain(parties_encrypting_to_wrong_parties)
            .deduplicate_and_sort();

        let deal_secret_shares: HashMap<_, _> = deal_secret_shares
            .into_iter()
            .filter(|(dealer_tangible_party_id, _)| {
                !malicious_dealers.contains(dealer_tangible_party_id)
            })
            .collect();

        // Now get the parties that behaved honestly in the first round, and assure they are an authorized subset.
        let honest_dealers: HashSet<PartyID> = deal_secret_shares.keys().copied().collect();
        self.dealer_access_structure
            .is_authorized_subset(&honest_dealers)?;

        if malicious_dealers.contains(&self.dealer_tangible_party_id) {
            // This means a bug assuming we acted honestly, and nothing else for us to do here.
            return Err(Error::InternalError);
        }

        if let Some(participating_tangible_party_id) = self.participating_tangible_party_id {
            if !parties_that_were_dealt_shares.contains(&participating_tangible_party_id) {
                // We're left out of the session because we were identified as malicious,
                // and either no one encrypted shares for us or no one will proceed to take us into account in this session
                // because we didn't agree on the right subset.
                // This means a bug assuming we acted honestly, and nothing else for us to do here.
                return Err(Error::InternalError);
            }
        }

        let parties_with_valid_encryption_key_values: HashSet<PartyID> =
            self.encryption_keys_per_crt_prime.keys().copied().collect();
        let parties_that_were_dealt_shares: HashSet<_> =
            parties_that_were_dealt_shares.clone().into_iter().collect();

        if !parties_with_valid_encryption_key_values.is_superset(&parties_that_were_dealt_shares) {
            // There was agreement on a set of parties with valid encryption keys, yet we found them invalid.
            // This must either mean we were sent wrong `encryption_keys_and_proofs_per_crt_prime`, or some bug happened, or there was an authorized subset that lied.
            // In any case we cannot continue.
            return Err(Error::InvalidParameters);
        }

        Ok((
            malicious_dealers,
            parties_that_were_dealt_shares,
            deal_secret_shares,
        ))
    }

    /// This function is a helper function that finds the consensus set of parties to encrypt to, meaning they hold valid encryption keys.
    /// It also reports parties disagreeing with consensus.
    ///
    /// Before encrypting values, proofs of valid encryption keys are verified,
    /// where honest behavior encrypts a share to a party if and only if they verified their encryption key.
    ///
    /// When going over the messages, we must determine which subset of parties had valid encryption keys.
    /// Because this is an asynchronous protocol, we might not have participated in that round so we might not even have access to which parties sent valid proofs.
    /// In order to avoid verifying the proofs again, and making sure there was an agreed upon subset of those that sent valid proofs,
    /// we check which parties each party encrypted shares to, and make sure only one such candidate was chosen by an authorized subset.
    pub fn consensus_parties_holding_valid_encryption_keys(
        &self,
        dealt_secret_shares: HashMap<
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
    ) -> Result<(Vec<PartyID>, Vec<PartyID>)> {
        let (parties_encrypting_inconsistently, parties_with_valid_encryption_keys) = dealt_secret_shares.iter().map(
            |(&dealer_tangible_party_id, dealt_secret_shares)| {
                // First, get the list of parties that the current party verified their encryption keys.
                // We do this by each virtual party, and then collect it as a `HashSet` and assure there is only one entry,
                // so that all virtual parties dealt to the same recipients.
                // Otherwise, we don't take this party into account.
                let parties_with_valid_encryption_keys_verified_by_virtual_parties = dealt_secret_shares.iter().map(|(_, encryptions_of_shares_and_proofs)| {
                    // Sort it for consistency.
                    let parties_with_valid_encryption_keys_verified_by_current_party: Vec<PartyID> = encryptions_of_shares_and_proofs
                        .keys()
                        .copied()
                        .deduplicate_and_sort();

                    parties_with_valid_encryption_keys_verified_by_current_party
                }).collect::<HashSet<_>>();

                let res = if let [parties_with_valid_encryption_keys_verified_by_current_party] =
                    &parties_with_valid_encryption_keys_verified_by_virtual_parties.clone().into_iter().collect::<Vec<_>>()[..] {
                    Ok(parties_with_valid_encryption_keys_verified_by_current_party.clone())
                } else {
                    Err(Error::InvalidMessage)
                };

                (dealer_tangible_party_id, res)
            },
        ).handle_invalid_messages_async();

        let (disagreeing_parties, parties_that_were_dealt_shares) =
            parties_with_valid_encryption_keys
                .weighted_majority_vote(&self.dealer_access_structure)
                .map_err(|_| Error::InternalError)?;

        let malicious_dealers: Vec<_> = parties_encrypting_inconsistently
            .into_iter()
            .chain(disagreeing_parties)
            .deduplicate_and_sort();

        Ok((malicious_dealers, parties_that_were_dealt_shares))
    }
}
