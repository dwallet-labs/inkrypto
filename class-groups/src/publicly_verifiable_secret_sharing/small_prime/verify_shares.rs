// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Rounds 2-3: Verify encrypted shares (PVSS.DistVerify)
//!
//! This module implements the verification phases of single-prime PVSS:
//! - Round 2: Self-verification by participating parties
//! - Round 3: Public verification by non-participating parties
//!
//! The key insight is that all shares dealt TO a specific party use the SAME encryption key
//! (the recipient's), enabling batch verification of proofs to that recipient.

use commitment;
use crypto_bigint::{Encoding, Int, Uint};
use group::helpers::DeduplicateAndSort;
use group::{direct_product, CsRng, GroupElement as _, PartyID, PrimeGroupElement};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use mpc::secret_sharing::shamir::Polynomial;
use mpc::{HandleInvalidMessages, MajorityVote, WeightedThresholdAccessStructure};
use proof::Proof as _;
use std::collections::{HashMap, HashSet};
use std::iter;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::encryption_key::public_parameters::Instantiate;
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::{encryption_key, encryption_key::EncryptionKey, SetupParameters};
use crate::{
    equivalence_class, CiphertextSpaceGroupElement, CompactIbqf, Error, ErrorKind, Result,
};

use super::{
    construct_encryption_of_discrete_log_public_parameters, DealSecretMessage,
    EncryptionOfDiscreteLogProof, ProtocolContext,
};

/// Verify all encrypted shares dealt TO a specific party using batch verification.
///
/// This function collects all proofs for shares encrypted to `participating_party_id`
/// and verifies them in a single batch. All these proofs share the same
/// `language_public_parameters` (same encryption key), enabling efficient batching.
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `participating_party_id` - The party receiving the shares
/// * `dealers_to_verify` - Set of dealer IDs whose shares should be verified
/// * `dealing_messages` - Map of dealer IDs to their dealing messages
/// * `encryption_scheme_public_parameters` - Pre-instantiated encryption scheme public parameters
///   for the recipient (caller instantiates)
/// * `base_protocol_context` - Protocol context for proofs
/// * `scalar_public_parameters` - Scalar public parameters for proof verification
/// * `group_public_parameters` - Group public parameters for commitment verification
/// * `rng` - Random number generator for batch verification
///
/// # Returns
/// Set of malicious dealers (those whose proofs failed verification)
#[allow(clippy::too_many_arguments)]
pub fn verify_shares_dealt_to_specific_party<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    participating_party_id: PartyID,
    dealers_to_verify: &HashSet<PartyID>,
    dealing_messages: &HashMap<
        PartyID,
        DealSecretMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    base_protocol_context: &crate::publicly_verifiable_secret_sharing::BaseProtocolContext,
    scalar_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> HashSet<PartyID>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    // Early return if nothing to verify
    if dealers_to_verify.is_empty() {
        return HashSet::new();
    }

    // Construct language_public_parameters from the pre-instantiated encryption scheme params
    let language_public_parameters = construct_encryption_of_discrete_log_public_parameters(
        scalar_public_parameters.clone(),
        group_public_parameters.clone(),
        encryption_scheme_public_parameters.clone(),
    );

    // Collect all (dealer_party_id, proof, protocol_context, statement) tuples for this recipient
    #[allow(clippy::type_complexity)]
    let (malicious_dealers, proofs_and_contexts_and_statements): (Vec<PartyID>, HashMap<_, _>) =
        dealers_to_verify
            .iter()
            .filter_map(|&dealer_party_id| {
                let dealing_message = dealing_messages.get(&dealer_party_id)?;

                // Get the dealt share for this recipient from this dealer
                // NOTE: if the dealer didn't deal to `participating_party_id`,
                // we skip verification as there is nothing to verify.
                // If the dealer should have dealt, the public check on `verify_encryptions_of_secret_shares()` would blame them as malicious,
                // thus guaranteeing their shares would not be accounted for (and thus we would be allowed to access the aggregated statements from the honest dealers.)
                let dealt_share = dealing_message
                    .encryptions_of_secret_shares_and_proofs
                    .get(&participating_party_id)?;

                Some((dealer_party_id, dealing_message, dealt_share))
            })
            .map(|(dealer_party_id, dealing_message, dealt_share)| {
                // If the dealer sent invalid group elements or wrong number of coefficients, mark as malicious.
                if dealing_message.coefficients_contribution_commitments.len()
                    != participating_parties_access_structure.threshold as usize
                {
                    return (dealer_party_id, Err(Error::from(ErrorKind::InvalidMessage)));
                }

                let commitment_polynomial = dealing_message
                    .coefficients_contribution_commitments
                    .iter()
                    .map(|commitment| {
                        GroupElement::new(commitment.clone(), group_public_parameters)
                            .map_err(|_| Error::from(ErrorKind::InvalidParameters))
                    })
                    .collect::<Result<Vec<_>>>()
                    .ok()
                    .and_then(|commitment_polynomial| {
                        Polynomial::try_from(commitment_polynomial).ok()
                    });

                let encryption_of_secret_share =
                    CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                        dealt_share.encryption_of_secret_share,
                        encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
                    )
                    .ok();

                if let Some((encryption_of_secret_share, commitment_polynomial)) =
                    encryption_of_secret_share.zip(commitment_polynomial)
                {
                    // Compute expected commitment using polynomial evaluation
                    let constant_time = false;
                    let expected_commitment = commitment_polynomial.evaluate_degree(
                        participating_party_id,
                        constant_time,
                        group_public_parameters,
                    );

                    // Create protocol context
                    let protocol_context = ProtocolContext {
                        dealer_party_id,
                        participating_party_id,
                        session_id,
                        base_protocol_context: base_protocol_context.clone(),
                    };

                    // Create statement
                    let statement = vec![direct_product::GroupElement::from((
                        encryption_of_secret_share,
                        expected_commitment,
                    ))];

                    (
                        dealer_party_id,
                        Ok(vec![(
                            dealt_share.encryption_of_secret_share_proof.clone(),
                            (protocol_context, statement),
                        )]),
                    )
                } else {
                    (dealer_party_id, Err(Error::from(ErrorKind::InvalidMessage)))
                }
            })
            .handle_invalid_messages_async();

    let (malicious_provers, _) = EncryptionOfDiscreteLogProof::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >::verify_batch_asynchronously(
        proofs_and_contexts_and_statements,
        &language_public_parameters,
        rng,
    );

    malicious_dealers
        .into_iter()
        .chain(malicious_provers)
        .collect()
}

/// Round 2: Verify shares dealt to this party (self-verification).
///
/// Called by participating parties to verify shares dealt TO them (not BY them).
/// Returns a set of **malicious dealers** (those whose shares failed verification).
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `dealer_party_id` - This party's ID in the dealer access structure.
///   Used for self-exclusion: we don't verify our own dealings since we know we're honest.
///   When dealers and participating parties don't match (reconfiguration), this differs
///   from `participating_party_id`.
/// * `participating_party_id` - This party's ID in the participating access structure.
///   Used as the recipient ID for share verification (verify shares dealt TO us).
/// * `dealing_messages` - Map of dealer IDs to their dealing messages
/// * `encryption_scheme_public_parameters` - Pre-instantiated encryption scheme public parameters
///   for our own party (the caller already has these from public input)
/// * `base_protocol_context` - Protocol context for proofs
/// * `scalar_public_parameters` - Scalar public parameters for proof verification
/// * `group_public_parameters` - Group public parameters for commitment verification
/// * `rng` - Random number generator for batch verification
///
/// # Returns
/// Set of malicious dealers (those whose shares failed verification for this party)
#[allow(clippy::too_many_arguments)]
pub fn verify_dealt_shares<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    dealing_messages: HashMap<
        PartyID,
        DealSecretMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    base_protocol_context: &crate::publicly_verifiable_secret_sharing::BaseProtocolContext,
    scalar_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> HashSet<PartyID>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    // No need to verify own proofs since we know we are honest.
    let dealers_to_verify: HashSet<PartyID> = dealing_messages
        .keys()
        .filter(|&&dealer_id| dealer_id != dealer_party_id)
        .copied()
        .collect();

    verify_shares_dealt_to_specific_party(
        session_id,
        participating_party_id,
        &dealers_to_verify,
        &dealing_messages,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        base_protocol_context,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )
}

/// Round 3: Verify encrypted shares for non-participating parties (public verification).
///
/// This function performs public verification of encrypted shares with per-recipient batching:
/// 1. Determine consensus recipients via weighted majority vote (detect dealers who dealt to wrong sets)
/// 2. For each consensus recipient, determine which dealers to verify:
///    - If recipient sent accusation: verify only their accused dealers
///    - If recipient is unresponsive (no accusation): verify ALL dealers (they never self-verified!)
/// 3. Batch verify all shares TO each recipient
///
/// # Arguments
/// * `dealer_party_id` - The calling party's ID in the dealer access structure.
///   Used for self-exclusion from dealer verification and sanity checks.
/// * `participating_party_id` - The calling party's ID in the participating access structure,
///   or `None` if the caller is not a participating party. Used for self-sanity checks
///   related to consensus recipients.
/// * `dealing_messages` - Map of dealer IDs to their dealing messages
/// * `malicious_dealers_by_party` - Map from participating (upcoming) party IDs to sets of dealers they accused in Round 2
/// * `already_malicious` - Already detected malicious dealers
/// * `setup_parameters` - Cryptographic setup parameters
/// * `encryption_keys` - Map of party IDs to their encryption keys
/// * `base_protocol_context` - Protocol context for proofs
/// * `scalar_public_parameters` - Scalar public parameters for proof verification
/// * `group_public_parameters` - Group public parameters for commitment verification
/// * `session_id` - Unique session identifier
/// * `dealer_access_structure` - Access structure for dealers (used for consensus voting)
/// * `rng` - Random number generator for batch verification
///
/// # Returns
/// Complete list of malicious dealers
#[allow(clippy::too_many_arguments)]
pub fn verify_encryptions_of_secret_shares<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    dealer_party_id: PartyID,
    participating_party_id: Option<PartyID>,
    dealing_messages: &HashMap<
        PartyID,
        DealSecretMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    malicious_dealers_by_party: &HashMap<PartyID, HashSet<PartyID>>,
    malicious_parties: HashSet<PartyID>,
    setup_parameters: &SetupParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    encryption_keys: &HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    base_protocol_context: &crate::publicly_verifiable_secret_sharing::BaseProtocolContext,
    scalar_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
    session_id: commitment::CommitmentSizedNumber,
    dealer_access_structure: &WeightedThresholdAccessStructure,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    // Step 1: Determine consensus on which recipients dealers dealt to.
    // Extract recipients per dealer (excluding self and already malicious).
    let recipients_by_dealer: HashMap<PartyID, Vec<PartyID>> = dealing_messages
        .iter()
        .filter(|(dealer_party_id, _)| !malicious_parties.contains(dealer_party_id))
        .map(|(&dealer_party_id, dealing_message)| {
            let recipients: Vec<PartyID> = dealing_message
                .encryptions_of_secret_shares_and_proofs
                .keys()
                .copied()
                .deduplicate_and_sort();

            (dealer_party_id, recipients)
        })
        .collect();

    // Use weighted majority vote to find consensus recipients and dealers who disagreed.
    let (dealers_to_wrong_recipients, consensus_recipients) = recipients_by_dealer
        .weighted_majority_vote(dealer_access_structure)
        .map_err(Error::from)?;

    if consensus_recipients
        .iter()
        .any(|participating_party_id| !encryption_keys.contains_key(participating_party_id))
    {
        // Either the consensus is wrong, or we have the wrong encryption keys as parameter.
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Make sure we have an authorized subset of receiving parties, otherwise they will never be able to reconstruct the secret.
    participating_parties_access_structure
        .is_authorized_subset(&consensus_recipients.iter().copied().collect())?;

    let malicious_parties = malicious_parties
        .into_iter()
        .chain(dealers_to_wrong_recipients)
        .deduplicate_and_sort();

    let dealers_to_verify_for_unresponsive_parties: HashSet<PartyID> = dealing_messages
        .keys()
        .filter(|&&dealer_id| {
            dealer_id != dealer_party_id && !malicious_parties.contains(&dealer_id)
        })
        .copied()
        .collect();

    // Step 3: For each consensus recipient, verify shares
    let malicious_provers: HashSet<PartyID> = consensus_recipients
        .iter()
        .flat_map(|&participating_party_id| {
            // We verified above that all recipients in the consensus sets have encryption keys.
            let encryption_key = encryption_keys.get(&participating_party_id).unwrap();

            // Determine dealers_to_verify for this recipient.
            // `malicious_dealers_by_party` is keyed by participating (upcoming) party IDs
            // (translated by the caller before passing to this function).
            let (accused, dealers_to_verify) = malicious_dealers_by_party
                .get(&participating_party_id)
                .map(|accused_by_recipient| {
                    // This participating party self-verified.
                    // Only verify dealers they specifically accused.
                    let dealers_to_verify: HashSet<PartyID> = accused_by_recipient
                        .iter()
                        .filter(|&&dealer_id| !malicious_parties.contains(&dealer_id))
                        .copied()
                        .collect();
                    (true, dealers_to_verify)
                })
                .unwrap_or_else(|| {
                    // Either:
                    // 1. Not a dealer (no entry in malicious_dealers_by_party) → can't
                    //    have self-verified
                    // 2. Is a dealer but didn't send accusations → unresponsive
                    // In both cases, verify ALL remaining dealers for this recipient.
                    (false, dealers_to_verify_for_unresponsive_parties.clone())
                });

            // Skip if nothing to verify for this recipient
            if dealers_to_verify.is_empty() {
                return HashSet::new();
            }

            // Instantiate encryption scheme parameters for this recipient
            let Ok(encryption_scheme_public_parameters) =
                encryption_key::PublicParameters::new(setup_parameters.clone(), *encryption_key)
            else {
                // The recipient encryption key is invalid, so the recipient is malicious
                return HashSet::from([participating_party_id]);
            };

            let malicious_parties = verify_shares_dealt_to_specific_party(
                session_id,
                participating_party_id,
                &dealers_to_verify,
                dealing_messages,
                &encryption_scheme_public_parameters,
                participating_parties_access_structure,
                base_protocol_context,
                scalar_public_parameters,
                group_public_parameters,
                rng,
            );

            if accused && (malicious_parties != dealers_to_verify) {
                // The recipient accused a wrong set of malicious parties.
                malicious_parties
                    .into_iter()
                    .chain(iter::once(participating_party_id))
                    .collect()
            } else {
                malicious_parties
            }
        })
        .collect();

    // Step 4: Combine all malicious dealers
    let malicious_dealers: HashSet<PartyID> = malicious_parties
        .into_iter()
        .chain(malicious_provers)
        .collect();

    // Verify that the remaining honest dealers form an authorized subset.
    let honest_dealers: HashSet<PartyID> = dealing_messages
        .keys()
        .filter(|party_id| !malicious_dealers.contains(party_id))
        .copied()
        .collect();
    dealer_access_structure.is_authorized_subset(&honest_dealers)?;

    // Self-sanity: if we are a dealer, we should not be in the malicious set.
    if malicious_dealers.contains(&dealer_party_id) {
        return Err(Error::from(ErrorKind::InternalError));
    }

    // Self-sanity: if we are a participating party, we should be in the consensus recipients.
    if let Some(participating_id) = participating_party_id {
        if !consensus_recipients.contains(&participating_id) {
            return Err(Error::from(ErrorKind::InternalError));
        }
    }

    Ok(malicious_dealers)
}
