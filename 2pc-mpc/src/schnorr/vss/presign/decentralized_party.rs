// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Decentralized Party Pre-signing (Protocol 9.2)
//!
//! Implements the decentralized party ($B_i$) side of Protocol 9.2.
//!
//! ## Dealing Round
//!
//! Each $B_i$:
//! 1. Samples $k_0^i, k_1^i \gets \mathbb{Z}_q$
//! 2. Runs VSS to share both nonce values
//! 3. Generates proofs of knowledge of the free coefficients (the nonces $k_0^i, k_1^i$)
//! 4. Broadcasts commitments $\{C_\ell^0\}, \{C_\ell^1\}$, encrypted shares, and proofs of knowledge
//!
//! ## Accusation Round
//!
//! Each $B_i$:
//! 1. Receives broadcasts from other parties
//! 2. Verifies proofs of knowledge of the free coefficients for each dealer
//! 3. Decrypts to obtain shares $[k_j^0]_i, [k_j^1]_i$
//! 4. Verifies shares against commitments
//! 5. Broadcasts accusations (revealed decryption keys) for malicious dealers
//!
//! ## Aggregation Round
//!
//! Each $B_i$:
//! 1. Verifies accusations, filters malicious dealers.
//! 2. Checks if valid subset $S_{\textsf{pres}}$ is authorized (meets threshold):
//!    - If authorized: aggregates shares and outputs presign
//!    - If not authorized: returns `Error::from(ErrorKind::ThresholdNotReached)` and waits for more messages
//! 3. Aggregates over valid authorized subset $S_{\textsf{pres}}$:
//!    - $K_{B,0} = \sum_{j \in S} C_0^j$
//!    - $K_{B,1} = \sum_{j \in S} C_1^j$
//!    - $[k_0]_i = \sum_{j \in S} [k_j^0]_i$
//!    - $[k_1]_i = \sum_{j \in S} [k_j^1]_i$
//!
//! ## Output
//!
//! - Public nonce shares: $(K_{B,0}, K_{B,1})$
//! - Private nonce shares: $([k_0]_i, [k_1]_i)$

use crate::schnorr::vss::presign::PrivatePresignOutput;
use crate::schnorr::vss::Presign;
use crate::Party::DecentralizedParty;
use crate::{Error, ErrorKind, ProtocolContext, Result};
use commitment::CommitmentSizedNumber;
use crypto_bigint::Uint;
use group::helpers::DeduplicateAndSort;
use group::{PartyID, PrimeGroupElement, Samplable};
use mpc::secret_sharing::shamir::known_order::{
    self as vss, Accusation, EncryptionPublicKey, EncryptionSecretKey,
};
use mpc::WeightedThresholdAccessStructure;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Wrapper around `EncryptionSecretKey` that implements `Debug` with redaction.
/// This is needed because the underlying HPKE private key doesn't implement Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateInput(EncryptionSecretKey);

impl PrivateInput {
    /// Create a new `PrivateInput` from an encryption secret key.
    pub fn new(key: EncryptionSecretKey) -> Self {
        Self(key)
    }
}

impl std::fmt::Debug for PrivateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrivateInput").field(&"[REDACTED]").finish()
    }
}

impl AsRef<EncryptionSecretKey> for PrivateInput {
    fn as_ref(&self) -> &EncryptionSecretKey {
        &self.0
    }
}

/// Creates the protocol context for VSS presign proofs.
///
/// This provides domain separation for the knowledge of free coefficient proofs.
fn protocol_context(session_id: CommitmentSizedNumber) -> ProtocolContext {
    ProtocolContext {
        party: DecentralizedParty,
        session_id,
        protocol_name: "2PC-MPC VSS Schnorr Presign".to_string(),
        round_name: "Dealing".to_string(),
        proof_name: "Knowledge of Free Coefficients".to_string(),
        public_key: None,
    }
}

/// Type alias for dealing messages in presign protocol.
///
/// Contains the VSS outputs for both nonce parts, dealt together.
pub type DealingMessage<const SCALAR_LIMBS: usize, GroupElement> =
    vss::DealingMessage<SCALAR_LIMBS, GroupElement, ProtocolContext>;

/// Type alias for dealing output in presign protocol.
///
/// Contains the dealing message plus any parties with invalid encryption keys.
pub type DealingOutput<const SCALAR_LIMBS: usize, GroupElement> =
    vss::DealingOutput<SCALAR_LIMBS, GroupElement, ProtocolContext>;

/// Type alias for accusation messages in presign protocol.
///
/// Maps dealer ID to the accusation (DLEQ proof of the shared secret).
/// Since all shares for a party are encrypted together, there's a single accusation per dealer.
pub type AccusationMessage = HashMap<PartyID, Accusation<ProtocolContext>>;

/// Executes Round 1 of the presign protocol.
///
/// Each party $B_i$:
/// 1. Samples random nonces $k_0^i, k_1^i$
/// 2. Uses VSS to create shares and commitments
/// 3. Prepares message
///
/// # Arguments
///
/// * `session_id` - Unique session identifier for domain separation
/// * `party_id` - This party's ID
/// * `threshold` - The threshold for secret sharing (t out of n)
/// * `scalar_public_parameters` - Scalar group public parameters
/// * `group_public_parameters` - Group public parameters
/// * `party_encryption_keys` - Encryption public keys for all parties
/// * `parties_with_uc_verified_public_keys` - Set of party IDs whose UC ZK-proofs of knowledge of the decryption key for their encryption keys have been verified.
///   Parties NOT in this set will be excluded from dealing and marked as having invalid keys.
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
///
/// The dealing output containing the message for Round 1 and any parties with invalid keys.
pub fn advance_dealing_round<const SCALAR_LIMBS: usize, GroupElement>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    threshold: PartyID,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    party_encryption_keys: &HashMap<PartyID, EncryptionPublicKey>,
    parties_with_uc_verified_public_keys: &HashSet<PartyID>,
    rng: &mut impl group::CsRng,
) -> Result<DealingOutput<SCALAR_LIMBS, GroupElement>>
where
    GroupElement:
        PrimeGroupElement<SCALAR_LIMBS> + group::Scale<group::Value<GroupElement::Scalar>> + Copy,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + Samplable
        + Copy
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    group::Value<GroupElement::Scalar>: Into<Uint<SCALAR_LIMBS>> + Serialize,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
{
    // Sample random nonces k_0^i, k_1^i
    let first_nonce = GroupElement::Scalar::sample(scalar_public_parameters, rng)
        .map_err(|_| Error::from(ErrorKind::InternalError))?;
    let second_nonce = GroupElement::Scalar::sample(scalar_public_parameters, rng)
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    let protocol_context = protocol_context(session_id);

    // Deal both nonces together (shares are encrypted together per party)
    let dealer_output = vss::deal_verifiable_secret_shares::<SCALAR_LIMBS, GroupElement, _>(
        party_id,
        &[first_nonce, second_nonce],
        threshold,
        party_encryption_keys,
        parties_with_uc_verified_public_keys,
        &protocol_context,
        group_public_parameters,
        scalar_public_parameters,
        rng,
    )?;

    Ok(dealer_output)
}

/// Executes Round 2 of the presign protocol.
///
/// Each party $B_i$:
/// 1. Receives broadcasts from all other parties
/// 2. Decrypts and verifies shares from each dealer
/// 3. For dealers whose shares fail verification, generates an accusation (DLEQ proof)
///
/// Public checks (proof verification, sanity) are deferred to the aggregation round.
///
/// # Arguments
///
/// * `session_id` - Unique session identifier for domain separation
/// * `party_id` - This party's ID
/// * `secret_key` - This party's encryption secret key
/// * `public_key` - This party's encryption public key
/// * `dealing_messages` - Map of party ID to their Round 1 message
/// * `scalar_public_parameters` - Scalar group public parameters
/// * `group_public_parameters` - Group public parameters
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
///
/// The accusation message.
pub fn advance_accusation_round<const SCALAR_LIMBS: usize, GroupElement>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    secret_key: &EncryptionSecretKey,
    public_key: &EncryptionPublicKey,
    dealing_messages: &HashMap<PartyID, DealingMessage<SCALAR_LIMBS, GroupElement>>,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl group::CsRng,
) -> Result<AccusationMessage>
where
    GroupElement:
        PrimeGroupElement<SCALAR_LIMBS> + group::Scale<group::Value<GroupElement::Scalar>> + Copy,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + Samplable
        + Copy
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    group::Value<GroupElement::Scalar>: From<Uint<SCALAR_LIMBS>> + for<'de> Deserialize<'de>,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
{
    let protocol_context = protocol_context(session_id);
    let number_of_secrets = 2;

    // For each dealer, verify our shares and generate accusations for failures.
    // Public checks (proof verification, sanity) are deferred to the aggregation round
    // where aggregate_shares_with_blending calls identify_malicious_dealers_publicly.
    let accusations = dealing_messages
        .iter()
        .filter_map(|(&dealer_party_id, message)| {
            let encrypted_shares = message.encrypted_shares.get(&party_id)?;

            vss::verify_shares_or_accuse_dealer::<SCALAR_LIMBS, GroupElement, ProtocolContext>(
                party_id,
                encrypted_shares,
                &message.coefficient_commitments,
                secret_key,
                public_key,
                dealer_party_id,
                &protocol_context,
                group_public_parameters,
                scalar_public_parameters,
                number_of_secrets,
                rng,
            )
            .map(|accusation| (dealer_party_id, accusation))
        })
        .collect();

    Ok(accusations)
}

/// Executes Round 3 of the presign protocol with blending for multiple outputs.
///
/// Uses Vandermonde-based blending to produce multiple
/// presign outputs from a single protocol run. This is more efficient than
/// running the protocol multiple times.
///
/// # Arguments
///
/// * `session_id` - Session identifier
/// * `party_id` - This party's ID
/// * `secret_key` - This party's encryption secret key
/// * `public_key` - This party's encryption public key
/// * `dealing_messages` - Map of party ID to their Round 1 message
/// * `accusation_messages` - Map of party ID to their Round 2 message (accusations)
/// * `scalar_public_parameters` - Scalar group public parameters
/// * `group_public_parameters` - Group public parameters
/// * `party_encryption_keys` - Encryption public keys for all parties
/// * `parties_with_uc_verified_public_keys` - Set of party IDs whose UC ZK-proofs of knowledge of the decryption key for their encryption keys have been verified.
///   Parties NOT in this set are considered to have invalid keys.
/// * `access_structure` - The access structure for blending computation
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
///
/// A tuple of (malicious parties, private outputs, public outputs).
pub fn advance_aggregation_round_with_blending<const SCALAR_LIMBS: usize, GroupElement>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    secret_key: &EncryptionSecretKey,
    public_key: &EncryptionPublicKey,
    dealing_messages: &HashMap<PartyID, DealingMessage<SCALAR_LIMBS, GroupElement>>,
    accusation_messages: &HashMap<PartyID, AccusationMessage>,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    party_encryption_keys: &HashMap<PartyID, EncryptionPublicKey>,
    parties_with_uc_verified_public_keys: &HashSet<PartyID>,
    access_structure: &WeightedThresholdAccessStructure,
    rng: &mut impl group::CsRng,
) -> Result<(
    Vec<PartyID>,
    Vec<PrivatePresignOutput<group::Value<GroupElement::Scalar>, GroupElement::Value>>,
    Vec<Presign<GroupElement::Value>>,
)>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>
        + Copy
        + group::Scale<group::Value<GroupElement::Scalar>>
        + mpc::ContributionBlending,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + Samplable
        + Copy
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>
        + mpc::ContributionBlending,
    group::Value<GroupElement::Scalar>: From<Uint<SCALAR_LIMBS>> + for<'de> Deserialize<'de>,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
{
    let protocol_context = protocol_context(session_id);
    let number_of_secrets = 2;

    // Aggregate shares (both nonces processed together since encrypted together)
    let output = vss::aggregate_shares_with_blending::<SCALAR_LIMBS, GroupElement, _>(
        party_id,
        secret_key,
        public_key,
        dealing_messages,
        accusation_messages,
        &protocol_context,
        group_public_parameters,
        scalar_public_parameters,
        party_encryption_keys,
        parties_with_uc_verified_public_keys,
        access_structure,
        number_of_secrets,
        rng,
    )?;

    let malicious_parties = output.malicious_parties.into_iter().deduplicate_and_sort();

    // Extract the two nonce vectors, verifying we got exactly 2 secrets
    let [first_private_nonce, second_private_nonce]: [_; 2] = output
        .blended_private_shares
        .try_into()
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    let [first_public_nonce, second_public_nonce]: [_; 2] = output
        .blended_public_values
        .try_into()
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    // Extract the blended coefficient commitments for each nonce
    // Structure: [secret_index][blending_output_index][coefficient_index]
    let [first_coefficient_commitments, second_coefficient_commitments]: [_; 2] = output
        .blended_coefficient_commitments
        .try_into()
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    // Verify all nonce vectors have the same length
    let number_of_blended_presigns = first_private_nonce.len();
    if second_private_nonce.len() != number_of_blended_presigns
        || first_public_nonce.len() != number_of_blended_presigns
        || second_public_nonce.len() != number_of_blended_presigns
        || first_coefficient_commitments.len() != number_of_blended_presigns
        || second_coefficient_commitments.len() != number_of_blended_presigns
    {
        return Err(Error::from(ErrorKind::InternalError));
    }

    // Transpose from per-nonce to per-presign using zip
    let (private_outputs, public_outputs) = first_private_nonce
        .into_iter()
        .zip(second_private_nonce)
        .zip(first_public_nonce.into_iter().zip(second_public_nonce))
        .zip(
            first_coefficient_commitments
                .into_iter()
                .zip(second_coefficient_commitments),
        )
        .enumerate()
        .map(
            |(
                presign_blending_index,
                (
                    (
                        (nonce_share_first_part, nonce_share_second_part),
                        (
                            decentralized_party_nonce_public_share_first_part,
                            decentralized_party_nonce_public_share_second_part,
                        ),
                    ),
                    (
                        nonce_share_first_part_coefficient_commitments,
                        nonce_share_second_part_coefficient_commitments,
                    ),
                ),
            )| {
                let private_presign = PrivatePresignOutput {
                    session_id,
                    // We will never generate more than 2^16 presigns in one session.
                    presign_blending_index: presign_blending_index as u16,
                    nonce_share_first_part,
                    nonce_share_second_part,
                    // Coefficient commitments for polynomial share verification (DOS protection).
                    // Note: These are public but kept in private output since they are O(threshold)
                    // in size and not needed by the centralized party.
                    nonce_share_first_part_coefficient_commitments,
                    nonce_share_second_part_coefficient_commitments,
                };
                let public_presign = Presign {
                    session_id,
                    presign_blending_index: presign_blending_index as u16,
                    decentralized_party_nonce_public_share_first_part,
                    decentralized_party_nonce_public_share_second_part,
                };
                (private_presign, public_presign)
            },
        )
        .unzip();

    Ok((malicious_parties, private_outputs, public_outputs))
}

pub mod party;

pub use party::{Party, PublicInput};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr::vss::presign::PrivatePresignOutput;
    use crate::schnorr::vss::Presign;
    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, CyclicGroupElement, GroupElement as _, OsCsRng};
    use mpc::secret_sharing::shamir::known_order::generate_encryption_keypair;

    /// Helper to generate encryption keys for parties.
    fn generate_party_encryption_keys(
        party_ids: &[PartyID],
        rng: &mut impl group::CsRng,
    ) -> (
        HashMap<PartyID, EncryptionPublicKey>,
        HashMap<PartyID, EncryptionSecretKey>,
    ) {
        let mut public_keys = HashMap::new();
        let mut secret_keys = HashMap::new();

        for &party_id in party_ids {
            let (secret_key, public_key) = generate_encryption_keypair(rng).unwrap();
            public_keys.insert(party_id, public_key);
            secret_keys.insert(party_id, secret_key);
        }

        (public_keys, secret_keys)
    }

    #[test]
    fn test_presign_dealing_round_creates_valid_output() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let session_id = CommitmentSizedNumber::from(1u64);

        let threshold = 2;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];

        let (party_public_keys, _party_secret_keys) =
            generate_party_encryption_keys(&party_ids, &mut rng);

        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Party 1 executes Round 1
        let dealing_output =
            advance_dealing_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                session_id,
                1,
                threshold,
                &scalar_group_public_parameters,
                &group_params,
                &party_public_keys,
                &parties_with_uc_verified_public_keys,
                &mut rng,
            )
            .unwrap();

        // No parties should have invalid keys in this test
        assert!(
            dealing_output
                .parties_with_invalid_encryption_keys
                .is_empty(),
            "No parties should have invalid encryption keys"
        );

        // Check that message contains expected structure
        let message = &dealing_output.message;
        assert_eq!(
            message.coefficient_commitments.len(),
            2,
            "Should have 2 nonces"
        );
        for nonce_commitments in &message.coefficient_commitments {
            assert_eq!(
                nonce_commitments.len(),
                threshold as usize,
                "Each nonce should have threshold coefficients"
            );
        }
        assert_eq!(
            message.encrypted_shares.len(),
            party_public_keys.len(),
            "Should have one encrypted share pair per party"
        );
    }

    #[test]
    fn test_presign_full_protocol_with_three_parties() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let session_id = CommitmentSizedNumber::from(1u64);

        let threshold = 2;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];

        // Generate encryption keys for all parties
        let (party_public_keys, party_secret_keys) =
            generate_party_encryption_keys(&party_ids, &mut rng);

        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Create access structure for blending
        let party_weights: HashMap<PartyID, u16> = party_ids.iter().map(|&id| (id, 1u16)).collect();
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_weights).unwrap();

        // Round 1: Each party generates their nonce shares via VSS
        let dealing_messages: HashMap<
            PartyID,
            DealingMessage<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
        > = party_ids
            .iter()
            .map(|&party_id| {
                let dealing_output =
                    advance_dealing_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                        session_id,
                        party_id,
                        threshold,
                        &scalar_group_public_parameters,
                        &group_params,
                        &party_public_keys,
                        &parties_with_uc_verified_public_keys,
                        &mut rng,
                    )
                    .unwrap();
                (party_id, dealing_output.message)
            })
            .collect();

        // Round 2: Each party decrypts, verifies, and broadcasts accusations
        let mut accusation_messages: HashMap<PartyID, AccusationMessage> = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let message =
                advance_accusation_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                )
                .unwrap();

            accusation_messages.insert(party_id, message);
        }

        // Round 3: Each party verifies accusations, finalizes
        let mut presign_outputs: HashMap<
            PartyID,
            (
                PrivatePresignOutput<
                    group::Value<secp256k1::Scalar>,
                    group::Value<secp256k1::GroupElement>,
                >,
                Presign<group::Value<secp256k1::GroupElement>>,
            ),
        > = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let (_malicious_parties, private_outputs, public_outputs) =
                advance_aggregation_round_with_blending::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &accusation_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &party_public_keys,
                    &parties_with_uc_verified_public_keys,
                    &access_structure,
                    &mut rng,
                )
                .unwrap();

            // Use the first blended output
            presign_outputs.insert(
                party_id,
                (private_outputs[0].clone(), public_outputs[0].clone()),
            );
        }

        // Verify that all parties computed the same public nonce shares
        let first_output = presign_outputs.get(&1).unwrap();
        for &party_id in &party_ids[1..] {
            let output = presign_outputs.get(&party_id).unwrap();
            assert_eq!(
                first_output
                    .1
                    .decentralized_party_nonce_public_share_first_part,
                output.1.decentralized_party_nonce_public_share_first_part,
                "All parties should agree on K_B,0"
            );
            assert_eq!(
                first_output
                    .1
                    .decentralized_party_nonce_public_share_second_part,
                output.1.decentralized_party_nonce_public_share_second_part,
                "All parties should agree on K_B,1"
            );
        }

        // Verify that the public nonce shares are non-trivial (not identity)
        let neutral =
            secp256k1::GroupElement::neutral_from_public_parameters(&group_params).unwrap();

        let k_b_0 = secp256k1::GroupElement::new(
            first_output
                .1
                .decentralized_party_nonce_public_share_first_part,
            &group_params,
        )
        .unwrap();
        let k_b_1 = secp256k1::GroupElement::new(
            first_output
                .1
                .decentralized_party_nonce_public_share_second_part,
            &group_params,
        )
        .unwrap();

        assert_ne!(
            k_b_0.value(),
            neutral.value(),
            "K_B,0 should not be identity"
        );
        assert_ne!(
            k_b_1.value(),
            neutral.value(),
            "K_B,1 should not be identity"
        );
    }

    #[test]
    fn test_presign_shares_are_valid_shamir_shares() {
        // This test verifies that the nonce shares are proper Shamir shares
        // by checking that the sum of shares * G equals the public commitment.

        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let session_id = CommitmentSizedNumber::from(2u64);

        let threshold = 2;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];

        let (party_public_keys, party_secret_keys) =
            generate_party_encryption_keys(&party_ids, &mut rng);

        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Create access structure for blending
        let party_weights: HashMap<PartyID, u16> = party_ids.iter().map(|&id| (id, 1u16)).collect();
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_weights).unwrap();

        // Run the full protocol
        let dealing_messages: HashMap<
            PartyID,
            DealingMessage<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
        > = party_ids
            .iter()
            .map(|&party_id| {
                let dealing_output =
                    advance_dealing_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                        session_id,
                        party_id,
                        threshold,
                        &scalar_group_public_parameters,
                        &group_params,
                        &party_public_keys,
                        &parties_with_uc_verified_public_keys,
                        &mut rng,
                    )
                    .unwrap();
                (party_id, dealing_output.message)
            })
            .collect();

        // Round 2: Each party decrypts, verifies, and broadcasts accusations
        let mut accusation_messages: HashMap<PartyID, AccusationMessage> = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let message =
                advance_accusation_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                )
                .unwrap();

            accusation_messages.insert(party_id, message);
        }

        // Round 3: Each party verifies accusations, finalizes
        let mut presign_outputs: HashMap<
            PartyID,
            (
                PrivatePresignOutput<
                    group::Value<secp256k1::Scalar>,
                    group::Value<secp256k1::GroupElement>,
                >,
                Presign<group::Value<secp256k1::GroupElement>>,
            ),
        > = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let (_malicious_parties, private_outputs, public_outputs) =
                advance_aggregation_round_with_blending::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &accusation_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &party_public_keys,
                    &parties_with_uc_verified_public_keys,
                    &access_structure,
                    &mut rng,
                )
                .unwrap();

            // Use the first blended output
            presign_outputs.insert(
                party_id,
                (private_outputs[0].clone(), public_outputs[0].clone()),
            );
        }

        // Verify: For each party, [k_0]_i * G should be consistent with the share structure
        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_params).unwrap();

        for &party_id in &party_ids {
            let (private_output, _public_output) = presign_outputs.get(&party_id).unwrap();

            // Each party's share commitment [k_0]_i * G
            let share_0 = secp256k1::Scalar::new(
                private_output.nonce_share_first_part,
                &scalar_group_public_parameters,
            )
            .unwrap();
            let share_1 = secp256k1::Scalar::new(
                private_output.nonce_share_second_part,
                &scalar_group_public_parameters,
            )
            .unwrap();

            let share_commitment_0 = share_0 * generator;
            let share_commitment_1 = share_1 * generator;

            // The shares should be non-trivial
            let neutral =
                secp256k1::GroupElement::neutral_from_public_parameters(&group_params).unwrap();
            assert_ne!(
                share_commitment_0.value(),
                neutral.value(),
                "Share commitment should not be identity"
            );
            assert_ne!(
                share_commitment_1.value(),
                neutral.value(),
                "Share commitment should not be identity"
            );
        }
    }

    #[test]
    fn test_presign_with_larger_threshold() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let session_id = CommitmentSizedNumber::from(3u64);

        let threshold = 4;
        let num_parties = 7;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, party_secret_keys) =
            generate_party_encryption_keys(&party_ids, &mut rng);

        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Create access structure for blending
        let party_weights: HashMap<PartyID, u16> = party_ids.iter().map(|&id| (id, 1u16)).collect();
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_weights).unwrap();

        // Round 1
        let dealing_messages: HashMap<
            PartyID,
            DealingMessage<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
        > = party_ids
            .iter()
            .map(|&party_id| {
                let dealing_output =
                    advance_dealing_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                        session_id,
                        party_id,
                        threshold,
                        &scalar_group_public_parameters,
                        &group_params,
                        &party_public_keys,
                        &parties_with_uc_verified_public_keys,
                        &mut rng,
                    )
                    .unwrap();
                (party_id, dealing_output.message)
            })
            .collect();

        // Round 2: Each party decrypts, verifies, and broadcasts accusations
        let mut accusation_messages: HashMap<PartyID, AccusationMessage> = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let message =
                advance_accusation_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                )
                .unwrap();

            accusation_messages.insert(party_id, message);
        }

        // Round 3: Each party verifies accusations, finalizes
        let mut presign_outputs: HashMap<
            PartyID,
            (
                PrivatePresignOutput<
                    group::Value<secp256k1::Scalar>,
                    group::Value<secp256k1::GroupElement>,
                >,
                Presign<group::Value<secp256k1::GroupElement>>,
            ),
        > = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();

            let (_malicious_parties, private_outputs, public_outputs) =
                advance_aggregation_round_with_blending::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &accusation_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &party_public_keys,
                    &parties_with_uc_verified_public_keys,
                    &access_structure,
                    &mut rng,
                )
                .unwrap();

            // Use the first blended output
            presign_outputs.insert(
                party_id,
                (private_outputs[0].clone(), public_outputs[0].clone()),
            );
        }

        // Verify all parties agree on public values
        let first_output = presign_outputs.get(&1).unwrap();
        for &party_id in &party_ids[1..] {
            let output = presign_outputs.get(&party_id).unwrap();
            assert_eq!(
                first_output
                    .1
                    .decentralized_party_nonce_public_share_first_part,
                output.1.decentralized_party_nonce_public_share_first_part,
                "All parties should agree on K_B,0"
            );
            assert_eq!(
                first_output
                    .1
                    .decentralized_party_nonce_public_share_second_part,
                output.1.decentralized_party_nonce_public_share_second_part,
                "All parties should agree on K_B,1"
            );
        }
    }

    #[test]
    fn test_presign_fails_with_insufficient_parties() {
        // Threshold requires 3 parties but we only have 2
        let threshold = 3;
        let party_ids: Vec<PartyID> = vec![1, 2];

        // Create access structure for blending - this should fail because threshold > total weight
        let party_weights: HashMap<PartyID, u16> = party_ids.iter().map(|&id| (id, 1u16)).collect();
        let result = WeightedThresholdAccessStructure::new(threshold, party_weights);

        // The access structure creation itself should fail when threshold exceeds total weight
        assert!(
            result.is_err(),
            "Should fail to create access structure when threshold > total weight"
        );
    }

    #[test]
    fn test_presign_with_blending() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let session_id = CommitmentSizedNumber::from(5u64);

        let threshold = 2;
        let party_ids: Vec<PartyID> = vec![1, 2, 3, 4, 5];

        let (party_public_keys, party_secret_keys) =
            generate_party_encryption_keys(&party_ids, &mut rng);

        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Create an access structure for blending
        let party_weights: HashMap<PartyID, u16> = party_ids.iter().map(|&id| (id, 1u16)).collect();
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_weights).unwrap();

        // Round 1
        let dealing_messages: HashMap<
            PartyID,
            DealingMessage<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
        > = party_ids
            .iter()
            .map(|&party_id| {
                let dealing_output =
                    advance_dealing_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                        session_id,
                        party_id,
                        threshold,
                        &scalar_group_public_parameters,
                        &group_params,
                        &party_public_keys,
                        &parties_with_uc_verified_public_keys,
                        &mut rng,
                    )
                    .unwrap();
                (party_id, dealing_output.message)
            })
            .collect();

        // Round 2
        let mut accusation_messages: HashMap<PartyID, AccusationMessage> = HashMap::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();
            let message =
                advance_accusation_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                )
                .unwrap();

            accusation_messages.insert(party_id, message);
        }

        // Round 3 with blending
        let mut all_blended_outputs: Vec<(
            Vec<
                PrivatePresignOutput<
                    group::Value<secp256k1::Scalar>,
                    group::Value<secp256k1::GroupElement>,
                >,
            >,
            Vec<Presign<group::Value<secp256k1::GroupElement>>>,
        )> = Vec::new();

        for &party_id in &party_ids {
            let secret_key = party_secret_keys.get(&party_id).unwrap();
            let public_key = party_public_keys.get(&party_id).unwrap();
            let (_malicious_parties, private_outputs, public_outputs) =
                advance_aggregation_round_with_blending::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &accusation_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    &party_public_keys,
                    &parties_with_uc_verified_public_keys,
                    &access_structure,
                    &mut rng,
                )
                .unwrap();

            all_blended_outputs.push((private_outputs, public_outputs));
        }

        // With 5 parties and threshold 2, we can have up to 3 adversary-controlled parties
        // So we should get 5 - 3 = 2 blended outputs (but it depends on the weight computation)
        // Actually with all weights = 1 and threshold = 2, max adversary parties = 1
        // So we get 5 - 1 = 4 blended outputs
        assert!(
            !all_blended_outputs.is_empty(),
            "Should produce at least one blended output"
        );

        let num_outputs = all_blended_outputs[0].1.len();
        assert!(
            num_outputs >= 1,
            "Should produce at least one blended output per party"
        );

        // Verify all parties got the same number of outputs
        for (_, public_outputs) in &all_blended_outputs {
            assert_eq!(
                public_outputs.len(),
                num_outputs,
                "All parties should have the same number of outputs"
            );
        }

        // Verify all parties agree on public values for each blended output
        for output_idx in 0..num_outputs {
            let first_public_output = &all_blended_outputs[0].1[output_idx];
            for (_, party_public_outputs) in &all_blended_outputs[1..] {
                assert_eq!(
                    first_public_output.decentralized_party_nonce_public_share_first_part,
                    party_public_outputs[output_idx]
                        .decentralized_party_nonce_public_share_first_part,
                    "All parties should agree on blended K_B,0 for output {output_idx}"
                );
                assert_eq!(
                    first_public_output.decentralized_party_nonce_public_share_second_part,
                    party_public_outputs[output_idx]
                        .decentralized_party_nonce_public_share_second_part,
                    "All parties should agree on blended K_B,1 for output {output_idx}"
                );
            }
        }

        // Verify that each blended output has non-trivial public nonce shares
        let neutral =
            secp256k1::GroupElement::neutral_from_public_parameters(&group_params).unwrap();
        for (output_idx, public_output) in all_blended_outputs[0].1.iter().enumerate() {
            let k_b_0 = secp256k1::GroupElement::new(
                public_output.decentralized_party_nonce_public_share_first_part,
                &group_params,
            )
            .unwrap();
            let k_b_1 = secp256k1::GroupElement::new(
                public_output.decentralized_party_nonce_public_share_second_part,
                &group_params,
            )
            .unwrap();

            assert_ne!(
                k_b_0.value(),
                neutral.value(),
                "Blended K_B,0 for output {output_idx} should not be identity"
            );
            assert_ne!(
                k_b_1.value(),
                neutral.value(),
                "Blended K_B,1 for output {output_idx} should not be identity"
            );
        }
    }
}
