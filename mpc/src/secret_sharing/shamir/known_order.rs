// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Verifiable Secret Sharing (VSS)
//!
//! This module implements Verifiable Secret Sharing with Feldman-style commitments
//! and HPKE encryption (X25519 + ChaCha20Poly1305).
//!
//! ## Overview
//!
//! The VSS scheme enables a dealer to share a secret $s$ among $n$ parties such that:
//! - Any $t$ parties can reconstruct the secret (threshold property)
//! - Each recipient can verify their share is consistent with the public commitments
//! - Shares are encrypted to each party using HPKE (confidentiality)
//!
//! ## Protocol Description
//!
//! ### Dealer Actions:
//!
//! 1. Sample polynomial $f(X) = s + a_1 X + \dots + a_{t-1} X^{t-1}$ where $s$ is the secret
//! 2. Compute coefficient commitments: $C_j = a_j \cdot G$ for $j \in [0, t-1]$
//! 3. Generate proof of knowledge of the free coefficient (the secret):
//!    - Prove knowledge of $s$ such that $C_0 = s \cdot G$ using a Maurer proof
//! 4. For each party $j \in [1, n]$:
//!    - Compute share $s_j = f(j)$
//!    - Encrypt share using HPKE to the party's public key
//! 5. Broadcast $(C_0, \dots, C_{t-1}, \pi_s, \textsf{ct}_1, \dots, \textsf{ct}_n)$
//!    where $\pi_s$ is the proof of knowledge of the free coefficient
//!
//! ### Recipient Actions:
//!
//! 1. Verify the proof of knowledge of the free coefficient $\pi_s$ against $C_0$
//! 2. Decrypt own share using own secret key
//! 3. Verify share against commitments:
//!    $$s_j \cdot G = \sum_{k=0}^{t-1} j^k \cdot C_k$$
//!
//! ## Security Properties
//!
//! - **Binding**: Dealer cannot open shares inconsistent with commitments
//! - **Hiding**: Shares reveal nothing about the secret (computational, from HPKE)
//! - **Reconstruction Security**: $t-1$ shares reveal nothing about secret

pub mod encryption;

use super::Polynomial;
use crate::{
    ContributionBlending, Error, ErrorKind, HandleInvalidMessages, Result,
    WeightedThresholdAccessStructure,
};
use crypto_bigint::Uint;
use encryption::{
    decrypt_shares, verify_accusation_and_decrypt, ProtocolContextWithPartyID,
    SharesAccusationDecryptionResult,
};
pub use encryption::{
    encrypt_shares, encryption_public_key_from_secret, generate_accusation,
    generate_and_uc_prove_encryption_keypair, generate_encryption_keypair,
    generate_encryption_secret_key, verify_uc_proofs_of_knowledge_of_encryption_secret_keys,
    Accusation, EncryptedShares, EncryptionPublicKey, EncryptionSecretKey,
    KnowledgeOfDecryptionKeyUCProof,
};
use group::helpers::TryCollectHashMap;
use group::{CsRng, GroupElement as _, Invert, PartyID, PrimeGroupElement, Samplable};
use itertools::multiunzip;
use maurer::{knowledge_of_discrete_log, SOUND_PROOFS_REPETITIONS};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::iter;

/// Proof of knowledge of the free coefficient (the secret) in the VSS protocol.
///
/// This is a Maurer proof proving that the dealer knows the discrete log of `C_0`,
/// i.e., the dealer knows `s` such that `C_0 = s * G`.
///
/// The `ProtocolContext` generic provides domain separation for the proof. The proof
/// uses `DealerEncryptionContext<ProtocolContext>` internally to include the dealer ID.
pub type KnowledgeOfFreeCoefficientProof<const SCALAR_LIMBS: usize, GroupElement, ProtocolContext> =
    maurer::Proof<
        SOUND_PROOFS_REPETITIONS,
        knowledge_of_discrete_log::Language<
            group::Scalar<SCALAR_LIMBS, GroupElement>,
            GroupElement,
        >,
        ProtocolContextWithPartyID<ProtocolContext>,
    >;

/// A dealing message from a single dealer in a VSS protocol.
///
/// Contains everything needed for parties to verify and use their shares.
/// Supports dealing multiple secrets at once, with all shares for a party encrypted together.
///
/// The `ProtocolContext` generic provides domain separation for the proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "GroupElement::Value: Serialize, KnowledgeOfFreeCoefficientProof<SCALAR_LIMBS, GroupElement, ProtocolContext>: Serialize",
    deserialize = "GroupElement::Value: Deserialize<'de>, KnowledgeOfFreeCoefficientProof<SCALAR_LIMBS, GroupElement, ProtocolContext>: Deserialize<'de>"
))]
pub struct DealingMessage<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
> {
    /// Coefficient commitments for each secret: outer Vec is per-secret, inner Vec is
    /// $[C_0, C_1, \dots, C_{t-1}]$ where $C_k = a_k \cdot G$.
    ///
    /// Note: $C_0 = s \cdot G$ is the public key share (commitment to the secret).
    pub coefficient_commitments: Vec<Vec<GroupElement::Value>>,
    /// Batched proof of knowledge of all free coefficients.
    ///
    /// A single proof proving the dealer knows all `s_i` such that `C_0[i] = s_i * G`.
    pub knowledge_of_free_coefficients_proof:
        KnowledgeOfFreeCoefficientProof<SCALAR_LIMBS, GroupElement, ProtocolContext>,
    /// Encrypted shares for each party. All shares for a party are encrypted together.
    pub encrypted_shares: HashMap<PartyID, EncryptedShares>,
}

/// Output from a VSS dealing operation.
///
/// Contains the dealing message to broadcast plus any parties identified as having
/// invalid encryption keys (identity point keys) that were excluded from dealing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealingOutput<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
> {
    /// The dealing message containing commitments, proofs, and encrypted shares.
    pub message: DealingMessage<SCALAR_LIMBS, GroupElement, ProtocolContext>,
    /// Parties with invalid encryption keys (identity points) that were excluded from dealing.
    ///
    /// These parties should be marked as malicious since they cannot receive shares securely.
    pub parties_with_invalid_encryption_keys: Vec<PartyID>,
}

/// Deals shares of multiple secrets to multiple parties using VSS.
///
/// Uses ephemeral keys for encryption - no dealer private key required.
/// All shares for a party (across all secrets) are encrypted together in a single ciphertext,
/// which means only one revealed key is needed for accusations.
///
/// # Arguments
///
/// * `dealer_party_id` - The ID of the dealer creating the shares (included in proof for domain separation)
/// * `secrets` - The secrets to share (one or more)
/// * `threshold` - The number of parties needed to reconstruct (t)
/// * `party_public_keys` - Map from party ID to their X25519 public key
/// * `parties_with_uc_verified_public_keys` - Set of party IDs whose encryption keys have been UC-verified.
///   Parties NOT in this set will be excluded from dealing and marked as having invalid keys.
/// * `protocol_context` - Protocol context for domain separation in proofs
/// * `group_public_parameters` - Public parameters for the group
/// * `scalar_public_parameters` - Public parameters for scalars
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
///
/// A `DealingOutput` containing:
/// - The dealing message with commitments, proofs of knowledge, and encrypted shares
/// - List of parties with invalid encryption keys (identity points or not UC-verified) that were excluded
#[allow(clippy::too_many_arguments)]
pub fn deal_verifiable_secret_shares<const SCALAR_LIMBS: usize, GroupElement, ProtocolContext>(
    dealer_party_id: PartyID,
    secrets: &[GroupElement::Scalar],
    threshold: PartyID,
    party_public_keys: &HashMap<PartyID, EncryptionPublicKey>,
    parties_with_uc_verified_public_keys: &HashSet<PartyID>,
    protocol_context: &ProtocolContext,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    rng: &mut impl group::CsRng,
) -> Result<DealingOutput<SCALAR_LIMBS, GroupElement, ProtocolContext>>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    GroupElement::Scalar:
        From<Uint<SCALAR_LIMBS>> + Samplable + Copy + std::ops::Mul<Output = GroupElement::Scalar>,
    group::Value<GroupElement::Scalar>: Into<Uint<SCALAR_LIMBS>>,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    if threshold == 0 {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    if secrets.is_empty() {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    if party_public_keys.is_empty() {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Validate party IDs are non-zero (we evaluate at $pid$, and 0 is the secret)
    if party_public_keys.keys().any(|&id| id == 0) {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Filter out parties with identity point encryption keys or without UC-verified keys.
    // These parties cannot receive shares securely and are marked as malicious.
    let (parties_with_invalid_encryption_keys, valid_party_encryption_keys): (
        Vec<PartyID>,
        HashMap<PartyID, EncryptionPublicKey>,
    ) = party_public_keys
        .iter()
        .map(|(&party_id, &encryption_key)| {
            let has_identity_key = encryption_key.is_neutral().into();
            let is_not_uc_verified = !parties_with_uc_verified_public_keys.contains(&party_id);
            if has_identity_key || is_not_uc_verified {
                (party_id, Err(Error::from(ErrorKind::InvalidParameters)))
            } else {
                (party_id, Ok(encryption_key))
            }
        })
        .handle_invalid_messages_async();

    // Validate threshold doesn't exceed the number of valid parties.
    // Reconstruction requires at least `threshold` shares, so we need at least that many parties.
    if threshold as usize > valid_party_encryption_keys.len() {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // The polynomial degree is threshold - 1, as we want to have `threshold` parties for reconstruction.
    let degree = threshold - 1;

    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    let dealer_proof_context = ProtocolContextWithPartyID {
        party_id: dealer_party_id,
        protocol_context: protocol_context.clone(),
    };

    let knowledge_of_free_coefficient_public_parameters =
        knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
            scalar_public_parameters.clone(),
            group_public_parameters.clone(),
            generator.value(),
            None, // No upper bound on discrete log bits
        );

    // For each secret, sample a polynomial and compute commitments
    let (all_coefficient_commitments, all_polynomials): (Vec<_>, Vec<_>) = secrets
        .iter()
        .map(|&secret| {
            // Sample polynomial with secret as constant term: f(X) = secret + a_1*X + ... + a_{t-1}*X^{t-1}
            let polynomial = Polynomial::sample_with_constant_term(
                degree,
                secret,
                scalar_public_parameters,
                rng,
            )?;

            // Compute coefficient commitments: C_k = a_k * G
            // Note: C_0 = secret * G is the public key share
            let coefficient_commitments: Vec<GroupElement::Value> = polynomial
                .coefficients()
                .iter()
                .map(|&coeff| generator.scale_by(&coeff, group_public_parameters).value())
                .collect();

            Ok((coefficient_commitments, polynomial))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .unzip();

    // Generate a single batched proof of knowledge of all free coefficients
    let (knowledge_of_free_coefficients_proof, _) = KnowledgeOfFreeCoefficientProof::prove(
        &dealer_proof_context,
        &knowledge_of_free_coefficient_public_parameters,
        secrets.to_vec(),
        rng,
    )
    .map_err(|_| Error::from(ErrorKind::InternalError))?;

    // Generate encrypted shares for each valid party - all shares encrypted together
    let encrypted_shares = valid_party_encryption_keys
        .iter()
        .map(|(&party_id, &party_encryption_key)| {
            // Collect all shares for this party (one from each polynomial)
            let is_evaluation_constant_time = true;
            let shares: Vec<_> = all_polynomials
                .iter()
                .map(|poly| {
                    poly.evaluate_degree(
                        party_id,
                        is_evaluation_constant_time,
                        scalar_public_parameters,
                    )
                })
                .collect();

            encrypt_shares(&shares, party_encryption_key, &dealer_proof_context, rng)
                .map(|encrypted| (party_id, encrypted))
        })
        .collect::<Result<HashMap<_, _>>>()?;

    Ok(DealingOutput {
        message: DealingMessage {
            coefficient_commitments: all_coefficient_commitments,
            knowledge_of_free_coefficients_proof,
            encrypted_shares,
        },
        parties_with_invalid_encryption_keys,
    })
}

/// Type alias for the complex return type of identify_malicious_dealers_publicly
pub type IdentifyPublicMaliciousDealersResult<GroupElement> =
    (HashSet<PartyID>, HashMap<PartyID, Vec<Vec<GroupElement>>>);

/// Identifies dealers who fail public (deterministic) checks on their dealing messages.
///
/// This function performs checks that all parties can verify without secrets:
/// 1. Sanity checks: each coefficient_commitments array has `threshold` elements
/// 2. Consistency checks: number of secrets matches expected
/// 3. Shares dealt to all parties with valid encryption keys
/// 4. Ephemeral keys are not identity points (prevents DH attack where recipients can't decrypt)
/// 5. Proof verification: batched knowledge of free coefficients proof verifies
///
/// # Arguments
///
/// * `dealing_messages` - Map of dealer ID to their dealing message
/// * `party_encryption_keys` - Map of party ID to their encryption public key
/// * `parties_with_uc_verified_public_keys` - Set of party IDs whose encryption keys have been UC-verified.
///   Parties NOT in this set are considered to have invalid keys.
/// * `protocol_context` - Protocol context for proof domain separation
/// * `access_structure` - The weighted threshold access structure
/// * `group_public_parameters` - Group public parameters
/// * `scalar_public_parameters` - Scalar public parameters
/// * `number_of_secrets` - Expected number of secrets (must match message structure)
///
/// # Returns
///
/// The set of dealers who failed public verification.
#[allow(clippy::too_many_arguments)]
pub fn identify_malicious_dealers_publicly<
    const SCALAR_LIMBS: usize,
    GroupElement,
    ProtocolContext,
>(
    dealing_messages: &HashMap<
        PartyID,
        DealingMessage<SCALAR_LIMBS, GroupElement, ProtocolContext>,
    >,
    party_encryption_keys: &HashMap<PartyID, EncryptionPublicKey>,
    parties_with_uc_verified_public_keys: &HashSet<PartyID>,
    protocol_context: &ProtocolContext,
    access_structure: &WeightedThresholdAccessStructure,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    number_of_shares: usize,
    rng: &mut impl CsRng,
) -> Result<IdentifyPublicMaliciousDealersResult<GroupElement>>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    GroupElement::Scalar:
        From<Uint<SCALAR_LIMBS>> + Samplable + Copy + std::ops::Mul<Output = GroupElement::Scalar>,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    // Identify parties with identity point encryption keys - they are malicious.
    // All parties can independently compute this, ensuring consistent identification.
    let parties_with_identity_keys: HashSet<PartyID> = party_encryption_keys
        .iter()
        .filter(|(_, key)| key.is_neutral().into())
        .map(|(&id, _)| id)
        .collect();

    // Identify parties without UC-verified public keys.
    let parties_with_unverified_encryption_keys: HashSet<PartyID> = party_encryption_keys
        .keys()
        .copied()
        .filter(|id| !parties_with_uc_verified_public_keys.contains(id))
        .collect();

    // Combine parties with invalid keys (identity keys or not UC-verified).
    let parties_with_invalid_keys: HashSet<PartyID> = parties_with_identity_keys
        .union(&parties_with_unverified_encryption_keys)
        .copied()
        .collect();

    let parties_with_valid_keys: HashSet<PartyID> = party_encryption_keys
        .keys()
        .copied()
        .filter(|id| !parties_with_invalid_keys.contains(id))
        .collect();

    // Now that we verified
    let (dealers_sending_invalid_coefficient_commitments, coefficient_commitments) =
        dealing_messages
            .iter()
            .map(|(&dealer_party_id, message)| {
                let coefficient_commitments = message
                    .coefficient_commitments
                    .iter()
                    .map(|coefficient_commitments| {
                        instantiate_coefficient_commitments(
                            coefficient_commitments,
                            group_public_parameters,
                        )
                    })
                    .collect::<Result<Vec<_>>>();

                (dealer_party_id, coefficient_commitments)
            })
            .handle_invalid_messages_async();

    // Identify structurally invalid dealers.
    let structurally_invalid_dealers: HashSet<PartyID> = dealing_messages
        .iter()
        .filter(|(dealer_party_id, _)| {
            !dealers_sending_invalid_coefficient_commitments.contains(dealer_party_id)
        })
        .filter(|(dealer_party_id, message)| {
            // Safe to unwrap by construction - we filtered out the dealers that sent invalid coefficient commitments.
            let coefficient_commitments = coefficient_commitments.get(dealer_party_id).unwrap();

            // Check 1: number of secrets must match expected
            let is_number_of_shares_wrong = coefficient_commitments.len() != number_of_shares;

            // Check 2: each coefficient_commitments must have exactly `threshold` elements
            let is_coefficients_length_wrong = coefficient_commitments
                .iter()
                .any(|commitments| commitments.len() != access_structure.threshold as usize);

            // Check 3: dealer must have dealt to all parties with valid encryption keys
            let dealt_parties: HashSet<PartyID> =
                message.encrypted_shares.keys().copied().collect();

            // Note: ephemeral key validation (identity/torsion) is handled via the accusation
            // mechanism. When a recipient tries to decrypt and encounters an invalid ephemeral
            // key, they generate an Accusation::IdentityEphemeralKey or Accusation::TorsionEphemeralKey,
            // which can be publicly verified. This is more efficient than validating O(dealers × recipients)
            // ephemeral keys in public checks.

            is_number_of_shares_wrong
                || is_coefficients_length_wrong
                || dealt_parties != parties_with_valid_keys
        })
        .map(|(&dealer_party_id, _)| dealer_party_id)
        .collect();

    // Collect proofs from structurally valid dealers for batch verification.
    let proofs_to_verify: HashMap<_, _> = dealing_messages
        .iter()
        .filter(|(dealer_party_id, _)| !structurally_invalid_dealers.contains(dealer_party_id))
        .map(|(&dealer_party_id, message)| {
            (
                dealer_party_id,
                (
                    &message.knowledge_of_free_coefficients_proof,
                    &message.coefficient_commitments,
                ),
            )
        })
        .collect();

    // Batch verify all proofs from structurally valid dealers.
    // All proofs share the same language public parameters, enabling efficient batch verification.
    let dealers_with_invalid_proofs = batch_verify_knowledge_of_free_coefficients_proofs::<
        SCALAR_LIMBS,
        GroupElement,
        ProtocolContext,
    >(
        proofs_to_verify,
        protocol_context,
        group_public_parameters,
        scalar_public_parameters,
        rng,
    )?;

    // Combine all malicious parties: structurally invalid dealers, proof-invalid dealers,
    // and parties with invalid encryption keys
    let publicly_malicious_dealers = dealers_sending_invalid_coefficient_commitments
        .into_iter()
        .chain(structurally_invalid_dealers)
        .chain(dealers_with_invalid_proofs)
        .chain(parties_with_invalid_keys)
        .collect();

    Ok((publicly_malicious_dealers, coefficient_commitments))
}

/// This function instantiates commitments over the coefficients of a polynomial coming from an untrusted source (i.e. sent by another dealer).
/// Only the commitment over the free coefficient must be in the prime sub-group in the curve25519.
/// All the other coefficients can be instantiated by `new_unchecked()`, which skips the expensive validations.
/// This is important for the VSS protocol, as we get O(t) commitments from O(n) dealers, thus we reduce O(n*t) ~= O(n^2) validation checks to O(n).
/// This is the case since these keys are only used for verification and equation of the form $g^{x}=h^{y}$ implies equality of the exponents both modulo the prime q and modulo the co-factor.
/// Importantly the elements are guaranteed to be group elements of the elliptic curve just not of the prime order subgroup.
fn instantiate_coefficient_commitments<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    coefficient_commitments: &[GroupElement::Value],
    group_public_parameters: &GroupElement::PublicParameters,
) -> Result<Vec<GroupElement>> {
    iter::once(GroupElement::new(
        coefficient_commitments[0].clone(),
        group_public_parameters,
    ))
    .chain(
        coefficient_commitments
            .iter()
            .skip(1)
            .map(|v| GroupElement::new_unchecked(v.clone(), group_public_parameters)),
    )
    .collect::<group::Result<Vec<_>>>()
    .map_err(Error::from)
}

/// Verifies a share against the coefficient commitments.
///
/// Checks that $s_j \cdot G = \sum_{k=0}^{t-1} j^k \cdot C_k$
///
/// # Arguments
///
/// * `party_id` - The party ID whose share is being verified
/// * `share_value` - The decrypted share value to verify
/// * `coefficient_commitments` - The coefficient commitments $[C_0, \dots, C_{t-1}]$
/// * `group_public_parameters` - Public parameters for the group
/// * `scalar_public_parameters` - Public parameters for scalars
///
/// # Returns
///
/// `Ok(()` if verification succeeds, `Err` otherwise.
pub fn verify_share<const SCALAR_LIMBS: usize, GroupElement>(
    party_id: PartyID,
    share: group::Value<GroupElement::Scalar>,
    coefficient_commitments: &[GroupElement::Value],
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
) -> Result<()>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>> + std::ops::Mul<Output = GroupElement::Scalar>,
{
    if party_id == 0 || coefficient_commitments.is_empty() {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;
    let share = GroupElement::Scalar::new(share, scalar_public_parameters)?;
    let share_commitment = generator.scale_by(&share, group_public_parameters);

    let coefficient_commitments =
        instantiate_coefficient_commitments(coefficient_commitments, group_public_parameters)?;

    let is_evaluation_constant_time = false;
    let reconstructed_commitment = Polynomial::try_from(coefficient_commitments)?.evaluate_degree(
        party_id,
        is_evaluation_constant_time,
        group_public_parameters,
    );

    if share_commitment != reconstructed_commitment {
        return Err(Error::from(ErrorKind::MaliciousMessageAsync));
    }

    Ok(())
}

/// Verifies an accusation (with discrete log equality proof) and checks if shares fail verification.
///
/// This function:
/// 1. Verifies the discrete log equality proof (proving the accuser's Diffie-Hellman result is correct)
/// 2. Derives the AEAD key and decrypts the shares
/// 3. Verifies each share against commitments
///
/// # Arguments
///
/// * `accuser_party_id` - The party ID of the accuser (whose shares are being decrypted)
/// * `accusation` - The accusation containing Diffie-Hellman result and discrete log equality proof
/// * `accuser_public_key` - The accuser's encryption public key (for discrete log equality verification)
/// * `encrypted_shares` - The encrypted shares
/// * `all_commitments` - The coefficient commitments for each secret (outer Vec is per-secret)
/// * `dealer_party_id` - The dealer's party ID for domain separation
/// * `protocol_context` - Protocol context for domain separation
/// * `group_public_parameters` - Group public parameters
/// * `scalar_public_parameters` - Scalar public parameters
///
/// # Returns
///
/// `true` if the accusation is valid (discrete log equality valid AND any share fails verification OR decryption fails),
/// `false` if discrete log equality fails (accuser is lying) or all shares verify correctly.
#[allow(clippy::too_many_arguments)]
pub fn verify_accusation<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    ProtocolContext,
>(
    accuser_party_id: PartyID,
    accusation: &Accusation<ProtocolContext>,
    accuser_public_key: &EncryptionPublicKey,
    encrypted_shares: &EncryptedShares,
    commitments_per_sharing: &[Vec<GroupElement::Value>],
    dealer_party_id: PartyID,
    protocol_context: &ProtocolContext,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    number_of_shares: usize,
) -> bool
where
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>,

    group::Value<GroupElement::Scalar>: From<Uint<SCALAR_LIMBS>>,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    let dealer_context = ProtocolContextWithPartyID {
        party_id: dealer_party_id,
        protocol_context: protocol_context.clone(),
    };

    // Verify the accusation and attempt to decrypt
    let share_values = match verify_accusation_and_decrypt::<GroupElement::Scalar, ProtocolContext>(
        accusation,
        accuser_public_key,
        encrypted_shares,
        &dealer_context,
    ) {
        SharesAccusationDecryptionResult::Decrypted(values) => values,
        SharesAccusationDecryptionResult::DecryptionFailed => {
            // Proof was valid but decryption failed - dealer is malicious
            return true;
        }
        SharesAccusationDecryptionResult::InvalidEphemeralKey => {
            // Dealer sent an invalid ephemeral key (identity or torsion) - dealer is malicious
            return true;
        }
        SharesAccusationDecryptionResult::FalseIdentityAccusation => {
            // Accuser falsely claimed identity ephemeral key - accuser is lying
            return false;
        }
        SharesAccusationDecryptionResult::FalseTorsionAccusation => {
            // Accuser falsely claimed torsion ephemeral key - accuser is lying
            return false;
        }
        SharesAccusationDecryptionResult::InvalidAccuserPublicKey => {
            // Accuser's public key is identity - accuser is lying
            return false;
        }
        SharesAccusationDecryptionResult::WrongDiffieHellmanSharedSecret => {
            // Proof verification failed - accuser is lying
            return false;
        }
    };

    // Check that we have the right number of shares
    if share_values.len() != number_of_shares || commitments_per_sharing.len() != number_of_shares {
        // Mismatch in number of shares - dealer sent malformed data
        return true;
    }

    // Check if any share verification fails - if any does, accusation is valid,
    // otherwise, accuser is malicious as accusation is invalid
    share_values
        .iter()
        .zip(commitments_per_sharing.iter())
        .any(|(&share_value, commitments)| {
            verify_share::<SCALAR_LIMBS, GroupElement>(
                accuser_party_id,
                share_value,
                commitments,
                group_public_parameters,
                scalar_public_parameters,
            )
            .is_err()
        })
}

/// Decrypts and verifies all shares for a specific party.
///
/// This function:
/// 1. Decrypts all shares using the party's secret key
/// 2. Verifies each share against its corresponding coefficient commitments
///
/// **Note**: Proof verification should be done separately via `identify_malicious_dealers_publicly`
/// before calling this function. This function assumes the dealer passed public verification.
///
/// # Arguments
///
/// * `party_id` - The ID of the party decrypting
/// * `encrypted_shares` - The encrypted shares (contains ephemeral public key)
/// * `all_coefficient_commitments` - The coefficient commitments for each secret (outer Vec is per-secret)
/// * `party_secret_key` - The party's encryption secret key
/// * `party_public_key` - The party's encryption public key
/// * `dealer_party_id` - The dealer's party ID for domain separation
/// * `protocol_context` - Protocol context for domain separation
/// * `group_public_parameters` - Public parameters for the group
/// * `scalar_public_parameters` - Public parameters for scalars
///
/// # Returns
///
/// `Ok(share_values)` if decryption and verification succeed.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_and_verify_shares<const SCALAR_LIMBS: usize, GroupElement, ProtocolContext>(
    party_id: PartyID,
    encrypted_shares: &EncryptedShares,
    all_coefficient_commitments: &[Vec<GroupElement::Value>],
    party_secret_key: &EncryptionSecretKey,
    party_public_key: &EncryptionPublicKey,
    dealer_party_id: PartyID,
    protocol_context: &ProtocolContext,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    number_of_shares: usize,
) -> Result<Vec<group::Value<GroupElement::Scalar>>>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>> + std::ops::Mul<Output = GroupElement::Scalar>,
    group::Value<GroupElement::Scalar>: From<Uint<SCALAR_LIMBS>>,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Serialize,
{
    let dealer_context = ProtocolContextWithPartyID {
        party_id: dealer_party_id,
        protocol_context: protocol_context.clone(),
    };

    // Decrypt all shares
    let shares = decrypt_shares::<GroupElement::Scalar, ProtocolContext>(
        encrypted_shares,
        *party_secret_key,
        *party_public_key,
        &dealer_context,
    )?;

    // Check we have the right number of shares
    if shares.len() != number_of_shares || all_coefficient_commitments.len() != number_of_shares {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Verify each share against its commitments
    shares
        .iter()
        .zip(all_coefficient_commitments.iter())
        .try_for_each(|(share, commitments)| {
            verify_share::<SCALAR_LIMBS, GroupElement>(
                party_id,
                *share,
                commitments,
                group_public_parameters,
                scalar_public_parameters,
            )
        })?;

    Ok(shares)
}

/// Generates an accusation (Diffie-Hellman result + discrete log equality proof) if any share verification fails.
///
/// This function decrypts and verifies shares. If any verification fails, it returns
/// an accusation with discrete log equality proof that can be used to prove the dealer sent an invalid share.
///
/// **Note**: If the ephemeral key is the identity point, no accusation is generated because:
/// 1. The dealer will be caught by public checks (identity ephemeral keys are detected there)
/// 2. A valid accusation cannot be generated for identity ephemeral keys
///
/// # Arguments
///
/// * `party_id` - The ID of the party verifying their shares
/// * `encrypted_shares` - The encrypted shares to verify
/// * `all_commitments` - The coefficient commitments for each secret (outer Vec is per-secret)
/// * `secret_key` - The party's decryption secret key
/// * `public_key` - The party's encryption public key (for discrete log equality proof)
/// * `dealer_party_id` - The dealer's party ID for domain separation
/// * `protocol_context` - Protocol context for domain separation
/// * `group_public_parameters` - Group public parameters
/// * `scalar_public_parameters` - Scalar public parameters
/// * `rng` - Cryptographically secure random number generator (for discrete log equality proof)
///
/// # Returns
///
/// `Some(Accusation)` if any share is invalid and an accusation should be made,
/// `None` if all shares are valid.
#[allow(clippy::too_many_arguments)]
pub fn verify_shares_or_accuse_dealer<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    ProtocolContext,
>(
    party_id: PartyID,
    encrypted_shares: &EncryptedShares,
    all_commitments: &[Vec<GroupElement::Value>],
    secret_key: &EncryptionSecretKey,
    public_key: &EncryptionPublicKey,
    dealer_party_id: PartyID,
    protocol_context: &ProtocolContext,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    number_of_shares: usize,
    rng: &mut impl group::CsRng,
) -> Option<Accusation<ProtocolContext>>
where
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>,

    group::Value<GroupElement::Scalar>: From<Uint<SCALAR_LIMBS>>,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    let dealer_context = ProtocolContextWithPartyID {
        party_id: dealer_party_id,
        protocol_context: protocol_context.clone(),
    };

    // Try to decrypt and verify all shares
    let verification_result =
        decrypt_and_verify_shares::<SCALAR_LIMBS, GroupElement, ProtocolContext>(
            party_id,
            encrypted_shares,
            all_commitments,
            secret_key,
            public_key,
            dealer_party_id,
            protocol_context,
            group_public_parameters,
            scalar_public_parameters,
            number_of_shares,
        );

    // If verification failed, generate the accusation.
    // This handles:
    // - Identity ephemeral key: returns Accusation::IdentityEphemeralKey
    // - Torsion ephemeral key: returns Accusation::TorsionEphemeralKey
    // - Invalid encrypted data: returns Accusation::InvalidEncryptedData with DH proof
    if verification_result.is_err() {
        generate_accusation(secret_key, encrypted_shares, &dealer_context, rng).ok()
    } else {
        None
    }
}

/// Batch verifies knowledge of free coefficient proofs from multiple dealers.
///
/// All proofs share the same language public parameters (knowledge of discrete log),
/// enabling efficient batch verification. This is more efficient than verifying
/// proofs individually, especially in the happy path where all proofs are valid.
///
/// # Arguments
///
/// * `proofs` - Map of dealer ID to (proof, coefficient_commitments)
/// * `protocol_context` - Protocol context for domain separation in proofs
/// * `group_public_parameters` - Public parameters for the group
/// * `scalar_public_parameters` - Public parameters for scalars
/// * `rng` - Random number generator for verification
///
/// # Returns
///
/// Set of dealer IDs whose proofs failed verification.
#[allow(clippy::type_complexity)]
fn batch_verify_knowledge_of_free_coefficients_proofs<
    const SCALAR_LIMBS: usize,
    GroupElement,
    ProtocolContext,
>(
    proofs: HashMap<
        PartyID,
        (
            &KnowledgeOfFreeCoefficientProof<SCALAR_LIMBS, GroupElement, ProtocolContext>,
            &Vec<Vec<GroupElement::Value>>,
        ),
    >,
    protocol_context: &ProtocolContext,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    GroupElement::Scalar:
        From<Uint<SCALAR_LIMBS>> + Samplable + Copy + std::ops::Mul<Output = GroupElement::Scalar>,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    if proofs.is_empty() {
        return Ok(HashSet::new());
    }

    // Construct the shared public parameters for the knowledge of discrete log language.
    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    let knowledge_of_free_coefficient_public_parameters =
        knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
            scalar_public_parameters.clone(),
            group_public_parameters.clone(),
            generator.value(),
            None,
        );

    // Build the input for batch verification: HashMap<PartyID, Vec<(Proof, (Context, Statements))>>
    // Note: structural validity (correct number of secrets, non-empty commitments) is already
    // checked before calling this function. Here we only validate that commitments are valid
    // group elements.
    let (dealers_with_invalid_commitments, proofs_and_contexts_and_statements): (
        Vec<_>,
        HashMap<
            PartyID,
            Vec<(
                KnowledgeOfFreeCoefficientProof<SCALAR_LIMBS, GroupElement, ProtocolContext>,
                (
                    ProtocolContextWithPartyID<ProtocolContext>,
                    Vec<GroupElement>,
                ),
            )>,
        >,
    ) = proofs
        .into_iter()
        .map(|(dealer_party_id, (proof, all_coefficient_commitments))| {
            // We already verified there are the correct number of commitments, each sized t,
            // so safe to unwrap, and we know we will have correct number of statements.
            // Extract free coefficient commitments (C_0 for each secret)
            let free_coefficient_commitments: Vec<GroupElement> = match all_coefficient_commitments
                .iter()
                .map(|commitments| {
                    GroupElement::new(commitments[0].clone(), group_public_parameters)
                })
                .collect::<group::Result<Vec<_>>>()
            {
                Ok(commitments) => commitments,
                Err(_) => {
                    return (
                        dealer_party_id,
                        Err(Error::from(ErrorKind::InvalidParameters)),
                    )
                }
            };

            let dealer_proof_context = ProtocolContextWithPartyID {
                party_id: dealer_party_id,
                protocol_context: protocol_context.clone(),
            };

            (
                dealer_party_id,
                Ok(vec![(
                    proof.clone(),
                    (dealer_proof_context, free_coefficient_commitments),
                )]),
            )
        })
        .handle_invalid_messages_async();

    // If all dealers had invalid commitments, no proofs to verify
    if proofs_and_contexts_and_statements.is_empty() {
        return Ok(dealers_with_invalid_commitments.into_iter().collect());
    }

    // Use verify_batch_asynchronously which tries batch verification first,
    // then falls back to individual verification if batch fails.
    let (dealers_with_invalid_proofs, _) = <KnowledgeOfFreeCoefficientProof<
        SCALAR_LIMBS,
        GroupElement,
        ProtocolContext,
    > as proof::Proof>::verify_batch_asynchronously(
        proofs_and_contexts_and_statements,
        &knowledge_of_free_coefficient_public_parameters,
        rng,
    );

    Ok(dealers_with_invalid_commitments
        .into_iter()
        .chain(dealers_with_invalid_proofs)
        .collect())
}

/// Output from the VSS aggregation with blending.
///
/// Contains the identified malicious parties and the blended outputs.
/// Supports multiple secrets - each secret gets its own set of blended outputs.
#[derive(Clone, Debug)]
pub struct AggregationOutput<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
> {
    /// Parties identified as malicious during aggregation.
    pub malicious_parties: HashSet<PartyID>,
    /// Blended private shares: outer Vec is per-secret, inner Vec is per blending output.
    pub blended_private_shares: Vec<Vec<group::Value<GroupElement::Scalar>>>,
    /// Blended public values (commitments to the blended secrets): outer Vec is per-secret, inner Vec is per blending output.
    pub blended_public_values: Vec<Vec<GroupElement::Value>>,
    /// Blended coefficient commitments for polynomial share verification.
    /// Structure: `[secret_index][blending_output_index][coefficient_index]`.
    /// These commitments allow verifying signature shares in the exponent during the sign protocol.
    pub blended_coefficient_commitments: Vec<Vec<Vec<GroupElement::Value>>>,
}

/// Aggregates VSS shares with blending to produce multiple outputs.
///
/// This function performs the complete aggregation round of a VSS protocol:
/// 1. Identifies malicious dealers from public checks (uses `identify_malicious_dealers_publicly`)
/// 2. Verifies accusations (with discrete log equality proofs) and identifies additional malicious parties
/// 3. Filters to get the honest subset
/// 4. Decrypts shares from honest dealers
/// 5. Blends contributions using the Vandermonde-based blending
///
/// Supports multiple secrets dealt together - each secret's contributions are blended separately.
///
/// # Arguments
///
/// * `party_id` - This party's ID
/// * `secret_key` - This party's encryption secret key
/// * `public_key` - This party's encryption public key
/// * `dealing_messages` - Map of dealer ID to their dealing message
/// * `accusations` - Map of accuser ID to (dealer ID -> accusation with discrete log equality proof)
/// * `protocol_context` - Protocol context for proof domain separation
/// * `group_public_parameters` - Group public parameters
/// * `scalar_public_parameters` - Scalar public parameters
/// * `party_encryption_keys` - Map of party ID to encryption public key
/// * `parties_with_uc_verified_public_keys` - Set of party IDs whose encryption keys have been UC-verified.
///   Parties NOT in this set are considered to have invalid keys.
/// * `access_structure` - The weighted threshold access structure
/// * `number_of_secrets` - Expected number of secrets per dealer
///
/// # Returns
///
/// `Ok(AggregationOutput)` containing malicious parties and blended outputs.
#[allow(clippy::too_many_arguments)]
pub fn aggregate_shares_with_blending<const SCALAR_LIMBS: usize, GroupElement, ProtocolContext>(
    party_id: PartyID,
    secret_key: &EncryptionSecretKey,
    public_key: &EncryptionPublicKey,
    dealing_messages: &HashMap<
        PartyID,
        DealingMessage<SCALAR_LIMBS, GroupElement, ProtocolContext>,
    >,
    accusations: &HashMap<PartyID, HashMap<PartyID, Accusation<ProtocolContext>>>,
    protocol_context: &ProtocolContext,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    party_encryption_keys: &HashMap<PartyID, EncryptionPublicKey>,
    parties_with_uc_verified_public_keys: &HashSet<PartyID>,
    access_structure: &WeightedThresholdAccessStructure,
    number_of_secrets: usize,
    rng: &mut impl CsRng,
) -> Result<AggregationOutput<SCALAR_LIMBS, GroupElement>>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + crate::ContributionBlending + Copy,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + Samplable
        + Copy
        + std::ops::Mul<Output = GroupElement::Scalar>
        + crate::ContributionBlending,

    group::Value<GroupElement::Scalar>: From<Uint<SCALAR_LIMBS>>,
    Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    if !party_encryption_keys.contains_key(&party_id) {
        // We cannot advance if we don't have an encryption key, as we won't get any shares
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Identify malicious dealers from public checks
    let (publicly_malicious_dealers, coefficient_commitments) =
        identify_malicious_dealers_publicly::<SCALAR_LIMBS, GroupElement, ProtocolContext>(
            dealing_messages,
            party_encryption_keys,
            parties_with_uc_verified_public_keys,
            protocol_context,
            access_structure,
            group_public_parameters,
            scalar_public_parameters,
            number_of_secrets,
            rng,
        )?;

    // Verify accusations (with discrete log equality proofs) and identify additional malicious parties
    let malicious_parties_from_accusations: HashSet<PartyID> = accusations
        .iter()
        .flat_map(|(&accuser_party_id, dealer_accusations)| {
            dealer_accusations
                .iter()
                // `move` is needed to copy `accuser_party_id` into the inner closure.
                // Without it, the closure would borrow from the outer closure, but `flat_map`
                // requires the returned iterator to outlive that borrow.
                .map(move |(&dealer_party_id, accusation)| {
                    // Get accuser's public key for discrete log equality verification
                    let accuser_public_key = match party_encryption_keys.get(&accuser_party_id) {
                        Some(pk) => pk,
                        None => {
                            // Dealer could not have dealt to a party with no encryption key, so the accuser party is malicious.
                            return accuser_party_id;
                        }
                    };

                    if let Some(message) = dealing_messages.get(&dealer_party_id) {
                        if let Some(encrypted_shares) =
                            message.encrypted_shares.get(&accuser_party_id)
                        {
                            if verify_accusation::<SCALAR_LIMBS, GroupElement, ProtocolContext>(
                                accuser_party_id,
                                accusation,
                                accuser_public_key,
                                encrypted_shares,
                                &message.coefficient_commitments,
                                dealer_party_id,
                                protocol_context,
                                group_public_parameters,
                                scalar_public_parameters,
                                number_of_secrets,
                            ) {
                                dealer_party_id
                            } else {
                                accuser_party_id
                            }
                        } else {
                            // We should only generate accusations for bad encryptions; missing encryptions would blame the dealer in the public checks.
                            accuser_party_id
                        }
                    } else {
                        // Missing dealer means accuser is malicious
                        accuser_party_id
                    }
                })
        })
        .collect();

    // Combine malicious parties from all sources
    let malicious_parties: HashSet<PartyID> = publicly_malicious_dealers
        .union(&malicious_parties_from_accusations)
        .copied()
        .collect();

    // Check if we are malicious ourselves - this should never happen
    if malicious_parties.contains(&party_id) {
        return Err(Error::from(ErrorKind::InternalError));
    }

    // Get honest dealers and verify authorization
    let honest_dealers: HashSet<PartyID> = dealing_messages
        .keys()
        .copied()
        .filter(|id| !malicious_parties.contains(id))
        .collect();

    access_structure
        .is_authorized_subset(&honest_dealers)
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    // Decrypt shares from honest dealers and collect contributions per secret
    // Structure: Vec of (dealer_party_id, Vec<shares for each secret>)
    let decrypted_shares = honest_dealers
        .iter()
        .filter_map(|&dealer_party_id| {
            let message = dealing_messages.get(&dealer_party_id)?;
            let encrypted_shares = message.encrypted_shares.get(&party_id)?;

            Some((dealer_party_id, message, encrypted_shares))
        })
        .map(|(dealer_party_id, message, encrypted_shares)| {
            let share_values =
                decrypt_and_verify_shares::<SCALAR_LIMBS, GroupElement, ProtocolContext>(
                    party_id,
                    encrypted_shares,
                    &message.coefficient_commitments,
                    secret_key,
                    public_key,
                    dealer_party_id,
                    protocol_context,
                    group_public_parameters,
                    scalar_public_parameters,
                    number_of_secrets,
                )
                .map_err(|_| Error::from(ErrorKind::MaliciousMessagePreventsAdvance))?;

            Ok::<_, Error>((dealer_party_id, share_values))
        })
        .try_collect_hash_map()?;

    // Verify we have shares from exactly the same dealers as honest_dealers.
    // If any dealer was filtered out, it means we couldn't decrypt shares from a dealer
    // that passed public checks. This should have been caught in the accusation round -
    // we're in an inconsistent state and cannot produce valid output.
    let honest_dealers_to_me: HashSet<PartyID> = decrypted_shares.keys().copied().collect();
    if honest_dealers_to_me != honest_dealers {
        return Err(Error::from(ErrorKind::MaliciousMessagePreventsAdvance));
    }

    // Get the number of coefficients (threshold) from the first honest dealer's message
    let threshold = honest_dealers
        .iter()
        .next()
        .and_then(|dealer_party_id| dealing_messages.get(dealer_party_id))
        .and_then(|msg| msg.coefficient_commitments.first())
        .map(|coeffs| coeffs.len())
        .ok_or_else(|| Error::from(ErrorKind::InternalError))?;

    // Blend each secret's contributions separately
    let (blended_public_values, blended_private_shares, blended_coefficient_commitments) =
        multiunzip(
            (0..number_of_secrets)
                .map(|secret_index| {
                    // Collect public contributions (C_0 = secret * G) for this secret
                    let public_contributions: HashMap<PartyID, GroupElement> = honest_dealers
                        .iter()
                        .map(|&dealer_party_id| {
                            let coefficient_commitments = coefficient_commitments
                                .get(&dealer_party_id)
                                .ok_or_else(|| Error::from(ErrorKind::InternalError))?;
                            let commitment = coefficient_commitments
                                .get(secret_index)
                                .ok_or_else(|| Error::from(ErrorKind::InternalError))?;
                            let free_coefficient_commitment = commitment[0];

                            Ok::<_, Error>((dealer_party_id, free_coefficient_commitment))
                        })
                        .try_collect_hash_map()?;

                    // Collect private shares for this secret
                    let private_contributions: HashMap<PartyID, GroupElement::Scalar> =
                        decrypted_shares
                            .iter()
                            .map(|(dealer_party_id, shares)| {
                                let share_value = shares
                                    .get(secret_index)
                                    .ok_or_else(|| Error::from(ErrorKind::InternalError))?;
                                let share = GroupElement::Scalar::new(
                                    *share_value,
                                    scalar_public_parameters,
                                )
                                .map_err(|_| Error::from(ErrorKind::InternalError))?;

                                Ok::<_, Error>((*dealer_party_id, share))
                            })
                            .try_collect_hash_map()?;

                    // Blend contributions for this secret (free coefficient / public value)
                    let blended_public_shares: Vec<_> = GroupElement::blend_contributions(
                        access_structure,
                        public_contributions,
                        group_public_parameters,
                    )?;

                    let blended_public_shares: Vec<_> = blended_public_shares
                        .into_iter()
                        .map(|g| g.value())
                        .collect();

                    let blended_secret_shares: Vec<_> = GroupElement::Scalar::blend_contributions(
                        access_structure,
                        private_contributions,
                        scalar_public_parameters,
                    )?;

                    let blended_secret_shares: Vec<_> = blended_secret_shares
                        .into_iter()
                        .map(|s| s.value())
                        .collect();

                    // Blend coefficient commitments for each coefficient position
                    // This produces Vec<Vec<GroupElement::Value>> where outer is per blending output,
                    // inner is per coefficient
                    let blended_coefficients_per_output: Vec<Vec<GroupElement::Value>> = (0
                        ..threshold)
                        .map(|coefficient_index| {
                            // Collect coefficient commitment at position coefficient_index from all
                            // honest dealers
                            let coefficient_contributions: HashMap<PartyID, GroupElement> =
                                honest_dealers
                                    .iter()
                                    .map(|&dealer_party_id| {
                                        let coefficient_commitments = coefficient_commitments
                                            .get(&dealer_party_id)
                                            .ok_or_else(|| Error::from(ErrorKind::InternalError))?;

                                        let coefficients = coefficient_commitments
                                            .get(secret_index)
                                            .ok_or_else(|| Error::from(ErrorKind::InternalError))?;
                                        let coefficient_commitment =
                                            coefficients[coefficient_index];

                                        Ok::<_, Error>((dealer_party_id, coefficient_commitment))
                                    })
                                    .try_collect_hash_map()?;

                            // Blend the coefficient commitments
                            let blended: Vec<_> = GroupElement::blend_contributions(
                                access_structure,
                                coefficient_contributions,
                                group_public_parameters,
                            )?;

                            Ok::<_, Error>(blended.into_iter().map(|g| g.value()).collect())
                        })
                        .collect::<Result<Vec<_>>>()?;

                    // Transpose from [coefficient_index][blending_output_index] to
                    // [blending_output_index][coefficient_index]
                    let number_of_blending_outputs = blended_coefficients_per_output
                        .first()
                        .map(|v| v.len())
                        .unwrap_or(0);
                    let transposed: Vec<Vec<GroupElement::Value>> = (0..number_of_blending_outputs)
                        .map(|blending_idx| {
                            blended_coefficients_per_output
                                .iter()
                                .map(|coeff_vec| coeff_vec[blending_idx].clone())
                                .collect()
                        })
                        .collect();

                    Ok((blended_public_shares, blended_secret_shares, transposed))
                })
                .collect::<Result<Vec<_>>>()?,
        );

    Ok(AggregationOutput {
        malicious_parties,
        blended_private_shares,
        blended_public_values,
        blended_coefficient_commitments,
    })
}

/// Computes the Lagrange coefficient for a party in secret sharing reconstruction.
///
/// For reconstruction at evaluation point $x = 0$, the Lagrange coefficient for party $j$ is:
/// $$\lambda_j = \prod_{k \neq j} \frac{-k}{j - k}$$
///
/// This coefficient is used to weight party $j$'s share when combining shares to reconstruct
/// the secret: $s = \sum_{j} \lambda_j \cdot s_j$
///
/// # Arguments
///
/// * `party_id` - The party ID $j$ for which to compute the coefficient
/// * `all_party_ids` - All party IDs participating in reconstruction
/// * `_scalar_public_parameters` - Scalar public parameters (unused but kept for API consistency)
///
/// # Returns
///
/// The Lagrange coefficient $\lambda_j$ as a scalar
pub fn compute_lagrange_coefficient<const SCALAR_LIMBS: usize, Scalar>(
    party_id: PartyID,
    all_party_ids: &[PartyID],
) -> Result<Scalar>
where
    Scalar: group::GroupElement
        + From<Uint<SCALAR_LIMBS>>
        + std::ops::Mul<Output = Scalar>
        + std::ops::Add<Output = Scalar>
        + std::ops::Neg<Output = Scalar>
        + group::Invert
        + Copy,
{
    let party_id_as_scalar: Scalar = Scalar::from(Uint::<SCALAR_LIMBS>::from(party_id as u64));
    let one: Scalar = Scalar::from(Uint::<SCALAR_LIMBS>::from(1u64));

    // Compute numerator = prod(k) and denominator = prod(j - k) for k != j
    let (numerator, denominator) = all_party_ids.iter().filter(|&&pid| pid != party_id).fold(
        (one, one),
        |(num, denom), &other_party_id| {
            let other_party_id_as_scalar: Scalar =
                Scalar::from(Uint::<SCALAR_LIMBS>::from(other_party_id as u64));
            // numerator *= k
            // denominator *= (j - k)
            let diff = party_id_as_scalar + (-other_party_id_as_scalar);
            (num * other_party_id_as_scalar, denom * diff)
        },
    );

    // lambda_j = numerator / denominator = numerator * denominator^(-1)
    // For evaluation at 0: lambda = prod(k / (j-k)) = prod(-k / (j-k)) with sign adjustment
    // Actually at x=0: lambda_j = prod_{k!=j} (0-k)/(j-k) = prod_{k!=j} (-k)/(j-k)
    // = prod(k) / prod(j-k) * (-1)^(n-1) where n is number of parties

    // Simpler: just compute prod(k) / prod(j-k) and negate if odd number of terms
    let number_of_other_parties = all_party_ids.len() - 1;
    let sign_adjustment = if number_of_other_parties % 2 == 1 {
        -one
    } else {
        one
    };

    // Compute inverse of denominator
    let denominator_inv: Scalar =
        Option::from(denominator.invert()).ok_or_else(|| Error::from(ErrorKind::InternalError))?;

    Ok(numerator * denominator_inv * sign_adjustment)
}

/// Reconstructs a secret from shares using Lagrange interpolation at zero.
///
/// Computes $s = \sum_{j \in S} \lambda_j \cdot s_j$ where
/// $\lambda_j = \prod_{k \in S, k \neq j} \frac{k}{k - j}$
/// are the Lagrange coefficients evaluated at $x = 0$.
///
/// This is a general-purpose interpolation function that works for any shares
/// (secret key shares, nonce shares, signature shares, etc.) as long as they
/// were created from polynomial evaluation at the party IDs.
///
/// # Arguments
///
/// * `shares` - Map from party ID to share value (must contain exactly `threshold` shares)
/// * `threshold` - The threshold of the secret sharing scheme
/// * `scalar_public_parameters` - Public parameters for scalars
///
/// # Returns
///
/// The reconstructed secret $s$.
///
/// # Errors
///
/// Returns `Error::from(ErrorKind::InvalidParameters)` if the number of shares does not equal the threshold.
pub fn lagrange_interpolate_at_zero<const SCALAR_LIMBS: usize, Scalar>(
    shares: &HashMap<PartyID, group::Value<Scalar>>,
    threshold: PartyID,
    scalar_public_parameters: &<Scalar as group::GroupElement>::PublicParameters,
) -> Result<group::Value<Scalar>>
where
    Scalar: group::GroupElement
        + From<Uint<SCALAR_LIMBS>>
        + std::ops::Mul<Output = Scalar>
        + Invert
        + Copy,
{
    if shares.len() != threshold as usize {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    let party_ids: Vec<PartyID> = shares.keys().copied().collect();
    let one: Scalar = Scalar::from(Uint::<SCALAR_LIMBS>::from(1u64));

    // Precompute party IDs as scalars
    let party_id_scalars: Vec<Scalar> = party_ids
        .iter()
        .map(|&pid| Scalar::from(Uint::<SCALAR_LIMBS>::from(pid as u64)))
        .collect();

    // Compute numerators and denominators for all parties
    let numerators_and_denominators: Vec<(Scalar, Scalar)> = party_ids
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let party_id_scalar = party_id_scalars[i];
            party_id_scalars
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .fold((one, one), |(num, denom), (_, other)| {
                    let diff = party_id_scalar.sub_constant_time(other, scalar_public_parameters);
                    (num * *other, denom * diff)
                })
        })
        .collect();

    // Extract denominators for batch inversion
    let mut denominators: Vec<Scalar> = numerators_and_denominators
        .iter()
        .map(|(_, d)| *d)
        .collect();

    // Batch invert all denominators at once
    Scalar::batch_invert(&mut denominators);

    // Compute sign adjustment (same for all parties since they all have same number of other parties)
    let number_of_other_parties = party_ids.len() - 1;
    let sign_adjustment = if number_of_other_parties % 2 == 1 {
        one.neg_constant_time(scalar_public_parameters)
    } else {
        one
    };

    // Compute final result
    let result =
        shares
            .iter()
            .zip(numerators_and_denominators.iter())
            .zip(denominators.iter())
            .try_fold(
                Scalar::neutral_from_public_parameters(scalar_public_parameters)?,
                |accumulator, (((&_party_id, share_value), (numerator, _)), denominator_inv)| {
                    let share = Scalar::new(share_value.clone(), scalar_public_parameters)?;
                    let lagrange_coefficient = *numerator * *denominator_inv * sign_adjustment;
                    Ok::<_, Error>(accumulator.add_constant_time(
                        &(lagrange_coefficient * share),
                        scalar_public_parameters,
                    ))
                },
            )?;

    Ok(result.value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{curve25519, secp256k1, CyclicGroupElement, OsCsRng, Samplable, Scale};
    use std::marker::PhantomData;

    /// Helper to generate encryption keys for a set of parties.
    fn generate_party_keys(
        party_ids: &[PartyID],
        rng: &mut impl group::CsRng,
    ) -> (
        HashMap<PartyID, EncryptionPublicKey>,
        HashMap<PartyID, EncryptionSecretKey>,
    ) {
        let mut public_keys = HashMap::new();
        let mut secret_keys = HashMap::new();

        for &party_id in party_ids {
            let (secret_key, public_key) = encryption::generate_encryption_keypair(rng).unwrap();
            public_keys.insert(party_id, public_key);
            secret_keys.insert(party_id, secret_key);
        }

        (public_keys, secret_keys)
    }

    #[test]
    fn test_deal_and_verify() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        // Setup
        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        // Generate key pairs for parties
        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        // Sample a secret
        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // Deal - no dealer keypair needed!
        // Dealer ID 0 is used (could be any non-participant ID)
        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret], // Now takes slice of secrets
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Verify each party can decrypt and verify their share
        for &party_id in &party_ids {
            let party_secret_key = party_secret_keys.get(&party_id).unwrap();
            let party_public_key = party_public_keys.get(&party_id).unwrap();
            let encrypted_shares = dealer_output
                .message
                .encrypted_shares
                .get(&party_id)
                .unwrap();
            let share_values = decrypt_and_verify_shares::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                _,
            >(
                party_id,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                party_secret_key,
                party_public_key,
                dealer_party_id,
                &protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                1,
            )
            .unwrap();

            // Share should be valid (non-zero for random secret)
            let zero =
                secp256k1::Scalar::neutral_from_public_parameters(&scalar_group_public_parameters)
                    .unwrap()
                    .value();
            assert_eq!(share_values.len(), 1);
            assert!(share_values[0] != zero);
        }
    }

    #[test]
    fn test_commitment_to_secret() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, _party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // C_0 should be secret * G (first secret's first commitment)
        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_params).unwrap();
        let expected_commitment = generator.scale_by(&secret, &group_params).value();
        assert_eq!(
            dealer_output.message.coefficient_commitments[0][0],
            expected_commitment
        );
    }

    #[test]
    fn test_invalid_threshold_zero() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let (secret_key, public_key) = encryption::generate_encryption_keypair(&mut rng).unwrap();
        let _ = secret_key; // unused in this test
        let party_public_keys: HashMap<PartyID, EncryptionPublicKey> =
            HashMap::from([(1, public_key)]);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // Mark party 1 as UC-verified
        let parties_with_uc_verified_public_keys: HashSet<PartyID> = HashSet::from([1]);
        let result = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            0, // Invalid threshold
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        );

        assert!(matches!(result, Err(e) if matches!(e.kind, ErrorKind::InvalidParameters)));
    }

    #[test]
    fn test_invalid_party_id_zero() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let (_secret_key, public_key) = encryption::generate_encryption_keypair(&mut rng).unwrap();
        let party_public_keys: HashMap<PartyID, EncryptionPublicKey> =
            HashMap::from([(0, public_key)]); // Invalid party ID

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // Mark party 0 as UC-verified (even though party ID 0 is invalid)
        let parties_with_uc_verified_public_keys: HashSet<PartyID> = HashSet::from([0]);
        let result = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            1,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        );

        assert!(matches!(result, Err(e) if matches!(e.kind, ErrorKind::InvalidParameters)));
    }

    #[test]
    fn test_empty_parties() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let party_public_keys: HashMap<PartyID, EncryptionPublicKey> = HashMap::new();

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        let parties_with_uc_verified_public_keys: HashSet<PartyID> = HashSet::new();
        let result = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            1,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        );

        assert!(matches!(result, Err(e) if matches!(e.kind, ErrorKind::InvalidParameters)));
    }

    #[test]
    fn test_invalid_threshold_exceeds_parties() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        // Only 2 parties, but threshold is 3 - impossible to reconstruct
        let party_ids: Vec<PartyID> = vec![1, 2];
        let (party_public_keys, _party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // Mark all parties as UC-verified
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let result = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            3, // Threshold exceeds number of parties (2)
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        );

        assert!(matches!(result, Err(e) if matches!(e.kind, ErrorKind::InvalidParameters)));
    }

    #[test]
    fn test_identity_point_encryption_key_excluded() {
        use group::GroupElement;

        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        // Create 3 parties, one with identity point as encryption key
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let (mut party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        // Replace party 2's key with the identity point (malicious/broken key)
        let identity_point = curve25519::GroupElement::neutral_from_public_parameters(
            &curve25519::PublicParameters::default(),
        )
        .unwrap();
        party_public_keys.insert(2, identity_point);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        let threshold: PartyID = 2;
        // Mark all parties as UC-verified (even party 2 with identity key)
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Dealing should succeed, but party 2 should be excluded
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Party 2 should be marked as having invalid key
        assert_eq!(
            dealer_output.parties_with_invalid_encryption_keys,
            vec![2],
            "Party 2 should be identified as having invalid encryption key"
        );

        // Only parties 1 and 3 should have received encrypted shares
        assert_eq!(
            dealer_output.message.encrypted_shares.len(),
            2,
            "Should only have encrypted shares for valid parties"
        );
        assert!(
            dealer_output.message.encrypted_shares.contains_key(&1),
            "Party 1 should have encrypted shares"
        );
        assert!(
            !dealer_output.message.encrypted_shares.contains_key(&2),
            "Party 2 should NOT have encrypted shares"
        );
        assert!(
            dealer_output.message.encrypted_shares.contains_key(&3),
            "Party 3 should have encrypted shares"
        );

        // Valid parties should be able to decrypt and verify their shares
        for &party_id in &[1, 3] {
            let party_secret_key = party_secret_keys.get(&party_id).unwrap();
            let party_public_key = party_public_keys.get(&party_id).unwrap();
            let encrypted_shares = dealer_output
                .message
                .encrypted_shares
                .get(&party_id)
                .unwrap();
            let share_values = decrypt_and_verify_shares::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                _,
            >(
                party_id,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                party_secret_key,
                party_public_key,
                dealer_party_id,
                &protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                1,
            )
            .expect("Valid party should be able to decrypt and verify");

            assert_eq!(share_values.len(), 1, "Should have one share value");
        }
    }

    #[test]
    fn test_identity_point_key_fails_if_threshold_not_met() {
        use group::GroupElement;

        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        // Create 2 parties, one with identity point as encryption key
        let party_ids: Vec<PartyID> = vec![1, 2];
        let (mut party_public_keys, _party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        // Replace party 2's key with the identity point
        let identity_point = curve25519::GroupElement::neutral_from_public_parameters(
            &curve25519::PublicParameters::default(),
        )
        .unwrap();
        party_public_keys.insert(2, identity_point);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        let threshold: PartyID = 2; // Requires 2 parties, but only 1 is valid
                                    // Mark all parties as UC-verified (even party 2 with identity key)
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Dealing should fail because threshold exceeds valid parties
        let result = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        );

        assert!(
            matches!(result, Err(e) if matches!(e.kind, ErrorKind::InvalidParameters)),
            "Should fail when identity point exclusion makes threshold impossible"
        );
    }

    #[test]
    fn test_identity_ephemeral_key_detected_via_accusation() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 1;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let mut dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        let victim_party_id: PartyID = 2;

        // Tamper with ephemeral key for victim party - set it to identity
        if let Some(encrypted) = dealer_output
            .message
            .encrypted_shares
            .get_mut(&victim_party_id)
        {
            encrypted.set_ephemeral_key_to_identity_for_testing();
        }

        // Get the victim's keys and the tampered encrypted shares
        let victim_secret_key = party_secret_keys.get(&victim_party_id).unwrap();
        let victim_public_key = party_public_keys.get(&victim_party_id).unwrap();
        let encrypted_shares = dealer_output
            .message
            .encrypted_shares
            .get(&victim_party_id)
            .unwrap();

        // The victim should be able to generate an accusation
        let accusation = verify_shares_or_accuse_dealer::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            victim_party_id,
            encrypted_shares,
            &dealer_output.message.coefficient_commitments,
            victim_secret_key,
            victim_public_key,
            dealer_party_id,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            1, // number_of_shares
            &mut rng,
        );

        // Verify the accusation is IdentityEphemeralKey
        assert!(
            matches!(accusation, Some(Accusation::IdentityEphemeralKey)),
            "Accusation should be IdentityEphemeralKey for identity ephemeral key"
        );

        // Verify the accusation to confirm dealer is malicious
        let accusation = accusation.unwrap();
        let verification_result =
            verify_accusation::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, _>(
                victim_party_id,
                &accusation,
                victim_public_key,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                dealer_party_id,
                &protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                1, // number_of_shares
            );

        assert!(
            verification_result,
            "Accusation verification should confirm dealer is malicious"
        );
    }

    #[test]
    fn test_invalid_share_fails_verification() {
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, _party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Create an invalid share value
        let invalid_share = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng)
            .unwrap()
            .value();

        // Verification should fail (use first secret's commitments)
        let result = verify_share::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
            1,
            invalid_share,
            &dealer_output.message.coefficient_commitments[0],
            &group_params,
            &scalar_group_public_parameters,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_one() {
        // With threshold = 1, any single share reveals the secret
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 1;

        let (secret_key, public_key) = encryption::generate_encryption_keypair(&mut rng).unwrap();
        let party_public_keys: HashMap<PartyID, EncryptionPublicKey> =
            HashMap::from([(1, public_key)]);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // Mark party 1 as UC-verified
        let parties_with_uc_verified_public_keys: HashSet<PartyID> = HashSet::from([1]);
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // With threshold = 1, there's only one commitment per secret (to the secret itself)
        // and each share equals the secret
        assert_eq!(dealer_output.message.coefficient_commitments.len(), 1); // One secret
        assert_eq!(dealer_output.message.coefficient_commitments[0].len(), 1); // One coefficient (threshold=1)

        let encrypted_shares = dealer_output.message.encrypted_shares.get(&1).unwrap();
        let number_of_shares = dealer_output.message.coefficient_commitments.len();
        let share_values =
            decrypt_and_verify_shares::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, _>(
                1,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                &secret_key,
                &public_key,
                dealer_party_id,
                &protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                number_of_shares,
            )
            .unwrap();

        // With t=1, the share equals the secret
        assert_eq!(share_values.len(), 1);
        assert_eq!(share_values[0], secret.value());
    }

    #[test]
    fn test_share_verification_mathematical_correctness() {
        // This test verifies the mathematical property:
        // share * G == sum(j^k * C_k) for k in [0, t-1]
        //
        // For a polynomial f(X) = a_0 + a_1*X + ... + a_{t-1}*X^{t-1}
        // and share s_j = f(j), we have:
        // s_j * G = f(j) * G = sum(a_k * j^k) * G = sum(j^k * a_k * G) = sum(j^k * C_k)

        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        let threshold = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3, 4, 5];

        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Verify each share
        let number_of_shares = dealer_output.message.coefficient_commitments.len();
        for &party_id in &party_ids {
            let encrypted_shares = dealer_output
                .message
                .encrypted_shares
                .get(&party_id)
                .unwrap();
            let party_secret_key = party_secret_keys.get(&party_id).unwrap();
            let party_public_key = party_public_keys.get(&party_id).unwrap();

            // This should succeed for all parties
            let _verified_shares = decrypt_and_verify_shares::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                _,
            >(
                party_id,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                party_secret_key,
                party_public_key,
                dealer_party_id,
                &protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                number_of_shares,
            )
            .unwrap_or_else(|_| panic!("Share verification should succeed for party {party_id}"));
        }
    }

    #[test]
    fn test_multiple_secrets() {
        // Test dealing multiple secrets at once
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        // Sample two secrets
        let secret1 = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let secret2 = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret1, secret2], // Two secrets
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Check structure
        assert_eq!(dealer_output.message.coefficient_commitments.len(), 2); // Two secrets

        // Verify each party can decrypt and verify both shares
        let number_of_shares = dealer_output.message.coefficient_commitments.len();
        for &party_id in &party_ids {
            let party_secret_key = party_secret_keys.get(&party_id).unwrap();
            let party_public_key = party_public_keys.get(&party_id).unwrap();
            let encrypted_shares = dealer_output
                .message
                .encrypted_shares
                .get(&party_id)
                .unwrap();
            let share_values = decrypt_and_verify_shares::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                _,
            >(
                party_id,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                party_secret_key,
                party_public_key,
                dealer_party_id,
                &protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                number_of_shares,
            )
            .unwrap();

            // Should have two share values
            assert_eq!(share_values.len(), 2);
        }

        // C_0 of first secret should be secret1 * G
        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_params).unwrap();
        assert_eq!(
            dealer_output.message.coefficient_commitments[0][0],
            generator.scale_by(&secret1, &group_params).value()
        );
        // C_0 of second secret should be secret2 * G
        assert_eq!(
            dealer_output.message.coefficient_commitments[1][0],
            generator.scale_by(&secret2, &group_params).value()
        );
    }

    #[test]
    fn test_malicious_dealer_detected_via_accusation() {
        // Test: A malicious dealer tampers with the ciphertext.
        // The recipient cannot decrypt, generates an accusation.
        // Verifier uses the accusation to determine the dealer is malicious.
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let mut dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Malicious dealer: tamper with party 1's ciphertext
        let target_party: PartyID = 1;
        dealer_output
            .message
            .encrypted_shares
            .get_mut(&target_party)
            .unwrap()
            .tamper_ciphertext_for_testing();

        // Party 1 tries to decrypt and fails
        let party_secret_key = party_secret_keys.get(&target_party).unwrap();
        let party_public_key = party_public_keys.get(&target_party).unwrap();
        let encrypted_shares = dealer_output
            .message
            .encrypted_shares
            .get(&target_party)
            .unwrap();
        let number_of_shares = dealer_output.message.coefficient_commitments.len();

        let decrypt_result =
            decrypt_and_verify_shares::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, _>(
                target_party,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                party_secret_key,
                party_public_key,
                dealer_party_id,
                &protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                number_of_shares,
            );

        // Decryption should fail because ciphertext is tampered
        assert!(decrypt_result.is_err());

        // Party 1 generates an accusation (needs ProtocolContextWithPartyID internally)
        let dealer_context_for_accusation = ProtocolContextWithPartyID {
            party_id: dealer_party_id,
            protocol_context,
        };
        let accusation = encryption::generate_accusation(
            party_secret_key,
            encrypted_shares,
            &dealer_context_for_accusation,
            &mut rng,
        )
        .unwrap();

        // Verifier checks the accusation
        let accusation_is_valid =
            verify_accusation::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, _>(
                target_party,
                &accusation,
                party_public_key,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                dealer_party_id,
                &dealer_context_for_accusation.protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                number_of_shares,
            );

        // Accusation should be valid because:
        // 1. discrete log equality proof is correct (party 1 is honest about the shared secret)
        // 2. Decryption fails (dealer tampered with ciphertext)
        assert!(
            accusation_is_valid,
            "Accusation should be valid - dealer is malicious"
        );
    }

    #[test]
    fn test_malicious_accuser_detected_via_false_accusation() {
        // Test: A malicious accuser creates a fake accusation with wrong shared secret.
        // The discrete log equality proof won't verify, identifying the accuser as malicious.
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Malicious party 1 tries to frame the dealer with a fake accusation
        let malicious_party: PartyID = 1;
        let malicious_party_secret_key = party_secret_keys.get(&malicious_party).unwrap();
        let _malicious_party_public_key = party_public_keys.get(&malicious_party).unwrap();
        let encrypted_shares = dealer_output
            .message
            .encrypted_shares
            .get(&malicious_party)
            .unwrap();

        // Generate a legitimate accusation first (needs ProtocolContextWithPartyID internally)
        let dealer_context_for_accusation = ProtocolContextWithPartyID {
            party_id: dealer_party_id,
            protocol_context,
        };
        let real_accusation = encryption::generate_accusation(
            malicious_party_secret_key,
            encrypted_shares,
            &dealer_context_for_accusation,
            &mut rng,
        )
        .unwrap();

        // Verifier checks with a WRONG public key (simulating the accuser lying about identity)
        // This tests what happens when someone presents an accusation but their public key
        // doesn't match (meaning they're trying to frame someone)
        let wrong_public_key = party_public_keys.get(&2).unwrap(); // Use party 2's key
        let number_of_shares = dealer_output.message.coefficient_commitments.len();

        let accusation_is_valid =
            verify_accusation::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, _>(
                malicious_party,
                &real_accusation,
                wrong_public_key, // Wrong public key!
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                dealer_party_id,
                &dealer_context_for_accusation.protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                number_of_shares,
            );

        // Accusation should be INVALID because the discrete log equality proof is for malicious_party's key,
        // not for wrong_public_key
        assert!(
            !accusation_is_valid,
            "Accusation should be invalid - accuser is lying about their identity"
        );
    }

    #[test]
    fn test_honest_accusation_against_correct_dealer_rejected() {
        // Test: An honest recipient accuses an honest dealer (shares are valid).
        // The accusation should be rejected because decryption succeeds and shares verify.
        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties = 3;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let secret = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let dealer_party_id: PartyID = 0;
        let protocol_context = PhantomData::<()>;
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();
        let dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            dealer_party_id,
            &[secret],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Party 1 generates an accusation even though dealer is honest
        let target_party: PartyID = 1;
        let party_secret_key = party_secret_keys.get(&target_party).unwrap();
        let party_public_key = party_public_keys.get(&target_party).unwrap();
        let encrypted_shares = dealer_output
            .message
            .encrypted_shares
            .get(&target_party)
            .unwrap();
        let number_of_shares = dealer_output.message.coefficient_commitments.len();

        // generate_accusation needs ProtocolContextWithPartyID internally
        let dealer_context_for_accusation = ProtocolContextWithPartyID {
            party_id: dealer_party_id,
            protocol_context,
        };
        let accusation = encryption::generate_accusation(
            party_secret_key,
            encrypted_shares,
            &dealer_context_for_accusation,
            &mut rng,
        )
        .unwrap();

        // Verifier checks the accusation
        let accusation_is_valid =
            verify_accusation::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, _>(
                target_party,
                &accusation,
                party_public_key,
                encrypted_shares,
                &dealer_output.message.coefficient_commitments,
                dealer_party_id,
                &dealer_context_for_accusation.protocol_context,
                &group_params,
                &scalar_group_public_parameters,
                number_of_shares,
            );

        // Accusation should be INVALID because:
        // 1. discrete log equality proof is valid
        // 2. Decryption succeeds
        // 3. Shares verify against commitments
        // Therefore the accuser is just making a false accusation
        assert!(
            !accusation_is_valid,
            "Accusation should be invalid - dealer is honest"
        );
    }

    #[test]
    fn test_protocol_completes_despite_malicious_dealer() {
        // Test: One dealer is malicious but there are enough honest dealers.
        // The protocol should complete successfully, identifying the malicious dealer.
        use crate::WeightedThresholdAccessStructure;

        let mut rng = OsCsRng;
        let group_params = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let threshold: PartyID = 2;
        let num_parties: PartyID = 4;
        let party_ids: Vec<PartyID> = (1..=num_parties).collect();

        let (party_public_keys, party_secret_keys) = generate_party_keys(&party_ids, &mut rng);

        let protocol_context = group_params.clone();
        // All parties are UC-verified for this test
        let parties_with_uc_verified_public_keys: HashSet<PartyID> =
            party_ids.iter().copied().collect();

        // Three dealers: party 1 (honest), party 2 (honest), party 3 (malicious)
        // Party 4 is just a participant (not a dealer)
        let honest_dealer1_id: PartyID = 1;
        let honest_dealer2_id: PartyID = 2;
        let malicious_dealer_party_id: PartyID = 3;

        let secret1 = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let secret2 = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let secret3 = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // First honest dealer deals correctly
        let honest_dealer1_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            honest_dealer1_id,
            &[secret1],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Second honest dealer deals correctly
        let honest_dealer2_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            honest_dealer2_id,
            &[secret2],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Malicious dealer deals and then tampers
        let mut malicious_dealer_output = deal_verifiable_secret_shares::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            malicious_dealer_party_id,
            &[secret3],
            threshold,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Malicious dealer tampers with party 4's share
        let target_party: PartyID = 4;
        malicious_dealer_output
            .message
            .encrypted_shares
            .get_mut(&target_party)
            .unwrap()
            .tamper_ciphertext_for_testing();

        // Build dealing messages
        let mut dealing_messages = HashMap::new();
        dealing_messages.insert(
            honest_dealer1_id,
            DealingMessage {
                encrypted_shares: honest_dealer1_output.message.encrypted_shares,
                coefficient_commitments: honest_dealer1_output.message.coefficient_commitments,
                knowledge_of_free_coefficients_proof: honest_dealer1_output
                    .message
                    .knowledge_of_free_coefficients_proof,
            },
        );
        dealing_messages.insert(
            honest_dealer2_id,
            DealingMessage {
                encrypted_shares: honest_dealer2_output.message.encrypted_shares,
                coefficient_commitments: honest_dealer2_output.message.coefficient_commitments,
                knowledge_of_free_coefficients_proof: honest_dealer2_output
                    .message
                    .knowledge_of_free_coefficients_proof,
            },
        );
        dealing_messages.insert(
            malicious_dealer_party_id,
            DealingMessage {
                encrypted_shares: malicious_dealer_output.message.encrypted_shares,
                coefficient_commitments: malicious_dealer_output.message.coefficient_commitments,
                knowledge_of_free_coefficients_proof: malicious_dealer_output
                    .message
                    .knowledge_of_free_coefficients_proof,
            },
        );

        // Party 4 tries to decrypt malicious dealer's share and fails
        let party4_secret_key = party_secret_keys.get(&target_party).unwrap();
        let party4_public_key = party_public_keys.get(&target_party).unwrap();
        let number_of_shares = dealing_messages
            .get(&malicious_dealer_party_id)
            .unwrap()
            .coefficient_commitments
            .len();

        let accusation = verify_shares_or_accuse_dealer::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            target_party,
            dealing_messages
                .get(&malicious_dealer_party_id)
                .unwrap()
                .encrypted_shares
                .get(&target_party)
                .unwrap(),
            &dealing_messages
                .get(&malicious_dealer_party_id)
                .unwrap()
                .coefficient_commitments,
            party4_secret_key,
            party4_public_key,
            malicious_dealer_party_id,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            number_of_shares,
            &mut rng,
        );

        // Party 4 should have generated an accusation
        assert!(
            accusation.is_some(),
            "Party 4 should generate accusation against malicious dealer"
        );

        // Build accusations map
        let mut accusations: HashMap<PartyID, HashMap<PartyID, encryption::Accusation<_>>> =
            HashMap::new();
        let mut party4_accusations = HashMap::new();
        party4_accusations.insert(malicious_dealer_party_id, accusation.unwrap());
        accusations.insert(target_party, party4_accusations);

        // Create access structure for threshold signature
        // Each party has weight 1, threshold is 2
        let party_to_weight: HashMap<PartyID, crate::Weight> =
            party_ids.iter().map(|&id| (id, 1)).collect();
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        // Run aggregation for party 1 (who doesn't have issues with either dealer)
        let party1_id: PartyID = 1;
        let party1_secret_key = party_secret_keys.get(&party1_id).unwrap();
        let party1_public_key = party_public_keys.get(&party1_id).unwrap();

        let result = aggregate_shares_with_blending::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            _,
        >(
            party1_id,
            party1_secret_key,
            party1_public_key,
            &dealing_messages,
            &accusations,
            &protocol_context,
            &group_params,
            &scalar_group_public_parameters,
            &party_public_keys,
            &parties_with_uc_verified_public_keys,
            &access_structure,
            1, // Expected number of secrets
            &mut rng,
        );

        // Protocol should complete
        assert!(
            result.is_ok(),
            "Protocol should complete successfully: {:?}",
            result.err()
        );

        let output = result.unwrap();

        // Malicious dealer should be identified
        assert!(
            output
                .malicious_parties
                .contains(&malicious_dealer_party_id),
            "Malicious dealer should be identified"
        );

        // Both honest dealers should NOT be in malicious set
        assert!(
            !output.malicious_parties.contains(&honest_dealer1_id),
            "Honest dealer 1 should not be marked malicious"
        );
        assert!(
            !output.malicious_parties.contains(&honest_dealer2_id),
            "Honest dealer 2 should not be marked malicious"
        );

        // Should have blended outputs (from honest dealers only)
        assert_eq!(output.blended_private_shares.len(), 1);
        assert_eq!(output.blended_public_values.len(), 1);
    }

    // ==================== Lagrange Interpolation Tests ====================

    /// Test that Lagrange coefficients sum to 1 (fundamental property).
    /// sum_{j in S} lambda_j = 1 for any subset S of size >= threshold.
    #[test]
    fn test_lagrange_coefficients_sum_to_one() {
        use crypto_bigint::Uint;

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        // Test with various party ID sets
        let test_cases: Vec<Vec<PartyID>> = vec![
            vec![1, 2, 3],
            vec![1, 2, 3, 4, 5],
            vec![5, 10, 15, 20, 25],          // Non-consecutive
            vec![1, 3, 7, 15, 31],            // Sparse
            vec![42, 43, 44, 45, 46, 47, 48], // Starting from middle
            (1..=67).collect(),               // Large threshold
        ];

        for party_ids in test_cases {
            let one = secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(1u64));

            let sum: secp256k1::Scalar = party_ids
                .iter()
                .map(|&party_id| {
                    compute_lagrange_coefficient::<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar>(
                        party_id, &party_ids,
                    )
                    .unwrap()
                })
                .fold(
                    secp256k1::Scalar::neutral_from_public_parameters(
                        &scalar_group_public_parameters,
                    )
                    .unwrap(),
                    |acc, coeff| acc + coeff,
                );

            assert_eq!(
                sum.value(),
                one.value(),
                "Lagrange coefficients should sum to 1 for party_ids {party_ids:?}"
            );
        }
    }

    /// Test Lagrange interpolation reconstructs a constant polynomial.
    #[test]
    fn test_lagrange_interpolate_constant_polynomial() {
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        let test_cases: Vec<Vec<PartyID>> =
            vec![vec![1, 2, 3], vec![5, 10, 15, 20, 25], (1..=20).collect()];

        for party_ids in test_cases {
            let threshold = party_ids.len() as PartyID;
            let constant =
                secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

            // All shares are the same constant
            let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> =
                party_ids.iter().map(|&id| (id, constant.value())).collect();

            let reconstructed = lagrange_interpolate_at_zero::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
            >(&shares, threshold, &scalar_group_public_parameters)
            .unwrap();

            assert_eq!(
                reconstructed,
                constant.value(),
                "Interpolating constant should return the constant for {party_ids:?}"
            );
        }
    }

    /// Test Lagrange interpolation reconstructs a linear polynomial f(x) = a + bx at x=0.
    #[test]
    fn test_lagrange_interpolate_linear_polynomial() {
        use crypto_bigint::Uint;

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        let test_cases: Vec<Vec<PartyID>> =
            vec![vec![1, 2, 3], vec![5, 10, 15], vec![100, 101, 102]];

        for party_ids in test_cases {
            let threshold = party_ids.len() as PartyID;

            // f(x) = a + b*x
            let a = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
            let b = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

            let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> = party_ids
                .iter()
                .map(|&id| {
                    let x = secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(
                        id as u64,
                    ));
                    let f_x = a + b * x;
                    (id, f_x.value())
                })
                .collect();

            let reconstructed = lagrange_interpolate_at_zero::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
            >(&shares, threshold, &scalar_group_public_parameters)
            .unwrap();

            assert_eq!(
                reconstructed,
                a.value(),
                "f(0) should equal constant term 'a' for {party_ids:?}"
            );
        }
    }

    /// Test Lagrange interpolation with higher degree polynomials.
    #[test]
    fn test_lagrange_interpolate_higher_degree_polynomial() {
        use crypto_bigint::Uint;

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        // Degree 9 polynomial requires 10 points
        let party_ids: Vec<PartyID> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let threshold = 10;

        // Sample random coefficients for f(x) = a_0 + a_1*x + ... + a_9*x^9
        let coefficients: Vec<secp256k1::Scalar> = (0..10)
            .map(|_| secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap())
            .collect();

        // Evaluate polynomial at each party ID
        let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> = party_ids
            .iter()
            .map(|&id| {
                let x =
                    secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(id as u64));
                let mut f_x = secp256k1::Scalar::neutral_from_public_parameters(
                    &scalar_group_public_parameters,
                )
                .unwrap();
                let mut x_power =
                    secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(1u64));

                for coeff in &coefficients {
                    f_x += *coeff * x_power;
                    x_power = x_power * x;
                }
                (id, f_x.value())
            })
            .collect();

        let reconstructed = lagrange_interpolate_at_zero::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
        >(&shares, threshold, &scalar_group_public_parameters)
        .unwrap();

        // f(0) = a_0 (the constant term)
        assert_eq!(
            reconstructed,
            coefficients[0].value(),
            "f(0) should equal the constant term"
        );
    }

    /// Test Lagrange interpolation with large threshold (t=67).
    #[test]
    fn test_lagrange_interpolate_large_threshold() {
        use crypto_bigint::Uint;

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        let threshold: PartyID = 67;
        let party_ids: Vec<PartyID> = (1..=67).collect();

        // Simple linear polynomial f(x) = a + b*x
        let a = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let b = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> = party_ids
            .iter()
            .map(|&id| {
                let x =
                    secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(id as u64));
                let f_x = a + b * x;
                (id, f_x.value())
            })
            .collect();

        let reconstructed = lagrange_interpolate_at_zero::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
        >(&shares, threshold, &scalar_group_public_parameters)
        .unwrap();

        assert_eq!(reconstructed, a.value(), "f(0) should equal 'a' for t=67");
    }

    /// Test Lagrange interpolation with non-consecutive party IDs.
    #[test]
    fn test_lagrange_interpolate_non_consecutive_ids() {
        use crypto_bigint::Uint;

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        // Arbitrary non-consecutive IDs
        let party_ids: Vec<PartyID> = vec![3, 7, 15, 22, 41, 56, 78, 91, 100];
        let threshold = party_ids.len() as PartyID;

        let a = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let b = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> = party_ids
            .iter()
            .map(|&id| {
                let x =
                    secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(id as u64));
                let f_x = a + b * x;
                (id, f_x.value())
            })
            .collect();

        let reconstructed = lagrange_interpolate_at_zero::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
        >(&shares, threshold, &scalar_group_public_parameters)
        .unwrap();

        assert_eq!(
            reconstructed,
            a.value(),
            "f(0) should equal 'a' for non-consecutive IDs"
        );
    }

    /// Test Lagrange interpolation with ristretto curve.
    #[test]
    fn test_lagrange_interpolate_ristretto() {
        use crypto_bigint::Uint;
        use group::ristretto;

        let scalar_group_public_parameters = ristretto::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        let party_ids: Vec<PartyID> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let threshold = party_ids.len() as PartyID;

        let a = ristretto::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let b = ristretto::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let shares: HashMap<PartyID, group::Value<ristretto::Scalar>> = party_ids
            .iter()
            .map(|&id| {
                let x =
                    ristretto::Scalar::from(Uint::<{ ristretto::SCALAR_LIMBS }>::from(id as u64));
                let f_x = a + b * x;
                (id, f_x.value())
            })
            .collect();

        let reconstructed = lagrange_interpolate_at_zero::<
            { ristretto::SCALAR_LIMBS },
            ristretto::Scalar,
        >(&shares, threshold, &scalar_group_public_parameters)
        .unwrap();

        assert_eq!(
            reconstructed,
            a.value(),
            "f(0) should equal 'a' for ristretto"
        );
    }

    /// Test Lagrange interpolation with curve25519.
    #[test]
    fn test_lagrange_interpolate_curve25519() {
        use crypto_bigint::Uint;

        let scalar_group_public_parameters = curve25519::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        let party_ids: Vec<PartyID> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let threshold = party_ids.len() as PartyID;

        let a = curve25519::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let b = curve25519::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        let shares: HashMap<PartyID, group::Value<curve25519::Scalar>> = party_ids
            .iter()
            .map(|&id| {
                let x =
                    curve25519::Scalar::from(Uint::<{ curve25519::SCALAR_LIMBS }>::from(id as u64));
                let f_x = a + b * x;
                (id, f_x.value())
            })
            .collect();

        let reconstructed = lagrange_interpolate_at_zero::<
            { curve25519::SCALAR_LIMBS },
            curve25519::Scalar,
        >(&shares, threshold, &scalar_group_public_parameters)
        .unwrap();

        assert_eq!(
            reconstructed,
            a.value(),
            "f(0) should equal 'a' for curve25519"
        );
    }

    /// Test that wrong number of shares returns error.
    #[test]
    fn test_lagrange_interpolate_wrong_share_count() {
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        let threshold: PartyID = 5;
        // Only provide 3 shares when threshold is 5
        let party_ids: Vec<PartyID> = vec![1, 2, 3];

        let constant =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> =
            party_ids.iter().map(|&id| (id, constant.value())).collect();

        let result = lagrange_interpolate_at_zero::<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar>(
            &shares,
            threshold,
            &scalar_group_public_parameters,
        );

        assert!(
            result.is_err(),
            "Should fail when shares.len() != threshold"
        );
    }
}
