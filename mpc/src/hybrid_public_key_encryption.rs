// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # HPKE Encryption with Discrete Log Equality Proof-based Accusations
//!
//! This module implements hybrid encryption using Curve25519 (Edwards form)
//! with HKDF-SHA256 + AES-256-GCM, following RFC 9180 HPKE construction.
//!
//! ## Accusation Mechanism
//!
//! When a recipient detects invalid data from a sender, they can accuse the sender by revealing:
//! 1. The raw Diffie-Hellman shared secret (before key derivation)
//! 2. A discrete log equality proof proving the shared secret is correct
//!
//! The discrete log equality proof proves: log_G(recipient_public_key) = log_ephemeral_public_key(shared_secret)
//! This ensures the accuser cannot lie about the shared secret.
//!
//! Verifiers can then:
//! 1. Verify the discrete log equality proof
//! 2. Derive the AEAD key from the shared secret
//! 3. Decrypt and verify the data
//!
//! If decryption fails (invalid AEAD tag), the sender is proven malicious.

use crate::{Error, ErrorKind, Result};
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::EdwardsPoint;
use group::{curve25519, CyclicGroupElement, GroupElement as GroupElementTrait, Samplable};
use hpke::{
    aead::{AeadCtxR, AeadCtxS, AesGcm256},
    kdf::{kem_derive_shared_secret, HkdfSha256},
    kem::X25519HkdfSha256,
    setup_receiver_from_shared_secret, setup_sender_from_shared_secret,
    util::kem_suite_id,
    SharedSecret,
};
use maurer::equality_of_discrete_logs;
#[cfg(all(feature = "parallel", not(feature = "unsafe_mock")))]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;

/// Size of compressed Edwards point (32 bytes).
const COMPRESSED_POINT_SIZE: usize = 32;
/// Size of the shared secret from the KEM (Nsecret = 32 for X25519).
const KEM_SHARED_SECRET_SIZE: usize = 32;

/// HPKE AEAD sender context type (for encryption).
type HpkeAeadCtxS = AeadCtxS<AesGcm256, HkdfSha256, X25519HkdfSha256>;
/// HPKE AEAD receiver context type (for decryption).
type HpkeAeadCtxR = AeadCtxR<AesGcm256, HkdfSha256, X25519HkdfSha256>;

/// A wrapper around $ProtocolContext$ that includes the party id of the party sending the proof or encryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolContextWithPartyID<ProtocolContext> {
    /// The party ID $pid$ of the dealer or prover.
    pub party_id: group::PartyID,
    /// The underlying protocol context for domain separation.
    pub protocol_context: ProtocolContext,
}

/// The ephemeral public key type (Curve25519 group element).
pub type EphemeralPublicKey = curve25519::GroupElement;

/// The public key type for encryption (Curve25519 group element).
pub type EncryptionPublicKey = curve25519::GroupElement;

/// The secret key type for encryption (Curve25519 scalar).
pub type EncryptionSecretKey = curve25519::Scalar;

/// The raw Diffie-Hellman shared secret (Curve25519 group element).
///
/// This is the result of `recipient_secret_key * ephemeral_public_key` before any
/// key derivation is applied.
pub type DiffieHellmanSharedSecret = curve25519::GroupElement;

/// Proof of equality of discrete logs used to prove correct Diffie-Hellman shared secret computation.
///
/// Proves: log_G(recipient_public_key) = log_ephemeral_public_key(shared_secret)
///
/// Uses the Maurer equality_of_discrete_logs language with Curve25519.
/// BATCH_SIZE=2: bases are [G, ephemeral_public_key], statement is [recipient_public_key, shared_secret].
pub type ProofOfCorrectDiffieHellmanSharedSecretComputation<ProtocolContext> =
    equality_of_discrete_logs::Proof<
        2,
        curve25519::Scalar,
        curve25519::GroupElement,
        ProtocolContextWithPartyID<ProtocolContext>,
    >;

/// UC-secure (Fischlin) proof of knowledge of the discrete log of an encryption public key.
///
/// This proof demonstrates that a party knows their decryption key (encryption secret key), i.e.,
/// proves knowledge of `secret_key` such that `public_key = secret_key * G`.
///
/// Uses the Fischlin transform to make the proof UC-secure (extractable and simulatable).
pub type KnowledgeOfDecryptionKeyUCProof = maurer::fischlin::Proof<
    { maurer::UC_PROOFS_REPETITIONS },
    maurer::knowledge_of_discrete_log::FischlinLanguage<
        { maurer::UC_PROOFS_REPETITIONS },
        curve25519::Scalar,
        curve25519::GroupElement,
    >,
    std::marker::PhantomData<()>,
>;

/// Public parameters for the UC proof of knowledge of encryption secret key.
type KnowledgeOfDecryptionKeyUCPublicParameters =
    maurer::knowledge_of_discrete_log::PublicParameters<
        curve25519::scalar::PublicParameters,
        curve25519::PublicParameters,
        group::Value<curve25519::GroupElement>,
    >;

/// Builds the HPKE info bytes from the encryption context.
fn build_info<ProtocolContext: Serialize>(
    context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<Vec<u8>> {
    serde_json::to_string_pretty(context)
        .map(|s| s.into_bytes())
        .map_err(|_| Error::from(ErrorKind::InternalError))
}

/// Serializes a Curve25519 group element to compressed Edwards format (32 bytes).
fn curve25519_point_to_bytes(point: curve25519::GroupElement) -> [u8; COMPRESSED_POINT_SIZE] {
    EdwardsPoint::from(point).compress().to_bytes()
}

/// Builds the discrete log equality proof language parameters.
///
/// The bases are [G, ephemeral_public_key], binding the ephemeral key into the proof.
fn proof_of_correct_diffie_hellman_shared_secret_computation_language_public_parameters(
    ephemeral_public_key: &EncryptionPublicKey,
) -> Result<
    equality_of_discrete_logs::PublicParameters<
        2,
        curve25519::scalar::PublicParameters,
        curve25519::PublicParameters,
        curve25519::Value,
    >,
> {
    let group_public_parameters = curve25519::PublicParameters::default();
    let generator =
        curve25519::GroupElement::generator_from_public_parameters(&group_public_parameters)?;

    let scalar_group_public_parameters = curve25519::scalar::PublicParameters::default();
    Ok(equality_of_discrete_logs::PublicParameters::new::<
        curve25519::Scalar,
        curve25519::GroupElement,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        [generator.value(), ephemeral_public_key.value()],
        None,
    ))
}

/// An accusation against a dealer for sending invalid encrypted data.
///
/// There are three types of accusations:
/// 1. `InvalidEncryptedData`: The encrypted data is invalid (decryption fails). The accuser
///    reveals the DH shared secret with a proof of correct computation.
/// 2. `IdentityEphemeralKey`: The dealer sent the identity point as the ephemeral key.
/// 3. `TorsionEphemeralKey`: The dealer sent a torsion point (not in prime subgroup) as the
///    ephemeral key.
///
/// For `IdentityEphemeralKey` and `TorsionEphemeralKey`, no proof is needed because these
/// properties are publicly verifiable from the encrypted data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // InvalidEncryptedData needs to carry a proof, others don't
pub enum Accusation<ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize> {
    /// The encrypted data is invalid - reveal DH shared secret with proof.
    InvalidEncryptedData {
        /// The raw Diffie-Hellman shared secret (serializable Value type).
        diffie_hellman_shared_secret: curve25519::Value,
        /// The ZK proof that the shared secret is correctly computed.
        proof_of_correct_diffie_hellman_shared_secret_computation:
            ProofOfCorrectDiffieHellmanSharedSecretComputation<ProtocolContext>,
    },
    /// The dealer sent the identity point as the ephemeral key.
    /// This is publicly verifiable - no proof needed.
    IdentityEphemeralKey,
    /// The dealer sent a torsion point (not in prime subgroup) as the ephemeral key.
    /// This is publicly verifiable - no proof needed.
    TorsionEphemeralKey,
}

/// The result of decrypting an accusation.
///
/// This enum clearly differentiates between the possible outcomes,
/// avoiding error overloading which can be confusing and error-prone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccusationDecryptionResult {
    /// The discrete log equality proof verified and data was successfully decrypted.
    /// Contains the decrypted plaintext bytes that must be inspected by the caller
    /// to determine if the accusation is actually valid (e.g., in VSS, verify against
    /// polynomial coefficients).
    Decrypted(Vec<u8>),
    /// The discrete log equality proof verified but decryption failed.
    /// The sender is malicious - they sent an invalid ciphertext.
    DecryptionFailed,
    /// The accusation is valid - the dealer sent an invalid ephemeral key (identity or torsion).
    /// The sender is malicious.
    InvalidEphemeralKey,
    /// The accuser claimed the ephemeral key was identity, but it is not.
    /// The accuser is malicious.
    FalseIdentityAccusation,
    /// The accuser claimed the ephemeral key was a torsion point, but it is valid.
    /// The accuser is malicious.
    FalseTorsionAccusation,
    /// The accuser's public key is the identity point, which is invalid.
    /// The accuser is malicious.
    InvalidAccuserPublicKey,
    /// The accuser is malicious - they lied about the Diffie-Hellman shared secret,
    /// so the discrete log equality proof failed verification, or the accusation was of the wrong type.
    FalseEncryptedDataAccusation,
}

/// Generates a new random encryption keypair.
pub fn generate_encryption_keypair(
    rng: &mut impl group::CsRng,
) -> Result<(EncryptionSecretKey, EncryptionPublicKey)> {
    let sk = generate_encryption_secret_key(rng)?;
    let pk = encryption_public_key_from_secret(sk)?;

    Ok((sk, pk))
}

/// Generates a new random encryption secret key.
pub fn generate_encryption_secret_key(rng: &mut impl group::CsRng) -> Result<EncryptionSecretKey> {
    let scalar_group_public_parameters = curve25519::scalar::PublicParameters::default();
    let secret_key = curve25519::Scalar::sample(&scalar_group_public_parameters, rng)?;

    Ok(secret_key)
}

/// Derives the public key from a secret key.
pub fn encryption_public_key_from_secret(
    secret_key: EncryptionSecretKey,
) -> Result<EncryptionPublicKey> {
    let group_public_parameters = curve25519::PublicParameters::default();
    let generator =
        curve25519::GroupElement::generator_from_public_parameters(&group_public_parameters)?;

    Ok(secret_key * generator)
}

/// Encrypted data using hybrid encryption.
///
/// Contains arbitrary data encrypted in a single ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The ephemeral public key used for this encryption (serializable Value type).
    ephemeral_public_key: curve25519::Value,
    /// The ciphertext (plaintext encrypted + authentication tag).
    ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Get the ephemeral public key as a validated GroupElement.
    ///
    /// Returns `Err` if the ephemeral public key is not in the prime subgroup (torsion attack).
    pub fn ephemeral_public_key(&self) -> Result<curve25519::GroupElement> {
        let group_public_parameters = curve25519::PublicParameters::default();
        curve25519::GroupElement::new(self.ephemeral_public_key, &group_public_parameters)
            .map_err(|_| Error::from(ErrorKind::InvalidParameters))
    }

    /// Get the ephemeral public key as a raw Value without validation.
    ///
    /// Use this when you need to inspect the value before validation (e.g., for accusation
    /// verification). For normal decryption, use `ephemeral_public_key()` which validates.
    pub fn ephemeral_public_key_value(&self) -> curve25519::Value {
        self.ephemeral_public_key
    }

    /// Get a reference to the ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Tamper with the ciphertext for testing malicious sender behavior.
    #[cfg(any(test, feature = "test_helpers"))]
    pub fn tamper_ciphertext_for_testing(&mut self) {
        if !self.ciphertext.is_empty() {
            self.ciphertext[0] ^= 0xff;
        }
    }

    /// Set the ephemeral public key to identity for testing identity ephemeral key detection.
    #[cfg(any(test, feature = "test_helpers"))]
    pub fn set_ephemeral_key_to_identity_for_testing(&mut self) {
        let group_params = curve25519::PublicParameters::default();
        if let Ok(identity) =
            curve25519::GroupElement::neutral_from_public_parameters(&group_params)
        {
            self.ephemeral_public_key = identity.value();
        }
    }

    /// Set the ephemeral public key to a torsion point for testing torsion ephemeral key detection.
    #[cfg(any(test, feature = "test_helpers"))]
    pub fn set_ephemeral_key_to_torsion_for_testing(&mut self) {
        // Use a known torsion point of order 8 on Curve25519.
        // This is a generator of the small subgroup.
        // Source: https://ristretto.group/test_vectors/ristretto255.html
        let torsion_bytes: [u8; 32] = [
            199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250,
            44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
        ];
        self.ephemeral_public_key = curve25519::Value::from(
            curve25519_dalek::edwards::CompressedEdwardsY(torsion_bytes)
                .decompress()
                .unwrap(),
        );
    }
}

/// Derives the HPKE shared secret from a Diffie-Hellman shared secret.
///
/// This follows the HPKE KEM specification:
/// KEM's ExtractAndExpand(dh, kem_context) to get the shared secret
fn derive_hpke_shared_secret<ProtocolContext: Serialize>(
    dh_shared_secret: DiffieHellmanSharedSecret,
    ephemeral_public_key: EphemeralPublicKey,
    recipient_public_key: EncryptionPublicKey,
    protocol_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<(SharedSecret<X25519HkdfSha256>, Vec<u8>)> {
    // Serialize points to compressed Edwards format
    let dh_bytes = curve25519_point_to_bytes(dh_shared_secret);
    let enc_bytes = curve25519_point_to_bytes(ephemeral_public_key);
    let pk_r_bytes = curve25519_point_to_bytes(recipient_public_key);

    // Use hpke's kem_derive_shared_secret which handles kem_context construction
    let kem_suite_id = kem_suite_id::<X25519HkdfSha256>();
    let mut shared_secret_bytes = [0u8; KEM_SHARED_SECRET_SIZE];
    kem_derive_shared_secret::<HkdfSha256>(
        &dh_bytes,
        &kem_suite_id,
        &enc_bytes,
        &pk_r_bytes,
        &mut shared_secret_bytes,
    )
    .map_err(|_| Error::from(ErrorKind::InternalError))?;

    // Build info for domain separation
    let info = build_info(protocol_context)?;

    let shared_secret = SharedSecret::<X25519HkdfSha256>::from_bytes(&shared_secret_bytes)
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    Ok((shared_secret, info))
}

/// Derive AEAD sender context using RFC 9180 HPKE construction (for encryption).
fn derive_sender_aead_ctx<ProtocolContext: Serialize>(
    dh_shared_secret: DiffieHellmanSharedSecret,
    ephemeral_public_key: EphemeralPublicKey,
    recipient_public_key: EncryptionPublicKey,
    protocol_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<HpkeAeadCtxS> {
    let (shared_secret, info) = derive_hpke_shared_secret(
        dh_shared_secret,
        ephemeral_public_key,
        recipient_public_key,
        protocol_context,
    )?;

    Ok(setup_sender_from_shared_secret(shared_secret, &info))
}

/// Derive AEAD receiver context using RFC 9180 HPKE construction (for decryption).
fn derive_receiver_aead_ctx<ProtocolContext: Serialize>(
    dh_shared_secret: DiffieHellmanSharedSecret,
    ephemeral_public_key: EphemeralPublicKey,
    recipient_public_key: EncryptionPublicKey,
    protocol_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<HpkeAeadCtxR> {
    let (shared_secret, info) = derive_hpke_shared_secret(
        dh_shared_secret,
        ephemeral_public_key,
        recipient_public_key,
        protocol_context,
    )?;

    Ok(setup_receiver_from_shared_secret(shared_secret, &info))
}

/// Encrypts arbitrary bytes for a recipient.
pub fn encrypt<ProtocolContext>(
    plaintext: &[u8],
    recipient_public_key: EncryptionPublicKey,
    protocol_context: &ProtocolContextWithPartyID<ProtocolContext>,
    rng: &mut impl group::CsRng,
) -> Result<EncryptedData>
where
    ProtocolContext: Clone + Debug + PartialEq + Eq + Serialize,
{
    if plaintext.is_empty() {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // SECURITY: Reject identity point as public key to prevent trivial DH attack
    // where scalar * identity = identity for any scalar.
    if recipient_public_key.is_neutral().into() {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Generate ephemeral keypair
    let (ephemeral_secret_key, ephemeral_public_key) = generate_encryption_keypair(rng)?;

    // Compute Diffie-Hellman shared secret
    let dh_shared_secret = ephemeral_secret_key * recipient_public_key;

    // Derive AEAD sender context using RFC 9180 HPKE construction
    let mut aead_ctx = derive_sender_aead_ctx(
        dh_shared_secret,
        ephemeral_public_key,
        recipient_public_key,
        protocol_context,
    )?;

    // Encrypt using HPKE AEAD context (empty AAD)
    let ciphertext = aead_ctx
        .seal(plaintext, &[])
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    Ok(EncryptedData {
        ephemeral_public_key: ephemeral_public_key.value(),
        ciphertext,
    })
}

/// Decrypts data for a recipient.
///
/// If decryption fails, use `generate_accusation` to create
/// a proof of the sender's misbehavior.
///
/// # Errors
///
/// - `IdentityEphemeralKey`: The ephemeral key is the identity point.
/// - `TorsionEphemeralKey`: The ephemeral key is not in the prime subgroup.
/// - `DecryptionFailed`: The ciphertext is invalid (wrong AEAD tag).
pub fn decrypt<ProtocolContext>(
    encrypted_data: &EncryptedData,
    recipient_secret_key: EncryptionSecretKey,
    recipient_public_key: EncryptionPublicKey,
    sender_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<Vec<u8>>
where
    ProtocolContext: Clone + Debug + PartialEq + Eq + Serialize,
{
    // SECURITY: Validate ephemeral public key is in prime subgroup (torsion-free).
    // This prevents small-subgroup attacks where a malicious sender uses a torsion point.
    // Note: Identity was already checked above and would pass this check (it's in the prime subgroup).
    let ephemeral_public_key = encrypted_data
        .ephemeral_public_key()
        .map_err(|_| Error::from(ErrorKind::TorsionEphemeralKey))?;

    // SECURITY: Check if ephemeral key is identity point (before torsion check).
    if ephemeral_public_key.is_neutral().into() {
        return Err(Error::from(ErrorKind::IdentityEphemeralKey));
    }

    // Compute Diffie-Hellman shared secret
    let dh_shared_secret = recipient_secret_key * ephemeral_public_key;

    // Decrypt using the shared secret
    decrypt_with_shared_secret(
        encrypted_data,
        dh_shared_secret,
        recipient_public_key,
        sender_context,
    )
}

/// Decrypts data using a Diffie-Hellman shared secret (for accusation verification).
pub fn decrypt_with_shared_secret<ProtocolContext>(
    encrypted_data: &EncryptedData,
    dh_shared_secret: DiffieHellmanSharedSecret,
    recipient_public_key: EncryptionPublicKey,
    sender_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<Vec<u8>>
where
    ProtocolContext: Clone + Debug + PartialEq + Eq + Serialize,
{
    // Get ephemeral public key (validates it's in prime subgroup)
    let ephemeral_public_key = encrypted_data.ephemeral_public_key()?;

    // Derive AEAD receiver context using RFC 9180 HPKE construction
    let mut aead_ctx = derive_receiver_aead_ctx(
        dh_shared_secret,
        ephemeral_public_key,
        recipient_public_key,
        sender_context,
    )?;

    // Decrypt using HPKE AEAD context (empty AAD)
    aead_ctx
        .open(&encrypted_data.ciphertext, &[])
        .map_err(|_| Error::from(ErrorKind::DecryptionFailed))
}

/// Generate an accusation for invalid encrypted data.
///
/// This function determines the appropriate accusation type based on the issue:
/// - If the ephemeral key is identity: returns `Accusation::IdentityEphemeralKey`
/// - If the ephemeral key is a torsion point: returns `Accusation::TorsionEphemeralKey`
/// - Otherwise: generates a DH shared secret proof and returns `Accusation::InvalidEncryptedData`
///
/// Note: For identity/torsion accusations, the `recipient_secret_key` and `rng` are not used
/// since no proof is needed (these properties are publicly verifiable).
pub fn generate_accusation<ProtocolContext>(
    recipient_secret_key: &EncryptionSecretKey,
    encrypted_data: &EncryptedData,
    sender_context: &ProtocolContextWithPartyID<ProtocolContext>,
    rng: &mut impl group::CsRng,
) -> Result<Accusation<ProtocolContext>>
where
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    // Check for torsion ephemeral key (not in prime subgroup)
    let ephemeral_public_key = match encrypted_data.ephemeral_public_key() {
        Ok(pk) => pk,
        Err(_) => return Ok(Accusation::TorsionEphemeralKey),
    };

    // Check for identity ephemeral key
    if ephemeral_public_key.is_neutral().into() {
        return Ok(Accusation::IdentityEphemeralKey);
    }

    // Generate proof for InvalidEncryptedData accusation
    let shared_secret = *recipient_secret_key * ephemeral_public_key;

    let language_public_parameters =
        proof_of_correct_diffie_hellman_shared_secret_computation_language_public_parameters(
            &ephemeral_public_key,
        )?;

    let (proof_of_correct_diffie_hellman_shared_secret_computation, _) =
        ProofOfCorrectDiffieHellmanSharedSecretComputation::prove(
            sender_context,
            &language_public_parameters,
            vec![*recipient_secret_key],
            rng,
        )
        .map_err(|_| Error::from(ErrorKind::InternalError))?;

    Ok(Accusation::InvalidEncryptedData {
        diffie_hellman_shared_secret: shared_secret.value(),
        proof_of_correct_diffie_hellman_shared_secret_computation,
    })
}

/// Verify an accusation and attempt to decrypt.
///
/// Returns an `AccusationDecryptionResult` that clearly indicates which party is at fault:
/// - `Decrypted`: Proof verified, data decrypted (caller must inspect data to validate accusation)
/// - `DecryptionFailed`: Proof verified but decryption failed (sender malicious)
/// - `InvalidEphemeralKey`: Ephemeral key is identity or torsion (sender malicious)
/// - `FalseIdentityAccusation`: Accuser claimed identity ephemeral key but it's not (accuser malicious)
/// - `FalseTorsionAccusation`: Accuser claimed torsion ephemeral key but it's valid (accuser malicious)
/// - `InvalidAccuserPublicKey`: Accuser's public key is identity (accuser malicious)
/// - `WrongDiffieHellmanSharedSecret`: Proof verification failed (accuser malicious)
pub fn verify_accusation_and_decrypt<ProtocolContext>(
    accusation: &Accusation<ProtocolContext>,
    accuser_public_key: &EncryptionPublicKey,
    encrypted_data: &EncryptedData,
    sender_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> AccusationDecryptionResult
where
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    match accusation {
        Accusation::IdentityEphemeralKey => {
            // Verify that the ephemeral key is indeed identity - publicly verifiable
            let ephemeral_value = encrypted_data.ephemeral_public_key_value();
            let edwards_point: EdwardsPoint = ephemeral_value.into();
            if edwards_point.is_identity() {
                AccusationDecryptionResult::InvalidEphemeralKey
            } else {
                AccusationDecryptionResult::FalseIdentityAccusation
            }
        }
        Accusation::TorsionEphemeralKey => {
            // Check if it's a torsion point (ephemeral_public_key() will fail if torsion)
            match encrypted_data.ephemeral_public_key() {
                Ok(_) => {
                    // Ephemeral key is valid (torsion-free) - accusation is false
                    AccusationDecryptionResult::FalseTorsionAccusation
                }
                Err(_) => {
                    // Ephemeral key is indeed torsion - accusation is valid
                    AccusationDecryptionResult::InvalidEphemeralKey
                }
            }
        }
        Accusation::InvalidEncryptedData {
            diffie_hellman_shared_secret,
            proof_of_correct_diffie_hellman_shared_secret_computation,
        } => {
            // Get ephemeral public key (validates it's in prime subgroup)
            let ephemeral_public_key = match encrypted_data.ephemeral_public_key() {
                Ok(pk) => pk,
                Err(_) => return AccusationDecryptionResult::FalseEncryptedDataAccusation,
            };

            // SECURITY: Reject if accuser's public key is identity (can't have valid proof).
            if accuser_public_key.is_neutral().into() {
                return AccusationDecryptionResult::InvalidAccuserPublicKey;
            }

            // SECURITY: If ephemeral key is identity, accuser should have used IdentityEphemeralKey
            // accusation, not InvalidEncryptedData. This is a wrong accusation type.
            if ephemeral_public_key.is_neutral().into() {
                return AccusationDecryptionResult::FalseEncryptedDataAccusation;
            }

            // Validate the Diffie-Hellman shared secret is in the prime subgroup
            let group_public_parameters = curve25519::PublicParameters::default();
            let dh_shared_secret = match curve25519::GroupElement::new(
                *diffie_hellman_shared_secret,
                &group_public_parameters,
            ) {
                Ok(ss) => ss,
                Err(_) => return AccusationDecryptionResult::FalseEncryptedDataAccusation,
            };

            let language_public_parameters =
                match proof_of_correct_diffie_hellman_shared_secret_computation_language_public_parameters(
                    &ephemeral_public_key,
                ) {
                    Ok(language_public_parameters) => language_public_parameters,
                    Err(_) => return AccusationDecryptionResult::FalseEncryptedDataAccusation,
                };

            // Build statement: [accuser_public_key, shared_secret]
            let statement = match group::self_product::GroupElement::new(
                [accuser_public_key.value(), *diffie_hellman_shared_secret].into(),
                &group::self_product::PublicParameters::<2, _>::new(group_public_parameters),
            ) {
                Ok(statement) => statement,
                Err(_) => return AccusationDecryptionResult::FalseEncryptedDataAccusation,
            };

            // Verify discrete log equality proof - if invalid, accuser is lying
            if proof_of_correct_diffie_hellman_shared_secret_computation
                .verify(sender_context, &language_public_parameters, vec![statement])
                .is_err()
            {
                return AccusationDecryptionResult::FalseEncryptedDataAccusation;
            }

            // Discrete log equality verified - attempt decryption
            match decrypt_with_shared_secret(
                encrypted_data,
                dh_shared_secret,
                *accuser_public_key,
                sender_context,
            ) {
                Ok(plaintext) => AccusationDecryptionResult::Decrypted(plaintext),
                Err(_) => AccusationDecryptionResult::DecryptionFailed,
            }
        }
    }
}

/// Constructs public parameters for UC proof of knowledge of encryption secret key.
fn construct_uc_proof_of_knowledge_of_encryption_secret_key_public_parameters(
) -> Result<KnowledgeOfDecryptionKeyUCPublicParameters> {
    let group_public_parameters = curve25519::PublicParameters::default();
    let generator =
        curve25519::GroupElement::generator_from_public_parameters(&group_public_parameters)?;

    let scalar_group_public_parameters = curve25519::scalar::PublicParameters::default();
    Ok(maurer::knowledge_of_discrete_log::PublicParameters::new::<
        curve25519::Scalar,
        curve25519::GroupElement,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        generator.value(),
        None,
    ))
}

/// Generates an encryption keypair with a UC-secure proof of knowledge of the secret key.
///
/// This function generates a new random encryption keypair and produces a Fischlin
/// (UC-secure) proof that the prover knows the discrete log of the public key.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
///
/// A tuple containing:
/// - The encryption secret key
/// - The encryption public key
/// - A UC proof of knowledge of the secret key
pub fn generate_and_uc_prove_encryption_keypair(
    rng: &mut impl group::CsRng,
) -> Result<(
    EncryptionSecretKey,
    EncryptionPublicKey,
    KnowledgeOfDecryptionKeyUCProof,
)> {
    let secret_key = generate_encryption_secret_key(rng)?;

    let language_public_parameters =
        construct_uc_proof_of_knowledge_of_encryption_secret_key_public_parameters()?;

    let (proof, public_key) = KnowledgeOfDecryptionKeyUCProof::prove(
        &std::marker::PhantomData,
        &language_public_parameters,
        secret_key,
        rng,
    )
    .map_err(|_| Error::from(ErrorKind::InternalError))?;

    Ok((secret_key, public_key, proof))
}

/// INSECURE mock twin gated by `unsafe_mock`. Returns every party as verified
/// without checking any UC proof, because the mock uses default proofs that real
/// verification rejects. The untouched production definition is directly below.
#[cfg(feature = "unsafe_mock")]
pub fn verify_uc_proofs_of_knowledge_of_encryption_secret_keys(
    party_encryption_keys_and_proofs: &std::collections::HashMap<
        group::PartyID,
        (EncryptionPublicKey, KnowledgeOfDecryptionKeyUCProof),
    >,
) -> Result<HashSet<group::PartyID>> {
    Ok(party_encryption_keys_and_proofs.keys().copied().collect())
}

/// Verifies UC proofs of knowledge of encryption secret keys for multiple parties.
///
/// This function verifies that each party in the provided map knows the discrete log
/// of their claimed encryption public key.
///
/// # Arguments
///
/// * `party_encryption_keys_and_proofs` - A map from party IDs to (public key, UC proof) pairs
///
/// # Returns
///
/// * `parties_with_uc_verified_public_keys` - Set of party IDs whose UC ZK-proofs of knowledge
///   of the decryption key for their encryption keys have been verified.
#[cfg(not(feature = "unsafe_mock"))]
pub fn verify_uc_proofs_of_knowledge_of_encryption_secret_keys(
    party_encryption_keys_and_proofs: &std::collections::HashMap<
        group::PartyID,
        (EncryptionPublicKey, KnowledgeOfDecryptionKeyUCProof),
    >,
) -> Result<HashSet<group::PartyID>> {
    let language_public_parameters =
        construct_uc_proof_of_knowledge_of_encryption_secret_key_public_parameters()?;

    #[cfg(feature = "parallel")]
    let parties_iter = party_encryption_keys_and_proofs.par_iter();
    #[cfg(not(feature = "parallel"))]
    let parties_iter = party_encryption_keys_and_proofs.iter();

    let parties_with_uc_verified_public_keys = parties_iter
        .filter_map(|(&party_id, (public_key, proof))| {
            // Verify the UC proof
            let verification_result = proof.verify(
                &std::marker::PhantomData,
                &language_public_parameters,
                *public_key,
            );

            if verification_result.is_ok() {
                Some(party_id)
            } else {
                None
            }
        })
        .collect();

    Ok(parties_with_uc_verified_public_keys)
}

/// Parses each party's serialized Curve25519 encryption public key and verifies its
/// UC proof of knowledge of the matching secret key, returning only the parties that
/// pass both checks.
///
/// A party is included in the result only if its serialized value deserializes into a
/// valid (torsion-free) group element AND its UC proof verifies against that key. Any
/// party that fails either check is silently dropped — never an error. This is
/// deliberate: the inputs come from mutually distrusting parties, so a single
/// malformed or unprovable submission must not fail the operation for everyone; it
/// only excludes the offending party. Because the result already contains exactly the
/// verified parties, the caller obtains the verified party-ID set as the map's keys.
///
/// The only `Err` returned is for a genuine internal failure constructing the proof
/// public parameters, never for bad per-party input.
///
/// # Arguments
///
/// * `party_encryption_key_values_and_proofs` - map from party ID to that party's
///   serialized encryption public key value and its UC proof of knowledge.
///
/// # Returns
///
/// A map from party ID to verified encryption public key, containing only the parties
/// whose key parsed and whose proof verified.
pub fn parse_and_uc_verify_encryption_keys(
    party_encryption_key_values_and_proofs: &std::collections::HashMap<
        group::PartyID,
        (curve25519::Value, KnowledgeOfDecryptionKeyUCProof),
    >,
) -> Result<std::collections::HashMap<group::PartyID, EncryptionPublicKey>> {
    let public_parameters = curve25519::PublicParameters::default();

    let parsed_keys_and_proofs: std::collections::HashMap<
        group::PartyID,
        (EncryptionPublicKey, KnowledgeOfDecryptionKeyUCProof),
    > = party_encryption_key_values_and_proofs
        .iter()
        .filter_map(|(&party_id, (encryption_key_value, proof))| {
            EncryptionPublicKey::new(*encryption_key_value, &public_parameters)
                .ok()
                .map(|encryption_key| (party_id, (encryption_key, proof.clone())))
        })
        .collect();

    let parties_with_uc_verified_public_keys =
        verify_uc_proofs_of_knowledge_of_encryption_secret_keys(&parsed_keys_and_proofs)?;

    let verified_encryption_keys = parsed_keys_and_proofs
        .into_iter()
        .filter(|(party_id, _)| parties_with_uc_verified_public_keys.contains(party_id))
        .map(|(party_id, (encryption_key, _proof))| (party_id, encryption_key))
        .collect();

    Ok(verified_encryption_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::OsCsRng;
    use std::marker::PhantomData;

    /// Test protocol context type.
    type TestProtocolContext = PhantomData<()>;

    /// Helper to create a test sender context
    fn test_sender_context(
        sender_id: group::PartyID,
    ) -> ProtocolContextWithPartyID<TestProtocolContext> {
        ProtocolContextWithPartyID {
            party_id: sender_id,
            protocol_context: PhantomData,
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Hello, HPKE!";

        let encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        let decrypted = decrypt(&encrypted, recipient_secret, recipient_public, &ctx).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let encrypted = encrypt(&plaintext, recipient_public, &ctx, &mut rng).unwrap();

        let decrypted = decrypt(&encrypted, recipient_secret, recipient_public, &ctx).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (_recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();
        let (wrong_secret, wrong_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";

        let encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        let result = decrypt(&encrypted, wrong_secret, wrong_public, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";

        let mut encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();
        encrypted.tamper_ciphertext_for_testing();

        let result = decrypt(&encrypted, recipient_secret, recipient_public, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_accusation_valid() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";

        let encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Generate accusation
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();

        // Verify and decrypt
        let result =
            verify_accusation_and_decrypt(&accusation, &recipient_public, &encrypted, &ctx);

        match result {
            AccusationDecryptionResult::Decrypted(decrypted) => {
                assert_eq!(&decrypted[..], plaintext);
            }
            _ => panic!("Expected Decrypted"),
        }
    }

    #[test]
    fn test_accusation_tampered_ciphertext_fails_decryption() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";

        let mut encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Generate accusation BEFORE tampering
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();

        // Tamper with ciphertext (simulating malicious sender)
        encrypted.tamper_ciphertext_for_testing();

        // Discrete log equality proof is still valid but decryption fails
        let result =
            verify_accusation_and_decrypt(&accusation, &recipient_public, &encrypted, &ctx);

        assert!(matches!(
            result,
            AccusationDecryptionResult::DecryptionFailed
        ));
    }

    #[test]
    fn test_accusation_wrong_accuser_public_key_fails() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();
        let (_, wrong_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";

        let encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Generate accusation with correct key
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();

        // Verify with wrong public key should fail
        let result = verify_accusation_and_decrypt(&accusation, &wrong_public, &encrypted, &ctx);

        assert!(matches!(
            result,
            AccusationDecryptionResult::FalseEncryptedDataAccusation
        ));
    }

    #[test]
    fn test_empty_plaintext_fails() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        let (_recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let result = encrypt(&[], recipient_public, &ctx, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation_consistency() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(42);

        // Generate keys
        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();
        let (ephemeral_secret, ephemeral_public) = generate_encryption_keypair(&mut rng).unwrap();

        // Compute Diffie-Hellman shared secret from both sides
        let dh_sender = ephemeral_secret * recipient_public;
        let dh_recipient = recipient_secret * ephemeral_public;

        assert_eq!(
            dh_sender.value(),
            dh_recipient.value(),
            "Diffie-Hellman shared secret should be the same from both sides"
        );

        // Derive sender context and encrypt
        let mut sender_ctx =
            derive_sender_aead_ctx(dh_sender, ephemeral_public, recipient_public, &ctx).unwrap();

        let plaintext = b"test message";
        let ciphertext = sender_ctx.seal(plaintext, &[]).unwrap();

        // Derive receiver context and decrypt
        let mut receiver_ctx =
            derive_receiver_aead_ctx(dh_recipient, ephemeral_public, recipient_public, &ctx)
                .unwrap();

        let decrypted = receiver_ctx.open(&ciphertext, &[]).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_identity_public_key_rejected() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        // Create identity point as public key using the GroupElement trait
        let group_params = curve25519::PublicParameters::default();
        let identity_public_key =
            curve25519::GroupElement::neutral_from_public_parameters(&group_params).unwrap();

        let plaintext = b"Secret message";

        // SECURITY: Encrypting to identity public key should fail
        let result = encrypt(plaintext, identity_public_key, &ctx, &mut rng);
        assert!(
            result.is_err(),
            "Encryption to identity public key should be rejected"
        );
    }

    #[test]
    fn test_identity_ephemeral_key_rejected() {
        let ctx = test_sender_context(1);

        let mut rng = OsCsRng;
        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        // Create identity point using the GroupElement trait
        let group_params = curve25519::PublicParameters::default();
        let identity_ephemeral =
            curve25519::GroupElement::neutral_from_public_parameters(&group_params).unwrap();

        // Create malicious encrypted data with identity as ephemeral public key
        let malicious_encrypted = EncryptedData {
            ephemeral_public_key: identity_ephemeral.value(),
            ciphertext: vec![0u8; 32], // Dummy ciphertext
        };

        // SECURITY: Decrypting with identity ephemeral key should fail with specific error
        let result = decrypt(
            &malicious_encrypted,
            recipient_secret,
            recipient_public,
            &ctx,
        );
        assert!(
            matches!(result, Err(e) if matches!(e.kind, ErrorKind::IdentityEphemeralKey)),
            "Decryption with identity ephemeral key should return IdentityEphemeralKey error"
        );
    }

    #[test]
    fn test_torsion_ephemeral_key_rejected() {
        let ctx = test_sender_context(1);

        let mut rng = OsCsRng;
        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";
        let mut encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Set ephemeral key to a torsion point
        encrypted.set_ephemeral_key_to_torsion_for_testing();

        // SECURITY: Decrypting with torsion ephemeral key should fail with specific error
        let result = decrypt(&encrypted, recipient_secret, recipient_public, &ctx);
        assert!(
            matches!(result, Err(e) if matches!(e.kind, ErrorKind::TorsionEphemeralKey)),
            "Decryption with torsion ephemeral key should return TorsionEphemeralKey error"
        );
    }

    #[test]
    fn test_identity_ephemeral_key_accusation() {
        let ctx = test_sender_context(1);

        let mut rng = OsCsRng;
        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";
        let mut encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Set ephemeral key to identity (simulating malicious sender)
        encrypted.set_ephemeral_key_to_identity_for_testing();

        // Generate accusation - should return IdentityEphemeralKey variant
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();
        assert!(
            matches!(accusation, Accusation::IdentityEphemeralKey),
            "Accusation for identity ephemeral key should be IdentityEphemeralKey variant"
        );

        // Verify accusation - should confirm sender is malicious
        let result =
            verify_accusation_and_decrypt(&accusation, &recipient_public, &encrypted, &ctx);
        assert!(
            matches!(result, AccusationDecryptionResult::InvalidEphemeralKey),
            "Verification should confirm identity ephemeral key is invalid"
        );
    }

    #[test]
    fn test_torsion_ephemeral_key_accusation() {
        let ctx = test_sender_context(1);

        let mut rng = OsCsRng;
        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";
        let mut encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Set ephemeral key to a torsion point (simulating malicious sender)
        encrypted.set_ephemeral_key_to_torsion_for_testing();

        // Generate accusation - should return TorsionEphemeralKey variant
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();
        assert!(
            matches!(accusation, Accusation::TorsionEphemeralKey),
            "Accusation for torsion ephemeral key should be TorsionEphemeralKey variant"
        );

        // Verify accusation - should confirm sender is malicious
        let result =
            verify_accusation_and_decrypt(&accusation, &recipient_public, &encrypted, &ctx);
        assert!(
            matches!(result, AccusationDecryptionResult::InvalidEphemeralKey),
            "Verification should confirm torsion ephemeral key is invalid"
        );
    }

    #[test]
    fn test_false_identity_accusation_rejected() {
        let ctx = test_sender_context(1);

        let mut rng = OsCsRng;
        let (_, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";
        let encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Try to falsely accuse sender of using identity ephemeral key
        let false_accusation: Accusation<PhantomData<()>> = Accusation::IdentityEphemeralKey;

        // Verification should reject the false accusation
        let result =
            verify_accusation_and_decrypt(&false_accusation, &recipient_public, &encrypted, &ctx);
        assert!(
            matches!(result, AccusationDecryptionResult::FalseIdentityAccusation),
            "False identity ephemeral key accusation should be rejected"
        );
    }

    #[test]
    fn test_false_torsion_accusation_rejected() {
        let ctx = test_sender_context(1);

        let mut rng = OsCsRng;
        let (_, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message";
        let encrypted = encrypt(plaintext, recipient_public, &ctx, &mut rng).unwrap();

        // Try to falsely accuse sender of using torsion ephemeral key
        let false_accusation: Accusation<PhantomData<()>> = Accusation::TorsionEphemeralKey;

        // Verification should reject the false accusation
        let result =
            verify_accusation_and_decrypt(&false_accusation, &recipient_public, &encrypted, &ctx);
        assert!(
            matches!(result, AccusationDecryptionResult::FalseTorsionAccusation),
            "False torsion ephemeral key accusation should be rejected"
        );
    }

    #[test]
    fn test_generate_keypair_with_uc_proof() {
        let mut rng = OsCsRng;

        let (secret_key, public_key, proof) =
            generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();

        // Verify that public key = secret_key * G
        let derived_public_key = encryption_public_key_from_secret(secret_key).unwrap();
        assert_eq!(
            public_key.value(),
            derived_public_key.value(),
            "Public key from proof should match derived public key"
        );

        // Verify the proof by calling the verification function
        let mut party_keys_and_proofs = std::collections::HashMap::new();
        party_keys_and_proofs.insert(1, (public_key, proof));

        let verified_parties =
            verify_uc_proofs_of_knowledge_of_encryption_secret_keys(&party_keys_and_proofs)
                .unwrap();

        assert!(
            verified_parties.contains(&1),
            "Valid proof should pass verification"
        );
    }

    #[test]
    fn test_verify_multiple_uc_proofs() {
        let mut rng = OsCsRng;

        // Generate keypairs with proofs for multiple parties
        let (_, pk_one, proof_one) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();
        let (_, pk_two, proof_two) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();
        let (_, pk_three, proof_three) =
            generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();

        let mut party_keys_and_proofs = std::collections::HashMap::new();
        party_keys_and_proofs.insert(1, (pk_one, proof_one));
        party_keys_and_proofs.insert(2, (pk_two, proof_two));
        party_keys_and_proofs.insert(3, (pk_three, proof_three));

        let verified_parties =
            verify_uc_proofs_of_knowledge_of_encryption_secret_keys(&party_keys_and_proofs)
                .unwrap();

        assert_eq!(
            verified_parties.len(),
            3,
            "All valid proofs should pass verification"
        );
        assert!(verified_parties.contains(&1));
        assert!(verified_parties.contains(&2));
        assert!(verified_parties.contains(&3));
    }

    #[test]
    fn test_detect_invalid_uc_proof() {
        let mut rng = OsCsRng;

        // Generate valid keypairs with proofs
        let (_, pk_one, proof_one) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();
        let (_, pk_two, proof_two) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();

        // Generate a keypair without proof for party 3, but use party 2's proof
        // (simulating a malicious party submitting wrong proof)
        let (_, pk_three, _) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();

        let mut party_keys_and_proofs = std::collections::HashMap::new();
        party_keys_and_proofs.insert(1, (pk_one, proof_one));
        party_keys_and_proofs.insert(2, (pk_two, proof_two.clone()));
        // Party 3 uses party 2's proof (should fail because proof is bound to pk_two)
        party_keys_and_proofs.insert(3, (pk_three, proof_two));

        let verified_parties =
            verify_uc_proofs_of_knowledge_of_encryption_secret_keys(&party_keys_and_proofs)
                .unwrap();

        assert!(
            !verified_parties.contains(&3),
            "Party with mismatched proof should not be verified"
        );
        assert!(
            verified_parties.contains(&1),
            "Party 1 with valid proof should be verified"
        );
        assert!(
            verified_parties.contains(&2),
            "Party 2 with valid proof should be verified"
        );
    }

    #[test]
    fn test_keypair_with_uc_proof_can_encrypt_decrypt() {
        let mut rng = OsCsRng;
        let ctx = test_sender_context(1);

        // Generate keypair with UC proof
        let (secret_key, public_key, _proof) =
            generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();

        // Verify the keypair works for encryption/decryption
        let plaintext = b"Test message for UC proof keypair";
        let encrypted = encrypt(plaintext, public_key, &ctx, &mut rng).unwrap();
        let decrypted = decrypt(&encrypted, secret_key, public_key, &ctx).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn parse_and_uc_verify_drops_only_bad_parties() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        let mut rng = OsCsRng;

        let (_, pk_one, proof_one) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();
        let (_, pk_two, proof_two) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();
        let (_, _pk_three, proof_three) =
            generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();

        // Party 3 submits a malformed (torsion, non-prime-order) key value: it cannot
        // be parsed into a valid group element.
        let torsion_value: curve25519::Value = EIGHT_TORSION[1].into();
        // Party 4 submits a well-formed key but party 2's proof, so its proof verifies
        // against the wrong key and fails.
        let (_, pk_four, _) = generate_and_uc_prove_encryption_keypair(&mut rng).unwrap();

        let party_encryption_key_values_and_proofs = std::collections::HashMap::from([
            (1u16, (pk_one.value(), proof_one)),
            (2u16, (pk_two.value(), proof_two.clone())),
            (3u16, (torsion_value, proof_three)),
            (4u16, (pk_four.value(), proof_two)),
        ]);

        let verified_encryption_keys =
            parse_and_uc_verify_encryption_keys(&party_encryption_key_values_and_proofs).unwrap();

        // A single malformed value (party 3) or wrong proof (party 4) excludes only that
        // party — the honest parties are unaffected (no network-wide hard failure).
        assert_eq!(
            verified_encryption_keys
                .keys()
                .copied()
                .collect::<HashSet<_>>(),
            HashSet::from([1u16, 2u16]),
        );
        assert_eq!(verified_encryption_keys.get(&1), Some(&pk_one));
        assert_eq!(verified_encryption_keys.get(&2), Some(&pk_two));
    }
}
