// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Share Encryption for VSS
//!
//! This module provides share-specific encryption/decryption operations for VSS,
//! built on top of the generic HPKE module.
//!
//! Shares are serialized using BCS before encryption and deserialized after decryption.

use crate::{hybrid_public_key_encryption, Error, ErrorKind, Result};
use group::GroupElement as GroupElementTrait;
use serde::Serialize;
use std::fmt::Debug;

pub use hybrid_public_key_encryption::{
    encryption_public_key_from_secret, generate_and_uc_prove_encryption_keypair,
    generate_encryption_keypair, generate_encryption_secret_key,
    verify_uc_proofs_of_knowledge_of_encryption_secret_keys, Accusation,
    AccusationDecryptionResult, DiffieHellmanSharedSecret, EncryptedData, EncryptionPublicKey,
    EncryptionSecretKey, EphemeralPublicKey, KnowledgeOfDecryptionKeyUCProof,
    ProofOfCorrectDiffieHellmanSharedSecretComputation, ProtocolContextWithPartyID,
};

/// Encrypted shares using hybrid encryption.
///
/// This is a type alias for the generic encrypted data type.
pub type EncryptedShares = EncryptedData;

/// The result of decrypting an accusation for shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SharesAccusationDecryptionResult<ShareValue> {
    /// The proof verified and shares were successfully decrypted.
    /// Caller must verify shares against commitments to validate accusation.
    Decrypted(Vec<ShareValue>),
    /// The proof verified but decryption failed (dealer malicious).
    DecryptionFailed,
    /// The dealer sent an invalid ephemeral key (identity or torsion).
    /// The dealer is malicious.
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
    /// The proof verification failed (accuser malicious).
    WrongDiffieHellmanSharedSecret,
}

/// Encrypts multiple share values for a recipient.
pub fn encrypt_shares<ShareScalar, ProtocolContext>(
    shares: &[ShareScalar],
    recipient_public_key: EncryptionPublicKey,
    protocol_context: &ProtocolContextWithPartyID<ProtocolContext>,
    rng: &mut impl group::CsRng,
) -> Result<EncryptedShares>
where
    ShareScalar: GroupElementTrait,
    ShareScalar::Value: Serialize,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Serialize,
{
    if shares.is_empty() {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Serialize share values using BCS
    let share_values: Vec<_> = shares.iter().map(|share| share.value()).collect();
    let plaintext =
        bcs::to_bytes(&share_values).map_err(|_| Error::from(ErrorKind::InternalError))?;

    // Encrypt using the generic HPKE module
    hybrid_public_key_encryption::encrypt(&plaintext, recipient_public_key, protocol_context, rng)
}

/// Decrypts shares for a recipient.
pub fn decrypt_shares<ShareScalar, ProtocolContext>(
    encrypted_shares: &EncryptedShares,
    recipient_secret_key: EncryptionSecretKey,
    recipient_public_key: EncryptionPublicKey,
    dealer_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<Vec<ShareScalar::Value>>
where
    ShareScalar: GroupElementTrait,
    ShareScalar::Value: for<'de> serde::Deserialize<'de>,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Serialize,
{
    // Decrypt using the generic HPKE module
    let plaintext = hybrid_public_key_encryption::decrypt(
        encrypted_shares,
        recipient_secret_key,
        recipient_public_key,
        dealer_context,
    )?;

    // Deserialize share values using BCS
    bcs::from_bytes(&plaintext).map_err(|_| Error::from(ErrorKind::InvalidParameters))
}

/// Decrypts shares using a Diffie-Hellman shared secret (for accusation verification).
pub fn decrypt_shares_with_shared_secret<ShareScalar, ProtocolContext>(
    encrypted_shares: &EncryptedShares,
    dh_shared_secret: DiffieHellmanSharedSecret,
    recipient_public_key: EncryptionPublicKey,
    dealer_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> Result<Vec<ShareScalar::Value>>
where
    ShareScalar: GroupElementTrait,
    ShareScalar::Value: for<'de> serde::Deserialize<'de>,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Serialize,
{
    // Decrypt using the generic HPKE module
    let plaintext = hybrid_public_key_encryption::decrypt_with_shared_secret(
        encrypted_shares,
        dh_shared_secret,
        recipient_public_key,
        dealer_context,
    )?;

    // Deserialize share values using BCS
    bcs::from_bytes(&plaintext).map_err(|_| Error::from(ErrorKind::InvalidParameters))
}

/// Generate an accusation for invalid shares.
pub fn generate_accusation<ProtocolContext>(
    recipient_secret_key: &EncryptionSecretKey,
    encrypted_shares: &EncryptedShares,
    dealer_context: &ProtocolContextWithPartyID<ProtocolContext>,
    rng: &mut impl group::CsRng,
) -> Result<Accusation<ProtocolContext>>
where
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    hybrid_public_key_encryption::generate_accusation(
        recipient_secret_key,
        encrypted_shares,
        dealer_context,
        rng,
    )
}

/// Verify an accusation and attempt to decrypt shares.
pub fn verify_accusation_and_decrypt<ShareScalar, ProtocolContext>(
    accusation: &Accusation<ProtocolContext>,
    accuser_public_key: &EncryptionPublicKey,
    encrypted_shares: &EncryptedShares,
    dealer_context: &ProtocolContextWithPartyID<ProtocolContext>,
) -> SharesAccusationDecryptionResult<ShareScalar::Value>
where
    ShareScalar: GroupElementTrait,
    ShareScalar::Value: for<'de> serde::Deserialize<'de>,
    ProtocolContext: Clone + Debug + PartialEq + Eq + Send + Sync + Serialize,
{
    match hybrid_public_key_encryption::verify_accusation_and_decrypt(
        accusation,
        accuser_public_key,
        encrypted_shares,
        dealer_context,
    ) {
        AccusationDecryptionResult::Decrypted(plaintext) => {
            // Try to deserialize the shares
            match bcs::from_bytes::<Vec<ShareScalar::Value>>(&plaintext) {
                Ok(shares) => SharesAccusationDecryptionResult::Decrypted(shares),
                Err(_) => SharesAccusationDecryptionResult::DecryptionFailed,
            }
        }
        AccusationDecryptionResult::DecryptionFailed => {
            SharesAccusationDecryptionResult::DecryptionFailed
        }
        AccusationDecryptionResult::InvalidEphemeralKey => {
            SharesAccusationDecryptionResult::InvalidEphemeralKey
        }
        AccusationDecryptionResult::FalseIdentityAccusation => {
            SharesAccusationDecryptionResult::FalseIdentityAccusation
        }
        AccusationDecryptionResult::FalseTorsionAccusation => {
            SharesAccusationDecryptionResult::FalseTorsionAccusation
        }
        AccusationDecryptionResult::InvalidAccuserPublicKey => {
            SharesAccusationDecryptionResult::InvalidAccuserPublicKey
        }
        AccusationDecryptionResult::FalseEncryptedDataAccusation => {
            SharesAccusationDecryptionResult::WrongDiffieHellmanSharedSecret
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{secp256k1, OsCsRng, Samplable};
    use std::marker::PhantomData;

    /// Test protocol context type.
    type TestProtocolContext = PhantomData<()>;

    /// Helper to create a test dealer context
    fn test_dealer_context(
        dealer_party_id: group::PartyID,
    ) -> ProtocolContextWithPartyID<TestProtocolContext> {
        ProtocolContextWithPartyID {
            party_id: dealer_party_id,
            protocol_context: PhantomData,
        }
    }

    #[test]
    fn test_encrypt_decrypt_single_share_roundtrip() {
        let mut rng = OsCsRng;
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let ctx = test_dealer_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let share_value = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();

        let encrypted =
            encrypt_shares::<_, _>(&[share_value], recipient_public, &ctx, &mut rng).unwrap();

        let decrypted: Vec<group::Value<secp256k1::Scalar>> =
            decrypt_shares::<secp256k1::Scalar, _>(
                &encrypted,
                recipient_secret,
                recipient_public,
                &ctx,
            )
            .unwrap();

        assert_eq!(decrypted.len(), 1);
        assert_eq!(share_value.value(), decrypted[0]);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_shares_roundtrip() {
        let mut rng = OsCsRng;
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let ctx = test_dealer_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let share1 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();
        let share2 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();
        let share3 = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();

        let encrypted =
            encrypt_shares::<_, _>(&[share1, share2, share3], recipient_public, &ctx, &mut rng)
                .unwrap();

        let decrypted: Vec<group::Value<secp256k1::Scalar>> =
            decrypt_shares::<secp256k1::Scalar, _>(
                &encrypted,
                recipient_secret,
                recipient_public,
                &ctx,
            )
            .unwrap();

        assert_eq!(decrypted.len(), 3);
        assert_eq!(share1.value(), decrypted[0]);
        assert_eq!(share2.value(), decrypted[1]);
        assert_eq!(share3.value(), decrypted[2]);
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut rng = OsCsRng;
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let ctx = test_dealer_context(1);

        let (_recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();
        let (wrong_secret, wrong_public) = generate_encryption_keypair(&mut rng).unwrap();

        let share_value = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();

        let encrypted =
            encrypt_shares::<_, _>(&[share_value], recipient_public, &ctx, &mut rng).unwrap();

        let result =
            decrypt_shares::<secp256k1::Scalar, _>(&encrypted, wrong_secret, wrong_public, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut rng = OsCsRng;
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let ctx = test_dealer_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let share_value = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();

        let mut encrypted =
            encrypt_shares::<_, _>(&[share_value], recipient_public, &ctx, &mut rng).unwrap();

        encrypted.tamper_ciphertext_for_testing();

        let result = decrypt_shares::<secp256k1::Scalar, _>(
            &encrypted,
            recipient_secret,
            recipient_public,
            &ctx,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_accusation_valid() {
        let mut rng = OsCsRng;
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let ctx = test_dealer_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let share_value = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();

        let encrypted =
            encrypt_shares::<_, _>(&[share_value], recipient_public, &ctx, &mut rng).unwrap();

        // Generate accusation
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();

        // Verify and decrypt
        let result = verify_accusation_and_decrypt::<secp256k1::Scalar, _>(
            &accusation,
            &recipient_public,
            &encrypted,
            &ctx,
        );

        match result {
            SharesAccusationDecryptionResult::Decrypted(decrypted) => {
                assert_eq!(decrypted.len(), 1);
                assert_eq!(share_value.value(), decrypted[0]);
            }
            _ => panic!("Expected Decrypted"),
        }
    }

    #[test]
    fn test_accusation_tampered_ciphertext_fails_decryption() {
        let mut rng = OsCsRng;
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let ctx = test_dealer_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let share_value = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();

        let mut encrypted =
            encrypt_shares::<_, _>(&[share_value], recipient_public, &ctx, &mut rng).unwrap();

        // Generate accusation BEFORE tampering
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();

        // Tamper with ciphertext
        encrypted.tamper_ciphertext_for_testing();

        let result = verify_accusation_and_decrypt::<secp256k1::Scalar, _>(
            &accusation,
            &recipient_public,
            &encrypted,
            &ctx,
        );

        assert!(matches!(
            result,
            SharesAccusationDecryptionResult::DecryptionFailed
        ));
    }

    #[test]
    fn test_accusation_wrong_accuser_public_key_fails() {
        let mut rng = OsCsRng;
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let ctx = test_dealer_context(1);

        let (recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();
        let (_, wrong_public) = generate_encryption_keypair(&mut rng).unwrap();

        let share_value = secp256k1::Scalar::sample(&scalar_public_parameters, &mut rng).unwrap();

        let encrypted =
            encrypt_shares::<_, _>(&[share_value], recipient_public, &ctx, &mut rng).unwrap();

        // Generate accusation with correct key
        let accusation =
            generate_accusation(&recipient_secret, &encrypted, &ctx, &mut rng).unwrap();

        // Verify with wrong public key should fail
        let result = verify_accusation_and_decrypt::<secp256k1::Scalar, _>(
            &accusation,
            &wrong_public,
            &encrypted,
            &ctx,
        );

        assert!(matches!(
            result,
            SharesAccusationDecryptionResult::WrongDiffieHellmanSharedSecret
        ));
    }

    #[test]
    fn test_empty_shares_fails() {
        let mut rng = OsCsRng;
        let ctx = test_dealer_context(1);

        let (_recipient_secret, recipient_public) = generate_encryption_keypair(&mut rng).unwrap();

        let result = encrypt_shares::<secp256k1::Scalar, _>(&[], recipient_public, &ctx, &mut rng);
        assert!(result.is_err());
    }
}
