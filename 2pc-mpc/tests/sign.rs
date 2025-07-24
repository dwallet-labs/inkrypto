// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};
use std::ops::Neg;

use crypto_bigint::U256;
use tiny_keccak::{Hasher, Keccak};

use common::run_presign_protocol;
use common::{DecentralizedPartyContext, ProtocolContext};
use group::{OsCsRng, PartyID};
use mpc::two_party::Round;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable};
use twopc_mpc::class_groups::ProtocolPublicParameters;
use twopc_mpc::presign::decentralized_party::class_groups::asynchronous;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use twopc_mpc::secp256k1::GroupElement as SecpGroupElement;
use twopc_mpc::secp256k1::Scalar as SecpScalar;
use twopc_mpc::secp256k1::MESSAGE_LIMBS;
use twopc_mpc::secp256k1::SCALAR_LIMBS;
use twopc_mpc::sign::centralized_party::message::class_groups::Message as SignMessage;
use twopc_mpc::sign::centralized_party::signature_homomorphic_evaluation_round;
use twopc_mpc::sign::centralized_party::signature_homomorphic_evaluation_round::PublicInput as SignCentralizedPartyPublicInput;
use twopc_mpc::sign::decentralized_party::class_groups::asynchronous::Party as DecentralizedSignParty;

mod common;

// Type aliases to improve readability
type DecentralizedSignPartyType = DecentralizedSignParty<
    { SCALAR_LIMBS },
    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { MESSAGE_LIMBS },
    SecpGroupElement,
>;

type DecentralizedSignMessage = <DecentralizedSignPartyType as mpc::Party>::Message;
type DecentralizedSignOutput = <DecentralizedSignPartyType as mpc::Party>::PublicOutput;
type DecentralizedSignError = <DecentralizedSignPartyType as mpc::Party>::Error;

type SignCentralizedPartyType = signature_homomorphic_evaluation_round::Party<
    { SCALAR_LIMBS },
    { SCALAR_LIMBS },
    SecpGroupElement,
    ::class_groups::EncryptionKey<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
    twopc_mpc::sign::centralized_party::message::class_groups::Message<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { MESSAGE_LIMBS },
        SecpGroupElement,
    >,
    ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
>;

pub type PresignOutput = <asynchronous::Party<
    { SCALAR_LIMBS },
    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { MESSAGE_LIMBS },
    SecpGroupElement,
> as mpc::Party>::PublicOutput;

pub type ProtocolParams = ProtocolPublicParameters<
    { SCALAR_LIMBS },
    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    SecpGroupElement,
>;

/// Execute the sign protocol using the provided DKG and Presign outputs.
///
/// The protocol consists of two phases:
/// 1. Centralized party generates signature components
/// 2. Decentralized parties perform partial decryption and combine to create the final signature
///
/// # Arguments
///
/// * `rng` - Random number generator
/// * `protocol_context` - The protocol context containing all necessary information
/// * `hashed_message` - Hashed message to sign
///
/// # Returns
///
/// The final signature (r, s)
pub fn run_sign_protocol(
    rng: &mut OsCsRng,
    protocol_context: &mut ProtocolContext,
    hashed_message: SecpScalar,
) -> Result<(SecpScalar, SecpScalar), DecentralizedSignError> {
    println!("Starting Sign protocol...");

    // Phase 1: Centralized party generates signature components
    println!("Phase 1: Centralized party generating signature components");
    let sign_message = execute_sign_phase1(rng, protocol_context, &hashed_message)
        .expect("Sign Phase 1 should complete successfully");
    // Phase 2: Decentralized parties perform partial decryption and combine
    println!("Phase 2: Decentralized parties performing partial decryption");

    // Get participating party IDs from the protocol context
    let participating_party_ids: Vec<PartyID> = protocol_context
        .decentralized_parties
        .iter()
        .map(|party| party.id)
        .collect();

    let signature = execute_sign_phase2(
        rng,
        protocol_context,
        &sign_message,
        &hashed_message,
        &participating_party_ids,
    )
    .expect("Sign Phase 2 should complete successfully");

    println!("Sign protocol completed successfully");
    Ok(signature)
}

/// Execute Phase 1 of the sign protocol - Centralized party signature generation
///
/// # Returns
/// The signature message from the centralized party
pub fn execute_sign_phase1(
    rng: &mut OsCsRng,
    protocol_context: &mut ProtocolContext,
    hashed_message: &SecpScalar,
) -> Result<
    twopc_mpc::sign::centralized_party::message::class_groups::Message<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { MESSAGE_LIMBS },
        SecpGroupElement,
    >,
    DecentralizedSignError,
> {
    println!("Starting Sign Phase 1: Centralized party signature generation");
    println!("Hashed message to sign: {hashed_message:?}");

    // Get the centralized party DKG output
    let dkg_context = protocol_context
        .clone()
        .centralized_party
        .dkg_context
        .expect("Centralized party should have DKG output");
    println!("Retrieved DKG context for centralized party");
    println!("DKG public key: {:?}", dkg_context.dkg_public_key);

    // Get the presign output for the centralized party
    let presign_context = protocol_context
        .clone()
        .centralized_party
        .presign_context
        .expect("Centralized party should have presign output");
    println!("Retrieved presign context for centralized party");

    // Create public input for the centralized party
    let sign_centralized_party_public_input = SignCentralizedPartyPublicInput {
        hashed_message: *hashed_message,
        dkg_output: dkg_context.dkg_output,
        presign: presign_context.presign_output,
        protocol_public_parameters: protocol_context.protocol_public_parameters.clone(),
    };
    println!("Created public input for centralized party");

    // Use SignCentralizedParty trait methods to advance the party
    let private_input = dkg_context.dkg_centralized_party_private_key_share;
    println!("Retrieved private key share for centralized party");

    // Generate the signature message from the centralized party
    println!("Generating signature message...");
    let round_result = SignCentralizedPartyType::advance(
        (), // No incoming message
        &private_input,
        &sign_centralized_party_public_input,
        rng,
    )
    .expect("Centralized party should generate signature message");

    println!("✓ Centralized party successfully generated signature message");

    Ok(round_result.outgoing_message)
}

/// Execute Phase 2 of the sign protocol - Decentralized parties partial decryption
///
/// # Returns
/// The final signature (r, s)
fn execute_sign_phase2(
    rng: &mut OsCsRng,
    protocol_context: &mut ProtocolContext,
    sign_message: &twopc_mpc::sign::centralized_party::message::class_groups::Message<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { MESSAGE_LIMBS },
        SecpGroupElement,
    >,
    hashed_message: &SecpScalar,
    participating_party_ids: &[PartyID],
) -> Result<(SecpScalar, SecpScalar), DecentralizedSignError> {
    println!("Starting Sign Phase 2: Decentralized parties partial decryption");
    println!(
        "Number of participating parties: {}",
        participating_party_ids.len()
    );
    println!("Participating party IDs: {participating_party_ids:?}");

    // Initialize message storage for the decentralized parties
    let mut messages: Vec<HashMap<PartyID, DecentralizedSignMessage>> = vec![];

    // Round 1: Partial decryption by all parties
    println!("\nExecuting Round 1 - Partial Decryption");
    let round1_messages = execute_sign_round(
        rng,
        protocol_context,
        sign_message,
        hashed_message,
        participating_party_ids,
        &messages,
        "Round 1 - Partial Decryption",
    )
    .expect("Sign Round 1 should complete successfully");

    println!("✓ Round 1 completed successfully");
    println!("Number of messages collected: {}", round1_messages.len());
    messages.push(round1_messages);

    // Designated party finalizes the signature
    let designated_party_id = participating_party_ids[0];
    println!("\nStarting signature finalization");
    println!("Designated party ID for finalization: {designated_party_id}");

    // Find the party context for the designated party
    let party_context = protocol_context
        .decentralized_parties
        .iter()
        .find(|p| p.id == designated_party_id)
        .expect("Designated party should be in the protocol context");

    // Get DKG output for the designated party
    let dkg_output = party_context
        .dkg_context
        .as_ref()
        .expect("Designated party should have DKG output")
        .dkg_output
        .clone();

    // Get presign output for the designated party
    let presign_output = party_context
        .presign_context
        .as_ref()
        .expect("Designated party should have presign output")
        .presign_output
        .clone();

    // Create public input for the sign protocol
    let sign_public_input = twopc_mpc::sign::decentralized_party::PublicInput {
        hashed_message: *hashed_message,
        dkg_output,
        expected_decrypters: HashSet::from_iter(
            1..=party_context
                .initialization_context
                .access_structure
                .number_of_tangible_parties(),
        ),
        presign: presign_output,
        sign_message: sign_message.clone(),
        decryption_key_share_public_parameters: party_context
            .initialization_context
            .decryption_key_share_public_parameters
            .clone(),
        protocol_public_parameters: party_context
            .initialization_context
            .protocol_public_parameters
            .clone(),
    };

    // Get participating party IDs from the protocol context
    let virtual_party_id_to_decryption_key_share = party_context
        .initialization_context
        .virtual_party_id_to_decryption_key_share
        .clone();

    // Process round 1 messages and finalize
    let result = DecentralizedSignPartyType::advance(
        protocol_context.session_id,
        designated_party_id,
        &protocol_context.access_structure,
        messages.clone(),
        Some(virtual_party_id_to_decryption_key_share), // No private input for the final round
        &sign_public_input,
        HashMap::new(),
        rng,
    )
    .expect("Sign finalization should complete successfully");

    match result {
        AsynchronousRoundResult::Finalize {
            malicious_parties,
            private_output: _,
            public_output,
        } => {
            if malicious_parties.is_empty() {
                println!("✓ No malicious parties detected during finalization");
            } else {
                println!("! Warning: Malicious parties detected: {malicious_parties:?}");
            }
            println!("Signature components:");
            println!("  r: {:?}", public_output.0);
            println!("  s: {:?}", public_output.1);
            Ok(public_output)
        }
        _ => panic!("Expected Finalize result in Sign finalization"),
    }
}

/// Execute a single round of the sign protocol for all participating parties
///
/// # Returns
/// Map of party IDs to their generated messages for this round
fn execute_sign_round(
    rng: &mut OsCsRng,
    protocol_context: &mut ProtocolContext,
    sign_message: &twopc_mpc::sign::centralized_party::message::class_groups::Message<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { MESSAGE_LIMBS },
        SecpGroupElement,
    >,
    hashed_message: &SecpScalar,
    participating_party_ids: &[PartyID],
    messages: &[HashMap<PartyID, DecentralizedSignMessage>],
    round_name: &str,
) -> Result<HashMap<PartyID, DecentralizedSignMessage>, DecentralizedSignError> {
    let mut round_messages = HashMap::new();

    for &party_id in participating_party_ids {
        // Find the party context
        let party_context = protocol_context
            .decentralized_parties
            .iter()
            .find(|p| p.id == party_id)
            .expect("Party ID should be in the protocol context");

        let result = advance_sign_party(rng, party_context, messages, sign_message, hashed_message)
            .expect("Sign party should advance successfully");

        match result {
            AsynchronousRoundResult::Advance {
                message,
                malicious_parties,
            } => {
                assert!(
                    malicious_parties.is_empty(),
                    "No parties should be flagged as malicious in Sign {round_name}"
                );
                round_messages.insert(party_id, message);
            }
            _ => panic!("Expected Advance result in Sign {round_name}"),
        }
    }

    Ok(round_messages)
}

/// Advance a sign party with the given inputs
fn advance_sign_party(
    rng: &mut OsCsRng,
    party_context: &DecentralizedPartyContext,
    messages: &[HashMap<PartyID, DecentralizedSignMessage>],
    sign_message: &twopc_mpc::sign::centralized_party::message::class_groups::Message<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { MESSAGE_LIMBS },
        SecpGroupElement,
    >,
    hashed_message: &SecpScalar,
) -> Result<
    AsynchronousRoundResult<DecentralizedSignMessage, (), DecentralizedSignOutput>,
    DecentralizedSignError,
> {
    // Get DKG output for this party
    let dkg_output = party_context
        .dkg_context
        .as_ref()
        .expect("Participating party should have DKG output")
        .dkg_output
        .clone();

    // Get presign output for this party
    let presign_output = party_context
        .presign_context
        .as_ref()
        .expect("Participating party should have presign output")
        .presign_output
        .clone();

    // Create public input for the sign protocol
    let sign_public_input = twopc_mpc::sign::decentralized_party::PublicInput {
        hashed_message: *hashed_message,
        dkg_output,
        expected_decrypters: HashSet::from_iter(
            1..=party_context
                .initialization_context
                .access_structure
                .number_of_tangible_parties(),
        ),
        presign: presign_output,
        sign_message: sign_message.clone(),
        decryption_key_share_public_parameters: party_context
            .initialization_context
            .decryption_key_share_public_parameters
            .clone(),
        protocol_public_parameters: party_context
            .initialization_context
            .protocol_public_parameters
            .clone(),
    };

    let private_input = party_context
        .initialization_context
        .virtual_party_id_to_decryption_key_share
        .clone();

    DecentralizedSignPartyType::advance(
        party_context.initialization_context.session_id,
        party_context.id,
        &party_context.initialization_context.access_structure,
        messages.to_vec(),
        Some(private_input),
        &sign_public_input,
        HashMap::new(),
        rng,
    )
}

#[cfg(test)]
mod tests {
    use common::run_dkg_protocol;
    use group::{GroupElement, OsCsRng};

    use super::*;

    /// This test demonstrates the complete workflow:
    /// 1. First, the DKG protocol is executed to establish key shares
    /// 2. Then, the Presign protocol is executed among the same parties
    /// 3. Then, the Sign protocol is executed to create a signature
    ///
    /// The test uses a 2-out-of-3 threshold scheme.
    #[test]
    fn test_dkg_and_presign_and_sign() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;
        let session_id = 12345;

        // Set up protocol context
        let mut protocol_context = ProtocolContext::new(session_id, num_parties, threshold);

        println!("Starting DKG protocol...");

        // Execute the DKG protocol
        let dkg_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, None)
            .expect("DKG protocol should complete successfully");

        println!("DKG protocol completed. Proceeding to Presign protocol...");

        // Execute the Presign protocol
        let _presign_outputs = run_presign_protocol(&mut rng, &mut protocol_context, &dkg_outputs)
            .expect("Presign protocol should complete successfully");

        println!("Presign protocol completed. Proceeding to Sign protocol...");

        // Create a message to sign
        let message_to_hash = b"Hello, world!";
        let mut hasher = Keccak::v256();
        hasher.update(message_to_hash);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);

        let hashed_message: SecpScalar = U256::from_be_slice(&output).into();

        let signature = run_sign_protocol(&mut rng, &mut protocol_context, hashed_message)
            .expect("Sign protocol should complete successfully");

        println!("Sign protocol completed successfully");
        println!("Signature: r={:?}, s={:?}", signature.0, signature.1);

        // Add verification step
        let (r, s) = signature;
        let public_key_value = protocol_context
            .centralized_party
            .dkg_context
            .expect("DKG context should exist")
            .dkg_public_key;

        // Convert the public key Value to a GroupElement
        let public_key = SecpGroupElement::new(
            public_key_value,
            &protocol_context
                .protocol_public_parameters
                .group_public_parameters,
        )
        .expect("Should be able to create group element from public key value");

        // Verify the signature
        twopc_mpc::sign::verify_signature::<SCALAR_LIMBS, SecpGroupElement>(
            r,
            s,
            hashed_message,
            public_key,
        )
        .expect("Signature verification should succeed");

        println!("✓ Signature verified successfully");
    }

    /// This test verifies that tampered signatures are rejected:
    /// 1. Generate a valid signature through the normal protocol flow
    /// 2. Modify the signature components (r,s) in various ways
    /// 3. Verify that the modified signatures are rejected
    #[test]
    fn test_bad_signature_verification() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;
        let session_id = 12345;

        // Set up protocol context and run protocols to get a valid signature
        let mut protocol_context = ProtocolContext::new(session_id, num_parties, threshold);

        // Run DKG
        let dkg_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, None)
            .expect("DKG protocol should complete successfully");

        // Run Presign
        let _ = run_presign_protocol(&mut rng, &mut protocol_context, &dkg_outputs)
            .expect("Presign protocol should complete successfully");

        // Create and hash a message
        let message_to_hash = b"Hello, world!";
        let mut hasher = Keccak::v256();
        hasher.update(message_to_hash);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        let hashed_message: SecpScalar = U256::from_be_slice(&output).into();

        // Get valid signature
        let (valid_r, valid_s) = run_sign_protocol(&mut rng, &mut protocol_context, hashed_message)
            .expect("Sign protocol should complete successfully");

        // Get public key
        let public_key_value = protocol_context
            .centralized_party
            .dkg_context
            .expect("DKG context should exist")
            .dkg_public_key;
        let public_key = SecpGroupElement::new(
            public_key_value,
            &protocol_context
                .protocol_public_parameters
                .group_public_parameters,
        )
        .expect("Should be able to create group element from public key value");

        println!("Testing various signature tampering scenarios...");

        // Test 1: Modify r component
        let tampered_r = valid_r.neg();
        let result = twopc_mpc::sign::verify_signature::<SCALAR_LIMBS, SecpGroupElement>(
            tampered_r,
            valid_s,
            hashed_message,
            public_key,
        );
        assert!(
            result.is_err(),
            "Verification should fail with tampered r value"
        );
        println!("✓ Correctly rejected signature with tampered r value");

        // Test 2: Modify s component
        let tampered_s = valid_s.neg();
        let result = twopc_mpc::sign::verify_signature::<SCALAR_LIMBS, SecpGroupElement>(
            valid_r,
            tampered_s,
            hashed_message,
            public_key,
        );
        assert!(
            result.is_err(),
            "Verification should fail with tampered s value"
        );
        println!("✓ Correctly rejected signature with tampered s value");

        // Test 3: Modify both r and s components
        let result = twopc_mpc::sign::verify_signature::<SCALAR_LIMBS, SecpGroupElement>(
            tampered_r,
            tampered_s,
            hashed_message,
            public_key,
        );
        assert!(
            result.is_err(),
            "Verification should fail with both components tampered"
        );
        println!("✓ Correctly rejected signature with both components tampered");
    }

    /// This test verifies that signatures cannot be verified with incorrect public keys:
    /// 1. Generate a valid signature through the normal protocol flow
    /// 2. Generate a different key pair
    /// 3. Try to verify the signature with the wrong public key
    #[test]
    fn test_wrong_key_signature_verification() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;
        let session_id = 12345;

        // Set up protocol context and run protocols to get a valid signature
        let mut protocol_context = ProtocolContext::new(session_id, num_parties, threshold);

        // Run DKG
        let dkg_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, None)
            .expect("DKG protocol should complete successfully");

        // Run Presign
        let _ = run_presign_protocol(&mut rng, &mut protocol_context, &dkg_outputs)
            .expect("Presign protocol should complete successfully");

        // Create and hash a message
        let message_to_hash = b"Hello, world!";
        let mut hasher = Keccak::v256();
        hasher.update(message_to_hash);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        let hashed_message: SecpScalar = U256::from_be_slice(&output).into();

        // Get valid signature
        let (r, s) = run_sign_protocol(&mut rng, &mut protocol_context, hashed_message)
            .expect("Sign protocol should complete successfully");

        // Create a different protocol context to get a different public key
        let mut wrong_protocol_context =
            ProtocolContext::new(session_id + 1, num_parties, threshold);
        let _ = run_dkg_protocol(&mut rng, &mut wrong_protocol_context, None)
            .expect("Second DKG protocol should complete successfully");

        // Get the wrong public key
        let wrong_public_key_value = wrong_protocol_context
            .centralized_party
            .dkg_context
            .expect("DKG context should exist")
            .dkg_public_key;
        let wrong_public_key = SecpGroupElement::new(
            wrong_public_key_value,
            &wrong_protocol_context
                .protocol_public_parameters
                .group_public_parameters,
        )
        .expect("Should be able to create group element from wrong public key value");

        println!("Testing signature verification with wrong public key...");

        // Try to verify the signature with the wrong public key
        let result = twopc_mpc::sign::verify_signature::<SCALAR_LIMBS, SecpGroupElement>(
            r,
            s,
            hashed_message,
            wrong_public_key,
        );

        assert!(
            result.is_err(),
            "Verification should fail with wrong public key"
        );
        println!("✓ Correctly rejected signature verification with wrong public key");
    }

    #[test]
    fn test_sign_malicious_parameter_detection() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;

        // Create two protocol contexts - one honest, one malicious
        let mut honest_context = ProtocolContext::new(1234, num_parties, threshold);
        let mut malicious_context = ProtocolContext::new(5678, num_parties, threshold);

        // Run DKG for both contexts
        let honest_dkg_outputs = run_dkg_protocol(&mut rng, &mut honest_context, None)
            .expect("Honest DKG protocol should complete successfully");
        let malicious_dkg_outputs = run_dkg_protocol(&mut rng, &mut malicious_context, None)
            .expect("Malicious DKG protocol should complete successfully");

        // Run Presign for both contexts
        let _honest_presign_outputs =
            run_presign_protocol(&mut rng, &mut honest_context, &honest_dkg_outputs)
                .expect("Honest Presign protocol should complete successfully");
        let _malicious_presign_outputs =
            run_presign_protocol(&mut rng, &mut malicious_context, &malicious_dkg_outputs)
                .expect("Malicious Presign protocol should complete successfully");

        // Create a message to sign
        let message_to_hash = b"Test message for malicious parameter detection";
        let mut hasher = Keccak::v256();
        hasher.update(message_to_hash);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        let hashed_message: SecpScalar = U256::from_be_slice(&output).into();

        // Generate signature messages from both contexts
        let honest_sign_message =
            execute_sign_phase1(&mut rng, &mut honest_context, &hashed_message)
                .expect("Honest sign phase 1 should complete successfully");

        let malicious_sign_message =
            execute_sign_phase1(&mut rng, &mut malicious_context, &hashed_message)
                .expect("Malicious sign phase 1 should complete successfully");

        // List of parameters to test for malicious behavior
        let parameters = [
            // "beta_displacer",
            // "beta_displacer_commitment_randomness",
            // "alpha_displacer",
            // "alpha_displacer_commitment_randomness",
            // "first_coefficient",
            // "first_coefficient_commitment_randomness",
            // "second_coefficient",
            // "second_coefficient_commitment_randomness",
            "public_signature_nonce",
            "decentralized_party_nonce_public_share",
            "signature_nonce_share_commitment",
            "alpha_displacer_commitment",
            "beta_displacer_commitment",
            "signature_nonce_share_by_secret_share_commitment",
            // "encryption_of_masked_decentralized_party_nonce_share_before_displacing",
            "non_zero_commitment_to_signature_nonce_share_proof",
            "non_zero_commitment_to_alpha_displacer_share_proof",
            "commitment_to_beta_displacer_share_uc_proof",
            "proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments",
            "public_signature_nonce_proof",
            "decentralized_party_nonce_public_share_displacement_proof",
        ];

        for param_name in &parameters {
            println!("Testing malicious parameter: {param_name}");

            // Create a hybrid message with just one malicious parameter
            let hybrid_message = create_hybrid_sign_message(
                &honest_sign_message,
                &malicious_sign_message,
                param_name,
            );

            // Test if the malicious parameter is detected
            let detected = test_malicious_parameter_detection(
                &mut rng,
                &honest_context,
                &hybrid_message,
                &hashed_message,
            );

            assert!(
                detected,
                "Malicious parameter '{param_name}' should have been detected"
            );

            println!("✓ Successfully detected malicious {param_name}");
        }
    }

    // Create a hybrid sign message with only one parameter being malicious
    fn create_hybrid_sign_message(
        honest_message: &SignMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            SecpGroupElement,
        >,
        malicious_message: &SignMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            SecpGroupElement,
        >,
        parameter_name: &str,
    ) -> SignMessage<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        SecpGroupElement,
    > {
        // Clone the honest message as our base
        let mut hybrid = honest_message.clone();

        // Replace only the specified parameter with the malicious version
        match parameter_name {
            // "beta_displacer" => {
            //     hybrid.beta_displacer = malicious_message.beta_displacer.clone();
            // },
            // "beta_displacer_commitment_randomness" => {
            //     hybrid.beta_displacer_commitment_randomness = 
            //         malicious_message.beta_displacer_commitment_randomness.clone();
            // },
            // "alpha_displacer" => {
            //     hybrid.alpha_displacer = malicious_message.alpha_displacer.clone();
            // },
            // "alpha_displacer_commitment_randomness" => {
            //     hybrid.alpha_displacer_commitment_randomness = 
            //         malicious_message.alpha_displacer_commitment_randomness.clone();
            // },
            // "first_coefficient" => {
            //     hybrid.first_coefficient = malicious_message.first_coefficient.clone();
            // },
            // "first_coefficient_commitment_randomness" => {
            //     hybrid.first_coefficient_commitment_randomness = 
            //         malicious_message.first_coefficient_commitment_randomness.clone();
            // },
            // "second_coefficient" => {
            //     hybrid.second_coefficient = malicious_message.second_coefficient.clone();
            // },
            // "second_coefficient_commitment_randomness" => {
            //     hybrid.second_coefficient_commitment_randomness = 
            //         malicious_message.second_coefficient_commitment_randomness.clone();
            // },
            "public_signature_nonce" => {
                hybrid.public_signature_nonce = malicious_message.public_signature_nonce;
            },
            "decentralized_party_nonce_public_share" => {
                hybrid.decentralized_party_nonce_public_share = malicious_message.decentralized_party_nonce_public_share;
            },
            "signature_nonce_share_commitment" => {
                hybrid.signature_nonce_share_commitment = malicious_message.signature_nonce_share_commitment;
            },
            "alpha_displacer_commitment" => {
                hybrid.alpha_displacer_commitment = malicious_message.alpha_displacer_commitment;
            },
            "beta_displacer_commitment" => {
                hybrid.beta_displacer_commitment = malicious_message.beta_displacer_commitment;
            },
            "signature_nonce_share_by_secret_share_commitment" => {
                hybrid.signature_nonce_share_by_secret_share_commitment = malicious_message.signature_nonce_share_by_secret_share_commitment;
            },
            // "encryption_of_masked_decentralized_party_nonce_share_before_displacing" => {
            //     hybrid.encryption_of_masked_decentralized_party_nonce_share_before_displacing = 
            //         malicious_message.encryption_of_masked_decentralized_party_nonce_share_before_displacing.clone();
            // },
            "non_zero_commitment_to_signature_nonce_share_proof" => {
                hybrid.non_zero_commitment_to_signature_nonce_share_proof = malicious_message.non_zero_commitment_to_signature_nonce_share_proof.clone();
            },
            "non_zero_commitment_to_alpha_displacer_share_proof" => {
                hybrid.non_zero_commitment_to_alpha_displacer_share_proof = malicious_message.non_zero_commitment_to_alpha_displacer_share_proof.clone();
            },
            "commitment_to_beta_displacer_share_uc_proof" => {
                hybrid.commitment_to_beta_displacer_share_uc_proof = malicious_message.commitment_to_beta_displacer_share_uc_proof.clone();
            },
            "proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments" => {
                hybrid.proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments = malicious_message.proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments.clone();
            },
            "public_signature_nonce_proof" => {
                hybrid.public_signature_nonce_proof = malicious_message.public_signature_nonce_proof.clone();
            },
            "decentralized_party_nonce_public_share_displacement_proof" => {
                hybrid.decentralized_party_nonce_public_share_displacement_proof = malicious_message.decentralized_party_nonce_public_share_displacement_proof.clone();
            },
            _ => panic!("Unknown parameter name: {parameter_name}"),
        }

        hybrid
    }

    // Test if the malicious parameter is detected by any party
    fn test_malicious_parameter_detection(
        rng: &mut OsCsRng,
        protocol_context: &ProtocolContext,
        sign_message: &SignMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            SecpGroupElement,
        >,
        hashed_message: &SecpScalar,
    ) -> bool {
        let mut detected = false;

        for party_context in &protocol_context.decentralized_parties {
            let result = advance_sign_party(rng, party_context, &[], sign_message, hashed_message);

            match result {
                Ok(AsynchronousRoundResult::Advance {
                    malicious_parties, ..
                }) => {
                    if !malicious_parties.is_empty() {
                        detected = true;
                        println!("Party {} detected malicious behavior", party_context.id);
                        break;
                    }
                }
                Err(e) => {
                    detected = true;
                    println!("Error detected: {e:?}");
                    break;
                }
                _ => {}
            }
        }

        detected
    }
}
