// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(dead_code)]

use crate::common;
use class_groups::Secp256k1DecryptionKeyShare;
use crypto_bigint::U256;
use group::secp256k1::Scalar as GroupSecpScalar;
use group::{secp256k1::group_element::Value as GroupSecpGroupElementValue, PartyID};
use homomorphic_encryption::AdditivelyHomomorphicDecryptionKeyShare;
use mpc::two_party::Round;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};
use rand_core::OsRng;
use std::collections::HashMap;
use twopc_mpc::class_groups::DKGDecentralizedPartyOutput;
use twopc_mpc::class_groups::DecryptionKeySharePublicParameters;
use twopc_mpc::class_groups::ProtocolPublicParameters;
use twopc_mpc::dkg::centralized_party;
use twopc_mpc::dkg::centralized_party::SecretKeyShare;
use twopc_mpc::dkg::decentralized_party::encryption_of_secret_key_share_round::class_groups::asynchronous as encryption_of_secret_key_share_round;
use twopc_mpc::dkg::decentralized_party::proof_verification_round;
use twopc_mpc::presign::decentralized_party::class_groups::asynchronous;
use twopc_mpc::presign::decentralized_party::PublicInput;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use twopc_mpc::secp256k1::GroupElement as SecpGroupElement;
use twopc_mpc::secp256k1::Scalar as SecpScalar;
use twopc_mpc::secp256k1::MESSAGE_LIMBS;
use twopc_mpc::secp256k1::SCALAR_LIMBS;

#[derive(Clone)]
pub struct CentralizedPartyInitializationContext {
    pub session_id: U256,
    pub access_structure: WeightedThresholdAccessStructure,
    pub protocol_public_parameters: ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
}

#[derive(Clone)]
pub struct CentralizedPartyDKGContext {
    /// $X_A$ - The centralized party's public key share
    pub dkg_public_key_share: GroupSecpGroupElementValue,
    /// $X$ - The joint public key
    pub dkg_public_key: GroupSecpGroupElementValue,
    /// $X_B$ - The decentralized party's public key share
    pub dkg_decentralized_party_public_key_share: GroupSecpGroupElementValue,
    /// $x_A$ - The centralized party's secret key share
    pub dkg_centralized_party_private_key_share: SecretKeyShare<GroupSecpScalar>,
    /// Output of the DKG protocol for the centralized party
    pub dkg_output: twopc_mpc::dkg::centralized_party::PublicOutput<GroupSecpGroupElementValue>,
}

#[derive(Clone)]
pub struct CentralizedPartyPresignContext {
    pub presign_output: PresignOutput,
}

#[derive(Clone)]
pub struct CentralizedPartyContext {
    pub id: PartyID,
    pub initialization_context: CentralizedPartyInitializationContext,
    pub dkg_context: Option<CentralizedPartyDKGContext>,
    pub presign_context: Option<CentralizedPartyPresignContext>,
}

#[derive(Clone)]
pub struct DecentralizedPartyInitializationContext {
    /// $sid$ - The session ID
    pub session_id: U256,
    /// The weighted threshold access structure
    pub access_structure: WeightedThresholdAccessStructure,
    /// Protocol public parameters including group parameters and encryption scheme parameters
    pub protocol_public_parameters: ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
    /// Public parameters for the decryption key shares
    pub decryption_key_share_public_parameters: DecryptionKeySharePublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
    /// Map from virtual party IDs to their decryption key shares
    pub virtual_party_id_to_decryption_key_share: HashMap<PartyID, Secp256k1DecryptionKeyShare>,
}

// Type definition for presign party output type
pub type PresignOutput = <asynchronous::Party<
    { SCALAR_LIMBS },
    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { MESSAGE_LIMBS },
    SecpGroupElement,
> as mpc::Party>::PublicOutput;

#[derive(Clone)]
pub struct DecentralizedPartyPresignContext {
    pub presign_output: PresignOutput,
}

#[derive(Clone)]
pub struct DecentralizedPartyDKGContext {
    /// Output of the DKG protocol for the decentralized party containing:
    /// - $X_B$ - The decentralized party's public key share
    /// - $X$ - The joint public key
    /// - $ct_{key}$ - Encryption of the secret key share
    /// - $X_A$ - The centralized party's public key share
    pub dkg_output: DKGDecentralizedPartyOutput<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
}

#[derive(Clone)]
pub struct DecentralizedPartyContext {
    pub id: PartyID,
    pub initialization_context: DecentralizedPartyInitializationContext,
    pub dkg_context: Option<DecentralizedPartyDKGContext>,
    pub presign_context: Option<DecentralizedPartyPresignContext>,
}

#[derive(Clone)]
pub struct ProtocolContext {
    /// $sid$ - The session ID
    pub session_id: U256,
    /// The centralized party's context
    pub centralized_party: CentralizedPartyContext,
    /// The decentralized parties' contexts
    pub decentralized_parties: Vec<DecentralizedPartyContext>,
    /// $t$ - The threshold number of parties needed
    pub threshold: usize,
    /// The weighted threshold access structure
    pub access_structure: WeightedThresholdAccessStructure,
    /// The IDs of all participating parties
    pub party_ids: Vec<PartyID>,
    /// Protocol public parameters including:
    /// - Group parameters
    /// - Encryption scheme parameters
    pub protocol_public_parameters: ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
    /// The decryption key for the protocol
    pub decryption_key: twopc_mpc::secp256k1::class_groups::DecryptionKey,
}

impl ProtocolContext {
    /// Creates a new ProtocolContext with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID for the protocol
    /// * `num_parties` - Number of decentralized parties
    /// * `threshold` - Threshold for the access structure
    ///
    /// # Returns
    ///
    /// A new ProtocolContext initialized with the given parameters
    pub fn new(session_id: u64, num_parties: usize, threshold: usize) -> Self {
        println!("Initializing new Protocol Context with:");
        println!("  Session ID: {}", session_id);
        println!("  Number of parties: {}", num_parties);
        println!("  Threshold: {}", threshold);

        assert!(
            num_parties >= threshold,
            "Number of parties must be greater than or equal to threshold"
        );
        assert!(threshold > 0, "Threshold must be greater than 0");
        assert!(num_parties > 0, "Number of parties must be greater than 0");

        println!("Generating protocol public parameters and decryption key...");
        let (protocol_public_parameters, decryption_key) =
            twopc_mpc::test_helpers::setup_class_groups_secp256k1();

        println!("Getting setup parameters from protocol public parameters...");
        let setup_parameters = protocol_public_parameters
            .encryption_scheme_public_parameters
            .setup_parameters
            .clone();

        let base = setup_parameters.h;
        let secret_key_bits = setup_parameters.decryption_key_bits();
        println!("Secret key bits length: {}", secret_key_bits);

        println!("Dealing trusted shares to parties...");
        let (decryption_key_share_public_parameters, decryption_key_shares) =
            class_groups::decryption_key_share::test_helpers::deal_trusted_shares::<
                { SCALAR_LIMBS },
                { FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                SecpGroupElement,
            >(
                threshold as u16,
                num_parties as u16,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
                decryption_key.decryption_key,
                base,
                secret_key_bits,
            );

        // Convert raw shares to Secp256k1DecryptionKeyShare instances
        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(party_id, share)| {
                (
                    party_id,
                    Secp256k1DecryptionKeyShare::new(
                        party_id,
                        share,
                        &decryption_key_share_public_parameters,
                    )
                    .unwrap(),
                )
            })
            .collect();

        println!("Setting up party IDs and access structure...");
        let party_ids = (1..=num_parties).map(|id| id as u16).collect::<Vec<_>>();

        let mut party_to_weight = HashMap::new();
        for &party_id in &party_ids {
            party_to_weight.insert(party_id, 1);
        }
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold.try_into().unwrap(), party_to_weight)
                .unwrap();

        println!("Creating centralized party context...");
        let centralized_party = CentralizedPartyContext {
            id: 0,
            initialization_context: CentralizedPartyInitializationContext {
                session_id: session_id.into(),
                access_structure: access_structure.clone(),
                protocol_public_parameters: protocol_public_parameters.clone(),
            },
            dkg_context: None,
            presign_context: None,
        };

        println!("Creating decentralized party contexts...");
        let decentralized_parties = party_ids
            .iter()
            .map(|&id| {
                println!("  Creating context for party ID: {}", id);
                let key_share = decryption_key_shares
                    .get(&id)
                    .expect("Missing decryption key share")
                    .clone();
                let mut vp_to_key_share = HashMap::new();
                vp_to_key_share.insert(id, key_share);

                DecentralizedPartyContext {
                    id,
                    initialization_context: DecentralizedPartyInitializationContext {
                        session_id: session_id.into(),
                        access_structure: access_structure.clone(),
                        protocol_public_parameters: protocol_public_parameters.clone(),
                        decryption_key_share_public_parameters:
                            decryption_key_share_public_parameters.clone(),
                        virtual_party_id_to_decryption_key_share: vp_to_key_share,
                    },
                    dkg_context: None,
                    presign_context: None,
                }
            })
            .collect();

        println!("Protocol Context initialization completed.");

        ProtocolContext {
            session_id: session_id.into(),
            centralized_party,
            decentralized_parties,
            threshold,
            access_structure,
            party_ids,
            protocol_public_parameters,
            decryption_key,
        }
    }
}

// Type aliases to improve readability
pub type DKGError = <encryption_of_secret_key_share_round::Party<
    { SCALAR_LIMBS },
    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    SecpGroupElement,
> as mpc::Party>::Error;

pub type EncryptionParty = encryption_of_secret_key_share_round::Party<
    { SCALAR_LIMBS },
    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    SecpGroupElement,
>;

pub type EncryptionOutput = <EncryptionParty as mpc::Party>::PublicOutput;

pub type VerificationParty = proof_verification_round::Party<
    { SCALAR_LIMBS },
    { SCALAR_LIMBS },
    SecpGroupElement,
    ::class_groups::EncryptionKey<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
    ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
>;

pub type VerificationOutput = <VerificationParty as mpc::Party>::PublicOutput;

pub type CentralizedPartyType = centralized_party::Party<
    { SCALAR_LIMBS },
    { SCALAR_LIMBS },
    SecpGroupElement,
    ::class_groups::EncryptionKey<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
    ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
>;

pub type CentralizedPartyResult = mpc::two_party::RoundResult<
    twopc_mpc::dkg::centralized_party::PublicKeyShareAndProof<
        GroupSecpGroupElementValue,
        twopc_mpc::languages::KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, SecpGroupElement>,
    >,
    SecretKeyShare<SecpScalar>,
    twopc_mpc::dkg::centralized_party::PublicOutput<GroupSecpGroupElementValue>,
>;

/// Phase 1 of the DKG protocol: Decentralized parties encryption of secret key shares
///
/// # Returns
/// A map from party IDs to their public outputs from the encryption phase
pub fn run_dkg_phase1(
    rng: &mut OsRng,
    protocol_context: &ProtocolContext,
) -> Result<HashMap<PartyID, EncryptionOutput>, DKGError> {
    println!("Starting Phase 1: Decentralized parties encryption of secret key shares");

    // Initialize message storage for the protocol
    let mut decentralized_messages: Vec<
        HashMap<PartyID, <EncryptionParty as mpc::Party>::Message>,
    > = vec![];

    // Execute Round 1: Each decentralized party generates its initial message
    let round1_messages = execute_encryption_round1(rng, protocol_context)?;
    decentralized_messages.push(round1_messages);
    println!("Phase 1 Round 1 completed");

    // Execute Round 2: Finalize the decentralized encryption
    let decentralized_party_outputs =
        execute_encryption_round2(rng, protocol_context, &decentralized_messages)?;
    println!("Phase 1 completed");

    Ok(decentralized_party_outputs)
}

/// Execute Round 1 of the encryption phase
pub fn execute_encryption_round1(
    rng: &mut OsRng,
    protocol_context: &ProtocolContext,
) -> Result<HashMap<PartyID, <EncryptionParty as mpc::Party>::Message>, DKGError> {
    let mut round1_messages = HashMap::new();

    for party_context in &protocol_context.decentralized_parties {
        let result = EncryptionParty::advance(
            party_context.initialization_context.session_id,
            party_context.id,
            &party_context.initialization_context.access_structure,
            vec![], // No previous messages in first round
            None,   // No private input
            &party_context
                .initialization_context
                .protocol_public_parameters,
            rng,
        )?;

        match result {
            AsynchronousRoundResult::Advance {
                message,
                malicious_parties,
            } => {
                assert!(
                    malicious_parties.is_empty(),
                    "No parties should be flagged as malicious in round 1"
                );
                round1_messages.insert(party_context.id, message);
            }
            _ => panic!("Expected Advance result in round 1"),
        }
    }

    Ok(round1_messages)
}

/// Execute Round 2 of the encryption phase
pub fn execute_encryption_round2(
    rng: &mut OsRng,
    protocol_context: &ProtocolContext,
    decentralized_messages: &[HashMap<PartyID, <EncryptionParty as mpc::Party>::Message>],
) -> Result<HashMap<PartyID, EncryptionOutput>, DKGError> {
    let mut decentralized_party_outputs = HashMap::new();

    for party_context in &protocol_context.decentralized_parties {
        let result = EncryptionParty::advance(
            party_context.initialization_context.session_id,
            party_context.id,
            &party_context.initialization_context.access_structure,
            decentralized_messages.to_vec(),
            None,
            &party_context
                .initialization_context
                .protocol_public_parameters,
            rng,
        )?;

        match result {
            AsynchronousRoundResult::Finalize {
                malicious_parties,
                private_output: _,
                public_output,
            } => {
                assert!(
                    malicious_parties.is_empty(),
                    "No parties should be flagged as malicious in final decentralized round"
                );
                decentralized_party_outputs.insert(party_context.id, public_output);
            }
            _ => panic!("Expected Finalize result in final decentralized round"),
        }
    }

    Ok(decentralized_party_outputs)
}

/// Phase 2 of the DKG protocol: Centralized party generates its key share and proof
///
/// # Returns
/// The centralized party result and updated protocol context
pub fn run_dkg_phase2(
    rng: &mut OsRng,
    protocol_context: &mut ProtocolContext,
    decentralized_party_outputs: &HashMap<PartyID, EncryptionOutput>,
) -> Result<CentralizedPartyResult, DKGError> {
    println!("Starting Phase 2: Centralized party key share generation");

    // Use the output from any decentralized party to create input for centralized party
    let first_party_output = decentralized_party_outputs
        .values()
        .next()
        .expect("At least one decentralized party output should exist");

    // Create public input for centralized party
    let centralized_party_public_input = create_centralized_party_input(protocol_context);

    // Advance the centralized party
    let centralized_party_result = CentralizedPartyType::advance(
        first_party_output.0,
        &(), // No private input
        &centralized_party_public_input,
        rng,
    )?;

    // Update the protocol context with the centralized party results
    update_protocol_context_with_dkg_results(protocol_context, &centralized_party_result);

    println!("Phase 2 completed");
    Ok(centralized_party_result)
}

/// Create the public input for the centralized party
pub fn create_centralized_party_input(
    protocol_context: &ProtocolContext,
) -> twopc_mpc::dkg::centralized_party::PublicInput<
    ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
> {
    twopc_mpc::dkg::centralized_party::PublicInput {
        protocol_public_parameters: protocol_context
            .centralized_party
            .initialization_context
            .protocol_public_parameters
            .clone(),
        session_id: protocol_context
            .centralized_party
            .initialization_context
            .session_id,
    }
}

/// Update the protocol context with the DKG results from the centralized party
pub fn update_protocol_context_with_dkg_results(
    protocol_context: &mut ProtocolContext,
    centralized_party_result: &CentralizedPartyResult,
) {
    protocol_context.centralized_party.dkg_context = Some(CentralizedPartyDKGContext {
        dkg_public_key_share: centralized_party_result.public_output.public_key_share,
        dkg_public_key: centralized_party_result.public_output.public_key,
        dkg_decentralized_party_public_key_share: centralized_party_result
            .public_output
            .decentralized_party_public_key_share,
        dkg_centralized_party_private_key_share: centralized_party_result.private_output,
        dkg_output: centralized_party_result.public_output.clone(),
    });
}

/// Phase 3 of the DKG protocol: Decentralized parties verify the centralized party's proof
///
/// # Returns
/// A map from party IDs to their verification results
pub fn run_dkg_phase3(
    rng: &mut OsRng,
    protocol_context: &mut ProtocolContext,
    decentralized_party_outputs: &HashMap<PartyID, EncryptionOutput>,
    centralized_party_result: &CentralizedPartyResult,
) -> Result<HashMap<PartyID, VerificationOutput>, DKGError> {
    println!("Starting Phase 3: Decentralized parties proof verification");

    let mut dkt_outputs = HashMap::new();

    for party_context in &mut protocol_context.decentralized_parties {
        let party_id = party_context.id;

        // Get the decentralized party output for this party
        let decentralized_output = decentralized_party_outputs
            .get(&party_id)
            .expect("Participating party should have decentralized output");

        // Create verification input and execute verification
        let verification_result = execute_verification_for_party(
            rng,
            party_context,
            decentralized_output,
            centralized_party_result,
        )?;

        dkt_outputs.insert(party_id, verification_result);
    }

    println!("Phase 3 completed");
    Ok(dkt_outputs)
}

/// Execute verification for a single decentralized party
pub fn execute_verification_for_party(
    rng: &mut OsRng,
    party_context: &mut DecentralizedPartyContext,
    decentralized_output: &EncryptionOutput,
    centralized_party_result: &CentralizedPartyResult,
) -> Result<VerificationOutput, DKGError> {
    // Create public input for verification
    let verification_public_input = (
        party_context
            .initialization_context
            .protocol_public_parameters
            .clone(),
        *decentralized_output,
        centralized_party_result.outgoing_message.clone(),
    )
        .into();

    // Run proof verification for this party
    let verification_result = VerificationParty::advance(
        party_context.initialization_context.session_id,
        party_context.id,
        &party_context.initialization_context.access_structure,
        vec![], // No messages needed for verification
        None,   // No private input
        &verification_public_input,
        rng,
    )?;

    match verification_result {
        AsynchronousRoundResult::Finalize {
            malicious_parties,
            private_output: _,
            public_output,
        } => {
            assert!(
                malicious_parties.is_empty(),
                "No parties should be flagged as malicious in verification round"
            );

            // Store DKG output in context
            party_context.dkg_context = Some(DecentralizedPartyDKGContext {
                dkg_output: public_output.clone(),
            });

            Ok(public_output)
        }
        _ => panic!("Expected Finalize result in verification round"),
    }
}

/// Execute a complete DKG protocol with the specified number of decentralized parties
/// and the given threshold.
///
/// The protocol consists of three phases:
/// 1. Decentralized parties generate encryption of secret key shares
/// 2. Centralized party generates its key share and proof
/// 3. Decentralized parties verify the centralized party's proof
///
/// # Arguments
///
/// * `rng` - Random number generator
/// * `protocol_context` - Protocol context containing party information and parameters
/// * `skip_parties` - Optional vector of party IDs to skip (simulating non-participation)
///
/// # Returns
///
/// A map from party IDs to their public outputs
pub fn run_dkg_protocol(
    rng: &mut OsRng,
    protocol_context: &mut ProtocolContext,
    skip_parties: Option<Vec<PartyID>>,
) -> Result<HashMap<PartyID, VerificationOutput>, DKGError> {
    // Filter out skipped parties if any
    let participating_party_ids = match &skip_parties {
        Some(skip_ids) => protocol_context
            .party_ids
            .iter()
            .filter(|&id| !skip_ids.contains(id))
            .copied()
            .collect::<Vec<_>>(),
        None => protocol_context.party_ids.clone(),
    };

    // Filter decentralized_parties to only include participating parties
    protocol_context
        .decentralized_parties
        .retain(|party| participating_party_ids.contains(&party.id));

    // Execute the three phases of the DKG protocol
    let decentralized_party_outputs = run_dkg_phase1(rng, protocol_context)?;
    let centralized_party_result =
        run_dkg_phase2(rng, protocol_context, &decentralized_party_outputs)?;
    let dkt_outputs = run_dkg_phase3(
        rng,
        protocol_context,
        &decentralized_party_outputs,
        &centralized_party_result,
    )?;

    println!("DKG protocol completed successfully");
    Ok(dkt_outputs)
}

// Type aliases to improve readability
pub type PresignPartyType = asynchronous::Party<
    { SCALAR_LIMBS },
    { FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { MESSAGE_LIMBS },
    SecpGroupElement,
>;

pub type PresignMessage = <PresignPartyType as mpc::Party>::Message;
pub type PresignError = <PresignPartyType as mpc::Party>::Error;

type DKGOutput = <proof_verification_round::Party<
    { SCALAR_LIMBS },
    { SCALAR_LIMBS },
    SecpGroupElement,
    ::class_groups::EncryptionKey<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
    ProtocolPublicParameters<
        { SCALAR_LIMBS },
        { FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        SecpGroupElement,
    >,
> as mpc::Party>::PublicOutput;

/// Execute the presign protocol using the provided DKG outputs from the decentralized parties.
///
/// The protocol consists of two phases:
/// 1. Encryption of Mask and Masked Key Share (Rounds 1-2)
/// 2. Nonce Public Share and Encryption of Masked Nonce (Round 3)
///
/// # Arguments
///
/// * `rng` - Random number generator
/// * `protocol_context` - The protocol context containing all necessary information
/// * `dkg_outputs` - DKG outputs from decentralized parties
///
/// # Returns
///
/// A map from party IDs to their presign outputs
pub fn run_presign_protocol(
    rng: &mut OsRng,
    protocol_context: &mut ProtocolContext,
    dkg_outputs: &HashMap<PartyID, DKGOutput>,
) -> Result<HashMap<PartyID, PresignOutput>, PresignError> {
    // Get participating party IDs from the protocol context
    let participating_party_ids: Vec<PartyID> = protocol_context
        .decentralized_parties
        .iter()
        .map(|party| party.id)
        .collect();

    // Initialize message storage
    let mut messages: Vec<HashMap<PartyID, PresignMessage>> = vec![];

    // Phase 1: Encryption of Mask and Masked Key Share (Rounds 1-2)
    println!("Starting Presign Phase 1: Encryption of Mask and Masked Key Share");
    messages = execute_presign_phase1(
        rng,
        protocol_context,
        dkg_outputs,
        &participating_party_ids,
        messages,
    )?;

    // Phase 2: Nonce Public Share and Encryption of Masked Nonce (Round 3)
    println!("Starting Presign Phase 2: Nonce Public Share and Encryption of Masked Nonce");
    messages = execute_presign_phase2(
        rng,
        protocol_context,
        dkg_outputs,
        &participating_party_ids,
        messages,
    )?;

    // Finalize: Each party processes all messages and produces final output
    println!("Finalizing Presign protocol");
    let presign_outputs = finalize_presign(
        rng,
        protocol_context,
        dkg_outputs,
        &participating_party_ids,
        &messages,
    )?;

    // Update the centralized party's presign context
    protocol_context.centralized_party.presign_context =
        Some(common::CentralizedPartyPresignContext {
            presign_output: presign_outputs[&participating_party_ids[0]].clone(),
        });

    // Update each decentralized party's presign context
    for party_context in &mut protocol_context.decentralized_parties {
        if let Some(output) = presign_outputs.get(&party_context.id) {
            party_context.presign_context =
                Some(common::DecentralizedPartyPresignContext {
                    presign_output: output.clone(),
                });
        }
    }

    println!("Presign protocol completed successfully");
    Ok(presign_outputs)
}

/// Execute Phase 1 of the presign protocol (Rounds 1-2)
///
/// # Returns
/// Updated messages from all rounds executed so far
fn execute_presign_phase1(
    rng: &mut OsRng,
    protocol_context: &ProtocolContext,
    dkg_outputs: &HashMap<PartyID, DKGOutput>,
    participating_party_ids: &[PartyID],
    mut messages: Vec<HashMap<PartyID, PresignMessage>>,
) -> Result<Vec<HashMap<PartyID, PresignMessage>>, PresignError> {
    // Round 1: Each party generates its initial message
    let round1_messages = execute_presign_round(
        rng,
        protocol_context,
        dkg_outputs,
        participating_party_ids,
        &messages,
        "Round 1",
    )?;
    messages.push(round1_messages);
    println!("Presign Round 1 completed");

    // Round 2: Process round 1 messages and generate round 2 message
    println!("Processing Round 1 messages and generating Round 2 messages");
    let round2_messages = execute_presign_round(
        rng,
        protocol_context,
        dkg_outputs,
        participating_party_ids,
        &messages,
        "Round 2",
    )?;
    messages.push(round2_messages);
    println!("Presign Round 2 completed");

    Ok(messages)
}

/// Execute Phase 2 of the presign protocol (Round 3)
///
/// # Returns
/// Updated messages from all rounds executed so far
fn execute_presign_phase2(
    rng: &mut OsRng,
    protocol_context: &ProtocolContext,
    dkg_outputs: &HashMap<PartyID, DKGOutput>,
    participating_party_ids: &[PartyID],
    mut messages: Vec<HashMap<PartyID, PresignMessage>>,
) -> Result<Vec<HashMap<PartyID, PresignMessage>>, PresignError> {
    // Round 3: Process round 2 messages and generate round 3 message
    let round3_messages = execute_presign_round(
        rng,
        protocol_context,
        dkg_outputs,
        participating_party_ids,
        &messages,
        "Round 3",
    )?;
    messages.push(round3_messages);
    println!("Presign Round 3 completed");

    Ok(messages)
}

/// Execute a single round of the presign protocol for all participating parties
///
/// # Returns
/// Map of party IDs to their generated messages for this round
fn execute_presign_round(
    rng: &mut OsRng,
    protocol_context: &ProtocolContext,
    dkg_outputs: &HashMap<PartyID, DKGOutput>,
    participating_party_ids: &[PartyID],
    messages: &[HashMap<PartyID, PresignMessage>],
    round_name: &str,
) -> Result<HashMap<PartyID, PresignMessage>, PresignError> {
    let mut round_messages = HashMap::new();

    for &party_id in participating_party_ids {
        // Find the party context
        let party_context = protocol_context
            .decentralized_parties
            .iter()
            .find(|p| p.id == party_id)
            .expect("Party ID should be in the protocol context");

        let result = advance_presign_party(rng, party_context, messages, dkg_outputs)?;

        match result {
            AsynchronousRoundResult::Advance {
                message,
                malicious_parties,
            } => {
                assert!(
                    malicious_parties.is_empty(),
                    "No parties should be flagged as malicious in Presign {}",
                    round_name
                );
                round_messages.insert(party_id, message);
            }
            _ => panic!("Expected Advance result in Presign {}", round_name),
        }
    }

    Ok(round_messages)
}

/// Advance a presign party with the given inputs
pub fn advance_presign_party(
    rng: &mut OsRng,
    party_context: &DecentralizedPartyContext,
    messages: &[HashMap<PartyID, PresignMessage>],
    dkg_outputs: &HashMap<PartyID, DKGOutput>,
) -> Result<AsynchronousRoundResult<PresignMessage, (), PresignOutput>, PresignError> {
    // Get DKG output for this party
    let dkg_output = dkg_outputs
        .get(&party_context.id)
        .expect("Participating party should have DKG output");

    // Create public input directly here
    let public_input = PublicInput {
        protocol_public_parameters: party_context
            .initialization_context
            .protocol_public_parameters
            .clone(),
        dkg_output: dkg_output.clone(),
    };

    PresignPartyType::advance(
        party_context.initialization_context.session_id,
        party_context.id,
        &party_context.initialization_context.access_structure,
        messages.to_vec(),
        None, // No private input
        &public_input,
        rng,
    )
}

/// Finalize the presign protocol for all participating parties
///
/// # Returns
/// Map of party IDs to their final presign outputs
pub fn finalize_presign(
    rng: &mut OsRng,
    protocol_context: &ProtocolContext,
    dkg_outputs: &HashMap<PartyID, DKGOutput>,
    participating_party_ids: &[PartyID],
    messages: &[HashMap<PartyID, PresignMessage>],
) -> Result<HashMap<PartyID, PresignOutput>, PresignError> {
    let mut presign_outputs = HashMap::new();

    for &party_id in participating_party_ids {
        // Find the party context
        let party_context = protocol_context
            .decentralized_parties
            .iter()
            .find(|p| p.id == party_id)
            .expect("Party ID should be in the protocol context");

        let result = advance_presign_party(rng, party_context, messages, dkg_outputs)?;

        match result {
            AsynchronousRoundResult::Finalize {
                malicious_parties,
                private_output: _,
                public_output,
            } => {
                assert!(
                    malicious_parties.is_empty(),
                    "No parties should be flagged as malicious in Presign finalization"
                );
                presign_outputs.insert(party_id, public_output);
            }
            _ => panic!("Expected Finalize result in Presign finalization"),
        }
    }

    Ok(presign_outputs)
}
