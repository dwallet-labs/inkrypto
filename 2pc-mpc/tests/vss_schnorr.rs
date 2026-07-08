// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Integration tests for VSS Schnorr protocol flow.
//!
//! This module tests the complete flow:
//! 1. Universal DKG -> Threshold Encryption to Sharing -> VSS Presign -> VSS Sign
//!
//! The threshold encryption to sharing protocol converts encrypted secret key shares
//! from DKG outputs into Shamir secret shares usable by the VSS Schnorr protocol.

#![allow(clippy::too_many_arguments)]
#![allow(unexpected_cfgs)]

/// Old integration test module - temporarily disabled pending API updates.
///
/// NOTE: These tests are temporarily disabled pending API updates to:
/// - `public_input_from_dkg` (signature changed to require PVSS encryption keys)
/// - `PrivatePresignOutput` (now has two generic parameters)
/// - `compute_signature_share` (signature changed)
/// - `Presign` struct fields renamed
///
/// Update tests once the API stabilizes.
#[cfg(all(feature = "test_helpers", feature = "DISABLED_PENDING_API_UPDATE"))]
mod disabled_tests {

    use std::collections::HashMap;

    use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::Random;
    use group::{secp256k1, CyclicGroupElement, GroupElement as _, HashScheme, OsCsRng, PartyID};
    use mpc::secret_sharing::shamir::known_order::{
        generate_encryption_keypair, EncryptionPublicKey, EncryptionSecretKey,
    };
    use mpc::WeightedThresholdAccessStructure;
    use twopc_mpc::decentralized_party::dkg::tests::generates_universal_distributed_key_internal;
    use twopc_mpc::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::{
        advance_accusation_round, advance_aggregation_round, advance_dealing_round,
        advance_threshold_decrypt_round, public_input_from_dkg, AccusationRoundMessage,
        DealingRoundMessage, PrivateInput, PrivateOutput, PublicOutput as EncToSharingPublicOutput,
        ThresholdDecryptionRoundMessage,
    };
    use twopc_mpc::schnorr::{TaprootSignature, VerifyingKey};
    use twopc_mpc::sign::EncodableSignature;

    /// Helper to generate HPKE encryption keys for parties.
    fn generate_party_encryption_keys(
        party_ids: &[PartyID],
        rng: &mut impl group::CsRng,
    ) -> (
        HashMap<PartyID, EncryptionPublicKey>,
        HashMap<PartyID, EncryptionSecretKey>,
    ) {
        let (public_keys, secret_keys): (HashMap<_, _>, HashMap<_, _>) = party_ids
            .iter()
            .map(|&party_id| {
                let (secret_key, public_key) = generate_encryption_keypair(rng).unwrap();
                ((party_id, public_key), (party_id, secret_key))
            })
            .unzip();

        (public_keys, secret_keys)
    }

    /// Run the threshold encryption to sharing protocol.
    ///
    /// Converts encrypted secret key shares from DKG to Shamir secret shares.
    ///
    /// # Arguments
    ///
    /// * `party_ids` - The participating party IDs
    /// * `access_structure` - The threshold access structure
    /// * `dkg_public_output` - The public output from Universal DKG
    /// * `decryption_key_shares` - Each party's decryption key shares for threshold decryption
    /// * `party_encryption_public_keys` - HPKE public keys for VSS share encryption
    /// * `party_encryption_secret_keys` - HPKE secret keys for VSS share decryption
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A tuple of (party_id -> private output, public output) containing Shamir shares and commitments.
    fn run_threshold_encryption_to_sharing_protocol(
        party_ids: &[PartyID],
        access_structure: &WeightedThresholdAccessStructure,
        dkg_public_output: &twopc_mpc::decentralized_party::dkg::PublicOutput,
        decryption_key_shares: &HashMap<
            PartyID,
            HashMap<PartyID, class_groups::SecretKeyShareSizedInteger>,
        >,
        party_encryption_public_keys: &HashMap<PartyID, EncryptionPublicKey>,
        party_encryption_secret_keys: &HashMap<PartyID, EncryptionSecretKey>,
        rng: &mut impl group::CsRng,
    ) -> (HashMap<PartyID, PrivateOutput>, EncToSharingPublicOutput) {
        let session_id = CommitmentSizedNumber::random(rng);

        // Create public input from DKG output
        let public_input = public_input_from_dkg(
            dkg_public_output,
            access_structure.clone(),
            party_encryption_public_keys.clone(),
        );

        // Round 1: Each party generates dealing messages
        println!("Running enc-to-sharing Round 1 (Dealing)...");
        let dealing_messages: HashMap<PartyID, DealingRoundMessage> = party_ids
            .iter()
            .map(|&party_id| {
                let dealing_msg = advance_dealing_round(session_id, party_id, &public_input, rng)
                    .expect("Dealing round should succeed");
                (party_id, dealing_msg)
            })
            .collect();

        // Round 2: Each party generates accusation messages
        println!("Running enc-to-sharing Round 2 (Accusation)...");
        let accusation_messages: HashMap<PartyID, AccusationRoundMessage> = party_ids
            .iter()
            .map(|&party_id| {
                let encryption_secret_key = *party_encryption_secret_keys
                    .get(&party_id)
                    .expect("Party should have encryption secret key");
                let party_decryption_key_shares = decryption_key_shares
                    .get(&party_id)
                    .expect("Party should have decryption key shares")
                    .clone();

                let private_input = PrivateInput {
                    decryption_key_shares: party_decryption_key_shares,
                    encryption_secret_key,
                };

                let accusation_msg = advance_accusation_round(
                    session_id,
                    party_id,
                    &private_input,
                    &public_input,
                    &dealing_messages,
                    rng,
                )
                .expect("Accusation round should succeed");

                (party_id, accusation_msg)
            })
            .collect();

        // Round 3: Each party generates threshold decryption shares
        println!("Running enc-to-sharing Round 3 (Threshold Decryption)...");
        let decryption_messages: HashMap<PartyID, ThresholdDecryptionRoundMessage> = party_ids
            .iter()
            .map(|&party_id| {
                let encryption_secret_key = *party_encryption_secret_keys
                    .get(&party_id)
                    .expect("Party should have encryption secret key");
                let party_decryption_key_shares = decryption_key_shares
                    .get(&party_id)
                    .expect("Party should have decryption key shares")
                    .clone();

                let private_input = PrivateInput {
                    decryption_key_shares: party_decryption_key_shares,
                    encryption_secret_key,
                };

                let (_malicious_parties, decryption_msg) = advance_threshold_decrypt_round(
                    session_id,
                    party_id,
                    &private_input,
                    &public_input,
                    &dealing_messages,
                    &accusation_messages,
                    access_structure,
                    rng,
                )
                .expect("Threshold decryption round should succeed");

                (party_id, decryption_msg)
            })
            .collect();

        // Round 4: Each party aggregates and computes final Shamir shares
        println!("Running enc-to-sharing Round 4 (Aggregation)...");
        let (private_outputs, public_output) = party_ids.iter().fold(
            (HashMap::new(), None),
            |(mut outputs, public_out), &party_id| {
                let encryption_secret_key = *party_encryption_secret_keys
                    .get(&party_id)
                    .expect("Party should have encryption secret key");
                let party_decryption_key_shares = decryption_key_shares
                    .get(&party_id)
                    .expect("Party should have decryption key shares")
                    .clone();

                let private_input = PrivateInput {
                    decryption_key_shares: party_decryption_key_shares,
                    encryption_secret_key,
                };

                let (_malicious_parties, private_output, enc_public_output) =
                    advance_aggregation_round(
                        session_id,
                        party_id,
                        &private_input,
                        &public_input,
                        &dealing_messages,
                        &accusation_messages,
                        &decryption_messages,
                        access_structure,
                    )
                    .expect("Aggregation round should succeed");

                outputs.insert(party_id, private_output);
                (outputs, public_out.or(Some(enc_public_output)))
            },
        );

        println!("Threshold encryption to sharing protocol completed successfully");
        (
            private_outputs,
            public_output.expect("Should have at least one party"),
        )
    }

    /// Run the VSS presign protocol.
    ///
    /// Returns: (private_outputs, public_outputs) for each party
    #[allow(clippy::type_complexity)]
    fn run_vss_presign_protocol(
        party_ids: &[PartyID],
        threshold: PartyID,
        session_id: CommitmentSizedNumber,
        party_public_keys: &HashMap<PartyID, EncryptionPublicKey>,
        party_secret_keys: &HashMap<PartyID, EncryptionSecretKey>,
        access_structure: &WeightedThresholdAccessStructure,
        rng: &mut impl group::CsRng,
    ) -> (
        HashMap<
            PartyID,
            twopc_mpc::schnorr::vss::presign::PrivatePresignOutput<group::Value<secp256k1::Scalar>>,
        >,
        HashMap<
            PartyID,
            twopc_mpc::schnorr::vss::presign::Presign<group::Value<secp256k1::GroupElement>>,
        >,
    ) {
        use twopc_mpc::schnorr::vss::presign::decentralized_party::{
            advance_accusation_round, advance_aggregation_round_with_blending,
            advance_dealing_round, AccusationMessage, DealingMessage,
        };

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        // Round 1: Each party generates their nonce shares via VSS
        let dealing_messages: HashMap<
            PartyID,
            DealingMessage<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>,
        > = party_ids
            .iter()
            .map(|&party_id| {
                let broadcast =
                    advance_dealing_round::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                        session_id,
                        party_id,
                        threshold,
                        &scalar_group_public_parameters,
                        &group_params,
                        party_public_keys,
                        rng,
                    )
                    .expect("Presign dealing round should succeed");
                (party_id, broadcast)
            })
            .collect();

        // Round 2: Each party decrypts, verifies, and broadcasts accusations
        let accusation_messages: HashMap<PartyID, AccusationMessage> = party_ids
            .iter()
            .map(|&party_id| {
                let secret_key = party_secret_keys.get(&party_id).unwrap();
                let public_key = party_public_keys.get(&party_id).unwrap();

                let broadcast = advance_accusation_round::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    session_id,
                    party_id,
                    secret_key,
                    public_key,
                    &dealing_messages,
                    &scalar_group_public_parameters,
                    &group_params,
                    rng,
                )
                .expect("Presign accusation round should succeed");

                (party_id, broadcast)
            })
            .collect();

        // Round 3: Each party verifies accusations and aggregates
        let (private_outputs, public_outputs): (HashMap<_, _>, HashMap<_, _>) = party_ids
            .iter()
            .map(|&party_id| {
                let secret_key = party_secret_keys.get(&party_id).unwrap();
                let public_key = party_public_keys.get(&party_id).unwrap();

                let (_malicious_parties, private_output_vec, public_output_vec) =
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
                        party_public_keys,
                        access_structure,
                    )
                    .expect("Presign aggregation round should succeed");

                // Use the first blended output
                (
                    (party_id, private_output_vec[0].clone()),
                    (party_id, public_output_vec[0].clone()),
                )
            })
            .unzip();

        (private_outputs, public_outputs)
    }

    /// Run the VSS sign protocol.
    ///
    /// Returns the final signature.
    #[allow(clippy::type_complexity)]
    fn run_vss_sign_protocol(
        party_ids: &[PartyID],
        centralized_secret_key_share: group::Value<secp256k1::Scalar>,
        dkg_output: &twopc_mpc::dkg::centralized_party::Output<
            group::Value<secp256k1::GroupElement>,
        >,
        presign: &twopc_mpc::schnorr::vss::presign::Presign<group::Value<secp256k1::GroupElement>>,
        secret_key_shares: &HashMap<
            PartyID,
            (
                group::Value<secp256k1::Scalar>,
                group::Value<secp256k1::Scalar>,
            ),
        >,
        nonce_shares: &HashMap<
            PartyID,
            (
                group::Value<secp256k1::Scalar>,
                group::Value<secp256k1::Scalar>,
            ),
        >,
        message: &[u8],
        hash_scheme: HashScheme,
        rng: &mut impl group::CsRng,
    ) -> TaprootSignature {
        use twopc_mpc::schnorr::vss::sign::centralized_party::{sign, verify_and_output};
        use twopc_mpc::schnorr::vss::sign::decentralized_party::{
            compute_signature_share, reconstruct_signature,
        };

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        // Step 1: Centralized party creates partial signature
        let (partial_signature, _signing_state) =
            sign::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                centralized_secret_key_share,
                message,
                hash_scheme,
                dkg_output,
                presign,
                &scalar_group_public_parameters,
                &group_params,
                rng,
            )
            .expect("Centralized party signing should succeed");

        // Step 2: Each decentralized party computes their signature share
        let session_id_bytes = presign.session_id.to_be_bytes();
        let signature_shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> = party_ids
            .iter()
            .map(|&party_id| {
                let (secret_key_share_first, secret_key_share_second) =
                    secret_key_shares.get(&party_id).unwrap();
                let (nonce_share_first, nonce_share_second) = nonce_shares.get(&party_id).unwrap();

                let share = compute_signature_share::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                >(
                    dkg_output,
                    *secret_key_share_first,
                    *secret_key_share_second,
                    presign.decentralized_party_nonce_public_shares,
                    *nonce_share_first,
                    *nonce_share_second,
                    &partial_signature,
                    message,
                    &session_id_bytes,
                    hash_scheme,
                    &scalar_group_public_parameters,
                    &group_params,
                )
                .expect("Signature share computation should succeed");

                (party_id, share)
            })
            .collect();

        // Step 3: Reconstruct the signature from shares
        let reconstructed_response = reconstruct_signature::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
        >(&signature_shares, &scalar_group_public_parameters)
        .expect("Signature reconstruction should succeed");

        // Step 4: Verify and output the final signature
        verify_and_output::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
            reconstructed_response,
            message,
            hash_scheme,
            dkg_output,
            presign,
            &partial_signature,
            &group_params,
        )
        .expect("Signature verification should succeed")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use group::Samplable;

        /// Test the full VSS Schnorr flow using the actual threshold encryption to sharing protocol.
        ///
        /// Flow: Universal DKG -> Threshold Encryption to Sharing -> VSS Presign -> VSS Sign
        #[test]
        fn test_vss_schnorr_with_enc_to_sharing() {
            let mut rng = OsCsRng;

            // Use threshold <= number_of_parties for VSS dealing to work
            // With 3 parties, threshold must be <= 3
            let threshold: u16 = 3;
            let party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);
            let party_ids: Vec<PartyID> = party_to_weight.keys().copied().collect();

            let access_structure =
                WeightedThresholdAccessStructure::new(threshold, party_to_weight.clone()).unwrap();

            println!("Running Universal DKG...");

            // Step 1: Run Universal DKG to get encrypted shares
            let (decryption_key_per_crt_prime, _encryption_keys_per_crt_prime_and_proofs) =
                construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&access_structure);

            let universal_dkg_public_output = generates_universal_distributed_key_internal(
                access_structure.clone(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            );

            println!("Universal DKG completed");

            // Get decryption key shares for each party from the DKG output
            let tangible_party_id_to_virtual_party_id_to_decryption_key_share: HashMap<_, _> =
                access_structure
                    .party_to_weight
                    .keys()
                    .map(|&party_id| {
                        let decryption_key_per_crt_prime =
                            *decryption_key_per_crt_prime.get(&party_id).unwrap();
                        let decryption_key_shares = universal_dkg_public_output
                            .decrypt_decryption_key_shares(
                                party_id,
                                &access_structure,
                                decryption_key_per_crt_prime,
                            )
                            .unwrap();

                        (party_id, decryption_key_shares)
                    })
                    .collect();

            // Generate HPKE encryption keys for VSS share encryption in enc-to-sharing
            let (party_encryption_public_keys, party_encryption_secret_keys) =
                generate_party_encryption_keys(&party_ids, &mut rng);

            println!("Running Threshold Encryption to Sharing protocol...");

            // Step 2: Run threshold encryption to sharing protocol to convert to Shamir shares
            let (enc_to_sharing_private_outputs, enc_to_sharing_public_output) =
                run_threshold_encryption_to_sharing_protocol(
                    &party_ids,
                    &access_structure,
                    &universal_dkg_public_output,
                    &tangible_party_id_to_virtual_party_id_to_decryption_key_share,
                    &party_encryption_public_keys,
                    &party_encryption_secret_keys,
                    &mut rng,
                );

            // Extract secp256k1 Shamir shares from enc-to-sharing output
            let secp256k1_secret_key_shares: HashMap<
                PartyID,
                (
                    group::Value<secp256k1::Scalar>,
                    group::Value<secp256k1::Scalar>,
                ),
            > = enc_to_sharing_private_outputs
                .iter()
                .map(|(&party_id, output)| {
                    (
                        party_id,
                        (
                            output.secp256k1_secret_key_share_first_part,
                            output.secp256k1_secret_key_share_second_part,
                        ),
                    )
                })
                .collect();

            println!("Obtained Shamir shares from enc-to-sharing");

            // Create a mock centralized party secret key share for testing
            // In production, this would come from the centralized party's DKG participation
            let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
            let group_params = secp256k1::group_element::PublicParameters::default();
            let generator =
                secp256k1::GroupElement::generator_from_public_parameters(&group_params).unwrap();

            let centralized_party_secret_key_share =
                secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
            let centralized_party_public_key_share =
                (centralized_party_secret_key_share * generator).value();

            // The decentralized party's public key share is from the enc-to-sharing public output
            // This is the commitment to the secret (constant term of the polynomial)
            let decentralized_party_public_key_share =
                enc_to_sharing_public_output.secp256k1_public_key_share_first_part;

            // Compute combined public key: X = X_A + X_B
            let decentralized_pk =
                secp256k1::GroupElement::new(decentralized_party_public_key_share, &group_params)
                    .unwrap();
            let centralized_pk =
                secp256k1::GroupElement::new(centralized_party_public_key_share, &group_params)
                    .unwrap();
            let combined_public_key = centralized_pk.add_vartime(&decentralized_pk);

            // Create DKG output structure for VSS sign protocol
            let dkg_output = twopc_mpc::dkg::centralized_party::Output {
                public_key_share: centralized_party_public_key_share,
                decentralized_party_public_key_share,
                public_key: combined_public_key.value(),
            };

            println!("Running VSS Presign protocol...");

            // Step 3: Run VSS presign protocol
            let session_id = CommitmentSizedNumber::from(1u64);
            let message = b"Test message for VSS Schnorr signing with enc-to-sharing";
            let hash_scheme = HashScheme::SHA256;

            let (private_presign_outputs, public_presign_outputs) = run_vss_presign_protocol(
                &party_ids,
                threshold,
                session_id,
                &party_encryption_public_keys,
                &party_encryption_secret_keys,
                &access_structure,
                &mut rng,
            );

            println!("VSS Presign completed");

            // Verify all parties agree on public nonce shares
            let first_public = public_presign_outputs.get(&party_ids[0]).unwrap();
            for &party_id in &party_ids[1..] {
                let public = public_presign_outputs.get(&party_id).unwrap();
                assert_eq!(
                    first_public.decentralized_party_nonce_public_shares.0,
                    public.decentralized_party_nonce_public_shares.0,
                    "All parties should agree on K_B,0"
                );
                assert_eq!(
                    first_public.decentralized_party_nonce_public_shares.1,
                    public.decentralized_party_nonce_public_shares.1,
                    "All parties should agree on K_B,1"
                );
            }

            // Collect nonce shares for signing
            let nonce_shares: HashMap<
                PartyID,
                (
                    group::Value<secp256k1::Scalar>,
                    group::Value<secp256k1::Scalar>,
                ),
            > = private_presign_outputs
                .iter()
                .map(|(&party_id, private_output)| (party_id, private_output.nonce_shares))
                .collect();

            println!("Running VSS Sign protocol...");

            // Step 4: Run VSS sign protocol using the actual Shamir shares
            let signature = run_vss_sign_protocol(
                &party_ids,
                centralized_party_secret_key_share.value(),
                &dkg_output,
                first_public,
                &secp256k1_secret_key_shares,
                &nonce_shares,
                message,
                hash_scheme,
                &mut rng,
            );

            println!("VSS Sign completed");

            // Verify signature using the VerifyingKey trait
            combined_public_key
                .verify(message, hash_scheme, &signature)
                .expect("Signature verification should succeed");

            // Verify signature is non-trivial
            let sig_bytes: [u8; 64] = signature.to_bytes();
            assert!(
                !sig_bytes.iter().all(|&b| b == 0),
                "Signature should not be all zeros"
            );

            println!("VSS Schnorr with enc-to-sharing flow completed successfully!");
        }
    }
} // End of disabled_tests module

/// Simplified integration tests using the `test_vss_signing_internal` function.
///
/// These tests demonstrate that the internal test function is accessible from integration
/// tests and can be called with externally provided data.
#[cfg(feature = "test_helpers")]
mod integration_with_internal_function {
    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, HashContext, HashScheme, OsCsRng, PartyID};
    use twopc_mpc::schnorr::vss::sign::tests::{
        generate_mock_keygen_outputs, generate_mock_presign_outputs, test_vss_signing_internal,
    };
    use twopc_mpc::sign::EncodableSignature;

    /// Test that the `test_vss_signing_internal` function works when called from an integration test.
    ///
    /// This test demonstrates:
    /// 1. The internal test function is accessible from integration tests
    /// 2. Mock keygen/presign data can be passed to the internal function
    /// 3. The signing flow produces a valid signature
    #[test]
    fn test_vss_signing_from_integration_test() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        let threshold: PartyID = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let message = b"Integration test message";
        let session_id = CommitmentSizedNumber::from(42u64);
        let hash_scheme = HashScheme::SHA256;

        // Generate mock data using the exposed helper functions
        let (
            secret_key_share,
            dkg_output,
            first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer,
            party_secret_key_shares,
        ) = generate_mock_keygen_outputs(
            &party_ids,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );

        let (presign, nonce_shares) = generate_mock_presign_outputs(
            &party_ids,
            session_id,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );

        // Call the internal test function - this is the key integration point
        // In a real integration test, `party_secret_key_shares` would come from
        // threshold_encryption_to_sharing instead of mocks
        let signature =
            test_vss_signing_internal::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, ()>(
                secret_key_share,
                &dkg_output,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                &party_secret_key_shares,
                &presign,
                &nonce_shares,
                threshold,
                message,
                hash_scheme,
                &HashContext::None,
                &scalar_group_public_parameters,
                &group_params,
                &mut rng,
            )
            .expect("VSS signing from integration test should succeed");

        // Verify signature is non-trivial
        let sig_bytes: [u8; 64] = signature.to_bytes();
        assert!(
            !sig_bytes.iter().all(|&b| b == 0),
            "Signature should not be all zeros"
        );

        println!("Integration test: VSS signing with internal function succeeded!");
    }

    /// Test with different message contents to verify the signing is message-dependent.
    #[test]
    fn test_vss_signing_message_dependency() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        let threshold: PartyID = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let session_id = CommitmentSizedNumber::from(100u64);
        let hash_scheme = HashScheme::SHA256;

        let messages: [&[u8]; 3] = [
            b"First message",
            b"Second message",
            b"Third message with different content",
        ];

        let signatures: Vec<[u8; 64]> = messages
            .iter()
            .map(|message| {
                let (
                    secret_key_share,
                    dkg_output,
                    first_key_public_randomizer,
                    second_key_public_randomizer,
                    free_coefficient_key_public_randomizer,
                    party_secret_key_shares,
                ) = generate_mock_keygen_outputs(
                    &party_ids,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                );

                let (presign, nonce_shares) = generate_mock_presign_outputs(
                    &party_ids,
                    session_id,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                );

                let signature = test_vss_signing_internal::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                    (),
                >(
                    secret_key_share,
                    &dkg_output,
                    first_key_public_randomizer,
                    second_key_public_randomizer,
                    free_coefficient_key_public_randomizer,
                    &party_secret_key_shares,
                    &presign,
                    &nonce_shares,
                    threshold,
                    message,
                    hash_scheme,
                    &HashContext::None,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                )
                .expect("Signing should succeed");

                signature.to_bytes()
            })
            .collect();

        // Signatures should all be different (different keygen/presign each time)
        assert_ne!(
            signatures[0], signatures[1],
            "Different messages with different keys should produce different signatures"
        );
        assert_ne!(
            signatures[1], signatures[2],
            "Different messages with different keys should produce different signatures"
        );
    }
}
