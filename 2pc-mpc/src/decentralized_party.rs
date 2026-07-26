// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub mod dkg;
pub mod reconfiguration;
pub mod threshold_encryption_of_secret_key_share_parts_to_sharing;

#[cfg(test)]
mod tests {
    use crate::decentralized_party::dkg::tests::generates_universal_distributed_key_internal;
    use crate::decentralized_party::reconfiguration;
    use crate::decentralized_party::reconfiguration::tests::reconfigures_internal_internal;
    use crate::sign::tests::{
        construct_decentralized_ecdsa_sign_party_public_inputs_class_groups,
        construct_decentralized_schnorr_sign_party_public_inputs_class_groups,
        dkg_presign_signs_internal, dkg_presign_signs_vss_internal_internal,
        presign_signs_internal, verify_eddsa_signature, verify_schnorrkel_signature,
        verify_secp256k1_ecdsa_signature, verify_secp256r1_ecdsa_signature,
        verify_taproot_signature, SignDataMode, MESSAGE,
    };
    use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::generate_and_prove_encryption_keypair;
    use class_groups::setup::DeriveFromPlaintextPublicParameters;
    use class_groups::{
        Curve25519EncryptionKey, RistrettoEncryptionKey, RistrettoSetupParameters,
        Secp256k1EncryptionKey, Secp256k1SetupParameters, Secp256r1EncryptionKey,
        Secp256r1SetupParameters, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    };
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::Random;
    use group::{
        curve25519, ristretto, secp256k1, secp256r1, GroupElement as GroupElementTrait,
        HashContext, HashScheme, OsCsRng, PartyID,
    };
    use mpc::WeightedThresholdAccessStructure;
    use std::collections::HashMap;
    use std::sync::Arc;

    // INSECURE `unsafe_mock`: this end-to-end exercises the real network-key machinery (PVSS
    // dealings, Shamir share reconstruction across reconfiguration, polynomial commitments) —
    // exactly the structures the network mocks stub out with empty/neutral values.
    #[cfg(not(feature = "unsafe_mock"))]
    #[test]
    fn dkgs_reconfigures_signs() {
        // Using uniform weight=1 for all parties
        let epoch1_threshold = 3;
        let epoch1_number_of_parties = 5;

        let epoch1_access_structure = WeightedThresholdAccessStructure::uniform(
            epoch1_threshold,
            epoch1_number_of_parties,
            epoch1_number_of_parties,
            &mut OsCsRng,
        )
        .unwrap();
        let epoch2_threshold = 4;
        let epoch2_number_of_parties = 6;
        let epoch2_access_structure = WeightedThresholdAccessStructure::uniform(
            epoch2_threshold,
            epoch2_number_of_parties,
            epoch2_number_of_parties,
            &mut OsCsRng,
        )
        .unwrap();

        let (epoch1_decryption_key_per_crt_prime, epoch1_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch1_access_structure);

        let (epoch2_decryption_key_per_crt_prime, epoch2_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch2_access_structure);

        // Parties 1-5 from epoch1 map to parties 1-5 in epoch2; party 6 is new (no previous state)
        let epoch1_tangible_party_id_to_epoch2: HashMap<PartyID, Option<PartyID>> = (1
            ..=epoch1_number_of_parties)
            .map(|party_id| (party_id, Some(party_id)))
            .collect();

        // Generate PVSS setup parameters (shared between epoch1 and epoch2)
        let secp256k1_setup_parameters_for_pvss =
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let ristretto_setup_parameters_for_pvss =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let secp256r1_setup_parameters_for_pvss =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        // Generate epoch1 PVSS encryption/decryption keys
        let epoch1_pvss_keys: Vec<_> = epoch1_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| {
                let secp256k1 = generate_and_prove_encryption_keypair::<
                    { secp256k1::SCALAR_LIMBS },
                    { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U1024::LIMBS },
                    { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U4096::LIMBS },
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    secp256k1::GroupElement,
                >(&secp256k1_setup_parameters_for_pvss, &mut OsCsRng)
                .unwrap();

                let ristretto = generate_and_prove_encryption_keypair::<
                    { ristretto::SCALAR_LIMBS },
                    { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U1024::LIMBS },
                    { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U4096::LIMBS },
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    ristretto::GroupElement,
                >(&ristretto_setup_parameters_for_pvss, &mut OsCsRng)
                .unwrap();

                let secp256r1 = generate_and_prove_encryption_keypair::<
                    { secp256r1::SCALAR_LIMBS },
                    { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U1024::LIMBS },
                    { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U4096::LIMBS },
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    secp256r1::GroupElement,
                >(&secp256r1_setup_parameters_for_pvss, &mut OsCsRng)
                .unwrap();

                (party_id, secp256k1, ristretto, secp256r1)
            })
            .collect();

        let (
            epoch1_secp256k1_pvss_encryption_keys_and_proofs,
            epoch1_secp256k1_pvss_decryption_keys,
            epoch1_ristretto_pvss_encryption_keys_and_proofs,
            epoch1_ristretto_pvss_decryption_keys,
            epoch1_secp256r1_pvss_encryption_keys_and_proofs,
            _epoch1_secp256r1_pvss_decryption_keys,
        ): (
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
        ) = itertools::multiunzip(epoch1_pvss_keys.into_iter().map(
            |(
                party_id,
                (secp256k1_enc, secp256k1_proof, secp256k1_dec),
                (ristretto_enc, ristretto_proof, ristretto_dec),
                (secp256r1_enc, secp256r1_proof, secp256r1_dec),
            )| {
                (
                    (party_id, (secp256k1_enc, secp256k1_proof)),
                    (party_id, secp256k1_dec),
                    (party_id, (ristretto_enc, ristretto_proof)),
                    (party_id, ristretto_dec),
                    (party_id, (secp256r1_enc, secp256r1_proof)),
                    (party_id, secp256r1_dec),
                )
            },
        ));

        let universal_dkg_public_output = generates_universal_distributed_key_internal(
            epoch1_access_structure.clone(),
            epoch1_secp256k1_pvss_encryption_keys_and_proofs.clone(),
            epoch1_ristretto_pvss_encryption_keys_and_proofs.clone(),
            epoch1_secp256r1_pvss_encryption_keys_and_proofs.clone(),
        );

        let epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share: HashMap<_, _> =
            epoch1_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let decryption_key_per_crt_prime =
                        *epoch1_decryption_key_per_crt_prime.get(&party_id).unwrap();
                    let decryption_key_shares = universal_dkg_public_output
                        .decrypt_decryption_key_shares(
                            party_id,
                            &epoch1_access_structure,
                            decryption_key_per_crt_prime,
                        )
                        .unwrap();

                    (party_id, decryption_key_shares)
                })
                .collect();

        let epoch1_secp256k1_decryption_key_share_public_parameters = universal_dkg_public_output
            .secp256k1_decryption_key_share_public_parameters(&epoch1_access_structure)
            .unwrap();
        let secp256k1_protocol_public_parameters = universal_dkg_public_output
            .secp256k1_protocol_public_parameters()
            .unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        // AHE presign uses () as private input
        let presign_private_inputs: HashMap<PartyID, ()> = epoch1_access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| (party_id, ()))
            .collect();

        let (
            secp256k1_centralized_party_dkg_output,
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output,
        ) = dkg_presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
            class_groups::Secp256k1DecryptionKeySharePublicParameters,
            _,
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            epoch1_secp256k1_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            construct_decentralized_ecdsa_sign_party_public_inputs_class_groups::<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::MESSAGE_LIMBS },
                secp256k1::GroupElement,
            >,
            secp256k1_protocol_public_parameters.clone(),
            presign_private_inputs.clone(),
            false,
            4, // ECDSA presign has 4 rounds
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
            SignDataMode::Unverified,
        );

        let epoch1_ristretto_decryption_key_share_public_parameters = universal_dkg_public_output
            .ristretto_decryption_key_share_public_parameters(&epoch1_access_structure)
            .unwrap();
        let ristretto_protocol_public_parameters = universal_dkg_public_output
            .ristretto_protocol_public_parameters()
            .unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let (
            ristretto_centralized_party_dkg_output,
            ristretto_centralized_party_secret_key_share,
            ristretto_decentralized_party_dkg_output,
        ) = dkg_presign_signs_internal::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            crate::ristretto::class_groups::SchnorrkelProtocol,
            class_groups::RistrettoDecryptionKeySharePublicParameters,
            _,
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::Merlin,
            HashContext::Schnorrkel {
                signing_context: b"substrate".to_vec(),
            },
            epoch1_ristretto_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            construct_decentralized_schnorr_sign_party_public_inputs_class_groups::<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
            ristretto_protocol_public_parameters.clone(),
            presign_private_inputs.clone(),
            false,
            2, // Schnorr presign has 2 rounds
            "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)".to_string(),
            SignDataMode::Unverified,
        );

        let epoch1_curve25519_decryption_key_share_public_parameters = universal_dkg_public_output
            .curve25519_decryption_key_share_public_parameters(&epoch1_access_structure)
            .unwrap();
        let curve25519_protocol_public_parameters = universal_dkg_public_output
            .curve25519_protocol_public_parameters()
            .unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let (
            curve25519_centralized_party_dkg_output,
            curve25519_centralized_party_secret_key_share,
            curve25519_decentralized_party_dkg_output,
        ) = dkg_presign_signs_internal::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
            crate::curve25519::class_groups::EdDSAProtocol,
            class_groups::Curve25519DecryptionKeySharePublicParameters,
            _,
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::SHA512,
            HashContext::None,
            epoch1_curve25519_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            construct_decentralized_schnorr_sign_party_public_inputs_class_groups::<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
            curve25519_protocol_public_parameters.clone(),
            presign_private_inputs.clone(),
            false,
            2, // Schnorr presign has 2 rounds
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)".to_string(),
            SignDataMode::Unverified,
        );

        let epoch1_secp256r1_decryption_key_share_public_parameters = universal_dkg_public_output
            .secp256r1_decryption_key_share_public_parameters(&epoch1_access_structure)
            .unwrap();
        let secp256r1_protocol_public_parameters = universal_dkg_public_output
            .secp256r1_protocol_public_parameters()
            .unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let (
            secp256r1_centralized_party_dkg_output,
            secp256r1_centralized_party_secret_key_share,
            secp256r1_decentralized_party_dkg_output,
        ) = dkg_presign_signs_internal::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            crate::secp256r1::class_groups::ECDSAProtocol,
            class_groups::Secp256r1DecryptionKeySharePublicParameters,
            _,
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            epoch1_secp256r1_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_secp256r1_ecdsa_signature,
            construct_decentralized_ecdsa_sign_party_public_inputs_class_groups::<
                { secp256r1::SCALAR_LIMBS },
                { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256r1::MESSAGE_LIMBS },
                secp256r1::GroupElement,
            >,
            secp256r1_protocol_public_parameters.clone(),
            presign_private_inputs.clone(),
            false,
            4, // ECDSA presign has 4 rounds
            "Class Groups Asynchronous ECDSA secp256r1".to_string(),
            SignDataMode::Unverified,
        );

        // ===== Epoch1 VSS signing directly from DKG output =====
        // Derive Shamir shares from the DKG's threshold_encryption_to_sharing_output
        // without needing self-reconfiguration.

        let dkg_secp256k1_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<secp256k1::Scalar>,
                group::Value<secp256k1::Scalar>,
            ),
        > = epoch1_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| {
                let (first_part, second_part) = universal_dkg_public_output
                    .derive_shamir_shares_of_secp256k1_secret_key_share_parts(
                        party_id,
                        *epoch1_secp256k1_pvss_decryption_keys
                            .get(&party_id)
                            .unwrap(),
                        epoch1_secp256k1_pvss_encryption_keys_and_proofs
                            .get(&party_id)
                            .unwrap()
                            .0,
                    )
                    .expect("derive secp256k1 shamir shares should succeed");

                (party_id, (first_part, second_part))
            })
            .collect();

        let secp256k1_protocol_public_parameters = Arc::new(secp256k1_protocol_public_parameters);
        dkg_presign_signs_vss_internal_internal::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
            crate::secp256k1::vss::TaprootVSSProtocol,
        >(
            epoch1_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            MESSAGE.as_bytes(),
            verify_taproot_signature,
            "VSS Taproot secp256k1 (post-DKG, no reconfiguration)",
            (*secp256k1_protocol_public_parameters).clone(),
            dkg_secp256k1_secret_key_shares,
            universal_dkg_public_output
                .threshold_encryption_to_sharing_output
                .secp256k1_first_secret_polynomial_commitments
                .clone(),
            universal_dkg_public_output
                .threshold_encryption_to_sharing_output
                .secp256k1_second_secret_polynomial_commitments
                .clone(),
            SignDataMode::Unverified,
        );

        let dkg_ristretto_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<ristretto::Scalar>,
                group::Value<ristretto::Scalar>,
            ),
        > = epoch1_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| {
                let (first_part, second_part) = universal_dkg_public_output
                    .derive_shamir_shares_of_ristretto_secret_key_share_parts(
                        party_id,
                        *epoch1_ristretto_pvss_decryption_keys
                            .get(&party_id)
                            .unwrap(),
                        epoch1_ristretto_pvss_encryption_keys_and_proofs
                            .get(&party_id)
                            .unwrap()
                            .0,
                    )
                    .expect("derive ristretto shamir shares should succeed");

                (party_id, (first_part, second_part))
            })
            .collect();

        let ristretto_protocol_public_parameters = Arc::new(ristretto_protocol_public_parameters);
        dkg_presign_signs_vss_internal_internal::<
            { ristretto::SCALAR_LIMBS },
            { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            ristretto::GroupElement,
            crate::ristretto::vss::SchnorrkelVSSProtocol,
        >(
            epoch1_access_structure.clone(),
            HashScheme::Merlin,
            HashContext::Schnorrkel {
                signing_context: b"substrate".to_vec(),
            },
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            "VSS Schnorrkel ristretto (post-DKG, no reconfiguration)",
            (*ristretto_protocol_public_parameters).clone(),
            dkg_ristretto_secret_key_shares,
            universal_dkg_public_output
                .threshold_encryption_to_sharing_output
                .ristretto_first_secret_polynomial_commitments
                .clone(),
            universal_dkg_public_output
                .threshold_encryption_to_sharing_output
                .ristretto_second_secret_polynomial_commitments
                .clone(),
            SignDataMode::Unverified,
        );

        let dkg_curve25519_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<curve25519::Scalar>,
                group::Value<curve25519::Scalar>,
            ),
        > = epoch1_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| {
                let (first_part, second_part) = universal_dkg_public_output
                    .derive_shamir_shares_of_curve25519_secret_key_share_parts(
                        party_id,
                        *epoch1_ristretto_pvss_decryption_keys
                            .get(&party_id)
                            .unwrap(),
                        epoch1_ristretto_pvss_encryption_keys_and_proofs
                            .get(&party_id)
                            .unwrap()
                            .0,
                    )
                    .expect("derive curve25519 shamir shares should succeed");

                (party_id, (first_part, second_part))
            })
            .collect();

        let curve25519_protocol_public_parameters = Arc::new(curve25519_protocol_public_parameters);
        dkg_presign_signs_vss_internal_internal::<
            { curve25519::SCALAR_LIMBS },
            { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            curve25519::GroupElement,
            crate::curve25519::vss::EdDSAVSSProtocol,
        >(
            epoch1_access_structure.clone(),
            HashScheme::SHA512,
            HashContext::None,
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            "VSS EdDSA curve25519 (post-DKG, no reconfiguration)",
            (*curve25519_protocol_public_parameters).clone(),
            dkg_curve25519_secret_key_shares,
            universal_dkg_public_output
                .threshold_encryption_to_sharing_output
                .curve25519_first_secret_polynomial_commitments
                .clone(),
            universal_dkg_public_output
                .threshold_encryption_to_sharing_output
                .curve25519_second_secret_polynomial_commitments
                .clone(),
            SignDataMode::Unverified,
        );

        // ===== Epoch1 VSS signing via self-reconfiguration =====
        // Self-reconfiguration: epoch1→epoch1 (identity mapping)
        let epoch1_identity_mapping: HashMap<PartyID, Option<PartyID>> = (1
            ..=epoch1_number_of_parties)
            .map(|party_id| (party_id, Some(party_id)))
            .collect();

        let epoch1_self_reconfiguration_public_input =
            reconfiguration::PublicInput::new_from_dkg_output(
                &epoch1_access_structure,
                epoch1_access_structure.clone(),
                epoch1_encryption_keys_per_crt_prime_and_proofs.clone(),
                epoch1_encryption_keys_per_crt_prime_and_proofs.clone(),
                epoch1_identity_mapping,
                universal_dkg_public_output.core.clone(),
                epoch1_secp256k1_pvss_encryption_keys_and_proofs.clone(),
                epoch1_ristretto_pvss_encryption_keys_and_proofs.clone(),
                epoch1_secp256r1_pvss_encryption_keys_and_proofs.clone(),
            )
            .unwrap();

        let epoch1_self_reconfiguration_private_inputs: HashMap<_, _> =
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share
                .iter()
                .map(|(&party_id, decryption_key_shares)| (party_id, decryption_key_shares.clone()))
                .collect();

        let epoch1_self_reconfiguration_output = reconfigures_internal_internal(
            CommitmentSizedNumber::random(&mut OsCsRng),
            epoch1_access_structure.clone(),
            epoch1_self_reconfiguration_private_inputs,
            epoch1_self_reconfiguration_public_input,
            false,
        );

        // Derive epoch1 Shamir shares for secp256k1 VSS signing
        let epoch1_secp256k1_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<secp256k1::Scalar>,
                group::Value<secp256k1::Scalar>,
            ),
        > =
            epoch1_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let (first_part, second_part) = epoch1_self_reconfiguration_output
                    .compute_secp256k1_shamir_shares_of_secret_key_share_parts(
                        party_id,
                        *epoch1_secp256k1_pvss_decryption_keys.get(&party_id).unwrap(),
                        epoch1_secp256k1_pvss_encryption_keys_and_proofs.get(&party_id).unwrap().0,
                    )
                    .expect(
                        "compute_secp256k1_shamir_shares_of_secret_key_share_parts should succeed",
                    );

                    (party_id, (first_part, second_part))
                })
                .collect();

        let (
            epoch1_secp256k1_first_polynomial_commitments,
            epoch1_secp256k1_second_polynomial_commitments,
        ) = epoch1_self_reconfiguration_output.secp256k1_polynomial_commitments();

        // Epoch1 secp256k1 Taproot VSS signing
        dkg_presign_signs_vss_internal_internal::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
            crate::secp256k1::vss::TaprootVSSProtocol,
        >(
            epoch1_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            MESSAGE.as_bytes(),
            verify_taproot_signature,
            "VSS Taproot secp256k1 (post-DKG epoch1)",
            (*secp256k1_protocol_public_parameters).clone(),
            epoch1_secp256k1_secret_key_shares,
            epoch1_secp256k1_first_polynomial_commitments.to_vec(),
            epoch1_secp256k1_second_polynomial_commitments.to_vec(),
            SignDataMode::Unverified,
        );

        // Derive epoch1 Shamir shares for ristretto VSS signing
        let epoch1_ristretto_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<ristretto::Scalar>,
                group::Value<ristretto::Scalar>,
            ),
        > =
            epoch1_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let (first_part, second_part) = epoch1_self_reconfiguration_output
                    .compute_ristretto_shamir_shares_of_secret_key_share_parts(
                        party_id,
                        *epoch1_ristretto_pvss_decryption_keys.get(&party_id).unwrap(),
                        epoch1_ristretto_pvss_encryption_keys_and_proofs.get(&party_id).unwrap().0,
                    )
                    .expect(
                        "compute_ristretto_shamir_shares_of_secret_key_share_parts should succeed",
                    );

                    (party_id, (first_part, second_part))
                })
                .collect();

        let (
            epoch1_ristretto_first_polynomial_commitments,
            epoch1_ristretto_second_polynomial_commitments,
        ) = epoch1_self_reconfiguration_output.ristretto_polynomial_commitments();

        // Epoch1 ristretto Schnorrkel VSS signing
        dkg_presign_signs_vss_internal_internal::<
            { ristretto::SCALAR_LIMBS },
            { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            ristretto::GroupElement,
            crate::ristretto::vss::SchnorrkelVSSProtocol,
        >(
            epoch1_access_structure.clone(),
            HashScheme::Merlin,
            HashContext::Schnorrkel {
                signing_context: b"substrate".to_vec(),
            },
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            "VSS Schnorrkel ristretto (post-DKG epoch1)",
            (*ristretto_protocol_public_parameters).clone(),
            epoch1_ristretto_secret_key_shares,
            epoch1_ristretto_first_polynomial_commitments.to_vec(),
            epoch1_ristretto_second_polynomial_commitments.to_vec(),
            SignDataMode::Unverified,
        );

        // Derive epoch1 Shamir shares for curve25519 VSS signing
        let epoch1_curve25519_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<curve25519::Scalar>,
                group::Value<curve25519::Scalar>,
            ),
        > =
            epoch1_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let (first_part, second_part) = epoch1_self_reconfiguration_output
                    .compute_curve25519_shamir_shares_of_secret_key_share_parts(
                        party_id,
                        *epoch1_ristretto_pvss_decryption_keys.get(&party_id).unwrap(),
                        epoch1_ristretto_pvss_encryption_keys_and_proofs.get(&party_id).unwrap().0,
                    )
                    .expect(
                        "compute_curve25519_shamir_shares_of_secret_key_share_parts should succeed",
                    );

                    (party_id, (first_part, second_part))
                })
                .collect();

        let (
            epoch1_curve25519_first_polynomial_commitments,
            epoch1_curve25519_second_polynomial_commitments,
        ) = epoch1_self_reconfiguration_output.curve25519_polynomial_commitments();

        // Epoch1 curve25519 EdDSA VSS signing
        dkg_presign_signs_vss_internal_internal::<
            { curve25519::SCALAR_LIMBS },
            { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            curve25519::GroupElement,
            crate::curve25519::vss::EdDSAVSSProtocol,
        >(
            epoch1_access_structure.clone(),
            HashScheme::SHA512,
            HashContext::None,
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            "VSS EdDSA curve25519 (post-DKG epoch1)",
            (*curve25519_protocol_public_parameters).clone(),
            epoch1_curve25519_secret_key_shares,
            epoch1_curve25519_first_polynomial_commitments.to_vec(),
            epoch1_curve25519_second_polynomial_commitments.to_vec(),
            SignDataMode::Unverified,
        );

        // ===== Epoch2 reconfiguration and signing =====

        // Generate PVSS encryption/decryption keys for epoch2 parties
        let pvss_keys: Vec<_> = epoch2_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| {
                let secp256k1 = generate_and_prove_encryption_keypair::<
                    { secp256k1::SCALAR_LIMBS },
                    { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U1024::LIMBS },
                    { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U4096::LIMBS },
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    secp256k1::GroupElement,
                >(&secp256k1_setup_parameters_for_pvss, &mut OsCsRng)
                .unwrap();

                let ristretto = generate_and_prove_encryption_keypair::<
                    { ristretto::SCALAR_LIMBS },
                    { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U1024::LIMBS },
                    { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U4096::LIMBS },
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    ristretto::GroupElement,
                >(&ristretto_setup_parameters_for_pvss, &mut OsCsRng)
                .unwrap();

                let secp256r1 = generate_and_prove_encryption_keypair::<
                    { secp256r1::SCALAR_LIMBS },
                    { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U1024::LIMBS },
                    { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U4096::LIMBS },
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    secp256r1::GroupElement,
                >(&secp256r1_setup_parameters_for_pvss, &mut OsCsRng)
                .unwrap();

                (party_id, secp256k1, ristretto, secp256r1)
            })
            .collect();

        let (
            secp256k1_pvss_encryption_keys_and_proofs,
            secp256k1_pvss_decryption_keys,
            ristretto_pvss_encryption_keys_and_proofs,
            ristretto_pvss_decryption_keys,
            secp256r1_pvss_encryption_keys_and_proofs,
            secp256r1_pvss_decryption_keys,
        ): (
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
        ) = itertools::multiunzip(pvss_keys.into_iter().map(
            |(
                party_id,
                (secp256k1_enc, secp256k1_proof, secp256k1_dec),
                (ristretto_enc, ristretto_proof, ristretto_dec),
                (secp256r1_enc, secp256r1_proof, secp256r1_dec),
            )| {
                (
                    (party_id, (secp256k1_enc, secp256k1_proof)),
                    (party_id, secp256k1_dec),
                    (party_id, (ristretto_enc, ristretto_proof)),
                    (party_id, ristretto_dec),
                    (party_id, (secp256r1_enc, secp256r1_proof)),
                    (party_id, secp256r1_dec),
                )
            },
        ));

        // Capture the (reconfiguration-invariant) class-group DKG output — the decentralized
        // party's threshold encryption key — before the DKG output's core is consumed below.
        let universal_class_group_dkg_output = universal_dkg_public_output.class_group_dkg_output();

        let reconfiguration_public_input = reconfiguration::PublicInput::new_from_dkg_output(
            &epoch1_access_structure,
            epoch2_access_structure.clone(),
            epoch1_encryption_keys_per_crt_prime_and_proofs,
            epoch2_encryption_keys_per_crt_prime_and_proofs.clone(),
            epoch1_tangible_party_id_to_epoch2.clone(),
            universal_dkg_public_output.core,
            secp256k1_pvss_encryption_keys_and_proofs.clone(),
            ristretto_pvss_encryption_keys_and_proofs.clone(),
            secp256r1_pvss_encryption_keys_and_proofs.clone(),
        )
        .unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        // Convert to new PrivateInput struct format
        let epoch1_reconfiguration_private_inputs: HashMap<_, _> =
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share
                .into_iter()
                .collect();

        let reconfiguration_public_output = reconfigures_internal_internal(
            session_id,
            epoch1_access_structure.clone(),
            epoch1_reconfiguration_private_inputs,
            reconfiguration_public_input,
            false,
        );

        // The reconfiguration output drops the per-CRT-prime threshold encryption data, retaining
        // only the invariant class-group encryption key. Reconstruct the decentralized party DKG
        // output for the upcoming (epoch2) committee by combining the original class-group DKG
        // output with the reconfiguration output, then verify the class-group threshold encryption
        // key round-trips unchanged and the per-curve data is threaded through from the
        // reconfiguration output.
        assert_eq!(
            reconfiguration_public_output.secp256k1_encryption_key(),
            universal_class_group_dkg_output.encryption_key,
            "the class-group encryption key is invariant across reconfiguration",
        );
        let reconstructed_dkg_output =
            crate::decentralized_party::dkg::PublicOutput::new_from_reconfiguration_output(
                universal_class_group_dkg_output.clone(),
                reconfiguration_public_output.clone(),
            )
            .unwrap();
        assert_eq!(
            reconstructed_dkg_output.class_group_dkg_output(),
            universal_class_group_dkg_output,
        );
        assert_eq!(
            reconstructed_dkg_output.secp256k1_public_key_share_first_part,
            reconfiguration_public_output.secp256k1_public_key_share_first_part,
        );
        assert_eq!(
            reconstructed_dkg_output.ristretto_public_key_share_second_part,
            reconfiguration_public_output.ristretto_public_key_share_second_part,
        );
        assert_eq!(
            reconstructed_dkg_output.secp256r1_public_key_share_first_part,
            reconfiguration_public_output.secp256r1_public_key_share_first_part,
        );

        let epoch2_secp256k1_decryption_key_share_public_parameters = reconfiguration_public_output
            .secp256k1_decryption_key_share_public_parameters(&epoch2_access_structure)
            .unwrap();

        let epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share: HashMap<_, _> =
            epoch2_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let decryption_key_shares = reconfiguration_public_output
                        .decrypt_decryption_key_shares(
                            party_id,
                            &epoch2_access_structure,
                            *epoch2_decryption_key_per_crt_prime.get(&party_id).unwrap(),
                        )
                        .unwrap();

                    (party_id, decryption_key_shares)
                })
                .collect();

        let secp256k1_dkg_output = match secp256k1_decentralized_party_dkg_output.clone() {
            crate::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(
                dkg_output,
            ) => Some(dkg_output),
            crate::dkg::decentralized_party::VersionedOutput::UniversalPublicDKGOutput {
                ..
            } => None,
        };

        // AHE presign uses () as private input
        let epoch2_presign_private_inputs: HashMap<PartyID, ()> = epoch2_access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| (party_id, ()))
            .collect();

        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
            class_groups::Secp256k1DecryptionKeySharePublicParameters,
            _,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            secp256k1_centralized_party_dkg_output.clone(),
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output.clone(),
            epoch2_secp256k1_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            construct_decentralized_ecdsa_sign_party_public_inputs_class_groups::<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::MESSAGE_LIMBS },
                secp256k1::GroupElement,
            >,
            secp256k1_protocol_public_parameters.clone(),
            crate::ecdsa::presign::decentralized_party::PublicInput {
                protocol_public_parameters: secp256k1_protocol_public_parameters.clone(),
                dkg_output: secp256k1_dkg_output.clone(),
            },
            epoch2_presign_private_inputs.clone(),
            4, // ECDSA presign has 4 rounds
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
            SignDataMode::Unverified,
        );

        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::TaprootProtocol,
            class_groups::Secp256k1DecryptionKeySharePublicParameters,
            _,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            secp256k1_centralized_party_dkg_output.clone(),
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output.clone(),
            epoch2_secp256k1_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_taproot_signature,
            construct_decentralized_schnorr_sign_party_public_inputs_class_groups::<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            secp256k1_protocol_public_parameters.clone(),
            crate::schnorr::ahe::presign::decentralized_party::PublicInput {
                protocol_public_parameters: secp256k1_protocol_public_parameters.clone(),
            },
            epoch2_presign_private_inputs.clone(),
            2, // Schnorr presign has 2 rounds
            "Class Groups Asynchronous Schnorr secp256k1 (Taproot)".to_string(),
            SignDataMode::Unverified,
        );

        let epoch2_ristretto_decryption_key_share_public_parameters = reconfiguration_public_output
            .ristretto_decryption_key_share_public_parameters(&epoch2_access_structure)
            .unwrap();

        presign_signs_internal::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            crate::ristretto::class_groups::SchnorrkelProtocol,
            class_groups::RistrettoDecryptionKeySharePublicParameters,
            _,
        >(
            epoch2_access_structure.clone(),
            HashScheme::Merlin,
            HashContext::Schnorrkel {
                signing_context: b"substrate".to_vec(),
            },
            ristretto_centralized_party_dkg_output.clone(),
            ristretto_centralized_party_secret_key_share,
            ristretto_decentralized_party_dkg_output.clone(),
            epoch2_ristretto_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            construct_decentralized_schnorr_sign_party_public_inputs_class_groups::<
                { ristretto::SCALAR_LIMBS },
                { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                ristretto::GroupElement,
            >,
            ristretto_protocol_public_parameters.clone(),
            crate::schnorr::ahe::presign::decentralized_party::PublicInput {
                protocol_public_parameters: ristretto_protocol_public_parameters.clone(),
            },
            epoch2_presign_private_inputs.clone(),
            2, // Schnorr presign has 2 rounds
            "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)".to_string(),
            SignDataMode::Unverified,
        );

        let epoch2_curve25519_decryption_key_share_public_parameters =
            reconfiguration_public_output
                .curve25519_decryption_key_share_public_parameters(&epoch2_access_structure)
                .unwrap();

        presign_signs_internal::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
            crate::curve25519::class_groups::EdDSAProtocol,
            class_groups::Curve25519DecryptionKeySharePublicParameters,
            _,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA512,
            HashContext::None,
            curve25519_centralized_party_dkg_output.clone(),
            curve25519_centralized_party_secret_key_share,
            curve25519_decentralized_party_dkg_output.clone(),
            epoch2_curve25519_decryption_key_share_public_parameters.clone(),
            {
                let keys =
                    epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            construct_decentralized_schnorr_sign_party_public_inputs_class_groups::<
                { curve25519::SCALAR_LIMBS },
                { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                curve25519::GroupElement,
            >,
            curve25519_protocol_public_parameters.clone(),
            crate::schnorr::ahe::presign::decentralized_party::PublicInput {
                protocol_public_parameters: curve25519_protocol_public_parameters.clone(),
            },
            epoch2_presign_private_inputs.clone(),
            2, // Schnorr presign has 2 rounds
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)".to_string(),
            SignDataMode::Unverified,
        );

        let epoch2_secp256r1_decryption_key_share_public_parameters = reconfiguration_public_output
            .secp256r1_decryption_key_share_public_parameters(&epoch2_access_structure)
            .unwrap();

        let secp256r1_dkg_output = match secp256r1_decentralized_party_dkg_output.clone() {
            crate::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(
                dkg_output,
            ) => Some(dkg_output),
            crate::dkg::decentralized_party::VersionedOutput::UniversalPublicDKGOutput {
                ..
            } => None,
        };

        let secp256r1_protocol_public_parameters = Arc::new(secp256r1_protocol_public_parameters);

        presign_signs_internal::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            crate::secp256r1::class_groups::ECDSAProtocol,
            class_groups::Secp256r1DecryptionKeySharePublicParameters,
            _,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            secp256r1_centralized_party_dkg_output,
            secp256r1_centralized_party_secret_key_share,
            secp256r1_decentralized_party_dkg_output,
            epoch2_secp256r1_decryption_key_share_public_parameters,
            {
                let keys =
                    epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_secp256r1_ecdsa_signature,
            construct_decentralized_ecdsa_sign_party_public_inputs_class_groups::<
                { secp256r1::SCALAR_LIMBS },
                { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256r1::MESSAGE_LIMBS },
                secp256r1::GroupElement,
            >,
            secp256r1_protocol_public_parameters.clone(),
            crate::ecdsa::presign::decentralized_party::PublicInput {
                protocol_public_parameters: secp256r1_protocol_public_parameters.clone(),
                dkg_output: secp256r1_dkg_output,
            },
            epoch2_presign_private_inputs.clone(),
            4, // ECDSA presign has 4 rounds
            "Class Groups Asynchronous ECDSA secp256r1".to_string(),
            SignDataMode::Unverified,
        );

        // Finally, try a trusted dealer setup, which uses the v1 output:
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        dkg_presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
            class_groups::Secp256k1DecryptionKeySharePublicParameters,
            _,
        >(
            session_id,
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            epoch2_secp256k1_decryption_key_share_public_parameters,
            {
                let keys =
                    epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone();
                move |_presign_outputs, _presign| keys.clone()
            },
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            construct_decentralized_ecdsa_sign_party_public_inputs_class_groups::<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::MESSAGE_LIMBS },
                secp256k1::GroupElement,
            >,
            (*secp256k1_protocol_public_parameters).clone(),
            epoch2_presign_private_inputs,
            true,
            4, // ECDSA presign has 4 rounds
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
            SignDataMode::Unverified,
        );

        // Verify that PVSS keys were generated and dealings exist
        assert!(
            !secp256k1_pvss_encryption_keys_and_proofs.is_empty(),
            "PVSS encryption keys should be generated for epoch2 parties"
        );
        assert!(
            !secp256k1_pvss_decryption_keys.is_empty(),
            "PVSS decryption keys should be stored for epoch2 parties"
        );

        // Masked secrets are now always populated after reconfiguration (non-Option fields)

        // Call per-curve decrypt functions for epoch2 parties to verify decryption works
        let secp256k1_group_params = secp256k1::group_element::PublicParameters::default();

        // Verify secp256r1 decryption works (secp256r1 uses AHE, not VSS, so just validation)
        for &party_id in epoch2_access_structure.party_to_weight.keys() {
            // Decrypt secp256r1 shares
            let _ = reconfiguration_public_output
                .compute_secp256r1_shamir_shares_of_secret_key_share_parts(
                    party_id,
                    *secp256r1_pvss_decryption_keys.get(&party_id).unwrap(),
                    secp256r1_pvss_encryption_keys_and_proofs
                        .get(&party_id)
                        .unwrap()
                        .0,
                )
                .expect("compute_secp256r1_shamir_shares_of_secret_key_share_parts should succeed");
        }

        // Get polynomial commitments from reconfiguration output
        let (epoch2_first_polynomial_commitments, epoch2_second_polynomial_commitments) =
            reconfiguration_public_output.secp256k1_polynomial_commitments();

        // Verify polynomial commitments have the correct length (threshold coefficients)
        assert_eq!(
            epoch2_first_polynomial_commitments.len(),
            epoch2_threshold as usize,
            "first polynomial commitments should have threshold coefficients"
        );
        assert_eq!(
            epoch2_second_polynomial_commitments.len(),
            epoch2_threshold as usize,
            "second polynomial commitments should have threshold coefficients"
        );

        // Verify all polynomial coefficients are valid group elements
        for (i, commitment) in epoch2_first_polynomial_commitments.iter().enumerate() {
            let _ = secp256k1::GroupElement::new(*commitment, &secp256k1_group_params)
                .unwrap_or_else(|_| panic!("first polynomial commitment {i} should be valid"));
        }
        for (i, commitment) in epoch2_second_polynomial_commitments.iter().enumerate() {
            let _ = secp256k1::GroupElement::new(*commitment, &secp256k1_group_params)
                .unwrap_or_else(|_| panic!("second polynomial commitment {i} should be valid"));
        }

        // The polynomial commitments from reconfiguration are SECRET KEY polynomial commitments.
        // The transformation from randomizer to secret key commitments is now done inside the
        // threshold_encryption_to_sharing protocol, so we can use them directly for VSS signing.

        // Collect secp256k1 secret key shares for VSS signing
        let secp256k1_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<secp256k1::Scalar>,
                group::Value<secp256k1::Scalar>,
            ),
        > =
            epoch2_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let (first_part, second_part) = reconfiguration_public_output
                    .compute_secp256k1_shamir_shares_of_secret_key_share_parts(
                        party_id,
                        *secp256k1_pvss_decryption_keys.get(&party_id).unwrap(),
                        secp256k1_pvss_encryption_keys_and_proofs.get(&party_id).unwrap().0,
                    )
                    .expect(
                        "compute_secp256k1_shamir_shares_of_secret_key_share_parts should succeed",
                    );

                    (party_id, (first_part, second_part))
                })
                .collect();

        // Run secp256k1 Taproot VSS signing using secret key polynomial commitments directly
        dkg_presign_signs_vss_internal_internal::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
            crate::secp256k1::vss::TaprootVSSProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            HashContext::None,
            MESSAGE.as_bytes(),
            verify_taproot_signature,
            "VSS Taproot secp256k1 (post-reconfiguration)",
            (*secp256k1_protocol_public_parameters).clone(),
            secp256k1_secret_key_shares,
            epoch2_first_polynomial_commitments.to_vec(),
            epoch2_second_polynomial_commitments.to_vec(),
            SignDataMode::Unverified,
        );

        // Collect ristretto secret key shares for VSS signing
        let ristretto_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<ristretto::Scalar>,
                group::Value<ristretto::Scalar>,
            ),
        > =
            epoch2_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let (first_part, second_part) = reconfiguration_public_output
                    .compute_ristretto_shamir_shares_of_secret_key_share_parts(
                        party_id,
                        *ristretto_pvss_decryption_keys.get(&party_id).unwrap(),
                        ristretto_pvss_encryption_keys_and_proofs.get(&party_id).unwrap().0,
                    )
                    .expect(
                        "compute_ristretto_shamir_shares_of_secret_key_share_parts should succeed",
                    );

                    (party_id, (first_part, second_part))
                })
                .collect();

        // Get ristretto polynomial commitments (already transformed to secret key commitments)
        let (ristretto_first_polynomial_commitments, ristretto_second_polynomial_commitments) =
            reconfiguration_public_output.ristretto_polynomial_commitments();

        // Run ristretto Schnorrkel VSS signing using secret key polynomial commitments directly
        dkg_presign_signs_vss_internal_internal::<
            { ristretto::SCALAR_LIMBS },
            { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            ristretto::GroupElement,
            crate::ristretto::vss::SchnorrkelVSSProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::Merlin,
            HashContext::Schnorrkel {
                signing_context: b"substrate".to_vec(),
            },
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            "VSS Schnorrkel ristretto (post-reconfiguration)",
            (*ristretto_protocol_public_parameters).clone(),
            ristretto_secret_key_shares,
            ristretto_first_polynomial_commitments.to_vec(),
            ristretto_second_polynomial_commitments.to_vec(),
            SignDataMode::Unverified,
        );

        // Collect curve25519 secret key shares for VSS signing
        let curve25519_secret_key_shares: HashMap<
            PartyID,
            (
                group::Value<curve25519::Scalar>,
                group::Value<curve25519::Scalar>,
            ),
        > =
            epoch2_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let (first_part, second_part) = reconfiguration_public_output
                    .compute_curve25519_shamir_shares_of_secret_key_share_parts(
                        party_id,
                        *ristretto_pvss_decryption_keys.get(&party_id).unwrap(),
                        ristretto_pvss_encryption_keys_and_proofs.get(&party_id).unwrap().0,
                    )
                    .expect(
                        "compute_curve25519_shamir_shares_of_secret_key_share_parts should succeed",
                    );

                    (party_id, (first_part, second_part))
                })
                .collect();

        // Get curve25519 polynomial commitments (already transformed to secret key commitments)
        let (curve25519_first_polynomial_commitments, curve25519_second_polynomial_commitments) =
            reconfiguration_public_output.curve25519_polynomial_commitments();

        // Run curve25519 EdDSA VSS signing using secret key polynomial commitments directly
        dkg_presign_signs_vss_internal_internal::<
            { curve25519::SCALAR_LIMBS },
            { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            curve25519::GroupElement,
            crate::curve25519::vss::EdDSAVSSProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA512,
            HashContext::None,
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            "VSS EdDSA curve25519 (post-reconfiguration)",
            (*curve25519_protocol_public_parameters).clone(),
            curve25519_secret_key_shares,
            curve25519_first_polynomial_commitments.to_vec(),
            curve25519_second_polynomial_commitments.to_vec(),
            SignDataMode::Unverified,
        );
    }
}
