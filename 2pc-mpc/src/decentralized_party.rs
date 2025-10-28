// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub mod dkg;
pub mod reconfiguration;
pub mod reconfiguration_v1_to_v2;

#[cfg(test)]
mod tests {
    use crate::decentralized_party::dkg::tests::generates_universal_distributed_key_internal;
    use crate::decentralized_party::reconfiguration::tests::reconfigures_internal_internal;
    use crate::decentralized_party::{reconfiguration, reconfiguration_v1_to_v2};
    use crate::sign::tests::{
        dkg_presign_signs_internal, presign_signs_internal, verify_eddsa_signature,
        verify_schnorrkel_signature, verify_secp256k1_ecdsa_signature,
        verify_secp256r1_ecdsa_signature, verify_taproot_signature, MESSAGE,
    };
    use crate::test_helpers::mock_decentralized_party_dkg;
    use crate::ProtocolPublicParameters;
    use class_groups::publicly_verifiable_secret_sharing::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use class_groups::test_helpers::{
        generates_distributed_key_secp256k1_internal,
        reconfigures_secp256k1_internal_internal_internal,
    };
    use class_groups::{
        CiphertextSpaceValue, Curve25519EncryptionKey, RistrettoEncryptionKey,
        Secp256k1EncryptionKey, Secp256r1EncryptionKey, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::Random;
    use group::{curve25519, ristretto, secp256k1, secp256r1, HashScheme, OsCsRng};
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;
    use mpc::WeightedThresholdAccessStructure;
    use std::collections::HashMap;

    #[test]
    fn dkgs_reconfigures_signs_v2() {
        let threshold = 4;
        let epoch1_party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);
        let epoch2_party_to_weight = HashMap::from([(1, 1), (2, 2), (3, 2)]);

        let epoch1_access_structure =
            WeightedThresholdAccessStructure::new(threshold, epoch1_party_to_weight).unwrap();

        let epoch2_access_structure =
            WeightedThresholdAccessStructure::new(threshold, epoch2_party_to_weight).unwrap();

        let (epoch1_decryption_key_per_crt_prime, epoch1_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch1_access_structure);

        let (epoch2_decryption_key_per_crt_prime, epoch2_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch2_access_structure);

        let epoch1_tangible_party_id_to_epoch2 =
            HashMap::from([(1, Some(2)), (2, None), (3, Some(3))]);

        let universal_dkg_public_output =
            generates_universal_distributed_key_internal(epoch1_access_structure.clone());

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
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::SHA256,
            epoch1_secp256k1_decryption_key_share_public_parameters.clone(),
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            secp256k1_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
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
            crate::ristretto::class_groups::SchnorrkelSubstrateProtocol,
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::Merlin,
            epoch1_ristretto_decryption_key_share_public_parameters.clone(),
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            ristretto_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)".to_string(),
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
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::SHA512,
            epoch1_curve25519_decryption_key_share_public_parameters.clone(),
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            curve25519_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)".to_string(),
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
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::SHA256,
            epoch1_secp256r1_decryption_key_share_public_parameters.clone(),
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256r1_ecdsa_signature,
            secp256r1_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous ECDSA secp256r1".to_string(),
        );

        let reconfiguration_public_input = reconfiguration::PublicInput::new_from_dkg_output(
            &epoch1_access_structure,
            epoch2_access_structure.clone(),
            epoch1_encryption_keys_per_crt_prime_and_proofs,
            epoch2_encryption_keys_per_crt_prime_and_proofs.clone(),
            epoch1_tangible_party_id_to_epoch2.clone(),
            universal_dkg_public_output,
        )
        .unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let reconfiguration_public_output = reconfigures_internal_internal(
            session_id,
            epoch1_access_structure.clone(),
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share,
            reconfiguration_public_input,
            false,
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

        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            secp256k1_centralized_party_dkg_output.clone(),
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output.clone(),
            epoch2_secp256k1_decryption_key_share_public_parameters.clone(),
            epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            secp256k1_protocol_public_parameters.clone(),
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
        );

        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::TaprootProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            secp256k1_centralized_party_dkg_output,
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output,
            epoch2_secp256k1_decryption_key_share_public_parameters.clone(),
            epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_taproot_signature,
            secp256k1_protocol_public_parameters.clone(),
            "Class Groups Asynchronous Schnorr secp256k1 (Taproot)".to_string(),
        );

        let epoch2_ristretto_decryption_key_share_public_parameters = reconfiguration_public_output
            .ristretto_decryption_key_share_public_parameters(&epoch2_access_structure)
            .unwrap();

        presign_signs_internal::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            crate::ristretto::class_groups::SchnorrkelSubstrateProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::Merlin,
            ristretto_centralized_party_dkg_output,
            ristretto_centralized_party_secret_key_share,
            ristretto_decentralized_party_dkg_output,
            epoch2_ristretto_decryption_key_share_public_parameters.clone(),
            epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            ristretto_protocol_public_parameters.clone(),
            "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)".to_string(),
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
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA512,
            curve25519_centralized_party_dkg_output,
            curve25519_centralized_party_secret_key_share,
            curve25519_decentralized_party_dkg_output,
            epoch2_curve25519_decryption_key_share_public_parameters.clone(),
            epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            curve25519_protocol_public_parameters.clone(),
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)".to_string(),
        );

        let epoch2_secp256r1_decryption_key_share_public_parameters = reconfiguration_public_output
            .secp256r1_decryption_key_share_public_parameters(&epoch2_access_structure)
            .unwrap();

        presign_signs_internal::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            crate::secp256r1::class_groups::ECDSAProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            secp256r1_centralized_party_dkg_output,
            secp256r1_centralized_party_secret_key_share,
            secp256r1_decentralized_party_dkg_output,
            epoch2_secp256r1_decryption_key_share_public_parameters,
            epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256r1_ecdsa_signature,
            secp256r1_protocol_public_parameters,
            "Class Groups Asynchronous ECDSA secp256r1".to_string(),
        );

        // Finally, try a trusted dealer setup, which uses the v1 output:
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        dkg_presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
        >(
            session_id,
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            epoch2_secp256k1_decryption_key_share_public_parameters,
            epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            secp256k1_protocol_public_parameters.clone(),
            true,
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
        );
    }

    #[test]
    fn dkgs_reconfigures_signs_v1_to_v2() {
        let epoch1_party_to_weight = HashMap::from([(1, 1), (2, 3), (3, 2)]);
        let epoch2_party_to_weight = HashMap::from([(1, 1), (2, 3), (3, 2)]);
        let epoch3_party_to_weight = HashMap::from([(1, 2), (2, 2), (3, 1)]);
        let epoch4_party_to_weight = HashMap::from([(1, 1), (2, 2), (3, 1), (4, 2)]);

        let epoch1_access_structure =
            WeightedThresholdAccessStructure::new(4, epoch1_party_to_weight).unwrap();

        let epoch2_access_structure =
            WeightedThresholdAccessStructure::new(4, epoch2_party_to_weight).unwrap();

        let epoch3_access_structure =
            WeightedThresholdAccessStructure::new(4, epoch3_party_to_weight).unwrap();

        let epoch4_access_structure =
            WeightedThresholdAccessStructure::new(5, epoch4_party_to_weight).unwrap();

        let (_, epoch1_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch1_access_structure);

        let (epoch2_decryption_key_per_crt_prime, epoch2_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch2_access_structure);

        let (epoch3_decryption_key_per_crt_prime, epoch3_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch3_access_structure);

        let (epoch4_decryption_key_per_crt_prime, epoch4_encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&epoch4_access_structure);

        let epoch1_tangible_party_id_to_epoch2 =
            HashMap::from([(1, Some(2)), (2, None), (3, Some(3))]);

        let epoch2_tangible_party_id_to_epoch3 =
            HashMap::from([(1, Some(3)), (2, None), (3, None)]);

        let epoch3_tangible_party_id_to_epoch4 =
            HashMap::from([(1, None), (2, Some(4)), (3, None)]);

        let (
            dkg_public_output_v1,
            epoch1_secp256k1_decryption_key_share_public_parameters,
            decryption_key_shares,
        ) = generates_distributed_key_secp256k1_internal(&epoch1_access_structure, false);

        let epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share: HashMap<_, _> =
            epoch1_access_structure
                .party_to_virtual_parties()
                .into_iter()
                .map(|(party_id, virtual_subset)| {
                    (
                        party_id,
                        virtual_subset
                            .into_iter()
                            .map(|virtual_party_id| {
                                (
                                    virtual_party_id,
                                    decryption_key_shares
                                        .get(&virtual_party_id)
                                        .unwrap()
                                        .decryption_key_share,
                                )
                            })
                            .collect(),
                    )
                })
                .collect();

        // Emulate a v1 dkg - use emulated protocol public parameters
        let (
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >(
            secp256k1::group_element::PublicParameters::default(),
            secp256k1::scalar::PublicParameters::default(),
            &epoch1_secp256k1_decryption_key_share_public_parameters
                .encryption_scheme_public_parameters,
        );

        let secp256k1_emulated_protocol_public_parameters = ProtocolPublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
        >(
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
            epoch1_secp256k1_decryption_key_share_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
        );

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
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
        >(
            session_id,
            epoch1_access_structure.clone(),
            HashScheme::SHA256,
            epoch1_secp256k1_decryption_key_share_public_parameters.clone(),
            epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            secp256k1_emulated_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
        );

        // Emulate a v1 dkg output - take the inner `Output` and transform to `v1`
        let secp256k1_centralized_party_dkg_output_v1: crate::dkg::centralized_party::VersionedOutput<{ secp256k1::SCALAR_LIMBS }, secp256k1::group_element::Value> = match secp256k1_centralized_party_dkg_output {
            crate::dkg::centralized_party::VersionedOutput::UniversalPublicDKGOutput {output, ..} =>
                crate::dkg::centralized_party::VersionedOutput::TargetedPublicDKGOutput(output),
            _ => panic!("unreachable")
        };

        let secp256k1_decentralized_party_dkg_output_v1: crate::dkg::decentralized_party::VersionedOutput<{ secp256k1::SCALAR_LIMBS },  secp256k1::group_element::Value, CiphertextSpaceValue<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,> = match secp256k1_decentralized_party_dkg_output {
            crate::dkg::decentralized_party::VersionedOutput::UniversalPublicDKGOutput {output, ..} =>
                crate::dkg::decentralized_party::VersionedOutput::TargetedPublicDKGOutput(output),
            _ => panic!("unreachable")
        };

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        let plaintext_space_public_parameters = secp256k1::scalar::PublicParameters::default();
        let public_input =
            ::class_groups::reconfiguration::PublicInput::new::<secp256k1::GroupElement>(
                &epoch1_access_structure,
                epoch2_access_structure.clone(),
                plaintext_space_public_parameters.clone(),
                epoch1_encryption_keys_per_crt_prime_and_proofs.clone(),
                epoch2_encryption_keys_per_crt_prime_and_proofs.clone(),
                epoch1_secp256k1_decryption_key_share_public_parameters.clone(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                epoch1_tangible_party_id_to_epoch2,
                dkg_public_output_v1.clone(),
            )
            .unwrap();

        let public_inputs: HashMap<_, _> = (1..=epoch1_access_structure
            .number_of_tangible_parties())
            .map(|party_id| (party_id, public_input.clone()))
            .collect();

        let (epoch2_decryption_key_share_public_parameters, decryption_key_shares) =
            reconfigures_secp256k1_internal_internal_internal(
                session_id,
                &epoch1_access_structure,
                &epoch2_access_structure,
                epoch1_tangible_party_id_to_virtual_party_id_to_decryption_key_share,
                epoch2_decryption_key_per_crt_prime,
                public_inputs,
                false,
            );

        let epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share: HashMap<_, _> =
            epoch2_access_structure
                .party_to_virtual_parties()
                .into_iter()
                .map(|(party_id, virtual_subset)| {
                    (
                        party_id,
                        virtual_subset
                            .into_iter()
                            .map(|virtual_party_id| {
                                (
                                    virtual_party_id,
                                    *decryption_key_shares.get(&virtual_party_id).unwrap(),
                                )
                            })
                            .collect(),
                    )
                })
                .collect();

        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
        >(
            epoch2_access_structure.clone(),
            HashScheme::SHA256,
            secp256k1_centralized_party_dkg_output_v1.clone(),
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output_v1.clone(),
            epoch2_decryption_key_share_public_parameters.clone(),
            epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            secp256k1_emulated_protocol_public_parameters,
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
        );

        let reconfiguration_v1_to_v2_public_input = reconfiguration_v1_to_v2::PublicInput::new(
            &epoch2_access_structure,
            epoch3_access_structure.clone(),
            epoch2_encryption_keys_per_crt_prime_and_proofs,
            epoch3_encryption_keys_per_crt_prime_and_proofs.clone(),
            epoch2_tangible_party_id_to_epoch3.clone(),
            epoch2_decryption_key_share_public_parameters,
            dkg_public_output_v1.clone(),
        )
        .unwrap();

        let reconfiguration_v1_to_v2_public_inputs = epoch2_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| (party_id, reconfiguration_v1_to_v2_public_input.clone()))
            .collect();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let (_, _, reconfiguration_v1_to_v2_public_output) =
            asynchronous_session_terminates_successfully_internal::<reconfiguration_v1_to_v2::Party>(
                session_id,
                &epoch2_access_structure,
                epoch2_tangible_party_id_to_virtual_party_id_to_decryption_key_share,
                reconfiguration_v1_to_v2_public_inputs,
                5,
                HashMap::new(),
                false,
                true,
            );

        let epoch3_secp256k1_decryption_key_share_public_parameters =
            reconfiguration_v1_to_v2_public_output
                .secp256k1_decryption_key_share_public_parameters(&epoch3_access_structure)
                .unwrap();

        let epoch3_tangible_party_id_to_virtual_party_id_to_decryption_key_share: HashMap<_, _> =
            epoch3_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let decryption_key_shares = reconfiguration_v1_to_v2_public_output
                        .decrypt_decryption_key_shares(
                            party_id,
                            &epoch3_access_structure,
                            *epoch3_decryption_key_per_crt_prime.get(&party_id).unwrap(),
                        )
                        .unwrap();

                    (party_id, decryption_key_shares)
                })
                .collect();

        // Use the non-emulated ones now, check it still works.
        let secp256k1_protocol_public_parameters = reconfiguration_v1_to_v2_public_output
            .secp256k1_protocol_public_parameters()
            .unwrap();

        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
        >(
            epoch3_access_structure.clone(),
            HashScheme::SHA256,
            secp256k1_centralized_party_dkg_output_v1.clone(),
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output_v1.clone(),
            epoch3_secp256k1_decryption_key_share_public_parameters.clone(),
            epoch3_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            secp256k1_protocol_public_parameters.clone(),
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
        );

        // Try taproot as well
        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::TaprootProtocol,
        >(
            epoch3_access_structure.clone(),
            HashScheme::SHA256,
            secp256k1_centralized_party_dkg_output_v1.clone(),
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output_v1.clone(),
            epoch3_secp256k1_decryption_key_share_public_parameters,
            epoch3_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_taproot_signature,
            secp256k1_protocol_public_parameters.clone(),
            "Class Groups Asynchronous Schnorr secp256k1 (Taproot)".to_string(),
        );

        let epoch3_ristretto_decryption_key_share_public_parameters =
            reconfiguration_v1_to_v2_public_output
                .ristretto_decryption_key_share_public_parameters(&epoch3_access_structure)
                .unwrap();

        let ristretto_protocol_public_parameters = reconfiguration_v1_to_v2_public_output
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
            crate::ristretto::class_groups::SchnorrkelSubstrateProtocol,
        >(
            session_id,
            epoch3_access_structure.clone(),
            HashScheme::Merlin,
            epoch3_ristretto_decryption_key_share_public_parameters.clone(),
            epoch3_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            ristretto_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)".to_string(),
        );

        let epoch3_curve25519_decryption_key_share_public_parameters =
            reconfiguration_v1_to_v2_public_output
                .curve25519_decryption_key_share_public_parameters(&epoch3_access_structure)
                .unwrap();

        let curve25519_protocol_public_parameters = reconfiguration_v1_to_v2_public_output
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
        >(
            session_id,
            epoch3_access_structure.clone(),
            HashScheme::SHA512,
            epoch3_curve25519_decryption_key_share_public_parameters.clone(),
            epoch3_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            curve25519_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)".to_string(),
        );

        let epoch3_secp256r1_decryption_key_share_public_parameters =
            reconfiguration_v1_to_v2_public_output
                .secp256r1_decryption_key_share_public_parameters(&epoch3_access_structure)
                .unwrap();

        let secp256r1_protocol_public_parameters = reconfiguration_v1_to_v2_public_output
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
        >(
            session_id,
            epoch3_access_structure.clone(),
            HashScheme::SHA256,
            epoch3_secp256r1_decryption_key_share_public_parameters.clone(),
            epoch3_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256r1_ecdsa_signature,
            secp256r1_protocol_public_parameters.clone(),
            false,
            "Class Groups Asynchronous ECDSA secp256r1".to_string(),
        );

        let reconfiguration_public_input =
            reconfiguration::PublicInput::new_from_reconfiguration_output(
                &epoch3_access_structure,
                epoch4_access_structure.clone(),
                epoch3_encryption_keys_per_crt_prime_and_proofs,
                epoch4_encryption_keys_per_crt_prime_and_proofs.clone(),
                epoch3_tangible_party_id_to_epoch4.clone(),
                dkg_public_output_v1,
                reconfiguration_v1_to_v2_public_output,
            )
            .unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);
        let reconfiguration_public_output = reconfigures_internal_internal(
            session_id,
            epoch3_access_structure.clone(),
            epoch3_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            reconfiguration_public_input,
            false,
        );

        let epoch4_secp256k1_decryption_key_share_public_parameters = reconfiguration_public_output
            .secp256k1_decryption_key_share_public_parameters(&epoch4_access_structure)
            .unwrap();

        let epoch4_tangible_party_id_to_virtual_party_id_to_decryption_key_share: HashMap<_, _> =
            epoch4_access_structure
                .party_to_weight
                .keys()
                .map(|&party_id| {
                    let decryption_key_shares = reconfiguration_public_output
                        .decrypt_decryption_key_shares(
                            party_id,
                            &epoch4_access_structure,
                            *epoch4_decryption_key_per_crt_prime.get(&party_id).unwrap(),
                        )
                        .unwrap();

                    (party_id, decryption_key_shares)
                })
                .collect();

        presign_signs_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::ECDSAProtocol,
        >(
            epoch4_access_structure.clone(),
            HashScheme::SHA256,
            secp256k1_centralized_party_dkg_output_v1,
            secp256k1_centralized_party_secret_key_share,
            secp256k1_decentralized_party_dkg_output_v1,
            epoch4_secp256k1_decryption_key_share_public_parameters,
            epoch4_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256k1_ecdsa_signature,
            secp256k1_protocol_public_parameters,
            "Class Groups Asynchronous ECDSA secp256k1".to_string(),
        );

        let epoch4_ristretto_decryption_key_share_public_parameters = reconfiguration_public_output
            .ristretto_decryption_key_share_public_parameters(&epoch4_access_structure)
            .unwrap();

        presign_signs_internal::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            crate::ristretto::class_groups::SchnorrkelSubstrateProtocol,
        >(
            epoch4_access_structure.clone(),
            HashScheme::Merlin,
            ristretto_centralized_party_dkg_output,
            ristretto_centralized_party_secret_key_share,
            ristretto_decentralized_party_dkg_output,
            epoch4_ristretto_decryption_key_share_public_parameters.clone(),
            epoch4_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_schnorrkel_signature,
            ristretto_protocol_public_parameters.clone(),
            "Class Groups Asynchronous Schnorr Ristretto (Schnorrkel/sr25519)".to_string(),
        );

        let epoch4_curve25519_decryption_key_share_public_parameters =
            reconfiguration_public_output
                .curve25519_decryption_key_share_public_parameters(&epoch4_access_structure)
                .unwrap();

        presign_signs_internal::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
            crate::curve25519::class_groups::EdDSAProtocol,
        >(
            epoch4_access_structure.clone(),
            HashScheme::SHA512,
            curve25519_centralized_party_dkg_output,
            curve25519_centralized_party_secret_key_share,
            curve25519_decentralized_party_dkg_output,
            epoch4_curve25519_decryption_key_share_public_parameters.clone(),
            epoch4_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_eddsa_signature,
            curve25519_protocol_public_parameters.clone(),
            "Class Groups Asynchronous Schnorr Curve25519 (EdDSA)".to_string(),
        );

        let epoch4_secp256r1_decryption_key_share_public_parameters = reconfiguration_public_output
            .secp256r1_decryption_key_share_public_parameters(&epoch4_access_structure)
            .unwrap();

        presign_signs_internal::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            crate::secp256r1::class_groups::ECDSAProtocol,
        >(
            epoch4_access_structure.clone(),
            HashScheme::SHA256,
            secp256r1_centralized_party_dkg_output,
            secp256r1_centralized_party_secret_key_share,
            secp256r1_decentralized_party_dkg_output,
            epoch4_secp256r1_decryption_key_share_public_parameters.clone(),
            epoch4_tangible_party_id_to_virtual_party_id_to_decryption_key_share.clone(),
            MESSAGE.as_bytes(),
            verify_secp256r1_ecdsa_signature,
            secp256r1_protocol_public_parameters.clone(),
            "Class Groups Asynchronous ECDSA secp256r1".to_string(),
        );
    }
}
