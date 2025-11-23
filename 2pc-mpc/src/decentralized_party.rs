// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub mod dkg;
pub mod reconfiguration;

#[cfg(test)]
mod tests {
    use crate::decentralized_party::dkg::tests::generates_universal_distributed_key_internal;
    use crate::decentralized_party::reconfiguration;
    use crate::decentralized_party::reconfiguration::tests::reconfigures_internal_internal;
    use crate::sign::tests::{
        dkg_presign_signs_internal, presign_signs_internal, verify_eddsa_signature,
        verify_schnorrkel_signature, verify_secp256k1_ecdsa_signature,
        verify_secp256r1_ecdsa_signature, verify_taproot_signature, MESSAGE,
    };
    use class_groups::publicly_verifiable_secret_sharing::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use class_groups::{
        Curve25519EncryptionKey, RistrettoEncryptionKey, Secp256k1EncryptionKey,
        Secp256r1EncryptionKey,
    };
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::Random;
    use group::{curve25519, ristretto, secp256k1, secp256r1, HashScheme, OsCsRng};
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
}
