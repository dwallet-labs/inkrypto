// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub mod centralized_party;
mod class_groups;
pub mod decentralized_party;

#[cfg(test)]
mod tests {
    use crate::schnorr::{
        generate_schnorr_signature_response, verify_schnorr_signature, EdDSASignature,
        SchnorrkelSignature, TaprootSignature, VerifyingKey,
    };
    use ecdsa::signature::digest::Digest;
    use group::{
        curve25519, ristretto, secp256k1, CyclicGroupElement, GroupElement, HashContext,
        HashScheme, OsCsRng, Samplable,
    };
    use k256::sha2::Sha256;
    use std::ops::Neg;

    #[test]
    fn signs_taproot() {
        let message = b"taprooted!";
        let hashed_message = Sha256::new_with_prefix(message).finalize();

        let group_public_parameters = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let mut secret_key =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();
        let mut nonce =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let mut public_nonce = nonce * generator;
        let mut public_key = secret_key * generator;

        if !public_key.is_taproot_normalized() {
            secret_key = secret_key.neg();
            public_key = public_key.neg();
        }

        if !public_nonce.is_taproot_normalized() {
            nonce = nonce.neg();
            public_nonce = public_nonce.neg();
        }

        let response = generate_schnorr_signature_response(
            secret_key,
            public_key,
            nonce,
            public_nonce,
            &hashed_message,
            HashScheme::SHA256,
            &HashContext::None,
            &scalar_group_public_parameters,
        )
        .unwrap();

        let res = verify_schnorr_signature(
            response,
            public_nonce,
            public_key,
            &hashed_message,
            HashScheme::SHA256,
            &HashContext::None,
            &group_public_parameters,
        );

        assert!(
            res.is_ok(),
            "generated signatures should be verified internally"
        );

        let signature = TaprootSignature::try_from((public_nonce.value(), response)).unwrap();
        let res = public_key.verify(
            &hashed_message,
            HashScheme::SHA256,
            &HashContext::None,
            &signature,
        );

        assert!(
            res.is_ok(),
            "generated signatures should be verified externally, got error {:?}",
            res.err().unwrap()
        );
    }

    #[test]
    fn signs_eddsa() {
        let message = b"hey edD!";

        let group_public_parameters = curve25519::PublicParameters::default();
        let scalar_group_public_parameters = curve25519::scalar::PublicParameters::default();

        let generator =
            curve25519::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let secret_key =
            curve25519::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();
        let nonce =
            curve25519::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let public_nonce = nonce * generator;
        let public_key = secret_key * generator;

        let response = generate_schnorr_signature_response(
            secret_key,
            public_key,
            nonce,
            public_nonce,
            message,
            HashScheme::SHA512,
            &HashContext::None,
            &scalar_group_public_parameters,
        )
        .unwrap();

        let res = verify_schnorr_signature(
            response,
            public_nonce,
            public_key,
            message,
            HashScheme::SHA512,
            &HashContext::None,
            &group_public_parameters,
        );

        assert!(
            res.is_ok(),
            "generated signatures should be verified internally"
        );

        let signature = EdDSASignature::try_from((public_nonce.value(), response)).unwrap();
        let res = public_key.verify(message, HashScheme::SHA512, &HashContext::None, &signature);

        assert!(
            res.is_ok(),
            "generated signatures should be verified externally, got error {:?}",
            res.err().unwrap()
        );
    }

    #[test]
    fn signs_schnorrkel() {
        let message = b"schnorrkelling with the Orcas!";

        let group_public_parameters = ristretto::group_element::PublicParameters::default();
        let scalar_group_public_parameters = ristretto::scalar::PublicParameters::default();

        let generator =
            ristretto::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let secret_key =
            ristretto::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();
        let nonce =
            ristretto::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let public_nonce = nonce * generator;
        let public_key = secret_key * generator;

        let schnorrkel_ctx = HashContext::Schnorrkel {
            signing_context: b"substrate".to_vec(),
        };

        let response = generate_schnorr_signature_response(
            secret_key,
            public_key,
            nonce,
            public_nonce,
            message,
            HashScheme::Merlin,
            &schnorrkel_ctx,
            &scalar_group_public_parameters,
        )
        .unwrap();

        let res = verify_schnorr_signature(
            response,
            public_nonce,
            public_key,
            message,
            HashScheme::Merlin,
            &schnorrkel_ctx,
            &group_public_parameters,
        );

        assert!(
            res.is_ok(),
            "generated signatures should be verified internally"
        );

        let signature = SchnorrkelSignature::try_from((public_nonce.value(), response)).unwrap();
        let res = public_key.verify(message, HashScheme::Merlin, &schnorrkel_ctx, &signature);

        assert!(
            res.is_ok(),
            "generated signatures should be verified externally, got error {:?}",
            res.err().unwrap()
        );
    }
}
