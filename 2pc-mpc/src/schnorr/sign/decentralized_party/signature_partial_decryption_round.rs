// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::schnorr::sign::centralized_party::PartialSignature;
use crate::schnorr::{Presign, VerifyingKey};
use crate::{dkg, Error};
use class_groups::SecretKeyShareSizedInteger;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::{CsRng, GroupElement, HashScheme, PartyID, StatisticalSecuritySizedNumber};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
};
use mpc::WeightedThresholdAccessStructure;
use std::collections::{HashMap, HashSet};

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            SecretKeyShare = SecretKeyShareSizedInteger,
        >,
        ProtocolPublicParameters,
    >
    super::Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        DecryptionKeyShare,
        ProtocolPublicParameters,
    >
where
    ProtocolPublicParameters: AsRef<
        crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    >,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    Error: From<DecryptionKeyShare::Error>,
{
    /// This function implements step (2f) of the Schnorr Sign Protocol generating encryption of the signature $\textsf{ct}_{B}$
    /// <https://eprint.iacr.org/archive/2025/297/1747917268.pdf> Protocol C.5
    /// $\textsf{ct}_{B} = \textsf{ct}_{k}\oplus (e\odot \textsf_{ct}_{\textsf{key}}\oplus z_{A})$
    pub(super) fn evaluate_encryption_of_signature_response(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        public_nonce: GroupElement,
        public_key: GroupElement,
        centralized_party_partial_response: GroupElement::Scalar,
        encryption_of_nonce_share: EncryptionKey::CiphertextSpaceGroupElement,
        encryption_of_secret_key_share: EncryptionKey::CiphertextSpaceGroupElement,
        protocol_public_parameters: &crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    ) -> crate::Result<EncryptionKey::CiphertextSpaceGroupElement> {
        let challenge = public_key.derive_challenge(&public_nonce, message, hash_scheme)?;

        let encryption_key =
            EncryptionKey::new(&protocol_public_parameters.encryption_scheme_public_parameters)?;
        let centralized_party_partial_response: Uint<SCALAR_LIMBS> =
            centralized_party_partial_response.value().into();
        let centralized_party_partial_response = EncryptionKey::PlaintextSpaceGroupElement::new(
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&centralized_party_partial_response).into(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;
        let neutral_randomness =
            EncryptionKey::RandomnessSpaceGroupElement::neutral_from_public_parameters(
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
            )?;
        let encryption_of_centralized_party_partial_response = encryption_key
            .encrypt_with_randomness(
                &centralized_party_partial_response,
                &neutral_randomness,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                true,
            );

        // $ ct_{B} = \textsf{ct}_{k}\oplus (e\odot \textsf_{ct}_{\textsf{key}}\oplus z_{A})$
        let challenge: Uint<SCALAR_LIMBS> = challenge.value().into();
        let encryption_of_signature_response = encryption_of_nonce_share
            .add_vartime(&encryption_of_secret_key_share.scale_vartime(&challenge))
            .add_vartime(&encryption_of_centralized_party_partial_response);

        Ok(encryption_of_signature_response)
    }

    /// Partially decrypt the encrypted signature $\textsf{ct}_{B}$
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    /// As observed in [FMM+24]{https://eprint.iacr.org/2024/253.pdf} (Pg. 27 "Optimized Threshold Decryption"), verifying the aggregated signature proves correctness of decryption shares, which in this case need not be proven or verified directly. This results with an improved amortized cost for decryption. For this purpose, in this function we only compute decryption shares without their corresponding proofs.
    pub fn partially_decrypt_encryption_of_signature_semi_honest(
        expected_decrypters: HashSet<PartyID>,
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        centralized_party_partial_signature: PartialSignature<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters,
        decryption_key_share_public_parameters: &DecryptionKeyShare::PublicParameters,
        virtual_party_id_to_decryption_key_share: HashMap<PartyID, DecryptionKeyShare>,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> crate::Result<HashMap<PartyID, DecryptionKeyShare::DecryptionShare>> {
        if Some(
            &virtual_party_id_to_decryption_key_share
                .keys()
                .copied()
                .collect(),
        ) != access_structure
            .party_to_virtual_parties()
            .get(&tangible_party_id)
        {
            return Err(Error::InvalidParameters);
        }

        let protocol_public_parameters = protocol_public_parameters.as_ref();

        let (
            centralized_party_partial_response,
            public_key,
            public_nonce,
            encryption_of_secret_key_share,
            encryption_of_nonce_share,
        ) = Self::verify_centralized_party_partial_signature_and_taproot_normalize_internal(
            message,
            hash_scheme,
            dkg_output,
            presign,
            centralized_party_partial_signature,
            protocol_public_parameters,
        )?;

        let encryption_of_signature_response = Self::evaluate_encryption_of_signature_response(
            message,
            hash_scheme,
            public_nonce,
            public_key,
            centralized_party_partial_response,
            encryption_of_nonce_share,
            encryption_of_secret_key_share,
            protocol_public_parameters,
        )?;

        // The `DecryptionKeyShare` trait works with virtual parties, whilst the input is in tangible parties.
        // So we transition back from each virtual party to its tangible corresponding party.
        let expected_decrypters = access_structure.virtual_subset(expected_decrypters)?;

        virtual_party_id_to_decryption_key_share
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                // === Compute \textsf{pt}_B ===
                // Protocol C.5 step 2(g).
                // This step emulates the functionality \mathcal{F}_{\textsf{TAHE}}.
                let signature_response_decryption_share =
                    Option::from(decryption_key_share.generate_decryption_share_semi_honest(
                        &encryption_of_signature_response, // $ ct_{B} $
                        expected_decrypters.clone(),
                        decryption_key_share_public_parameters,
                    ))
                    .ok_or(Error::InternalError)?;

                Ok((virtual_party_id, signature_response_decryption_share))
            })
            .collect()
    }

    /// Partially decrypt the encrypted signature $\textsf{ct}_{B}$.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    pub fn partially_decrypt_encryption_of_signature(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        centralized_party_partial_signature: PartialSignature<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters,
        decryption_key_share_public_parameters: &DecryptionKeyShare::PublicParameters,
        virtual_party_id_to_decryption_key_share: HashMap<PartyID, DecryptionKeyShare>,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        rng: &mut impl CsRng,
    ) -> crate::Result<
        HashMap<
            PartyID,
            (
                DecryptionKeyShare::DecryptionShare,
                DecryptionKeyShare::PartialDecryptionProof,
            ),
        >,
    > {
        if Some(
            &virtual_party_id_to_decryption_key_share
                .keys()
                .copied()
                .collect(),
        ) != access_structure
            .party_to_virtual_parties()
            .get(&tangible_party_id)
        {
            return Err(Error::InvalidParameters);
        }

        let protocol_public_parameters = protocol_public_parameters.as_ref();

        let (
            centralized_party_partial_response,
            public_key,
            public_nonce,
            encryption_of_secret_key_share,
            encryption_of_nonce_share,
        ) = Self::verify_centralized_party_partial_signature_and_taproot_normalize_internal(
            message,
            hash_scheme,
            dkg_output,
            presign,
            centralized_party_partial_signature,
            protocol_public_parameters,
        )?;

        let encryption_of_signature_response = Self::evaluate_encryption_of_signature_response(
            message,
            hash_scheme,
            public_nonce,
            public_key,
            centralized_party_partial_response,
            encryption_of_nonce_share,
            encryption_of_secret_key_share,
            protocol_public_parameters,
        )?;

        virtual_party_id_to_decryption_key_share
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                let (decryption_shares, proof) =
                    Option::from(decryption_key_share.generate_decryption_shares(
                        vec![encryption_of_signature_response],
                        decryption_key_share_public_parameters,
                        rng,
                    ))
                    .ok_or(Error::InternalError)?;

                match &decryption_shares[..] {
                    [signature_response_decryption_share] => Ok((
                        virtual_party_id,
                        (signature_response_decryption_share.clone(), proof),
                    )),
                    _ => Err(Error::InternalError),
                }
            })
            .collect()
    }
}
