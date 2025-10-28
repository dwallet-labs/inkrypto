// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::schnorr::sign::centralized_party::PartialSignature;
use crate::schnorr::sign::verify_schnorr_signature;
use crate::schnorr::{Presign, VerifyingKey};
use crate::{dkg, Error};
use class_groups::SecretKeyShareSizedInteger;
use crypto_bigint::{ConcatMixed, Encoding, NonZero, Uint};
use group::helpers::DeduplicateAndSort;
use group::Reduce;
use group::{
    CsRng, GroupElement, HashScheme, KnownOrderGroupElement, PartyID,
    StatisticalSecuritySizedNumber,
};
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
    pub fn decrypt_signature_semi_honest(
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
        access_structure: &WeightedThresholdAccessStructure,
        decryption_shares: HashMap<PartyID, DecryptionKeyShare::DecryptionShare>,
    ) -> crate::Result<(GroupElement::Value, group::Value<GroupElement::Scalar>)> {
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        // The `DecryptionKeyShare` trait works with virtual parties, whilst the input is in tangible parties.
        // So we transition back from each virtual party to its tangible corresponding party.
        let expected_decrypters = access_structure.virtual_subset(expected_decrypters)?;

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

        let decryption_shares = decryption_shares
            .into_iter()
            .map(|(party_id, decryption_share)| (party_id, vec![decryption_share]))
            .collect();
        let plaintexts = DecryptionKeyShare::combine_decryption_shares_semi_honest(
            vec![encryption_of_signature_response],
            decryption_shares,
            expected_decrypters,
            decryption_key_share_public_parameters,
        )?;

        match &plaintexts[..] {
            [signature_response] => Self::verify_decrypted_signature(
                message,
                hash_scheme,
                public_nonce,
                public_key,
                signature_response,
                protocol_public_parameters,
            ),
            _ => Err(Error::InternalError),
        }
    }

    pub fn decrypt_signature(
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
        access_structure: &WeightedThresholdAccessStructure,
        invalid_semi_honest_decryption_shares: HashMap<
            PartyID,
            DecryptionKeyShare::DecryptionShare,
        >,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (
                DecryptionKeyShare::DecryptionShare,
                DecryptionKeyShare::PartialDecryptionProof,
            ),
        >,
        rng: &mut impl CsRng,
    ) -> crate::Result<(
        Vec<PartyID>,
        (GroupElement::Value, group::Value<GroupElement::Scalar>),
    )> {
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        // The `DecryptionKeyShare` trait works with virtual parties, whilst the input is in tangible parties.
        // So we transition back from each virtual party to its tangible corresponding party.
        let expected_decrypters = access_structure.virtual_subset(expected_decrypters)?;

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

        let invalid_semi_honest_decryption_shares = invalid_semi_honest_decryption_shares
            .into_iter()
            .map(|(party_id, decryption_share)| (party_id, vec![decryption_share]))
            .collect();
        let decryption_shares_and_proofs: HashMap<_, _> = decryption_shares_and_proofs
            .into_iter()
            .map(|(party_id, (decryption_share, proof))| {
                (party_id, (vec![decryption_share], proof))
            })
            .collect();
        let (malicious_second_round_virtual_parties, plaintexts) =
            DecryptionKeyShare::combine_decryption_shares(
                vec![encryption_of_signature_response],
                decryption_shares_and_proofs.clone(),
                decryption_key_share_public_parameters,
                rng,
            )?;

        let valid_maliciously_secure_decryption_shares = decryption_shares_and_proofs
            .into_iter()
            .filter(|(virtual_party_id, _)| {
                !malicious_second_round_virtual_parties.contains(virtual_party_id)
            })
            .map(|(virtual_party_id, (decryption_shares, _))| (virtual_party_id, decryption_shares))
            .collect();

        let malicious_first_round_virtual_parties =
            DecryptionKeyShare::identify_malicious_semi_honest_decrypters(
                invalid_semi_honest_decryption_shares,
                valid_maliciously_secure_decryption_shares,
                expected_decrypters,
                decryption_key_share_public_parameters,
            )?;

        if malicious_first_round_virtual_parties.is_empty() {
            // If we reached the maliciously-secure path, the semi-honest have failed.
            // This must occur because at least one party behaved maliciously and failed the semi-honest threshold decryption,
            // i.e. sent a wrong decryption share.
            // If we identified no malicious party, we have a bug and fail on an internal error so it can be identified.
            return Err(Error::InternalError);
        }

        // The `DecryptionKeyShare` trait works with virtual parties, whilst the `mpc` traits reports tangible parties as malicious.
        // So we transition back from each virtual party to its tangible corresponding party.
        let malicious_decrypters = malicious_first_round_virtual_parties
            .into_iter()
            .chain(malicious_second_round_virtual_parties)
            .flat_map(|virtual_party_id| access_structure.to_tangible_party_id(virtual_party_id))
            .deduplicate_and_sort();

        match &plaintexts[..] {
            [signature_response] => Self::verify_decrypted_signature(
                message,
                hash_scheme,
                public_nonce,
                public_key,
                signature_response,
                protocol_public_parameters,
            )
            .map(|signature| (malicious_decrypters, signature)),
            _ => Err(Error::InternalError),
        }
    }

    /// A helper function for the lightweight $$ O(1) $$ threshold decryption logic, which simply verifies the output of
    /// the decryption sent by the designated decrypting party. Blames it in case of an invalid
    /// signature, and accepts otherwise.
    ///
    /// Used in the malicious case as a sanity check as well.
    pub fn verify_decrypted_signature(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        public_nonce: GroupElement,
        public_key: GroupElement,
        signature_response: &EncryptionKey::PlaintextSpaceGroupElement,
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
    ) -> crate::Result<(GroupElement::Value, group::Value<GroupElement::Scalar>)> {
        // = q
        let group_order = GroupElement::Scalar::order_from_public_parameters(
            &protocol_public_parameters.scalar_group_public_parameters,
        );
        let group_order =
            Option::<_>::from(NonZero::new(group_order)).ok_or(Error::InternalError)?;

        let signature_response: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (*signature_response).into();

        let signature_response = GroupElement::Scalar::new(
            signature_response.reduce(&group_order).into(),
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        verify_schnorr_signature(
            signature_response,
            public_nonce,
            public_key,
            message,
            hash_scheme,
            &protocol_public_parameters.group_public_parameters,
        )?;

        Ok((public_nonce.value(), signature_response.value()))
    }
}
