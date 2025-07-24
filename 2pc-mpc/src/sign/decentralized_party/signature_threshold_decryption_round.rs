// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{NonZero, Uint};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use std::{collections::HashMap, ops::Neg};

use crate::{dkg, sign::verify_signature, Error, ProtocolPublicParameters};
use group::helpers::DeduplicateAndSort;
use group::{
    AffineXCoordinate, GroupElement, Invert, KnownOrderGroupElement, PartyID, PrimeGroupElement,
    Reduce,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
};
use mpc::WeightedThresholdAccessStructure;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party {}

impl Party {
    /// This function implements round 2 of Protocol C.3 (Sign):
    /// Computes signature (r, s) for (m, X).
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_signature_semi_honest<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        expected_decrypters: HashSet<PartyID>,
        // $ m $
        hashed_message: GroupElement::Scalar,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        decryption_shares: HashMap<PartyID, Vec<DecryptionKeyShare::DecryptionShare>>,
        encryption_of_partial_signature: EncryptionKey::CiphertextSpaceGroupElement,
        encryption_of_displaced_decentralized_party_nonce_share: EncryptionKey::CiphertextSpaceGroupElement,
        // $R$
        public_signature_nonce: GroupElement::Value,
        decryption_key_share_public_parameters: &DecryptionKeyShare::PublicParameters,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)>
    where
        Error: From<DecryptionKeyShare::Error>,
    {
        // The `DecryptionKeyShare` trait works with virtual parties, whilst the input is in tangible parties.
        // So we transition back from each virtual party to its tangible corresponding party.
        let expected_decrypters = access_structure.virtual_subset(expected_decrypters)?;

        let plaintexts = DecryptionKeyShare::combine_decryption_shares_semi_honest(
            vec![
                encryption_of_partial_signature,
                encryption_of_displaced_decentralized_party_nonce_share,
            ],
            decryption_shares,
            expected_decrypters,
            decryption_key_share_public_parameters,
        )?;

        Self::compute_and_verify_message::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >(
            hashed_message,
            dkg_output.clone(),
            public_signature_nonce,
            protocol_public_parameters,
            plaintexts,
        )
    }

    /// This function implements round 2 of Protocol C.3 (Sign):
    /// Computes signature (r, s) for (m, X).
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    ///
    /// This function is only called in the malicious flow, in case the semi-honest decryption failed.
    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_signature<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        expected_decrypters: HashSet<PartyID>,
        // $ m $
        hashed_message: GroupElement::Scalar,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        invalid_semi_honest_decryption_shares: HashMap<
            PartyID,
            Vec<DecryptionKeyShare::DecryptionShare>,
        >,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (
                Vec<DecryptionKeyShare::DecryptionShare>,
                DecryptionKeyShare::PartialDecryptionProof,
            ),
        >,
        encryption_of_partial_signature: EncryptionKey::CiphertextSpaceGroupElement,
        encryption_of_displaced_decentralized_party_nonce_share: EncryptionKey::CiphertextSpaceGroupElement,
        // $R$
        public_signature_nonce: GroupElement::Value,
        decryption_key_share_public_parameters: &DecryptionKeyShare::PublicParameters,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
        access_structure: &WeightedThresholdAccessStructure,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<(Vec<PartyID>, (GroupElement::Scalar, GroupElement::Scalar))>
    where
        Error: From<DecryptionKeyShare::Error>,
    {
        // The `DecryptionKeyShare` trait works with virtual parties, whilst the input is in tangible parties.
        // So we transition back from each virtual party to its tangible corresponding party.
        let expected_decrypters = access_structure.virtual_subset(expected_decrypters)?;

        // The semi-honest decryption failed, must go through the expensive malicious variant.
        let (malicious_second_round_virtual_parties, plaintexts) =
            DecryptionKeyShare::combine_decryption_shares(
                vec![
                    encryption_of_partial_signature,
                    encryption_of_displaced_decentralized_party_nonce_share,
                ],
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

        Self::compute_and_verify_message::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >(
            hashed_message,
            dkg_output,
            public_signature_nonce,
            protocol_public_parameters,
            plaintexts,
        )
        .map(|signature| (malicious_decrypters, signature))
    }

    pub fn compute_and_verify_message<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        // $ m $
        hashed_message: GroupElement::Scalar,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        // $R$
        public_signature_nonce: GroupElement::Value,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
        plaintexts: Vec<EncryptionKey::PlaintextSpaceGroupElement>,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)> {
        match &plaintexts[..] {
            [partial_signature, displaced_decentralized_party_nonce] => {
                // = q
                let group_order = GroupElement::Scalar::order_from_public_parameters(
                    &protocol_public_parameters.scalar_group_public_parameters,
                );
                let group_order =
                    Option::<_>::from(NonZero::new(group_order)).ok_or(Error::InternalError)?;

                let partial_signature: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
                    (*partial_signature).into();

                let partial_signature = GroupElement::Scalar::new(
                    partial_signature.reduce(&group_order).into(),
                    &protocol_public_parameters.scalar_group_public_parameters,
                )?;

                let displaced_decentralized_party_nonce: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
                    (*displaced_decentralized_party_nonce).into();

                let displaced_decentralized_party_nonce = GroupElement::Scalar::new(
                    displaced_decentralized_party_nonce
                        .reduce(&group_order)
                        .into(),
                    &protocol_public_parameters.scalar_group_public_parameters,
                )?;

                // === Compute (\textsf{pt}_4)^{-1} ===
                // Protocol C.3, step 2(b) in the broadcast round.
                // = (\gamma \cdot k_B)^{-1} where k_{B} denotes the translated nonce share of the decentralized party.
                let inverted_displaced_decentralized_party_nonce =
                    displaced_decentralized_party_nonce.invert();
                if inverted_displaced_decentralized_party_nonce
                    .is_none()
                    .into()
                {
                    return Err(Error::SignatureVerification);
                }

                // === Compute s' ===
                // Protocol C.3, step 2(b) in the broadcast round.
                // s' =\textsf{pt}_4^{-1} \cdot \textsf{pt}_A
                //    = k \cdot (rx + m) where k = k_{A}\cdot k_{B}^{-1}
                let signature_s =
                    inverted_displaced_decentralized_party_nonce.unwrap() * partial_signature;
                let negated_signature_s = signature_s.neg();

                // === Compute s ===
                // Protocol C.3, step 2(b) in the broadcast round.
                // = min(s', q-s')
                // Attend to malleability.
                let signature_s = if negated_signature_s.value() < signature_s.value() {
                    negated_signature_s
                } else {
                    signature_s
                };

                // = X
                let public_key = GroupElement::new(
                    dkg_output.public_key,
                    &protocol_public_parameters.group_public_parameters,
                )?;

                // = R
                let public_nonce = GroupElement::new(
                    public_signature_nonce,
                    &protocol_public_parameters.group_public_parameters,
                )?;

                // = r
                let nonce_x_coordinate = public_nonce.x();

                // Verify signature (r, s) for (m, X)
                verify_signature(nonce_x_coordinate, signature_s, hashed_message, public_key)?;

                Ok((nonce_x_coordinate, signature_s))
            }
            _ => Err(Error::InternalError),
        }
    }

    /// The lightweight $$ O(1) $$ threshold decryption logic, which simply verifies the output of
    /// the decryption sent by the designated decrypting party. Blames it in case of an invalid
    /// signature, and accepts otherwise.
    pub fn verify_decrypted_signature<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        // $ m $
        hashed_message: GroupElement::Scalar,
        // $R$
        public_signature_nonce: GroupElement::Value,
        signature_s: GroupElement::Scalar,
        designated_decrypting_party_id: PartyID,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)> {
        // = X
        let public_key = GroupElement::new(
            dkg_output.public_key,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // = R
        let public_nonce = GroupElement::new(
            public_signature_nonce,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // = r
        let nonce_x_coordinate = public_nonce.x();

        verify_signature(nonce_x_coordinate, signature_s, hashed_message, public_key).map_err(
            |_| Error::MaliciousDesignatedDecryptingParty(designated_decrypting_party_id),
        )?;

        Ok((nonce_x_coordinate, signature_s))
    }
}
#[cfg(feature = "class_groups")]
mod class_groups;

#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
mod paillier;
