// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Signature Threshold Decryption round party for Class Groups

use group::{CsRng, PrimeGroupElement};
use homomorphic_encryption::GroupsPublicParametersAccessors;

use crate::bulletproofs::{RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS};
use crate::paillier::bulletproofs::{PaillierProtocolPublicParameters, UnboundedDComEvalWitness};
use crate::paillier::{
    CiphertextSpaceGroupElement, DecryptionKeyShare, DecryptionShare, EncryptionKey,
    PartialDecryptionProof, PLAINTEXT_SPACE_SCALAR_LIMBS,
};
use crate::sign::centralized_party::message::paillier::Message;

use super::*;

impl Party {
    /// This function implements round 2 of Protocol C.3 (Sign):
    /// Computes signature (r, s) for (m, X).
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    pub fn decrypt_signature_semi_honest_paillier<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    >(
        expected_decrypters: HashSet<PartyID>,
        decryption_shares: HashMap<PartyID, Vec<DecryptionShare>>,
        hashed_message: GroupElement::Scalar,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement>,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        >,
        decryption_key_share_public_parameters: &<DecryptionKeyShare as AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>>::PublicParameters,
        paillier_protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)> {
        let encryption_of_partial_signature = CiphertextSpaceGroupElement::new(
            sign_message.encryption_of_partial_signature,
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )?;

        let encryption_of_displaced_decentralized_party_nonce_share =
            CiphertextSpaceGroupElement::new(
                sign_message.encryption_of_displaced_decentralized_party_nonce_share,
                paillier_protocol_public_parameters
                    .protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        Self::decrypt_signature_semi_honest::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            DecryptionKeyShare,
        >(
            expected_decrypters,
            hashed_message,
            dkg_output,
            decryption_shares,
            encryption_of_partial_signature,
            encryption_of_displaced_decentralized_party_nonce_share,
            sign_message.public_signature_nonce,
            decryption_key_share_public_parameters,
            &paillier_protocol_public_parameters.protocol_public_parameters,
            access_structure,
        )
    }

    /// This function implements round 2 of Protocol C.3 (Sign):
    /// Computes signature (r, s) for (m, X).
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    ///
    /// This function is only called in the malicious flow, in case the semi-honest decryption failed.
    pub fn decrypt_signature_paillier<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    >(
        expected_decrypters: HashSet<PartyID>,
        invalid_semi_honest_decryption_shares: HashMap<PartyID, Vec<DecryptionShare>>,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (Vec<DecryptionShare>, PartialDecryptionProof),
        >,
        hashed_message: GroupElement::Scalar,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement>,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        >,
        decryption_key_share_public_parameters: &<DecryptionKeyShare as AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>>::PublicParameters,
        access_structure: &WeightedThresholdAccessStructure,
        paillier_protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> crate::Result<(Vec<PartyID>, (GroupElement::Scalar, GroupElement::Scalar))> {
        let encryption_of_partial_signature = CiphertextSpaceGroupElement::new(
            sign_message.encryption_of_partial_signature,
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )?;

        let encryption_of_displaced_decentralized_party_nonce_share =
            CiphertextSpaceGroupElement::new(
                sign_message.encryption_of_displaced_decentralized_party_nonce_share,
                paillier_protocol_public_parameters
                    .protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        Self::decrypt_signature::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            DecryptionKeyShare,
        >(
            expected_decrypters,
            hashed_message,
            dkg_output,
            invalid_semi_honest_decryption_shares,
            decryption_shares_and_proofs,
            encryption_of_partial_signature,
            encryption_of_displaced_decentralized_party_nonce_share,
            sign_message.public_signature_nonce,
            decryption_key_share_public_parameters,
            &paillier_protocol_public_parameters.protocol_public_parameters,
            access_structure,
            rng,
        )
    }

    /// The lightweight $$ O(1) $$ threshold decryption logic, which simply verifies the output of
    /// the decryption sent by the designated decrypting party. Blames it in case of an invalid
    /// signature, and accepts otherwise.
    pub fn verify_decrypted_signature_paillier<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    >(
        hashed_message: GroupElement::Scalar,
        signature_s: GroupElement::Scalar,
        designated_decrypting_party_id: PartyID,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement>,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        >,
        paillier_protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
    ) -> crate::Result<(GroupElement::Scalar, GroupElement::Scalar)> {
        Self::verify_decrypted_signature::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >(
            hashed_message,
            sign_message.public_signature_nonce,
            signature_s,
            designated_decrypting_party_id,
            dkg_output,
            &paillier_protocol_public_parameters.protocol_public_parameters,
        )
    }
}
