// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Signature Partial Decryption round party for Paillier

use group::PrimeGroupElement;

use crate::languages::paillier::verify_committed_linear_evaluation;
use crate::paillier::bulletproofs::PaillierProtocolPublicParameters;
use crate::paillier::{
    CiphertextSpaceGroupElement, DecryptionKeyShare, DecryptionShare, PartialDecryptionProof,
};
use crate::{
    bulletproofs::{RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS},
    paillier::bulletproofs::UnboundedDComEvalWitness,
    paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS},
};

use super::*;

impl Party {
    /// Partially decrypt the encrypted signature parts sent by the centralized party.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    #[allow(clippy::too_many_arguments)]
    pub fn partially_decrypt_encryption_of_signature_parts_prehash_semi_honest_paillier<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    >(
        expected_decrypters: HashSet<PartyID>,
        hashed_message: GroupElement::Scalar,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement>,
        >,
        presign: presign::Presign<
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
        virtual_party_id_to_decryption_key_share: HashMap<PartyID, DecryptionKeyShare>,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        paillier_protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result< HashMap<
        PartyID,(DecryptionShare, DecryptionShare)>> where Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
    {
        Self::verify_encryption_of_signature_parts_prehash_paillier(
            paillier_protocol_public_parameters,
            dkg_output,
            presign,
            sign_message.clone(),
            hashed_message,
            rng,
        )?;

        Self::partially_decrypt_encryption_of_signature_parts_prehash_semi_honest::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            DecryptionKeyShare,
        >(
            expected_decrypters,
            sign_message.encryption_of_partial_signature,
            sign_message.encryption_of_displaced_decentralized_party_nonce_share,
            decryption_key_share_public_parameters,
            virtual_party_id_to_decryption_key_share,
            tangible_party_id,
            access_structure,
            &paillier_protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters,
        )
    }

    /// Partially decrypt the encrypted signature parts sent by the centralized party.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    #[allow(clippy::too_many_arguments)]
    pub fn partially_decrypt_encryption_of_signature_parts_prehash_paillier<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    >(
        hashed_message: GroupElement::Scalar,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement>,
        >,
        presign: presign::Presign<
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
        virtual_party_id_to_decryption_key_share: HashMap<PartyID, DecryptionKeyShare>,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        paillier_protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<
        HashMap<PartyID, (DecryptionShare, DecryptionShare, PartialDecryptionProof)>,
    > where         Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
    {
        Self::verify_encryption_of_signature_parts_prehash_paillier(
            paillier_protocol_public_parameters,
            dkg_output,
            presign,
            sign_message.clone(),
            hashed_message,
            rng,
        )?;

        Self::partially_decrypt_encryption_of_signature_parts_prehash::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            DecryptionKeyShare,
        >(
            sign_message.encryption_of_partial_signature,
            sign_message.encryption_of_displaced_decentralized_party_nonce_share,
            decryption_key_share_public_parameters,
            virtual_party_id_to_decryption_key_share,
            tangible_party_id,
            access_structure,
            &paillier_protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters,
            rng,
        )
    }

    /// This function implements step (2e) of the Sign protocol:
    /// Verifies zk-proofs of C_{k}, C_{\alpha}, C_{\beta}, C_{kx}, R, R_{B} ,\textsf{ct}_{\alpha,\beta}. and \textsf{ct}_A.
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    /// Verify the validity of the encrypted signature parts sent by the centralized party.
    /// If this function returns `Ok()`, it means that a valid signature over `message` is
    /// guaranteed to be able to be generated by the decentralized party, whenever a threshold of
    /// honest parties decides to engage in the signing protocol.
    ///
    /// to Note: `hashed_message` is a `Scalar` which must be a
    /// hash on the message bytes translated into a 32-byte number.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_encryption_of_signature_parts_prehash_paillier<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    >(
        paillier_protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement>,
        >,
        presign: presign::Presign<
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
        hashed_message: GroupElement::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<()> where         Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
    {
        let (
            encryption_of_masked_decentralized_party_nonce_share_before_displacing,
            first_coefficient_commitment,
            second_coefficient_commitment
        ): (CiphertextSpaceGroupElement, GroupElement, GroupElement) = Self::verify_encryption_of_signature_parts_prehash::<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>(
            hashed_message, presign.session_id,
            sign_message.public_signature_nonce,
            sign_message.decentralized_party_nonce_public_share,
            sign_message.signature_nonce_share_commitment,
            sign_message.alpha_displacer_commitment,
            sign_message.beta_displacer_commitment,
            sign_message.signature_nonce_share_by_secret_share_commitment,
            sign_message.non_zero_commitment_to_signature_nonce_share_proof,
            sign_message.non_zero_commitment_to_alpha_displacer_share_proof,
            sign_message.commitment_to_beta_displacer_share_uc_proof,
            sign_message.proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments,
            sign_message.public_signature_nonce_proof,
            sign_message.decentralized_party_nonce_public_share_displacement_proof,
            &paillier_protocol_public_parameters.protocol_public_parameters.scalar_group_public_parameters,
            &paillier_protocol_public_parameters.protocol_public_parameters.group_public_parameters,
            &paillier_protocol_public_parameters.protocol_public_parameters.encryption_scheme_public_parameters,
            dkg_output.clone(),
            presign.clone(),
        )?;

        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                paillier_protocol_public_parameters
                    .protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                paillier_protocol_public_parameters
                    .protocol_public_parameters
                    .group_public_parameters
                    .clone(),
            )?;

        // $C_\alpha$
        let alpha_displacer_commitment = GroupElement::new(
            sign_message.alpha_displacer_commitment,
            &paillier_protocol_public_parameters
                .protocol_public_parameters
                .group_public_parameters,
        )?;

        // $C_\beta$
        let beta_displacer_commitment = GroupElement::new(
            sign_message.beta_displacer_commitment,
            &paillier_protocol_public_parameters
                .protocol_public_parameters
                .group_public_parameters,
        )?;

        let (
            ..,
            encryption_of_displaced_decentralized_party_nonce_share_protocol_context,
            encryption_of_partial_signature_protocol_context,
        ) = generate_protocol_contexts(presign.session_id, &dkg_output.public_key);

        // (d). Verify $\pi_{\textsf{ct}_{\alpha,\beta}}$.
        verify_committed_linear_evaluation::<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >(
            presign.encryption_of_mask,
            encryption_of_masked_decentralized_party_nonce_share_before_displacing.value(),
            sign_message.encryption_of_displaced_decentralized_party_nonce_share,
            beta_displacer_commitment,  // $C_\beta$
            alpha_displacer_commitment, // $C_\alpha$
            sign_message
                .encryption_of_displaced_decentralized_party_nonce_share_range_proof_commitment,
            sign_message.encryption_of_displaced_decentralized_party_nonce_share_proof,
            commitment_scheme_public_parameters.clone().into(),
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .group_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .unbounded_dcom_eval_witness_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .range_proof_dcom_eval_public_parameters
                .clone(),
            &encryption_of_displaced_decentralized_party_nonce_share_protocol_context,
            true,
            rng,
        )?;

        // (d) Verify $\pi_{\ct_{\CentralizedParty}}$.
        verify_committed_linear_evaluation::<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >(
            presign.encryption_of_mask,
            presign.encryption_of_masked_decentralized_party_key_share,
            sign_message.encryption_of_partial_signature,
            first_coefficient_commitment,  // $C_1$
            second_coefficient_commitment, // $C_2$
            sign_message.encryption_of_partial_signature_range_proof_commitment,
            sign_message.encryption_of_partial_signature_proof,
            commitment_scheme_public_parameters.clone().into(),
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .group_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .unbounded_dcom_eval_witness_public_parameters
                .clone(),
            paillier_protocol_public_parameters
                .range_proof_dcom_eval_public_parameters
                .clone(),
            &encryption_of_partial_signature_protocol_context,
            false,
            rng,
        )?;

        Ok(())
    }
}
