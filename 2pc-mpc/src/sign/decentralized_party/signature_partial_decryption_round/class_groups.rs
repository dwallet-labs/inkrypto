// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Signature Partial Decryption round party for Class Groups

use crate::class_groups::DecryptionShare;
use crate::class_groups::{
    DKGDecentralizedPartyOutput, DecryptionKeySharePublicParameters, PartialDecryptionProof,
    Presign,
};
use crate::languages::class_groups::verify_committed_linear_evaluation;
use crate::sign::centralized_party::message::class_groups::Message;
use ::class_groups::decryption_key_share;
use ::class_groups::equivalence_class::EquivalenceClassOps;
use ::class_groups::MultiFoldNupowAccelerator;
use ::class_groups::SecretKeyShareSizedInteger;
use ::class_groups::{encryption_key, CompactIbqf, EquivalenceClass};
use ::class_groups::{
    equivalence_class, CiphertextSpacePublicParameters, RandomnessSpaceGroupElement,
    RandomnessSpacePublicParameters,
};
use ::class_groups::{CiphertextSpaceGroupElement, DecryptionKeyShare, EncryptionKey};
use ::class_groups::{DecryptionKey, DiscreteLogInF};
use crypto_bigint::Int;
use group::{GroupElement, HashToGroup};
use mpc::secret_sharing::shamir::over_the_integers::AdjustedLagrangeCoefficientSizedNumber;

use super::*;

impl Party {
    /// Partially decrypt the encrypted signature parts sent by the centralized party.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    #[allow(clippy::too_many_arguments)]
    pub fn partially_decrypt_encryption_of_signature_parts_prehash_semi_honest_class_groups<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >(
        expected_decrypters: HashSet<PartyID>,
        hashed_message: GroupElement::Scalar,
        dkg_output: DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        presign: Presign<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        decryption_key_share_public_parameters: &DecryptionKeySharePublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        virtual_party_id_to_decryption_key_share: HashMap<
            PartyID,
            DecryptionKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    ) -> crate::Result<     HashMap<
        PartyID,(
        DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    )>>
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicEncryptionKey<
            SCALAR_LIMBS,
            PublicParameters = encryption_key::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            PlaintextSpaceGroupElement = GroupElement::Scalar,
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
            CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        DecryptionKeyShare<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicDecryptionKeyShare<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            PublicParameters = decryption_key_share::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            SecretKeyShare = SecretKeyShareSizedInteger,
            PartialDecryptionProof = decryption_key_share::PartialDecryptionProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber,
            Error = ::class_groups::Error
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        Self::verify_encryption_of_signature_parts_prehash_class_groups(
            protocol_public_parameters,
            dkg_output,
            presign,
            sign_message.clone(),
            hashed_message,
        )?;

        Self::partially_decrypt_encryption_of_signature_parts_prehash_semi_honest::<
            SCALAR_LIMBS,
            ::class_groups::EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            ::class_groups::DecryptionKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >(
            expected_decrypters,
            sign_message.encryption_of_partial_signature,
            sign_message.encryption_of_displaced_decentralized_party_nonce_share,
            decryption_key_share_public_parameters,
            virtual_party_id_to_decryption_key_share,
            tangible_party_id,
            access_structure,
            &protocol_public_parameters.encryption_scheme_public_parameters,
        )
    }

    /// Partially decrypt the encrypted signature parts sent by the centralized party.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    #[allow(clippy::too_many_arguments)]
    pub fn partially_decrypt_encryption_of_signature_parts_prehash_class_groups<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >(
        hashed_message: GroupElement::Scalar,
        dkg_output: DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        presign: Presign<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        decryption_key_share_public_parameters: &DecryptionKeySharePublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        virtual_party_id_to_decryption_key_share: HashMap<
            PartyID,
            DecryptionKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        rng: &mut impl CsRng,
    ) -> crate::Result<
        HashMap<
            PartyID,
            (
                DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                PartialDecryptionProof<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            ),
        >,
    >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicEncryptionKey<
            SCALAR_LIMBS,
            PublicParameters = encryption_key::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            PlaintextSpaceGroupElement = GroupElement::Scalar,
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
            CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        DecryptionKeyShare<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicDecryptionKeyShare<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            PublicParameters = decryption_key_share::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            SecretKeyShare = SecretKeyShareSizedInteger,
            PartialDecryptionProof = decryption_key_share::PartialDecryptionProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber,
            Error = ::class_groups::Error
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        Self::verify_encryption_of_signature_parts_prehash_class_groups(
            protocol_public_parameters,
            dkg_output,
            presign,
            sign_message.clone(),
            hashed_message,
        )?;

        Self::partially_decrypt_encryption_of_signature_parts_prehash::<
            SCALAR_LIMBS,
            ::class_groups::EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            ::class_groups::DecryptionKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >(
            sign_message.encryption_of_partial_signature,
            sign_message.encryption_of_displaced_decentralized_party_nonce_share,
            decryption_key_share_public_parameters,
            virtual_party_id_to_decryption_key_share,
            tangible_party_id,
            access_structure,
            &protocol_public_parameters.encryption_scheme_public_parameters,
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
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    pub fn verify_encryption_of_signature_parts_prehash_class_groups<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >(
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        dkg_output: DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        presign: Presign<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        sign_message: Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        hashed_message: GroupElement::Scalar,
    ) -> crate::Result<()>
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicEncryptionKey<
            SCALAR_LIMBS,
            PublicParameters = encryption_key::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            PlaintextSpaceGroupElement = GroupElement::Scalar,
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
            CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        let (
            encryption_of_masked_decentralized_party_nonce_share_before_displacing,
            first_coefficient_commitment,
            second_coefficient_commitment
        ): (CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, GroupElement, GroupElement) = Self::verify_encryption_of_signature_parts_prehash::<SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey<SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement>>(
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
            &protocol_public_parameters.scalar_group_public_parameters,
            &protocol_public_parameters.group_public_parameters,
            &protocol_public_parameters.encryption_scheme_public_parameters,
            dkg_output.clone(),
            presign.clone(),
        )?;

        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
            )?;

        // $C_\alpha$
        let alpha_displacer_commitment = GroupElement::new(
            sign_message.alpha_displacer_commitment,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // $C_\beta$
        let beta_displacer_commitment = GroupElement::new(
            sign_message.beta_displacer_commitment,
            &protocol_public_parameters.group_public_parameters,
        )?;

        let (
            ..,
            encryption_of_displaced_decentralized_party_nonce_share_protocol_context,
            encryption_of_partial_signature_protocol_context,
        ) = generate_protocol_contexts(presign.session_id, &dkg_output.public_key);

        // (d). Verify $\pi_{\textsf{ct}_{\alpha,\beta}}$.
        verify_committed_linear_evaluation::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >(
            presign.encryption_of_mask,
            encryption_of_masked_decentralized_party_nonce_share_before_displacing.value(),
            sign_message.encryption_of_displaced_decentralized_party_nonce_share,
            beta_displacer_commitment,  // $C_\beta$
            alpha_displacer_commitment, // $C_\alpha$
            sign_message.encryption_of_displaced_decentralized_party_nonce_share_proof,
            commitment_scheme_public_parameters.clone().into(),
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            &encryption_of_displaced_decentralized_party_nonce_share_protocol_context,
            true,
        )?;

        // (d). Verify $\pi_{\textsf{ct}_{A}}$.
        verify_committed_linear_evaluation::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >(
            presign.encryption_of_mask,
            presign.encryption_of_masked_decentralized_party_key_share,
            sign_message.encryption_of_partial_signature,
            first_coefficient_commitment,  // $C_1$
            second_coefficient_commitment, // $C_2$
            sign_message.encryption_of_partial_signature_proof,
            commitment_scheme_public_parameters.clone().into(),
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            &encryption_of_partial_signature_protocol_context,
            true,
        )?;

        Ok(())
    }
}
