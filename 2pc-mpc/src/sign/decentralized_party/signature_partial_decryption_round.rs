// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use crypto_bigint::{ConcatMixed, Encoding, Uint};
use serde::{Deserialize, Serialize};

use commitment::{pedersen, CommitmentSizedNumber};
use group::{
    AffineXCoordinate, CsRng, GroupElement, PartyID, PrimeGroupElement,
    StatisticalSecuritySizedNumber,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use mpc::WeightedThresholdAccessStructure;

use crate::languages::{
    CommitmentOfDiscreteLogProof, EqualityBetweenCommitmentsWithDifferentPublicParametersProof,
    KnowledgeOfDecommitmentProof, KnowledgeOfDecommitmentUCProof,
    VectorCommitmentOfDiscreteLogProof,
};
use crate::sign::centralized_party::signature_homomorphic_evaluation_round::generate_protocol_contexts;
use crate::{dkg, languages, presign, sign, Error};

#[cfg(feature = "class_groups")]
mod class_groups;

#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
mod paillier;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party {}

impl Party {
    /// Partially decrypt the encrypted signature parts sent by the centralized party.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    /// As observed in [FMM+24]{https://eprint.iacr.org/2024/253.pdf} (Pg. 27 "Optimized Threshold Decryption"), verifying the aggregated signature proves correctness of decryption shares, which in this case need not be proven or verified directly. This results with an improved amortized cost for decryption. For this purpose, in this function we only compute decryption shares without their corresponding proofs.
    pub fn partially_decrypt_encryption_of_signature_parts_prehash_semi_honest<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        expected_decrypters: HashSet<PartyID>,
        // $\textsf{ct}_A$
        encryption_of_partial_signature: homomorphic_encryption::CiphertextSpaceValue<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
        // $\textsf{ct}_{\alpha,\beta}$
        encryption_of_displaced_decentralized_party_nonce_share: homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        decryption_key_share_public_parameters: &DecryptionKeyShare::PublicParameters,
        virtual_party_id_to_decryption_key_share: HashMap<PartyID, DecryptionKeyShare>,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
    ) -> crate::Result<
        HashMap<
            PartyID,
            (
                DecryptionKeyShare::DecryptionShare,
                DecryptionKeyShare::DecryptionShare,
            ),
        >,
    >
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Error: From<DecryptionKeyShare::Error>,
    {
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

        // The `DecryptionKeyShare` trait works with virtual parties, whilst the input is in tangible parties.
        // So we transition back from each virtual party to its tangible corresponding party.
        let expected_decrypters = access_structure.virtual_subset(expected_decrypters)?;

        // = \textsf{ct}_A
        let encryption_of_partial_signature = EncryptionKey::CiphertextSpaceGroupElement::new(
            encryption_of_partial_signature,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        // $\textsf{ct}_{\alpha,\beta}$
        let encryption_of_displaced_decentralized_party_nonce_share =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                encryption_of_displaced_decentralized_party_nonce_share,
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
            )?;

        virtual_party_id_to_decryption_key_share
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                // === Compute \textsf{pt}_A ===
                // Protocol C.3, round 2 step e.
                // This step emulates the functionality \mathcal{F}_{\textsf{TAHE}}.
                let partial_signature_decryption_share =
                    Option::from(decryption_key_share.generate_decryption_share_semi_honest(
                        &encryption_of_partial_signature, // = \textsf{ct}_A
                        expected_decrypters.clone(),
                        decryption_key_share_public_parameters,
                    ))
                    .ok_or(Error::InternalError)?;

                // === Compute \textsf{pt}_4 ===
                // Protocol C.3, step 2(e)
                let displaced_decentralized_party_nonce_decryption_share =
                    Option::from(decryption_key_share.generate_decryption_share_semi_honest(
                        &encryption_of_displaced_decentralized_party_nonce_share,
                        expected_decrypters.clone(),
                        decryption_key_share_public_parameters,
                    ))
                    .ok_or(Error::InternalError)?;

                Ok((
                    virtual_party_id,
                    (
                        partial_signature_decryption_share,
                        displaced_decentralized_party_nonce_decryption_share,
                    ),
                ))
            })
            .collect()
    }

    /// Partially decrypt the encrypted signature parts sent by the centralized party.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    #[allow(clippy::too_many_arguments)]
    pub fn partially_decrypt_encryption_of_signature_parts_prehash<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        // $\textsf{ct}_A$
        encryption_of_partial_signature: homomorphic_encryption::CiphertextSpaceValue<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
        // $\textsf{ct}_{\alpha,\beta}$
        encryption_of_displaced_decentralized_party_nonce_share: homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        decryption_key_share_public_parameters: &DecryptionKeyShare::PublicParameters,
        virtual_party_id_to_decryption_key_share: HashMap<PartyID, DecryptionKeyShare>,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<
        HashMap<
            PartyID,
            (
                DecryptionKeyShare::DecryptionShare,
                DecryptionKeyShare::DecryptionShare,
                DecryptionKeyShare::PartialDecryptionProof,
            ),
        >,
    >
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Error: From<DecryptionKeyShare::Error>,
    {
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

        // = \textsf{ct}_A
        let encryption_of_partial_signature = EncryptionKey::CiphertextSpaceGroupElement::new(
            encryption_of_partial_signature,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        // $\textsf{ct}_{\alpha,\beta}$
        let encryption_of_displaced_decentralized_party_nonce_share =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                encryption_of_displaced_decentralized_party_nonce_share,
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
            )?;

        virtual_party_id_to_decryption_key_share.into_iter().map(|(virtual_party_id, decryption_key_share)| {
            let (decryption_shares, proof) = Option::from(decryption_key_share.generate_decryption_shares(
                vec![
                    encryption_of_partial_signature,
                    encryption_of_displaced_decentralized_party_nonce_share,
                ],
                decryption_key_share_public_parameters,
                rng,
            ))
                .ok_or(Error::InternalError)?;

            match &decryption_shares[..] {
                [partial_signature_decryption_share,
                displaced_decentralized_party_nonce_decryption_share, ] => Ok((virtual_party_id, (
                    partial_signature_decryption_share.clone(),
                    displaced_decentralized_party_nonce_decryption_share.clone(),
                    proof
                ))),
                _ => Err(Error::InternalError)
            }
        }).collect()
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
    fn verify_encryption_of_signature_parts_prehash<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
    // $ m $
        hashed_message: GroupElement::Scalar,
        session_id: CommitmentSizedNumber,
    // $R$
        public_signature_nonce: GroupElement::Value,
    // $R_B$
        decentralized_party_nonce_public_share: GroupElement::Value,
    // $C_{k}$
        signature_nonce_share_commitment: GroupElement::Value,
    // $C_\alpha$
        alpha_displacer_commitment: GroupElement::Value,
    // $C_\beta$
        beta_displacer_commitment: GroupElement::Value,
    // $C_{kx}$
        signature_nonce_share_by_secret_share_commitment: GroupElement::Value,
    // $\pi_{k}$
        non_zero_commitment_to_signature_nonce_share_proof: KnowledgeOfDecommitmentProof<
            SCALAR_LIMBS,
            GroupElement,
        >,
    // $\pi_{\alpha}$
        non_zero_commitment_to_alpha_displacer_share_proof: KnowledgeOfDecommitmentProof<
            SCALAR_LIMBS,
            GroupElement,
        >,
    // $\pi_{\beta}$
        commitment_to_beta_displacer_share_uc_proof: KnowledgeOfDecommitmentUCProof<
            SCALAR_LIMBS,
            GroupElement,
        >,
    // $\pi_{kx}$
        proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments:
        EqualityBetweenCommitmentsWithDifferentPublicParametersProof<
            SCALAR_LIMBS,
            GroupElement,
        >,
    // $\pi_{R}$
        public_signature_nonce_proof: CommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    // $\pi_{R_{B}}$
        decentralized_party_nonce_public_share_displacement_proof:
        VectorCommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
        scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
        group_public_parameters: &GroupElement::PublicParameters,
        encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: presign::Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    ) -> crate::Result<(
        EncryptionKey::CiphertextSpaceGroupElement,
        GroupElement,
        GroupElement,
    )> where         Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
    {
        // $ R_B$
        let nonce_public_share = GroupElement::new(
            decentralized_party_nonce_public_share,
            group_public_parameters,
        )?;

        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                scalar_group_public_parameters.clone(),
                group_public_parameters.clone(),
            )?;

        // $ R $
        let public_signature_nonce =
            GroupElement::new(public_signature_nonce, group_public_parameters)?;

        // $ r $
        let nonce_x_coordinate = public_signature_nonce.x();

        // $ G $
        let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

        // $C_{k}$
        let signature_nonce_share_commitment =
            GroupElement::new(signature_nonce_share_commitment, group_public_parameters)?;

        // $C_\alpha$
        let alpha_displacer_commitment =
            GroupElement::new(alpha_displacer_commitment, group_public_parameters)?;

        // $C_\beta$
        let beta_displacer_commitment =
            GroupElement::new(beta_displacer_commitment, group_public_parameters)?;

        // $C_{kx}$
        let signature_nonce_share_by_secret_share_commitment = GroupElement::new(
            signature_nonce_share_by_secret_share_commitment,
            group_public_parameters,
        )?;

        // --- Step 2(c) ---
        // Call the random oracle
        // $\mathcal{H}(textsf{sid},\textsf{msg}, \mathbb{G},G,q,H,X,\textsf{pres}_{X,\textsf{sid}},C_{k},C_{kx},X_{A},C_{\
        // alpha},C_{\beta},\pi_{k},\pi_{\alpha},\pi_{\beta})$, and receives $\mu_{k}$. It then
        // computes:
        // (c)i. $\textsf{ct}_{\gamma\cdot k}=(\textsf{ct}_{\gamma\cdot k_{0}})\oplus(\mu_{k}\odot\textsf{ct}_{\gamma\cdot k_{1}})$
        // (c)ii. $R'_B=( R_{B,0})+(\mu_{k}\cdot
        // R_{B,1})$

        // ($\textsf{ct}_{\gamma\cdot k}$, $R'_B$)
        let (encryption_of_masked_decentralized_party_nonce_share_before_displacing, decentralized_party_nonce_public_share_before_displacing) = sign::derive_randomized_decentralized_party_public_nonce_share_and_encryption_of_nonce_share::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >(
            session_id,
            &hashed_message,
            presign.clone(),
            encryption_scheme_public_parameters,
            group_public_parameters,
            &commitment_scheme_public_parameters,
            &dkg_output.public_key,
            &dkg_output.centralized_party_public_key_share,
            &signature_nonce_share_commitment,
            &alpha_displacer_commitment,
            &beta_displacer_commitment,
            &signature_nonce_share_by_secret_share_commitment,
            &non_zero_commitment_to_signature_nonce_share_proof,
            &non_zero_commitment_to_alpha_displacer_share_proof,
            &commitment_to_beta_displacer_share_uc_proof,
        )?;

        // (c)iii. $C_1=(r\odot C_{kx})\oplus(m\odot C_{k})$
        let first_coefficient_commitment = (nonce_x_coordinate
            * signature_nonce_share_by_secret_share_commitment)
            + (hashed_message * signature_nonce_share_commitment);

        // (c)iv.  $C_2=r\odot C_{k}$
        let second_coefficient_commitment = nonce_x_coordinate * signature_nonce_share_commitment;

        let (
            non_zero_commitment_to_signature_nonce_share_protocol_context,
            non_zero_commitment_to_alpha_displacer_share_protocol_context,
            commitment_to_beta_displacer_share_protocol_context,
            equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments_protocol_context,
            decentralized_party_nonce_public_share_displacement_protocol_context,
            public_signature_nonce_protocol_context,
            ..,
        ) = generate_protocol_contexts(session_id, &dkg_output.public_key);

        // --- Step (e): Verify the Proofs. ---
        // (d) Verify $\pi_{k}$.
        languages::verify_knowledge_of_decommitment(
            generator,
            commitment_scheme_public_parameters
                .with_altered_message_generators([signature_nonce_share_commitment.value()]),
            &non_zero_commitment_to_signature_nonce_share_protocol_context,
            non_zero_commitment_to_signature_nonce_share_proof,
        )?;

        // (d) Verify $\pi_{\alpha}$.
        languages::verify_knowledge_of_decommitment(
            generator,
            commitment_scheme_public_parameters
                .with_altered_message_generators([alpha_displacer_commitment.value()]),
            &non_zero_commitment_to_alpha_displacer_share_protocol_context,
            non_zero_commitment_to_alpha_displacer_share_proof,
        )?;

        // (d) Verify $\pi_{\beta}$.
        languages::verify_uc_knowledge_of_decommitment(
            beta_displacer_commitment,
            commitment_scheme_public_parameters.clone(),
            &commitment_to_beta_displacer_share_protocol_context,
            commitment_to_beta_displacer_share_uc_proof,
        )?;

        // (d) Verify $\pi_{kx}$.
        languages::verify_equality_between_commitments_with_different_public_parameters(
            signature_nonce_share_commitment, // $ C_{k} $
            signature_nonce_share_by_secret_share_commitment, // $ C_{kx} $
            commitment_scheme_public_parameters.clone(),
            commitment_scheme_public_parameters
                .with_altered_message_generators([dkg_output.centralized_party_public_key_share]),
            &equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments_protocol_context,
            proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments,
        )?;

        // (d) Verify $\pi_{R}$.
        languages::verify_commitment_of_discrete_log(
            public_signature_nonce.value(),   // $ R $
            signature_nonce_share_commitment, // $ C_{k} $
            nonce_public_share,               // $ R_{\DistributedParty} $
            commitment_scheme_public_parameters.clone(),
            scalar_group_public_parameters.clone(),
            group_public_parameters.clone(),
            &public_signature_nonce_protocol_context,
            public_signature_nonce_proof,
        )?;

        // (e)vi. Verify $\pi_{R_{B}}$.
        languages::verify_vector_commitment_of_discrete_log(
            decentralized_party_nonce_public_share_before_displacing.value(),
            alpha_displacer_commitment, // $C_\alpha$
            beta_displacer_commitment,  // $C_\beta$
            nonce_public_share,         // $ R_{B} $
            commitment_scheme_public_parameters.clone().into(),
            scalar_group_public_parameters.clone(),
            group_public_parameters.clone(),
            &decentralized_party_nonce_public_share_displacement_protocol_context,
            decentralized_party_nonce_public_share_displacement_proof,
        )?;

        Ok((
            encryption_of_masked_decentralized_party_nonce_share_before_displacing,
            first_coefficient_commitment,
            second_coefficient_commitment,
        ))
    }
}
