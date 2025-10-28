// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file defines the `Message` struct for Class Groups

use std::fmt::Debug;

use crate::languages;
use crate::languages::{
    CommitmentOfDiscreteLogProof, EqualityBetweenCommitmentsWithDifferentPublicParametersProof,
    KnowledgeOfDecommitmentProof, KnowledgeOfDecommitmentUCProof,
    VectorCommitmentOfDiscreteLogProof,
};
use ::class_groups::CiphertextSpaceGroupElement;

pub type Message<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = private::Message<
    <GroupElement as group::GroupElement>::Value,
    group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    KnowledgeOfDecommitmentProof<SCALAR_LIMBS, GroupElement>,
    KnowledgeOfDecommitmentUCProof<SCALAR_LIMBS, GroupElement>,
    EqualityBetweenCommitmentsWithDifferentPublicParametersProof<SCALAR_LIMBS, GroupElement>,
    CommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    VectorCommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    languages::class_groups::CommittedLinearEvaluationProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
>;

pub(super) mod private {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Message<
        GroupElementValue,
        CiphertextValue,
        DcomProof,
        DcomUCProof,
        DcomEqProof,
        DComDLProof,
        VecDComDLProof,
        DComEvalProof,
    > {
        // $R$
        pub public_signature_nonce: GroupElementValue,
        // $R_B$
        pub decentralized_party_nonce_public_share: GroupElementValue,
        // $C_{k}$
        pub signature_nonce_share_commitment: GroupElementValue,
        // $C_\alpha$
        pub alpha_displacer_commitment: GroupElementValue,
        // $C_\beta$
        pub beta_displacer_commitment: GroupElementValue,
        // $C_{kx}$
        pub signature_nonce_share_by_secret_share_commitment: GroupElementValue,
        // $\textsf{ct}_A$
        pub encryption_of_partial_signature: CiphertextValue,
        // $\textsf{ct}_{\alpha,\beta}$
        pub encryption_of_displaced_decentralized_party_nonce_share: CiphertextValue,
        // $\pi_{k}$
        pub non_zero_commitment_to_signature_nonce_share_proof: DcomProof,
        // $\pi_{\alpha}$
        pub non_zero_commitment_to_alpha_displacer_share_proof: DcomProof,
        // $\pi_{\beta}$
        pub commitment_to_beta_displacer_share_uc_proof: DcomUCProof,
        // $\pi_{kx}$
        pub proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments:
            DcomEqProof,
        // $\pi_{R}$
        pub public_signature_nonce_proof: DComDLProof,
        // $\pi_{R_{B}}$
        pub decentralized_party_nonce_public_share_displacement_proof: VecDComDLProof,
        // $\pi_{\textsf{ct{_{A}$
        pub encryption_of_partial_signature_proof: DComEvalProof,
        // $\pi_{\textsf{ct}_{\alpha,\beta}}$
        pub encryption_of_displaced_decentralized_party_nonce_share_proof: DComEvalProof,
    }
}
