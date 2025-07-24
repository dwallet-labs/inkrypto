// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file defines the `Message` struct for Paillier

use crate::languages;
use crate::languages::{
    CommitmentOfDiscreteLogProof, EqualityBetweenCommitmentsWithDifferentPublicParametersProof,
    KnowledgeOfDecommitmentProof, KnowledgeOfDecommitmentUCProof,
    VectorCommitmentOfDiscreteLogProof,
};

pub type Message<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
    RangeProof,
    UnboundedDComEvalWitness,
> = private::Message<
    <GroupElement as group::GroupElement>::Value,
    proof::range::CommitmentSchemeCommitmentSpaceValue<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >,
    homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    KnowledgeOfDecommitmentProof<SCALAR_LIMBS, GroupElement>,
    KnowledgeOfDecommitmentUCProof<SCALAR_LIMBS, GroupElement>,
    EqualityBetweenCommitmentsWithDifferentPublicParametersProof<SCALAR_LIMBS, GroupElement>,
    CommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    VectorCommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    languages::paillier::CommittedLinearEvaluationProof<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        UnboundedDComEvalWitness,
    >,
>;

pub(super) mod private {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Message<
        GroupElementValue,
        RangeProofCommitmentValue,
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
        pub(in crate::sign) decentralized_party_nonce_public_share: GroupElementValue,
        // $C_{k}$
        pub(in crate::sign) signature_nonce_share_commitment: GroupElementValue,
        // $C_\alpha$
        pub(in crate::sign) alpha_displacer_commitment: GroupElementValue,
        // $C_\beta$
        pub(in crate::sign) beta_displacer_commitment: GroupElementValue,
        // $C_{kx}$
        pub(in crate::sign) signature_nonce_share_by_secret_share_commitment: GroupElementValue,
        // $\textsf{ct}_A$
        pub(in crate::sign) encryption_of_partial_signature: CiphertextValue,
        // $\textsf{ct}_{\alpha,\beta}$
        pub(in crate::sign) encryption_of_displaced_decentralized_party_nonce_share:
            CiphertextValue,
        // $\pi_{k}$
        pub(in crate::sign) non_zero_commitment_to_signature_nonce_share_proof: DcomProof,
        // $\pi_{\alpha}$
        pub(in crate::sign) non_zero_commitment_to_alpha_displacer_share_proof: DcomProof,
        // $\pi_{\beta}$
        pub(in crate::sign) commitment_to_beta_displacer_share_uc_proof: DcomUCProof,
        // $\pi_{kx}$
        pub(in crate::sign) proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments:
            DcomEqProof,
        // $\pi_{R}$
        pub(in crate::sign) public_signature_nonce_proof: DComDLProof,
        // $\pi_{R_{B}}$
        pub(in crate::sign) decentralized_party_nonce_public_share_displacement_proof:
            VecDComDLProof,
        pub(in crate::sign) encryption_of_partial_signature_range_proof_commitment:
            RangeProofCommitmentValue,
        // $\pi_{\textsf{ct}_{A}$
        pub(in crate::sign) encryption_of_partial_signature_proof: DComEvalProof,
        pub(in crate::sign) encryption_of_displaced_decentralized_party_nonce_share_range_proof_commitment:
            RangeProofCommitmentValue,
        // $\pi_{\textsf{ct}_{\alpha,\beta}}$
        pub(in crate::sign) encryption_of_displaced_decentralized_party_nonce_share_proof:
            DComEvalProof,
    }
}
