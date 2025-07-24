// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Signature Homomorphic Evaluation round party for Paillier

use group::PrimeGroupElement;
use mpc::two_party::RoundResult;

use crate::languages::paillier::prove_committed_linear_evaluation;
use crate::paillier::bulletproofs::PaillierProtocolPublicParameters;
use crate::paillier::CiphertextSpaceGroupElement;
use crate::paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS};
use crate::{
    bulletproofs::{RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS},
    paillier::bulletproofs::UnboundedDComEvalWitness,
};

use super::*;

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    > mpc::two_party::Round
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        Message<
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
        PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
    >
where
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        > + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    type Error = Error;
    type PrivateInput = SecretKeyShare<group::Value<GroupElement::Scalar>>;
    type PublicInput = PublicInput<
        GroupElement::Scalar,
        dkg::centralized_party::PublicOutput<GroupElement::Value>,
        presign::Presign<GroupElement::Value, group::Value<CiphertextSpaceGroupElement>>,
        PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = Self::PublicOutput;

    type PublicOutput = ();

    type IncomingMessage = ();
    type OutgoingMessage = Message<
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
    >;

    fn advance(
        _message: Self::IncomingMessage,
        secret_key_share: &Self::PrivateInput,
        public_input: &Self::PublicInput,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<
        RoundResult<Self::OutgoingMessage, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Self::evaluate_encryption_of_partial_signature_prehash_paillier(
            public_input.hashed_message,
            secret_key_share.0,
            public_input.dkg_output.clone(),
            public_input.presign.clone(),
            &public_input.protocol_public_parameters,
            rng,
        )
        .map(|sign_message| RoundResult {
            outgoing_message: sign_message,
            private_output: (),
            public_output: (),
        })
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        Message<
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
        PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
    >
where
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        > + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    pub fn evaluate_encryption_of_partial_signature_prehash_paillier(
        hashed_message: GroupElement::Scalar,
        centralized_party_secret_key_share: group::Value<GroupElement::Scalar>,
        dkg_output: dkg::centralized_party::PublicOutput<GroupElement::Value>,
        presign: presign::Presign<GroupElement::Value, group::Value<CiphertextSpaceGroupElement>>,
        paillier_protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        Message<
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
    > {
        let (
            beta_displacer,
            beta_displacer_commitment_randomness,
            alpha_displacer,
            alpha_displacer_commitment_randomness,
            first_coefficient,
            first_coefficient_commitment_randomness,
            second_coefficient,
            second_coefficient_commitment_randomness,
            public_signature_nonce,
            decentralized_party_nonce_public_share,
            signature_nonce_share_commitment,
            alpha_displacer_commitment,
            beta_displacer_commitment,
            signature_nonce_share_by_secret_share_commitment,
            encryption_of_masked_decentralized_party_nonce_share_before_displacing,
            non_zero_commitment_to_signature_nonce_share_proof,
            non_zero_commitment_to_alpha_displacer_share_proof,
            commitment_to_beta_displacer_share_uc_proof,
            proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments,
            public_signature_nonce_proof,
            decentralized_party_nonce_public_share_displacement_proof,
        ) = Self::evaluate_encryption_of_partial_signature_prehash(
            hashed_message,
            centralized_party_secret_key_share,
            dkg_output.clone(),
            presign.clone(),
            paillier_protocol_public_parameters,
            presign.session_id,
            rng,
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

        let (
            ..,
            encryption_of_displaced_decentralized_party_nonce_share_protocol_context,
            encryption_of_partial_signature_protocol_context,
        ) = generate_protocol_contexts(presign.session_id, &dkg_output.public_key);

        // (f) iv. $\pi_{\textsf{ct}_{\alpha,\beta}}\gets\Pi_{\textsf{zk}}^{L_{\sf
        // DComEval}[G,H,\textsf{},(\textsf{ct}_{\gamma},\textsf{ct}_{\gamma\cdot k},(\mathbb{G},G,q))]}(textsf{ct}_{\alpha,\beta},(C_{\beta},C_{\alpha});(\beta,\
        // alpha),\rho_{0},\rho_{1},\eta_{0})$.
        let (
            encryption_of_displaced_decentralized_party_nonce_share_proof,
            encryption_of_displaced_decentralized_party_nonce_share_range_proof_commitment,
            encryption_of_displaced_decentralized_party_nonce_share,
        ) = prove_committed_linear_evaluation::<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >(
            presign.encryption_of_mask,
            encryption_of_masked_decentralized_party_nonce_share_before_displacing.value(),
            beta_displacer,
            beta_displacer_commitment_randomness,
            alpha_displacer,
            alpha_displacer_commitment_randomness,
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

        // (f) v. $\pi_{\textsf{ct}_{A}}\gets \Pi_{\textsf{zk}}^{L_{\sf
        // DComEval}[G,H,\textsf{pk},(\textsf{ct}_{\gamma{,\textsf{ct}_{\gamma\cdot \textsf{key}}),(\mathbb{G},G,q)]}(\textsf{ct}_\A,(C_1,C_2);
        // (a_1,a_2), \rho_3\cdot r+\rho_0\cdot m,r\cdot
        // \rho_0,\eta_1)$
        let (
            encryption_of_partial_signature_proof,
            encryption_of_partial_signature_range_proof_commitment,
            encryption_of_partial_signature,
        ) = prove_committed_linear_evaluation::<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >(
            presign.encryption_of_mask,
            presign.encryption_of_masked_decentralized_party_key_share,
            first_coefficient,
            first_coefficient_commitment_randomness,
            second_coefficient,
            second_coefficient_commitment_randomness,
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

        let sign_message = Message {
            public_signature_nonce: public_signature_nonce.value(),
            decentralized_party_nonce_public_share: decentralized_party_nonce_public_share.value(),
            signature_nonce_share_commitment: signature_nonce_share_commitment.value(),
            alpha_displacer_commitment: alpha_displacer_commitment.value(),
            beta_displacer_commitment: beta_displacer_commitment.value(),
            signature_nonce_share_by_secret_share_commitment:
                signature_nonce_share_by_secret_share_commitment.value(),
            encryption_of_partial_signature: encryption_of_partial_signature.value(),
            encryption_of_displaced_decentralized_party_nonce_share:
                encryption_of_displaced_decentralized_party_nonce_share.value(),
            non_zero_commitment_to_signature_nonce_share_proof,
            non_zero_commitment_to_alpha_displacer_share_proof,
            commitment_to_beta_displacer_share_uc_proof,
            proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments,
            public_signature_nonce_proof,
            decentralized_party_nonce_public_share_displacement_proof,
            encryption_of_partial_signature_range_proof_commitment:
                encryption_of_partial_signature_range_proof_commitment.value(),
            encryption_of_partial_signature_proof,
            encryption_of_displaced_decentralized_party_nonce_share_range_proof_commitment:
                encryption_of_displaced_decentralized_party_nonce_share_range_proof_commitment
                    .value(),
            encryption_of_displaced_decentralized_party_nonce_share_proof,
        };

        Ok(sign_message)
    }
}
