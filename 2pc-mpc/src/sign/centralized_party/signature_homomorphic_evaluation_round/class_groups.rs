// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Signature Homomorphic Evaluation round party for Class Groups

use crypto_bigint::{Int, Uint};

use ::class_groups::CiphertextSpaceGroupElement;
use ::class_groups::{encryption_key, CompactIbqf, EncryptionKey, EquivalenceClass};
use ::class_groups::{
    equivalence_class, CiphertextSpacePublicParameters, RandomnessSpaceGroupElement,
    RandomnessSpacePublicParameters,
};
use mpc::two_party::RoundResult;

use crate::languages::class_groups::prove_committed_linear_evaluation;
use crate::sign::centralized_party::message::class_groups::Message;

use super::*;

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >
    Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        ::class_groups::EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        > + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    pub fn evaluate_encryption_of_partial_signature_prehash_class_groups(
        hashed_message: GroupElement::Scalar,
        centralized_party_secret_key_share: group::Value<GroupElement::Scalar>,
        centralized_party_dkg_public_output: dkg::centralized_party::PublicOutput<
            GroupElement::Value,
        >,
        presign: presign::Presign<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        rng: &mut impl CryptoRngCore,
    ) -> Result<
        Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
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
            centralized_party_dkg_public_output.clone(),
            presign.clone(),
            protocol_public_parameters,
            presign.session_id,
            rng,
        )?;

        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
            )?;

        let (
            ..,
            encryption_of_displaced_decentralized_party_nonce_share_protocol_context,
            encryption_of_partial_signature_protocol_context,
        ) = generate_protocol_contexts(
            presign.session_id,
            &centralized_party_dkg_public_output.public_key,
        );

        // (f) iv. $\pi_{\textsf{ct}_{\alpha,\beta}}\gets\Pi_{\textsf{zk}}^{L_{\sf
        // DComEval}[G,H,\textsf{},(\textsf{ct}_{\gamma},\textsf{ct}_{\gamma\cdot k},(\mathbb{G},G,q))]}(textsf{ct}_{\alpha,\beta},(C_{\beta},C_{\alpha});(\beta,\
        // alpha),\rho_{0},\rho_{1},\eta_{0})$.
        let (
            encryption_of_displaced_decentralized_party_nonce_share_proof,
            encryption_of_displaced_decentralized_party_nonce_share,
        ) = prove_committed_linear_evaluation::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >(
            presign.encryption_of_mask,
            encryption_of_masked_decentralized_party_nonce_share_before_displacing.value(),
            beta_displacer,
            beta_displacer_commitment_randomness,
            alpha_displacer,
            alpha_displacer_commitment_randomness,
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
            rng,
        )?;

        // (f) v. $\pi_{\textsf{ct}_{A}}\gets \Pi_{\textsf{zk}}^{L_{\sf
        // DComEval}[G,H,\textsf{pk},(\textsf{ct}_{\gamma{,\textsf{ct}_{\gamma\cdot \textsf{key}}),(\mathbb{G},G,q)]}(\textsf{ct}_\A,(C_1,C_2);
        // (a_1,a_2), \rho_3\cdot r+\rho_0\cdot m,r\cdot
        // \rho_0,\eta_1)$
        let (encryption_of_partial_signature_proof, encryption_of_partial_signature) =
            prove_committed_linear_evaluation::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >(
                presign.encryption_of_mask,
                presign.encryption_of_masked_decentralized_party_key_share,
                first_coefficient,
                first_coefficient_commitment_randomness,
                second_coefficient,
                second_coefficient_commitment_randomness,
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
            encryption_of_partial_signature_proof,
            encryption_of_displaced_decentralized_party_nonce_share_proof,
        };

        Ok(sign_message)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    > mpc::two_party::Round
    for Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        ::class_groups::EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        > + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    type Error = Error;
    type PrivateInput = SecretKeyShare<group::Value<GroupElement::Scalar>>;
    type PublicInput = PublicInput<
        GroupElement::Scalar,
        dkg::centralized_party::PublicOutput<GroupElement::Value>,
        presign::Presign<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = Self::PublicOutput;

    type PublicOutput = ();

    type IncomingMessage = ();
    type OutgoingMessage = Message<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
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
        Self::evaluate_encryption_of_partial_signature_prehash_class_groups(
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
