// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the centralized party in the trusted dealer setting for Paillier

use crypto_bigint::{ConcatMixed, Uint};
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement, PrimeGroupElement, Scale, StatisticalSecuritySizedNumber};
use mpc::two_party::RoundResult;
use tiresias::{CiphertextSpaceValue, LargeBiPrimeSizedNumber};

use crate::dkg::centralized_party::trusted_dealer::encryption_of_decenetralized_party_secret_key_share_protocol_context;
use crate::dkg::centralized_party::{PublicInput, PublicOutput, SecretKeyShare};
use crate::languages::paillier::prove_encryption_of_discrete_log;
use crate::languages::paillier::EncryptionOfDiscreteLogProof;
use crate::languages::KnowledgeOfDiscreteLogProof;
use crate::paillier::bulletproofs::PaillierProtocolPublicParameters;
use crate::paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS};
use crate::{
    bulletproofs::{RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS},
    Error, ProtocolContext, Result,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Message<
    KnowledgeOfDiscreteLogProof,
    EncDLProof,
    GroupValue,
    RangeProofCommitmentValue,
    CiphertextValue,
> {
    pub(crate) knowledge_of_secret_key_share_proof: KnowledgeOfDiscreteLogProof,
    pub(crate) encryption_of_decentralized_party_secret_key_share_proof: EncDLProof,
    pub(crate) encryption_of_decentralized_party_secret_key_range_proof_commitment:
        RangeProofCommitmentValue,
    pub(crate) encryption_of_decentralized_party_secret_key_share: CiphertextValue,
    pub(crate) centralized_party_public_key_share: GroupValue,
    pub(crate) decentralized_party_public_key_share: GroupValue,
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Scale<LargeBiPrimeSizedNumber>,
    >
    super::Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
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
    /// This function implements the first and only round of the centralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    fn deal_trusted_shares_paillier(
        secret_key: group::Value<GroupElement::Scalar>,
        session_id: CommitmentSizedNumber,
        protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(
        SecretKeyShare<group::Value<GroupElement::Scalar>>,
        PublicOutput<GroupElement::Value>,
        Message<
            KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
            EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                GroupElement,
                ProtocolContext,
            >,
            GroupElement::Value,
            proof::range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RangeProof,
            >,
            CiphertextSpaceValue,
        >,
    )> {
        let (
            secret_key_share,
            decentralized_party_secret_key_share,
            knowledge_of_secret_key_share_proof,
            public_output,
        ) = Self::deal_trusted_shares(secret_key, protocol_public_parameters, session_id, rng)?;

        let protocol_context =
            encryption_of_decenetralized_party_secret_key_share_protocol_context(session_id);

        let (
            encryption_of_decentralized_party_secret_key_share_proof,
            encryption_of_decentralized_party_secret_key_range_proof_commitment,
            encryption_of_decentralized_party_secret_key_share,
        ) = prove_encryption_of_discrete_log(
            protocol_public_parameters
                .protocol_public_parameters
                .group_public_parameters
                .clone(),
            protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            protocol_public_parameters
                .unbounded_encdl_witness_public_parameters
                .clone(),
            protocol_public_parameters
                .range_proof_enc_dl_public_parameters
                .clone(),
            &protocol_context,
            decentralized_party_secret_key_share,
            rng,
        )?;

        let message = Message {
            knowledge_of_secret_key_share_proof,
            encryption_of_decentralized_party_secret_key_share_proof,
            encryption_of_decentralized_party_secret_key_range_proof_commitment:
                encryption_of_decentralized_party_secret_key_range_proof_commitment.value(),
            encryption_of_decentralized_party_secret_key_share:
                encryption_of_decentralized_party_secret_key_share.value(),
            centralized_party_public_key_share: public_output.public_key_share,
            decentralized_party_public_key_share: public_output
                .decentralized_party_public_key_share,
        };

        Ok((secret_key_share, public_output, message))
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Scale<LargeBiPrimeSizedNumber>,
    > mpc::two_party::Round
    for super::Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
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
    type PrivateInput = group::Value<GroupElement::Scalar>;
    type PublicInput = PublicInput<
        PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
    >;
    type PrivateOutput = SecretKeyShare<group::Value<GroupElement::Scalar>>;
    type PublicOutputValue = Self::PublicOutput;
    type PublicOutput = PublicOutput<GroupElement::Value>;
    type IncomingMessage = ();
    type OutgoingMessage = Message<
        KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
        EncryptionOfDiscreteLogProof<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            GroupElement,
            ProtocolContext,
        >,
        GroupElement::Value,
        proof::range::CommitmentSchemeCommitmentSpaceValue<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RangeProof,
        >,
        CiphertextSpaceValue,
    >;

    fn advance(
        _message: Self::IncomingMessage,
        secret_key: &Self::PrivateInput,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> std::result::Result<
        RoundResult<Self::OutgoingMessage, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let (secret_key_share, public_output, outgoing_message) =
            Self::deal_trusted_shares_paillier(
                *secret_key,
                public_input.session_id,
                &public_input.protocol_public_parameters,
                rng,
            )?;

        Ok(RoundResult {
            outgoing_message,
            private_output: secret_key_share,
            public_output,
        })
    }
}
