// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the decentralized party in the trusted dealer setting for Paillier

use std::collections::{HashMap, HashSet};

use crypto_bigint::{ConcatMixed, Uint};

use commitment::CommitmentSizedNumber;
use group::{CsRng, PartyID, PrimeGroupElement, Scale, StatisticalSecuritySizedNumber};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};
use tiresias::{CiphertextSpaceValue, LargeBiPrimeSizedNumber};

use crate::dkg::centralized_party::trusted_dealer::encryption_of_decenetralized_party_secret_key_share_protocol_context;
use crate::dkg::centralized_party::trusted_dealer::paillier::Message;
use crate::dkg::decentralized_party::Output;
use crate::languages::paillier::{verify_encryption_of_discrete_log, EncryptionOfDiscreteLogProof};
use crate::languages::KnowledgeOfDiscreteLogProof;
use crate::paillier::bulletproofs::PaillierProtocolPublicParameters;
use crate::paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS};
use crate::{
    bulletproofs::{RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS},
    ProtocolContext, Result,
};

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
    /// This function implements the first and only round of the decentralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    #[allow(clippy::type_complexity)]
    fn verify_encryption_of_dealt_trusted_share_paillier(
        session_id: CommitmentSizedNumber,
        protocol_public_parameters: &PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >,
        message: &Message<
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
        rng: &mut impl CsRng,
    ) -> Result<Output<GroupElement::Value, CiphertextSpaceValue>> {
        let protocol_context =
            encryption_of_decenetralized_party_secret_key_share_protocol_context(session_id);

        verify_encryption_of_discrete_log(
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
            message
                .encryption_of_decentralized_party_secret_key_share_proof
                .clone(),
            message.decentralized_party_public_key_share,
            message.encryption_of_decentralized_party_secret_key_range_proof_commitment,
            message.encryption_of_decentralized_party_secret_key_share,
            rng,
        )?;

        Self::verify_knowledge_of_centralized_party_key_share_proof(
            message.centralized_party_public_key_share,
            message.decentralized_party_public_key_share,
            message.encryption_of_decentralized_party_secret_key_share,
            message.knowledge_of_secret_key_share_proof.clone(),
            protocol_public_parameters,
            session_id,
        )
    }
}

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Scale<LargeBiPrimeSizedNumber>,
    > AsynchronouslyAdvanceable
    for super::Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
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
    type PrivateInput = ();

    fn advance(
        _session_id: CommitmentSizedNumber,
        _party_id: PartyID,
        _access_structure: &WeightedThresholdAccessStructure,
        _messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
        rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let public_output = Self::verify_encryption_of_dealt_trusted_share_paillier(
            public_input.session_id,
            &public_input.protocol_public_parameters,
            &public_input.centralized_party_message,
            rng,
        )?;

        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: (),
            public_output,
        })
    }

    fn round_causing_threshold_not_reached(_current_round: u64) -> Option<u64> {
        // This is a 1-round protocol, that only receives a message from the user,
        // so no `ThresholdNotReached` error can occur.
        None
    }
}
