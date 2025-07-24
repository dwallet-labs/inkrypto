// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the decentralized party in the trusted dealer setting for Class Groups

use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};

use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::MultiFoldNupowAccelerator;
use class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CiphertextSpaceValue, CompactIbqf, EncryptionKey,
    EquivalenceClass, RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use commitment::CommitmentSizedNumber;
use group::{CsRng, PartyID, PrimeGroupElement};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use crate::class_groups::ProtocolPublicParameters;
use crate::dkg::centralized_party::trusted_dealer::class_groups::Message;
use crate::dkg::centralized_party::trusted_dealer::encryption_of_decenetralized_party_secret_key_share_protocol_context;
use crate::dkg::decentralized_party::trusted_dealer::Party;
use crate::dkg::decentralized_party::Output;
use crate::languages::class_groups::{
    verify_encryption_of_discrete_log, EncryptionOfDiscreteLogProof,
};
use crate::languages::KnowledgeOfDiscreteLogProof;
use crate::{ProtocolContext, Result};

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    >
    super::Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        Message<
            KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
            EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >,
            GroupElement::Value,
            CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
{
    /// This function implements the first and only round of the decentralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    fn verify_encryption_of_dealt_trusted_share_class_groups(
        session_id: CommitmentSizedNumber,
        protocol_public_parameters: &ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        message: &Message<
            KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
            EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >,
            GroupElement::Value,
            CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    ) -> Result<Output<GroupElement::Value, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>
    {
        let protocol_context =
            encryption_of_decenetralized_party_secret_key_share_protocol_context(session_id);

        verify_encryption_of_discrete_log(
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            &protocol_context,
            message
                .encryption_of_decentralized_party_secret_key_share_proof
                .clone(),
            message.decentralized_party_public_key_share,
            message.encryption_of_decentralized_party_secret_key_share,
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
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    > AsynchronouslyAdvanceable
    for Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        Message<
            KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
            EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >,
            GroupElement::Value,
            CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
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
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let public_output = Self::verify_encryption_of_dealt_trusted_share_class_groups(
            public_input.session_id,
            &public_input.protocol_public_parameters,
            &public_input.centralized_party_message,
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
