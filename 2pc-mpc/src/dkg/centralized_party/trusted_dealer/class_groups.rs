// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the centralized party in the trusted dealer setting for Class Groups

use crypto_bigint::{Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::MultiFoldNupowAccelerator;
use class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CiphertextSpaceValue, CompactIbqf, EncryptionKey,
    EquivalenceClass, RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement, PrimeGroupElement};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::two_party::RoundResult;

use crate::class_groups::ProtocolPublicParameters;
use crate::dkg::centralized_party::trusted_dealer::encryption_of_decenetralized_party_secret_key_share_protocol_context;
use crate::dkg::centralized_party::{PublicInput, PublicOutput, SecretKeyShare};
use crate::languages::class_groups::{
    prove_encryption_of_discrete_log, EncryptionOfDiscreteLogProof,
};
use crate::languages::KnowledgeOfDiscreteLogProof;
use crate::{Error, ProtocolContext, Result};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Message<KnowledgeOfDiscreteLogProof, EncDLProof, GroupValue, CiphertextValue> {
    pub(crate) knowledge_of_secret_key_share_proof: KnowledgeOfDiscreteLogProof,
    pub(crate) encryption_of_decentralized_party_secret_key_share_proof: EncDLProof,
    pub(crate) encryption_of_decentralized_party_secret_key_share: CiphertextValue,
    pub(crate) centralized_party_public_key_share: GroupValue,
    pub(crate) decentralized_party_public_key_share: GroupValue,
}

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
    /// This function implements the first and only round of the centralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    fn deal_trusted_shares_class_groups(
        secret_key: group::Value<GroupElement::Scalar>,
        session_id: CommitmentSizedNumber,
        protocol_public_parameters: &ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(
        SecretKeyShare<group::Value<GroupElement::Scalar>>,
        PublicOutput<GroupElement::Value>,
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
            encryption_of_decentralized_party_secret_key_share,
        ) = prove_encryption_of_discrete_log(
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            &protocol_context,
            decentralized_party_secret_key_share,
            rng,
        )?;

        let message = Message {
            knowledge_of_secret_key_share_proof,
            encryption_of_decentralized_party_secret_key_share_proof,
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
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    > mpc::two_party::Round
    for super::Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
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
    type Error = Error;
    type PrivateInput = group::Value<GroupElement::Scalar>;
    type PublicInput = PublicInput<
        ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
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
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
            ProtocolContext,
        >,
        GroupElement::Value,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
            Self::deal_trusted_shares_class_groups(
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
