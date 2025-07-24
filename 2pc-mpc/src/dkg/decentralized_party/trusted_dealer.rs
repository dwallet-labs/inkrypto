// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#[cfg(feature = "class_groups")]
pub mod class_groups;
#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
pub mod paillier;

use crate::dkg::centralized_party::trusted_dealer::knowledge_of_secret_key_share_protocol_context;
use crate::dkg::decentralized_party::Output;
use crate::languages::{verify_knowledge_of_discrete_log, KnowledgeOfDiscreteLogProof};
use crate::Error;
use commitment::CommitmentSizedNumber;
use group::PrimeGroupElement;
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
    Message,
    ProtocolPublicParameters,
>(
    PhantomData<GroupElement>,
    PhantomData<EncryptionKey>,
    PhantomData<Message>,
    PhantomData<ProtocolPublicParameters>,
);

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<Message, ProtocolPublicParameters> {
    pub centralized_party_message: Message,
    pub protocol_public_parameters: ProtocolPublicParameters,
    pub session_id: CommitmentSizedNumber,
}

impl<Message, ProtocolPublicParameters>
    From<(ProtocolPublicParameters, CommitmentSizedNumber, Message)>
    for PublicInput<Message, ProtocolPublicParameters>
{
    fn from(
        (protocol_public_parameters, session_id, centralized_party_message): (
            ProtocolPublicParameters,
            CommitmentSizedNumber,
            Message,
        ),
    ) -> Self {
        Self {
            centralized_party_message,
            session_id,
            protocol_public_parameters,
        }
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        Message: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        Message,
        ProtocolPublicParameters,
    >
{
    /// A helper function for the first and only round of the decentralized party in a trusted dealer setting.
    /// Verifies that the centralized party knows the secret key share that corresponds to the value of the public key share it sent.
    /// Used for the "import" feature.
    fn verify_knowledge_of_centralized_party_key_share_proof(
        centralized_party_public_key_share_value: GroupElement::Value,
        public_key_share_value: GroupElement::Value,
        encryption_of_secret_key_share: group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        knowledge_of_secret_key_share_proof: KnowledgeOfDiscreteLogProof<
            SCALAR_LIMBS,
            GroupElement,
        >,
        protocol_public_parameters: &ProtocolPublicParameters,
        session_id: CommitmentSizedNumber,
    ) -> crate::Result<
        Output<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
    >
    where
        ProtocolPublicParameters: AsRef<
            crate::ProtocolPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                GroupElement::PublicParameters,
                EncryptionKey::PublicParameters,
            >,
        >,
    {
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        let public_key_share = GroupElement::new(
            public_key_share_value,
            &protocol_public_parameters.group_public_parameters,
        )?;

        let centralized_party_public_key_share = GroupElement::new(
            centralized_party_public_key_share_value,
            &protocol_public_parameters.group_public_parameters,
        )?;

        let protocol_context = knowledge_of_secret_key_share_protocol_context(session_id);
        verify_knowledge_of_discrete_log(
            centralized_party_public_key_share,
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            &protocol_context,
            knowledge_of_secret_key_share_proof,
        )?;

        let public_key = (centralized_party_public_key_share + public_key_share).value();

        let output = Output {
            public_key_share: public_key_share_value,
            public_key,
            encryption_of_secret_key_share,
            centralized_party_public_key_share: centralized_party_public_key_share_value,
        };

        Ok(output)
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        Message: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > mpc::Party
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        Message,
        ProtocolPublicParameters,
    >
{
    type Error = Error;
    type PublicInput = PublicInput<Message, ProtocolPublicParameters>;
    type PrivateOutput = ();
    type PublicOutputValue = Self::PublicOutput;
    type PublicOutput =
        Output<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>;
    type Message = ();
}
