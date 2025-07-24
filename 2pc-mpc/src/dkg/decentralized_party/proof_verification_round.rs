// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{ConcatMixed, Uint};
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{
    direct_product, GroupElement, PartyID, PrimeGroupElement, StatisticalSecuritySizedNumber,
};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use crate::dkg::centralized_party::{protocol_context, PublicKeyShareAndProof};
use crate::dkg::derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share;
use crate::{
    dkg::{centralized_party, decentralized_party::Output},
    languages,
    languages::KnowledgeOfDiscreteLogUCProof,
    Error, ProtocolContext,
};

pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    ProtocolPublicParameters,
>(
    PhantomData<GroupElement>,
    PhantomData<EncryptionKey>,
    PhantomData<ProtocolPublicParameters>,
);

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
    >
where
    ProtocolPublicParameters: AsRef<
        crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
    >,
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    /// This function implements round 3 in the DKG protocol:
    /// Verifies zk-proof for $X_{A}$, and sets
    /// $X=X_{A}+X_{B}$.
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    pub fn verify_proof_of_centralized_party_public_key_share(
        public_key_share_and_proof: centralized_party::PublicKeyShareAndProof<
            GroupElement::Value,
            KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        >,
        decentralized_party_encryption_of_secret_key_share_first_part: group::Value<
            EncryptionKey::CiphertextSpaceGroupElement,
        >,
        decentralized_party_encryption_of_secret_key_share_second_part: group::Value<
            EncryptionKey::CiphertextSpaceGroupElement,
        >,
        decentralized_party_public_key_share_first_part: GroupElement::Value,
        decentralized_party_public_key_share_second_part: GroupElement::Value,
        protocol_public_parameters: &ProtocolPublicParameters,
        session_id: CommitmentSizedNumber,
    ) -> crate::Result<
        Output<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
    > {
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        // $X_{A}$
        let centralized_party_public_key_share = GroupElement::new(
            public_key_share_and_proof.public_key_share,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // $X_{B}$
        let (encryption_of_secret_key_share, public_key_share) = derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share::<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>(
            session_id,
            decentralized_party_encryption_of_secret_key_share_first_part,
            decentralized_party_encryption_of_secret_key_share_second_part,
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            &public_key_share_and_proof.public_key_share,
            &public_key_share_and_proof.proof,
            &protocol_public_parameters.group_public_parameters,
            &protocol_public_parameters.encryption_scheme_public_parameters,
        )?;

        let protocol_context: ProtocolContext = protocol_context(session_id);

        // === 3(b) Verify knowledge of $x_{A}$ proof ===
        // Verify $\pi_{\sf{DL}}$
        languages::verify_uc_knowledge_of_discrete_log(
            centralized_party_public_key_share,
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            &protocol_context,
            public_key_share_and_proof.proof,
        )?;

        // === 3(d) Set $X=X_{A}+X_{B}$. ===
        let public_key = centralized_party_public_key_share + public_key_share;

        // === 3(f) Output (and record) ===
        Ok(Output {
            public_key_share: public_key_share.value(),
            public_key: public_key.value(),
            encryption_of_secret_key_share: encryption_of_secret_key_share.value(),
            centralized_party_public_key_share: public_key_share_and_proof.public_key_share,
        })
    }
}

/// The public input of the DKG proof verification round.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<
    GroupElementValue,
    CiphertextSpaceValue,
    KnowledgeOfDiscreteLogUCProof,
    ProtocolPublicParameters,
> {
    pub public_key_share_and_proof:
        centralized_party::PublicKeyShareAndProof<GroupElementValue, KnowledgeOfDiscreteLogUCProof>,
    // $ \textsf{ct}_{\textsf{key},0} $
    pub encryption_of_secret_key_share_first_part: CiphertextSpaceValue,
    // $  \textsf{ct}_{\textsf{key},1} $
    pub encryption_of_secret_key_share_second_part: CiphertextSpaceValue,
    // $X_{B,0}$
    pub public_key_share_first_part: GroupElementValue,
    // $X_{B,1}$
    pub public_key_share_second_part: GroupElementValue,
    pub protocol_public_parameters: ProtocolPublicParameters,
    // The session id $sid$ of the DKG protocol.
    pub session_id: CommitmentSizedNumber,
}

impl<
        GroupElementValue,
        CiphertextSpaceValue,
        KnowledgeOfDiscreteLogUCProof,
        ProtocolPublicParameters,
    >
    From<(
        ProtocolPublicParameters,
        (
            [direct_product::Value<CiphertextSpaceValue, GroupElementValue>; 2],
            CommitmentSizedNumber,
        ),
        PublicKeyShareAndProof<GroupElementValue, KnowledgeOfDiscreteLogUCProof>,
    )>
    for PublicInput<
        GroupElementValue,
        CiphertextSpaceValue,
        KnowledgeOfDiscreteLogUCProof,
        ProtocolPublicParameters,
    >
{
    fn from(
        (
            protocol_public_parameters,
            (encryption_of_secret_key_share_and_public_key_share_parts, session_id),
            public_key_share_and_proof,
        ): (
            ProtocolPublicParameters,
            (
                [direct_product::Value<CiphertextSpaceValue, GroupElementValue>; 2],
                CommitmentSizedNumber,
            ),
            PublicKeyShareAndProof<GroupElementValue, KnowledgeOfDiscreteLogUCProof>,
        ),
    ) -> Self {
        let [encryption_of_secret_key_share_and_public_key_share_first_part, encryption_of_secret_key_share_and_public_key_share_second_part] =
            encryption_of_secret_key_share_and_public_key_share_parts;

        let (encryption_of_secret_key_share_first_part, public_key_share_first_part) =
            encryption_of_secret_key_share_and_public_key_share_first_part.into();

        let (encryption_of_secret_key_share_second_part, public_key_share_second_part) =
            encryption_of_secret_key_share_and_public_key_share_second_part.into();

        Self {
            public_key_share_and_proof,
            encryption_of_secret_key_share_first_part,
            encryption_of_secret_key_share_second_part,
            public_key_share_first_part,
            public_key_share_second_part,
            protocol_public_parameters,
            session_id,
        }
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > mpc::Party
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
    >
{
    type Error = Error;
    type PublicInput = PublicInput<
        GroupElement::Value,
        homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        ProtocolPublicParameters,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = Self::PublicOutput;
    type PublicOutput =
        Output<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>;
    type Message = ();
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
    > AsynchronouslyAdvanceable
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
    >
where
    ProtocolPublicParameters: AsRef<
        crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
    >,
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
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
        _rng: &mut impl CryptoRngCore,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Self::verify_proof_of_centralized_party_public_key_share(
            public_input.public_key_share_and_proof.clone(),
            public_input.encryption_of_secret_key_share_first_part,
            public_input.encryption_of_secret_key_share_second_part,
            public_input.public_key_share_first_part,
            public_input.public_key_share_second_part,
            &public_input.protocol_public_parameters,
            public_input.session_id,
        )
        .map(|public_output| AsynchronousRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: (),
            public_output,
        })
    }

    fn round_causing_threshold_not_reached(_failed_round: usize) -> Option<usize> {
        // This is a 1-round protocol, that only receives a message from the user,
        // so no `ThresholdNotReached` error can occur.
        None
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
    > Default
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
    >
{
    fn default() -> Self {
        Self(PhantomData, PhantomData, PhantomData)
    }
}
