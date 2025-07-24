// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::fmt::Debug;
use std::marker::PhantomData;

use crypto_bigint::{ConcatMixed, Uint};
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement, PrimeGroupElement, Samplable, StatisticalSecuritySizedNumber};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::two_party::RoundResult;

use crate::dkg::decentralized_party::EncryptionOfSecretKeyShareAndPublicKeyShare;
use crate::dkg::derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share;
use crate::Party::CentralizedParty;
use crate::{languages, languages::KnowledgeOfDiscreteLogUCProof, Error, ProtocolContext};

pub mod trusted_dealer;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKeyShare<GroupElementValue>(pub(crate) GroupElementValue);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicOutput<GroupElementValue> {
    pub public_key_share: GroupElementValue,
    pub public_key: GroupElementValue,
    pub decentralized_party_public_key_share: GroupElementValue,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyShareAndProof<GroupElementValue, KnowledgeOfDiscreteLogUCProof> {
    pub proof: KnowledgeOfDiscreteLogUCProof,
    pub public_key_share: GroupElementValue,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
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
{
    /// This function implements step 2 of the DKG protocol:
    ///
    /// Samples $x_\A\gets\mathbb{Z}_q$ and sets
    /// $X_{A}=x_{A}\cdot G$
    ///
    /// Runs $\Pi_{\textsf{zk-uc}}^{L_{\
    /// sf{DL}}[(\mathbb{G}, G,q)]}(X_{A};x_{A)$ generating a proof
    /// $\pi_{\sf{DL}}$.
    /// Call the random oracle on the public parameters, the distributed party output and the proof to get $\mu_{x}^{0},\mu_{x}^{1},\mu_{x}^{G}$
    /// Sets $X=X_{A}+\mu_{x}^{0}\cdot X_{B}^{0}+\mu_{x}^{1}\cdot X_{B}^{1}+\mu_{x}^{G}\cdot G$.
    ///
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    pub fn sample_and_prove_public_key_share(
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
        rng: &mut impl CsRng,
    ) -> crate::Result<(
        PublicKeyShareAndProof<
            GroupElement::Value,
            KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        >,
        SecretKeyShare<group::Value<GroupElement::Scalar>>,
        PublicOutput<GroupElement::Value>,
    )>  where Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>{
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        // === 2(c) Sample $x_A\gets\mathbb{Z}_q$ ====
        let secret_key_share = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )?;

        let protocol_context: ProtocolContext = protocol_context(session_id);

        // Run $\Pi_{\textsf{zk-uc}}^{L_{\sf{DL}}[(\mathbb{G}, G,q)]}(
        // X_{A};x_{A})$ generating a proof $\pi_{\sf{DL}}$
        let (knowledge_of_discrete_log_uc_proof, public_key_share) =
            languages::uc_prove_knowledge_of_discrete_log::<SCALAR_LIMBS, GroupElement>(
                secret_key_share,
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
                &protocol_context,
                rng,
            )?;

        // $X_{B}=\mu_{x}^{0}\cdot X_{B}^{0}+\mu_{x}^{1}\cdot X_{B}^{1}+\mu_{x}^{G}\cdot G$.
        let (_, decentralized_party_public_key_share) = derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share::<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>(
            session_id,
            decentralized_party_encryption_of_secret_key_share_first_part,
            decentralized_party_encryption_of_secret_key_share_second_part,
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            &public_key_share.value(),
            &knowledge_of_discrete_log_uc_proof,
            &protocol_public_parameters.group_public_parameters,
            &protocol_public_parameters.encryption_scheme_public_parameters,
        )?;

        // === 2(c) Set $X_{A}=x_{A}\cdot G$ ===
        let public_key = public_key_share + decentralized_party_public_key_share;

        let public_key_share = public_key_share.value();

        // === Construct X_A proof object ===
        // Used to emulate idealized 2(d), 2(e) F^{L_DL}_{com-zk}
        let public_key_share_and_proof = PublicKeyShareAndProof::<
            GroupElement::Value,
            KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        > {
            proof: knowledge_of_discrete_log_uc_proof,
            public_key_share,
        };

        // === 3(b) Output (and record) ===
        let output = PublicOutput {
            public_key_share,
            public_key: public_key.value(),
            decentralized_party_public_key_share: decentralized_party_public_key_share.value(),
        };

        Ok((
            public_key_share_and_proof,
            SecretKeyShare(secret_key_share.value()),
            output,
        ))
    }
}

pub(super) fn protocol_context(session_id: CommitmentSizedNumber) -> ProtocolContext {
    ProtocolContext {
        party: CentralizedParty,
        session_id,
        protocol_name: "2PC-MPC DKG".to_string(),
        round_name: "2 - Sample and Prove Centralized Public Key Share".to_string(),
        proof_name: "$\\pi_{\\sf{DL}}$ - Knowledge of Centralized Party Secret Key Share UC Proof"
            .to_string(),
        public_key: None,
    }
}

/// The public input of the DKG proof verification round.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<ProtocolPublicParameters> {
    pub protocol_public_parameters: ProtocolPublicParameters,
    pub session_id: CommitmentSizedNumber,
}

impl<ProtocolPublicParameters> From<(ProtocolPublicParameters, CommitmentSizedNumber)>
    for PublicInput<ProtocolPublicParameters>
{
    fn from(
        (protocol_public_parameters, session_id): (ProtocolPublicParameters, CommitmentSizedNumber),
    ) -> Self {
        Self {
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
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
    > mpc::two_party::Round
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
    type Error = Error;
    type PrivateInput = ();
    type PublicInput = PublicInput<ProtocolPublicParameters>;
    type PrivateOutput = SecretKeyShare<group::Value<GroupElement::Scalar>>;
    type PublicOutputValue = Self::PublicOutput;
    type PublicOutput = PublicOutput<GroupElement::Value>;

    type IncomingMessage = [EncryptionOfSecretKeyShareAndPublicKeyShare<
        GroupElement::Value,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
    >; 2];

    type OutgoingMessage = PublicKeyShareAndProof<
        GroupElement::Value,
        KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
    >;

    fn advance(
        encryption_of_secret_key_share_and_public_key_share_parts: Self::IncomingMessage,
        _private_input: &Self::PrivateInput,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<
        RoundResult<Self::OutgoingMessage, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let [encryption_of_secret_key_share_and_public_key_share_first_part, encryption_of_secret_key_share_and_public_key_share_second_part] =
            encryption_of_secret_key_share_and_public_key_share_parts;

        let (
            decentralized_party_encryption_of_secret_key_share_first_part,
            decentralized_party_public_key_share_first_part,
        ) = encryption_of_secret_key_share_and_public_key_share_first_part.into();

        let (
            decentralized_party_encryption_of_secret_key_share_second_part,
            decentralized_party_public_key_share_second_part,
        ) = encryption_of_secret_key_share_and_public_key_share_second_part.into();

        let (outgoing_message, private_output, public_output) =
            Self::sample_and_prove_public_key_share(
                decentralized_party_encryption_of_secret_key_share_first_part,
                decentralized_party_encryption_of_secret_key_share_second_part,
                decentralized_party_public_key_share_first_part,
                decentralized_party_public_key_share_second_part,
                &public_input.protocol_public_parameters,
                public_input.session_id,
                rng,
            )?;

        Ok(RoundResult {
            outgoing_message,
            private_output,
            public_output,
        })
    }
}
