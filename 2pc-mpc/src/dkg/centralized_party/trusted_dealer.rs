// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement, PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;

use crate::dkg::centralized_party::{PublicOutput, SecretKeyShare};
use crate::languages::{prove_knowledge_of_discrete_log, KnowledgeOfDiscreteLogProof};
use crate::Party::CentralizedParty;
use crate::ProtocolContext;

#[cfg(feature = "class_groups")]
pub mod class_groups;
#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
pub mod paillier;

pub(crate) fn encryption_of_decenetralized_party_secret_key_share_protocol_context(
    session_id: CommitmentSizedNumber,
) -> ProtocolContext {
    ProtocolContext {
        party: CentralizedParty,
        session_id,
        protocol_name: "2PC-MPC Trusted Dealer DKG".to_string(),
        round_name: "1 - Deal Trusted Shares".to_string(),
        proof_name: "$\\Pi_{\\textsf{zk}}^{L_{\\sf EncDL}[\textsf{pk}, (\\mathbb{G}, G, q)]}$ - Encryption of Dealt Decentralized Party Secret Key Share and Public Key Share Proof"
            .to_string(),
        public_key: None,
    }
}

pub(crate) fn knowledge_of_secret_key_share_protocol_context(
    session_id: CommitmentSizedNumber,
) -> ProtocolContext {
    ProtocolContext {
        party: CentralizedParty,
        session_id,
        protocol_name: "2PC-MPC Trusted Dealer DKG".to_string(),
        round_name: "1 - Deal Trusted Shares".to_string(),
        proof_name: "$\\Pi_{\\textsf{zk}}^{L_{\\sf{DL}}[(\\mathbb{G}, G,q)]}(x\\cdot G;x)$ - Knowledge of Secret Key Share Proof"
            .to_string(),
        public_key: None,
    }
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
    /// This function implements the first and only round of the centralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    fn deal_trusted_shares(
        secret_key: group::Value<GroupElement::Scalar>,
        protocol_public_parameters: &ProtocolPublicParameters,
        session_id: CommitmentSizedNumber,
        rng: &mut impl CsRng,
    ) -> crate::Result<(
        SecretKeyShare<group::Value<GroupElement::Scalar>>,
        GroupElement::Scalar,
        KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
        PublicOutput<GroupElement::Value>,
    )>
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
        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )?;

        let secret_key = GroupElement::Scalar::new(
            secret_key,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;
        let public_key = (secret_key * generator).value();

        // sampled decntralized party secret key share uniformly at random. $x_{B}\gets [0,q], x_{A}=x-X_{B}, X_{B}=x_{B}\cdot G,X_{A}=X-X_{B}$.
        let decentralized_party_secret_key_share = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )?;
        let decentralized_party_public_key_share =
            (decentralized_party_secret_key_share * generator).value();

        let secret_key_share = secret_key - decentralized_party_secret_key_share;

        let protocol_context = knowledge_of_secret_key_share_protocol_context(session_id);

        let (knowledge_of_secret_key_share_proof, public_key_share) =
            prove_knowledge_of_discrete_log::<SCALAR_LIMBS, GroupElement>(
                secret_key_share,
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
                &protocol_context,
                rng,
            )?;

        let public_output = PublicOutput {
            public_key,
            public_key_share: public_key_share.value(),
            decentralized_party_public_key_share,
        };

        Ok((
            SecretKeyShare(secret_key_share.value()),
            decentralized_party_secret_key_share,
            knowledge_of_secret_key_share_proof,
            public_output,
        ))
    }
}
