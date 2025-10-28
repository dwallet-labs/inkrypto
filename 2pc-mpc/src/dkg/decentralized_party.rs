// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;
use std::marker::PhantomData;

use crypto_bigint::{ConcatMixed, Encoding, Uint};
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{
    GroupElement, PrimeGroupElement, Scale, StatisticalSecuritySizedNumber, Transcribeable,
};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;

use crate::dkg::centralized_party::{protocol_context, PublicKeyShareAndProof};
use crate::dkg::derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share;
use crate::{
    dkg::centralized_party, languages, languages::KnowledgeOfDiscreteLogUCProof, Error,
    ProtocolContext, ProtocolPublicParameters,
};

mod class_groups;
pub mod trusted_dealer;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Output<GroupElementValue, CiphertextSpaceValue> {
    pub public_key_share: GroupElementValue,
    pub public_key: GroupElementValue,
    pub encryption_of_secret_key_share: CiphertextSpaceValue,
    pub centralized_party_public_key_share: GroupElementValue,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum VersionedOutput<const SCALAR_LIMBS: usize, GroupElementValue, CiphertextSpaceValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    TargetedPublicDKGOutput(Output<GroupElementValue, CiphertextSpaceValue>),
    UniversalPublicDKGOutput {
        output: Output<GroupElementValue, CiphertextSpaceValue>,
        first_key_public_randomizer: Uint<SCALAR_LIMBS>,
        second_key_public_randomizer: Uint<SCALAR_LIMBS>,
        free_coefficient_key_public_randomizer: Uint<SCALAR_LIMBS>,
        global_decentralized_party_output_commitment: CommitmentSizedNumber,
    },
}

impl<const SCALAR_LIMBS: usize, GroupElementValue, CiphertextSpaceValue>
    From<VersionedOutput<SCALAR_LIMBS, GroupElementValue, CiphertextSpaceValue>>
    for Output<GroupElementValue, CiphertextSpaceValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn from(
        versioned_output: VersionedOutput<SCALAR_LIMBS, GroupElementValue, CiphertextSpaceValue>,
    ) -> Self {
        match versioned_output {
            VersionedOutput::TargetedPublicDKGOutput(output) => output,
            VersionedOutput::UniversalPublicDKGOutput { output, .. } => output,
        }
    }
}

impl<GroupElementValue: PartialEq, CiphertextSpaceValue>
    PartialEq<centralized_party::Output<GroupElementValue>>
    for Output<GroupElementValue, CiphertextSpaceValue>
{
    fn eq(&self, other: &centralized_party::Output<GroupElementValue>) -> bool {
        self.public_key_share == other.decentralized_party_public_key_share
            && self.centralized_party_public_key_share == other.public_key_share
            && self.public_key == other.public_key
    }
}

impl<const SCALAR_LIMBS: usize, GroupElementValue: PartialEq, CiphertextSpaceValue>
    PartialEq<centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElementValue>>
    for VersionedOutput<SCALAR_LIMBS, GroupElementValue, CiphertextSpaceValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn eq(
        &self,
        other: &centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElementValue>,
    ) -> bool {
        match self {
            VersionedOutput::TargetedPublicDKGOutput(output) => match other {
                centralized_party::VersionedOutput::TargetedPublicDKGOutput(other_output) => {
                    output == other_output
                }
                _ => false,
            },
            VersionedOutput::UniversalPublicDKGOutput {
                output,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                global_decentralized_party_output_commitment,
            } => match other {
                centralized_party::VersionedOutput::UniversalPublicDKGOutput {
                    output: other_output,
                    first_key_public_randomizer: other_first_key_public_randomizer,
                    second_key_public_randomizer: other_second_key_public_randomizer,
                    free_coefficient_key_public_randomizer:
                        other_free_coefficient_key_public_randomizer,
                    global_decentralized_party_output_commitment:
                        other_global_decentralized_party_output_commitment,
                } => {
                    output == other_output
                        && first_key_public_randomizer == other_first_key_public_randomizer
                        && second_key_public_randomizer == other_second_key_public_randomizer
                        && free_coefficient_key_public_randomizer
                            == other_free_coefficient_key_public_randomizer
                        && global_decentralized_party_output_commitment
                            == other_global_decentralized_party_output_commitment
                }
                _ => false,
            },
        }
    }
}

impl<
        const SCALAR_LIMBS: usize,
        GroupElementValue: PartialEq + Serialize,
        CiphertextSpaceValue: Serialize,
        ScalarPublicParameters,
        GroupPublicParameters,
        EncryptionSchemePublicParameters: Transcribeable + Clone,
    >
    PartialEq<
        ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            CiphertextSpaceValue,
            EncryptionSchemePublicParameters,
        >,
    > for VersionedOutput<SCALAR_LIMBS, GroupElementValue, CiphertextSpaceValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn eq(
        &self,
        protocol_public_parameters: &ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            CiphertextSpaceValue,
            EncryptionSchemePublicParameters,
        >,
    ) -> bool {
        match self {
            VersionedOutput::TargetedPublicDKGOutput(_) => {
                // Nothing to compare to
                true
            }
            VersionedOutput::UniversalPublicDKGOutput {
                global_decentralized_party_output_commitment,
                ..
            } => {
                if let Ok(protocol_global_decentralized_party_output_commitment) =
                    protocol_public_parameters.global_decentralized_party_output_commitment()
                {
                    *global_decentralized_party_output_commitment
                        == protocol_global_decentralized_party_output_commitment
                } else {
                    // this is only in the case of a bug
                    false
                }
            }
        }
    }
}

impl<const SCALAR_LIMBS: usize, GroupElementValue, CiphertextSpaceValue>
    From<Output<GroupElementValue, CiphertextSpaceValue>>
    for VersionedOutput<SCALAR_LIMBS, GroupElementValue, CiphertextSpaceValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn from(output: Output<GroupElementValue, CiphertextSpaceValue>) -> Self {
        VersionedOutput::TargetedPublicDKGOutput(output)
    }
}

impl<GroupElementValue, CiphertextSpaceValue> From<Output<GroupElementValue, CiphertextSpaceValue>>
    for centralized_party::Output<GroupElementValue>
{
    fn from(dkg_output: Output<GroupElementValue, CiphertextSpaceValue>) -> Self {
        Self {
            public_key_share: dkg_output.centralized_party_public_key_share,
            decentralized_party_public_key_share: dkg_output.public_key_share,
            public_key: dkg_output.public_key,
        }
    }
}

impl<const SCALAR_LIMBS: usize, GroupElementValue, CiphertextSpaceValue>
    From<VersionedOutput<SCALAR_LIMBS, GroupElementValue, CiphertextSpaceValue>>
    for centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElementValue>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    fn from(
        dkg_output: VersionedOutput<SCALAR_LIMBS, GroupElementValue, CiphertextSpaceValue>,
    ) -> Self {
        match dkg_output {
            VersionedOutput::TargetedPublicDKGOutput(output) => {
                centralized_party::VersionedOutput::TargetedPublicDKGOutput(output.into())
            }
            VersionedOutput::UniversalPublicDKGOutput {
                output,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                global_decentralized_party_output_commitment,
            } => centralized_party::VersionedOutput::UniversalPublicDKGOutput {
                output: output.into(),
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                global_decentralized_party_output_commitment,
            },
        }
    }
}

pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    ProtocolPublicParameters,
    CentralizedPartyKeyShareVerification,
>(
    PhantomData<GroupElement>,
    PhantomData<EncryptionKey>,
    PhantomData<ProtocolPublicParameters>,
    PhantomData<CentralizedPartyKeyShareVerification>,
);

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters,
        CentralizedPartyKeyShareVerification,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
        CentralizedPartyKeyShareVerification,
    >
where
    ProtocolPublicParameters: AsRef<
        crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    >,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    EncryptionKey::CiphertextSpaceGroupElement: Scale<Uint<SCALAR_LIMBS>>,
{
    /// This function implements round 3 in the DKG protocol:
    /// Verifies zk-proof for $X_{A}$, and sets
    /// $X=X_{A}+X_{B}=X_{A}+\mu_{x}^{0}\cdot X_{0,B}+\mu_{x}^{1}\cdot X_{1,B}+\mu_{x}^{G}\cdot G$.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428>
    pub fn verify_proof_of_centralized_party_public_key_share(
        public_key_share_and_proof: centralized_party::PublicKeyShareAndProof<
            GroupElement::Value,
            KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        >,
        encryption_of_decentralized_party_secret_key_share_first_part: group::Value<
            EncryptionKey::CiphertextSpaceGroupElement,
        >,
        encryption_of_decentralized_party_secret_key_share_second_part: group::Value<
            EncryptionKey::CiphertextSpaceGroupElement,
        >,
        decentralized_party_public_key_share_first_part: GroupElement::Value,
        decentralized_party_public_key_share_second_part: GroupElement::Value,
        protocol_public_parameters: &ProtocolPublicParameters,
        session_id: CommitmentSizedNumber,
    ) -> crate::Result<
        VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    > {
        let protocol_public_parameters = protocol_public_parameters.as_ref();

        // $X_{A}$
        let centralized_party_public_key_share = GroupElement::new(
            public_key_share_and_proof.public_key_share,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // $X_{B}$
        let (           first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer, encryption_of_secret_key_share, public_key_share) = derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share::<SCALAR_LIMBS, PLAINTEXT_SPACE_SCALAR_LIMBS, GroupElement, EncryptionKey>(
            session_id,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
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

        let output = Output {
            public_key_share: public_key_share.value(),
            public_key: public_key.value(),
            encryption_of_secret_key_share: encryption_of_secret_key_share.value(),
            centralized_party_public_key_share: public_key_share_and_proof.public_key_share,
        };

        let global_decentralized_party_output_commitment =
            protocol_public_parameters.global_decentralized_party_output_commitment()?;

        let versioned_output = VersionedOutput::UniversalPublicDKGOutput {
            output,
            first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer,
            global_decentralized_party_output_commitment,
        };

        // === 3(f) Output (and record) ===
        Ok(versioned_output)
    }
}

/// The public input of the DKG proof verification round.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<
    GroupElementValue,
    KnowledgeOfDiscreteLogUCProof,
    ProtocolPublicParameters,
    CentralizedPartyKeyShareVerification,
> {
    pub public_key_share_and_proof:
        centralized_party::PublicKeyShareAndProof<GroupElementValue, KnowledgeOfDiscreteLogUCProof>,
    pub protocol_public_parameters: ProtocolPublicParameters,
    pub centralized_party_secret_key_share_verification: CentralizedPartyKeyShareVerification,
}

impl<
        GroupElementValue,
        KnowledgeOfDiscreteLogUCProof,
        ProtocolPublicParameters,
        CentralizedPartyKeyShareVerification,
    >
    From<(
        ProtocolPublicParameters,
        PublicKeyShareAndProof<GroupElementValue, KnowledgeOfDiscreteLogUCProof>,
        CentralizedPartyKeyShareVerification,
    )>
    for PublicInput<
        GroupElementValue,
        KnowledgeOfDiscreteLogUCProof,
        ProtocolPublicParameters,
        CentralizedPartyKeyShareVerification,
    >
{
    fn from(
        (
            protocol_public_parameters,
            public_key_share_and_proof,
            centralized_party_secret_key_share_verification,
        ): (
            ProtocolPublicParameters,
            PublicKeyShareAndProof<GroupElementValue, KnowledgeOfDiscreteLogUCProof>,
            CentralizedPartyKeyShareVerification,
        ),
    ) -> Self {
        Self {
            public_key_share_and_proof,
            protocol_public_parameters,
            centralized_party_secret_key_share_verification,
        }
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
        CentralizedPartyKeyShareVerification: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > mpc::Party
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
        CentralizedPartyKeyShareVerification,
    >
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    type Error = Error;
    type PublicInput = PublicInput<
        GroupElement::Value,
        KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        ProtocolPublicParameters,
        CentralizedPartyKeyShareVerification,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = Self::PublicOutput;
    type PublicOutput = VersionedOutput<
        SCALAR_LIMBS,
        GroupElement::Value,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
    >;
    type Message = ();
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
        CentralizedPartyKeyShareVerification: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > Default
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        ProtocolPublicParameters,
        CentralizedPartyKeyShareVerification,
    >
{
    fn default() -> Self {
        Self(PhantomData, PhantomData, PhantomData, PhantomData)
    }
}
