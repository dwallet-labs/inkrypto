// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

use crypto_bigint::U256;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{PartyID, Transcribeable};
use proof::TranscriptProtocol;

pub mod languages;

pub mod decentralized_party;
pub mod dkg;
pub mod ecdsa;
pub mod presign;
pub mod schnorr;
pub mod sign;

pub use sign::Protocol;

/// 2PC-MPC error.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("commitment error")]
    Commitment(#[from] commitment::Error),
    #[error("homomorphic encryption error")]
    HomomorphicEncryption(#[from] homomorphic_encryption::Error),
    #[error("mpc error")]
    MPC(#[from] ::mpc::Error),
    #[error("asynchronous proof aggregation error")]
    AsyncProofAggregation(#[from] ::proof::aggregation::asynchronous::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("maurer error")]
    Maurer(#[from] maurer::Error),
    #[error("class groups error")]
    ClassGroup(#[from] ::class_groups::Error),
    #[error("serialization/deserialization error: {0:?}")]
    Serialization(String),
    #[error(
        "parties {:?} did not send partial decryption proofs in the signing identifiable abort protocol", .0
    )]
    UnresponsiveParties(Vec<PartyID>),
    #[error(
        "parties {:?} did not send the decryption shares and proofs for their virtual subset", .0
    )]
    WrongVirtualSubset(Vec<PartyID>),
    #[error("the other party maliciously attempted to bypass the commitment round by sending decommitment which does not match its commitment"
    )]
    WrongDecommitment,
    #[error("the designated decrypting party behaved maliciously by not sending the honest decrypted values"
    )]
    MaliciousDesignatedDecryptingParty(PartyID),
    #[error("invalid public centralized key share")]
    InvalidPublicCentralizedKeyShare,
    #[error("signature failed to verify")]
    SignatureVerification,
    #[error("invalid message")]
    InvalidMessage,
    #[error("an unsupported non-standard signature scheme or variant")]
    Nonstandard,
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

/// 2PC-MPC result.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Party {
    CentralizedParty,
    DecentralizedParty,
    DecentralizedPartyWithPartyID(PartyID),
}

/// The protocol context for the `2pc-mpc` protocol.
/// In this struct we only keep track of whether it is the centralized ($pid_A$) or decentralized party ($pid_B$) using `Self::party`.
/// However, during proof aggregation, the individual party IDs are taken into account:
/// - In the synchronous proof aggregation protocol, the party ID is being inserted into the transcript from which the commitment is derived in the commitment round.
/// - In the asynchronous proof aggregation protocol, this struct is wrapped by the AggregationProtocolContext, which is composed of `Self` and the party ID $pid_i$.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolContext {
    party: Party,
    session_id: CommitmentSizedNumber,
    protocol_name: String,
    round_name: String,
    proof_name: String,
    // For presign & sign
    public_key: Option<Vec<u8>>,
}

/// The shared part of the protocol context, that defines a specific proof in a specific protocol.
/// Needs a `PartyID` to transform into `ProtocolContext`, see [`BaseProtocolContext::with_party_id_and_session_id()`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BaseProtocolContext {
    protocol_name: String,
    round_name: String,
    proof_name: String,
}

impl BaseProtocolContext {
    /// Transforms `BaseProtocolContext` into the specialized
    /// per-party, per-session `ProtocolContext` given the `party_id` and `session_id`.
    fn with_party_id_and_session_id(
        &self,
        party_id: PartyID,
        session_id: CommitmentSizedNumber,
    ) -> ProtocolContext {
        ProtocolContext {
            party: Party::DecentralizedPartyWithPartyID(party_id),
            session_id,
            protocol_name: self.protocol_name.clone(),
            round_name: self.round_name.clone(),
            proof_name: self.proof_name.clone(),
            public_key: None,
        }
    }

    /// Transforms `BaseProtocolContext` into the specialized
    /// per-session `ProtocolContext` given the `session_id`.
    /// Used for proof/statement aggregation protocols which internally wrap the protocol context with the party id.
    fn with_session_id(&self, session_id: CommitmentSizedNumber) -> ProtocolContext {
        ProtocolContext {
            party: Party::DecentralizedParty,
            session_id,
            protocol_name: self.protocol_name.clone(),
            round_name: self.round_name.clone(),
            proof_name: self.proof_name.clone(),
            public_key: None,
        }
    }
}

impl From<ProtocolContext> for U256 {
    fn from(value: ProtocolContext) -> Self {
        value.session_id
    }
}

impl From<Error> for mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Group(e) => mpc::Error::Group(e),
            Error::MPC(e) => e,
            Error::AsyncProofAggregation(e) => e.into(),
            Error::Maurer(e) => e.into(),
            Error::Proof(e) => e.into(),
            Error::UnresponsiveParties(parties) => mpc::Error::UnresponsiveParties(parties),
            Error::WrongVirtualSubset(parties) => mpc::Error::InvalidMessage(parties),
            Error::MaliciousDesignatedDecryptingParty(designated_party_id) => {
                mpc::Error::MaliciousMessage(vec![designated_party_id])
            }
            Error::InvalidParameters => mpc::Error::InvalidParameters,
            Error::InvalidPublicParameters => mpc::Error::InvalidParameters,
            Error::ClassGroup(e) => e.into(),
            e => mpc::Error::Consumer(format!("2pc-mpc error {e:?}")),
        }
    }
}

pub const CENTRALIZED_PARTY_ID: PartyID = 1;
pub const DECENTRALIZED_PARTY_ID: PartyID = 2;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolPublicParameters<
    ScalarPublicParameters,
    GroupPublicParameters,
    GroupElementValue,
    CiphertextSpaceValue,
    EncryptionSchemePublicParameters,
> {
    pub decentralized_party_public_key_share_first_part: GroupElementValue,
    pub decentralized_party_public_key_share_second_part: GroupElementValue,
    pub encryption_of_decentralized_party_secret_key_share_first_part: CiphertextSpaceValue,
    pub encryption_of_decentralized_party_secret_key_share_second_part: CiphertextSpaceValue,
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub group_public_parameters: GroupPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionSchemePublicParameters,
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue: Serialize,
        CiphertextSpaceValue: Serialize,
        EncryptionSchemePublicParameters: Transcribeable + Clone,
    >
    ProtocolPublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        CiphertextSpaceValue,
        EncryptionSchemePublicParameters,
    >
{
    // This function generates a commitment that is used to ensure
    // that future protocols correctly reference the
    // intended one-time DKG instance for the distributed party. Since different
    // protocols may depend on different DKG outputs, this mapping prevents
    // accidental mismatches. For example, when using  pre-sign output on must use the
    // correct DKG output they were derived from.
    //
    // This sanity is merely an extra safeguard makes it much harder
    // to accidentally reference the wrong DKG output.
    fn global_decentralized_party_output_commitment(&self) -> Result<CommitmentSizedNumber> {
        let mut transcript = Transcript::new(b"key share parts commitment");

        transcript.transcribe(
            b"$\\textsf{TAHE}.\\textsf{pk}$",
            self.encryption_scheme_public_parameters.clone(),
        )?;

        transcript.serialize_to_transcript_as_json(
            b"$X_{\\DistributedParty}^{0}$",
            &self.decentralized_party_public_key_share_first_part,
        )?;
        transcript.serialize_to_transcript_as_json(
            b"$X_{\\DistributedParty}^{1}$",
            &self.decentralized_party_public_key_share_second_part,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"$\\textsf{ct}_{\\textsf{key}}^{0}$",
            &self.encryption_of_decentralized_party_secret_key_share_first_part,
        )?;
        transcript.serialize_to_transcript_as_json(
            b"$\\textsf{ct}_{\\textsf{key}}^{1}$",
            &self.encryption_of_decentralized_party_secret_key_share_second_part,
        )?;

        let commitment = transcript.challenge(b"commitment");

        Ok(commitment)
    }
}

impl<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        CiphertextSpaceValue,
        EncryptionSchemePublicParameters,
    >
    AsRef<
        ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            CiphertextSpaceValue,
            EncryptionSchemePublicParameters,
        >,
    >
    for ProtocolPublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        CiphertextSpaceValue,
        EncryptionSchemePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &ProtocolPublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        CiphertextSpaceValue,
        EncryptionSchemePublicParameters,
    > {
        self
    }
}

pub mod class_groups {
    use std::fmt::Debug;
    use std::marker::PhantomData;

    use crypto_bigint::{Encoding, Int, Uint};
    use serde::{Deserialize, Serialize};

    use ::class_groups::{
        encryption_key, CiphertextSpaceGroupElement, CompactIbqf, EncryptionKey, EquivalenceClass,
        SECRET_KEY_SHARE_WITNESS_LIMBS,
    };
    use ::class_groups::{
        equivalence_class, CiphertextSpacePublicParameters, RandomnessSpaceGroupElement,
        RandomnessSpacePublicParameters,
    };
    use class_groups::CiphertextSpaceValue;
    use group::PrimeGroupElement;
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
    use maurer::{encryption_of_discrete_log, encryption_of_tuple, scaling_of_discrete_log};

    use crate::dkg::centralized_party::SecretKeyShare;
    use crate::languages::class_groups::EncryptionOfDiscreteLogProof;
    use crate::languages::{KnowledgeOfDiscreteLogProof, KnowledgeOfDiscreteLogUCProof};
    use crate::{dkg, ProtocolContext};

    pub type PublicParameters<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
    >;

    pub type ProtocolPublicParameters<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = crate::ProtocolPublicParameters<
        group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
        group::PublicParameters<GroupElement>,
        group::Value<GroupElement>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        homomorphic_encryption::PublicParameters<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
    >;

    impl<
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            CiphertextSpaceValue,
            EncryptionSchemePublicParameters,
        >
        super::ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            CiphertextSpaceValue,
            EncryptionSchemePublicParameters,
        >
    {
        pub fn new<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        >(
            decentralized_party_public_key_share_first_part: GroupElement::Value,
            decentralized_party_public_key_share_second_part: GroupElement::Value,
            encryption_of_decentralized_party_secret_key_share_first_part: CiphertextSpaceValue,
            encryption_of_decentralized_party_secret_key_share_second_part: CiphertextSpaceValue,
            encryption_scheme_public_parameters: EncryptionSchemePublicParameters,
        ) -> Self
        where
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>
                + group::GroupElement<
                    PublicParameters = GroupPublicParameters,
                    Value = GroupElementValue,
                >,
            GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >: AdditivelyHomomorphicEncryptionKey<
                SCALAR_LIMBS,
                PublicParameters = EncryptionSchemePublicParameters,
            >,
            GroupPublicParameters: Default,
            ScalarPublicParameters: Default,
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
                RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
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
            CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
                group::GroupElement<Value = CiphertextSpaceValue>,
        {
            let scalar_group_public_parameters =
                group::PublicParameters::<GroupElement::Scalar>::default();

            let group_public_parameters = GroupElement::PublicParameters::default();

            Self {
                decentralized_party_public_key_share_first_part,
                decentralized_party_public_key_share_second_part,
                encryption_of_decentralized_party_secret_key_share_first_part,
                encryption_of_decentralized_party_secret_key_share_second_part,
                scalar_group_public_parameters,
                group_public_parameters,
                encryption_scheme_public_parameters,
            }
        }
    }
    pub type DecryptionShare<const SCALAR_LIMBS: usize, const DISCRIMINANT_LIMBS: usize> =
        CompactIbqf<DISCRIMINANT_LIMBS>;
    pub type PartialDecryptionProof<const SCALAR_LIMBS: usize, const DISCRIMINANT_LIMBS: usize> =
        Vec<
            maurer::equality_of_discrete_logs::Proof<
                2,
                group::bounded_integers_group::GroupElement<SECRET_KEY_SHARE_WITNESS_LIMBS>,
                EquivalenceClass<DISCRIMINANT_LIMBS>,
                (),
            >,
        >;
    pub type DecryptionKeySharePublicParameters<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = class_groups::decryption_key_share::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
    >;

    pub type DKGCentralizedPartyOutput<const SCALAR_LIMBS: usize, GroupElement> =
        crate::dkg::centralized_party::Output<group::Value<GroupElement>>;

    pub type DKGCentralizedPartyVersionedOutput<const SCALAR_LIMBS: usize, GroupElement> =
        crate::dkg::centralized_party::VersionedOutput<SCALAR_LIMBS, group::Value<GroupElement>>;

    pub type DKGDecentralizedPartyOutput<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = crate::dkg::decentralized_party::Output<
        group::Value<GroupElement>,
        group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    >;

    pub type DKGDecentralizedPartyVersionedOutput<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = crate::dkg::decentralized_party::VersionedOutput<
        SCALAR_LIMBS,
        group::Value<GroupElement>,
        group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    >;

    pub type EncryptionOfSecretKeyShareAndPublicKeyShare<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = group::Value<
        encryption_of_discrete_log::StatementSpaceGroupElement<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
    >;

    pub type EncryptionOfSecretKeyShareParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = dkg::encryption_of_secret_key_share::class_groups::asynchronous::Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;

    pub type CentralizedPartyKeyShareVerification<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = crate::dkg::CentralizedPartyKeyShareVerification<
        SecretKeyShare<group::Value<group::Scalar<SCALAR_LIMBS, GroupElement>>>,
        CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        (
            EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                PhantomData<()>,
            >,
            CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ),
    >;

    pub type TrustedDealerDKGDecentralizedParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = crate::dkg::decentralized_party::trusted_dealer::Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        crate::dkg::centralized_party::trusted_dealer::class_groups::Message<
            KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
            EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >,
            group::Value<GroupElement>,
            CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        CentralizedPartyKeyShareVerification<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;

    pub type DKGDecentralizedPartyPublicInput<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = dkg::decentralized_party::PublicInput<
        group::Value<GroupElement>,
        KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        CentralizedPartyKeyShareVerification<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;
    pub type DKGDecentralizedParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = dkg::decentralized_party::Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        class_groups::EncryptionKey<
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
        CentralizedPartyKeyShareVerification<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;
    pub type DKGCentralizedParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = dkg::centralized_party::Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        class_groups::EncryptionKey<
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
    >;

    pub mod schnorr {
        use super::*;

        pub type Presign<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = crate::schnorr::presign::Presign<
            group::Value<GroupElement>,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >;

        pub mod asynchronous {
            use super::*;

            #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
            pub struct Protocol<
                const SCALAR_LIMBS: usize,
                const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
                const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
                const MESSAGE_LIMBS: usize,
                GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
            >(PhantomData<GroupElement>)
            where
                Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
                Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
                Uint<SCALAR_LIMBS>: Encoding,
                Uint<MESSAGE_LIMBS>: Encoding;
        }
    }

    pub mod ecdsa {
        use super::*;
        use crate::ecdsa::sign::centralized_party::message::class_groups::Message as SignMessage;
        use maurer::extended_encryption_of_tuple;

        pub type Presign<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = crate::ecdsa::presign::Presign<
            group::Value<GroupElement>,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >;

        pub type UniversalPresign<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = crate::ecdsa::presign::UniversalPresign<
            group::Value<GroupElement>,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >;

        pub type VersionedPresign<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = crate::ecdsa::presign::VersionedPresign<
            group::Value<GroupElement>,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >;

        pub type PresignAsyncECDSAParty<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement,
        > = crate::ecdsa::presign::decentralized_party::class_groups::asynchronous::Party<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;

        pub type PresignAsyncSchnorrParty<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = crate::schnorr::presign::decentralized_party::encryption_of_nonce_share_round::class_groups::asynchronous::Party<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;

        pub type EncryptionOfMaskAndMaskedKeyShare<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = group::Value<
            encryption_of_tuple::StatementSpaceGroupElement<
                SCALAR_LIMBS,
                SCALAR_LIMBS,
                EncryptionKey<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >,
            >,
        >;

        pub type EncryptionOfMaskAndMaskedKeyShareParts<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = group::Value<
            extended_encryption_of_tuple::StatementSpaceGroupElement<
                2,
                SCALAR_LIMBS,
                SCALAR_LIMBS,
                EncryptionKey<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >,
            >,
        >;

        pub type NoncePublicShareAndEncryptionOfMaskedNonceShare<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        > = group::Value<
            scaling_of_discrete_log::StatementSpaceGroupElement<
                SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >,
            >,
        >;

        pub type SignPartyPublicInput<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement,
        > = crate::ecdsa::sign::decentralized_party::PublicInput<
            DKGDecentralizedPartyVersionedOutput<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            VersionedPresign<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            SignMessage<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
            DecryptionKeySharePublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;

        pub type DKGSignPartyPublicInput<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement,
        > = crate::ecdsa::sign::decentralized_party::DKGSignPublicInput<
            DKGDecentralizedPartyPublicInput<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            VersionedPresign<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            SignMessage<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
            DecryptionKeySharePublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;

        pub mod asynchronous {
            use super::*;

            #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
            pub struct Protocol<
                const SCALAR_LIMBS: usize,
                const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
                const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
                const MESSAGE_LIMBS: usize,
                GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
            >(PhantomData<GroupElement>)
            where
                Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
                Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
                Uint<SCALAR_LIMBS>: Encoding,
                Uint<MESSAGE_LIMBS>: Encoding;
        }
    }
}

pub mod secp256r1 {
    pub use ::class_groups::RISTRETTO_MESSAGE_LIMBS as MESSAGE_LIMBS;
    use group::secp256r1;

    pub const SCALAR_LIMBS: usize = secp256r1::SCALAR_LIMBS;
    pub type GroupElement = secp256r1::GroupElement;
    pub type Scalar = secp256r1::Scalar;

    pub mod class_groups {
        use crate::{languages, ProtocolContext};
        use ::class_groups::{Secp256r1DecryptionKey, Secp256r1EncryptionKey};

        use super::*;

        pub const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS;
        pub const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;

        pub type EncryptionKey = Secp256r1EncryptionKey;
        pub type DecryptionKey = Secp256r1DecryptionKey;
        pub type ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;

        pub type ECDSAProtocol = crate::class_groups::ecdsa::asynchronous::Protocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;

        pub type DKGProtocol = ECDSAProtocol;

        pub type EncryptionOfDiscreteLogProof =
            languages::class_groups::EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >;

        pub type EncryptionOfSecretKeyShareParty =
            crate::class_groups::EncryptionOfSecretKeyShareParty<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >;
    }
}

pub mod curve25519 {
    pub use ::class_groups::CURVE25519_MESSAGE_LIMBS as MESSAGE_LIMBS;
    use group::curve25519;

    pub const SCALAR_LIMBS: usize = curve25519::SCALAR_LIMBS;
    pub type GroupElement = curve25519::GroupElement;
    pub type Scalar = curve25519::Scalar;

    pub mod class_groups {
        use crate::{languages, ProtocolContext};
        use ::class_groups::{Curve25519DecryptionKey, Curve25519EncryptionKey};

        use super::*;

        pub const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS;
        pub const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;

        pub type EncryptionKey = Curve25519EncryptionKey;
        pub type DecryptionKey = Curve25519DecryptionKey;
        pub type ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;

        pub type EdDSAProtocol = crate::class_groups::schnorr::asynchronous::Protocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;

        pub type DKGProtocol = EdDSAProtocol;

        pub type EncryptionOfDiscreteLogProof =
            languages::class_groups::EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >;

        pub type EncryptionOfSecretKeyShareParty =
            crate::class_groups::EncryptionOfSecretKeyShareParty<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >;
    }
}

pub mod ristretto {
    pub use ::class_groups::RISTRETTO_MESSAGE_LIMBS as MESSAGE_LIMBS;
    use group::ristretto;

    pub const SCALAR_LIMBS: usize = ristretto::SCALAR_LIMBS;
    pub type GroupElement = ristretto::GroupElement;
    pub type Scalar = ristretto::Scalar;

    pub mod class_groups {
        use crate::{languages, ProtocolContext};
        use ::class_groups::{RistrettoDecryptionKey, RistrettoEncryptionKey};

        use super::*;

        pub const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS;
        pub const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;

        pub type EncryptionKey = RistrettoEncryptionKey;
        pub type DecryptionKey = RistrettoDecryptionKey;
        pub type ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;

        pub type SchnorrkelSubstrateProtocol = crate::class_groups::schnorr::asynchronous::Protocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;

        pub type DKGProtocol = SchnorrkelSubstrateProtocol;

        pub type EncryptionOfDiscreteLogProof =
            languages::class_groups::EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >;

        pub type EncryptionOfSecretKeyShareParty =
            crate::class_groups::EncryptionOfSecretKeyShareParty<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >;
    }
}

pub mod secp256k1 {
    pub use ::class_groups::SECP256K1_MESSAGE_LIMBS as MESSAGE_LIMBS;
    use group::secp256k1;

    pub const SCALAR_LIMBS: usize = secp256k1::SCALAR_LIMBS;
    pub type GroupElement = secp256k1::GroupElement;
    pub type Scalar = secp256k1::Scalar;

    pub mod class_groups {
        use crate::{languages, ProtocolContext};
        use ::class_groups::{Secp256k1DecryptionKey, Secp256k1EncryptionKey};

        use super::*;

        pub const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS;
        pub const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;

        pub type EncryptionKey = Secp256k1EncryptionKey;
        pub type DecryptionKey = Secp256k1DecryptionKey;
        pub type ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;

        pub type ECDSAProtocol = crate::class_groups::ecdsa::asynchronous::Protocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;

        pub type TaprootProtocol = crate::class_groups::schnorr::asynchronous::Protocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;

        pub type DKGProtocol = ECDSAProtocol;

        pub type EncryptionOfDiscreteLogProof =
            languages::class_groups::EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >;

        pub type EncryptionOfSecretKeyShareParty =
            crate::class_groups::EncryptionOfSecretKeyShareParty<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >;
    }
}
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use crate::ProtocolPublicParameters;
    use class_groups::test_helpers::{
        get_setup_parameters_curve25519_112_bits_deterministic,
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
        get_setup_parameters_secp256r1_112_bits_deterministic,
    };
    use class_groups::{
        Curve25519DecryptionKey, Curve25519EncryptionKey, RistrettoDecryptionKey,
        RistrettoEncryptionKey, Secp256k1DecryptionKey, Secp256k1EncryptionKey,
        Secp256r1DecryptionKey, Secp256r1EncryptionKey,
    };
    use crypto_bigint::Uint;
    use group::{
        curve25519, ristretto, secp256k1, secp256r1, GroupElement, OsCsRng, PrimeGroupElement,
        Samplable,
    };
    use homomorphic_encryption::{
        AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors,
    };

    pub(crate) fn mock_decentralized_party_dkg<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        group_public_parameters: group::PublicParameters<GroupElement>,
        scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
    ) -> (
        GroupElement::Value,
        GroupElement::Value,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
    ) {
        let encryption_key = EncryptionKey::new(encryption_scheme_public_parameters).unwrap();

        let generator =
            GroupElement::generator_from_public_parameters(&group_public_parameters).unwrap();

        let decentralized_party_secret_key_share_first_part =
            GroupElement::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let decentralized_party_secret_key_share_first_part_value: Uint<SCALAR_LIMBS> =
            decentralized_party_secret_key_share_first_part.into();
        let decentralized_party_secret_key_share_first_part_value =
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
                &decentralized_party_secret_key_share_first_part_value,
            );
        let decentralized_party_secret_key_share_first_part_plaintext =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                decentralized_party_secret_key_share_first_part_value.into(),
                encryption_scheme_public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap();
        let (_, encryption_of_decentralized_party_secret_key_share_first_part) = encryption_key
            .encrypt(
                &decentralized_party_secret_key_share_first_part_plaintext,
                encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();

        let decentralized_party_secret_key_share_second_part =
            GroupElement::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let decentralized_party_secret_key_share_second_part_value: Uint<SCALAR_LIMBS> =
            decentralized_party_secret_key_share_second_part.into();
        let decentralized_party_secret_key_share_second_part_value =
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
                &decentralized_party_secret_key_share_second_part_value,
            );
        let decentralized_party_secret_key_share_second_part_plaintext =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                decentralized_party_secret_key_share_second_part_value.into(),
                encryption_scheme_public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap();
        let (_, encryption_of_decentralized_party_secret_key_share_second_part) = encryption_key
            .encrypt(
                &decentralized_party_secret_key_share_second_part_plaintext,
                encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();

        let decentralized_party_public_key_share_first_part =
            decentralized_party_secret_key_share_first_part * generator;
        let decentralized_party_public_key_share_second_part =
            decentralized_party_secret_key_share_second_part * generator;

        (
            decentralized_party_public_key_share_first_part.value(),
            decentralized_party_public_key_share_second_part.value(),
            encryption_of_decentralized_party_secret_key_share_first_part.value(),
            encryption_of_decentralized_party_secret_key_share_second_part.value(),
        )
    }

    #[allow(dead_code)]
    pub fn setup_class_groups_secp256r1() -> (
        crate::secp256r1::class_groups::ProtocolPublicParameters,
        crate::secp256r1::class_groups::DecryptionKey,
    ) {
        let setup_parameters = get_setup_parameters_secp256r1_112_bits_deterministic();
        let (encryption_scheme_public_parameters, decryption_key) =
            Secp256r1DecryptionKey::generate_with_setup_parameters(setup_parameters, &mut OsCsRng)
                .unwrap();

        let (
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
        >(
            secp256r1::group_element::PublicParameters::default(),
            secp256r1::scalar::PublicParameters::default(),
            &encryption_scheme_public_parameters,
        );

        let protocol_public_parameters = ProtocolPublicParameters::new::<
            { secp256r1::SCALAR_LIMBS },
            { crate::secp256r1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256r1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256r1::GroupElement,
        >(
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
            encryption_scheme_public_parameters.clone(),
        );

        (protocol_public_parameters, decryption_key)
    }

    #[allow(dead_code)]
    pub fn setup_class_groups_secp256k1() -> (
        crate::secp256k1::class_groups::ProtocolPublicParameters,
        crate::secp256k1::class_groups::DecryptionKey,
    ) {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (encryption_scheme_public_parameters, decryption_key) =
            Secp256k1DecryptionKey::generate_with_setup_parameters(setup_parameters, &mut OsCsRng)
                .unwrap();

        let (
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >(
            secp256k1::group_element::PublicParameters::default(),
            secp256k1::scalar::PublicParameters::default(),
            &encryption_scheme_public_parameters,
        );

        let protocol_public_parameters = ProtocolPublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
        >(
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
            encryption_scheme_public_parameters.clone(),
        );

        (protocol_public_parameters, decryption_key)
    }

    #[allow(dead_code)]
    pub fn setup_class_groups_ristretto() -> (
        crate::ristretto::class_groups::ProtocolPublicParameters,
        crate::ristretto::class_groups::DecryptionKey,
    ) {
        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let (encryption_scheme_public_parameters, decryption_key) =
            RistrettoDecryptionKey::generate_with_setup_parameters(setup_parameters, &mut OsCsRng)
                .unwrap();

        let (
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
        >(
            ristretto::group_element::PublicParameters::default(),
            ristretto::scalar::PublicParameters::default(),
            &encryption_scheme_public_parameters,
        );

        let protocol_public_parameters = ProtocolPublicParameters::new::<
            { ristretto::SCALAR_LIMBS },
            { crate::ristretto::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::ristretto::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            ristretto::GroupElement,
        >(
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
            encryption_scheme_public_parameters.clone(),
        );

        (protocol_public_parameters, decryption_key)
    }

    #[allow(dead_code)]
    pub fn setup_class_groups_curve25519() -> (
        crate::curve25519::class_groups::ProtocolPublicParameters,
        crate::curve25519::class_groups::DecryptionKey,
    ) {
        let setup_parameters = get_setup_parameters_curve25519_112_bits_deterministic();
        let (encryption_scheme_public_parameters, decryption_key) =
            Curve25519DecryptionKey::generate_with_setup_parameters(setup_parameters, &mut OsCsRng)
                .unwrap();

        let (
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
        >(
            curve25519::PublicParameters::default(),
            curve25519::scalar::PublicParameters::default(),
            &encryption_scheme_public_parameters,
        );

        let protocol_public_parameters = ProtocolPublicParameters::new::<
            { curve25519::SCALAR_LIMBS },
            { crate::curve25519::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::curve25519::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            curve25519::GroupElement,
        >(
            decentralized_party_public_key_share_first_part,
            decentralized_party_public_key_share_second_part,
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_of_decentralized_party_secret_key_share_second_part,
            encryption_scheme_public_parameters.clone(),
        );

        (protocol_public_parameters, decryption_key)
    }
}
