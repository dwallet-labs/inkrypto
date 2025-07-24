// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::U256;
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::PartyID;

pub mod languages;

#[cfg(any(
    all(feature = "paillier", feature = "bulletproofs",),
    feature = "class_groups"
))]
pub mod dkg;
#[cfg(any(
    all(feature = "paillier", feature = "bulletproofs",),
    feature = "class_groups"
))]
pub mod presign;
#[cfg(any(
    all(feature = "paillier", feature = "bulletproofs",),
    feature = "class_groups"
))]
pub mod sign;

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
    #[cfg(feature = "paillier")]
    #[error("enhanced maurer error")]
    EnhancedMaurer(#[from] enhanced_maurer::Error),
    #[cfg(feature = "paillier")]
    #[error("tiresias error")]
    Tiresias(#[from] tiresias::Error),
    #[cfg(feature = "class_groups")]
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
            #[cfg(feature = "paillier")]
            Error::Tiresias(e) => e.into(),
            #[cfg(feature = "paillier")]
            Error::EnhancedMaurer(e) => e.into(),
            #[cfg(feature = "class_groups")]
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
    EncryptionSchemePublicParameters,
> {
    pub scalar_group_public_parameters: ScalarPublicParameters,
    pub group_public_parameters: GroupPublicParameters,
    pub encryption_scheme_public_parameters: EncryptionSchemePublicParameters,
}

impl<ScalarPublicParameters, GroupPublicParameters, EncryptionSchemePublicParameters>
    AsRef<
        ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            EncryptionSchemePublicParameters,
        >,
    >
    for ProtocolPublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        EncryptionSchemePublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &ProtocolPublicParameters<
        ScalarPublicParameters,
        GroupPublicParameters,
        EncryptionSchemePublicParameters,
    > {
        self
    }
}

#[cfg(feature = "class_groups")]
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
    use group::PrimeGroupElement;
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
    use maurer::{encryption_of_discrete_log, encryption_of_tuple, scaling_of_discrete_log};

    use crate::dkg;
    use crate::languages::KnowledgeOfDiscreteLogUCProof;

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

    impl<ScalarPublicParameters, GroupPublicParameters, EncryptionSchemePublicParameters>
        super::ProtocolPublicParameters<
            ScalarPublicParameters,
            GroupPublicParameters,
            EncryptionSchemePublicParameters,
        >
    {
        pub fn new<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement,
        >(
            encryption_scheme_public_parameters: EncryptionSchemePublicParameters,
        ) -> Self
        where
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>
                + group::GroupElement<PublicParameters = GroupPublicParameters>,
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
        {
            let scalar_group_public_parameters =
                group::PublicParameters::<GroupElement::Scalar>::default();

            let group_public_parameters = GroupElement::PublicParameters::default();

            Self {
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
        crate::dkg::centralized_party::PublicOutput<group::Value<GroupElement>>;

    pub type DKGDecentralizedPartyOutput<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = crate::dkg::decentralized_party::Output<
        group::Value<GroupElement>,
        group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    >;

    pub type Presign<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = crate::presign::Presign<
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

    pub type EncryptionOfSecretKeyShareRoundAsyncParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = dkg::decentralized_party::encryption_of_secret_key_share_round::class_groups::asynchronous::Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;

    pub type ProofVerificationRoundPublicInput<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = dkg::decentralized_party::proof_verification_round::PublicInput<
        group::Value<GroupElement>,
        group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;
    pub type ProofVerificationRoundParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    > = dkg::decentralized_party::proof_verification_round::Party<
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

    pub type PresignAsyncParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement,
    > = crate::presign::decentralized_party::class_groups::asynchronous::Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >;

    pub type EncryptionOfMaskAndMaskedKey<
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

#[cfg(feature = "paillier")]
pub mod paillier {
    use group::self_product;
    use maurer::{encryption_of_discrete_log, encryption_of_tuple, scaling_of_discrete_log};

    use crate::dkg;
    use crate::languages::KnowledgeOfDiscreteLogUCProof;
    use crate::paillier::bulletproofs::PaillierProtocolPublicParameters;

    pub const PLAINTEXT_SPACE_SCALAR_LIMBS: usize = tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS;
    pub type EncryptionKey = tiresias::EncryptionKey;
    pub type DecryptionKeyShare = tiresias::DecryptionKeyShare;
    pub type PartialDecryptionProof = tiresias::proofs::ProofOfEqualityOfDiscreteLogs;
    pub type DecryptionShare = tiresias::PaillierModulusSizedNumber;
    pub type PublicParameters = tiresias::encryption_key::PublicParameters;

    pub type UnboundedEncDLWitness = tiresias::RandomnessSpaceGroupElement;
    pub type UnboundedScaleDLWitness = tiresias::RandomnessSpaceGroupElement;
    pub type UnboundedEncDHWitness =
        self_product::GroupElement<2, tiresias::RandomnessSpaceGroupElement>;

    pub type PlaintextSpaceGroupElement = tiresias::PlaintextSpaceGroupElement;
    pub type RandomnessSpaceGroupElement = tiresias::RandomnessSpaceGroupElement;
    pub type CiphertextSpaceGroupElement = tiresias::CiphertextSpaceGroupElement;

    pub mod asynchronous {
        use std::marker::PhantomData;

        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
        pub struct Protocol<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const RANGE_CLAIMS_PER_MASK: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement,
        >(PhantomData<GroupElement>);
    }

    pub type DKGCentralizedPartyOutput<const SCALAR_LIMBS: usize, GroupElement> =
        crate::dkg::centralized_party::PublicOutput<group::Value<GroupElement>>;

    pub type DKGDecentralizedPartyOutput<GroupElement> = crate::dkg::decentralized_party::Output<
        group::Value<GroupElement>,
        group::Value<CiphertextSpaceGroupElement>,
    >;

    pub type EncryptionOfSecretKeyShareAndPublicKeyShare<const SCALAR_LIMBS: usize, GroupElement> =
        group::Value<
            encryption_of_discrete_log::StatementSpaceGroupElement<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >,
        >;

    pub type ProofVerificationRoundPublicInput<
        const SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        GroupElement,
    > = dkg::decentralized_party::proof_verification_round::PublicInput<
        group::Value<GroupElement>,
        group::Value<CiphertextSpaceGroupElement>,
        KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
            group::PublicParameters<GroupElement>,
        >,
    >;

    pub type ProofVerificationRoundParty<
        const SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        GroupElement,
    > = dkg::decentralized_party::proof_verification_round::Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
            group::PublicParameters<GroupElement>,
        >,
    >;

    pub type DKGCentralizedParty<
        const SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        GroupElement,
    > = dkg::centralized_party::Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
            group::PublicParameters<GroupElement>,
        >,
    >;

    pub type EncryptionOfSecretKeyShareRoundAsyncParty<
        const SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        GroupElement,
    > = dkg::decentralized_party::encryption_of_secret_key_share_round::paillier::asynchronous::Party<RANGE_CLAIMS_PER_SCALAR, NUM_RANGE_CLAIMS, SCALAR_LIMBS, GroupElement>;

    pub type PresignAsyncParty<
        const SCALAR_LIMBS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        GroupElement,
    > = crate::presign::decentralized_party::paillier::asynchronous::Party<
        RANGE_CLAIMS_PER_SCALAR,
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        GroupElement,
    >;

    pub type EncryptionOfMaskAndMaskedKey<const SCALAR_LIMBS: usize> = group::Value<
        encryption_of_tuple::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            EncryptionKey,
        >,
    >;

    pub type NoncePublicShareAndEncryptionOfMaskedNonceShare<
        const SCALAR_LIMBS: usize,
        GroupElement,
    > = group::Value<
        scaling_of_discrete_log::StatementSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >,
    >;

    pub type Presign<GroupElement> = crate::presign::Presign<
        group::Value<GroupElement>,
        group::Value<CiphertextSpaceGroupElement>,
    >;

    #[cfg(feature = "bulletproofs")]
    pub mod bulletproofs {
        use serde::{Deserialize, Serialize};

        use group::{direct_product, PrimeGroupElement};
        use homomorphic_encryption::GroupsPublicParametersAccessors;
        use tiresias::{LargeBiPrimeSizedNumber, RandomnessSpacePublicParameters};

        use crate::bulletproofs::*;
        use crate::languages::DIMENSION;
        use crate::ProtocolPublicParameters;

        use super::*;

        pub type UnboundedDComEvalWitness<const SCALAR_LIMBS: usize, GroupElement> =
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, group::Scalar<SCALAR_LIMBS, GroupElement>>,
                tiresias::RandomnessSpaceGroupElement,
            >;

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct PaillierProtocolPublicParameters<
            const SCALAR_LIMBS: usize,
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const NUM_RANGE_CLAIMS: usize,
            ScalarPublicParameters,
            GroupPublicParameters,
        > {
            pub protocol_public_parameters: ProtocolPublicParameters<
                ScalarPublicParameters,
                GroupPublicParameters,
                super::PublicParameters,
            >,
            pub unbounded_encdl_witness_public_parameters:
                group::PublicParameters<UnboundedEncDLWitness>,
            pub unbounded_encdh_witness_public_parameters:
                group::PublicParameters<UnboundedEncDHWitness>,
            pub unbounded_dcom_eval_witness_public_parameters: direct_product::PublicParameters<
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                RandomnessSpacePublicParameters,
            >,
            pub range_proof_enc_dl_public_parameters:
                crate::bulletproofs::PublicParameters<RANGE_CLAIMS_PER_SCALAR>,
            pub range_proof_dcom_eval_public_parameters:
                crate::bulletproofs::PublicParameters<NUM_RANGE_CLAIMS>,
        }

        impl<
                const SCALAR_LIMBS: usize,
                const RANGE_CLAIMS_PER_SCALAR: usize,
                const NUM_RANGE_CLAIMS: usize,
                ScalarPublicParameters,
                GroupPublicParameters,
            >
            AsRef<
                ProtocolPublicParameters<
                    ScalarPublicParameters,
                    GroupPublicParameters,
                    super::PublicParameters,
                >,
            >
            for PaillierProtocolPublicParameters<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                NUM_RANGE_CLAIMS,
                ScalarPublicParameters,
                GroupPublicParameters,
            >
        {
            fn as_ref(
                &self,
            ) -> &ProtocolPublicParameters<
                ScalarPublicParameters,
                GroupPublicParameters,
                super::PublicParameters,
            > {
                &self.protocol_public_parameters
            }
        }

        impl<
                const SCALAR_LIMBS: usize,
                const RANGE_CLAIMS_PER_SCALAR: usize,
                const NUM_RANGE_CLAIMS: usize,
                ScalarPublicParameters,
                GroupPublicParameters,
            >
            PaillierProtocolPublicParameters<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                NUM_RANGE_CLAIMS,
                ScalarPublicParameters,
                GroupPublicParameters,
            >
        where
            ScalarPublicParameters: Default + Clone,
            GroupPublicParameters: Default,
        {
            pub fn new<GroupElement>(paillier_associated_bi_prime: LargeBiPrimeSizedNumber) -> Self
            where
                GroupElement: PrimeGroupElement<SCALAR_LIMBS>
                    + group::GroupElement<PublicParameters = GroupPublicParameters>,
                GroupElement::Scalar:
                    group::GroupElement<PublicParameters = ScalarPublicParameters>,
            {
                let scalar_group_public_parameters =
                    group::PublicParameters::<GroupElement::Scalar>::default();

                let group_public_parameters = GroupElement::PublicParameters::default();

                let range_proof_enc_dl_public_parameters =
                    proof::range::bulletproofs::PublicParameters::<RANGE_CLAIMS_PER_SCALAR>::default();

                let range_proof_dcom_eval_public_parameters =
                    proof::range::bulletproofs::PublicParameters::<NUM_RANGE_CLAIMS>::default();

                let encryption_scheme_public_parameters =
                    tiresias::encryption_key::PublicParameters::new(paillier_associated_bi_prime)
                        .unwrap();

                let unbounded_encdl_witness_public_parameters = encryption_scheme_public_parameters
                    .randomness_space_public_parameters()
                    .clone();

                let unbounded_encdh_witness_public_parameters = self_product::PublicParameters::new(
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                );

                let unbounded_dcom_eval_witness_public_parameters =
                    direct_product::PublicParameters(
                        self_product::PublicParameters::new(scalar_group_public_parameters.clone()),
                        encryption_scheme_public_parameters
                            .randomness_space_public_parameters()
                            .clone(),
                    );

                Self {
                    protocol_public_parameters: ProtocolPublicParameters {
                        scalar_group_public_parameters,
                        group_public_parameters,
                        encryption_scheme_public_parameters,
                    },
                    range_proof_enc_dl_public_parameters,
                    range_proof_dcom_eval_public_parameters,
                    unbounded_encdl_witness_public_parameters,
                    unbounded_encdh_witness_public_parameters,
                    unbounded_dcom_eval_witness_public_parameters,
                }
            }
        }

        pub type SignMessage<
            const SCALAR_LIMBS: usize,
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const RANGE_CLAIMS_PER_MASK: usize,
            const NUM_RANGE_CLAIMS: usize,
            GroupElement,
        > = crate::sign::centralized_party::message::paillier::Message<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            RangeProof,
            UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        >;
    }
}

#[cfg(feature = "bulletproofs")]
pub mod bulletproofs {
    use group::ristretto;
    use proof::{range, range::bulletproofs};

    pub const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize = ristretto::SCALAR_LIMBS;
    pub type RangeProof = bulletproofs::RangeProof;

    pub type MessageSpaceGroupElement<const NUM_RANGE_CLAIMS: usize> =
        range::CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >;

    pub type RandomnessSpaceGroupElement<const NUM_RANGE_CLAIMS: usize> =
        range::CommitmentSchemeRandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >;

    pub type CommitmentSpaceGroupElement<const NUM_RANGE_CLAIMS: usize> =
        range::CommitmentSchemeCommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >;

    pub type PublicParameters<const NUM_RANGE_CLAIMS: usize> =
        range::bulletproofs::PublicParameters<NUM_RANGE_CLAIMS>;
}

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    pub use ::class_groups::SECP256K1_MESSAGE_LIMBS as MESSAGE_LIMBS;
    use group::secp256k1;

    pub const SCALAR_LIMBS: usize = secp256k1::SCALAR_LIMBS;
    pub type GroupElement = secp256k1::GroupElement;
    pub type Scalar = secp256k1::Scalar;

    #[cfg(feature = "class_groups")]
    pub mod class_groups {
        use crate::{languages, ProtocolContext};

        use super::*;

        pub const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS;
        pub const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize =
            ::class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;

        pub type EncryptionKey = ::class_groups::EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >;
        pub type DecryptionKey = ::class_groups::DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >;
        pub type ProtocolPublicParameters = crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;

        pub type AsyncProtocol = crate::class_groups::asynchronous::Protocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;

        pub type EncryptionOfDiscreteLogProof =
            languages::class_groups::EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >;

        pub type EncryptionOfSecretKeyShareRoundAsyncParty =
            crate::class_groups::EncryptionOfSecretKeyShareRoundAsyncParty<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >;
    }

    #[cfg(feature = "paillier")]
    pub mod paillier {
        #[cfg(feature = "bulletproofs")]
        pub mod bulletproofs {
            use crate::{languages, ProtocolContext};

            use super::super::bulletproofs::*;
            use super::super::*;

            pub type PaillierProtocolPublicParameters =
                crate::paillier::bulletproofs::PaillierProtocolPublicParameters<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    NUM_RANGE_CLAIMS,
                    secp256k1::scalar::PublicParameters,
                    secp256k1::group_element::PublicParameters,
                >;

            pub type AsyncProtocol = crate::paillier::asynchronous::Protocol<
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                NUM_RANGE_CLAIMS,
                SCALAR_LIMBS,
                GroupElement,
            >;

            pub type EncryptionOfDiscreteLogProof =
                languages::paillier::EncryptionOfDiscreteLogProof<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    GroupElement,
                    ProtocolContext,
                >;

            pub type EncryptionOfSecretKeyShareRoundAsyncParty =
                crate::paillier::EncryptionOfSecretKeyShareRoundAsyncParty<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    NUM_RANGE_CLAIMS,
                    GroupElement,
                >;
        }
    }

    #[cfg(feature = "bulletproofs")]
    pub mod bulletproofs {
        use crypto_bigint::{Uint, U64};

        use group::StatisticalSecuritySizedNumber;
        use proof::range::bulletproofs::RANGE_CLAIM_BITS;

        use crate::languages::DIMENSION;

        use super::SCALAR_LIMBS;

        pub const RANGE_CLAIMS_PER_SCALAR: usize =
            Uint::<SCALAR_LIMBS>::BITS as usize / RANGE_CLAIM_BITS;
        pub const MASK_LIMBS: usize =
            SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

        pub const RANGE_CLAIMS_PER_MASK: usize =
            Uint::<MASK_LIMBS>::BITS as usize / RANGE_CLAIM_BITS;

        pub const NUM_RANGE_CLAIMS: usize =
            DIMENSION * RANGE_CLAIMS_PER_SCALAR + RANGE_CLAIMS_PER_MASK;
    }
}
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use class_groups::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use class_groups::Secp256k1DecryptionKey;
    use group::{secp256k1, OsCsRng};
    use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;
    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    use tiresias::test_helpers::{N, SECRET_KEY};

    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    use crate::secp256k1::paillier::bulletproofs::PaillierProtocolPublicParameters;
    use crate::ProtocolPublicParameters;

    #[cfg(feature = "class_groups")]
    #[allow(dead_code)]
    pub fn setup_class_groups_secp256k1() -> (
        crate::class_groups::ProtocolPublicParameters<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
        >,
        crate::secp256k1::class_groups::DecryptionKey,
    ) {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (encryption_scheme_public_parameters, decryption_key) =
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

        let protocol_public_parameters = ProtocolPublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
        >(encryption_scheme_public_parameters.clone());

        (protocol_public_parameters, decryption_key)
    }

    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    #[allow(dead_code)]
    pub fn setup_paillier_secp256k1() -> (PaillierProtocolPublicParameters, tiresias::DecryptionKey)
    {
        let paillier_protocol_public_parameters =
            PaillierProtocolPublicParameters::new::<secp256k1::GroupElement>(N);

        let decryption_key = tiresias::DecryptionKey::new(
            SECRET_KEY,
            &paillier_protocol_public_parameters
                .protocol_public_parameters
                .encryption_scheme_public_parameters,
        )
        .unwrap();

        (paillier_protocol_public_parameters, decryption_key)
    }
}
