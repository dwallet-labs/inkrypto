// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;

use crypto_bigint::{ConcatMixed, NonZero, Uint};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement, PrimeGroupElement, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use mpc::{two_party, AsynchronouslyAdvanceable};
use proof::TranscriptProtocol;

use crate::languages::KnowledgeOfDiscreteLogUCProof;

pub mod centralized_party;
#[cfg(feature = "class_groups")]
mod class_groups;
pub mod decentralized_party;
#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
mod paillier;

/// An instantiation of the 2PC-MPC DKG protocol.
pub trait Protocol {
    /// The DKG protocol's public parameters.
    type ProtocolPublicParameters: Serialize + Clone + Debug + PartialEq + Eq;

    /// The DKG protocol's protocol context.
    type ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync;

    /// An encryption key.
    type EncryptionKey: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq;

    /// A secret key.
    type SecretKey: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq;

    /// The private output of the centralized party's DKG protocol.
    /// *** SECURITY NOTICE ***
    /// KEEP PRIVATE: **must never be published or broadcasted**.
    type CentralizedPartySecretKeyShare: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The output of the centralized party's DKG protocol.
    type CentralizedPartyDKGPublicOutput: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The output of the decentralized party's DKG protocol.
    /// Contains only public information.
    type DecentralizedPartyDKGOutput: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The output of the first round of the decentralized party's DKG protocol.
    type EncryptionOfSecretKeyShareAndPublicKeyShare: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Send
        + Sync;

    /// The first round of the decentralized party's DKG protocol.
    type EncryptionOfSecretKeyShareRoundParty: mpc::Party<
            PublicInput = Self::ProtocolPublicParameters,
            PublicOutput = (
                [Self::EncryptionOfSecretKeyShareAndPublicKeyShare; 2],
                CommitmentSizedNumber,
            ),
            PublicOutputValue = (
                [Self::EncryptionOfSecretKeyShareAndPublicKeyShare; 2],
                CommitmentSizedNumber,
            ),
        > + AsynchronouslyAdvanceable<PrivateInput = ()>
        + Send
        + Sync;

    /// The public input of the second and final round of the decentralized party's DKG protocol.
    type ProofVerificationRoundPublicInput: From<(
            Self::ProtocolPublicParameters,
            (
                [Self::EncryptionOfSecretKeyShareAndPublicKeyShare; 2],
                CommitmentSizedNumber,
            ),
            Self::PublicKeyShareAndProof,
        )> + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The second and final round of the decentralized party's DKG protocol.
    type ProofVerificationRoundParty: mpc::Party<
            Message = (),
            PublicOutput = Self::DecentralizedPartyDKGOutput,
            PublicOutputValue = Self::DecentralizedPartyDKGOutput,
            PublicInput = Self::ProofVerificationRoundPublicInput,
        > + AsynchronouslyAdvanceable<PrivateInput = ()>
        + Send
        + Sync;

    /// The public input of the first and only round of the centralized party's DKG protocol.
    type DKGCentralizedPartyPublicInput: From<(Self::ProtocolPublicParameters, CommitmentSizedNumber)>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The outgoing message of the first and only round of the centralized party's DKG protocol.
    type PublicKeyShareAndProof: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The first and only round of the centralized party's DKG protocol.
    type DKGCentralizedPartyRound: two_party::Round<
        IncomingMessage = [Self::EncryptionOfSecretKeyShareAndPublicKeyShare; 2],
        OutgoingMessage = Self::PublicKeyShareAndProof,
        PrivateInput = (),
        PublicInput = Self::DKGCentralizedPartyPublicInput,
        PublicOutput = Self::CentralizedPartyDKGPublicOutput,
        PublicOutputValue = Self::CentralizedPartyDKGPublicOutput,
        PrivateOutput = Self::CentralizedPartySecretKeyShare,
    >;

    /// The message sent in the "encrypted user-share" feature
    /// by the centralized party to prove it encrypted its secret key share under its own key.
    type EncryptedSecretKeyShareMessage: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// A helper function for the "encrypted user-share" feature,
    /// in which the centralized party encrypts its secret key share under its own key,
    /// and lets an external entity verify & store it as backup.
    ///
    /// This function is called by the centralized party to
    /// encrypt & prove its share, and returns the encryption and the proof.
    fn encrypt_and_prove_centralized_party_share(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        encryption_key: Self::EncryptionKey,
        secret_key_share: Self::CentralizedPartySecretKeyShare,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self::EncryptedSecretKeyShareMessage>;

    /// A helper function for the "encrypted user-share" feature,
    /// in which the centralized party encrypts its secret key share under its own key,
    /// and lets an external entity verify & store it as backup.
    ///
    /// This function is called by the external entity to verify the proof,
    /// and returns the encryption of the centralized party secret key share if it is valid.
    fn verify_encryption_of_centralized_party_share_proof(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        dkg_output: Self::DecentralizedPartyDKGOutput,
        encryption_key: Self::EncryptionKey,
        encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage,
        rng: &mut impl CsRng,
    ) -> crate::Result<()>;

    /// A helper function for the "public user-share" feature, in which the centralized party (a.k.a. the "user") publishes its secret key share so that anyone can emulate it.
    /// This function verifies that value is the right one, by comparing it to the output of the DKG.
    fn verify_centralized_party_secret_key_share(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        dkg_output: Self::DecentralizedPartyDKGOutput,
        centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare,
    ) -> crate::Result<()>;

    /// The message sent by the centralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    type DealTrustedShareMessage: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The first and only round of the centralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    type TrustedDealerDKGCentralizedPartyRound: two_party::Round<
        IncomingMessage = (),
        OutgoingMessage = Self::DealTrustedShareMessage,
        PrivateInput = Self::SecretKey,
        PublicInput = Self::DKGCentralizedPartyPublicInput,
        PublicOutput = Self::CentralizedPartyDKGPublicOutput,
        PublicOutputValue = Self::CentralizedPartyDKGPublicOutput,
        PrivateOutput = Self::CentralizedPartySecretKeyShare,
    >;

    /// The public input of the  decentralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    type TrustedDealerDKGDecentralizedPublicInput: From<(
            Self::ProtocolPublicParameters,
            CommitmentSizedNumber,
            Self::DealTrustedShareMessage,
        )> + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The decentralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    type TrustedDealerDKGDecentralizedParty: mpc::Party<
            Message = (),
            PublicOutput = Self::DecentralizedPartyDKGOutput,
            PublicOutputValue = Self::DecentralizedPartyDKGOutput,
            PublicInput = Self::TrustedDealerDKGDecentralizedPublicInput,
        > + AsynchronouslyAdvanceable<PrivateInput = ()>
        + Send
        + Sync;
}

/// This function derives the randomized public key share of the decentralized party
/// $X_B$ and the encryption of its secret key share $\textsf{ct}_{\textsf{key}}$ (i.e. discrete
/// log) from two points $X_B^{0}, X_B^{1}$ and encryptions of
/// their discrete logs $\textsf{ct{_{\textsf{key}}^{0}, \textsf{ct}_{\textsf{key}}^{1}$ by applying a linear combination using the
/// public randomizers $\mu_{x}^{0},\mu_{x}^{1},\mu_{x}^{G}$ derived from a hash
/// $\mathcal{O}(X_B^{0},X_B^{1},
/// X_{A},\pi_{\sf{DL}})$:
///  - $\textsf{ct}_{\textsf{key}}=(\mu_{x}^{0}\odot \textsf{ct}_{\textsf{key}}^{0})\oplus (\mu_{x}^{1}\odot \textsf{ct}_{\textsf{key}}^{1})\oplus \mu_{x}^{G}$
///  - $X_B=\mu_{x}^{1}\cdot X_B^{0}+\mu_{x}^{1}X_B^{1}+\mu_{x}^{G}\cdot G$
#[allow(clippy::too_many_arguments)]
fn derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    session_id: CommitmentSizedNumber,
    decentralized_party_encryption_of_secret_key_share_first_part: group::Value<
        EncryptionKey::CiphertextSpaceGroupElement,
    >,
    decentralized_party_encryption_of_secret_key_share_second_part: group::Value<
        EncryptionKey::CiphertextSpaceGroupElement,
    >,
    decentralized_party_public_key_share_first_part: GroupElement::Value,
    decentralized_party_public_key_share_second_part: GroupElement::Value,
    centralized_party_public_key_share: &GroupElement::Value, // $X_{A}$
    knowledge_of_discrete_log_uc_proof: &KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>, // $\pi_{\sf{DL}}$
    group_public_parameters: &GroupElement::PublicParameters,
    encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
) -> crate::Result<(EncryptionKey::CiphertextSpaceGroupElement, GroupElement)>
where
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    // $\textsf{ct}_{\textsf{key}}^{0}$
    let decentralized_party_encryption_of_secret_key_share_first_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            decentralized_party_encryption_of_secret_key_share_first_part,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    // $X_B^{0}$
    let decentralized_party_public_key_share_first_part = GroupElement::new(
        decentralized_party_public_key_share_first_part,
        group_public_parameters,
    )?;

    // $\textsf{ct}_{\textsf{key}}^{1}$
    let decentralized_party_encryption_of_secret_key_share_second_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            decentralized_party_encryption_of_secret_key_share_second_part,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    // $X_B^{1}$
    let decentralized_party_public_key_share_second_part = GroupElement::new(
        decentralized_party_public_key_share_second_part,
        group_public_parameters,
    )?;

    let mut transcript = Transcript::new(
        b"DKG randomize decentralized party public key share and encryption of secret key share",
    );

    transcript.append_uint(b"$ sid $", &session_id);
    transcript.transcribe(b"$ \\GG,G,q $", group_public_parameters.clone())?;

    transcript.serialize_to_transcript_as_json(
        b"$X_{\\CentralizedParty}$",
        &centralized_party_public_key_share,
    )?;

    transcript.serialize_to_transcript_as_json(
        b"$X_{\\DistributedParty}^{0}$",
        &decentralized_party_public_key_share_first_part.value(),
    )?;
    transcript.serialize_to_transcript_as_json(
        b"$X_{\\DistributedParty}^{1}$",
        &decentralized_party_public_key_share_second_part.value(),
    )?;

    transcript.serialize_to_transcript_as_json(
        b"$\\pi_{\\sf{DL}}$",
        knowledge_of_discrete_log_uc_proof,
    )?;

    let group_order = NonZero::new(GroupElement::order_from_public_parameters(
        group_public_parameters,
    ))
    .unwrap();

    let first_key_public_randomizer: Uint<SCALAR_LIMBS> =
        group::Value::<GroupElement::Scalar>::from(
            transcript.uniformly_reduced_challenge::<SCALAR_LIMBS>(b"$\\mu_{x}^{0}$", &group_order),
        )
        .into();

    let second_key_public_randomizer: Uint<SCALAR_LIMBS> =
        group::Value::<GroupElement::Scalar>::from(
            transcript.uniformly_reduced_challenge::<SCALAR_LIMBS>(b"$\\mu_{x}^{1}$", &group_order),
        )
        .into();

    let free_coefficient_key_public_randomizer: Uint<SCALAR_LIMBS> =
        group::Value::<GroupElement::Scalar>::from(
            transcript.uniformly_reduced_challenge::<SCALAR_LIMBS>(b"$\\mu_{x}^{G}$", &group_order),
        )
        .into();

    let encryption_key = EncryptionKey::new(encryption_scheme_public_parameters)?;
    let neutral_randomness =
        EncryptionKey::RandomnessSpaceGroupElement::neutral_from_public_parameters(
            encryption_scheme_public_parameters.randomness_space_public_parameters(),
        )?;
    let free_coefficient_key_public_randomizer_plaintext =
        EncryptionKey::PlaintextSpaceGroupElement::new(
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&free_coefficient_key_public_randomizer)
                .into(),
            encryption_scheme_public_parameters.plaintext_space_public_parameters(),
        )?;
    let encryption_of_free_coefficient_key_public_randomizer = encryption_key
        .encrypt_with_randomness(
            &free_coefficient_key_public_randomizer_plaintext,
            &neutral_randomness,
            encryption_scheme_public_parameters,
            true,
        );

    //  Compute $\textsf{ct}_{\textsf{key}}=(\mu_{x}^{0}\odot \textsf{ct}_{\textsf{key}}^{0})\oplus (\mu_{x}^{1}\odot \textsf{ct}_{\textsf{key}}^{1})\oplus \mu_{x}^{G}$
    let decentralized_party_encryption_of_secret_key_share =
        ((decentralized_party_encryption_of_secret_key_share_first_part
            .scale_vartime(&first_key_public_randomizer))
        .add_vartime(
            &(decentralized_party_encryption_of_secret_key_share_second_part
                .scale_vartime(&second_key_public_randomizer)),
        ))
        .add_vartime(&(encryption_of_free_coefficient_key_public_randomizer));

    //  Compute $X_B=\mu_{x}^{1}\cdot X_B^{0}+\mu_{x}^{1}X_B^{1}+\mu_{x}^{G}\cdot G$
    let decentralized_party_public_key_share = ((decentralized_party_public_key_share_first_part
        .scale_vartime(&first_key_public_randomizer))
    .add_vartime(
        &(decentralized_party_public_key_share_second_part
            .scale_vartime(&second_key_public_randomizer)),
    ))
    .add_vartime(&(generator.scale_vartime(&free_coefficient_key_public_randomizer)));

    Ok((
        decentralized_party_encryption_of_secret_key_share,
        decentralized_party_public_key_share,
    ))
}

#[cfg(any(test, feature = "benchmarking"))]
#[allow(dead_code)]
pub(crate) mod tests {
    use std::{collections::HashMap, time::Duration};

    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::{Random, Uint};
    use rstest::rstest;

    use group::{secp256k1, GroupElement as _, OsCsRng, PartyID, PrimeGroupElement, Samplable};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;
    use mpc::two_party::Round;
    use mpc::{Weight, WeightedThresholdAccessStructure};

    use crate::dkg::centralized_party::{PublicKeyShareAndProof, SecretKeyShare};
    use crate::languages::KnowledgeOfDiscreteLogUCProof;
    use crate::ProtocolPublicParameters;

    #[cfg(feature = "class_groups")]
    use crate::test_helpers::setup_class_groups_secp256k1;
    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    use crate::test_helpers::setup_paillier_secp256k1;

    use super::*;

    pub(crate) fn setup_session(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) -> (CommitmentSizedNumber, WeightedThresholdAccessStructure) {
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        (session_id, access_structure)
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    #[cfg(feature = "class_groups")]
    fn generates_distributed_key_async_class_groups_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_distributed_key_async_class_groups_secp256k1_internal(threshold, party_to_weight)
    }

    #[cfg(feature = "class_groups")]
    pub(crate) fn generates_distributed_key_async_class_groups_secp256k1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let (protocol_public_parameters, decryption_key) = setup_class_groups_secp256k1();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        generates_distributed_key_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            ::class_groups::EncryptionKey<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            ::class_groups::DecryptionKey<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            crate::secp256k1::class_groups::AsyncProtocol,
        >(
            session_id,
            access_structure,
            protocol_public_parameters,
            decryption_key,
            "Class Groups Asynchronous secp256k1".to_string(),
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    #[cfg(feature = "class_groups")]
    fn deals_trusted_shares_async_class_groups_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        deals_trusted_shares_async_class_groups_secp256k1_internal(threshold, party_to_weight)
    }

    #[cfg(feature = "class_groups")]
    pub(crate) fn deals_trusted_shares_async_class_groups_secp256k1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let (protocol_public_parameters, _) = setup_class_groups_secp256k1();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        deals_trusted_shares_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            ::class_groups::EncryptionKey<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            crate::secp256k1::class_groups::AsyncProtocol,
        >(session_id, access_structure, protocol_public_parameters);
    }

    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn generates_distributed_key_async_paillier_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        generates_distributed_key_async_paillier_secp256k1_internal(threshold, party_to_weight)
    }

    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    pub(crate) fn generates_distributed_key_async_paillier_secp256k1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let (paillier_protocol_public_parameters, decryption_key) = setup_paillier_secp256k1();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        generates_distributed_key_internal::<
            { secp256k1::SCALAR_LIMBS },
            { crate::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            tiresias::DecryptionKey,
            crate::secp256k1::paillier::bulletproofs::AsyncProtocol,
        >(
            session_id,
            access_structure,
            paillier_protocol_public_parameters,
            decryption_key,
            "Paillier Asynchronous secp256k1".to_string(),
        );
    }

    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn deals_trusted_shares_async_paillier_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        deals_trusted_shares_async_paillier_secp256k1_internal(threshold, party_to_weight)
    }

    #[cfg(all(feature = "paillier", feature = "bulletproofs",))]
    pub(crate) fn deals_trusted_shares_async_paillier_secp256k1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let (paillier_protocol_public_parameters, _) = setup_paillier_secp256k1();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        deals_trusted_shares_internal::<
            { secp256k1::SCALAR_LIMBS },
            { crate::paillier::PLAINTEXT_SPACE_SCALAR_LIMBS },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
            crate::secp256k1::paillier::bulletproofs::AsyncProtocol,
        >(
            session_id,
            access_structure,
            paillier_protocol_public_parameters,
        );
    }

    pub fn generates_distributed_key_internal<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKey: AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        P,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: WeightedThresholdAccessStructure,
        protocol_public_parameters: P::ProtocolPublicParameters,
        _decryption_key: DecryptionKey,
        description: String,
    ) -> (
        P::CentralizedPartyDKGPublicOutput,
        P::CentralizedPartySecretKeyShare,
        P::DecentralizedPartyDKGOutput,
    )
    where
        GroupElement::Scalar: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        P: Protocol<
            CentralizedPartyDKGPublicOutput = centralized_party::PublicOutput<
                group::Value<GroupElement>,
            >,
            CentralizedPartySecretKeyShare = SecretKeyShare<group::Value<GroupElement::Scalar>>,
            DecentralizedPartyDKGOutput = decentralized_party::Output<
                GroupElement::Value,
                group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            >,
            PublicKeyShareAndProof = PublicKeyShareAndProof<
                group::Value<GroupElement>,
                KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
            >,
        >,
        P::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
                group::PublicParameters<GroupElement>,
                EncryptionKey::PublicParameters,
            >,
        >,
    {
        let measurement = WallTime;
        let mut centralized_party_total_time = Duration::ZERO;
        let mut decentralized_party_total_time = Duration::ZERO;

        let parties: Vec<PartyID> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .collect();
        let private_inputs: HashMap<_, _> = parties
            .iter()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        let encryption_of_secret_share_round_public_inputs = parties
            .iter()
            .map(|&party_id| (party_id, protocol_public_parameters.clone()))
            .collect();

        let (
            encryption_of_decentralized_party_secret_share_time,
            times,
            (encryption_of_secret_key_share_and_public_key_share, _),
        ) = asynchronous_session_terminates_successfully_internal::<
            P::EncryptionOfSecretKeyShareRoundParty,
        >(
            session_id,
            &access_structure,
            private_inputs.clone(),
            encryption_of_secret_share_round_public_inputs,
            2,
            HashMap::new(),
            false,
            false,
        );

        let centralized_party_public_input =
            (protocol_public_parameters.clone(), session_id).into();

        let now = measurement.start();

        let round_result = P::DKGCentralizedPartyRound::advance(
            encryption_of_secret_key_share_and_public_key_share.clone(),
            &(),
            &centralized_party_public_input,
            &mut OsCsRng,
        )
        .unwrap();

        let public_key_share_and_proof = round_result.outgoing_message;
        let centralized_party_dkg_output = round_result.public_output;
        let centralized_party_secret_key_share = round_result.private_output;

        centralized_party_total_time =
            measurement.add(&centralized_party_total_time, &measurement.end(now));

        let decentralized_party_public_key_share = GroupElement::new(
            centralized_party_dkg_output.decentralized_party_public_key_share,
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        let secret_key_share = GroupElement::Scalar::new(
            centralized_party_secret_key_share.0,
            &protocol_public_parameters
                .as_ref()
                .scalar_group_public_parameters,
        )
        .unwrap();

        let public_key_share = GroupElement::new(
            centralized_party_dkg_output.public_key_share,
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        let public_key = GroupElement::new(
            centralized_party_dkg_output.public_key,
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        assert_eq!(
            decentralized_party_public_key_share + public_key_share,
            public_key
        );

        let generator = public_key_share.generator();

        assert_eq!(secret_key_share * generator, public_key_share);

        let proof_verification_round_public_inputs = parties
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    (
                        protocol_public_parameters.clone(),
                        (
                            encryption_of_secret_key_share_and_public_key_share.clone(),
                            session_id,
                        ),
                        public_key_share_and_proof.clone(),
                    )
                        .into(),
                )
            })
            .collect();

        let (proof_verification_round_time, _, decentralized_party_dkg_output) =
            asynchronous_session_terminates_successfully_internal::<P::ProofVerificationRoundParty>(
                CommitmentSizedNumber::random(&mut OsCsRng),
                &access_structure,
                private_inputs,
                proof_verification_round_public_inputs,
                1,
                HashMap::new(),
                false,
                false,
            );

        assert_eq!(
            centralized_party_dkg_output.public_key_share,
            decentralized_party_dkg_output.centralized_party_public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output.decentralized_party_public_key_share,
            decentralized_party_dkg_output.public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output.public_key,
            decentralized_party_dkg_output.public_key,
        );

        decentralized_party_total_time = measurement.add(
            &decentralized_party_total_time,
            &encryption_of_decentralized_party_secret_share_time,
        );

        decentralized_party_total_time = measurement.add(
            &decentralized_party_total_time,
            &proof_verification_round_time,
        );

        let number_of_tangible_parties = access_structure.number_of_tangible_parties();
        let number_of_virtual_parties = access_structure.number_of_virtual_parties();
        let threshold = access_structure.threshold;

        println!(
            "{description} DKG, {number_of_tangible_parties}, {number_of_virtual_parties}, {threshold}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
            centralized_party_total_time.as_millis(),
            decentralized_party_total_time.as_millis(),
            encryption_of_decentralized_party_secret_share_time.as_millis(),
            times[0].as_millis(),
            times[1].as_millis(),
            proof_verification_round_time.as_millis(),
        );

        (
            centralized_party_dkg_output,
            centralized_party_secret_key_share,
            decentralized_party_dkg_output,
        )
    }

    pub fn deals_trusted_shares_internal<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        P,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: WeightedThresholdAccessStructure,
        protocol_public_parameters: P::ProtocolPublicParameters,
    ) -> (
        P::CentralizedPartyDKGPublicOutput,
        P::CentralizedPartySecretKeyShare,
        P::DecentralizedPartyDKGOutput,
    )
    where
        GroupElement::Scalar: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        P: Protocol<
            CentralizedPartyDKGPublicOutput = centralized_party::PublicOutput<
                group::Value<GroupElement>,
            >,
            CentralizedPartySecretKeyShare = SecretKeyShare<group::Value<GroupElement::Scalar>>,
            DecentralizedPartyDKGOutput = decentralized_party::Output<
                GroupElement::Value,
                group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            >,
            PublicKeyShareAndProof = PublicKeyShareAndProof<
                group::Value<GroupElement>,
                KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
            >,
            SecretKey = group::Value<GroupElement::Scalar>,
        >,
        P::ProtocolPublicParameters: AsRef<
            ProtocolPublicParameters<
                group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
                group::PublicParameters<GroupElement>,
                EncryptionKey::PublicParameters,
            >,
        >,
    {
        let parties: Vec<PartyID> = access_structure
            .party_to_virtual_parties()
            .keys()
            .copied()
            .collect();
        let private_inputs: HashMap<_, _> = parties
            .iter()
            .copied()
            .map(|party_id| (party_id, ()))
            .collect();

        let centralized_party_public_input =
            (protocol_public_parameters.clone(), session_id).into();

        let secret_key = GroupElement::Scalar::sample(
            &protocol_public_parameters
                .as_ref()
                .scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        let expected_public_key = secret_key * generator;

        let round_result = P::TrustedDealerDKGCentralizedPartyRound::advance(
            (),
            &secret_key.value(),
            &centralized_party_public_input,
            &mut OsCsRng,
        )
        .unwrap();

        let centralized_party_message = round_result.outgoing_message;
        let centralized_party_dkg_output = round_result.public_output;
        let centralized_party_secret_key_share = round_result.private_output;

        let decentralized_party_public_key_share = GroupElement::new(
            centralized_party_dkg_output.decentralized_party_public_key_share,
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        let secret_key_share = GroupElement::Scalar::new(
            centralized_party_secret_key_share.0,
            &protocol_public_parameters
                .as_ref()
                .scalar_group_public_parameters,
        )
        .unwrap();

        let public_key_share = GroupElement::new(
            centralized_party_dkg_output.public_key_share,
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        let public_key = GroupElement::new(
            centralized_party_dkg_output.public_key,
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        assert_eq!(public_key, expected_public_key);

        assert_eq!(
            decentralized_party_public_key_share + public_key_share,
            public_key
        );

        let generator = public_key_share.generator();

        assert_eq!(secret_key_share * generator, public_key_share);

        let proof_verification_round_public_inputs = parties
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    (
                        protocol_public_parameters.clone(),
                        session_id,
                        centralized_party_message.clone(),
                    )
                        .into(),
                )
            })
            .collect();

        let (.., decentralized_party_dkg_output) =
            asynchronous_session_terminates_successfully_internal::<
                P::TrustedDealerDKGDecentralizedParty,
            >(
                CommitmentSizedNumber::random(&mut OsCsRng),
                &access_structure,
                private_inputs,
                proof_verification_round_public_inputs,
                1,
                HashMap::new(),
                false,
                false,
            );

        assert_eq!(
            centralized_party_dkg_output.public_key_share,
            decentralized_party_dkg_output.centralized_party_public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output.decentralized_party_public_key_share,
            decentralized_party_dkg_output.public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output.public_key,
            decentralized_party_dkg_output.public_key,
        );

        (
            centralized_party_dkg_output,
            centralized_party_secret_key_share,
            decentralized_party_dkg_output,
        )
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn mock_dkg_output<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            group::PublicParameters<GroupElement>,
            EncryptionKey::PublicParameters,
        >,
    ) -> (
        centralized_party::PublicOutput<GroupElement::Value>,
        SecretKeyShare<group::Value<GroupElement::Scalar>>,
        decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    ) {
        let encryption_key =
            EncryptionKey::new(&protocol_public_parameters.encryption_scheme_public_parameters)
                .unwrap();

        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();

        let centralized_party_secret_key_share = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let decentralized_party_secret_key_share = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let decentralized_party_secret_key_share_value: Uint<SCALAR_LIMBS> =
            decentralized_party_secret_key_share.into();
        let decentralized_party_secret_key_share_value =
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&decentralized_party_secret_key_share_value);
        let decentralized_party_secret_key_share_plaintext =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                decentralized_party_secret_key_share_value.into(),
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            )
            .unwrap();
        let (_, encryption_of_secret_key_share) = encryption_key
            .encrypt(
                &decentralized_party_secret_key_share_plaintext,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();

        let centralized_party_public_key_share = centralized_party_secret_key_share * generator;
        let decentralized_party_public_key_share = decentralized_party_secret_key_share * generator;

        let public_key = centralized_party_public_key_share + decentralized_party_public_key_share;

        let centralized_party_output = centralized_party::PublicOutput {
            public_key_share: centralized_party_public_key_share.value(),
            public_key: public_key.value(),
            decentralized_party_public_key_share: decentralized_party_public_key_share.value(),
        };

        let decentralized_party_output = decentralized_party::Output {
            encryption_of_secret_key_share: encryption_of_secret_key_share.value(),
            public_key_share: decentralized_party_public_key_share.value(),
            centralized_party_public_key_share: centralized_party_public_key_share.value(),
            public_key: public_key.value(),
        };

        (
            centralized_party_output,
            SecretKeyShare(centralized_party_secret_key_share.value()),
            decentralized_party_output,
        )
    }
}

#[cfg(all(test, feature = "benchmarking"))]
mod benches {
    use group::OsCsRng;
    use mpc::WeightedThresholdAccessStructure;

    #[test]
    #[ignore]
    #[allow(clippy::single_element_loop)]
    fn benchmark() {
        println!(
            "\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Centralized Party Total Time (ms), Decentralized Party Total Time (ms), Decentralized Party Encryption of Secret Key Share Time (ms), Decentralized Party Proof Verification Round Time (ms)",
        );

        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            super::tests::generates_distributed_key_async_class_groups_secp256k1_internal(
                access_structure.threshold,
                access_structure.party_to_weight,
            );
        }
    }
}
