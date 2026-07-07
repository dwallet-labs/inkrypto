// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{ConcatMixed, Encoding, NonZero, Uint};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;

use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement, PrimeGroupElement, Scale, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use mpc::{two_party, AsynchronouslyAdvanceable};
use proof::TranscriptProtocol;

use crate::languages::KnowledgeOfDiscreteLogUCProof;

pub mod centralized_party;
pub(crate) mod class_groups;
pub mod decentralized_party;
pub mod encryption_of_secret_key_share;

/// An instantiation of the 2PC-MPC DKG protocol.
pub trait Protocol {
    /// The DKG protocol's public parameters.
    type ProtocolPublicParameters: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The DKG protocol's protocol context.
    type ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync;

    /// An encryption key.
    type EncryptionKeyValue: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq;

    /// A decryption key.
    type DecryptionKey: Serialize + for<'a> Deserialize<'a> + Clone + Debug + PartialEq + Eq;

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
    /// Contains only public information.
    type CentralizedPartyDKGOutput: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + From<Self::CentralizedPartyTargetedDKGOutput>
        + From<Self::DecentralizedPartyDKGOutput>
        + Eq;

    /// The output of the centralized party's DKG protocol for targeted protocols.
    /// Contains only public information.
    type CentralizedPartyTargetedDKGOutput: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + From<Self::DecentralizedPartyTargetedDKGOutput>
        + Eq;

    /// The output of the decentralized party's DKG protocol.
    /// Contains only public information.
    type DecentralizedPartyDKGOutput: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + PartialEq<Self::CentralizedPartyDKGOutput>
        + From<Self::DecentralizedPartyTargetedDKGOutput>
        + Eq;

    /// The output of the decentralized party's DKG protocol for targeted protocols.
    /// Contains only public information.
    type DecentralizedPartyTargetedDKGOutput: Serialize
        + for<'a> Deserialize<'a>
        + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The public input of the decentralized party's DKG protocol.
    type DKGDecentralizedPartyPublicInput: From<(
            Arc<Self::ProtocolPublicParameters>,
            Self::PublicKeyShareAndProof,
            crate::dkg::CentralizedPartyKeyShareVerification<
                Self::CentralizedPartySecretKeyShare,
                Self::EncryptionKeyValue,
                Self::EncryptedSecretKeyShareMessage,
            >,
        )> + Clone
        + Debug
        + PartialEq
        + Eq;

    /// The decentralized party's DKG protocol.
    type DKGDecentralizedParty: mpc::Party<
            Message = (),
            PublicOutput = Self::DecentralizedPartyDKGOutput,
            PublicOutputValue = Self::DecentralizedPartyDKGOutput,
            PublicInput = Self::DKGDecentralizedPartyPublicInput,
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
        IncomingMessage = (),
        OutgoingMessage = Self::PublicKeyShareAndProof,
        PrivateInput = (),
        PublicInput = Self::DKGCentralizedPartyPublicInput,
        PublicOutput = Self::CentralizedPartyDKGOutput,
        PublicOutputValue = Self::CentralizedPartyDKGOutput,
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
    /// This function is called by the centralized party to generate the decryption key
    /// which will be used later to decrypt the secret key share in [`Self::verify_and_decrypt_encryption_of_centralized_party_share_proof()`].
    ///
    /// *WARNING*: KEEP OUTPUT PRIVATE.
    fn generate_decryption_key(rng: &mut impl CsRng) -> crate::Result<Self::DecryptionKey>;

    /// A helper function for the "encrypted user-share" feature,
    /// in which the centralized party encrypts its secret key share under its own key,
    /// and lets an external entity verify & store it as backup.
    ///
    /// This function is called by the centralized party to after generating the decryption key
    /// in [`Self::generate_decryption_key()`] in order to get the corresponding *public* encryption key.
    fn encryption_key_from_decryption_key(
        decryption_key: Self::DecryptionKey,
    ) -> crate::Result<Self::EncryptionKeyValue>;

    /// A helper function for the "encrypted user-share" feature,
    /// in which the centralized party encrypts its secret key share under its own key,
    /// and lets an external entity verify & store it as backup.
    ///
    /// This function is called by the centralized party to
    /// encrypt & prove its share, and returns the encryption and the proof.
    fn encrypt_and_prove_centralized_party_share(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        encryption_key_value: Self::EncryptionKeyValue,
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
        encryption_key_value: Self::EncryptionKeyValue,
        encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage,
        rng: &mut impl CsRng,
    ) -> crate::Result<()>;

    /// A helper function for the "encrypted user-share" feature,
    /// in which the centralized party encrypts its secret key share under its own key,
    /// and lets an external entity verify & store it as backup.
    ///
    /// This function is called by the centralized party to verify
    /// and decrypt the encryption of the centralized party secret key share if it is valid.
    ///
    /// *WARNING*: KEEP OUTPUT PRIVATE.
    fn verify_and_decrypt_encryption_of_centralized_party_share_proof(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        dkg_output: Self::DecentralizedPartyDKGOutput,
        encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage,
        decryption_key: Self::DecryptionKey,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self::CentralizedPartySecretKeyShare>;

    /// A helper function for the "public user-share" feature, in which the centralized party (a.k.a. the "user") publishes its secret key share so that anyone can emulate it.
    /// This function verifies that value is the right one, by comparing it to the output of the DKG.
    fn verify_centralized_party_public_key_share(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        dkg_output: Self::DecentralizedPartyDKGOutput,
        centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare,
    ) -> crate::Result<()>;

    /// Compute the decentralized party DKG output for threshold mode (no centralized party).
    ///
    /// Uses neutral for the centralized party's public key share and default proof bytes
    /// in the Fiat-Shamir transcript, derives the randomized decentralized party public key
    /// share and encryption of secret key share, and returns the DKG output with
    /// `$\textsf{pk} = X_B$` (the decentralized party's key share is the full public key).
    fn threshold_dkg_output(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        session_id: CommitmentSizedNumber,
    ) -> crate::Result<Self::DecentralizedPartyDKGOutput>;

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
        PublicOutput = Self::CentralizedPartyDKGOutput,
        PublicOutputValue = Self::CentralizedPartyDKGOutput,
        PrivateOutput = Self::CentralizedPartySecretKeyShare,
    >;

    /// The public input of the  decentralized party in a trusted dealer setting.
    /// Used for the "import" feature.
    type TrustedDealerDKGDecentralizedPublicInput: From<(
            Arc<Self::ProtocolPublicParameters>,
            CommitmentSizedNumber,
            Self::DealTrustedShareMessage,
            crate::dkg::CentralizedPartyKeyShareVerification<
                Self::CentralizedPartySecretKeyShare,
                Self::EncryptionKeyValue,
                Self::EncryptedSecretKeyShareMessage,
            >,
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

/// Defines the verification method to be performed (if any)
/// on the centralized party's (a.k.a. the "user") key share
/// by the decentralized party (a.k.a. the "network".)
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub enum CentralizedPartyKeyShareVerification<
    CentralizedPartySecretKeyShare,
    EncryptionKeyValue,
    EncryptedSecretKeyShareMessage,
> {
    /// Used in the "encrypted user-share" feature,
    /// in which the centralized party (a.k.a. the "user") encrypts its secret key share under its own key,
    /// which is verified & stores it as a backup by the decentralized party (a.k.a. the "network".)
    Encrypted {
        encryption_key_value: EncryptionKeyValue,
        encrypted_secret_key_share_message: EncryptedSecretKeyShareMessage,
    },
    /// Used in the "public user-share" feature, in which the centralized party (a.k.a. the "user")
    /// publishes its secret key share so that anyone can emulate it.
    Public {
        centralized_party_secret_key_share: CentralizedPartySecretKeyShare,
    },
    /// No verification: the centralized party (a.k.a. the "user") is
    /// in sole-responsibility for the self-custody of its share.
    None,
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
fn derive_randomized_decentralized_party_public_key_share_and_encryption_of_secret_key_share<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    session_id: CommitmentSizedNumber,
    encryption_of_decentralized_party_secret_key_share_first_part: group::Value<
        EncryptionKey::CiphertextSpaceGroupElement,
    >,
    encryption_of_decentralized_party_secret_key_share_second_part: group::Value<
        EncryptionKey::CiphertextSpaceGroupElement,
    >,
    decentralized_party_public_key_share_first_part: GroupElement::Value,
    decentralized_party_public_key_share_second_part: GroupElement::Value,
    centralized_party_public_key_share: &GroupElement::Value, // $X_{A}$
    knowledge_of_discrete_log_uc_proof: &KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>, // $\pi_{\sf{DL}}$
    group_public_parameters: &GroupElement::PublicParameters,
    encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
) -> crate::Result<(
    Uint<SCALAR_LIMBS>,
    Uint<SCALAR_LIMBS>,
    Uint<SCALAR_LIMBS>,
    EncryptionKey::CiphertextSpaceGroupElement,
    GroupElement,
)>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    EncryptionKey::CiphertextSpaceGroupElement: Scale<Uint<SCALAR_LIMBS>>,
{
    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    // $\textsf{ct}_{\textsf{key}}^{0}$
    let encryption_of_decentralized_party_secret_key_share_first_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            encryption_of_decentralized_party_secret_key_share_first_part,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    // $X_B^{0}$
    let decentralized_party_public_key_share_first_part = GroupElement::new(
        decentralized_party_public_key_share_first_part,
        group_public_parameters,
    )?;

    // $\textsf{ct}_{\textsf{key}}^{1}$
    let encryption_of_decentralized_party_secret_key_share_second_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            encryption_of_decentralized_party_secret_key_share_second_part,
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

    transcript.append_uint::<{ CommitmentSizedNumber::LIMBS }>(b"$ sid $", &session_id);
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

    let ciphertext_space_public_parameters =
        encryption_scheme_public_parameters.ciphertext_space_public_parameters();

    //  Compute $\textsf{ct}_{\textsf{key}}=(\mu_{x}^{0}\odot \textsf{ct}_{\textsf{key}}^{0})\oplus (\mu_{x}^{1}\odot \textsf{ct}_{\textsf{key}}^{1})\oplus \mu_{x}^{G}$
    let decentralized_party_encryption_of_secret_key_share =
        ((encryption_of_decentralized_party_secret_key_share_first_part.scale_vartime_by(
            &first_key_public_randomizer,
            ciphertext_space_public_parameters,
        ))
        .add_vartime(
            &(encryption_of_decentralized_party_secret_key_share_second_part.scale_vartime_by(
                &second_key_public_randomizer,
                ciphertext_space_public_parameters,
            )),
            ciphertext_space_public_parameters,
        ))
        .add_vartime(
            &encryption_of_free_coefficient_key_public_randomizer,
            ciphertext_space_public_parameters,
        );

    //  Compute $X_B=\mu_{x}^{0}\cdot X_B^{0}+\mu_{x}^{1}X_B^{1}+\mu_{x}^{G}\cdot G$
    let decentralized_party_public_key_share = ((decentralized_party_public_key_share_first_part
        .scale_vartime(&first_key_public_randomizer, group_public_parameters))
    .add_vartime(
        &(decentralized_party_public_key_share_second_part
            .scale_vartime(&second_key_public_randomizer, group_public_parameters)),
        group_public_parameters,
    ))
    .add_vartime(
        &(generator.scale_vartime(
            &free_coefficient_key_public_randomizer,
            group_public_parameters,
        )),
        group_public_parameters,
    );

    Ok((
        first_key_public_randomizer,
        second_key_public_randomizer,
        free_coefficient_key_public_randomizer,
        decentralized_party_encryption_of_secret_key_share,
        decentralized_party_public_key_share,
    ))
}

#[cfg(any(test, feature = "benchmarking"))]
#[allow(dead_code)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::dkg::centralized_party::{PublicKeyShareAndProof, SecretKeyShare};
    use crate::languages::KnowledgeOfDiscreteLogUCProof;
    use ::class_groups::{
        Curve25519EncryptionKey, RistrettoEncryptionKey, Secp256k1EncryptionKey,
        Secp256r1EncryptionKey,
    };
    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::{Random, Uint};
    use group::{
        curve25519, ristretto, secp256k1, secp256r1, GroupElement as _, OsCsRng, PartyID,
        PrimeGroupElement, Samplable,
    };
    use homomorphic_encryption::{
        AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors,
    };
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;
    use mpc::two_party::Round;
    use mpc::{Weight, WeightedThresholdAccessStructure};
    use rstest::rstest;

    use crate::test_helpers::{setup_class_groups_curve25519, setup_class_groups_secp256k1};
    use crate::test_helpers::{setup_class_groups_ristretto, setup_class_groups_secp256r1};
    use crate::ProtocolPublicParameters;

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
    #[case(2, HashMap::from([(1, 1), (2, 1)]), false)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), false)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), true)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), true)]
    fn generates_distributed_key_async_class_groups_secp256r1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] emulated: bool,
    ) {
        generates_distributed_key_async_class_groups_secp256r1_internal(
            threshold,
            party_to_weight,
            emulated,
        )
    }

    pub(crate) fn generates_distributed_key_async_class_groups_secp256r1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        emulated: bool,
    ) {
        let (protocol_public_parameters, _) = setup_class_groups_secp256r1();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        generates_distributed_key_internal::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            crate::secp256r1::class_groups::DKGProtocol,
        >(
            session_id,
            access_structure,
            protocol_public_parameters,
            "Class Groups Asynchronous secp256r1".to_string(),
            emulated,
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), false)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), false)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), true)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), true)]
    fn generates_distributed_key_async_class_groups_curve25519(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] emulated: bool,
    ) {
        generates_distributed_key_async_class_groups_curve25519_internal(
            threshold,
            party_to_weight,
            emulated,
        )
    }

    pub(crate) fn generates_distributed_key_async_class_groups_curve25519_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        emulated: bool,
    ) {
        let (protocol_public_parameters, _) = setup_class_groups_curve25519();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        generates_distributed_key_internal::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
            crate::curve25519::class_groups::DKGProtocol,
        >(
            session_id,
            access_structure,
            protocol_public_parameters,
            "Class Groups Asynchronous Curve25519 (EdDSA)".to_string(),
            emulated,
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), false)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), false)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), true)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), true)]
    fn generates_distributed_key_async_class_groups_ristretto(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] emulated: bool,
    ) {
        generates_distributed_key_async_class_groups_ristretto_internal(
            threshold,
            party_to_weight,
            emulated,
        )
    }

    pub(crate) fn generates_distributed_key_async_class_groups_ristretto_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        emulated: bool,
    ) {
        let (protocol_public_parameters, _) = setup_class_groups_ristretto();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        generates_distributed_key_internal::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            crate::ristretto::class_groups::DKGProtocol,
        >(
            session_id,
            access_structure,
            protocol_public_parameters,
            "Class Groups Asynchronous Ristretto (Schnorrkel/sr25519)".to_string(),
            emulated,
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), false)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), false)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), true)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), true)]
    fn generates_distributed_key_async_class_groups_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] emulated: bool,
    ) {
        generates_distributed_key_async_class_groups_secp256k1_internal(
            threshold,
            party_to_weight,
            emulated,
        )
    }

    pub(crate) fn generates_distributed_key_async_class_groups_secp256k1_internal(
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        emulated: bool,
    ) {
        let (protocol_public_parameters, _) = setup_class_groups_secp256k1();

        let (session_id, access_structure) = setup_session(threshold, party_to_weight.clone());

        generates_distributed_key_internal::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::secp256k1::class_groups::DKGProtocol,
        >(
            session_id,
            access_structure,
            protocol_public_parameters,
            "Class Groups Asynchronous secp256k1".to_string(),
            emulated,
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn deals_trusted_shares_async_class_groups_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        deals_trusted_shares_async_class_groups_secp256k1_internal(threshold, party_to_weight)
    }

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
            Secp256k1EncryptionKey,
            crate::class_groups::asynchronous::DKGProtocol<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
        >(session_id, access_structure, protocol_public_parameters);
    }

    pub fn generates_distributed_key_internal<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        P,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: WeightedThresholdAccessStructure,
        protocol_public_parameters: P::ProtocolPublicParameters,
        description: String,
        emulated: bool,
    ) -> (
        P::CentralizedPartyDKGOutput,
        P::CentralizedPartySecretKeyShare,
        P::DecentralizedPartyDKGOutput,
    )
    where
        GroupElement::Scalar: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        P: Protocol<
            CentralizedPartyDKGOutput = centralized_party::VersionedOutput<
                SCALAR_LIMBS,
                group::Value<GroupElement>,
            >,
            CentralizedPartySecretKeyShare = SecretKeyShare<group::Value<GroupElement::Scalar>>,
            DecentralizedPartyDKGOutput = decentralized_party::VersionedOutput<
                SCALAR_LIMBS,
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
        Uint<SCALAR_LIMBS>: Encoding,
    {
        if emulated {
            // Emulated mode: no centralized party participates.
            // Use threshold_dkg_output which sets $x_A = 0$ (neutral public key share).
            let decentralized_party_dkg_output =
                P::threshold_dkg_output(&protocol_public_parameters, session_id).unwrap();
            let centralized_party_dkg_output: P::CentralizedPartyDKGOutput =
                decentralized_party_dkg_output.clone().into();

            let decentralized_party_dkg_output_inner =
                decentralized_party::Output::from(decentralized_party_dkg_output.clone());

            // Verify centralized party public key share is neutral (X_A = 0 and implies x_{A}=0).
            let centralized_party_public_key_share = GroupElement::new(
                decentralized_party_dkg_output_inner
                    .centralized_party_public_key_share
                    .clone(),
                &protocol_public_parameters.as_ref().group_public_parameters,
            )
            .unwrap();
            assert!(
                bool::from(centralized_party_public_key_share.is_neutral()),
                "emulated DKG must have neutral centralized party public key share"
            );

            // Verify public_key = public_key_share (since $X_A = 0$, $X = X_B$).
            assert_eq!(
                decentralized_party_dkg_output_inner.public_key,
                decentralized_party_dkg_output_inner.public_key_share,
            );

            let zero_scalar_value: group::Value<GroupElement::Scalar> =
                Uint::<SCALAR_LIMBS>::ZERO.into();
            let zero_secret_key_share = SecretKeyShare::from(zero_scalar_value);

            println!("{description} DKG (emulated)");

            return (
                centralized_party_dkg_output,
                zero_secret_key_share,
                decentralized_party_dkg_output,
            );
        }

        let measurement = WallTime;

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

        let centralized_party_public_input: P::DKGCentralizedPartyPublicInput =
            (protocol_public_parameters.clone(), session_id).into();

        let now = measurement.start();

        let round_result = P::DKGCentralizedPartyRound::advance(
            (),
            &(),
            &centralized_party_public_input,
            &mut OsCsRng,
        )
        .unwrap();

        let public_key_share_and_proof = round_result.outgoing_message;
        let centralized_party_dkg_output = round_result.public_output;
        let centralized_party_dkg_output_inner =
            centralized_party::Output::from(centralized_party_dkg_output.clone());
        let centralized_party_secret_key_share = round_result.private_output;

        let centralized_party_time = measurement.end(now);

        let decentralized_party_public_key_share = GroupElement::new(
            centralized_party_dkg_output_inner
                .decentralized_party_public_key_share
                .clone(),
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
            centralized_party_dkg_output_inner.public_key_share.clone(),
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        let public_key = GroupElement::new(
            centralized_party_dkg_output_inner.public_key.clone(),
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        assert_eq!(
            decentralized_party_public_key_share.add_vartime(
                &public_key_share,
                &protocol_public_parameters.as_ref().group_public_parameters
            ),
            public_key
        );

        let generator = public_key_share.generator();

        assert_eq!(secret_key_share * generator, public_key_share);

        let user_decryption_key = P::generate_decryption_key(&mut OsCsRng).unwrap();
        let user_encryption_key =
            P::encryption_key_from_decryption_key(user_decryption_key).unwrap();
        let centralized_party_secret_key_share = SecretKeyShare(secret_key_share.value());
        let encryption_of_secret_key_share_and_proof =
            P::encrypt_and_prove_centralized_party_share(
                &protocol_public_parameters,
                user_encryption_key.clone(),
                centralized_party_secret_key_share,
                &mut OsCsRng,
            )
            .unwrap();

        let protocol_public_parameters = Arc::new(protocol_public_parameters);
        let proof_verification_round_public_inputs = parties
            .into_iter()
            .map(|party_id| {
                let centralized_party_secret_key_share_verification_method = match party_id % 3 {
                    0 => CentralizedPartyKeyShareVerification::None,
                    1 => CentralizedPartyKeyShareVerification::Encrypted {
                        encryption_key_value: user_encryption_key.clone(),
                        encrypted_secret_key_share_message:
                            encryption_of_secret_key_share_and_proof.clone(),
                    },
                    2 => CentralizedPartyKeyShareVerification::Public {
                        centralized_party_secret_key_share,
                    },
                    _ => unreachable!(),
                };

                (
                    party_id,
                    (
                        protocol_public_parameters.clone(),
                        public_key_share_and_proof.clone(),
                        centralized_party_secret_key_share_verification_method,
                    )
                        .into(),
                )
            })
            .collect();

        let (decentralized_party_time, _, decentralized_party_dkg_output) =
            asynchronous_session_terminates_successfully_internal::<P::DKGDecentralizedParty>(
                session_id,
                &access_structure,
                private_inputs,
                proof_verification_round_public_inputs,
                1,
                HashMap::new(),
                false,
                false,
            );

        let decentralized_party_dkg_output_inner =
            decentralized_party::Output::from(decentralized_party_dkg_output.clone());

        assert_eq!(
            centralized_party_dkg_output_inner.public_key_share.clone(),
            decentralized_party_dkg_output_inner.centralized_party_public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output_inner
                .decentralized_party_public_key_share
                .clone(),
            decentralized_party_dkg_output_inner.public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output_inner.public_key.clone(),
            decentralized_party_dkg_output_inner.public_key,
        );

        // Test malicious case.
        // INSECURE `unsafe_mock`: the mock decentralized party skips all verification, so
        // malformed centralized shares are (by design) not rejected — the malicious flow is
        // only meaningful for the real protocol.
        #[cfg(not(feature = "unsafe_mock"))]
        {
            let wrong_centralized_party_secret_key_share = SecretKeyShare(
                GroupElement::Scalar::neutral_from_public_parameters(
                    &protocol_public_parameters
                        .as_ref()
                        .as_ref()
                        .scalar_group_public_parameters,
                )
                .unwrap()
                .value(),
            );
            let wrong_encryption_of_secret_key_share_and_proof =
                P::encrypt_and_prove_centralized_party_share(
                    &protocol_public_parameters,
                    user_encryption_key.clone(),
                    wrong_centralized_party_secret_key_share,
                    &mut OsCsRng,
                )
                .unwrap();

            let malicious_encrypted_secret_key_share_public_input: P::DKGDecentralizedPartyPublicInput =
                (
                    protocol_public_parameters.clone(),
                    public_key_share_and_proof.clone(),
                    CentralizedPartyKeyShareVerification::Encrypted {
                        encryption_key_value: user_encryption_key.clone(),
                        encrypted_secret_key_share_message:
                            wrong_encryption_of_secret_key_share_and_proof.clone(),
                    },
                )
                    .into();
            let malicious_encrypted_secret_key_share_result = P::DKGDecentralizedParty::advance(
                session_id,
                1,
                &access_structure,
                vec![],
                None,
                &malicious_encrypted_secret_key_share_public_input,
                &mut OsCsRng,
            );

            assert!(malicious_encrypted_secret_key_share_result.is_err());

            let malicious_public_secret_key_share_public_input: P::DKGDecentralizedPartyPublicInput = (
                protocol_public_parameters.clone(),
                public_key_share_and_proof.clone(),
                CentralizedPartyKeyShareVerification::Public {
                    centralized_party_secret_key_share: wrong_centralized_party_secret_key_share,
                },
            )
                .into();
            let malicious_public_secret_key_share_result = P::DKGDecentralizedParty::advance(
                session_id,
                1,
                &access_structure,
                vec![],
                None,
                &malicious_public_secret_key_share_public_input,
                &mut OsCsRng,
            );

            assert!(malicious_public_secret_key_share_result.is_err());
        }

        let number_of_tangible_parties = access_structure.number_of_tangible_parties();
        let number_of_virtual_parties = access_structure.number_of_virtual_parties();
        let threshold = access_structure.threshold;

        println!(
            "{description} DKG, {number_of_tangible_parties}, {number_of_virtual_parties}, {threshold}, {:?}, {:?}",
            centralized_party_time.as_millis(),
            decentralized_party_time.as_millis(),
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
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        P,
    >(
        session_id: CommitmentSizedNumber,
        access_structure: WeightedThresholdAccessStructure,
        protocol_public_parameters: P::ProtocolPublicParameters,
    ) -> (
        P::CentralizedPartyDKGOutput,
        P::CentralizedPartySecretKeyShare,
        P::DecentralizedPartyDKGOutput,
    )
    where
        GroupElement::Scalar: From<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        P: Protocol<
            CentralizedPartyDKGOutput = centralized_party::VersionedOutput<
                SCALAR_LIMBS,
                group::Value<GroupElement>,
            >,
            CentralizedPartySecretKeyShare = SecretKeyShare<group::Value<GroupElement::Scalar>>,
            DecentralizedPartyDKGOutput = decentralized_party::VersionedOutput<
                SCALAR_LIMBS,
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
        Uint<SCALAR_LIMBS>: Encoding,
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

        let centralized_party_public_input: P::DKGCentralizedPartyPublicInput =
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
        let centralized_party_dkg_output_inner =
            centralized_party::Output::from(centralized_party_dkg_output.clone());
        let centralized_party_secret_key_share = round_result.private_output;

        let decentralized_party_public_key_share = GroupElement::new(
            centralized_party_dkg_output_inner
                .decentralized_party_public_key_share
                .clone(),
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
            centralized_party_dkg_output_inner.public_key_share.clone(),
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        let public_key = GroupElement::new(
            centralized_party_dkg_output_inner.public_key.clone(),
            &protocol_public_parameters.as_ref().group_public_parameters,
        )
        .unwrap();

        assert_eq!(public_key, expected_public_key);

        assert_eq!(
            decentralized_party_public_key_share.add_vartime(
                &public_key_share,
                &protocol_public_parameters.as_ref().group_public_parameters
            ),
            public_key
        );

        let generator = public_key_share.generator();

        assert_eq!(secret_key_share * generator, public_key_share);

        let protocol_public_parameters = Arc::new(protocol_public_parameters);
        let proof_verification_round_public_inputs = parties
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    (
                        protocol_public_parameters.clone(),
                        session_id,
                        centralized_party_message.clone(),
                        CentralizedPartyKeyShareVerification::None,
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

        let decentralized_party_dkg_output_inner =
            decentralized_party::Output::from(decentralized_party_dkg_output.clone());

        assert_eq!(
            centralized_party_dkg_output_inner.public_key_share.clone(),
            decentralized_party_dkg_output_inner.centralized_party_public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output_inner
                .decentralized_party_public_key_share
                .clone(),
            decentralized_party_dkg_output_inner.public_key_share,
        );

        assert_eq!(
            centralized_party_dkg_output_inner.public_key.clone(),
            decentralized_party_dkg_output_inner.public_key,
        );

        (
            centralized_party_dkg_output,
            centralized_party_secret_key_share,
            decentralized_party_dkg_output,
        )
    }

    pub(crate) fn mock_targeted_dkg_output<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            group::PublicParameters<GroupElement>,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    ) -> (
        centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElement::Value>,
        SecretKeyShare<group::Value<GroupElement::Scalar>>,
        decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
    )
    where
        Uint<SCALAR_LIMBS>: Encoding,
    {
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

        let public_key = centralized_party_public_key_share.add_vartime(
            &decentralized_party_public_key_share,
            &protocol_public_parameters.group_public_parameters,
        );

        let centralized_party_output = centralized_party::Output {
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
            centralized_party_output.into(),
            SecretKeyShare(centralized_party_secret_key_share.value()),
            decentralized_party_output.into(),
        )
    }

    /// Verify that `threshold_dkg_output` is deterministic: the same seeded RNG and
    /// session ID always produce the same public key.
    #[test]
    fn threshold_dkg_output_is_deterministic() {
        use commitment::CommitmentSizedNumber;
        use group::secp256k1;
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        type Secp256k1EncryptionKey = ::class_groups::Secp256k1EncryptionKey;

        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let (protocol_public_parameters, _) =
            crate::test_helpers::setup_class_groups_secp256k1_with_rng(&mut rng);

        let session_id = CommitmentSizedNumber::from(42u64);

        let dkg_output = decentralized_party::Party::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            crate::class_groups::ProtocolPublicParameters<
                { secp256k1::SCALAR_LIMBS },
                { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                secp256k1::GroupElement,
            >,
            (),
        >::threshold_dkg_output(&protocol_public_parameters, session_id)
        .unwrap();

        let output: decentralized_party::Output<_, _> = dkg_output.into();

        // Hardcoded expected public key (captured from seed=0, session_id=42).
        // If this changes, it means threshold_dkg_output behavior changed.
        let expected_public_key: group::Value<secp256k1::GroupElement> = serde_json::from_str(
            "\"03765AA6BD79B0F1B8BE255D2F1E711F9039FBB08B7B9B712AF7821F60FC7B6660\"",
        )
        .unwrap();
        assert_eq!(
            output.public_key, expected_public_key,
            "threshold_dkg_output should produce the expected deterministic public key"
        );

        // Run again with the same seed to verify determinism.
        let mut rng_second = ChaCha20Rng::seed_from_u64(0);
        let (protocol_public_parameters_second, _) =
            crate::test_helpers::setup_class_groups_secp256k1_with_rng(&mut rng_second);

        let dkg_output_second =
            decentralized_party::Party::<
                { secp256k1::SCALAR_LIMBS },
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                Secp256k1EncryptionKey,
                crate::class_groups::ProtocolPublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::GroupElement,
                >,
                (),
            >::threshold_dkg_output(&protocol_public_parameters_second, session_id)
            .unwrap();

        let output_second: decentralized_party::Output<_, _> = dkg_output_second.into();

        assert_eq!(
            output.public_key, output_second.public_key,
            "threshold_dkg_output should be deterministic for the same seed and session_id"
        );
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
            "\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Centralized Party Total Time (ms), Decentralized Party Total Time (ms)",
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
                access_structure.party_to_weight.clone(),
                false,
            );

            super::tests::generates_distributed_key_async_class_groups_secp256r1_internal(
                access_structure.threshold,
                access_structure.party_to_weight.clone(),
                false,
            );

            super::tests::generates_distributed_key_async_class_groups_curve25519_internal(
                access_structure.threshold,
                access_structure.party_to_weight.clone(),
                false,
            );

            super::tests::generates_distributed_key_async_class_groups_ristretto_internal(
                access_structure.threshold,
                access_structure.party_to_weight.clone(),
                false,
            );
        }
    }
}
