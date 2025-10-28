// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crate::schnorr::sign::centralized_party::PartialSignature;
use crate::schnorr::sign::{
    derive_randomized_decentralized_party_public_nonce_share_and_encryption_of_nonce_share,
    verify_partial_schnorr_signature,
};
use crate::schnorr::{Presign, VerifyingKey};
use crate::{dkg, Error};
use ::class_groups::SecretKeyShareSizedInteger;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::helpers::{DeduplicateAndSort, TryCollectHashMap};
use group::{CsRng, GroupElement, HashScheme, PartyID, StatisticalSecuritySizedNumber};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
};
use mpc::{
    AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages,
    WeightedThresholdAccessStructure,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Neg;

pub(crate) mod class_groups;
pub mod signature_partial_decryption_round;
pub mod signature_threshold_decryption_round;

pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    ProtocolPublicParameters,
>(
    PhantomData<GroupElement>,
    PhantomData<EncryptionKey>,
    PhantomData<DecryptionKeyShare>,
    PhantomData<ProtocolPublicParameters>,
);

/// The public input of the decentralized party's Sign protocol.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<
    DKGOutput,
    Presign,
    PartialSignature,
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub centralized_party_partial_signature: PartialSignature,
    pub decryption_key_share_public_parameters: DecryptionKeySharePublicParameters,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

/// The public input of the decentralized party's DKG followed by a Sign protocol.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DKGSignPublicInput<
    DKGPublicInput,
    Presign,
    PartialSignature,
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub dkg_public_input: DKGPublicInput,
    pub presign: Presign,
    pub centralized_party_partial_signature: PartialSignature,
    pub decryption_key_share_public_parameters: DecryptionKeySharePublicParameters,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum Message<DecryptionShare, PartialDecryptionProof> {
    DecryptionShares(HashMap<PartyID, DecryptionShare>),
    DecryptionSharesAndProof(HashMap<PartyID, (DecryptionShare, PartialDecryptionProof)>),
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            SecretKeyShare = SecretKeyShareSizedInteger,
        >,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > mpc::Party
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        DecryptionKeyShare,
        ProtocolPublicParameters,
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
{
    type Error = Error;
    type PublicInput = PublicInput<
        dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
        DecryptionKeyShare::PublicParameters,
        ProtocolPublicParameters,
    >;
    type PrivateOutput = ();
    type PublicOutputValue = GroupElement::Signature;
    type PublicOutput = Self::PublicOutputValue;
    type Message =
        Message<DecryptionKeyShare::DecryptionShare, DecryptionKeyShare::PartialDecryptionProof>;
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            SecretKeyShare = SecretKeyShareSizedInteger,
        >,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > AsynchronouslyAdvanceable
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        DecryptionKeyShare,
        ProtocolPublicParameters,
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
    Error: From<DecryptionKeyShare::Error>,
{
    type PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;

    fn advance(
        _session_id: CommitmentSizedNumber,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        virtual_party_id_to_decryption_key_share: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Self::advance_sign_party(
            tangible_party_id,
            access_structure,
            messages,
            virtual_party_id_to_decryption_key_share,
            public_input,
            rng,
        )
    }

    fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
        match failed_round {
            3 => Some(2),
            _ => None,
        }
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
            SecretKeyShare = SecretKeyShareSizedInteger,
        >,
        ProtocolPublicParameters,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        DecryptionKeyShare,
        ProtocolPublicParameters,
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
    Error: From<DecryptionKeyShare::Error>,
{
    fn advance_sign_party(
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<
            HashMap<
                PartyID,
                Message<
                    DecryptionKeyShare::DecryptionShare,
                    DecryptionKeyShare::PartialDecryptionProof,
                >,
            >,
        >,
        virtual_party_id_to_decryption_key_share: Option<
            HashMap<PartyID, SecretKeyShareSizedInteger>,
        >,
        public_input: &PublicInput<
            dkg::decentralized_party::VersionedOutput<
                SCALAR_LIMBS,
                GroupElement::Value,
                group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            >,
            Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
            DecryptionKeyShare::PublicParameters,
            ProtocolPublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<
            Message<
                DecryptionKeyShare::DecryptionShare,
                DecryptionKeyShare::PartialDecryptionProof,
            >,
            (),
            GroupElement::Signature,
        >,
        Error,
    > {
        if &public_input.dkg_output != public_input.protocol_public_parameters.as_ref()
            || &public_input.presign != public_input.protocol_public_parameters.as_ref()
        {
            return Err(Error::InvalidParameters);
        }

        let virtual_party_id_to_decryption_key_share =
            virtual_party_id_to_decryption_key_share.ok_or(Error::InvalidParameters)?;

        let virtual_party_id_to_decryption_key_share = virtual_party_id_to_decryption_key_share
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                DecryptionKeyShare::new(
                    virtual_party_id,
                    decryption_key_share,
                    &public_input.decryption_key_share_public_parameters,
                    rng,
                )
                .map(|decryption_key_share| (virtual_party_id, decryption_key_share))
            })
            .try_collect_hash_map()?;

        match &messages[..] {
            [] => Self::partially_decrypt_encryption_of_signature_semi_honest(
                public_input.expected_decrypters.clone(),
                &public_input.message,
                public_input.hash_scheme,
                public_input.dkg_output.clone().into(),
                public_input.presign.clone(),
                public_input.centralized_party_partial_signature.clone(),
                &public_input.protocol_public_parameters,
                &public_input.decryption_key_share_public_parameters,
                virtual_party_id_to_decryption_key_share,
                tangible_party_id,
                access_structure,
            )
            .map(|message| AsynchronousRoundResult::Advance {
                malicious_parties: vec![],
                message: Message::DecryptionShares(message),
            }),
            [first_round_messages] => {
                // Make sure everyone sent the first round message for each virtual party in their virtual subset.
                let (malicious_parties, decryption_shares) = first_round_messages
                    .clone()
                    .into_iter()
                    .map(|(tangible_party_id, message)| {
                        let res = match message {
                            Message::DecryptionShares(decryption_shares)
                                if Some(&decryption_shares.keys().copied().collect())
                                    == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) =>
                            {
                                Ok(decryption_shares)
                            }
                            _ => Err(Error::InvalidParameters),
                        };

                        (tangible_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Map to virtual parties
                let decryption_shares = decryption_shares.into_values().flatten().collect();

                if let Ok(signature) = Self::decrypt_signature_semi_honest(
                    public_input.expected_decrypters.clone(),
                    &public_input.message,
                    public_input.hash_scheme,
                    public_input.dkg_output.clone().into(),
                    public_input.presign.clone(),
                    public_input.centralized_party_partial_signature.clone(),
                    &public_input.protocol_public_parameters,
                    &public_input.decryption_key_share_public_parameters,
                    access_structure,
                    decryption_shares,
                ) {
                    // Happy-flow: no party sent wrong decryption shares and we were able to finalize the signature in the semi-honest flow.
                    GroupElement::Signature::try_from(signature).map(|signature| {
                        AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output: (),
                            public_output: signature,
                        }
                    })
                } else {
                    // Sad-flow (infrequent): at least one party maliciously decrypted the message and we were unable to finalize the signature in the semi-honest flow.
                    // Therefore, we must perform an additional round where we verifiably decrypt the signature reconstruct the maliciously generated decryption shares, identifying the malicious parties in retrospect.
                    Self::partially_decrypt_encryption_of_signature(
                        &public_input.message,
                        public_input.hash_scheme,
                        public_input.dkg_output.clone().into(),
                        public_input.presign.clone(),
                        public_input.centralized_party_partial_signature.clone(),
                        &public_input.protocol_public_parameters,
                        &public_input.decryption_key_share_public_parameters,
                        virtual_party_id_to_decryption_key_share,
                        tangible_party_id,
                        access_structure,
                        rng,
                    )
                    .map(|message| AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message: Message::DecryptionSharesAndProof(message),
                    })
                }
            }
            [first_round_messages, second_round_messages] => {
                // Make sure everyone sent the first round message for each virtual party in their virtual subset.
                let (
                    parties_sending_invalid_first_round_messages,
                    invalid_semi_honest_decryption_shares,
                ) = first_round_messages
                    .clone()
                    .into_iter()
                    .map(|(tangible_party_id, message)| {
                        let res = match message {
                            Message::DecryptionShares(decryption_shares)
                                if Some(&decryption_shares.keys().copied().collect())
                                    == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) =>
                            {
                                Ok(decryption_shares)
                            }
                            _ => Err(Error::InvalidParameters),
                        };

                        (tangible_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Next make sure everyone sent the second round message.
                let (parties_sending_invalid_second_round_messages, decryption_shares_and_proofs) =
                    second_round_messages
                        .clone()
                        .into_iter()
                        .map(|(tangible_party_id, message)| {
                            let res = match message {
                                Message::DecryptionSharesAndProof(decryption_shares_and_proofs)
                                    if Some(
                                        &decryption_shares_and_proofs.keys().copied().collect(),
                                    ) == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) =>
                                {
                                    Ok(decryption_shares_and_proofs)
                                }
                                _ => Err(Error::InvalidParameters),
                            };

                            (tangible_party_id, res)
                        })
                        .handle_invalid_messages_async();

                // Map to virtual parties
                let invalid_semi_honest_decryption_shares = invalid_semi_honest_decryption_shares
                    .into_values()
                    .flatten()
                    .collect();
                let decryption_shares_and_proofs = decryption_shares_and_proofs
                    .into_values()
                    .flatten()
                    .collect();

                let (malicious_decrypters, signature) = Self::decrypt_signature(
                    public_input.expected_decrypters.clone(),
                    &public_input.message,
                    public_input.hash_scheme,
                    public_input.dkg_output.clone().into(),
                    public_input.presign.clone(),
                    public_input.centralized_party_partial_signature.clone(),
                    &public_input.protocol_public_parameters,
                    &public_input.decryption_key_share_public_parameters,
                    access_structure,
                    invalid_semi_honest_decryption_shares,
                    decryption_shares_and_proofs,
                    rng,
                )?;

                let malicious_parties = parties_sending_invalid_first_round_messages
                    .into_iter()
                    .chain(parties_sending_invalid_second_round_messages)
                    .chain(malicious_decrypters)
                    .deduplicate_and_sort();

                GroupElement::Signature::try_from(signature).map(|signature| {
                    AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output: (),
                        public_output: signature,
                    }
                })
            }
            _ => Err(Error::InvalidParameters),
        }
    }

    /// This function implements step (2b) of the Sign protocol:
    /// Verifies that $z_{A}$ is a valid response, i.e. $z_{A} \cdot G = K_{A} + e \cdot X_{A}$.
    /// Here, `e` is the challenge derived from the full public key $X$ and public nonce $K$.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428> Protocol C.5
    /// If this returns `Ok()`, the decentralized party can generate a valid signature over
    /// `message` whenever a threshold of honest parties participates in signing.
    pub(super) fn verify_centralized_party_partial_signature_and_taproot_normalize(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        dkg_output: dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        centralized_party_partial_signature: PartialSignature<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
        >,
        protocol_public_parameters: &crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    ) -> crate::Result<(
        GroupElement::Scalar,
        GroupElement,
        GroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
    )> {
        let dkg_output = dkg::decentralized_party::Output::from(dkg_output.clone());

        Self::verify_centralized_party_partial_signature_and_taproot_normalize_internal(
            message,
            hash_scheme,
            dkg_output,
            presign,
            centralized_party_partial_signature,
            protocol_public_parameters,
        )
    }

    /// This function implements step (2b) of the Sign protocol:
    /// Verifies that $z_{A}$ is a valid response, i.e. $z_{A} \cdot G = K_{A} + e \cdot X_{A}$.
    /// Here, `e` is the challenge derived from the full public key $X$ and public nonce $K$.
    /// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428> Protocol C.5
    /// If this returns `Ok()`, the decentralized party can generate a valid signature over
    /// `message` whenever a threshold of honest parties participates in signing.
    pub(super) fn verify_centralized_party_partial_signature_and_taproot_normalize_internal(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        centralized_party_partial_signature: PartialSignature<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
        >,
        protocol_public_parameters: &crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            GroupElement::Value,
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            EncryptionKey::PublicParameters,
        >,
    ) -> crate::Result<(
        GroupElement::Scalar,
        GroupElement,
        GroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
    )> {
        // $ z_{A} $
        let centralized_party_partial_response = GroupElement::Scalar::new(
            centralized_party_partial_signature.partial_response,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        // === 2(b) $K_{B} = K_{B,0}+\mu_{k}K_{B,1}$ where $\mu_{k}\gets \mathcal{H}(\textsf{sid},X,K_{B,0},K_{B,1},K_{A},\textsf{msg})$
        // The hash additionally includes a fixed prefix and the group public parameters (omitted in the paper).
        // Group elements are hashed in their original form, before any negation for Taproot normalization.
        // ($ K_{B}, \textsf{ct}_{k} $)
        let (mut encryption_of_nonce_share, public_nonce_share) =
            derive_randomized_decentralized_party_public_nonce_share_and_encryption_of_nonce_share::<
                SCALAR_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                GroupElement,
                EncryptionKey,
            >(
                presign.session_id,
                message,
                hash_scheme,
                presign,
                &centralized_party_partial_signature.public_nonce_share_prenormalization,
                &protocol_public_parameters.encryption_scheme_public_parameters,
                &protocol_public_parameters.group_public_parameters,
                &dkg_output.public_key,
            )?;

        // $ X_{A} $
        let mut centralized_party_public_key_share = GroupElement::new(
            dkg_output.centralized_party_public_key_share,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // $ X $
        let mut public_key = GroupElement::new(
            dkg_output.public_key,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // $\textsf{ct}_{\textsf{key}}$
        let mut encryption_of_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            dkg_output.encryption_of_secret_key_share,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )?;

        // If a group element is not Taproot-normalized, its negation will be.
        // Continue signing using the negated public_key (now Taproot-normalized) and the corresponding negated secret share encryption.
        if !public_key.is_taproot_normalized() {
            centralized_party_public_key_share = centralized_party_public_key_share.neg();
            public_key = public_key.neg();
            encryption_of_secret_key_share = encryption_of_secret_key_share.neg();
        }

        // $ K_{A} $
        let mut centralized_party_public_nonce_share = GroupElement::new(
            centralized_party_partial_signature.public_nonce_share_prenormalization,
            &protocol_public_parameters.group_public_parameters,
        )?;

        // $ K $
        let mut public_nonce =
            centralized_party_public_nonce_share.add_vartime(&public_nonce_share);

        if !public_nonce.is_taproot_normalized() {
            // We don't normalize `public_nonce_share` has it is unused after this point.
            centralized_party_public_nonce_share = centralized_party_public_nonce_share.neg();
            public_nonce = public_nonce.neg();
            encryption_of_nonce_share = encryption_of_nonce_share.neg();
        }

        verify_partial_schnorr_signature(
            centralized_party_partial_response,
            centralized_party_public_nonce_share,
            public_nonce,
            centralized_party_public_key_share,
            public_key,
            message,
            hash_scheme,
            &protocol_public_parameters.group_public_parameters,
        )?;

        Ok((
            centralized_party_partial_response,
            public_key,
            public_nonce,
            encryption_of_secret_key_share,
            encryption_of_nonce_share,
        ))
    }
}

impl<
        DKGOutput,
        Presign,
        PartialSignature,
        DecryptionKeySharePublicParameters,
        ProtocolPublicParameters,
    >
    From<(
        HashSet<PartyID>,
        ProtocolPublicParameters,
        Vec<u8>,
        HashScheme,
        DKGOutput,
        Presign,
        PartialSignature,
        DecryptionKeySharePublicParameters,
    )>
    for PublicInput<
        DKGOutput,
        Presign,
        PartialSignature,
        DecryptionKeySharePublicParameters,
        ProtocolPublicParameters,
    >
{
    fn from(
        (
            expected_decrypters,
            protocol_public_parameters,
            message,
            hash_scheme,
            dkg_output,
            presign,
            sign_message,
            decryption_key_share_public_parameters,
        ): (
            HashSet<PartyID>,
            ProtocolPublicParameters,
            Vec<u8>,
            HashScheme,
            DKGOutput,
            Presign,
            PartialSignature,
            DecryptionKeySharePublicParameters,
        ),
    ) -> Self {
        Self {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_output,
            presign,
            centralized_party_partial_signature: sign_message,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        }
    }
}

impl<
        DKGPublicInput,
        Presign,
        PartialSignature,
        DecryptionKeySharePublicParameters,
        ProtocolPublicParameters,
    >
    From<(
        HashSet<PartyID>,
        ProtocolPublicParameters,
        Vec<u8>,
        HashScheme,
        DKGPublicInput,
        Presign,
        PartialSignature,
        DecryptionKeySharePublicParameters,
    )>
    for DKGSignPublicInput<
        DKGPublicInput,
        Presign,
        PartialSignature,
        DecryptionKeySharePublicParameters,
        ProtocolPublicParameters,
    >
{
    fn from(
        (
            expected_decrypters,
            protocol_public_parameters,
            message,
            hash_scheme,
            dkg_public_input,
            presign,
            sign_message,
            decryption_key_share_public_parameters,
        ): (
            HashSet<PartyID>,
            ProtocolPublicParameters,
            Vec<u8>,
            HashScheme,
            DKGPublicInput,
            Presign,
            PartialSignature,
            DecryptionKeySharePublicParameters,
        ),
    ) -> Self {
        Self {
            expected_decrypters,
            message,
            hash_scheme,
            dkg_public_input,
            presign,
            centralized_party_partial_signature: sign_message,
            decryption_key_share_public_parameters,
            protocol_public_parameters,
        }
    }
}
