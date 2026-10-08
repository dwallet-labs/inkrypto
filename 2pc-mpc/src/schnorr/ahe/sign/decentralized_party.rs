// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crate::schnorr::ahe::sign::VerifiedSignData;
use crate::schnorr::ahe::Presign;
use crate::schnorr::sign::decentralized_party::{
    derive_normalized_public_key_and_nonce, emulated_partial_signature,
    verify_centralized_party_partial_signature, NormalizedPublicKeyAndNonce,
};
use crate::schnorr::PartialSignature;
use crate::schnorr::VerifyingKey;
use crate::sign::SignData;
use crate::{dkg, Error};
use ::class_groups::SecretKeyShareSizedInteger;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::helpers::{DeduplicateAndSort, TryCollectHashMap};
use group::{
    CsRng, GroupElement, HashContext, HashScheme, PartyID, StatisticalSecuritySizedNumber,
};
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
use std::sync::Arc;

pub(crate) mod class_groups;
pub mod signature_partial_decryption_round;
pub mod signature_threshold_decryption_round;

pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<
    DKGOutput,
    Presign,
    PartialSignature,
    VerifiedSignData,
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub hash_context: HashContext,
    pub dkg_output: DKGOutput,
    /// Required unless `centralized_party_partial_signature` is `SignData::Verified`, in which
    /// case the verified data already holds everything the presign would have contributed and the
    /// presign may be omitted. When present, it is still checked against the protocol public
    /// parameters.
    pub presign: Option<Presign>,
    pub centralized_party_partial_signature: SignData<PartialSignature, VerifiedSignData>,
    pub decryption_key_share_public_parameters: Arc<DecryptionKeySharePublicParameters>,
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
}

/// The public input of the decentralized party's DKG followed by a Sign protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DKGSignPublicInput<
    DKGPublicInput,
    Presign,
    PartialSignature,
    VerifiedSignData,
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub hash_context: HashContext,
    pub dkg_public_input: DKGPublicInput,
    /// See [`PublicInput::presign`].
    pub presign: Option<Presign>,
    pub centralized_party_partial_signature: SignData<PartialSignature, VerifiedSignData>,
    pub decryption_key_share_public_parameters: Arc<DecryptionKeySharePublicParameters>,
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum Message<DecryptionShare, PartialDecryptionProof> {
    DecryptionShares(HashMap<PartyID, DecryptionShare>),
    DecryptionSharesAndProof(HashMap<PartyID, (DecryptionShare, PartialDecryptionProof)>),
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
        VerifiedSignData<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
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
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
            VerifiedSignData<
                GroupElement::Value,
                group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            >,
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
        let protocol_public_parameters = (*public_input.protocol_public_parameters).as_ref();
        // A present presign must match the protocol public parameters. A missing presign is
        // only acceptable for verified sign data; the round functions require it for the other
        // variants.
        if &public_input.dkg_output != protocol_public_parameters
            || public_input
                .presign
                .as_ref()
                .is_some_and(|presign| presign != protocol_public_parameters)
        {
            return Err(crate::Error::from_kind(crate::ErrorKind::InvalidParameters));
        }

        let virtual_party_id_to_decryption_key_share = virtual_party_id_to_decryption_key_share
            .ok_or_else(|| crate::Error::from_kind(crate::ErrorKind::InvalidParameters))?;

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
                &public_input.hash_context,
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
                            _ => Err(crate::Error::from_kind(crate::ErrorKind::InvalidParameters)),
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
                    &public_input.hash_context,
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
                        &public_input.hash_context,
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
                            _ => Err(crate::Error::from_kind(crate::ErrorKind::InvalidParameters)),
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
                                _ => Err(crate::Error::from_kind(
                                    crate::ErrorKind::InvalidParameters,
                                )),
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
                    &public_input.hash_context,
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
            _ => Err(crate::Error::from_kind(crate::ErrorKind::InvalidParameters)),
        }
    }

    /// Deserializes verified sign data into the three values the decryption rounds need: the
    /// normalized public nonce $K$, the normalized public key $X$ and the encryption of the
    /// signature response $\textsf{ct}_B$.
    ///
    /// The values were computed by
    /// [`crate::sign::Protocol::verify_centralized_party_partial_signature`] from the full
    /// partial signature, the DKG output and the presign, after verifying the partial signature.
    /// Deserializing validates them as group and ciphertext elements; no presign is needed.
    fn unpack_verified_sign_data(
        verified_sign_data: VerifiedSignData<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
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
        GroupElement,
        GroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
    )> {
        // $K$
        let public_nonce = GroupElement::new(
            verified_sign_data.public_nonce,
            &protocol_public_parameters.group_public_parameters,
        )?;
        // $X$
        let public_key = GroupElement::new(
            verified_sign_data.public_key,
            &protocol_public_parameters.group_public_parameters,
        )?;
        // $\textsf{ct}_B$
        let encryption_of_signature_response = EncryptionKey::CiphertextSpaceGroupElement::new(
            verified_sign_data.encryption_of_signature_response,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )?;

        Ok((public_nonce, public_key, encryption_of_signature_response))
    }

    /// Resolves the sign data into the normalized public nonce $K$, the normalized public key $X$
    /// and the encryption of the signature response $\textsf{ct}_B$, without performing any
    /// verification.
    ///
    /// - `Verified`: unpacks the stored values (see [`Self::unpack_verified_sign_data`]). The
    ///   presign is not read.
    /// - `Unverified`: uses the partial signature as-is (the caller is responsible for having
    ///   verified it in a previous round).
    /// - `ToBeEmulated`: uses the partial signature a non-existent centralized party would have
    ///   sent (see [`emulated_partial_signature`]).
    ///
    /// For the last two it derives $K$ and $X$ (step 1b) and evaluates $\textsf{ct}_B$ (step 2f)
    /// from the presign, which is then required: a missing presign is an `InvalidParameters`
    /// error. Use it only in rounds that combine decryption shares, not in rounds that apply a
    /// decryption key share.
    pub(super) fn resolve_sign_data(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        hash_context: &HashContext,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: Option<
            Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
        >,
        sign_data: SignData<
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
            VerifiedSignData<
                GroupElement::Value,
                group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            >,
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
        GroupElement,
        GroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
    )> {
        let centralized_party_partial_signature = match sign_data {
            SignData::Verified(verified_sign_data) => {
                return Self::unpack_verified_sign_data(
                    verified_sign_data,
                    protocol_public_parameters,
                );
            }
            SignData::Unverified(centralized_party_partial_signature) => {
                centralized_party_partial_signature
            }
            SignData::ToBeEmulated => emulated_partial_signature::<SCALAR_LIMBS, GroupElement>(
                &dkg_output.centralized_party_public_key_share,
                &protocol_public_parameters.group_public_parameters,
                &protocol_public_parameters.scalar_group_public_parameters,
            )?,
        };
        let presign =
            presign.ok_or_else(|| crate::Error::from_kind(crate::ErrorKind::InvalidParameters))?;

        let normalized_public_key_and_nonce =
            derive_normalized_public_key_and_nonce::<SCALAR_LIMBS, GroupElement>(
                presign.session_id,
                message,
                hash_scheme,
                presign
                    .decentralized_party_nonce_public_share_first_part
                    .clone(),
                presign
                    .decentralized_party_nonce_public_share_second_part
                    .clone(),
                &dkg_output.centralized_party_public_key_share,
                &centralized_party_partial_signature.public_nonce_share_prenormalization,
                &dkg_output.public_key,
                &protocol_public_parameters.group_public_parameters,
            )?;

        Self::evaluate_encryption_of_signature_response_from_presign(
            message,
            hash_scheme,
            hash_context,
            dkg_output,
            presign,
            centralized_party_partial_signature,
            normalized_public_key_and_nonce,
            protocol_public_parameters,
        )
    }

    /// Resolves the sign data like [`Self::resolve_sign_data`], **verifying the centralized
    /// party's partial signature for the `Unverified` variant** (step 2b).
    ///
    /// This function MUST be used instead of [`Self::resolve_sign_data`] in every round that
    /// applies a decryption key share, so that a key share is never applied to a ciphertext built
    /// from an unchecked partial signature.
    ///
    /// - `Unverified`: requires the presign. Derives $K$ and $X$, verifies $z_A$ against them,
    ///   and evaluates $\textsf{ct}_B$.
    /// - `Verified` and `ToBeEmulated`: same as [`Self::resolve_sign_data`]. Verified data was
    ///   checked when it was produced, and the emulated partial signature needs no check.
    pub(super) fn emulate_or_verify_or_unpack_sign_data(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        hash_context: &HashContext,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: Option<
            Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
        >,
        sign_data: SignData<
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
            VerifiedSignData<
                GroupElement::Value,
                group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
            >,
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
        GroupElement,
        GroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
    )> {
        match sign_data {
            SignData::Unverified(centralized_party_partial_signature) => {
                let presign = presign
                    .ok_or_else(|| crate::Error::from_kind(crate::ErrorKind::InvalidParameters))?;
                let normalized_public_key_and_nonce =
                    derive_normalized_public_key_and_nonce::<SCALAR_LIMBS, GroupElement>(
                        presign.session_id,
                        message,
                        hash_scheme,
                        presign
                            .decentralized_party_nonce_public_share_first_part
                            .clone(),
                        presign
                            .decentralized_party_nonce_public_share_second_part
                            .clone(),
                        &dkg_output.centralized_party_public_key_share,
                        &centralized_party_partial_signature.public_nonce_share_prenormalization,
                        &dkg_output.public_key,
                        &protocol_public_parameters.group_public_parameters,
                    )?;

                verify_centralized_party_partial_signature::<SCALAR_LIMBS, GroupElement>(
                    &normalized_public_key_and_nonce,
                    centralized_party_partial_signature.clone(),
                    message,
                    hash_scheme,
                    hash_context,
                    &protocol_public_parameters.group_public_parameters,
                    &protocol_public_parameters.scalar_group_public_parameters,
                )?;

                Self::evaluate_encryption_of_signature_response_from_presign(
                    message,
                    hash_scheme,
                    hash_context,
                    dkg_output,
                    presign,
                    centralized_party_partial_signature,
                    normalized_public_key_and_nonce,
                    protocol_public_parameters,
                )
            }
            sign_data => Self::resolve_sign_data(
                message,
                hash_scheme,
                hash_context,
                dkg_output,
                presign,
                sign_data,
                protocol_public_parameters,
            ),
        }
    }

    /// Evaluates the encryption of the signature response $\textsf{ct}_B$ (step 2f) from the
    /// presign's encrypted nonce shares and the DKG output's encrypted key share.
    ///
    /// Computes $\textsf{ct}_k = \textsf{ct}_{k_0} \oplus \mu_k \odot \textsf{ct}_{k_1}$ and
    /// $\textsf{ct}_{\textsf{key}}$, negating each wherever $K$ or $X$ was negated, then
    /// $\textsf{ct}_B = \textsf{ct}_k \oplus (e \odot \textsf{ct}_{\textsf{key}}) \oplus z_A$.
    ///
    /// Returns $K$, $X$ and $\textsf{ct}_B$. Checks nothing.
    fn evaluate_encryption_of_signature_response_from_presign(
        // $m$
        message: &[u8],
        hash_scheme: HashScheme,
        hash_context: &HashContext,
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
        normalized_public_key_and_nonce: NormalizedPublicKeyAndNonce<SCALAR_LIMBS, GroupElement>,
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
        GroupElement,
        GroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
    )> {
        let ciphertext_space_public_parameters = protocol_public_parameters
            .encryption_scheme_public_parameters
            .ciphertext_space_public_parameters();

        // $ z_{A} $
        let centralized_party_partial_response = GroupElement::Scalar::new(
            centralized_party_partial_signature.partial_response,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        // $\textsf{ct}_{k_{0}}$
        let encryption_of_decentralized_party_nonce_share_first_part =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                presign.encryption_of_decentralized_party_nonce_share_first_part,
                ciphertext_space_public_parameters,
            )?;

        // $\textsf{ct}_{k_{1}}$
        let encryption_of_decentralized_party_nonce_share_second_part =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                presign.encryption_of_decentralized_party_nonce_share_second_part,
                ciphertext_space_public_parameters,
            )?;

        // $ \textsf{ct}_{k} $
        let encryption_of_nonce_share = encryption_of_decentralized_party_nonce_share_first_part
            .add_vartime(
                &encryption_of_decentralized_party_nonce_share_second_part.scale_vartime(
                    &normalized_public_key_and_nonce.presign_public_randomizer,
                    ciphertext_space_public_parameters,
                ),
                ciphertext_space_public_parameters,
            );

        // $\textsf{ct}_{\textsf{key}}$
        let encryption_of_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            dkg_output.encryption_of_secret_key_share,
            ciphertext_space_public_parameters,
        )?;

        // If a group element is not Taproot-normalized, its negation will be.
        // Continue signing using the negated public_key (now Taproot-normalized) and the corresponding negated secret share encryption.
        let encryption_of_secret_key_share = if normalized_public_key_and_nonce.key_normalized {
            encryption_of_secret_key_share.neg_constant_time(ciphertext_space_public_parameters)
        } else {
            encryption_of_secret_key_share
        };

        let encryption_of_nonce_share = if normalized_public_key_and_nonce.nonce_normalized {
            encryption_of_nonce_share.neg_constant_time(ciphertext_space_public_parameters)
        } else {
            encryption_of_nonce_share
        };

        let encryption_of_signature_response = Self::evaluate_encryption_of_signature_response(
            message,
            hash_scheme,
            hash_context,
            normalized_public_key_and_nonce.public_nonce,
            normalized_public_key_and_nonce.public_key,
            centralized_party_partial_response,
            encryption_of_nonce_share,
            encryption_of_secret_key_share,
            protocol_public_parameters,
        )?;

        Ok((
            normalized_public_key_and_nonce.public_nonce,
            normalized_public_key_and_nonce.public_key,
            encryption_of_signature_response,
        ))
    }
}

#[cfg(test)]
mod tests {
    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, GroupElement as _, HashContext, HashScheme};

    use crate::schnorr::ahe::sign::VerifiedSignData;
    use crate::sign::SignData;

    type Secp256k1Party = super::Party<
        { secp256k1::SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        secp256k1::GroupElement,
        ::class_groups::Secp256k1EncryptionKey,
        ::class_groups::Secp256k1DecryptionKeyShare,
        crate::class_groups::ProtocolPublicParameters<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
        >,
    >;

    /// Verified sign data must stand in for the presign exactly, and only it may omit it.
    ///
    /// Emulated sign data is resolved from the presign by both resolvers, which must agree, and
    /// is rejected without the presign. Its result, passed in as verified sign data with no
    /// presign, must resolve to the same public nonce, public key and encrypted response.
    #[test]
    fn verified_sign_data_resolves_to_the_values_computed_from_the_presign() {
        let (protocol_public_parameters, _raw_decryption_key) =
            crate::test_helpers::setup_class_groups_secp256k1();

        let session_id = CommitmentSizedNumber::from(42u64);

        let decentralized_dkg_output =
            crate::dkg::decentralized_party::Party::<
                { secp256k1::SCALAR_LIMBS },
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                ::class_groups::Secp256k1EncryptionKey,
                crate::class_groups::ProtocolPublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::GroupElement,
                >,
                (),
            >::threshold_dkg_output(&protocol_public_parameters, session_id)
            .unwrap();

        let presign = crate::presign::tests::mock_schnorr_presign::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            ::class_groups::Secp256k1EncryptionKey,
        >(session_id, &protocol_public_parameters);

        let message = b"sign me without a presign";

        let to_verified_sign_data =
            |(public_nonce, public_key, encryption_of_signature_response): (
                secp256k1::GroupElement,
                secp256k1::GroupElement,
                ::class_groups::CiphertextSpaceGroupElement<
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                >,
            )| VerifiedSignData {
                public_nonce: public_nonce.value(),
                public_key: public_key.value(),
                encryption_of_signature_response: encryption_of_signature_response.value(),
            };

        let resolved = Secp256k1Party::resolve_sign_data(
            message,
            HashScheme::SHA256,
            &HashContext::None,
            decentralized_dkg_output.clone().into(),
            Some(presign.clone()),
            SignData::ToBeEmulated,
            protocol_public_parameters.as_ref(),
        )
        .map(to_verified_sign_data)
        .expect("emulated sign data must resolve from the presign");

        let resolved_by_verifying_resolver = Secp256k1Party::emulate_or_verify_or_unpack_sign_data(
            message,
            HashScheme::SHA256,
            &HashContext::None,
            decentralized_dkg_output.clone().into(),
            Some(presign),
            SignData::ToBeEmulated,
            protocol_public_parameters.as_ref(),
        )
        .map(to_verified_sign_data)
        .expect("emulated sign data must resolve from the presign");

        assert_eq!(resolved_by_verifying_resolver, resolved);

        assert!(
            Secp256k1Party::resolve_sign_data(
                message,
                HashScheme::SHA256,
                &HashContext::None,
                decentralized_dkg_output.clone().into(),
                None,
                SignData::ToBeEmulated,
                protocol_public_parameters.as_ref(),
            )
            .is_err(),
            "emulated sign data must be rejected without the presign"
        );

        let unpacked = Secp256k1Party::resolve_sign_data(
            message,
            HashScheme::SHA256,
            &HashContext::None,
            decentralized_dkg_output.into(),
            None,
            SignData::Verified(resolved.clone()),
            protocol_public_parameters.as_ref(),
        )
        .map(to_verified_sign_data)
        .expect("verified sign data must resolve without the presign");

        assert_eq!(unpacked, resolved);
    }
}
