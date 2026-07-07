// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use crate::schnorr::ahe::Presign;
use crate::schnorr::sign::decentralized_party::normalize_and_optionally_verify_centralized_party_partial_signature;
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
    DecryptionKeySharePublicParameters,
    ProtocolPublicParameters,
> {
    pub expected_decrypters: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub hash_context: HashContext,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub centralized_party_partial_signature: SignData<PartialSignature, PartialSignature>,
    pub decryption_key_share_public_parameters: Arc<DecryptionKeySharePublicParameters>,
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
}

/// The public input of the decentralized party's DKG followed by a Sign protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub hash_context: HashContext,
    pub dkg_public_input: DKGPublicInput,
    pub presign: Presign,
    pub centralized_party_partial_signature: SignData<PartialSignature, PartialSignature>,
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
        if &public_input.dkg_output != (*public_input.protocol_public_parameters).as_ref()
            || &public_input.presign != (*public_input.protocol_public_parameters).as_ref()
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

    /// Resolves the `SignData` enum into a concrete `PartialSignature`, constructing a default
    /// (identity/zero) partial signature for the `ToBeEmulated` variant.
    ///
    /// Returns `(partial_signature, should_verify)` where `should_verify` indicates whether
    /// the partial signature needs verification (`true` for `Unverified` and `ToBeEmulated`,
    /// `false` for `Verified`).
    fn resolve_sign_data(
        sign_data: SignData<
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
        >,
        centralized_party_public_key_share: &GroupElement::Value,
        group_public_parameters: &GroupElement::PublicParameters,
        scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    ) -> crate::Result<(
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
        bool,
    )> {
        crate::schnorr::sign::decentralized_party::resolve_sign_data::<SCALAR_LIMBS, GroupElement>(
            sign_data,
            centralized_party_public_key_share,
            group_public_parameters,
            scalar_group_public_parameters,
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
        hash_context: &HashContext,
        dkg_output: dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        presign: Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        sign_data: SignData<
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
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
        let (centralized_party_partial_signature, should_verify) = Self::resolve_sign_data(
            sign_data,
            &dkg_output.centralized_party_public_key_share,
            &protocol_public_parameters.group_public_parameters,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        // $ z_{A} $
        let centralized_party_partial_response = GroupElement::Scalar::new(
            centralized_party_partial_signature.partial_response,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        // $\textsf{ct}_{k_{0}$
        let encryption_of_decentralized_party_nonce_share_first_part =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                presign.encryption_of_decentralized_party_nonce_share_first_part,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        // $\textsf{ct}_{k_{1}$
        let encryption_of_decentralized_party_nonce_share_second_part =
            EncryptionKey::CiphertextSpaceGroupElement::new(
                presign.encryption_of_decentralized_party_nonce_share_second_part,
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .ciphertext_space_public_parameters(),
            )?;

        let verification_result =
            normalize_and_optionally_verify_centralized_party_partial_signature::<
                SCALAR_LIMBS,
                GroupElement,
            >(
                presign.session_id,
                message,
                hash_scheme,
                hash_context,
                presign.decentralized_party_nonce_public_share_first_part,
                presign.decentralized_party_nonce_public_share_second_part,
                &dkg_output.centralized_party_public_key_share,
                centralized_party_partial_signature,
                &dkg_output.public_key,
                &protocol_public_parameters.group_public_parameters,
                &protocol_public_parameters.scalar_group_public_parameters,
                should_verify,
            )?;

        let ciphertext_space_public_parameters = protocol_public_parameters
            .encryption_scheme_public_parameters
            .ciphertext_space_public_parameters();

        // $ \textsf{ct}_{k} $
        let mut encryption_of_nonce_share =
            encryption_of_decentralized_party_nonce_share_first_part.add_vartime(
                &encryption_of_decentralized_party_nonce_share_second_part.scale_vartime(
                    &verification_result.presign_public_randomizer,
                    ciphertext_space_public_parameters,
                ),
                ciphertext_space_public_parameters,
            );

        // $\textsf{ct}_{\textsf{key}}$
        let mut encryption_of_secret_key_share = EncryptionKey::CiphertextSpaceGroupElement::new(
            dkg_output.encryption_of_secret_key_share,
            ciphertext_space_public_parameters,
        )?;

        // If a group element is not Taproot-normalized, its negation will be.
        // Continue signing using the negated public_key (now Taproot-normalized) and the corresponding negated secret share encryption.
        if verification_result.key_normalized {
            encryption_of_secret_key_share = encryption_of_secret_key_share
                .neg_constant_time(ciphertext_space_public_parameters);
        }

        if verification_result.nonce_normalized {
            encryption_of_nonce_share =
                encryption_of_nonce_share.neg_constant_time(ciphertext_space_public_parameters);
        }

        Ok((
            centralized_party_partial_response,
            verification_result.public_key,
            verification_result.public_nonce,
            encryption_of_secret_key_share,
            encryption_of_nonce_share,
        ))
    }
}
