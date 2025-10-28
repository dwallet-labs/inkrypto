// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Encryption of Mask and Masked Key Share (Parts) Round for Class Groups

use crate::class_groups::ecdsa::{
    EncryptionOfMaskAndMaskedKeyShare, EncryptionOfMaskAndMaskedKeyShareParts,
};
use crate::class_groups::DKGDecentralizedPartyOutput;
use crate::ecdsa::presign::decentralized_party::class_groups::asynchronous::{Message, Party};
use crate::ecdsa::presign::decentralized_party::{
    encryption_of_mask_and_masked_key_share_round, PublicInput,
};
use crate::ecdsa::VerifyingKey;
use crate::languages::class_groups::{
    construct_encryption_of_tuple_public_parameters,
    construct_extended_encryption_of_tuple_public_parameters, EncryptionOfTupleProof,
    EncryptionOfTuplePublicParameters, ExtendedEncryptionOfTupleProof,
    ExtendedEncryptionOfTuplePublicParameters,
};
use crate::{Error, ProtocolContext, Result};
use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CiphertextSpaceValue, CompactIbqf, EncryptionKey,
    EquivalenceClass, MultiFoldNupowAccelerator, RandomnessSpaceGroupElement,
    RandomnessSpacePublicParameters,
};
use commitment::CommitmentSizedNumber;
use crypto_bigint::{Encoding, Int, Uint};
use group::helpers::DeduplicateAndSort;
use group::{CsRng, GroupElement, PartyID};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::{HandleInvalidMessages, MajorityVote, WeightedThresholdAccessStructure};
use std::collections::HashMap;

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
    >
    Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >
where
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
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
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
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    Uint<MESSAGE_LIMBS>: Encoding,
{
    pub(crate) fn encryption_of_mask_and_masked_key_share_aggregation_public_input(
        session_id: CommitmentSizedNumber,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        dkg_output: DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    ) -> Result<
        proof::aggregation::asynchronous::PublicInput<
            ProtocolContext,
            EncryptionOfTuplePublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
    > {
        let language_public_parameters = construct_encryption_of_tuple_public_parameters::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >(
            dkg_output.encryption_of_secret_key_share,
            public_input
                .protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            public_input
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
        )?;

        let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
            protocol_context: public_input
                .encryption_of_mask_and_masked_key_share_round_protocol_context_v1(session_id),
            public_parameters: language_public_parameters,
            batch_size: 1,
        };

        Ok(aggregation_public_input)
    }

    pub(crate) fn encryption_of_mask_and_masked_key_share_parts_aggregation_public_input(
        session_id: CommitmentSizedNumber,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
    ) -> Result<
        proof::aggregation::asynchronous::PublicInput<
            ProtocolContext,
            ExtendedEncryptionOfTuplePublicParameters<
                2,
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
    > {
        let language_public_parameters = construct_extended_encryption_of_tuple_public_parameters::<
            2,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >(
            [
                public_input
                    .protocol_public_parameters
                    .encryption_of_decentralized_party_secret_key_share_first_part,
                public_input
                    .protocol_public_parameters
                    .encryption_of_decentralized_party_secret_key_share_second_part,
            ],
            public_input
                .protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            public_input
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
        )?;

        let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
            protocol_context: public_input
                .encryption_of_mask_and_masked_key_share_round_protocol_context_v1(session_id),
            public_parameters: language_public_parameters,
            batch_size: 1,
        };

        Ok(aggregation_public_input)
    }

    pub(crate) fn advance_encryption_of_mask_and_masked_key_share_proof_round(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<
        Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
    > {
        match public_input.dkg_output.clone() {
            Some(dkg_output) => {
                let witness = encryption_of_mask_and_masked_key_share_round::Party::sample_mask_and_nonce_share_and_initialize_proof_aggregation::<
                    SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                    ::class_groups::EncryptionKey<SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement>,
                >(&public_input.protocol_public_parameters, rng)?;

                let private_input = Some(vec![witness]);

                let aggregation_public_input =
                    Self::encryption_of_mask_and_masked_key_share_aggregation_public_input(
                        session_id,
                        public_input,
                        dkg_output,
                    )?;

                let (proof, statement_values) = proof::aggregation::asynchronous::Party::<
                    EncryptionOfTupleProof<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        MESSAGE_LIMBS,
                        GroupElement,
                    >,
                >::advance_first_round(
                    session_id,
                    party_id,
                    private_input,
                    &aggregation_public_input,
                    rng,
                )?;

                Ok(Message::EncryptionOfMaskAndMaskedKeyShareAndProof((
                    proof,
                    statement_values,
                )))
            }
            None => {
                let witness = encryption_of_mask_and_masked_key_share_round::Party::sample_mask_and_nonce_share_and_initialize_extended_proof_aggregation::<
                    SCALAR_LIMBS,
                    SCALAR_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                    ::class_groups::EncryptionKey<SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement>,
                >(&public_input.protocol_public_parameters, rng)?;

                let private_input = Some(vec![witness]);

                let aggregation_public_input =
                    Self::encryption_of_mask_and_masked_key_share_parts_aggregation_public_input(
                        session_id,
                        public_input,
                    )?;

                let (proof, statement_values) = proof::aggregation::asynchronous::Party::<
                    ExtendedEncryptionOfTupleProof<
                        2,
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        MESSAGE_LIMBS,
                        GroupElement,
                    >,
                >::advance_first_round(
                    session_id,
                    party_id,
                    private_input,
                    &aggregation_public_input,
                    rng,
                )?;

                Ok(Message::EncryptionOfMaskAndMaskedKeySharePartsAndProof((
                    proof,
                    statement_values,
                )))
            }
        }
    }

    pub(crate) fn advance_encryption_of_mask_and_masked_key_share_proof_verification_round(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        encryption_of_mask_and_masked_key_share_proofs_and_statements: HashMap<
            PartyID,
            Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(
        Vec<PartyID>,
        Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
    )> {
        match public_input.dkg_output.clone() {
            Some(dkg_output) => {
                // Make sure everyone sent the encryption of mask and masked key share and proof message.
                let (
                    parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages,
                    encryption_of_mask_and_masked_key_share_messages,
                ) = encryption_of_mask_and_masked_key_share_proofs_and_statements
                    .into_iter()
                    .map(|(party_id, message)| {
                        let res = match message {
                            Message::EncryptionOfMaskAndMaskedKeyShareAndProof(message) => {
                                Ok(message)
                            }
                            _ => Err(Error::InvalidParameters),
                        };

                        (party_id, res)
                    })
                    .handle_invalid_messages_async();

                let aggregation_public_input =
                    Self::encryption_of_mask_and_masked_key_share_aggregation_public_input(
                        session_id,
                        public_input,
                        dkg_output,
                    )?;

                let (malicious_provers, aggregated_statements) =
                    proof::aggregation::asynchronous::Party::<
                        EncryptionOfTupleProof<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            MESSAGE_LIMBS,
                            GroupElement,
                        >,
                    >::advance_second_round(
                        session_id,
                        access_structure,
                        &aggregation_public_input,
                        encryption_of_mask_and_masked_key_share_messages,
                        rng,
                    )?;

                let malicious_parties =
                    parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages
                        .into_iter()
                        .chain(malicious_provers)
                        .deduplicate_and_sort();

                match aggregated_statements[..] {
                    [statement] => Ok((
                        malicious_parties,
                        Message::EncryptionOfMaskAndMaskedKeyShare(statement.value()),
                    )),
                    _ => Err(Error::InternalError),
                }
            }
            None => {
                // Make sure everyone sent the encryption of mask and masked key share and proof message.
                let (
                    parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages,
                    encryption_of_mask_and_masked_key_share_parts_messages,
                ) = encryption_of_mask_and_masked_key_share_proofs_and_statements
                    .into_iter()
                    .map(|(party_id, message)| {
                        let res = match message {
                            Message::EncryptionOfMaskAndMaskedKeySharePartsAndProof(message) => {
                                Ok(message)
                            }
                            _ => Err(Error::InvalidParameters),
                        };

                        (party_id, res)
                    })
                    .handle_invalid_messages_async();

                let aggregation_public_input =
                    Self::encryption_of_mask_and_masked_key_share_parts_aggregation_public_input(
                        session_id,
                        public_input,
                    )?;

                let (malicious_provers, aggregated_statements) =
                    proof::aggregation::asynchronous::Party::<
                        ExtendedEncryptionOfTupleProof<
                            2,
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            MESSAGE_LIMBS,
                            GroupElement,
                        >,
                    >::advance_second_round(
                        session_id,
                        access_structure,
                        &aggregation_public_input,
                        encryption_of_mask_and_masked_key_share_parts_messages,
                        rng,
                    )?;

                let malicious_parties =
                    parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages
                        .into_iter()
                        .chain(malicious_provers)
                        .deduplicate_and_sort();

                match aggregated_statements[..] {
                    [statement] => Ok((
                        malicious_parties,
                        Message::EncryptionOfMaskAndMaskedKeyShareParts(statement.value()),
                    )),
                    _ => Err(Error::InternalError),
                }
            }
        }
    }

    pub(crate) fn majority_vote_encryption_of_mask_and_masked_key_share(
        access_structure: &WeightedThresholdAccessStructure,
        encryption_of_mask_and_masked_key_share_messages: HashMap<
            PartyID,
            Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        EncryptionOfMaskAndMaskedKeyShare<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    )> {
        // Make sure everyone sent the encryption of mask and masked key share message.
        let (
            parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages,
            encryption_of_mask_and_masked_key_share_messages,
        ) = encryption_of_mask_and_masked_key_share_messages
            .into_iter()
            .map(|(party_id, message)| {
                let res = match message {
                    Message::EncryptionOfMaskAndMaskedKeyShare(message) => Ok(message),
                    _ => Err(Error::InvalidParameters),
                };

                (party_id, res)
            })
            .handle_invalid_messages_async();

        // To ensure agreement on the previous round, apply a majority vote.
        // Parties in this round that claim a different subset of previous round messages are marked malicious.
        let (disagreeing_parties, encryption_of_mask_and_masked_key_share) =
            encryption_of_mask_and_masked_key_share_messages
                .clone()
                .weighted_majority_vote(access_structure)
                .map_err(|_| Error::InternalError)?;

        let malicious_parties =
            parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages
                .into_iter()
                .chain(disagreeing_parties)
                .deduplicate_and_sort();

        Ok((malicious_parties, encryption_of_mask_and_masked_key_share))
    }

    pub(crate) fn majority_vote_encryption_of_mask_and_masked_key_share_parts(
        access_structure: &WeightedThresholdAccessStructure,
        encryption_of_mask_and_masked_key_share_parts_messages: HashMap<
            PartyID,
            Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        EncryptionOfMaskAndMaskedKeyShareParts<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    )> {
        // Make sure everyone sent the encryption of mask and masked key share message.
        let (
            parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages,
            encryption_of_mask_and_masked_key_share_parts_messages,
        ) = encryption_of_mask_and_masked_key_share_parts_messages
            .into_iter()
            .map(|(party_id, message)| {
                let res = match message {
                    Message::EncryptionOfMaskAndMaskedKeyShareParts(message) => Ok(message),
                    _ => Err(Error::InvalidParameters),
                };

                (party_id, res)
            })
            .handle_invalid_messages_async();

        // To ensure agreement on the previous round, apply a majority vote.
        // Parties in this round that claim a different subset of previous round messages are marked malicious.
        let (disagreeing_parties, encryption_of_mask_and_masked_key_share_parts) =
            encryption_of_mask_and_masked_key_share_parts_messages
                .clone()
                .weighted_majority_vote(access_structure)
                .map_err(|_| Error::InternalError)?;

        let malicious_parties =
            parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages
                .into_iter()
                .chain(disagreeing_parties)
                .deduplicate_and_sort();

        Ok((
            malicious_parties,
            encryption_of_mask_and_masked_key_share_parts,
        ))
    }

    pub(crate) fn majority_vote_encryption_of_mask(
        access_structure: &WeightedThresholdAccessStructure,
        encryption_of_mask_and_masked_key_share_messages: HashMap<
            PartyID,
            Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
    ) -> Result<(
        Vec<PartyID>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    )> {
        match public_input.dkg_output.clone() {
            Some(_) => {
                let (disagreeing_parties, encryption_of_mask_and_masked_key_share) =
                    Self::majority_vote_encryption_of_mask_and_masked_key_share(
                        access_structure,
                        encryption_of_mask_and_masked_key_share_messages,
                    )?;

                let [encryption_of_mask, _] = encryption_of_mask_and_masked_key_share.into();

                Ok((disagreeing_parties, encryption_of_mask))
            }
            None => {
                let (disagreeing_parties, encryption_of_mask_and_masked_key_share_parts) =
                    Self::majority_vote_encryption_of_mask_and_masked_key_share_parts(
                        access_structure,
                        encryption_of_mask_and_masked_key_share_messages,
                    )?;

                let (encryption_of_mask, _) = encryption_of_mask_and_masked_key_share_parts.into();

                Ok((disagreeing_parties, encryption_of_mask))
            }
        }
    }
}
