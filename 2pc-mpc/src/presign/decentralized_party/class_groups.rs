// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Presign Protocol for Class Groups

pub mod asynchronous {
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::marker::PhantomData;

    use crypto_bigint::{Encoding, Int, Uint};
    use serde::{Deserialize, Serialize};

    use crate::class_groups::{EncryptionOfMaskAndMaskedKey, Presign};
    use crate::languages::class_groups::EncryptionOfTupleProof;
    use crate::languages::class_groups::{
        construct_encryption_of_tuple_public_parameters,
        construct_scaling_of_discrete_log_public_parameters, ScalingOfDiscreteLogProof,
    };
    use crate::presign::decentralized_party::PublicInput;
    use crate::presign::decentralized_party::{
        encryption_of_mask_and_masked_key_share_round,
        nonce_public_share_and_encryption_of_masked_nonce_round,
    };
    use crate::{Error, Result};
    use ::class_groups::CiphertextSpaceGroupElement;
    use ::class_groups::{encryption_key, CompactIbqf, EncryptionKey, EquivalenceClass};
    use ::class_groups::{equivalence_class, RandomnessSpaceGroupElement};
    use ::class_groups::{CiphertextSpacePublicParameters, RandomnessSpacePublicParameters};
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::rand_core::CryptoRngCore;
    use group::helpers::DeduplicateAndSort;
    use group::{GroupElement, PartyID, PrimeGroupElement};
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages, MajorityVote,
        WeightedThresholdAccessStructure,
    };

    pub type Message<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement,
    > = super::super::Message<
        proof::aggregation::asynchronous::Message<
            EncryptionOfTupleProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
        EncryptionOfMaskAndMaskedKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        proof::aggregation::asynchronous::Message<
            ScalingOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
    >;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Party<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement,
    >(PhantomData<GroupElement>)
    where
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<MESSAGE_LIMBS>: Encoding;

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > mpc::Party
        for Party<
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
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        type Error = Error;
        type PublicInput = PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = Presign<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type PublicOutput = Self::PublicOutputValue;
        type Message = Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;
    }

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > AsynchronouslyAdvanceable
        for Party<
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
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        type PrivateInput = ();

        fn advance(
            session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            _private_input: Option<Self::PrivateInput>,
            public_input: &Self::PublicInput,
            rng: &mut impl CryptoRngCore,
        ) -> Result<AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>>
        {
            if messages.len() < 2 {
                // Make sure everyone sent the encryption of mask and masked key share and proof message,
                // if it is the right round - default to sending nothing.
                let (
                    parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages,
                    encryption_of_mask_and_masked_key_share_messages,
                ) = messages
                    .first()
                    .map(|messages| {
                        let (malicious_parties, messages) = messages
                            .clone()
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

                        (malicious_parties, vec![messages])
                    })
                    .unwrap_or_default();

                Self::advance_encryption_of_mask_and_masked_key_share_round(
                    session_id,
                    party_id,
                    access_structure,
                    encryption_of_mask_and_masked_key_share_messages,
                    public_input,
                    parties_sending_invalid_encryption_of_mask_and_masked_key_share_messages,
                    rng,
                )
            } else {
                // Make sure everyone sent the encryption of mask and masked key message.
                let (
                    parties_sending_invalid_encryption_of_mask_and_masked_key_messages,
                    encryption_of_mask_and_masked_key_messages,
                ) = messages
                    .get(1)
                    .map(|messages| {
                        messages
                            .clone()
                            .into_iter()
                            .map(|(party_id, message)| {
                                let res = match message {
                                    Message::EncryptionOfMaskAndMaskedKey(message) => Ok(message),
                                    _ => Err(Error::InvalidParameters),
                                };

                                (party_id, res)
                            })
                            .handle_invalid_messages_async()
                    })
                    .ok_or(Error::InternalError)?;

                // Make sure everyone sent the nonce public share and encryption of masked nonce share and proof message,
                // if it is the right round - default to sending nothing.
                let (
                    parties_sending_invalid_nonce_public_share_and_encryption_of_masked_nonce_share_messages,
                    nonce_public_share_and_encryption_of_masked_nonce_share_messages,
                ) = messages.get(2)
                    .map(|messages| {
                        let (malicious_parties, messages) = messages.clone().into_iter()
                            .map(|(party_id, message)| {
                                let res = match message {
                                    Message::NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof(message) => {
                                        Ok(message)
                                    }
                                    _ => Err(Error::InvalidParameters),
                                };

                                (party_id, res)
                            })
                            .handle_invalid_messages_async();

                        (malicious_parties, vec![messages])
                    }).unwrap_or_default();

                // To ensure agreement on the previous round, apply a majority vote.
                // Parties in this round that claim a different subset of previous round messages are marked malicious.
                let (disagreeing_parties, encryption_of_mask_and_masked_key) =
                    encryption_of_mask_and_masked_key_messages
                        .clone()
                        .weighted_majority_vote(access_structure)
                        .map_err(|_| Error::InternalError)?;

                let malicious_parties = parties_sending_invalid_encryption_of_mask_and_masked_key_messages.into_iter().chain(parties_sending_invalid_nonce_public_share_and_encryption_of_masked_nonce_share_messages).chain(disagreeing_parties).deduplicate_and_sort();

                Self::advance_nonce_public_share_and_encryption_of_masked_nonce_round(
                    session_id,
                    party_id,
                    access_structure,
                    nonce_public_share_and_encryption_of_masked_nonce_share_messages,
                    public_input,
                    malicious_parties,
                    encryption_of_mask_and_masked_key,
                    rng,
                )
            }
        }

        fn round_causing_threshold_not_reached(failed_round: usize) -> Option<usize> {
            if failed_round <= 2 {
                <proof::aggregation::asynchronous::Party<
                    EncryptionOfTupleProof<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        MESSAGE_LIMBS,
                        GroupElement,
                    >,
                > as AsynchronouslyAdvanceable>::round_causing_threshold_not_reached(
                    failed_round
                )
            } else {
                <proof::aggregation::asynchronous::Party<
                    ScalingOfDiscreteLogProof<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        MESSAGE_LIMBS,
                        GroupElement,
                    >,
                > as AsynchronouslyAdvanceable>::round_causing_threshold_not_reached(
                    failed_round
                )
                .map(|round| {
                    // Account for the static offset (i.e. we are running this sub-protocol after two rounds.)
                    round + 2
                })
            }
        }
    }

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
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
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        #[allow(clippy::too_many_arguments)]
        fn advance_encryption_of_mask_and_masked_key_share_round(
            session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<
                HashMap<
                    PartyID,
                    proof::aggregation::asynchronous::Message<
                        EncryptionOfTupleProof<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            MESSAGE_LIMBS,
                            GroupElement,
                        >,
                    >,
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
            malicious_parties: Vec<PartyID>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<
            AsynchronousRoundResult<
                Message<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                >,
                (),
                Presign<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >,
            >,
        > {
            let private_input = match &messages[..] {
                [] => {
                    let witness = encryption_of_mask_and_masked_key_share_round::Party::sample_mask_and_nonce_share_and_initialize_proof_aggregation::<
                        SCALAR_LIMBS,
                        SCALAR_LIMBS,
                        MESSAGE_LIMBS,
                        GroupElement,
                        ::class_groups::EncryptionKey<SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement>,
                    >(&public_input.protocol_public_parameters, rng)?;

                    Ok(Some(vec![witness]))
                }
                [_] => Ok(None),
                _ => Err(Error::InvalidParameters),
            }?;

            let language_public_parameters = construct_encryption_of_tuple_public_parameters::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >(
                public_input.dkg_output.encryption_of_secret_key_share,
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
                    .encryption_of_mask_and_masked_key_share_round_protocol_context(session_id),
                public_parameters: language_public_parameters,
                batch_size: 1,
            };

            match <proof::aggregation::asynchronous::Party<
                EncryptionOfTupleProof<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                >,
            > as AsynchronouslyAdvanceable>::advance(
                session_id,
                party_id,
                access_structure,
                messages,
                private_input,
                &aggregation_public_input,
                rng,
            )? {
                AsynchronousRoundResult::Advance {
                    malicious_parties: malicious_provers,
                    message,
                } => {
                    let malicious_parties = malicious_parties
                        .into_iter()
                        .chain(malicious_provers)
                        .collect();

                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message: Message::EncryptionOfMaskAndMaskedKeyShareAndProof(message),
                    })
                }
                AsynchronousRoundResult::Finalize {
                    malicious_parties: malicious_provers,
                    private_output: _,
                    public_output,
                } => match &public_output[..] {
                    [statement] => {
                        let malicious_parties = malicious_parties
                            .into_iter()
                            .chain(malicious_provers)
                            .collect();

                        Ok(AsynchronousRoundResult::Advance {
                            malicious_parties,
                            message: Message::EncryptionOfMaskAndMaskedKey(statement.value()),
                        })
                    }
                    _ => Err(Error::InternalError),
                },
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn advance_nonce_public_share_and_encryption_of_masked_nonce_round(
            session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<
                HashMap<
                    PartyID,
                    proof::aggregation::asynchronous::Message<
                        ScalingOfDiscreteLogProof<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            MESSAGE_LIMBS,
                            GroupElement,
                        >,
                    >,
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
            malicious_parties: Vec<PartyID>,
            encryption_of_mask_and_masked_key: EncryptionOfMaskAndMaskedKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            rng: &mut impl CryptoRngCore,
        ) -> Result<
            AsynchronousRoundResult<
                Message<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                >,
                (),
                Presign<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >,
            >,
        > {
            let private_input = match &messages[..] {
                [] => {
                    let witnesses =
                        nonce_public_share_and_encryption_of_masked_nonce_round::Party::initialize_proof_aggregation::<
                            SCALAR_LIMBS,
                            SCALAR_LIMBS,
                            MESSAGE_LIMBS,
                            GroupElement,
                            ::class_groups::EncryptionKey<
                                SCALAR_LIMBS,
                                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                GroupElement,
                            >,
                        >(&public_input.protocol_public_parameters, rng)?;

                    Ok(Some(witnesses))
                }
                [_] => Ok(None),
                _ => Err(Error::InvalidParameters),
            }?;

            let [mask_and_encryption_of_masked_key_share, _] =
                encryption_of_mask_and_masked_key.into();

            let language_public_parameters = construct_scaling_of_discrete_log_public_parameters::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >(
                mask_and_encryption_of_masked_key_share,
                public_input
                    .protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                public_input
                    .protocol_public_parameters
                    .group_public_parameters
                    .clone(),
                public_input
                    .protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
            )?;

            let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
                protocol_context: public_input
                    .nonce_public_share_and_encryption_of_masked_nonce_round_protocol_context(
                        session_id,
                    ),
                public_parameters: language_public_parameters,
                batch_size: 2,
            };

            match <proof::aggregation::asynchronous::Party<
                ScalingOfDiscreteLogProof<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                >,
            > as AsynchronouslyAdvanceable>::advance(
                session_id,
                party_id,
                access_structure,
                messages,
                private_input,
                &aggregation_public_input,
                rng,
            )? {
                AsynchronousRoundResult::Advance {
                    malicious_parties: malicious_provers,
                    message,
                } => {
                    let malicious_parties = malicious_parties
                        .into_iter()
                        .chain(malicious_provers)
                        .deduplicate_and_sort();

                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message: Message::NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof(
                            message,
                        ),
                    })
                }
                AsynchronousRoundResult::Finalize {
                    malicious_parties: malicious_provers,
                    private_output,
                    public_output,
                } => match &public_output[..] {
                    [first_statement, second_statement] => {
                        let malicious_parties = malicious_parties
                            .into_iter()
                            .chain(malicious_provers)
                            .deduplicate_and_sort();

                        Ok(AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output,
                            public_output: Presign::<
                                SCALAR_LIMBS,
                                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                GroupElement,
                            >::new(
                                session_id,
                                encryption_of_mask_and_masked_key,
                                [first_statement.value(), second_statement.value()],
                            ),
                        })
                    }
                    _ => Err(Error::InternalError),
                },
            }
        }
    }
}
