// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Presign Protocol for Paillier

pub mod asynchronous {
    use crypto_bigint::rand_core::CryptoRngCore;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::marker::PhantomData;

    use crate::languages::paillier::{
        construct_encryption_of_tuple_public_parameters,
        construct_scaling_of_discrete_log_public_parameters, EncryptionOfTupleEnhancedLanguage,
        EncryptionOfTupleProof, ScalingOfDiscreteLogEnhancedLanguage, ScalingOfDiscreteLogProof,
    };
    use crate::paillier::{
        bulletproofs::PaillierProtocolPublicParameters, EncryptionOfMaskAndMaskedKey,
    };
    use crate::paillier::{CiphertextSpaceGroupElement, Presign};
    use crate::paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS};
    use crate::presign::decentralized_party::{
        encryption_of_mask_and_masked_key_share_round,
        nonce_public_share_and_encryption_of_masked_nonce_round, PublicInput,
    };
    use crate::{Error, Result};
    use commitment::CommitmentSizedNumber;
    use group::helpers::DeduplicateAndSort;
    use group::{GroupElement, PartyID, PrimeGroupElement};
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages, MajorityVote,
        WeightedThresholdAccessStructure,
    };
    use serde::{Deserialize, Serialize};

    pub type Message<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const SCALAR_LIMBS: usize,
        GroupElement,
    > = super::super::Message<
        proof::aggregation::asynchronous::Message<
            EncryptionOfTupleProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
        >,
        EncryptionOfMaskAndMaskedKey<SCALAR_LIMBS>,
        proof::aggregation::asynchronous::Message<
            ScalingOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
        >,
    >;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Party<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    >(PhantomData<GroupElement>);

    impl<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > mpc::Party
        for Party<RANGE_CLAIMS_PER_SCALAR, NUM_RANGE_CLAIMS, SCALAR_LIMBS, GroupElement>
    {
        type Error = Error;
        type PublicInput = PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement>,
            PaillierProtocolPublicParameters<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                NUM_RANGE_CLAIMS,
                group::PublicParameters<GroupElement::Scalar>,
                GroupElement::PublicParameters,
            >,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = Presign<GroupElement>;
        type PublicOutput = Self::PublicOutputValue;
        type Message = Message<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>;
    }

    impl<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > AsynchronouslyAdvanceable
        for Party<RANGE_CLAIMS_PER_SCALAR, NUM_RANGE_CLAIMS, SCALAR_LIMBS, GroupElement>
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
                    EncryptionOfTupleProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
                > as AsynchronouslyAdvanceable>::round_causing_threshold_not_reached(
                    failed_round
                )
            } else {
                <proof::aggregation::asynchronous::Party<
                    ScalingOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
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
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > Party<RANGE_CLAIMS_PER_SCALAR, NUM_RANGE_CLAIMS, SCALAR_LIMBS, GroupElement>
    {
        #[allow(clippy::too_many_arguments)]
        #[allow(clippy::type_complexity)]
        fn advance_encryption_of_mask_and_masked_key_share_round(
            session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<
                HashMap<
                    PartyID,
                    proof::aggregation::asynchronous::Message<
                        EncryptionOfTupleProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
                    >,
                >,
            >,
            public_input: &PublicInput<
                GroupElement::Value,
                group::Value<CiphertextSpaceGroupElement>,
                PaillierProtocolPublicParameters<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    NUM_RANGE_CLAIMS,
                    group::PublicParameters<GroupElement::Scalar>,
                    GroupElement::PublicParameters,
                >,
            >,
            malicious_parties: Vec<PartyID>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<
            AsynchronousRoundResult<
                Message<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>,
                (),
                Presign<GroupElement>,
            >,
        > {
            // Construct L_EncDH public parameters
            // Used in emulating F^{L_EncDH}_{agg-zk}
            let enhanced_language_public_parameters =
                construct_encryption_of_tuple_public_parameters::<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    GroupElement,
                >(
                    public_input.dkg_output.encryption_of_secret_key_share,
                    public_input
                        .protocol_public_parameters
                        .protocol_public_parameters
                        .scalar_group_public_parameters
                        .clone(),
                    public_input
                        .protocol_public_parameters
                        .protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .clone(),
                    public_input
                        .protocol_public_parameters
                        .unbounded_encdh_witness_public_parameters
                        .clone(),
                    public_input
                        .protocol_public_parameters
                        .range_proof_enc_dl_public_parameters
                        .clone(),
                )?;

            let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
                protocol_context: public_input
                    .encryption_of_mask_and_masked_key_share_round_protocol_context(session_id),
                public_parameters: enhanced_language_public_parameters,
                batch_size: 1,
            };

            let private_input = match &messages[..] {
                [] => {
                    let witness = encryption_of_mask_and_masked_key_share_round::Party::sample_mask_and_nonce_share_and_initialize_proof_aggregation::<
                        SCALAR_LIMBS,
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        GroupElement,
                        EncryptionKey,
                    >(
                        &public_input.protocol_public_parameters.protocol_public_parameters,
                        rng,
                    )?;
                    // Map (\gamma_i, \eta_{1}^{i}, η_{2}^{i}) tuples to tuples of the form
                    // - [commitment message]    cm_i = decomposed \gamma_i
                    // - [commitment randomness] cr_i = fresh random sampled value
                    // - [unbounded witness]     uw_i = (\eta_{1}^{i}, \eta_{1}^{i})
                    let witness = EncryptionOfTupleEnhancedLanguage::<
                        SCALAR_LIMBS,
                        RANGE_CLAIMS_PER_SCALAR,
                        GroupElement,
                    >::generate_witness(
                        witness, &aggregation_public_input.public_parameters, rng
                    )?;
                    Ok(Some(vec![witness]))
                }
                [_] => Ok(None),
                _ => Err(Error::InvalidParameters),
            }?;

            match <proof::aggregation::asynchronous::Party<
                EncryptionOfTupleProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
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
                        let (_, statement) = statement.into();

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
        #[allow(clippy::type_complexity)]
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
                            RANGE_CLAIMS_PER_SCALAR,
                            GroupElement,
                        >,
                    >,
                >,
            >,
            public_input: &PublicInput<
                GroupElement::Value,
                group::Value<CiphertextSpaceGroupElement>,
                PaillierProtocolPublicParameters<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    NUM_RANGE_CLAIMS,
                    group::PublicParameters<GroupElement::Scalar>,
                    GroupElement::PublicParameters,
                >,
            >,
            malicious_parties: Vec<PartyID>,
            encryption_of_mask_and_masked_key: EncryptionOfMaskAndMaskedKey<SCALAR_LIMBS>,
            rng: &mut impl CryptoRngCore,
        ) -> Result<
            AsynchronousRoundResult<
                Message<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>,
                (),
                Presign<GroupElement>,
            >,
        > {
            let [mask_and_encryption_of_masked_key_share, _] =
                encryption_of_mask_and_masked_key.into();

            // Construct L_{\textsf{ScaleDL}} public parameters
            let enhanced_language_public_parameters =
                construct_scaling_of_discrete_log_public_parameters::<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    GroupElement,
                >(
                    mask_and_encryption_of_masked_key_share,
                    public_input
                        .protocol_public_parameters
                        .protocol_public_parameters
                        .scalar_group_public_parameters
                        .clone(),
                    public_input
                        .protocol_public_parameters
                        .protocol_public_parameters
                        .group_public_parameters
                        .clone(),
                    public_input
                        .protocol_public_parameters
                        .protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .clone(),
                    public_input
                        .protocol_public_parameters
                        .unbounded_encdl_witness_public_parameters
                        .clone(),
                    public_input
                        .protocol_public_parameters
                        .range_proof_enc_dl_public_parameters
                        .clone(),
                )?;

            let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
                protocol_context: public_input
                    .nonce_public_share_and_encryption_of_masked_nonce_round_protocol_context(
                        session_id,
                    ),
                public_parameters: enhanced_language_public_parameters,
                batch_size: 2,
            };

            let private_input = match &messages[..] {
                [] => {
                    let witnesses = nonce_public_share_and_encryption_of_masked_nonce_round::Party::initialize_proof_aggregation::<
                        SCALAR_LIMBS,
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        GroupElement,
                        EncryptionKey,
                    >(
                        &public_input
                            .protocol_public_parameters
                            .protocol_public_parameters,
                        rng,
                    )?;

                    // map (k_i, \eta^i_{3,0}, \eta^i_{3,1}) to a tuple with
                    // - [commitment message]    cm_i = decomposed k_i
                    // - [commitment randomness] cr_i = randomly sampled value
                    // - [unbounded witness]     uw_i = (\eta^i_{3,0}, \eta^i_{3,1})
                    let witnesses = ScalingOfDiscreteLogEnhancedLanguage::<
                        SCALAR_LIMBS,
                        RANGE_CLAIMS_PER_SCALAR,
                        GroupElement,
                    >::generate_witnesses(
                        witnesses,
                        &aggregation_public_input.public_parameters,
                        rng,
                    )?;
                    Ok(Some(witnesses))
                }
                [_] => Ok(None),
                _ => Err(Error::InvalidParameters),
            }?;

            match <proof::aggregation::asynchronous::Party<
                ScalingOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
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

                        let (_, first_statement) = first_statement.into();
                        let (_, second_statement) = second_statement.into();

                        Ok(AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output,
                            public_output: Presign::<GroupElement>::new(
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
