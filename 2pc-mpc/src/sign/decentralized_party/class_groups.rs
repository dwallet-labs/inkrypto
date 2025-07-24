// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Sign` decentralized party for Class Groups

pub mod asynchronous {
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use crypto_bigint::rand_core::CryptoRngCore;
    use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};

    use ::class_groups::DecryptionKeyShare;
    use ::class_groups::{
        encryption_key, CiphertextSpaceGroupElement, CompactIbqf, EncryptionKey, EquivalenceClass,
    };
    use ::class_groups::{
        equivalence_class, CiphertextSpacePublicParameters, RandomnessSpaceGroupElement,
        RandomnessSpacePublicParameters,
    };
    use ::class_groups::{DecryptionKey, DiscreteLogInF};
    use commitment::CommitmentSizedNumber;
    use group::helpers::DeduplicateAndSort;
    use group::{
        AffineXCoordinate, HashToGroup, PartyID, PrimeGroupElement, StatisticalSecuritySizedNumber,
    };
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages,
        WeightedThresholdAccessStructure,
    };

    use crate::class_groups::{
        DKGDecentralizedPartyOutput, DecryptionKeySharePublicParameters, DecryptionShare,
        PartialDecryptionProof, Presign,
    };
    use crate::sign::centralized_party::message::class_groups::Message as SignMessage;
    use crate::Error;

    use super::super::*;

    /// A party participating in the decentralized party's Asynchronous Sign protocol.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Party<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    >(PhantomData<GroupElement>);

    #[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
    pub enum Message<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
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
    {
        DecryptionShares(
            HashMap<
                PartyID,
                (
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                ),
            >,
        ),
        DecryptionSharesAndProof(
            HashMap<
                PartyID,
                (
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    PartialDecryptionProof<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                ),
            >,
        ),
    }

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
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
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        type Error = Error;
        type PublicInput = PublicInput<
            GroupElement::Scalar,
            DKGDecentralizedPartyOutput<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            Presign<
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
        type PrivateOutput = ();
        type PublicOutputValue = (GroupElement::Scalar, GroupElement::Scalar);
        type PublicOutput = Self::PublicOutputValue;
        type Message = Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >;
    }

    impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
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
        Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
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
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        type PrivateInput = HashMap<
            PartyID,
            DecryptionKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;

        fn advance(
            _session_id: CommitmentSizedNumber,
            tangible_party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            virtual_party_id_to_decryption_key_share: Option<Self::PrivateInput>,
            public_input: &Self::PublicInput,
            rng: &mut impl CryptoRngCore,
        ) -> Result<
            AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
            Self::Error,
        > {
            let virtual_party_id_to_decryption_key_share =
                virtual_party_id_to_decryption_key_share
                    .ok_or(Error::InvalidParameters)?;

            match &messages[..] {
                [] => {
                    signature_partial_decryption_round::Party::partially_decrypt_encryption_of_signature_parts_prehash_semi_honest_class_groups(
                        public_input.expected_decrypters.clone(),
                        public_input.hashed_message,
                        public_input.dkg_output.clone(),
                        public_input.presign.clone(),
                        public_input.sign_message.clone(),
                        &public_input.decryption_key_share_public_parameters,
                        virtual_party_id_to_decryption_key_share,
                        tangible_party_id,
                        access_structure,
                        &public_input.protocol_public_parameters,
                    ).map(|message| AsynchronousRoundResult::Advance { malicious_parties: vec![],message: Message::DecryptionShares(message) })
                }
                [first_round_messages] => {
                    // First make sure everyone sent the first round message for each virtual party in their virtual subset.
                    let (malicious_parties, decryption_shares) =
                        first_round_messages
                            .clone()
                            .into_iter()
                            .map(|(tangible_party_id, message)| {
                                let res = match message {
                                    Message::DecryptionShares(decryption_shares) if Some(
                                        &decryption_shares
                                            .keys()
                                            .copied()
                                            .collect(),
                                    ) == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) => {
                                        Ok(decryption_shares)
                                    },
                                    _ => Err(Error::InvalidParameters),
                                };

                                (tangible_party_id, res)
                            })
                            .handle_invalid_messages_async();

                    // Map to virtual parties
                    let decryption_shares = decryption_shares.into_values().flat_map(|decryption_shares| decryption_shares.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share))| (virtual_party_id, vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share])).collect::<Vec<_>>()).collect();

                    if let Ok(signature) = signature_threshold_decryption_round::Party::decrypt_signature_semi_honest_class_groups(public_input.expected_decrypters.clone(), decryption_shares, public_input.hashed_message, public_input.dkg_output.clone(), public_input.sign_message.clone(), &public_input.decryption_key_share_public_parameters, &public_input.protocol_public_parameters, access_structure) {
                        // Happy-flow: no party maliciously decrypted the message and we were able to finalize the signature in the semi-honest flow.
                        Ok(AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output: (),
                            public_output: signature,
                        })
                    } else {
                        // Sad-flow (infrequent): at least one party maliciously decrypted the message and we were unable to finalize the signature in the semi-honest flow.
                        // Therefore, we must perform an additional round where we verifiably decrypt the signature reconstruct the maliciously generated decryption shares, identifying the malicious parties in retrospect.
                        signature_partial_decryption_round::Party::partially_decrypt_encryption_of_signature_parts_prehash_class_groups(
                            public_input.hashed_message,
                            public_input.dkg_output.clone(),
                            public_input.presign.clone(),
                            public_input.sign_message.clone(),
                            &public_input.decryption_key_share_public_parameters,
                            virtual_party_id_to_decryption_key_share,
                            tangible_party_id,
                            access_structure,
                            &public_input.protocol_public_parameters,
                            rng
                        ).map(|message| AsynchronousRoundResult::Advance { malicious_parties, message: Message::DecryptionSharesAndProof(message) })
                    }
                },
                [first_round_messages, second_round_messages] => {
                    // First make sure everyone sent the first round message for each virtual party in their virtual subset.
                    let (parties_sending_invalid_first_round_messages, invalid_semi_honest_decryption_shares) =
                        first_round_messages
                            .clone()
                            .into_iter()
                            .map(|(tangible_party_id, message)| {
                                let res = match message {
                                    Message::DecryptionShares(decryption_shares) if Some(
                                        &decryption_shares
                                            .keys()
                                            .copied()
                                            .collect(),
                                    ) == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) => {
                                        Ok(decryption_shares)
                                    },
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
                                    Message::DecryptionSharesAndProof(decryption_shares_and_proofs) if Some(
                                        &decryption_shares_and_proofs
                                            .keys()
                                            .copied()
                                            .collect(),
                                    ) == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) => {
                                        Ok(decryption_shares_and_proofs)
                                    }
                                    _ => Err(Error::InvalidParameters),
                                };

                                (tangible_party_id, res)
                            })
                            .handle_invalid_messages_async();

                    // Map to virtual parties
                    let invalid_semi_honest_decryption_shares = invalid_semi_honest_decryption_shares.into_values().flat_map(|decryption_shares| decryption_shares.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share))| (virtual_party_id, vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share])).collect::<Vec<_>>()).collect();
                    let decryption_shares_and_proofs = decryption_shares_and_proofs.into_values().flat_map(|decryption_shares_and_proofs| decryption_shares_and_proofs.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share, proof))| (virtual_party_id, (vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share], proof))).collect::<Vec<_>>()).collect();

                    let (malicious_decrypters, signature) = signature_threshold_decryption_round::Party::decrypt_signature_class_groups(public_input.expected_decrypters.clone(), invalid_semi_honest_decryption_shares, decryption_shares_and_proofs, public_input.hashed_message, public_input.dkg_output.clone(), public_input.sign_message.clone(), &public_input.decryption_key_share_public_parameters, access_structure, &public_input.protocol_public_parameters, rng)?;

                    let malicious_parties = parties_sending_invalid_first_round_messages
                        .into_iter()
                        .chain(parties_sending_invalid_second_round_messages)
                        .chain(malicious_decrypters)
                        .deduplicate_and_sort();

                    Ok(AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output: (),
                        public_output: signature,
                    })
                }
                _ => Err(Error::InvalidParameters),
            }
        }

        fn round_causing_threshold_not_reached(failed_round: usize) -> Option<usize> {
            match failed_round {
                3 => Some(2),
                _ => None
            }
        }
    }
}
