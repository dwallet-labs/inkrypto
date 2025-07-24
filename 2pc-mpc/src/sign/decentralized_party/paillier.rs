// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Sign` decentralized party for Paillier

pub mod asynchronous {
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::rand_core::CryptoRngCore;
    use group::helpers::DeduplicateAndSort;
    use group::{AffineXCoordinate, PartyID, PrimeGroupElement};
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages,
        WeightedThresholdAccessStructure,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use crate::paillier::bulletproofs::{PaillierProtocolPublicParameters, SignMessage};
    use crate::paillier::{
        DKGDecentralizedPartyOutput, DecryptionKeyShare, DecryptionShare, PartialDecryptionProof,
        Presign,
    };
    use crate::sign::decentralized_party::{
        signature_partial_decryption_round, signature_threshold_decryption_round, PublicInput,
    };
    use crate::Error;

    use super::super::super::*;

    /// A party participating in the decentralized party's Asynchronous Sign protocol.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Party<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    >(PhantomData<GroupElement>);

    #[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
    pub enum Message {
        DecryptionShares(HashMap<PartyID, (DecryptionShare, DecryptionShare)>),
        DecryptionSharesAndProof(
            HashMap<PartyID, (DecryptionShare, DecryptionShare, PartialDecryptionProof)>,
        ),
    }

    impl<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const RANGE_CLAIMS_PER_MASK: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        > mpc::Party
        for Party<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            SCALAR_LIMBS,
            GroupElement,
        >
    where
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        type Error = Error;
        type PublicInput = PublicInput<
            GroupElement::Scalar,
            DKGDecentralizedPartyOutput<GroupElement>,
            Presign<GroupElement>,
            SignMessage<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RANGE_CLAIMS_PER_MASK,
                NUM_RANGE_CLAIMS,
                GroupElement,
            >,
            tiresias::decryption_key_share::PublicParameters,
            PaillierProtocolPublicParameters<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                NUM_RANGE_CLAIMS,
                group::PublicParameters<GroupElement::Scalar>,
                GroupElement::PublicParameters,
            >,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = (GroupElement::Scalar, GroupElement::Scalar);
        type PublicOutput = Self::PublicOutputValue;
        type Message = Message;
    }

    impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>
        + AffineXCoordinate<SCALAR_LIMBS>
        + group::HashToGroup,
    > AsynchronouslyAdvanceable
    for Party<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        GroupElement,
    >
    where
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
        Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
    {
        type PrivateInput = HashMap<PartyID, DecryptionKeyShare>;

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
                    signature_partial_decryption_round::Party::partially_decrypt_encryption_of_signature_parts_prehash_semi_honest_paillier(
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
                        rng
                    ).map(|message| AsynchronousRoundResult::Advance { malicious_parties: vec![], message: Message::DecryptionShares(message) })
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

                    if let Ok(signature) = signature_threshold_decryption_round::Party::decrypt_signature_semi_honest_paillier(public_input.expected_decrypters.clone(), decryption_shares, public_input.hashed_message, public_input.dkg_output.clone(), public_input.sign_message.clone(), &public_input.decryption_key_share_public_parameters, &public_input.protocol_public_parameters, access_structure) {
                        // Happy-flow: no party maliciously decrypted the message and we were able to finalize the signature in the semi-honest flow.
                        Ok(AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output: (),
                            public_output: signature,
                        })
                    } else {
                        // Sad-flow (infrequent): at least one party maliciously decrypted the message and we were unable to finalize the signature in the semi-honest flow.
                        // Therefore, we must perform an additional round where we verifiably decrypt the signature reconstruct the maliciously generated decryption shares, identifying the malicious parties in retrospect.
                        signature_partial_decryption_round::Party::partially_decrypt_encryption_of_signature_parts_prehash_paillier(
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
                    let invalid_semi_honest_decryption_shares: HashMap<_, _> = invalid_semi_honest_decryption_shares.into_values().flat_map(|decryption_shares| decryption_shares.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share))| (virtual_party_id, vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share])).collect::<Vec<_>>()).collect();
                    let decryption_shares_and_proofs = decryption_shares_and_proofs.into_values().flat_map(|decryption_shares_and_proofs| decryption_shares_and_proofs.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share, proof))| (virtual_party_id, (vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share], proof))).collect::<Vec<_>>()).collect();

                    let (malicious_decrypters, signature) = signature_threshold_decryption_round::Party::decrypt_signature_paillier(public_input.expected_decrypters.clone(), invalid_semi_honest_decryption_shares, decryption_shares_and_proofs, public_input.hashed_message, public_input.dkg_output.clone(), public_input.sign_message.clone(), &public_input.decryption_key_share_public_parameters, access_structure, &public_input.protocol_public_parameters, rng)?;

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
