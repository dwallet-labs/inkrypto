// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use super::PublicInput;

use crate::decentralized_party::dkg::{Message, PublicOutput};
use crate::Result;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
};
use class_groups::{
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use commitment::CommitmentSizedNumber;
use crypto_bigint::Uint;
use group::helpers::DeduplicateAndSort;
use group::{secp256k1, CsRng, PartyID};
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};
use std::collections::HashMap;

impl super::Party {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_sixth_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput,
        verified_dealers_messages: HashMap<PartyID, Message>,
        accused_dealers_messages: HashMap<PartyID, Message>,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        // Step 1: Extract and majority-vote on R4 VerifiedDealers
        let (fourth_round_output, dealing_round_messages, vote_malicious_parties) =
            Self::extract_verified_dealers_and_majority_vote(
                verified_dealers_messages,
                access_structure,
            )?;

        // Step 2: Extract accusation messages from R5 AccusedDealers
        let accusation_messages: HashMap<PartyID, _> = accused_dealers_messages
            .into_iter()
            .filter_map(|(party_id, message)| {
                if let Message::AccusedDealers { threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message } = message {
                    Some((party_id, threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message))
                } else {
                    None
                }
            })
            .collect();

        // Step 3: Compute decryption key share from CRT keys
        let decryption_key_shares =
            class_groups::dkg::PublicOutput::<
                { secp256k1::SCALAR_LIMBS },
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::decrypt_decryption_key_shares_internal::<secp256k1::GroupElement>(
                tangible_party_id,
                access_structure,
                decryption_key_per_crt_prime,
                fourth_round_output
                    .inner_protocol_public_output
                    .encryptions_of_shares_per_crt_prime
                    .clone(),
            )?;

        // In the uniform access structure, each tangible party has exactly one virtual
        // party (itself), so extract the single decryption key share.
        let decryption_key_share = *decryption_key_shares
            .get(&tangible_party_id)
            .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;

        // Step 5: Construct Protocol 0.1 PublicInput from majority-voted CG DKG R4 output
        let threshold_encryption_of_secret_key_share_parts_to_sharing_public_input =
            Self::construct_threshold_encryption_of_secret_key_share_parts_to_sharing_public_input(
                public_input,
                &fourth_round_output,
            )?;

        // Step 6: Call decryption::advance
        let (decryption_malicious_parties, decryption_round_message) =
            crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::decryption::advance(
                session_id,
                tangible_party_id,
                Some(tangible_party_id),
                decryption_key_share,
                &threshold_encryption_of_secret_key_share_parts_to_sharing_public_input,
                &dealing_round_messages,
                &accusation_messages,
                rng,
            )?;

        let malicious_parties = vote_malicious_parties
            .into_iter()
            .chain(decryption_malicious_parties)
            .deduplicate_and_sort();

        let message = Message::ThresholdDecryptSecretKeyShares {
            threshold_encryption_of_secret_key_share_parts_to_sharing_decryption_round_message:
                decryption_round_message,
        };

        Ok(AsynchronousRoundResult::Advance {
            malicious_parties,
            message,
        })
    }
}
