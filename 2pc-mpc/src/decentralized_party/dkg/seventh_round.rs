// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use super::PublicInput;

use crate::decentralized_party::dkg::{Message, PublicOutput, PublicOutputCore};
use crate::Result;
use group::helpers::DeduplicateAndSort;
use group::{CsRng, PartyID};
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};
use std::collections::HashMap;

impl super::Party {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_seventh_round(
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput,
        verified_dealers_messages: HashMap<PartyID, Message>,
        threshold_decrypt_messages: HashMap<PartyID, Message>,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        // Step 1: Extract and majority-vote on R4 VerifiedDealers
        let (fourth_round_output, dealing_round_messages, vote_malicious_parties) =
            Self::extract_verified_dealers_and_majority_vote(
                verified_dealers_messages,
                access_structure,
            )?;

        // Step 2: Extract decryption messages from R6 ThresholdDecryptSecretKeyShares
        let decryption_messages: HashMap<PartyID, _> = threshold_decrypt_messages
            .into_iter()
            .filter_map(|(party_id, message)| {
                if let Message::ThresholdDecryptSecretKeyShares { threshold_encryption_of_secret_key_share_parts_to_sharing_decryption_round_message } = message {
                    Some((party_id, threshold_encryption_of_secret_key_share_parts_to_sharing_decryption_round_message))
                } else {
                    None
                }
            })
            .collect();

        // Step 3: Construct Protocol 0.1 PublicInput from majority-voted CG DKG R4 output
        let threshold_encryption_of_secret_key_share_parts_to_sharing_public_input =
            Self::construct_threshold_encryption_of_secret_key_share_parts_to_sharing_public_input(
                public_input,
                &fourth_round_output,
            )?;

        // Step 5: Call aggregation::advance to get Protocol 0.1 PublicOutput
        let (aggregation_malicious_parties, threshold_enc_public_output) =
            crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::aggregation::advance(
                &threshold_encryption_of_secret_key_share_parts_to_sharing_public_input,
                &dealing_round_messages,
                &decryption_messages,
                rng,
            )?;

        // Step 6: Construct final DKG PublicOutput combining inner DKG output + Protocol 0.1 output
        let malicious_parties = vote_malicious_parties
            .into_iter()
            .chain(aggregation_malicious_parties)
            .deduplicate_and_sort();

        let core = PublicOutputCore::new(
            fourth_round_output.inner_protocol_public_output,
            fourth_round_output.secp256k1_encryption_of_secret_key_share_first_part,
            fourth_round_output.secp256k1_encryption_of_secret_key_share_second_part,
            fourth_round_output.secp256k1_public_key_share_first_part,
            fourth_round_output.secp256k1_public_key_share_second_part,
            fourth_round_output.ristretto_encryption_of_secret_key_share_first_part,
            fourth_round_output.ristretto_encryption_of_secret_key_share_second_part,
            fourth_round_output.ristretto_public_key_share_first_part,
            fourth_round_output.ristretto_public_key_share_second_part,
            fourth_round_output.ristretto_encryption_key,
            fourth_round_output.ristretto_public_verification_keys,
            fourth_round_output.curve25519_encryption_of_secret_key_share_first_part,
            fourth_round_output.curve25519_encryption_of_secret_key_share_second_part,
            fourth_round_output.curve25519_public_key_share_first_part,
            fourth_round_output.curve25519_public_key_share_second_part,
            fourth_round_output.secp256r1_encryption_of_secret_key_share_first_part,
            fourth_round_output.secp256r1_encryption_of_secret_key_share_second_part,
            fourth_round_output.secp256r1_public_key_share_first_part,
            fourth_round_output.secp256r1_public_key_share_second_part,
            fourth_round_output.secp256r1_encryption_key,
            fourth_round_output.secp256r1_public_verification_keys,
        )?;

        let public_output = PublicOutput {
            core,
            threshold_encryption_to_sharing_output: threshold_enc_public_output,
        };

        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties,
            private_output: (),
            public_output,
        })
    }
}
