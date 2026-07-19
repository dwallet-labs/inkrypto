// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use class_groups::{
    publicly_verifiable_secret_sharing,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::secp256k1::{GroupElement, SCALAR_LIMBS};
use group::{CsRng, PartyID};
use mpc::{AsynchronousRoundResult, HandleInvalidMessages};

use crate::decentralized_party::reconfiguration::{Message, NonAggregatedPublicOutput};
use crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::{
    AccusationRoundMessage, DealingRoundMessage,
};
use crate::{Error, ErrorKind, Result};

use super::PublicInput;

impl super::Party {
    pub(crate) fn advance_second_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        public_input: &PublicInput,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::chinese_remainder_theorem::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_randomizer_and_prove_coefficient_commitments_messages: HashMap<PartyID, Message>,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), NonAggregatedPublicOutput>> {
        Self::advance_second_round_internal(
            tangible_party_id,
            session_id,
            public_input,
            randomizer_contribution_to_upcoming_pvss_party,
            deal_randomizer_and_prove_coefficient_commitments_messages,
            rng,
        )
        .map(
            |(malicious_parties, message)| AsynchronousRoundResult::Advance {
                malicious_parties,
                message,
            },
        )
    }

    pub(crate) fn advance_second_round_internal(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        public_input: &PublicInput,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::chinese_remainder_theorem::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_randomizer_and_prove_coefficient_commitments_messages: HashMap<PartyID, Message>,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Message)> {
        let (
            parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
            deal_randomizer_messages,
            _,
            dealing_round_messages,
        ) = Self::handle_first_round_messages(
            &public_input.class_groups_public_input.setup_parameters,
            &public_input.ristretto_setup_parameters,
            &public_input.secp256r1_setup_parameters,
            deal_randomizer_and_prove_coefficient_commitments_messages,
        )?;

        let (inner_protocol_malicious_parties, verified_dealers_to_upcoming) =
            class_groups::reconfiguration::Party::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >::advance_second_round_internal(
                tangible_party_id,
                &public_input.class_groups_public_input,
                deal_randomizer_messages,
                randomizer_contribution_to_upcoming_pvss_party,
                rng,
            )?;

        let malicious_parties =
            parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages
                .into_iter()
                .chain(inner_protocol_malicious_parties)
                .deduplicate_and_sort();

        // Protocol 0.1: Perform accusation round using threshold_encryption_to_sharing
        // This verifies PVSS shares dealt to this party for each curve using batch verification
        let accusation_message = Self::perform_accusation_round(
            tangible_party_id,
            session_id,
            public_input,
            &dealing_round_messages,
            rng,
        )?;

        let message = Message::VerifiedRandomizerDealers {
            class_groups_message: class_groups::reconfiguration::Message::VerifiedRandomizerDealers(
                verified_dealers_to_upcoming,
            ),
            threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message:
                accusation_message,
        };

        Ok((malicious_parties, message))
    }

    /// Performs the accusation round for Protocol 0.1.
    ///
    /// Uses threshold_encryption_to_sharing::accusation::advance() to verify PVSS shares
    /// dealt to this party for all curves using batch verification.
    ///
    /// Returns an AccusationRoundMessage containing malicious dealers (those whose shares
    /// failed verification).
    fn perform_accusation_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        public_input: &PublicInput,
        dealing_round_messages: &HashMap<PartyID, DealingRoundMessage>,
        rng: &mut impl CsRng,
    ) -> crate::Result<AccusationRoundMessage> {
        // Look up the upcoming party ID for this tangible party
        let upcoming_party_id = public_input
            .class_groups_public_input
            .current_tangible_party_id_to_upcoming
            .get(&tangible_party_id)
            .cloned()
            .ok_or_else(|| crate::Error::from(crate::ErrorKind::InvalidParameters))?;

        // If party is leaving the committee (no upcoming ID), return Ok(None) to skip accusation
        let Some(participating_party_id) = upcoming_party_id else {
            return Ok(None);
        };

        // Call the accusation module to perform batch PVSS verification.
        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::accusation::advance(
            session_id,
            tangible_party_id,
            participating_party_id,
            &public_input.threshold_encryption_of_secret_key_share_parts_to_sharing_public_input,
            dealing_round_messages,
            rng,
        )
    }

    pub(crate) fn handle_second_round_messages(
        public_input: &PublicInput,
        verified_dealers_messages: HashMap<PartyID, Message>,
    ) -> Result<(
        Vec<PartyID>,
        HashMap<
            PartyID,
            class_groups::reconfiguration::Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        HashMap<PartyID, AccusationRoundMessage>,
    )> {
        // Make sure everyone sent the second round message, and validate accusation
        // consistency: parties mapping to Some(upcoming_id) must have Some accusation,
        // parties mapping to None must have None accusation.
        let (parties_sending_invalid_verified_dealers_messages, verified_dealers_messages) =
            verified_dealers_messages
                .into_iter()
                .map(|(dealer_party_id, message)| {
                    let res = match message {
                        Message::VerifiedRandomizerDealers {
                            class_groups_message,
                            threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message,
                        } => {
                            let is_upcoming = public_input
                                .class_groups_public_input
                                .current_tangible_party_id_to_upcoming
                                .get(&dealer_party_id)
                                .unwrap_or(&None)
                                .is_some();

                            if is_upcoming
                                == threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message
                                    .is_some()
                            {
                                Ok((
                                    class_groups_message,
                                    threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message,
                                ))
                            } else {
                                Err(Error::from(ErrorKind::InvalidMessage))
                            }
                        }
                        _ => Err(Error::from(ErrorKind::InvalidMessage)),
                    };

                    (dealer_party_id, res)
                })
                .handle_invalid_messages_async();

        let (class_groups_messages, accusation_messages_by_current_id): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = verified_dealers_messages
            .into_iter()
            .map(|(party_id, (class_groups_message, accusation_message))| {
                (
                    (party_id, class_groups_message),
                    (party_id, accusation_message),
                )
            })
            .unzip();

        // Remap accusation messages from current party IDs to upcoming party IDs.
        let accusation_messages: HashMap<PartyID, AccusationRoundMessage> =
            accusation_messages_by_current_id
                .into_iter()
                .flat_map(|(current_party_id, accusation_message)| {
                    public_input
                        .class_groups_public_input
                        .current_tangible_party_id_to_upcoming
                        .get(&current_party_id)
                        .unwrap_or(&None)
                        .map(|upcoming_id| (upcoming_id, accusation_message))
                })
                .collect();

        Ok((
            parties_sending_invalid_verified_dealers_messages,
            class_groups_messages,
            accusation_messages,
        ))
    }
}
