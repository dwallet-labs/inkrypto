// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use class_groups::{
    publicly_verifiable_secret_sharing, RistrettoSetupParameters, Secp256r1SetupParameters,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use group::helpers::DeduplicateAndSort;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{CsRng, PartyID};
use mpc::{AsynchronousRoundResult, HandleInvalidMessages, WeightedThresholdAccessStructure};

use crate::decentralized_party::dkg::{Message, PublicOutput};
use crate::{Error, Result};

use super::PublicInput;

impl super::Party {
    pub(crate) fn advance_second_round(
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput,
        decryption_key_contribution_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_decryption_key_contribution_and_prove_coefficient_commitments_messages: HashMap<
            PartyID,
            Message,
        >,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        Self::advance_second_round_internal(
            tangible_party_id,
            access_structure,
            &public_input.class_groups_public_input,
            &public_input.ristretto_setup_parameters,
            &public_input.secp256r1_setup_parameters,
            decryption_key_contribution_pvss_party,
            deal_decryption_key_contribution_and_prove_coefficient_commitments_messages,
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
        access_structure: &WeightedThresholdAccessStructure,
        class_groups_public_input: &class_groups::dkg::PublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<Scalar>,
        >,
        ristretto_setup_parameters: &RistrettoSetupParameters,
        secp256r1_setup_parameters: &Secp256r1SetupParameters,
        decryption_key_contribution_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_decryption_key_contribution_and_prove_coefficient_commitments_messages: HashMap<
            PartyID,
            Message,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Message)> {
        let (
            parties_sending_invalid_deal_decryption_key_contribution_and_prove_coefficient_commitments_messages,
            deal_decryption_key_contribution_messages,
            _,
        ) = Self::handle_first_round_messages(
            &class_groups_public_input.setup_parameters,
            ristretto_setup_parameters,
            secp256r1_setup_parameters,
            deal_decryption_key_contribution_and_prove_coefficient_commitments_messages,
        )?;

        let (inner_protocol_malicious_parties, verified_dealers_) = class_groups::dkg::Party::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::advance_second_round_internal(
            tangible_party_id,
            access_structure,
            &class_groups_public_input.setup_parameters_per_crt_prime,
            decryption_key_contribution_pvss_party,
            deal_decryption_key_contribution_messages,
            rng,
        )?;

        let malicious_parties =
            parties_sending_invalid_deal_decryption_key_contribution_and_prove_coefficient_commitments_messages
                .into_iter()
                .chain(inner_protocol_malicious_parties)
                .deduplicate_and_sort();

        let message = Message::VerifiedDecryptionKeyContributionDealers(
            class_groups::dkg::Message::VerifiedDealers(verified_dealers_),
        );

        Ok((malicious_parties, message))
    }

    pub(crate) fn handle_second_round_messages(
        verified_dealers_messages: HashMap<PartyID, Message>,
    ) -> Result<(
        Vec<PartyID>,
        HashMap<
            PartyID,
            class_groups::dkg::Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    )> {
        // Make sure everyone sent the second round message.
        let (parties_sending_invalid_verified_dealers_messages, verified_dealers_messages) =
            verified_dealers_messages
                .into_iter()
                .map(|(dealer_party_id, message)| {
                    let res = match message {
                        Message::VerifiedDecryptionKeyContributionDealers(message) => Ok(message),
                        _ => Err(Error::InvalidMessage),
                    };

                    (dealer_party_id, res)
                })
                .handle_invalid_messages_async();

        Ok((
            parties_sending_invalid_verified_dealers_messages,
            verified_dealers_messages,
        ))
    }
}
