// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use super::PublicInput;

use crate::decentralized_party::dkg::{FourthRoundInternalOutput, Message, PublicOutput};
use crate::Result;
use class_groups::encryption_key::public_parameters::Instantiate;
use commitment::CommitmentSizedNumber;
use group::{CsRng, GroupElement as _, PartyID};
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};
use std::collections::HashMap;

impl super::Party {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn advance_fifth_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput,
        verified_dealers_messages: HashMap<PartyID, Message>,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        // Step 1: Extract and majority-vote on R4 VerifiedDealers
        let (fourth_round_output, dealing_round_messages, vote_malicious_parties) =
            Self::extract_verified_dealers_and_majority_vote(
                verified_dealers_messages,
                access_structure,
            )?;

        // Step 2: Construct Protocol 0.1 PublicInput from majority-voted CG DKG R4 output
        let threshold_encryption_of_secret_key_share_parts_to_sharing_public_input =
            Self::construct_threshold_encryption_of_secret_key_share_parts_to_sharing_public_input(
                public_input,
                &fourth_round_output,
            )?;

        // Step 4: Perform accusation round
        let accusation = Self::perform_accusation_round(
            tangible_party_id,
            session_id,
            &threshold_encryption_of_secret_key_share_parts_to_sharing_public_input,
            &dealing_round_messages,
            rng,
        )?;

        let message = Message::AccusedDealers {
            threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message:
                accusation,
        };

        Ok(AsynchronousRoundResult::Advance {
            malicious_parties: vote_malicious_parties,
            message,
        })
    }

    /// Performs the accusation round for Protocol 0.1.
    ///
    /// Uses the pre-constructed `threshold_encryption_of_secret_key_share_parts_to_sharing_public_input` (built from real CG DKG R4 output)
    /// to verify PVSS randomizer shares.
    pub(crate) fn perform_accusation_round(
        party_id: PartyID,
        session_id: CommitmentSizedNumber,
        threshold_encryption_of_secret_key_share_parts_to_sharing_public_input: &crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::PublicInput,
        dealing_round_messages: &HashMap<
            PartyID,
            crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::DealingRoundMessage,
        >,
        rng: &mut impl CsRng,
    ) -> crate::Result<crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::AccusationRoundMessage>
    {
        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::accusation::advance(
            session_id,
            party_id,
            party_id,
            threshold_encryption_of_secret_key_share_parts_to_sharing_public_input,
            dealing_round_messages,
            rng,
        )
    }

    /// Constructs the Protocol 0.1 PublicInput from the CG DKG Round 4 output.
    ///
    /// This is shared between fourth_round (dealing), fifth_round (accusation),
    /// sixth_round (decryption) and seventh_round (aggregation).
    pub(crate) fn construct_threshold_encryption_of_secret_key_share_parts_to_sharing_public_input(
        public_input: &PublicInput,
        fourth_round_output: &FourthRoundInternalOutput,
    ) -> Result<
        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::PublicInput,
    >{
        let secp256k1_setup_parameters = &public_input.class_groups_public_input.setup_parameters;

        let secp256k1_encryption_scheme_public_parameters =
            class_groups::encryption_key::PublicParameters::new_maximally_accelerated(
                secp256k1_setup_parameters.clone(),
                class_groups::EquivalenceClass::new(
                    fourth_round_output
                        .inner_protocol_public_output
                        .encryption_key,
                    secp256k1_setup_parameters.equivalence_class_public_parameters(),
                )?,
            )?;

        let ristretto_encryption_scheme_public_parameters =
            class_groups::encryption_key::PublicParameters::new_maximally_accelerated(
                public_input.ristretto_setup_parameters.clone(),
                class_groups::EquivalenceClass::new(
                    fourth_round_output.ristretto_encryption_key,
                    public_input
                        .ristretto_setup_parameters
                        .equivalence_class_public_parameters(),
                )?,
            )?;

        let secp256r1_encryption_scheme_public_parameters =
            class_groups::encryption_key::PublicParameters::new_maximally_accelerated(
                public_input.secp256r1_setup_parameters.clone(),
                class_groups::EquivalenceClass::new(
                    fourth_round_output.secp256r1_encryption_key,
                    public_input
                        .secp256r1_setup_parameters
                        .equivalence_class_public_parameters(),
                )?,
            )?;

        let secp256k1_decryption_key_share_public_parameters =
            class_groups::Secp256k1DecryptionKeySharePublicParameters::new::<
                group::secp256k1::GroupElement,
            >(
                public_input.access_structure.threshold,
                public_input.access_structure.number_of_virtual_parties(),
                secp256k1_encryption_scheme_public_parameters
                    .setup_parameters
                    .h
                    .value(),
                fourth_round_output
                    .inner_protocol_public_output
                    .public_verification_keys
                    .clone(),
                secp256k1_encryption_scheme_public_parameters.clone(),
            )?;

        let ristretto_decryption_key_share_public_parameters =
            class_groups::RistrettoDecryptionKeySharePublicParameters::new::<
                group::ristretto::GroupElement,
            >(
                public_input.access_structure.threshold,
                public_input.access_structure.number_of_virtual_parties(),
                ristretto_encryption_scheme_public_parameters
                    .setup_parameters
                    .h
                    .value(),
                fourth_round_output
                    .ristretto_public_verification_keys
                    .clone(),
                ristretto_encryption_scheme_public_parameters.clone(),
            )?;

        let secp256r1_decryption_key_share_public_parameters =
            class_groups::Secp256r1DecryptionKeySharePublicParameters::new::<
                group::secp256r1::GroupElement,
            >(
                public_input.access_structure.threshold,
                public_input.access_structure.number_of_virtual_parties(),
                secp256r1_encryption_scheme_public_parameters
                    .setup_parameters
                    .h
                    .value(),
                fourth_round_output
                    .secp256r1_public_verification_keys
                    .clone(),
                secp256r1_encryption_scheme_public_parameters.clone(),
            )?;

        Ok(
            crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::PublicInput {
                secp256k1_encryption_of_first_secret_key_share:
                    fourth_round_output.secp256k1_encryption_of_secret_key_share_first_part,
                secp256k1_encryption_of_second_secret_key_share:
                    fourth_round_output.secp256k1_encryption_of_secret_key_share_second_part,
                secp256k1_first_public_key_share:
                    fourth_round_output.secp256k1_public_key_share_first_part,
                secp256k1_second_public_key_share:
                    fourth_round_output.secp256k1_public_key_share_second_part,
                secp256k1_encryption_scheme_public_parameters,
                secp256k1_public_verification_keys: fourth_round_output
                    .inner_protocol_public_output
                    .public_verification_keys
                    .clone(),

                ristretto_encryption_of_first_secret_key_share:
                    fourth_round_output.ristretto_encryption_of_secret_key_share_first_part,
                ristretto_encryption_of_second_secret_key_share:
                    fourth_round_output.ristretto_encryption_of_secret_key_share_second_part,
                ristretto_first_public_key_share:
                    fourth_round_output.ristretto_public_key_share_first_part.value(),
                ristretto_second_public_key_share:
                    fourth_round_output.ristretto_public_key_share_second_part.value(),
                ristretto_encryption_scheme_public_parameters: ristretto_encryption_scheme_public_parameters.clone(),
                ristretto_public_verification_keys: fourth_round_output
                    .ristretto_public_verification_keys
                    .clone(),

                curve25519_encryption_of_first_secret_key_share:
                    fourth_round_output.curve25519_encryption_of_secret_key_share_first_part,
                curve25519_encryption_of_second_secret_key_share:
                    fourth_round_output.curve25519_encryption_of_secret_key_share_second_part,
                secp256r1_encryption_of_first_secret_key_share:
                    fourth_round_output.secp256r1_encryption_of_secret_key_share_first_part,
                secp256r1_encryption_of_second_secret_key_share:
                    fourth_round_output.secp256r1_encryption_of_secret_key_share_second_part,
                secp256r1_first_public_key_share:
                    fourth_round_output.secp256r1_public_key_share_first_part,
                secp256r1_second_public_key_share:
                    fourth_round_output.secp256r1_public_key_share_second_part,
                secp256r1_encryption_scheme_public_parameters,
                secp256r1_public_verification_keys: fourth_round_output
                    .secp256r1_public_verification_keys
                    .clone(),

                // In DKG, dealers and participants are the same committee
                dealer_access_structure: public_input.access_structure.clone(),
                participating_parties_access_structure: public_input.access_structure.clone(),
                participating_and_dealers_match: true,

                secp256k1_pvss_encryption_keys_and_proofs: public_input
                    .secp256k1_pvss_encryption_keys_and_proofs
                    .clone(),
                ristretto_pvss_encryption_keys_and_proofs: public_input
                    .ristretto_pvss_encryption_keys_and_proofs
                    .clone(),
                secp256r1_pvss_encryption_keys_and_proofs: public_input
                    .secp256r1_pvss_encryption_keys_and_proofs
                    .clone(),

                secp256k1_setup_parameters: public_input
                    .class_groups_public_input
                    .setup_parameters
                    .clone(),
                ristretto_setup_parameters: public_input.ristretto_setup_parameters.clone(),
                secp256r1_setup_parameters: public_input.secp256r1_setup_parameters.clone(),

                secp256k1_decryption_key_share_public_parameters,
                ristretto_decryption_key_share_public_parameters,
                secp256r1_decryption_key_share_public_parameters,
            },
        )
    }
}
