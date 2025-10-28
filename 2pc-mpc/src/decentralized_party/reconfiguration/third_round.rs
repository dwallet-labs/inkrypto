// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use class_groups::{
    publicly_verifiable_secret_sharing, EquivalenceClass, RistrettoSetupParameters,
    Secp256r1SetupParameters, SecretKeyShareSizedInteger,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::direct_product::ThreeWayGroupElement;
use group::helpers::DeduplicateAndSort;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{CsRng, PartyID};
use mpc::{
    AsynchronousRoundResult, HandleInvalidMessages, MajorityVote, WeightedThresholdAccessStructure,
};

use crate::decentralized_party::reconfiguration::{Message, PublicOutput};
use crate::languages::EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters;
use crate::{decentralized_party::dkg, Error, Result};

use super::{EqualityOfCoefficientsCommitmentsProof, PublicInput};

impl super::Party {
    pub(crate) fn advance_third_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        randomizer_contribution_to_threshold_encryption_key_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        current_access_structure: &WeightedThresholdAccessStructure,
        equality_of_discrete_log_in_hidden_order_group_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        public_input: &PublicInput,
        equality_of_coefficients_commitments_language_public_parameters: EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_randomizer_and_prove_coefficient_commitments_messages: HashMap<PartyID, Message>,
        verified_dealers_messages: HashMap<PartyID, Message>,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        equality_of_coefficients_commitments_base_protocol_context: crate::BaseProtocolContext,
        current_decryption_key_share_bits: u32,
        randomizer_contribution_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        Self::advance_third_round_internal(
            tangible_party_id,
            session_id,
            randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
            current_access_structure,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            &public_input.class_groups_public_input,
            &public_input.ristretto_setup_parameters,
            &public_input.secp256r1_setup_parameters,
            equality_of_coefficients_commitments_language_public_parameters,
            randomizer_contribution_to_upcoming_pvss_party,
            deal_randomizer_and_prove_coefficient_commitments_messages,
            verified_dealers_messages,
            decryption_key_shares,
            equality_of_coefficients_commitments_base_protocol_context,
            current_decryption_key_share_bits,
            randomizer_contribution_bits,
            rng,
        )
        .map(
            |(malicious_parties, message)| AsynchronousRoundResult::Advance {
                malicious_parties,
                message,
            },
        )
    }

    pub(crate) fn advance_third_round_internal(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        randomizer_contribution_to_threshold_encryption_key_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        current_access_structure: &WeightedThresholdAccessStructure,
        equality_of_discrete_log_in_hidden_order_group_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        class_groups_public_input: &class_groups::reconfiguration::PublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<Scalar>,
        >,
        ristretto_setup_parameters: &RistrettoSetupParameters,
        secp256r1_setup_parameters: &Secp256r1SetupParameters,
        equality_of_coefficients_commitments_language_public_parameters: EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        deal_randomizer_and_prove_coefficient_commitments_messages: HashMap<PartyID, Message>,
        verified_dealers_messages: HashMap<PartyID, Message>,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        equality_of_coefficients_commitments_base_protocol_context: crate::BaseProtocolContext,
        current_decryption_key_share_bits: u32,
        randomizer_contribution_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Message)> {
        let (
            parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
            deal_randomizer_messages,
            equality_of_coefficients_commitments_proofs_and_statements,
        ) = Self::handle_first_round_messages(
            &class_groups_public_input.setup_parameters,
            ristretto_setup_parameters,
            secp256r1_setup_parameters,
            deal_randomizer_and_prove_coefficient_commitments_messages,
        )?;

        let (parties_sending_invalid_verified_dealers_messages, verified_dealers_messages) =
            Self::handle_second_round_messages(verified_dealers_messages)?;

        let coefficient_committers: HashSet<PartyID> =
            equality_of_coefficients_commitments_proofs_and_statements
                .keys()
                .copied()
                .collect();

        let malicious_coefficient_committers =
            dkg::Party::verify_equality_of_coefficients_commitments(
                session_id,
                &class_groups_public_input.upcoming_access_structure,
                equality_of_coefficients_commitments_base_protocol_context,
                equality_of_coefficients_commitments_language_public_parameters,
                &equality_of_coefficients_commitments_proofs_and_statements,
            );

        let (
            inner_protocol_malicious_parties,
            malicious_randomizer_dealers,
            masked_decryption_key_decryption_shares_and_proofs,
            prove_public_verification_keys_messages,
        ) = class_groups::reconfiguration::Party::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::advance_third_round_internal(
            tangible_party_id,
            session_id,
            randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
            current_access_structure,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            class_groups_public_input,
            deal_randomizer_messages,
            randomizer_contribution_to_upcoming_pvss_party,
            verified_dealers_messages,
            decryption_key_shares,
            current_decryption_key_share_bits,
            randomizer_contribution_bits,
            malicious_coefficient_committers,
            rng,
        )?;

        let malicious_parties =
            parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages
                .into_iter()
                .chain(parties_sending_invalid_verified_dealers_messages)
                .chain(inner_protocol_malicious_parties)
                .deduplicate_and_sort();

        let malicious_coefficients_committers = malicious_parties.iter().copied().collect();

        let honest_committers: HashSet<_> = coefficient_committers
            .difference(&malicious_coefficients_committers)
            .copied()
            .collect();

        current_access_structure.is_authorized_subset(&honest_committers)?;

        let message = Message::ThresholdDecryptShares {
            malicious_coefficients_committers,
            threshold_decrypt_message:
                class_groups::reconfiguration::Message::ThresholdDecryptShares {
                    malicious_randomizer_dealers,
                    masked_decryption_key_decryption_shares_and_proofs,
                    prove_public_verification_keys_messages,
                },
        };

        Ok((malicious_parties, message))
    }

    pub(crate) fn handle_third_round_messages(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        threshold_decrypt_messages: HashMap<PartyID, Message>,
        equality_of_coefficients_commitments_proofs_and_statements: HashMap<
            PartyID,
            (
                EqualityOfCoefficientsCommitmentsProof,
                Vec<
                    ThreeWayGroupElement<
                        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    >,
                >,
            ),
        >,
    ) -> Result<(
        Vec<PartyID>,
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        HashMap<
            PartyID,
            class_groups::reconfiguration::Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    )> {
        // Make sure everyone sent the third round message.
        let (parties_sending_invalid_threshold_decrypt_messages, threshold_decrypt_messages) =
            threshold_decrypt_messages
                .into_iter()
                .map(|(dealer_party_id, message)| {
                    let res = match message {
                        Message::ThresholdDecryptShares {
                            malicious_coefficients_committers,
                            threshold_decrypt_message,
                        } => Ok((
                            malicious_coefficients_committers.deduplicate_and_sort(),
                            threshold_decrypt_message,
                        )),
                        _ => Err(Error::InvalidMessage),
                    };

                    (dealer_party_id, res)
                })
                .handle_invalid_messages_async();

        let (malicious_coefficients_committers, threshold_decrypt_messages): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = threshold_decrypt_messages
            .into_iter()
            .map(
                |(
                    dealer_tangible_party_id,
                    (malicious_coefficients_committers, threshold_decrypt_message),
                )| {
                    (
                        (dealer_tangible_party_id, malicious_coefficients_committers),
                        (dealer_tangible_party_id, threshold_decrypt_message),
                    )
                },
            )
            .unzip();

        let (malicious_voters, malicious_coefficients_committers) =
            malicious_coefficients_committers.weighted_majority_vote(current_access_structure)?;

        let (
            _,
            ristretto_randomizer_contribution_commitments,
            ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
            secp256r1_randomizer_contribution_commitments,
            secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
        ) = dkg::Party::parse_coefficient_commitments(
            &malicious_coefficients_committers,
            equality_of_coefficients_commitments_proofs_and_statements,
            upcoming_access_structure,
        );

        let third_round_malicious_parties: Vec<_> =
            parties_sending_invalid_threshold_decrypt_messages
                .into_iter()
                .chain(malicious_voters)
                .deduplicate_and_sort();

        Ok((
            third_round_malicious_parties,
            ristretto_randomizer_contribution_commitments,
            ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
            secp256r1_randomizer_contribution_commitments,
            secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
            threshold_decrypt_messages,
        ))
    }
}
