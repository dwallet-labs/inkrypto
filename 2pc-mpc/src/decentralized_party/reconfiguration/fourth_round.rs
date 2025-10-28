// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use super::PublicInput;

use crate::decentralized_party::reconfiguration::{Message, PublicOutput};
use crate::{Error, Result};
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use class_groups::publicly_verifiable_secret_sharing::BaseProtocolContext;
use class_groups::{
    publicly_verifiable_secret_sharing, reconfiguration::RANDOMIZER_LIMBS, EquivalenceClass,
    RistrettoSetupParameters, Secp256r1SetupParameters,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use commitment::CommitmentSizedNumber;
use crypto_bigint::Int;
use group::helpers::DeduplicateAndSort;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{CsRng, GroupElement as _, PartyID, Scale};
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};
use std::collections::HashMap;

impl super::Party {
    pub(crate) fn advance_fourth_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        current_access_structure: &WeightedThresholdAccessStructure,
        equality_of_discrete_log_in_hidden_order_group_base_protocol_context: BaseProtocolContext,
        public_input: &PublicInput,
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
        threshold_decrypt_messages: HashMap<PartyID, Message>,
        current_decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        let (
            malicious_parties,
            inner_protocol_public_output,
            ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
            ristretto_encryption_key,
            secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
            secp256r1_encryption_key,
        ) = Self::advance_fourth_round_internal(
            tangible_party_id,
            session_id,
            current_access_structure,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            &public_input.class_groups_public_input,
            &public_input.ristretto_setup_parameters,
            &public_input.secp256r1_setup_parameters,
            randomizer_contribution_to_upcoming_pvss_party,
            deal_randomizer_and_prove_coefficient_commitments_messages,
            threshold_decrypt_messages,
            current_decryption_key_share_bits,
            rng,
        )?;

        let public_output = PublicOutput::new(
            inner_protocol_public_output,
            public_input.secp256k1_encryption_of_secret_key_share_first_part,
            public_input.secp256k1_encryption_of_secret_key_share_second_part,
            public_input.secp256k1_public_key_share_first_part,
            public_input.secp256k1_public_key_share_second_part,
            public_input.ristretto_encryption_of_secret_key_share_first_part,
            public_input.ristretto_encryption_of_secret_key_share_second_part,
            public_input.ristretto_public_key_share_first_part,
            public_input.ristretto_public_key_share_second_part,
            ristretto_encryption_key.value(),
            ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
            public_input.curve25519_encryption_of_secret_key_share_first_part,
            public_input.curve25519_encryption_of_secret_key_share_second_part,
            public_input.curve25519_public_key_share_first_part,
            public_input.curve25519_public_key_share_second_part,
            public_input.secp256r1_encryption_of_secret_key_share_first_part,
            public_input.secp256r1_encryption_of_secret_key_share_second_part,
            public_input.secp256r1_public_key_share_first_part,
            public_input.secp256r1_public_key_share_second_part,
            secp256r1_encryption_key.value(),
            secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
            public_input.ristretto_setup_parameters.h,
            public_input.secp256r1_setup_parameters.h,
            &public_input
                .class_groups_public_input
                .upcoming_access_structure,
        )?;

        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties,
            private_output: (),
            public_output,
        })
    }

    pub(crate) fn advance_fourth_round_internal(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        current_access_structure: &WeightedThresholdAccessStructure,
        equality_of_discrete_log_in_hidden_order_group_base_protocol_context: BaseProtocolContext,
        class_groups_public_input: &class_groups::reconfiguration::PublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<Scalar>,
        >,
        ristretto_setup_parameters: &RistrettoSetupParameters,
        secp256r1_setup_parameters: &Secp256r1SetupParameters,
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
        threshold_decrypt_messages: HashMap<PartyID, Message>,
        current_decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<(
        Vec<PartyID>,
        ::class_groups::reconfiguration::PublicOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    )> {
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

        let (
            third_round_malicious_parties,
            ristretto_randomizer_contribution_commitments,
            ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
            secp256r1_randomizer_contribution_commitments,
            secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
            threshold_decrypt_messages,
        ) = Self::handle_third_round_messages(
            current_access_structure,
            &class_groups_public_input.upcoming_access_structure,
            threshold_decrypt_messages,
            equality_of_coefficients_commitments_proofs_and_statements,
        )?;

        let (inner_protocol_malicious_parties, masked_decryption_key, inner_protocol_public_output) =
            class_groups::reconfiguration::Party::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >::advance_fourth_round_internal(
                tangible_party_id,
                current_access_structure,
                session_id,
                equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                class_groups_public_input,
                deal_randomizer_messages,
                randomizer_contribution_to_upcoming_pvss_party,
                threshold_decrypt_messages,
                current_decryption_key_share_bits,
                rng,
            )?;

        let ristretto_encryption_key = Self::compute_encryption_key(
            masked_decryption_key,
            ristretto_randomizer_contribution_commitments,
            ristretto_setup_parameters.h,
            ristretto_setup_parameters.equivalence_class_public_parameters(),
        )?;

        let secp256r1_encryption_key = Self::compute_encryption_key(
            masked_decryption_key,
            secp256r1_randomizer_contribution_commitments,
            secp256r1_setup_parameters.h,
            secp256r1_setup_parameters.equivalence_class_public_parameters(),
        )?;

        let malicious_parties: Vec<_> =
            parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages
                .into_iter()
                .chain(third_round_malicious_parties)
                .chain(inner_protocol_malicious_parties)
                .deduplicate_and_sort();

        Ok((
            malicious_parties,
            inner_protocol_public_output,
            ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
            ristretto_encryption_key,
            secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
            secp256r1_encryption_key,
        ))
    }

    pub(crate) fn compute_encryption_key(
        masked_decryption_key: Int<RANDOMIZER_LIMBS>,
        randomizer_contribution_commitments: HashMap<
            PartyID,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        public_verification_key_base: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        equivalence_class_public_parameters: &::class_groups::equivalence_class::PublicParameters<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> Result<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>> {
        let masked_decryption_key_commitment = public_verification_key_base
            .scale_vartime_accelerated(&masked_decryption_key, equivalence_class_public_parameters);

        let randomizer_commitment = randomizer_contribution_commitments
            .into_values()
            .reduce(|a, b| a.add_vartime(&b))
            .ok_or(Error::InternalError)?;

        let encryption_key = masked_decryption_key_commitment - randomizer_commitment;

        Ok(encryption_key)
    }
}
