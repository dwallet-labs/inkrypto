// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use super::PublicInput;

use crate::decentralized_party::dkg::{Message, PublicOutput};
use crate::Result;
use class_groups::dkg::compute_public_verification_keys_for_participating_party;
use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use class_groups::publicly_verifiable_secret_sharing::BaseProtocolContext;
use class_groups::{
    publicly_verifiable_secret_sharing, CiphertextSpaceValue, CompactIbqf,
    Curve25519SetupParameters, EquivalenceClass, RistrettoEncryptionSchemePublicParameters,
    RistrettoSetupParameters, Secp256k1EncryptionSchemePublicParameters, Secp256k1SetupParameters,
    Secp256r1EncryptionSchemePublicParameters, Secp256r1SetupParameters,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{curve25519, ristretto, secp256k1, secp256r1, CsRng, GroupElement as _, PartyID};
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};
use std::collections::HashMap;

impl super::Party {
    pub(crate) fn advance_fourth_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        equality_of_discrete_log_in_hidden_order_group_base_protocol_context: BaseProtocolContext,
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
        encrypt_decryption_key_shares_and_secret_key_shares_messages: HashMap<PartyID, Message>,
        secp256k1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        ristretto_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        curve25519_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        secp256r1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        let (
            malicious_parties,
            inner_protocol_public_output,
            ristretto_public_verification_keys,
            ristretto_encryption_key,
            secp256r1_public_verification_keys,
            secp256r1_encryption_key,
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
        ) = Self::advance_fourth_round_internal(
            tangible_party_id,
            session_id,
            access_structure,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            &public_input.class_groups_public_input,
            &public_input.class_groups_public_input.setup_parameters,
            &public_input.ristretto_setup_parameters,
            &public_input.curve25519_setup_parameters,
            &public_input.secp256r1_setup_parameters,
            decryption_key_contribution_pvss_party,
            deal_decryption_key_contribution_and_prove_coefficient_commitments_messages,
            encrypt_decryption_key_shares_and_secret_key_shares_messages,
            secp256k1_encryption_of_secret_key_share_base_protocol_context,
            ristretto_encryption_of_secret_key_share_base_protocol_context,
            curve25519_encryption_of_secret_key_share_base_protocol_context,
            secp256r1_encryption_of_secret_key_share_base_protocol_context,
            decryption_key_share_bits,
            rng,
        )?;

        let public_output = PublicOutput::new(
            inner_protocol_public_output,
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            ristretto_encryption_key.value(),
            ristretto_public_verification_keys,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
            secp256r1_encryption_key.value(),
            secp256r1_public_verification_keys,
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
        access_structure: &WeightedThresholdAccessStructure,
        encryption_of_decryption_key_base_protocol_context: BaseProtocolContext,
        class_groups_public_input: &class_groups::dkg::PublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<Scalar>,
        >,
        secp256k1_setup_parameters: &Secp256k1SetupParameters,
        ristretto_setup_parameters: &RistrettoSetupParameters,
        curve25519_setup_parameters: &Curve25519SetupParameters,
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
        encrypt_decryption_key_shares_and_secret_key_shares_messages: HashMap<PartyID, Message>,
        secp256k1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        ristretto_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        curve25519_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        secp256r1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<(
        Vec<PartyID>,
        ::class_groups::dkg::PublicOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256k1::group_element::Value,
        secp256k1::group_element::Value,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ristretto::GroupElement,
        ristretto::GroupElement,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        curve25519::GroupElement,
        curve25519::GroupElement,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256r1::group_element::Value,
        secp256r1::group_element::Value,
    )> {
        let (
            parties_sending_invalid_deal_decryption_key_contribution_and_prove_coefficient_commitments_messages,
            deal_decryption_key_contribution_messages,
            equality_of_coefficients_commitments_proofs_and_statements,
        ) = Self::handle_first_round_messages(
            &class_groups_public_input.setup_parameters,
            ristretto_setup_parameters,
            secp256r1_setup_parameters,
            deal_decryption_key_contribution_and_prove_coefficient_commitments_messages,
        )?;

        let (
            third_round_malicious_parties,
            malicious_coefficients_committers,
            ristretto_decryption_key_contribution_commitments,
            ristretto_reconstructed_commitments_to_decryption_key_contribution_sharing,
            secp256r1_decryption_key_contribution_commitments,
            secp256r1_reconstructed_commitments_to_decryption_key_contribution_sharing,
            encrypt_decryption_key_shares_messages,
            secp256k1_encryption_of_secret_key_shares_messages,
            ristretto_encryption_of_secret_key_shares_messages,
            curve25519_encryption_of_secret_key_shares_messages,
            secp256r1_encryption_of_secret_key_shares_messages,
        ) = Self::handle_third_round_messages(
            access_structure,
            encrypt_decryption_key_shares_and_secret_key_shares_messages,
            equality_of_coefficients_commitments_proofs_and_statements,
        )?;

        let (inner_protocol_malicious_parties, inner_protocol_public_output) =
            class_groups::dkg::Party::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >::advance_fourth_round_internal(
                tangible_party_id,
                session_id,
                encryption_of_decryption_key_base_protocol_context,
                access_structure,
                class_groups_public_input,
                decryption_key_contribution_pvss_party,
                deal_decryption_key_contribution_messages,
                encrypt_decryption_key_shares_messages,
                decryption_key_share_bits,
                rng,
            )?;

        let secp256k1_encryption_key = EquivalenceClass::new(
            inner_protocol_public_output.encryption_key,
            secp256k1_setup_parameters.equivalence_class_public_parameters(),
        )?;

        // Note that the decryption key contribution commitments come from `handle_third_round_messages`,
        // which already filtered ones coming from `malicious_coefficients_committers`, and thus these are only the honest commitments.
        let ristretto_encryption_key = class_groups::dkg::PublicOutput::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::compute_encryption_key(
            ristretto_decryption_key_contribution_commitments
        )?;

        let secp256r1_encryption_key = class_groups::dkg::PublicOutput::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::compute_encryption_key(
            secp256r1_decryption_key_contribution_commitments
        )?;

        let (
            malicious_encryption_of_secret_key_shares_parties,
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
        ) = Self::verify_and_aggregate_encryptions_of_secret_key_shares(
            session_id,
            access_structure,
            secp256k1_encryption_of_secret_key_share_base_protocol_context,
            ristretto_encryption_of_secret_key_share_base_protocol_context,
            curve25519_encryption_of_secret_key_share_base_protocol_context,
            secp256r1_encryption_of_secret_key_share_base_protocol_context,
            secp256k1_setup_parameters.clone(),
            ristretto_setup_parameters.clone(),
            curve25519_setup_parameters.clone(),
            secp256r1_setup_parameters.clone(),
            secp256k1_encryption_key,
            ristretto_encryption_key,
            secp256r1_encryption_key,
            secp256k1_encryption_of_secret_key_shares_messages,
            ristretto_encryption_of_secret_key_shares_messages,
            curve25519_encryption_of_secret_key_shares_messages,
            secp256r1_encryption_of_secret_key_shares_messages,
            rng,
        )?;

        let malicious_parties: Vec<_> =
            parties_sending_invalid_deal_decryption_key_contribution_and_prove_coefficient_commitments_messages
                .into_iter()
                .chain(third_round_malicious_parties.clone())
                .chain(inner_protocol_malicious_parties)
                .chain(malicious_encryption_of_secret_key_shares_parties)
                .deduplicate_and_sort();

        let ristretto_public_verification_keys = Self::compute_public_verification_keys(
            access_structure,
            malicious_coefficients_committers.clone(),
            ristretto_reconstructed_commitments_to_decryption_key_contribution_sharing,
        );

        let secp256r1_public_verification_keys = Self::compute_public_verification_keys(
            access_structure,
            malicious_coefficients_committers,
            secp256r1_reconstructed_commitments_to_decryption_key_contribution_sharing,
        );

        Ok((
            malicious_parties,
            inner_protocol_public_output,
            ristretto_public_verification_keys,
            ristretto_encryption_key,
            secp256r1_public_verification_keys,
            secp256r1_encryption_key,
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
        ))
    }

    pub(crate) fn verify_and_aggregate_encryptions_of_secret_key_shares(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        secp256k1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        ristretto_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        curve25519_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        secp256r1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        secp256k1_setup_parameters: Secp256k1SetupParameters,
        ristretto_setup_parameters: RistrettoSetupParameters,
        curve25519_setup_parameters: Curve25519SetupParameters,
        secp256r1_setup_parameters: Secp256r1SetupParameters,
        secp256k1_encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ristretto_encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256r1_encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256k1_encryption_of_secret_key_shares_messages: HashMap<PartyID, <crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
        ristretto_encryption_of_secret_key_shares_messages: HashMap<PartyID, <crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
        curve25519_encryption_of_secret_key_shares_messages: HashMap<PartyID, <crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
        secp256r1_encryption_of_secret_key_shares_messages: HashMap<PartyID, <crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
        rng: &mut impl CsRng,
    ) -> Result<(
        Vec<PartyID>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256k1::group_element::Value,
        secp256k1::group_element::Value,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ristretto::GroupElement,
        ristretto::GroupElement,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        curve25519::GroupElement,
        curve25519::GroupElement,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256r1::group_element::Value,
        secp256r1::group_element::Value,
    )> {
        let secp256k1_encryption_scheme_public_parameters =
            Secp256k1EncryptionSchemePublicParameters::new(
                secp256k1_setup_parameters,
                secp256k1_encryption_key,
            )?;

        let secp256k1_public_input = crate::dkg::encryption_of_secret_key_share::PublicInput::<
            secp256k1::scalar::PublicParameters,
            secp256k1::group_element::PublicParameters,
            Secp256k1EncryptionSchemePublicParameters,
        > {
            scalar_group_public_parameters: secp256k1::scalar::PublicParameters::default(),
            group_public_parameters: secp256k1::group_element::PublicParameters::default(),
            encryption_scheme_public_parameters: secp256k1_encryption_scheme_public_parameters,
            base_protocol_context: secp256k1_encryption_of_secret_key_share_base_protocol_context,
        };

        let (
            secp256k1_malicious_parties,
            [secp256k1_encryption_of_secret_key_share_and_public_key_share_first_part, secp256k1_encryption_of_secret_key_share_and_public_key_share_second_part],
        ) = crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty::advance_second_round(
            session_id,
            access_structure,
            &secp256k1_public_input,
            secp256k1_encryption_of_secret_key_shares_messages,
            rng,
        )?;

        let (
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_public_key_share_first_part,
        ) = secp256k1_encryption_of_secret_key_share_and_public_key_share_first_part.into();

        let (
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_second_part,
        ) = secp256k1_encryption_of_secret_key_share_and_public_key_share_second_part.into();

        let ristretto_encryption_scheme_public_parameters =
            RistrettoEncryptionSchemePublicParameters::new(
                ristretto_setup_parameters,
                ristretto_encryption_key,
            )?;

        let ristretto_public_input = crate::dkg::encryption_of_secret_key_share::PublicInput::<
            ristretto::scalar::PublicParameters,
            ristretto::group_element::PublicParameters,
            RistrettoEncryptionSchemePublicParameters,
        > {
            scalar_group_public_parameters: ristretto::scalar::PublicParameters::default(),
            group_public_parameters: ristretto::group_element::PublicParameters::default(),
            encryption_scheme_public_parameters: ristretto_encryption_scheme_public_parameters,
            base_protocol_context: ristretto_encryption_of_secret_key_share_base_protocol_context,
        };

        let (
            ristretto_malicious_parties,
            [ristretto_encryption_of_secret_key_share_and_public_key_share_first_part, ristretto_encryption_of_secret_key_share_and_public_key_share_second_part],
        ) = crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty::advance_second_round(
            session_id,
            access_structure,
            &ristretto_public_input,
            ristretto_encryption_of_secret_key_shares_messages,
            rng,
        )?;

        let (
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_public_key_share_first_part,
        ) = ristretto_encryption_of_secret_key_share_and_public_key_share_first_part.into();

        let (
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_second_part,
        ) = ristretto_encryption_of_secret_key_share_and_public_key_share_second_part.into();

        // Curve25519 and Ristretto uses the same Scalar field and thus the same encryption key.
        let curve25519_encryption_key = ristretto_encryption_key;
        let curve25519_encryption_scheme_public_parameters =
            RistrettoEncryptionSchemePublicParameters::new(
                curve25519_setup_parameters,
                curve25519_encryption_key,
            )?;

        let curve25519_public_input = crate::dkg::encryption_of_secret_key_share::PublicInput::<
            group::curve25519::scalar::PublicParameters,
            group::curve25519::PublicParameters,
            RistrettoEncryptionSchemePublicParameters,
        > {
            scalar_group_public_parameters: group::curve25519::scalar::PublicParameters::default(),
            group_public_parameters: group::curve25519::PublicParameters::default(),
            encryption_scheme_public_parameters: curve25519_encryption_scheme_public_parameters,
            base_protocol_context: curve25519_encryption_of_secret_key_share_base_protocol_context,
        };

        let (
            curve25519_malicious_parties,
            [curve25519_encryption_of_secret_key_share_and_public_key_share_first_part, curve25519_encryption_of_secret_key_share_and_public_key_share_second_part],
        ) = crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty::advance_second_round(
            session_id,
            access_structure,
            &curve25519_public_input,
            curve25519_encryption_of_secret_key_shares_messages,
            rng,
        )?;

        let (
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_public_key_share_first_part,
        ) = curve25519_encryption_of_secret_key_share_and_public_key_share_first_part.into();

        let (
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_second_part,
        ) = curve25519_encryption_of_secret_key_share_and_public_key_share_second_part.into();

        let secp256r1_encryption_scheme_public_parameters =
            Secp256r1EncryptionSchemePublicParameters::new(
                secp256r1_setup_parameters,
                secp256r1_encryption_key,
            )?;

        let secp256r1_public_input = crate::dkg::encryption_of_secret_key_share::PublicInput::<
            secp256r1::scalar::PublicParameters,
            secp256r1::group_element::PublicParameters,
            Secp256r1EncryptionSchemePublicParameters,
        > {
            scalar_group_public_parameters: secp256r1::scalar::PublicParameters::default(),
            group_public_parameters: secp256r1::group_element::PublicParameters::default(),
            encryption_scheme_public_parameters: secp256r1_encryption_scheme_public_parameters,
            base_protocol_context: secp256r1_encryption_of_secret_key_share_base_protocol_context,
        };

        let (
            secp256r1_malicious_parties,
            [secp256r1_encryption_of_secret_key_share_and_public_key_share_first_part, secp256r1_encryption_of_secret_key_share_and_public_key_share_second_part],
        ) = crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty::advance_second_round(
            session_id,
            access_structure,
            &secp256r1_public_input,
            secp256r1_encryption_of_secret_key_shares_messages,
            rng,
        )?;

        let (
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_public_key_share_first_part,
        ) = secp256r1_encryption_of_secret_key_share_and_public_key_share_first_part.into();

        let (
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_second_part,
        ) = secp256r1_encryption_of_secret_key_share_and_public_key_share_second_part.into();

        let malicious_parties = secp256k1_malicious_parties
            .into_iter()
            .chain(ristretto_malicious_parties)
            .chain(curve25519_malicious_parties)
            .chain(secp256r1_malicious_parties)
            .deduplicate_and_sort();

        Ok((
            malicious_parties,
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
        ))
    }

    /// Sum the commitments to each receiving virtual party to get its public verification key.
    /// Note:
    /// * `reconstructed_commitments_to_sharing` is keyed by *virtual* participant party id.
    pub(crate) fn compute_public_verification_keys(
        access_structure: &WeightedThresholdAccessStructure,
        malicious_coefficients_committers: Vec<PartyID>,
        reconstructed_commitments_to_sharing: HashMap<
            PartyID,
            HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    ) -> HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>> {
        // Filter malicious parties out.
        let reconstructed_commitments_to_sharing: HashMap<_, _> =
            reconstructed_commitments_to_sharing
                .into_iter()
                .filter(|(dealer_party_id, _)| {
                    !malicious_coefficients_committers.contains(dealer_party_id)
                })
                .collect();

        access_structure
            .party_to_virtual_parties()
            .keys()
            .flat_map(|participating_tangible_party_id| {
                compute_public_verification_keys_for_participating_party(
                    access_structure,
                    reconstructed_commitments_to_sharing.clone(),
                    participating_tangible_party_id,
                )
                .ok()
            })
            .flatten()
            .map(|(party_id, public_verification_key)| (party_id, public_verification_key.value()))
            .collect()
    }
}
