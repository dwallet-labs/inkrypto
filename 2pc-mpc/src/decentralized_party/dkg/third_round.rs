// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::Uint;
use itertools::multiunzip;
use std::collections::{HashMap, HashSet};

use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES, NUM_SECRET_SHARE_PRIMES,
};
use class_groups::{
    publicly_verifiable_secret_sharing, Curve25519SetupParameters, EquivalenceClass,
    RistrettoEncryptionSchemePublicParameters, RistrettoSetupParameters,
    Secp256k1EncryptionSchemePublicParameters, Secp256k1SetupParameters,
    Secp256r1EncryptionSchemePublicParameters, Secp256r1SetupParameters,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::direct_product::ThreeWayGroupElement;
use group::helpers::DeduplicateAndSort;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{ristretto, secp256k1, secp256r1, CsRng, PartyID};
use mpc::secret_sharing::shamir::over_the_integers::factorial;
use mpc::{
    AsynchronousRoundResult, HandleInvalidMessages, MajorityVote, WeightedThresholdAccessStructure,
};

use crate::decentralized_party::dkg::{Message, PublicOutput};
use crate::languages::{
    verify_equality_of_discrete_log_proof, EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters,
};
use crate::{Error, Result};

use super::{EqualityOfCoefficientsCommitmentsProof, PublicInput};

impl super::Party {
    pub(crate) fn advance_third_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        encryption_of_decryption_key_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        access_structure: &WeightedThresholdAccessStructure,
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
        verified_dealers_messages: HashMap<PartyID, Message>,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
        equality_of_coefficients_commitments_base_protocol_context: crate::BaseProtocolContext,
        secp256k1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        ristretto_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        curve25519_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        secp256r1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        Self::advance_third_round_internal(
            tangible_party_id,
            session_id,
            encryption_of_decryption_key_base_protocol_context,
            access_structure,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            &public_input.class_groups_public_input,
            &public_input.class_groups_public_input.setup_parameters,
            &public_input.ristretto_setup_parameters,
            &public_input.curve25519_setup_parameters,
            &public_input.secp256r1_setup_parameters,
            equality_of_coefficients_commitments_language_public_parameters,
            decryption_key_contribution_pvss_party,
            deal_decryption_key_contribution_and_prove_coefficient_commitments_messages,
            verified_dealers_messages,
            decryption_key_per_crt_prime,
            equality_of_coefficients_commitments_base_protocol_context,
            secp256k1_encryption_of_secret_key_share_base_protocol_context,
            ristretto_encryption_of_secret_key_share_base_protocol_context,
            curve25519_encryption_of_secret_key_share_base_protocol_context,
            secp256r1_encryption_of_secret_key_share_base_protocol_context,
            decryption_key_share_bits,
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
        encryption_of_decryption_key_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        access_structure: &WeightedThresholdAccessStructure,
        equality_of_discrete_log_in_hidden_order_group_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
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
        equality_of_coefficients_commitments_language_public_parameters: EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
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
        verified_dealers_messages: HashMap<PartyID, Message>,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
        equality_of_coefficients_commitments_base_protocol_context: crate::BaseProtocolContext,
        secp256k1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        ristretto_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        curve25519_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        secp256r1_encryption_of_secret_key_share_base_protocol_context: crate::BaseProtocolContext,
        decryption_key_share_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Message)> {
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

        let (parties_sending_invalid_verified_dealers_messages, verified_dealers_messages) =
            Self::handle_second_round_messages(verified_dealers_messages)?;

        let coefficient_committers: HashSet<PartyID> =
            equality_of_coefficients_commitments_proofs_and_statements
                .keys()
                .copied()
                .collect();

        let malicious_coefficient_committers = Self::verify_equality_of_coefficients_commitments(
            session_id,
            access_structure,
            equality_of_coefficients_commitments_base_protocol_context,
            equality_of_coefficients_commitments_language_public_parameters,
            &equality_of_coefficients_commitments_proofs_and_statements,
        );

        let (
            inner_protocol_malicious_parties,
            malicious_decryption_key_contribution_dealers,
            encryptions_of_decryption_key_shares_and_proofs,
        ) = class_groups::dkg::Party::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::advance_third_round_internal(
            tangible_party_id,
            session_id,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            encryption_of_decryption_key_base_protocol_context,
            access_structure,
            class_groups_public_input,
            decryption_key_contribution_pvss_party,
            deal_decryption_key_contribution_messages,
            verified_dealers_messages,
            decryption_key_per_crt_prime,
            decryption_key_share_bits,
            malicious_coefficient_committers,
            rng,
        )?;

        let malicious_parties =
            parties_sending_invalid_deal_decryption_key_contribution_and_prove_coefficient_commitments_messages
                .into_iter()
                .chain(parties_sending_invalid_verified_dealers_messages)
                .chain(inner_protocol_malicious_parties)
                .deduplicate_and_sort();

        let malicious_coefficients_committers = malicious_parties.iter().copied().collect();

        let honest_committers: HashSet<_> = coefficient_committers
            .difference(&malicious_coefficients_committers)
            .copied()
            .collect();

        access_structure.is_authorized_subset(&honest_committers)?;

        let (
            secp256k1_decryption_key_contribution_commitments,
            ristretto_decryption_key_contribution_commitments,
            _,
            secp256r1_decryption_key_contribution_commitments,
            _,
        ) = Self::parse_coefficient_commitments(
            &malicious_parties,
            equality_of_coefficients_commitments_proofs_and_statements,
            access_structure,
        );

        let secp256k1_encryption_key = class_groups::dkg::PublicOutput::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::compute_encryption_key(
            secp256k1_decryption_key_contribution_commitments
        )?;

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
            secp256k1_encryption_of_secret_key_shares_message,
            ristretto_encryption_of_secret_key_shares_message,
            curve25519_encryption_of_secret_key_shares_message,
            secp256r1_encryption_of_secret_key_shares_message,
        ) = Self::encrypt_secret_key_shares(
            tangible_party_id,
            session_id,
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
            rng,
        )?;

        let message = Message::EncryptDecryptionKeySharesAndSecretKeyShares {
            malicious_coefficients_committers,
            encrypt_decryption_key_shares_message:
                class_groups::dkg::Message::EncryptDecryptionKeyShares {
                    malicious_decryption_key_contribution_dealers,
                    encryptions_of_decryption_key_shares_and_proofs,
                },
            secp256k1_encryption_of_secret_key_shares_message,
            ristretto_encryption_of_secret_key_shares_message,
            curve25519_encryption_of_secret_key_shares_message,
            secp256r1_encryption_of_secret_key_shares_message,
        };

        Ok((malicious_parties, message))
    }

    pub(crate) fn verify_equality_of_coefficients_commitments(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        equality_of_coefficients_commitments_base_protocol_context: crate::BaseProtocolContext,
        equality_of_coefficients_commitments_language_public_parameters: EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        equality_of_coefficients_commitments_proofs_and_statements: &HashMap<
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
    ) -> HashSet<PartyID> {
        equality_of_coefficients_commitments_proofs_and_statements
            .iter()
            .filter_map(|(&dealer_party_id, (proof, coefficients_commitments))| {
                // Mark any party that did not send exactly `threshold` coefficient commitments as malicious.
                if coefficients_commitments.len() == usize::from(access_structure.threshold) {
                    let protocol_context =
                        equality_of_coefficients_commitments_base_protocol_context
                            .with_party_id_and_session_id(dealer_party_id, session_id);

                    if verify_equality_of_discrete_log_proof(
                        &equality_of_coefficients_commitments_language_public_parameters,
                        coefficients_commitments.clone(),
                        &protocol_context,
                        proof,
                    )
                    .is_ok()
                    {
                        None
                    } else {
                        Some(dealer_party_id)
                    }
                } else {
                    Some(dealer_party_id)
                }
            })
            .collect()
    }

    pub(crate) fn parse_coefficient_commitments(
        malicious_coefficients_committers: &[PartyID],
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
        access_structure: &WeightedThresholdAccessStructure,
    ) -> (
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
    ) {
        let n_factorial = factorial(access_structure.number_of_virtual_parties());

        multiunzip(equality_of_coefficients_commitments_proofs_and_statements
            .into_iter()
            .filter_map(|(dealer_party_id, (_, coefficients_commitments))| {
                if malicious_coefficients_committers.contains(&dealer_party_id) {
                    None
                } else {
                    let (secp256k1_coefficient_commitments, ristretto_coefficient_commitments, secp256r1_coefficient_commitments): (Vec<_>, Vec<_>, Vec<_>) = multiunzip(coefficients_commitments.into_iter().map(|coefficient_commitments| {
                        let (secp256k1_coefficient_commitment, ristretto_coefficient_commitment, secp256r1_coefficient_commitment) = coefficient_commitments.into();

                        (secp256k1_coefficient_commitment, ristretto_coefficient_commitment, secp256r1_coefficient_commitment)
                    }));

                    // Safe to dereference, we validated there are at `t` coefficients.
                    let secp256k1_secret_contribution_commitment = secp256k1_coefficient_commitments[0];

                    let ristretto_secret_contribution_contribution_commitment = ristretto_coefficient_commitments[0];
                    let ristretto_reconstructed_commitments_to_secret_contribution_sharing: HashMap<_, _> =
                        (1..=access_structure.number_of_virtual_parties()).map(|virtual_party_id| {
                            let commitment_to_share = publicly_verifiable_secret_sharing::Party::<
                                NUM_SECRET_SHARE_PRIMES,
                                SECRET_KEY_SHARE_LIMBS,
                                SECRET_KEY_SHARE_WITNESS_LIMBS,
                                SCALAR_LIMBS,
                                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                ristretto::GroupElement,
                            >::reconstruct_commitment_to_share_in_the_exponent(
                                n_factorial,
                                virtual_party_id,
                                ristretto_coefficient_commitments.clone(),
                            );

                            (virtual_party_id, commitment_to_share)
                        }).collect();

                    let secp256r1_secret_contribution_commitment = secp256r1_coefficient_commitments[0];
                    let secp256r1_reconstructed_commitments_to_secret_contribution_sharing: HashMap<_, _> =
                        (1..=access_structure.number_of_virtual_parties()).map(|virtual_party_id| {
                            let commitment_to_share = publicly_verifiable_secret_sharing::Party::<
                                NUM_SECRET_SHARE_PRIMES,
                                SECRET_KEY_SHARE_LIMBS,
                                SECRET_KEY_SHARE_WITNESS_LIMBS,
                                SCALAR_LIMBS,
                                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                secp256r1::GroupElement,
                            >::reconstruct_commitment_to_share_in_the_exponent(
                                n_factorial,
                                virtual_party_id,
                                secp256r1_coefficient_commitments.clone(),
                            );

                            (virtual_party_id, commitment_to_share)
                        }).collect();

                    Some(
                        (
                            (dealer_party_id, secp256k1_secret_contribution_commitment),
                            (dealer_party_id, ristretto_secret_contribution_contribution_commitment),
                            (dealer_party_id, ristretto_reconstructed_commitments_to_secret_contribution_sharing),
                            (dealer_party_id, secp256r1_secret_contribution_commitment),
                            (dealer_party_id, secp256r1_reconstructed_commitments_to_secret_contribution_sharing)
                        )
                    )
                }
            }))
    }

    pub(crate) fn encrypt_secret_key_shares(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
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
        rng: &mut impl CsRng,
    ) -> Result<(
        <crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        <crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        <crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        <crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
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

        let secp256k1_encryption_of_secret_key_shares_message =
            crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty::advance_first_round(
                session_id,
                tangible_party_id,
                &secp256k1_public_input,
                rng,
            )?;

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

        let ristretto_encryption_of_secret_key_shares_message =
            crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty::advance_first_round(
                session_id,
                tangible_party_id,
                &ristretto_public_input,
                rng,
            )?;

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

        let curve25519_encryption_of_secret_key_shares_message =
            crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty::advance_first_round(
                session_id,
                tangible_party_id,
                &curve25519_public_input,
                rng,
            )?;

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

        let secp256r1_encryption_of_secret_key_shares_message =
            crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty::advance_first_round(
                session_id,
                tangible_party_id,
                &secp256r1_public_input,
                rng,
            )?;

        Ok((
            secp256k1_encryption_of_secret_key_shares_message,
            ristretto_encryption_of_secret_key_shares_message,
            curve25519_encryption_of_secret_key_shares_message,
            secp256r1_encryption_of_secret_key_shares_message,
        ))
    }

    pub(crate) fn handle_third_round_messages(
        access_structure: &WeightedThresholdAccessStructure,
        encrypt_decryption_key_shares_and_secret_key_shares_messages: HashMap<PartyID, Message>,
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
        Vec<PartyID>,
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        HashMap<PartyID, HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        HashMap<
            PartyID,
            class_groups::dkg::Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        HashMap<PartyID, <crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
        HashMap<PartyID, <crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
        HashMap<PartyID, <crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
        HashMap<PartyID, <crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message>,
    )>{
        // Make sure everyone sent the third round message.
        let (
            parties_sending_invalid_encrypt_decryption_key_shares_and_secret_key_shares_messages,
            encrypt_decryption_key_shares_and_secret_key_shares_messages,
        ) = encrypt_decryption_key_shares_and_secret_key_shares_messages
            .into_iter()
            .map(|(dealer_party_id, message)| {
                let res = match message {
                    Message::EncryptDecryptionKeySharesAndSecretKeyShares {
                        malicious_coefficients_committers,
                        encrypt_decryption_key_shares_message,
                        secp256k1_encryption_of_secret_key_shares_message,
                        ristretto_encryption_of_secret_key_shares_message,
                        curve25519_encryption_of_secret_key_shares_message,
                        secp256r1_encryption_of_secret_key_shares_message,
                    } => Ok((
                        malicious_coefficients_committers.deduplicate_and_sort(),
                        encrypt_decryption_key_shares_message,
                        secp256k1_encryption_of_secret_key_shares_message,
                        ristretto_encryption_of_secret_key_shares_message,
                        curve25519_encryption_of_secret_key_shares_message,
                        secp256r1_encryption_of_secret_key_shares_message,
                    )),
                    _ => Err(Error::InvalidMessage),
                };

                (dealer_party_id, res)
            })
            .handle_invalid_messages_async();

        let (
            malicious_coefficients_committers,
            encrypt_decryption_key_shares_messages,
            secp256k1_encryption_of_secret_key_shares_messages,
            ristretto_encryption_of_secret_key_shares_messages,
            curve25519_encryption_of_secret_key_shares_messages,
            secp256r1_encryption_of_secret_key_shares_messages,
        ): (
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
            HashMap<_, _>,
        ) = multiunzip(
            encrypt_decryption_key_shares_and_secret_key_shares_messages
                .into_iter()
                .map(
                    |(
                        dealer_tangible_party_id,
                        (
                            malicious_coefficients_committers,
                            encrypt_decryption_key_shares_message,
                            secp256k1_encryption_of_secret_key_shares_message,
                            ristretto_encryption_of_secret_key_shares_message,
                            curve25519_encryption_of_secret_key_shares_message,
                            secp256r1_encryption_of_secret_key_shares_message,
                        ),
                    )| {
                        (
                            (dealer_tangible_party_id, malicious_coefficients_committers),
                            (
                                dealer_tangible_party_id,
                                encrypt_decryption_key_shares_message,
                            ),
                            (
                                dealer_tangible_party_id,
                                secp256k1_encryption_of_secret_key_shares_message,
                            ),
                            (
                                dealer_tangible_party_id,
                                ristretto_encryption_of_secret_key_shares_message,
                            ),
                            (
                                dealer_tangible_party_id,
                                curve25519_encryption_of_secret_key_shares_message,
                            ),
                            (
                                dealer_tangible_party_id,
                                secp256r1_encryption_of_secret_key_shares_message,
                            ),
                        )
                    },
                ),
        );

        let (malicious_voters, malicious_coefficients_committers) =
            malicious_coefficients_committers.weighted_majority_vote(access_structure)?;

        let (
            _,
            ristretto_decryption_key_contribution_commitments,
            ristretto_reconstructed_commitments_to_decryption_key_contribution_sharing,
            secp256r1_decryption_key_contribution_commitments,
            secp256r1_reconstructed_commitments_to_decryption_key_contribution_sharing,
        ) = Self::parse_coefficient_commitments(
            &malicious_coefficients_committers,
            equality_of_coefficients_commitments_proofs_and_statements,
            access_structure,
        );

        let third_round_malicious_parties: Vec<_> =
            parties_sending_invalid_encrypt_decryption_key_shares_and_secret_key_shares_messages
                .into_iter()
                .chain(malicious_voters)
                .deduplicate_and_sort();

        Ok((
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
        ))
    }
}
