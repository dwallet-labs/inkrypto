// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Round 3: Verification and threshold decryption.
//!
//! Each party:
//! 1. Processes accusations and verifies dealers (both EncDL and PVSS verification)
//! 2. Computes the masked secrets: E(x + r) = E(x) + sum E(r_i)
//! 3. Generates threshold decryption shares with proofs for E(x + r)

use super::{
    AccusationRoundMessage, DealingRoundMessage, PublicInput, Result,
    ThresholdDecryptionRoundMessage, CURVE25519_FIRST_SECRET_NAME, CURVE25519_SECOND_SECRET_NAME,
    RISTRETTO_FIRST_SECRET_NAME, RISTRETTO_SECOND_SECRET_NAME, SECP256K1_FIRST_SECRET_NAME,
    SECP256K1_SECOND_SECRET_NAME, SECP256R1_FIRST_SECRET_NAME, SECP256R1_SECOND_SECRET_NAME,
};
use crate::Error;
use class_groups::{
    RistrettoDecryptionKeyShare, RistrettoEncryptionKey, Secp256k1DecryptionKeyShare,
    Secp256k1EncryptionKey, Secp256r1DecryptionKeyShare, Secp256r1EncryptionKey,
    SecretKeyShareSizedInteger,
};
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::{curve25519, ristretto, secp256k1, secp256r1, CsRng, PartyID};
use itertools::multiunzip;
use std::collections::{HashMap, HashSet};

/// Executes Round 3 of the threshold encryption to sharing protocol.
///
/// Each party:
/// 1. Processes accusations and verifies dealers (both EncDL and PVSS verification)
/// 2. Computes the masked secrets: E(x + r) = E(x) + sum E(r_i)
/// 3. Generates threshold decryption shares with proofs for each masked secret
#[allow(clippy::too_many_arguments)]
pub fn advance(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: Option<PartyID>,
    decryption_key_share: SecretKeyShareSizedInteger,
    public_input: &PublicInput,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    accusation_messages: &HashMap<PartyID, AccusationRoundMessage>,
    rng: &mut impl CsRng,
) -> Result<(Vec<PartyID>, ThresholdDecryptionRoundMessage)> {
    // Step 1: Convert accusation messages to malicious_dealers_by_party format
    let malicious_dealers_by_party: HashMap<PartyID, HashSet<PartyID>> = accusation_messages
        .iter()
        .filter_map(|(&party_id, accusation)| {
            accusation
                .as_ref()
                .map(|malicious_set| (party_id, malicious_set.clone()))
        })
        .collect();

    // Step 2: Extract per-curve Dealing HashMaps and encryption scheme public parameters
    let secp256k1_encryption_scheme_public_parameters = public_input
        .secp256k1_encryption_scheme_public_parameters
        .clone();
    let ristretto_encryption_scheme_public_parameters = public_input
        .ristretto_encryption_scheme_public_parameters
        .clone();
    let secp256r1_encryption_scheme_public_parameters = public_input
        .secp256r1_encryption_scheme_public_parameters
        .clone();

    // Extract per-curve first/second Dealing structs from DealingRoundMessages
    let (
        secp256k1_first_dealings,
        secp256k1_second_dealings,
        ristretto_first_dealings,
        ristretto_second_dealings,
        curve25519_first_dealings,
        curve25519_second_dealings,
        secp256r1_first_dealings,
        secp256r1_second_dealings,
    ): (
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
    ) = multiunzip(dealing_messages.iter().map(|(&party_id, msg)| {
        (
            (
                party_id,
                msg.secp256k1_dealing_message
                    .first_randomizer_contribution_dealing
                    .clone(),
            ),
            (
                party_id,
                msg.secp256k1_dealing_message
                    .second_randomizer_contribution_dealing
                    .clone(),
            ),
            (
                party_id,
                msg.ristretto_dealing_message
                    .first_randomizer_contribution_dealing
                    .clone(),
            ),
            (
                party_id,
                msg.ristretto_dealing_message
                    .second_randomizer_contribution_dealing
                    .clone(),
            ),
            (
                party_id,
                msg.curve25519_dealing_message
                    .first_randomizer_contribution_dealing
                    .clone(),
            ),
            (
                party_id,
                msg.curve25519_dealing_message
                    .second_randomizer_contribution_dealing
                    .clone(),
            ),
            (
                party_id,
                msg.secp256r1_dealing_message
                    .first_randomizer_contribution_dealing
                    .clone(),
            ),
            (
                party_id,
                msg.secp256r1_dealing_message
                    .second_randomizer_contribution_dealing
                    .clone(),
            ),
        )
    }));

    // Step 3: Unified verification + partial decryption for each curve and secret.
    // Each call verifies dealers (EncDL + PVSS), computes E(x+r), and generates
    // decryption shares — all in one function. Malicious parties are chained through.
    let (malicious_parties, secp256k1_first_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { secp256k1::SCALAR_LIMBS },
            { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            Secp256k1DecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            secp256k1_first_dealings,
            &malicious_dealers_by_party,
            &public_input.secp256k1_pvss_encryption_keys_and_proofs,
            &public_input.secp256k1_setup_parameters,
            &secp256k1_encryption_scheme_public_parameters,
            HashSet::new(),
            SECP256K1_FIRST_SECRET_NAME,
            &secp256k1::scalar::PublicParameters::default(),
            &secp256k1::group_element::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.secp256k1_encryption_of_first_secret_key_share,
            &public_input.secp256k1_decryption_key_share_public_parameters,
            rng,
        )?;

    let (malicious_parties, secp256k1_second_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { secp256k1::SCALAR_LIMBS },
            { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
            Secp256k1DecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            secp256k1_second_dealings,
            &malicious_dealers_by_party,
            &public_input.secp256k1_pvss_encryption_keys_and_proofs,
            &public_input.secp256k1_setup_parameters,
            &secp256k1_encryption_scheme_public_parameters,
            malicious_parties,
            SECP256K1_SECOND_SECRET_NAME,
            &secp256k1::scalar::PublicParameters::default(),
            &secp256k1::group_element::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.secp256k1_encryption_of_second_secret_key_share,
            &public_input.secp256k1_decryption_key_share_public_parameters,
            rng,
        )?;

    let (malicious_parties, ristretto_first_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { ristretto::SCALAR_LIMBS },
            { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            RistrettoDecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            ristretto_first_dealings,
            &malicious_dealers_by_party,
            &public_input.ristretto_pvss_encryption_keys_and_proofs,
            &public_input.ristretto_setup_parameters,
            &ristretto_encryption_scheme_public_parameters,
            malicious_parties,
            RISTRETTO_FIRST_SECRET_NAME,
            &ristretto::scalar::PublicParameters::default(),
            &ristretto::group_element::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.ristretto_encryption_of_first_secret_key_share,
            &public_input.ristretto_decryption_key_share_public_parameters,
            rng,
        )?;

    let (malicious_parties, ristretto_second_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { ristretto::SCALAR_LIMBS },
            { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
            RistrettoDecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            ristretto_second_dealings,
            &malicious_dealers_by_party,
            &public_input.ristretto_pvss_encryption_keys_and_proofs,
            &public_input.ristretto_setup_parameters,
            &ristretto_encryption_scheme_public_parameters,
            malicious_parties,
            RISTRETTO_SECOND_SECRET_NAME,
            &ristretto::scalar::PublicParameters::default(),
            &ristretto::group_element::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.ristretto_encryption_of_second_secret_key_share,
            &public_input.ristretto_decryption_key_share_public_parameters,
            rng,
        )?;

    // Curve25519 uses RistrettoEncryptionKey/RistrettoDecryptionKeyShare (same scalar field)
    let (malicious_parties, curve25519_first_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { curve25519::SCALAR_LIMBS },
            { class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            curve25519::GroupElement,
            RistrettoEncryptionKey,
            RistrettoDecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            curve25519_first_dealings,
            &malicious_dealers_by_party,
            &public_input.ristretto_pvss_encryption_keys_and_proofs,
            &public_input.ristretto_setup_parameters,
            &ristretto_encryption_scheme_public_parameters,
            malicious_parties,
            CURVE25519_FIRST_SECRET_NAME,
            &curve25519::scalar::PublicParameters::default(),
            &curve25519::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.curve25519_encryption_of_first_secret_key_share,
            &public_input.ristretto_decryption_key_share_public_parameters,
            rng,
        )?;

    let (malicious_parties, curve25519_second_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { curve25519::SCALAR_LIMBS },
            { class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            curve25519::GroupElement,
            RistrettoEncryptionKey,
            RistrettoDecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            curve25519_second_dealings,
            &malicious_dealers_by_party,
            &public_input.ristretto_pvss_encryption_keys_and_proofs,
            &public_input.ristretto_setup_parameters,
            &ristretto_encryption_scheme_public_parameters,
            malicious_parties,
            CURVE25519_SECOND_SECRET_NAME,
            &curve25519::scalar::PublicParameters::default(),
            &curve25519::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.curve25519_encryption_of_second_secret_key_share,
            &public_input.ristretto_decryption_key_share_public_parameters,
            rng,
        )?;

    let (malicious_parties, secp256r1_first_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { secp256r1::SCALAR_LIMBS },
            { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            Secp256r1DecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            secp256r1_first_dealings,
            &malicious_dealers_by_party,
            &public_input.secp256r1_pvss_encryption_keys_and_proofs,
            &public_input.secp256r1_setup_parameters,
            &secp256r1_encryption_scheme_public_parameters,
            malicious_parties,
            SECP256R1_FIRST_SECRET_NAME,
            &secp256r1::scalar::PublicParameters::default(),
            &secp256r1::group_element::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.secp256r1_encryption_of_first_secret_key_share,
            &public_input.secp256r1_decryption_key_share_public_parameters,
            rng,
        )?;

    let (malicious_parties, secp256r1_second_decryption_shares) =
        class_groups::threshold_encryption_to_sharing::advance_partial_decryption_round_internal::<
            { secp256r1::SCALAR_LIMBS },
            { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
            Secp256r1DecryptionKeyShare,
        >(
            session_id,
            dealer_party_id,
            participating_party_id,
            secp256r1_second_dealings,
            &malicious_dealers_by_party,
            &public_input.secp256r1_pvss_encryption_keys_and_proofs,
            &public_input.secp256r1_setup_parameters,
            &secp256r1_encryption_scheme_public_parameters,
            malicious_parties,
            SECP256R1_SECOND_SECRET_NAME,
            &secp256r1::scalar::PublicParameters::default(),
            &secp256r1::group_element::PublicParameters::default(),
            &public_input.dealer_access_structure,
            &public_input.participating_parties_access_structure,
            decryption_key_share,
            public_input.secp256r1_encryption_of_second_secret_key_share,
            &public_input.secp256r1_decryption_key_share_public_parameters,
            rng,
        )?;

    // Step 4: Check authorized subset with access structure (ACS pattern)
    let malicious_dealers = malicious_parties.into_iter().deduplicate_and_sort();

    let honest_dealers_set: HashSet<PartyID> = dealing_messages
        .keys()
        .filter(|&&dealer_party_id| !malicious_dealers.contains(&dealer_party_id))
        .copied()
        .collect();

    public_input
        .dealer_access_structure
        .is_authorized_subset(&honest_dealers_set)
        .map_err(Error::from)?;

    let decryption_round_message = ThresholdDecryptionRoundMessage {
        malicious_dealers: malicious_dealers.clone(),
        secp256k1_first_decryption_shares,
        secp256k1_second_decryption_shares,
        ristretto_first_decryption_shares,
        ristretto_second_decryption_shares,
        curve25519_first_decryption_shares,
        curve25519_second_decryption_shares,
        secp256r1_first_decryption_shares,
        secp256r1_second_decryption_shares,
    };

    Ok((malicious_dealers, decryption_round_message))
}
