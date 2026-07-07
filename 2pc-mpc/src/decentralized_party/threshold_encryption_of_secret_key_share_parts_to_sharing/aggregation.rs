// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Round 4: Aggregation.
//!
//! Each party:
//! 1. Verifies and combines decryption shares to recover (x + r)
//! 2. Aggregates VSS shares: [r]_i = sum [r_j]_i
//! 3. Computes final Shamir shares: [x]_i = (x + r) - [r]_i

use std::collections::{HashMap, HashSet};

use class_groups::{
    RistrettoDecryptionKeyShare, RistrettoEncryptionKey, Secp256k1DecryptionKeyShare,
    Secp256k1EncryptionKey, Secp256r1DecryptionKeyShare, Secp256r1EncryptionKey,
};
use group::helpers::DeduplicateAndSort;
use group::{curve25519, ristretto, secp256k1, secp256r1, CsRng, GroupElement, PartyID};
use itertools::multiunzip;
use mpc::MajorityVote;

use super::{
    DealingRoundMessage, PublicInput, PublicOutput, Result, ThresholdDecryptionRoundMessage,
};

/// Per-curve recovered masked secret key share parts (first_secret, second_secret).
struct RecoveredMaskedSecretKeyShareParts {
    secp256k1_first_masked_secret_key_share_part: secp256k1::Scalar,
    secp256k1_second_masked_secret_key_share_part: secp256k1::Scalar,
    ristretto_first_masked_secret_key_share_part: ristretto::Scalar,
    ristretto_second_masked_secret_key_share_part: ristretto::Scalar,
    curve25519_first_masked_secret_key_share_part: curve25519::Scalar,
    curve25519_second_masked_secret_key_share_part: curve25519::Scalar,
    secp256r1_first_masked_secret_key_share_part: secp256r1::Scalar,
    secp256r1_second_masked_secret_key_share_part: secp256r1::Scalar,
}

/// Executes Round 4 of the threshold encryption to sharing protocol.
///
/// 1. Determines consensus malicious dealers via weighted majority vote on Round 3 messages
/// 2. Combines decryption shares to recover (x + r) for each secret
/// 3. Computes polynomial commitments and public output
///
/// Parties decrypt their shares individually later via `decrypt_*_secret_key_shares()`.
#[allow(clippy::too_many_arguments)]
pub fn advance(
    public_input: &PublicInput,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    decryption_messages: &HashMap<PartyID, ThresholdDecryptionRoundMessage>,
    rng: &mut impl CsRng,
) -> Result<(Vec<PartyID>, PublicOutput)> {
    // Step 1: Determine consensus malicious dealers via weighted majority vote.
    // Each party reported their malicious_dealers in the ThresholdDecryptionRoundMessage.
    let malicious_dealers_votes: HashMap<PartyID, Vec<PartyID>> = decryption_messages
        .iter()
        .map(|(&party_id, msg)| (party_id, msg.malicious_dealers.clone()))
        .collect();

    let (malicious_voters, malicious_dealers) =
        malicious_dealers_votes.weighted_majority_vote(&public_input.dealer_access_structure)?;

    // Step 2: Determine honest dealers and check ACS
    let malicious_dealers: HashSet<PartyID> = malicious_dealers.iter().copied().collect();

    let honest_dealers: Vec<PartyID> = dealing_messages
        .keys()
        .filter(|id| !malicious_dealers.contains(id))
        .copied()
        .deduplicate_and_sort();

    let honest_dealers_set: HashSet<PartyID> = honest_dealers.iter().copied().collect();

    public_input
        .dealer_access_structure
        .is_authorized_subset(&honest_dealers_set)
        .map_err(crate::Error::from)?;

    // Step 3: Extract per-curve first/second Dealings from DealingRoundMessages
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

    let secp256k1_encryption_scheme_public_parameters = public_input
        .secp256k1_encryption_scheme_public_parameters
        .clone();
    let ristretto_encryption_scheme_public_parameters = public_input
        .ristretto_encryption_scheme_public_parameters
        .clone();
    let secp256r1_encryption_scheme_public_parameters = public_input
        .secp256r1_encryption_scheme_public_parameters
        .clone();

    // Step 4: Extract decryption shares with proofs
    let secp256k1_first_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.secp256k1_first_decryption_shares
        });
    let secp256k1_second_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.secp256k1_second_decryption_shares
        });
    let ristretto_first_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.ristretto_first_decryption_shares
        });
    let ristretto_second_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.ristretto_second_decryption_shares
        });
    let curve25519_first_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.curve25519_first_decryption_shares
        });
    let curve25519_second_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.curve25519_second_decryption_shares
        });
    let secp256r1_first_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.secp256r1_first_decryption_shares
        });
    let secp256r1_second_decryption_shares =
        extract_decryption_shares_for_curve(decryption_messages, |msg| {
            &msg.secp256r1_second_decryption_shares
        });

    // Step 5: Combine decryption shares to recover (x + r) for each secret
    let (
        secp256k1_first_malicious_decrypters,
        secp256k1_first_masked_secret_key_share_part,
        secp256k1_first_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { secp256k1::SCALAR_LIMBS },
        { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256k1::GroupElement,
        Secp256k1EncryptionKey,
        Secp256k1DecryptionKeyShare,
    >(
        secp256k1_first_dealings,
        &malicious_dealers,
        public_input.secp256k1_encryption_of_first_secret_key_share,
        &secp256k1_encryption_scheme_public_parameters,
        secp256k1_first_decryption_shares,
        &public_input.secp256k1_decryption_key_share_public_parameters,
        &secp256k1::group_element::PublicParameters::default(),
        rng,
    )?;

    let (
        secp256k1_second_malicious_decrypters,
        secp256k1_second_masked_secret_key_share_part,
        secp256k1_second_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { secp256k1::SCALAR_LIMBS },
        { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256k1::GroupElement,
        Secp256k1EncryptionKey,
        Secp256k1DecryptionKeyShare,
    >(
        secp256k1_second_dealings,
        &malicious_dealers,
        public_input.secp256k1_encryption_of_second_secret_key_share,
        &secp256k1_encryption_scheme_public_parameters,
        secp256k1_second_decryption_shares,
        &public_input.secp256k1_decryption_key_share_public_parameters,
        &secp256k1::group_element::PublicParameters::default(),
        rng,
    )?;

    let (
        ristretto_first_malicious_decrypters,
        ristretto_first_masked_secret_key_share_part,
        ristretto_first_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { ristretto::SCALAR_LIMBS },
        { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        ristretto::GroupElement,
        RistrettoEncryptionKey,
        RistrettoDecryptionKeyShare,
    >(
        ristretto_first_dealings,
        &malicious_dealers,
        public_input.ristretto_encryption_of_first_secret_key_share,
        &ristretto_encryption_scheme_public_parameters,
        ristretto_first_decryption_shares,
        &public_input.ristretto_decryption_key_share_public_parameters,
        &ristretto::group_element::PublicParameters::default(),
        rng,
    )?;

    let (
        ristretto_second_malicious_decrypters,
        ristretto_second_masked_secret_key_share_part,
        ristretto_second_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { ristretto::SCALAR_LIMBS },
        { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        ristretto::GroupElement,
        RistrettoEncryptionKey,
        RistrettoDecryptionKeyShare,
    >(
        ristretto_second_dealings,
        &malicious_dealers,
        public_input.ristretto_encryption_of_second_secret_key_share,
        &ristretto_encryption_scheme_public_parameters,
        ristretto_second_decryption_shares,
        &public_input.ristretto_decryption_key_share_public_parameters,
        &ristretto::group_element::PublicParameters::default(),
        rng,
    )?;

    // Curve25519 uses RistrettoEncryptionKey/RistrettoDecryptionKeyShare (same scalar field)
    let (
        curve25519_first_malicious_decrypters,
        curve25519_first_masked_secret_key_share_part,
        curve25519_first_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { curve25519::SCALAR_LIMBS },
        { class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        curve25519::GroupElement,
        RistrettoEncryptionKey,
        RistrettoDecryptionKeyShare,
    >(
        curve25519_first_dealings,
        &malicious_dealers,
        public_input.curve25519_encryption_of_first_secret_key_share,
        &ristretto_encryption_scheme_public_parameters,
        curve25519_first_decryption_shares,
        &public_input.ristretto_decryption_key_share_public_parameters,
        &curve25519::PublicParameters::default(),
        rng,
    )?;

    let (
        curve25519_second_malicious_decrypters,
        curve25519_second_masked_secret_key_share_part,
        curve25519_second_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { curve25519::SCALAR_LIMBS },
        { class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        curve25519::GroupElement,
        RistrettoEncryptionKey,
        RistrettoDecryptionKeyShare,
    >(
        curve25519_second_dealings,
        &malicious_dealers,
        public_input.curve25519_encryption_of_second_secret_key_share,
        &ristretto_encryption_scheme_public_parameters,
        curve25519_second_decryption_shares,
        &public_input.ristretto_decryption_key_share_public_parameters,
        &curve25519::PublicParameters::default(),
        rng,
    )?;

    let (
        secp256r1_first_malicious_decrypters,
        secp256r1_first_masked_secret_key_share_part,
        secp256r1_first_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { secp256r1::SCALAR_LIMBS },
        { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256r1::GroupElement,
        Secp256r1EncryptionKey,
        Secp256r1DecryptionKeyShare,
    >(
        secp256r1_first_dealings,
        &malicious_dealers,
        public_input.secp256r1_encryption_of_first_secret_key_share,
        &secp256r1_encryption_scheme_public_parameters,
        secp256r1_first_decryption_shares,
        &public_input.secp256r1_decryption_key_share_public_parameters,
        &secp256r1::group_element::PublicParameters::default(),
        rng,
    )?;

    let (
        secp256r1_second_malicious_decrypters,
        secp256r1_second_masked_secret_key_share_part,
        secp256r1_second_secret_polynomial_commitments,
    ) = class_groups::threshold_encryption_to_sharing::combine_decryption_shares_of_masked_secret::<
        { secp256r1::SCALAR_LIMBS },
        { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256r1::GroupElement,
        Secp256r1EncryptionKey,
        Secp256r1DecryptionKeyShare,
    >(
        secp256r1_second_dealings,
        &malicious_dealers,
        public_input.secp256r1_encryption_of_second_secret_key_share,
        &secp256r1_encryption_scheme_public_parameters,
        secp256r1_second_decryption_shares,
        &public_input.secp256r1_decryption_key_share_public_parameters,
        &secp256r1::group_element::PublicParameters::default(),
        rng,
    )?;

    let masked_secret_key_share_parts = RecoveredMaskedSecretKeyShareParts {
        secp256k1_first_masked_secret_key_share_part,
        secp256k1_second_masked_secret_key_share_part,
        ristretto_first_masked_secret_key_share_part,
        ristretto_second_masked_secret_key_share_part,
        curve25519_first_masked_secret_key_share_part,
        curve25519_second_masked_secret_key_share_part,
        secp256r1_first_masked_secret_key_share_part,
        secp256r1_second_masked_secret_key_share_part,
    };

    // Step 6: Extract randomizer dealings from honest dealers only
    let (
        secp256k1_randomizer_dealings,
        ristretto_randomizer_dealings,
        curve25519_randomizer_dealings,
        secp256r1_randomizer_dealings,
    ): (HashMap<_, _>, HashMap<_, _>, HashMap<_, _>, HashMap<_, _>) =
        multiunzip(honest_dealers.iter().filter_map(|&dealer_party_id| {
            let dealing_msg = dealing_messages.get(&dealer_party_id)?;
            Some((
                (
                    dealer_party_id,
                    dealing_msg.secp256k1_dealing_message.clone(),
                ),
                (
                    dealer_party_id,
                    dealing_msg.ristretto_dealing_message.clone(),
                ),
                (
                    dealer_party_id,
                    dealing_msg.curve25519_dealing_message.clone(),
                ),
                (
                    dealer_party_id,
                    dealing_msg.secp256r1_dealing_message.clone(),
                ),
            ))
        }));

    // Step 7: Compute polynomial commitments and public key share commitments
    let public_output = compute_public_output(
        &masked_secret_key_share_parts,
        secp256k1_first_secret_polynomial_commitments,
        secp256k1_second_secret_polynomial_commitments,
        ristretto_first_secret_polynomial_commitments,
        ristretto_second_secret_polynomial_commitments,
        curve25519_first_secret_polynomial_commitments,
        curve25519_second_secret_polynomial_commitments,
        secp256r1_first_secret_polynomial_commitments,
        secp256r1_second_secret_polynomial_commitments,
        secp256k1_randomizer_dealings,
        ristretto_randomizer_dealings,
        curve25519_randomizer_dealings,
        secp256r1_randomizer_dealings,
    )?;

    let malicious_parties = malicious_voters
        .into_iter()
        .chain(malicious_dealers)
        .chain(secp256k1_first_malicious_decrypters)
        .chain(secp256k1_second_malicious_decrypters)
        .chain(ristretto_first_malicious_decrypters)
        .chain(ristretto_second_malicious_decrypters)
        .chain(curve25519_first_malicious_decrypters)
        .chain(curve25519_second_malicious_decrypters)
        .chain(secp256r1_first_malicious_decrypters)
        .chain(secp256r1_second_malicious_decrypters)
        .deduplicate_and_sort();

    Ok((malicious_parties, public_output))
}

/// Extracts decryption shares with proofs for a specific curve and secret from all parties.
///
/// Each party's message contains a single `CurveDecryptionSharesWithProof` per secret.
/// The tangible party ID is used as the decryption share key (equals virtual party ID
/// under uniform access structure).
fn extract_decryption_shares_for_curve<F>(
    decryption_messages: &HashMap<PartyID, ThresholdDecryptionRoundMessage>,
    get_curve_shares: F,
) -> HashMap<PartyID, super::CurveDecryptionSharesWithProof>
where
    F: Fn(&ThresholdDecryptionRoundMessage) -> &super::CurveDecryptionSharesWithProof,
{
    decryption_messages
        .iter()
        .map(|(&party_id, msg)| (party_id, get_curve_shares(msg).clone()))
        .collect()
}

/// Computes the full PublicOutput including:
/// - Public key share commitments (from secret key polynomial commitments at x=0)
/// - Secret key polynomial commitments (already transformed from randomizer commitments
///   by `combine_decryption_shares_of_masked_secret`)
/// - PVSS dealings (for parties to decrypt their shares later)
/// - Masked secrets (x + r)
#[allow(clippy::too_many_arguments)]
fn compute_public_output(
    masked_secret_key_share_parts: &RecoveredMaskedSecretKeyShareParts,
    secp256k1_first_secret_polynomial_commitments: Vec<group::Value<secp256k1::GroupElement>>,
    secp256k1_second_secret_polynomial_commitments: Vec<group::Value<secp256k1::GroupElement>>,
    ristretto_first_secret_polynomial_commitments: Vec<group::Value<ristretto::GroupElement>>,
    ristretto_second_secret_polynomial_commitments: Vec<group::Value<ristretto::GroupElement>>,
    curve25519_first_secret_polynomial_commitments: Vec<group::Value<curve25519::GroupElement>>,
    curve25519_second_secret_polynomial_commitments: Vec<group::Value<curve25519::GroupElement>>,
    secp256r1_first_secret_polynomial_commitments: Vec<group::Value<secp256r1::GroupElement>>,
    secp256r1_second_secret_polynomial_commitments: Vec<group::Value<secp256r1::GroupElement>>,
    secp256k1_randomizer_dealings: HashMap<PartyID, super::Secp256k1CurveDealing>,
    ristretto_randomizer_dealings: HashMap<PartyID, super::RistrettoCurveDealing>,
    curve25519_randomizer_dealings: HashMap<PartyID, super::Curve25519CurveDealing>,
    secp256r1_randomizer_dealings: HashMap<PartyID, super::Secp256r1CurveDealing>,
) -> Result<PublicOutput> {
    // Extract public key shares from secret key polynomial commitments.
    // Public key share = constant term (s_0 = x * G is the public key share commitment).
    let secp256k1_first_public_key_share = secp256k1_first_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;
    let secp256k1_second_public_key_share = secp256k1_second_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;
    let ristretto_first_public_key_share = ristretto_first_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;
    let ristretto_second_public_key_share = ristretto_second_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;
    let curve25519_first_public_key_share = curve25519_first_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;
    let curve25519_second_public_key_share = curve25519_second_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;
    let secp256r1_first_public_key_share = secp256r1_first_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;
    let secp256r1_second_public_key_share = secp256r1_second_secret_polynomial_commitments
        .first()
        .copied()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;

    Ok(PublicOutput {
        secp256k1_first_public_key_share,
        secp256k1_second_public_key_share,
        secp256k1_first_secret_polynomial_commitments,
        secp256k1_second_secret_polynomial_commitments,
        ristretto_first_public_key_share,
        ristretto_second_public_key_share,
        ristretto_first_secret_polynomial_commitments,
        ristretto_second_secret_polynomial_commitments,
        curve25519_first_public_key_share,
        curve25519_second_public_key_share,
        curve25519_first_secret_polynomial_commitments,
        curve25519_second_secret_polynomial_commitments,
        secp256r1_first_public_key_share,
        secp256r1_second_public_key_share,
        secp256r1_first_secret_polynomial_commitments,
        secp256r1_second_secret_polynomial_commitments,
        // PVSS dealings for parties to decrypt their shares later
        secp256k1_randomizer_dealings,
        ristretto_randomizer_dealings,
        curve25519_randomizer_dealings,
        secp256r1_randomizer_dealings,
        // Masked secrets (x + r) - safe to store publicly since r masks x
        secp256k1_first_masked_secret_key_share_part: masked_secret_key_share_parts
            .secp256k1_first_masked_secret_key_share_part
            .value(),
        secp256k1_second_masked_secret_key_share_part: masked_secret_key_share_parts
            .secp256k1_second_masked_secret_key_share_part
            .value(),
        ristretto_first_masked_secret_key_share_part: masked_secret_key_share_parts
            .ristretto_first_masked_secret_key_share_part
            .value(),
        ristretto_second_masked_secret_key_share_part: masked_secret_key_share_parts
            .ristretto_second_masked_secret_key_share_part
            .value(),
        curve25519_first_masked_secret_key_share_part: masked_secret_key_share_parts
            .curve25519_first_masked_secret_key_share_part
            .value(),
        curve25519_second_masked_secret_key_share_part: masked_secret_key_share_parts
            .curve25519_second_masked_secret_key_share_part
            .value(),
        secp256r1_first_masked_secret_key_share_part: masked_secret_key_share_parts
            .secp256r1_first_masked_secret_key_share_part
            .value(),
        secp256r1_second_masked_secret_key_share_part: masked_secret_key_share_parts
            .secp256r1_second_masked_secret_key_share_part
            .value(),
    })
}
