// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Round 2: Self-Verification (Accusation Round).
//!
//! PVSS Round 2 self-verification optimization: each party verifies ONLY the shares
//! dealt to them by checking in the exponent (faster than ZK proof verification).
//!
//! For each dealer's PVSS dealing:
//! 1. Decrypt the encrypted share to this party
//! 2. Check that decrypted share matches commitment: ∏_{j=0}^{t-1} C_j^{i^j}
//! 3. Verify EncDL proof between ciphertext and commitment
//!
//! Returns:
//! - `Some(malicious_dealers)` if party is online - dealers whose shares FAILED verification
//! - `None` if party is offline
//!
//! This sends malicious dealers (accusations) instead of verified dealers for efficiency:
//! in the happy path, most parties are honest so the malicious set is typically much smaller.

use std::collections::{HashMap, HashSet};

use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::{encryption_key, CompactIbqf, EquivalenceClass};
use commitment::CommitmentSizedNumber;
use group::{curve25519, ristretto, secp256k1, secp256r1, CsRng, GroupElement as _, PartyID};

use mpc::WeightedThresholdAccessStructure;

use super::{
    AccusationRoundMessage, DealingRoundMessage, PublicInput, Result, CURVE25519_FIRST_SECRET_NAME,
    CURVE25519_SECOND_SECRET_NAME, RISTRETTO_FIRST_SECRET_NAME, RISTRETTO_SECOND_SECRET_NAME,
    SECP256K1_FIRST_SECRET_NAME, SECP256K1_SECOND_SECRET_NAME, SECP256R1_FIRST_SECRET_NAME,
    SECP256R1_SECOND_SECRET_NAME,
};

/// Executes Round 2 of the threshold encryption to sharing protocol.
///
/// PVSS self-verification optimization: each party verifies only shares dealt to them.
/// This is faster than verifying ZK proofs and provides O(1) verification per party.
///
/// Dealers who are NOT accused here will skip ZK proof verification in Round 3.
/// This sends accusations (malicious dealers) instead of verified dealers for efficiency.
///
/// # Arguments
///
/// * `session_id` - Unique session identifier for domain separation
/// * `party_id` - This party's ID
/// * `public_input` - Protocol public input
/// * `dealing_messages` - Map of dealer ID to their Round 1 message
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
///
/// `Some(malicious_dealers)` - set of dealers whose shares FAILED verification.
pub fn advance(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    public_input: &PublicInput,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    rng: &mut impl CsRng,
) -> Result<AccusationRoundMessage> {
    // PVSS self-verification: each party verifies only the shares dealt to them.
    // This is a per-party check - each party can only verify their own encrypted shares.
    //
    // Global/public verification (EncDL proofs for encrypted randomizers) is done in the
    // decryption round, since it's deterministic and produces the same result for all parties.
    let malicious_dealers = verify_dealt_randomizer_shares(
        session_id,
        dealer_party_id,
        participating_party_id,
        public_input,
        dealing_messages,
        rng,
    )?;

    Ok(Some(malicious_dealers))
}

/// Gets malicious dealers from PVSS verification for all curves.
/// Returns the union of malicious dealers across all curves.
fn verify_dealt_randomizer_shares(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    public_input: &PublicInput,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>> {
    let (secp256k1_key_compact, _) = public_input
        .secp256k1_pvss_encryption_keys_and_proofs
        .get(&participating_party_id)
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InvalidParameters))?;

    // Get malicious dealers for secp256k1 PVSS shares (first_part and second_part)
    let malicious_dealers_secp256k1 = verify_dealt_randomizer_shares_secp256k1(
        session_id,
        dealer_party_id,
        participating_party_id,
        dealing_messages,
        public_input.secp256k1_setup_parameters.clone(),
        *secp256k1_key_compact,
        &public_input.participating_parties_access_structure,
        rng,
    )?;

    // Ristretto and curve25519 share the same scalar field, so they use the same encryption key
    let (ristretto_key_compact, _) = public_input
        .ristretto_pvss_encryption_keys_and_proofs
        .get(&participating_party_id)
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InvalidParameters))?;

    // Get malicious dealers for ristretto PVSS shares (first_part and second_part)
    let malicious_dealers_ristretto = verify_dealt_randomizer_shares_ristretto(
        session_id,
        dealer_party_id,
        participating_party_id,
        dealing_messages,
        public_input.ristretto_setup_parameters.clone(),
        *ristretto_key_compact,
        &public_input.participating_parties_access_structure,
        rng,
    )?;

    // Get malicious dealers for curve25519 PVSS shares (uses ristretto parameters)
    let malicious_dealers_curve25519 = verify_dealt_randomizer_shares_curve25519(
        session_id,
        dealer_party_id,
        participating_party_id,
        dealing_messages,
        public_input.ristretto_setup_parameters.clone(),
        *ristretto_key_compact,
        &public_input.participating_parties_access_structure,
        rng,
    )?;

    let (secp256r1_key_compact, _) = public_input
        .secp256r1_pvss_encryption_keys_and_proofs
        .get(&participating_party_id)
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InvalidParameters))?;

    // Get malicious dealers for secp256r1 PVSS shares (first_part and second_part)
    let malicious_dealers_secp256r1 = verify_dealt_randomizer_shares_secp256r1(
        session_id,
        dealer_party_id,
        participating_party_id,
        dealing_messages,
        public_input.secp256r1_setup_parameters.clone(),
        *secp256r1_key_compact,
        &public_input.participating_parties_access_structure,
        rng,
    )?;

    // Union all malicious dealers across all curves
    let malicious_dealers: HashSet<PartyID> = malicious_dealers_secp256k1
        .union(&malicious_dealers_ristretto)
        .copied()
        .collect::<HashSet<_>>()
        .union(&malicious_dealers_curve25519)
        .copied()
        .collect::<HashSet<_>>()
        .union(&malicious_dealers_secp256r1)
        .copied()
        .collect();

    Ok(malicious_dealers)
}

/// Internal function: Verify dealt randomizer shares for a single randomizer contribution.
/// Delegates to class_groups::threshold_encryption_to_sharing::advance_accusation_round_internal.
#[allow(clippy::too_many_arguments)]
fn verify_dealt_shares_for_single_randomizer_contribution_internal<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    dealing_messages: HashMap<
        PartyID,
        class_groups::publicly_verifiable_secret_sharing::small_prime::DealSecretMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    secret_name: &str,
    encryption_scheme_public_parameters: &class_groups::encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>>
where
    crypto_bigint::Int<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    class_groups::EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        group::GroupElement<
                Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                PublicParameters = class_groups::equivalence_class::PublicParameters<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            > + class_groups::equivalence_class::EquivalenceClassOps<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MultiFoldNupowAccelerator = class_groups::MultiFoldNupowAccelerator<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
    class_groups::EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = class_groups::encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = class_groups::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = class_groups::CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    class_groups::encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                class_groups::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + class_groups::encryption_key::public_parameters::Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    Ok(
        class_groups::threshold_encryption_to_sharing::advance_accusation_round_internal(
            session_id,
            dealer_party_id,
            participating_party_id,
            dealing_messages,
            &class_groups::threshold_encryption_to_sharing::pvss_base_protocol_context(secret_name),
            encryption_scheme_public_parameters,
            participating_parties_access_structure,
            scalar_public_parameters,
            group_public_parameters,
            rng,
        ),
    )
}

/// Generic internal function for verifying dealt randomizer shares for any curve.
/// Extracts first and second dealings, verifies them separately, and returns union of malicious dealers.
#[allow(clippy::too_many_arguments)]
fn verify_dealt_randomizer_shares_generic_internal<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    first_randomizer_dealing_messages: HashMap<
        PartyID,
        class_groups::publicly_verifiable_secret_sharing::small_prime::DealSecretMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    second_randomizer_dealing_messages: HashMap<
        PartyID,
        class_groups::publicly_verifiable_secret_sharing::small_prime::DealSecretMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    setup_parameters: class_groups::setup::SetupParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    pvss_encryption_key_compact: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    first_secret_name: &str,
    second_secret_name: &str,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>>
where
    crypto_bigint::Int<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    class_groups::EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        group::GroupElement<
                Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                PublicParameters = class_groups::equivalence_class::PublicParameters<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            > + class_groups::equivalence_class::EquivalenceClassOps<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MultiFoldNupowAccelerator = class_groups::MultiFoldNupowAccelerator<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
    class_groups::EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = class_groups::encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = class_groups::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = class_groups::CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    class_groups::encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                class_groups::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + class_groups::encryption_key::public_parameters::Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    let encryption_key = EquivalenceClass::new(
        pvss_encryption_key_compact,
        setup_parameters.equivalence_class_public_parameters(),
    )?;
    let encryption_scheme_public_parameters =
        encryption_key::PublicParameters::new(setup_parameters, encryption_key)?;

    // Verify first secret
    let first_malicious = verify_dealt_shares_for_single_randomizer_contribution_internal::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >(
        session_id,
        dealer_party_id,
        participating_party_id,
        first_randomizer_dealing_messages,
        first_secret_name,
        &encryption_scheme_public_parameters,
        participating_parties_access_structure,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )?;

    // Verify second secret
    let second_malicious = verify_dealt_shares_for_single_randomizer_contribution_internal::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >(
        session_id,
        dealer_party_id,
        participating_party_id,
        second_randomizer_dealing_messages,
        second_secret_name,
        &encryption_scheme_public_parameters,
        participating_parties_access_structure,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )?;

    // Union malicious parties
    Ok(first_malicious.union(&second_malicious).copied().collect())
}

// ==================== PVSS Share Verification Functions ====================
// These functions use verify_dealt_shares() for batch PVSS verification
// Now return malicious dealers instead of verified dealers

/// Gets malicious dealers from secp256k1 PVSS shares (first_part and second_part).
fn verify_dealt_randomizer_shares_secp256k1(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    setup_parameters: class_groups::Secp256k1SetupParameters,
    pvss_encryption_key_compact: CompactIbqf<
        { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>> {
    let (first_randomizer_dealing_messages, second_randomizer_dealing_messages): (
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
    ) = dealing_messages
        .iter()
        .map(|(&party_id, msg)| {
            let dealing = &msg.secp256k1_dealing_message;
            (
                (
                    party_id,
                    dealing
                        .first_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
                (
                    party_id,
                    dealing
                        .second_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
            )
        })
        .unzip();

    verify_dealt_randomizer_shares_generic_internal::<
        { secp256k1::SCALAR_LIMBS },
        { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256k1::GroupElement,
    >(
        session_id,
        dealer_party_id,
        participating_party_id,
        first_randomizer_dealing_messages,
        second_randomizer_dealing_messages,
        setup_parameters,
        pvss_encryption_key_compact,
        participating_parties_access_structure,
        SECP256K1_FIRST_SECRET_NAME,
        SECP256K1_SECOND_SECRET_NAME,
        &secp256k1::scalar::PublicParameters::default(),
        &secp256k1::group_element::PublicParameters::default(),
        rng,
    )
}

/// Gets malicious dealers from ristretto PVSS shares (first_part and second_part).
fn verify_dealt_randomizer_shares_ristretto(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    setup_parameters: class_groups::RistrettoSetupParameters,
    pvss_encryption_key_compact: CompactIbqf<
        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>> {
    let (first_randomizer_dealing_messages, second_randomizer_dealing_messages): (
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
    ) = dealing_messages
        .iter()
        .map(|(&party_id, msg)| {
            let dealing = &msg.ristretto_dealing_message;
            (
                (
                    party_id,
                    dealing
                        .first_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
                (
                    party_id,
                    dealing
                        .second_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
            )
        })
        .unzip();

    verify_dealt_randomizer_shares_generic_internal::<
        { ristretto::SCALAR_LIMBS },
        { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        ristretto::GroupElement,
    >(
        session_id,
        dealer_party_id,
        participating_party_id,
        first_randomizer_dealing_messages,
        second_randomizer_dealing_messages,
        setup_parameters,
        pvss_encryption_key_compact,
        participating_parties_access_structure,
        RISTRETTO_FIRST_SECRET_NAME,
        RISTRETTO_SECOND_SECRET_NAME,
        &ristretto::scalar::PublicParameters::default(),
        &ristretto::group_element::PublicParameters::default(),
        rng,
    )
}

/// Gets malicious dealers from curve25519 PVSS shares (first_part and second_part).
/// Note: curve25519 uses ristretto encryption parameters since they share the same scalar field.
fn verify_dealt_randomizer_shares_curve25519(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    setup_parameters: class_groups::Curve25519SetupParameters,
    pvss_encryption_key_compact: CompactIbqf<
        { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>> {
    let (first_randomizer_dealing_messages, second_randomizer_dealing_messages): (
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
    ) = dealing_messages
        .iter()
        .map(|(&party_id, msg)| {
            let dealing = &msg.curve25519_dealing_message;
            (
                (
                    party_id,
                    dealing
                        .first_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
                (
                    party_id,
                    dealing
                        .second_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
            )
        })
        .unzip();

    verify_dealt_randomizer_shares_generic_internal::<
        { curve25519::SCALAR_LIMBS },
        { class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        curve25519::GroupElement,
    >(
        session_id,
        dealer_party_id,
        participating_party_id,
        first_randomizer_dealing_messages,
        second_randomizer_dealing_messages,
        setup_parameters,
        pvss_encryption_key_compact,
        participating_parties_access_structure,
        CURVE25519_FIRST_SECRET_NAME,
        CURVE25519_SECOND_SECRET_NAME,
        &curve25519::scalar::PublicParameters::default(),
        &curve25519::PublicParameters::default(),
        rng,
    )
}

/// Gets malicious dealers from secp256r1 PVSS shares (first_part and second_part).
fn verify_dealt_randomizer_shares_secp256r1(
    session_id: CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    dealing_messages: &HashMap<PartyID, DealingRoundMessage>,
    setup_parameters: class_groups::Secp256r1SetupParameters,
    pvss_encryption_key_compact: CompactIbqf<
        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    rng: &mut impl CsRng,
) -> Result<HashSet<PartyID>> {
    let (first_randomizer_dealing_messages, second_randomizer_dealing_messages): (
        HashMap<PartyID, _>,
        HashMap<PartyID, _>,
    ) = dealing_messages
        .iter()
        .map(|(&party_id, msg)| {
            let dealing = &msg.secp256r1_dealing_message;
            (
                (
                    party_id,
                    dealing
                        .first_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
                (
                    party_id,
                    dealing
                        .second_randomizer_contribution_dealing
                        .randomizer_contribution_dealing_message
                        .clone(),
                ),
            )
        })
        .unzip();

    verify_dealt_randomizer_shares_generic_internal::<
        { secp256r1::SCALAR_LIMBS },
        { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256r1::GroupElement,
    >(
        session_id,
        dealer_party_id,
        participating_party_id,
        first_randomizer_dealing_messages,
        second_randomizer_dealing_messages,
        setup_parameters,
        pvss_encryption_key_compact,
        participating_parties_access_structure,
        SECP256R1_FIRST_SECRET_NAME,
        SECP256R1_SECOND_SECRET_NAME,
        &secp256r1::scalar::PublicParameters::default(),
        &secp256r1::group_element::PublicParameters::default(),
        rng,
    )
}
