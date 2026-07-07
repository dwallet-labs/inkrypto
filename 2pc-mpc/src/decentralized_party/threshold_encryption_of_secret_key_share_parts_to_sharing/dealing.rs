// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Round 1: Dealing randomizers.
//!
//! Each party:
//! 1. Samples randomizers for each curve's 2 secrets
//! 2. Encrypts each randomizer using the curve's encryption key
//! 3. Deals VSS shares separately for each curve

use std::collections::HashMap;

use class_groups::{
    CompactIbqf, RistrettoEncryptionSchemePublicParameters,
    Secp256k1EncryptionSchemePublicParameters, Secp256r1EncryptionSchemePublicParameters,
};
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::{curve25519, ristretto, secp256k1, secp256r1, CsRng, PartyID, Samplable};

use mpc::WeightedThresholdAccessStructure;

use class_groups::threshold_encryption_to_sharing::DealingRoundOutput;

use super::{
    Dealing, DealingRoundMessage, PublicInput, Result, CURVE25519_FIRST_SECRET_NAME,
    CURVE25519_SECOND_SECRET_NAME, RISTRETTO_FIRST_SECRET_NAME, RISTRETTO_SECOND_SECRET_NAME,
    SECP256K1_FIRST_SECRET_NAME, SECP256K1_SECOND_SECRET_NAME, SECP256R1_FIRST_SECRET_NAME,
    SECP256R1_SECOND_SECRET_NAME,
};

/// Generic internal function for dealing a single randomizer contribution.
/// Delegates to class_groups::threshold_encryption_to_sharing::advance_dealing_round_internal.
///
/// # Returns
/// Tuple of (malicious_parties, verified_encryption_keys, dealing) where verified_encryption_keys
/// can be reused for subsequent calls via `deal_single_randomizer_contribution_internal_with_preverified_keys`.
#[allow(clippy::too_many_arguments)]
fn deal_single_randomizer_contribution_internal<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    randomizer_contribution: GroupElement::Scalar,
    secret_name: &str,
    participating_and_dealers_match: bool,
    pvss_encryption_keys: &HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
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
) -> Result<
    DealingRoundOutput<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>
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
    class_groups::DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        class_groups::EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    class_groups::threshold_encryption_to_sharing::advance_dealing_round_internal(
        session_id,
        party_id,
        randomizer_contribution,
        secret_name,
        participating_and_dealers_match,
        pvss_encryption_keys,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )
    .map_err(Into::into)
}

/// Optimized variant that skips encryption key verification.
/// Use when encryption keys have already been verified by a previous call to
/// `deal_single_randomizer_contribution_internal`.
#[allow(clippy::too_many_arguments)]
fn deal_single_randomizer_contribution_internal_with_preverified_keys<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    randomizer_contribution: GroupElement::Scalar,
    secret_name: &str,
    verified_encryption_keys: HashMap<
        PartyID,
        class_groups::EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
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
) -> Result<
    Dealing<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>
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
    class_groups::DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        class_groups::EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    class_groups::threshold_encryption_to_sharing::advance_dealing_round_internal_with_preverified_encryption_keys(
        session_id,
        party_id,
        randomizer_contribution,
        secret_name,
        verified_encryption_keys,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )
    .map_err(Into::into)
}

/// Generic internal function for dealing randomizers for any curve.
fn deal_randomizers_generic_internal<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    pvss_encryption_keys: &HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
    encryption_scheme_public_parameters: &class_groups::encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    participating_and_dealers_match: bool,
    first_secret_name: &str,
    second_secret_name: &str,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<(
    Vec<PartyID>,
    super::CurveDealing<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
)>
where
    GroupElement::Scalar: group::Samplable,
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
    for<'a> &'a class_groups::encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: homomorphic_encryption::GroupsPublicParametersAccessors<
        'a,
        group::PublicParameters<GroupElement::Scalar>,
        class_groups::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        class_groups::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    class_groups::DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        class_groups::EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    // Sample secrets
    let first_randomizer_contribution =
        GroupElement::Scalar::sample(scalar_public_parameters, rng)?;
    let second_randomizer_contribution =
        GroupElement::Scalar::sample(scalar_public_parameters, rng)?;

    // Deal first randomizer contribution (verify encryption keys)
    let DealingRoundOutput {
        malicious_parties,
        verified_encryption_keys,
        dealing: first_randomizer_contribution_dealing,
    } = deal_single_randomizer_contribution_internal::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >(
        session_id,
        party_id,
        first_randomizer_contribution,
        first_secret_name,
        participating_and_dealers_match,
        pvss_encryption_keys,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )?;

    // Deal second randomizer contribution (use pre-verified encryption keys - no verification)
    let second_randomizer_contribution_dealing =
        deal_single_randomizer_contribution_internal_with_preverified_keys::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >(
            session_id,
            party_id,
            second_randomizer_contribution,
            second_secret_name,
            verified_encryption_keys,
            encryption_scheme_public_parameters,
            participating_parties_access_structure,
            scalar_public_parameters,
            group_public_parameters,
            rng,
        )?;

    Ok((
        malicious_parties,
        super::CurveDealing {
            first_randomizer_contribution_dealing,
            second_randomizer_contribution_dealing,
        },
    ))
}

/// Internal function: Deals randomizers for secp256k1, returns CurveDealing struct.
/// Can be called from other protocols (e.g., DKG, reconfiguration) for sub-protocol integration.
fn deal_randomizers_secp256k1_internal(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    pvss_encryption_keys: &HashMap<
        PartyID,
        (
            CompactIbqf<{ class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            >,
        ),
    >,
    encryption_scheme_public_parameters: &Secp256k1EncryptionSchemePublicParameters,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    participating_and_dealers_match: bool,
    rng: &mut impl CsRng,
) -> Result<(Vec<PartyID>, super::Secp256k1CurveDealing)> {
    deal_randomizers_generic_internal::<
        { secp256k1::SCALAR_LIMBS },
        { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256k1::GroupElement,
    >(
        session_id,
        party_id,
        pvss_encryption_keys,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        participating_and_dealers_match,
        SECP256K1_FIRST_SECRET_NAME,
        SECP256K1_SECOND_SECRET_NAME,
        &secp256k1::scalar::PublicParameters::default(),
        &secp256k1::group_element::PublicParameters::default(),
        rng,
    )
}

/// Internal function: Deals randomizers for ristretto, returns CurveDealing struct.
/// Can be called from other protocols (e.g., DKG, reconfiguration) for sub-protocol integration.
fn deal_randomizers_ristretto_internal(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    pvss_encryption_keys: &HashMap<
        PartyID,
        (
            CompactIbqf<{ class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            >,
        ),
    >,
    encryption_scheme_public_parameters: &RistrettoEncryptionSchemePublicParameters,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    participating_and_dealers_match: bool,
    rng: &mut impl CsRng,
) -> Result<(Vec<PartyID>, super::RistrettoCurveDealing)> {
    deal_randomizers_generic_internal::<
        { ristretto::SCALAR_LIMBS },
        { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        ristretto::GroupElement,
    >(
        session_id,
        party_id,
        pvss_encryption_keys,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        participating_and_dealers_match,
        RISTRETTO_FIRST_SECRET_NAME,
        RISTRETTO_SECOND_SECRET_NAME,
        &ristretto::scalar::PublicParameters::default(),
        &ristretto::group_element::PublicParameters::default(),
        rng,
    )
}

/// Internal function: Deals randomizers for curve25519, returns CurveDealing struct.
/// Uses ristretto parameters since they share the same scalar field.
/// Can be called from other protocols (e.g., DKG, reconfiguration) for sub-protocol integration.
fn deal_randomizers_curve25519_internal(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    pvss_encryption_keys: &HashMap<
        PartyID,
        (
            CompactIbqf<{ class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            >,
        ),
    >,
    encryption_scheme_public_parameters: &RistrettoEncryptionSchemePublicParameters,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    participating_and_dealers_match: bool,
    rng: &mut impl CsRng,
) -> Result<(Vec<PartyID>, super::Curve25519CurveDealing)> {
    deal_randomizers_generic_internal::<
        { curve25519::SCALAR_LIMBS },
        { class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        curve25519::GroupElement,
    >(
        session_id,
        party_id,
        pvss_encryption_keys,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        participating_and_dealers_match,
        CURVE25519_FIRST_SECRET_NAME,
        CURVE25519_SECOND_SECRET_NAME,
        &curve25519::scalar::PublicParameters::default(),
        &curve25519::PublicParameters::default(),
        rng,
    )
}

/// Internal function: Deals randomizers for secp256r1, returns CurveDealing struct.
/// Can be called from other protocols (e.g., DKG, reconfiguration) for sub-protocol integration.
fn deal_randomizers_secp256r1_internal(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    pvss_encryption_keys: &HashMap<
        PartyID,
        (
            CompactIbqf<{ class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            >,
        ),
    >,
    encryption_scheme_public_parameters: &Secp256r1EncryptionSchemePublicParameters,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    participating_and_dealers_match: bool,
    rng: &mut impl CsRng,
) -> Result<(Vec<PartyID>, super::Secp256r1CurveDealing)> {
    deal_randomizers_generic_internal::<
        { secp256r1::SCALAR_LIMBS },
        { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        secp256r1::GroupElement,
    >(
        session_id,
        party_id,
        pvss_encryption_keys,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        participating_and_dealers_match,
        SECP256R1_FIRST_SECRET_NAME,
        SECP256R1_SECOND_SECRET_NAME,
        &secp256r1::scalar::PublicParameters::default(),
        &secp256r1::group_element::PublicParameters::default(),
        rng,
    )
}

/// Executes Round 1 of the threshold encryption to sharing protocol.
///
/// Each party:
/// 1. Samples randomizers for each curve's 2 secrets
/// 2. Encrypts each randomizer using the curve's encryption key
/// 3. Deals PVSS shares separately for each curve (one dealing per secret)
///
/// Returns a tuple of (malicious_parties, dealing_message) where malicious_parties
/// contains parties whose encryption keys failed verification during dealing.
pub fn advance_dealing_round(
    session_id: CommitmentSizedNumber,
    party_id: PartyID,
    public_input: &PublicInput,
    rng: &mut impl CsRng,
) -> Result<(Vec<PartyID>, DealingRoundMessage)> {
    // Get per-curve encryption scheme public parameters
    let secp256k1_encryption_scheme_public_parameters = public_input
        .secp256k1_encryption_scheme_public_parameters
        .clone();
    let ristretto_encryption_scheme_public_parameters = public_input
        .ristretto_encryption_scheme_public_parameters
        .clone();
    let secp256r1_encryption_scheme_public_parameters = public_input
        .secp256r1_encryption_scheme_public_parameters
        .clone();

    let (secp256k1_malicious_dealers, secp256k1_dealing_message) =
        deal_randomizers_secp256k1_internal(
            session_id,
            party_id,
            &public_input.secp256k1_pvss_encryption_keys_and_proofs,
            &secp256k1_encryption_scheme_public_parameters,
            &public_input.participating_parties_access_structure,
            public_input.participating_and_dealers_match,
            rng,
        )?;

    let (ristretto_malicious_dealers, ristretto_dealing_message) =
        deal_randomizers_ristretto_internal(
            session_id,
            party_id,
            &public_input.ristretto_pvss_encryption_keys_and_proofs,
            &ristretto_encryption_scheme_public_parameters,
            &public_input.participating_parties_access_structure,
            public_input.participating_and_dealers_match,
            rng,
        )?;

    // Curve25519 uses ristretto encryption scheme and PVSS keys (same scalar field)
    let (curve25519_malicious_dealers, curve25519_dealing_message) =
        deal_randomizers_curve25519_internal(
            session_id,
            party_id,
            &public_input.ristretto_pvss_encryption_keys_and_proofs,
            &ristretto_encryption_scheme_public_parameters,
            &public_input.participating_parties_access_structure,
            public_input.participating_and_dealers_match,
            rng,
        )?;

    let (secp256r1_malicious_dealers, secp256r1_dealing_message) =
        deal_randomizers_secp256r1_internal(
            session_id,
            party_id,
            &public_input.secp256r1_pvss_encryption_keys_and_proofs,
            &secp256r1_encryption_scheme_public_parameters,
            &public_input.participating_parties_access_structure,
            public_input.participating_and_dealers_match,
            rng,
        )?;

    // Union and deduplicate malicious parties from all curves
    let malicious_parties = secp256k1_malicious_dealers
        .into_iter()
        .chain(ristretto_malicious_dealers)
        .chain(curve25519_malicious_dealers)
        .chain(secp256r1_malicious_dealers)
        .deduplicate_and_sort();

    Ok((
        malicious_parties,
        DealingRoundMessage {
            secp256k1_dealing_message,
            ristretto_dealing_message,
            curve25519_dealing_message,
            secp256r1_dealing_message,
        },
    ))
}
