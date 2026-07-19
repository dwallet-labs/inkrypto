// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Threshold Encryption to Sharing Protocol
//!
//! This module implements the generic single-curve threshold encryption to sharing protocol.
//! It converts threshold-encrypted secrets into Shamir secret shares.
//!
//! ## Protocol Overview
//!
//! Given encryptions of secrets $E(x_1), ..., E(x_n)$, the protocol produces
//! Shamir shares $[x_i]_j$ for each party $j$.
//!
//! The protocol uses masking with randomizers:
//! 1. Each party samples randomizers and deals VSS shares
//! 2. Parties compute masked values via threshold decryption
//! 3. Final shares are computed by unmasking
//!
//! ## Usage
//!
//! This module provides generic `_internal` functions that operate on a single curve.
//! Higher-level orchestration (e.g., multi-curve protocols) should call these
//! functions for each curve and combine the results.

use std::collections::{HashMap, HashSet};

use crate::encryption_key::public_parameters::Instantiate;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::small_prime::construct_encryption_of_discrete_log_public_parameters;
use crate::publicly_verifiable_secret_sharing::small_prime::{
    deal_secret_shares, deal_secret_shares_with_preverified_encryption_keys, decrypt_share,
    verify_dealt_shares, verify_encryptions_of_secret_shares, DealSecretMessage,
    DealSecretSharesOutput,
};
use crate::publicly_verifiable_secret_sharing::BaseProtocolContext;
use crate::{
    encryption_key, CiphertextSpaceGroupElement, CiphertextSpaceValue, CompactIbqf, DecryptionKey,
    EncryptionKey, EquivalenceClass, Error, ErrorKind, MultiFoldNupowAccelerator,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters, Result,
};
use crypto_bigint::{Encoding, Int, Uint};
use group::{CsRng, GroupElement as _, PartyID, PrimeGroupElement, Samplable};
use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::{HandleInvalidMessages, WeightedThresholdAccessStructure};
use serde::{Deserialize, Serialize};

/// The protocol name used for domain separation in proofs.
pub const PROTOCOL_NAME: &str = "Class Groups Threshold Encryption to Sharing";

/// Returns the `BaseProtocolContext` for PVSS dealing/verification of randomizer contributions.
///
/// The `secret_name` describes the curve and what is being masked/shared
/// (e.g., "secp256k1 Masked Secret First", "ristretto Secret Key Share First Part Second").
/// "Randomizer Contribution" is appended automatically.
pub fn pvss_base_protocol_context(secret_name: &str) -> BaseProtocolContext {
    BaseProtocolContext {
        protocol_name: PROTOCOL_NAME.to_string(),
        round: 1,
        proof_name: format!(
            "Proof of Valid Encryption of {secret_name} Randomizer Contribution Share"
        ),
    }
}

/// Returns the `BaseProtocolContext` for encrypted randomizer proofs.
///
/// The `secret_name` describes the curve and what is being masked/shared
/// (e.g., "secp256k1 Masked Secret First", "ristretto Secret Key Share First Part Second").
/// "Randomizer Contribution" is appended automatically.
pub fn encryption_of_randomizer_contribution_base_protocol_context(
    secret_name: &str,
) -> BaseProtocolContext {
    BaseProtocolContext {
        protocol_name: PROTOCOL_NAME.to_string(),
        round: 1,
        proof_name: format!("Proof of Valid Encryption of {secret_name} Randomizer Contribution"),
    }
}

/// PVSS dealing for a single secret (one randomizer contribution).
///
/// This struct holds all the data produced during the dealing round for one secret.
/// The caller invokes the dealing function once per secret (e.g., twice for first
/// and second randomizer contributions).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "")]
pub struct Dealing<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
> where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    /// Encryption of the randomizer contribution E(r).
    pub encryption_of_randomizer_contribution:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// EncDL proof for the encrypted randomizer contribution.
    pub encryption_of_randomizer_contribution_proof: EncryptionOfRandomizerContributionProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    /// PVSS dealing message for the randomizer contribution.
    pub randomizer_contribution_dealing_message: DealSecretMessage<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
}

/// Proof type for encrypted randomizer (EncDL proof).
#[allow(type_alias_bounds)]
pub type EncryptionOfRandomizerContributionProof<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
> = maurer::Proof<
    { maurer::SOUND_PROOFS_REPETITIONS },
    maurer::encryption_of_discrete_log::Language<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        homomorphic_encryption::PlaintextSpaceGroupElement<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    EncryptedRandomizerProtocolContext,
>;

/// Protocol context for encrypted randomizer proofs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRandomizerProtocolContext {
    pub dealer_party_id: PartyID,
    pub session_id: commitment::CommitmentSizedNumber,
    pub base_protocol_context: BaseProtocolContext,
}

/// Return type for [`advance_dealing_round_internal`]: malicious parties, verified encryption keys,
/// and the dealing.
pub struct DealingRoundOutput<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
> where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    pub malicious_parties: Vec<PartyID>,
    pub verified_encryption_keys:
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    pub dealing: Dealing<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
}

// =============================================================================
// Round 1: Dealing
// =============================================================================

/// Deals one randomizer contribution.
///
/// Each party:
/// 1. Takes a randomizer contribution as input
/// 2. Encrypts the randomizer contribution using the party's encryption key
/// 3. Deals PVSS shares for the randomizer contribution
///
/// The caller invokes this function once per randomizer contribution (e.g., twice for first
/// and second randomizer contributions), providing appropriate `pvss_base_protocol_context` and
/// `encryption_of_randomizer_contribution_base_protocol_context` for domain separation.
///
/// # Arguments
/// * `session_id` - Unique session identifier for domain separation
/// * `party_id` - This party's ID
/// * `threshold` - The threshold for PVSS
/// * `randomizer_contribution` - The randomizer contribution to deal
/// * `secret_name` - The secret name for protocol context creation (e.g., "secp256k1 Masked Secret First")
/// * `encryption_keys_and_proofs` - PVSS encryption keys and proofs for all parties
/// * `encryption_scheme_public_parameters` - Encryption scheme parameters
/// * `scalar_public_parameters` - Scalar field public parameters
/// * `group_public_parameters` - Group public parameters
/// * `rng` - Random number generator
///
/// # Returns
/// Tuple of (malicious_parties, verified_encryption_keys, dealing) where:
/// - malicious_parties contains parties whose encryption keys failed verification
/// - verified_encryption_keys can be reused for subsequent calls via
///   `advance_dealing_round_internal_with_preverified_encryption_keys`
///
/// # Note on `participating_and_dealers_match`
/// When dealers and participants are the same set (e.g. in DKG), encryption key
/// verification failures indicate malicious dealers. When they differ (e.g. in
/// reconfiguration), failures are for participants, not dealers, so they should
/// not be reported as malicious dealers.
#[allow(clippy::too_many_arguments)]
pub fn advance_dealing_round_internal<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    party_id: PartyID,
    randomizer_contribution: GroupElement::Scalar,
    secret_name: &str,
    participating_and_dealers_match: bool,
    encryption_keys_and_proofs: &HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            crate::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
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
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    crate::DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    // Create base protocol contexts from secret_name
    let pvss_base_protocol_context = pvss_base_protocol_context(secret_name);
    let encryption_of_randomizer_contribution_base_protocol_context =
        encryption_of_randomizer_contribution_base_protocol_context(secret_name);

    let setup_parameters = &encryption_scheme_public_parameters.setup_parameters;

    let DealSecretSharesOutput {
        malicious_parties,
        verified_encryption_keys,
        dealing_message,
    } = deal_secret_shares::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        {
            crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
        },
        GroupElement,
    >(
        session_id,
        party_id,
        randomizer_contribution,
        setup_parameters,
        encryption_keys_and_proofs,
        participating_and_dealers_match,
        participating_parties_access_structure,
        &pvss_base_protocol_context,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )?;

    let (encryption_of_randomizer_contribution, encryption_of_randomizer_contribution_proof) =
        encrypt_and_prove_randomizer_contribution::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >(
            session_id,
            party_id,
            randomizer_contribution,
            encryption_scheme_public_parameters,
            &encryption_of_randomizer_contribution_base_protocol_context,
            group_public_parameters,
            rng,
        )?;

    Ok(DealingRoundOutput {
        malicious_parties,
        verified_encryption_keys,
        dealing: Dealing {
            encryption_of_randomizer_contribution,
            encryption_of_randomizer_contribution_proof,
            randomizer_contribution_dealing_message: dealing_message,
        },
    })
}

/// Optimized variant of `advance_dealing_round_internal` that skips encryption key verification.
///
/// Use when encryption keys have already been verified by a previous call to
/// `advance_dealing_round_internal`. This is useful when dealing multiple secrets
/// for the same set of parties (e.g., first and second randomizer contributions).
///
/// # Arguments
/// * `session_id` - Unique session identifier for domain separation
/// * `party_id` - This party's ID
/// * `threshold` - The threshold for PVSS
/// * `randomizer_contribution` - The randomizer contribution to deal
/// * `secret_name` - The randomizer contribution name for protocol context creation (e.g., "secp256k1 Masked Secret Second")
/// * `verified_encryption_keys` - Pre-verified encryption keys from a previous call
/// * `encryption_scheme_public_parameters` - Encryption scheme parameters
/// * `scalar_public_parameters` - Scalar field public parameters
/// * `group_public_parameters` - Group public parameters
/// * `rng` - Random number generator
///
/// # Returns
/// The dealing message (no malicious parties since verification is skipped)
#[allow(clippy::too_many_arguments)]
pub fn advance_dealing_round_internal_with_preverified_encryption_keys<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    party_id: PartyID,
    randomizer_contribution: GroupElement::Scalar,
    secret_name: &str,
    verified_encryption_keys: HashMap<
        PartyID,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
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
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    crate::DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    // Create base protocol contexts from secret_name
    let pvss_base_protocol_context = pvss_base_protocol_context(secret_name);
    let encryption_of_randomizer_contribution_base_protocol_context =
        encryption_of_randomizer_contribution_base_protocol_context(secret_name);

    let setup_parameters = &encryption_scheme_public_parameters.setup_parameters;

    // Deal using pre-verified keys (skip verification)
    let dealing_message = deal_secret_shares_with_preverified_encryption_keys(
        session_id,
        party_id,
        randomizer_contribution,
        setup_parameters,
        verified_encryption_keys.clone(),
        participating_parties_access_structure,
        &pvss_base_protocol_context,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )?;

    // Create encrypted randomizer with proof (encrypted under threshold key)
    let (encryption_of_randomizer_contribution, encryption_of_randomizer_contribution_proof) =
        encrypt_and_prove_randomizer_contribution::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >(
            session_id,
            party_id,
            randomizer_contribution,
            encryption_scheme_public_parameters,
            &encryption_of_randomizer_contribution_base_protocol_context,
            group_public_parameters,
            rng,
        )?;

    Ok(Dealing {
        encryption_of_randomizer_contribution,
        encryption_of_randomizer_contribution_proof,
        randomizer_contribution_dealing_message: dealing_message,
    })
}

// =============================================================================
// Round 2: Accusation (Self-Verification)
// =============================================================================

/// Verifies dealt shares for one secret.
///
/// Each party verifies only the shares dealt to them by checking in the exponent.
/// Returns the set of malicious dealers whose shares failed verification.
///
/// The caller invokes this function once per secret (e.g., twice for first and second
/// randomizer contributions), providing appropriate `pvss_base_protocol_context` for
/// domain separation.
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `dealer_party_id` - This party's ID in the dealer access structure.
///   Used for self-exclusion: we don't verify our own dealings since we know we're honest.
///   When dealers and participating parties don't match (reconfiguration), this differs
///   from `participating_party_id`.
/// * `participating_party_id` - This party's ID in the participating access structure.
///   Used to look up the party's encryption key and as the recipient ID for share verification.
/// * `dealing_messages` - One secret's dealings from all dealers
/// * `pvss_base_protocol_context` - Protocol context for PVSS proofs (provides domain separation)
/// * `encryption_scheme_public_parameters` - Encryption scheme parameters for this party's own key
/// * `scalar_public_parameters` - Scalar field public parameters
/// * `group_public_parameters` - Group public parameters
/// * `rng` - Random number generator
///
/// # Returns
/// Set of malicious dealers whose shares failed verification.
#[allow(clippy::too_many_arguments)]
pub fn advance_accusation_round_internal<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: PartyID,
    dealing_messages: HashMap<
        PartyID,
        DealSecretMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    pvss_base_protocol_context: &BaseProtocolContext,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> HashSet<PartyID>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    verify_dealt_shares::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >(
        session_id,
        dealer_party_id,
        participating_party_id,
        dealing_messages,
        encryption_scheme_public_parameters,
        participating_parties_access_structure,
        pvss_base_protocol_context,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )
}

// =============================================================================
// Helper: Encrypted Randomizer Proof Creation
// =============================================================================

/// Creates an encrypted randomizer with an EncDL proof for a single secret.
#[allow(clippy::too_many_arguments)]
fn encrypt_and_prove_randomizer_contribution<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    dealer_party_id: PartyID,
    secret: GroupElement::Scalar,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    base_protocol_context: &BaseProtocolContext,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<(
    CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    EncryptionOfRandomizerContributionProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
)>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    // Build EncDL language public parameters
    let language_public_parameters = construct_encryption_of_discrete_log_public_parameters(
        encryption_scheme_public_parameters
            .plaintext_space_public_parameters()
            .clone(),
        group_public_parameters.clone(),
        encryption_scheme_public_parameters.clone(),
    );

    // Sample encryption randomness
    let encryption_randomness =
        RandomnessSpaceGroupElement::<FUNDAMENTAL_DISCRIMINANT_LIMBS>::sample(
            encryption_scheme_public_parameters.randomness_space_public_parameters(),
            rng,
        )?;

    // Create protocol context with domain separation
    let protocol_context = EncryptedRandomizerProtocolContext {
        dealer_party_id,
        session_id,
        base_protocol_context: base_protocol_context.clone(),
    };

    // Generate proof with single witness
    let (proof, statements) = EncryptionOfRandomizerContributionProof::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >::prove(
        &protocol_context,
        &language_public_parameters,
        vec![(secret, encryption_randomness).into()],
        rng,
    )?;

    let (ciphertext, _commitment) = (*statements
        .first()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?)
    .into();

    Ok((ciphertext.value(), proof))
}

// =============================================================================
// Helper: Compute Encryption of Masked Secret
// =============================================================================

/// Computes the encryption of the masked secret: E(x + r) = E(x) + Σ E(r_i).
///
/// This is the core homomorphic operation that adds random masks to the original
/// ciphertext. The result can be threshold-decrypted to recover (x + r) without
/// revealing x.
///
/// # Arguments
/// * `encryption_of_secret` - The original encryption E(x) as a Value
/// * `encryptions_of_randomizer_contributions` - The encrypted randomizer contributions E(r_i) as Values
/// * `ciphertext_space_public_parameters` - Public parameters for the ciphertext space
///
/// # Returns
/// The masked ciphertext E(x + r) as a GroupElement
fn compute_encryption_of_masked_secret<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS> + Copy,
>(
    encryption_of_secret: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    dealing_messages: HashMap<
        PartyID,
        Dealing<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    malicious_parties: &HashSet<PartyID>,
    ciphertext_space_public_parameters: &crate::CiphertextSpacePublicParameters<
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
) -> Result<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    let encryption_of_secret =
        CiphertextSpaceGroupElement::new(encryption_of_secret, ciphertext_space_public_parameters)
            .map_err(crate::Error::from)?;

    let contributions = dealing_messages
        .iter()
        .filter(|(dealer_party_id, _)| !malicious_parties.contains(dealer_party_id))
        .map(|(_, dealing)| {
            CiphertextSpaceGroupElement::new(
                dealing.encryption_of_randomizer_contribution,
                ciphertext_space_public_parameters,
            )
            .map_err(crate::Error::from)
        })
        .collect::<Result<Vec<_>>>()?;

    let encryption_of_masked_secret = contributions
        .into_iter()
        .fold(encryption_of_secret, |acc, contribution| {
            acc.add_vartime(&contribution, ciphertext_space_public_parameters)
        });

    Ok(encryption_of_masked_secret)
}

// =============================================================================
// Round 3: Decryption
// =============================================================================

/// Decryption shares with proof for a set of ciphertexts.
///
/// Contains the decryption shares and proof of correct decryption for
/// a batch of ciphertexts.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "")]
pub struct DecryptionShareAndProof<const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize>
where
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
{
    /// Decryption share for a single ciphertext.
    pub share: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Proof of correct decryption.
    pub proof:
        crate::decryption_key_share::PartialDecryptionProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
}

/// Verifies dealers and generates partial decryption shares for a single secret.
///
/// This performs the full Round 3 processing for one secret in a single call:
/// 1. **EncDL verification**: Batch-verifies encrypted randomizer contribution proofs
/// 2. **PVSS verification**: Publicly verifies accused dealers' PVSS dealing proofs
/// 3. **Computes E(x+r)**: Homomorphically adds honest dealers' encrypted randomizers to E(x)
/// 4. **Generates decryption shares**: Creates partial decryption shares with proofs for E(x+r)
///
/// The caller invokes this function once per secret (e.g., 8 times for 4 curves x 2 secrets),
/// chaining `malicious_parties` through each call.
///
/// # Returns
/// Tuple of (malicious_parties, decryption_shares_map) where:
/// - malicious_parties is the updated set including previously detected and newly detected
/// - decryption_shares_map maps virtual party IDs to their decryption shares with proofs
#[allow(clippy::too_many_arguments)]
pub fn advance_partial_decryption_round_internal<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS> + Copy,
    EncryptionKeyType: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    DecryptionKeyShareType: homomorphic_encryption::AdditivelyHomomorphicDecryptionKeyShare<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKeyType,
        SecretKeyShare = crate::SecretKeyShareSizedInteger,
        PartialDecryptionProof = crate::decryption_key_share::PartialDecryptionProof<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
>(
    session_id: commitment::CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participating_party_id: Option<PartyID>,
    dealing_messages: HashMap<
        PartyID,
        Dealing<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    malicious_dealers_by_party: &HashMap<PartyID, HashSet<PartyID>>,
    encryption_keys_and_proofs: &HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            crate::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
    setup_parameters: &crate::setup::SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    threshold_encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    malicious_parties: HashSet<PartyID>,
    secret_name: &str,
    scalar_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
    dealer_access_structure: &mpc::WeightedThresholdAccessStructure,
    participating_parties_access_structure: &mpc::WeightedThresholdAccessStructure,
    decryption_key_share: crate::SecretKeyShareSizedInteger,
    encryption_of_secret: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    decryption_key_share_public_parameters: &DecryptionKeyShareType::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<(
    HashSet<PartyID>,
    DecryptionShareAndProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
)>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    EncryptionKeyType::CiphertextSpaceGroupElement: Clone,
    encryption_key::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    // Step 1: EncDL verification of encrypted randomizer contributions
    let base_protocol_context =
        encryption_of_randomizer_contribution_base_protocol_context(secret_name);

    let (malicious_dealers, proofs_and_contexts_and_statements): (_, HashMap<_, _>) =
        dealing_messages
            .iter()
            .map(|(&dealer_party_id, dealing)| {
                let commitment = dealing
                    .randomizer_contribution_dealing_message
                    .coefficients_contribution_commitments
                    .first()
                    .and_then(|commitment| {
                        GroupElement::new(commitment.clone(), group_public_parameters).ok()
                    });

                let encryption_of_randomizer_contribution =
                    CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                        dealing.encryption_of_randomizer_contribution,
                        threshold_encryption_scheme_public_parameters
                            .ciphertext_space_public_parameters(),
                    )
                    .ok();

                let protocol_context = EncryptedRandomizerProtocolContext {
                    dealer_party_id,
                    session_id,
                    base_protocol_context: base_protocol_context.clone(),
                };

                let proof_protocol_context_and_statement = commitment
                    .zip(encryption_of_randomizer_contribution)
                    .map(|(commitment, encryption_of_randomizer_contribution)| {
                        let statement = group::direct_product::GroupElement::from((
                            encryption_of_randomizer_contribution,
                            commitment,
                        ));

                        vec![(
                            dealing.encryption_of_randomizer_contribution_proof.clone(),
                            (protocol_context, vec![statement]),
                        )]
                    })
                    .ok_or_else(|| Error::from(ErrorKind::InvalidMessage));

                (dealer_party_id, proof_protocol_context_and_statement)
            })
            .handle_invalid_messages_async();

    let language_public_parameters = construct_encryption_of_discrete_log_public_parameters(
        threshold_encryption_scheme_public_parameters
            .plaintext_space_public_parameters()
            .clone(),
        group_public_parameters.clone(),
        threshold_encryption_scheme_public_parameters.clone(),
    );

    let (malicious_provers, _) = <EncryptionOfRandomizerContributionProof<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as proof::Proof>::verify_batch_asynchronously(
        proofs_and_contexts_and_statements,
        &language_public_parameters,
        rng,
    );

    let malicious_dealers: HashSet<PartyID> = malicious_dealers
        .into_iter()
        .chain(malicious_provers)
        .collect();

    // Combine input malicious parties with EncDL-malicious parties
    let malicious_parties: HashSet<PartyID> = malicious_parties
        .into_iter()
        .chain(malicious_dealers)
        .collect();

    // Step 2: PVSS verification of accused dealers
    let encryption_keys: HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>> =
        encryption_keys_and_proofs
            .iter()
            .filter_map(|(&party_id, (key_compact, _proof))| {
                let encryption_key = EquivalenceClass::new(
                    *key_compact,
                    setup_parameters.equivalence_class_public_parameters(),
                )
                .ok()?;

                Some((party_id, encryption_key))
            })
            .collect();

    let pvss_base_protocol_context = pvss_base_protocol_context(secret_name);

    let deal_secret_messages: HashMap<_, _> = dealing_messages
        .iter()
        .map(|(&party_id, dealing)| {
            (
                party_id,
                dealing.randomizer_contribution_dealing_message.clone(),
            )
        })
        .collect();

    let malicious_parties = verify_encryptions_of_secret_shares::<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >(
        dealer_party_id,
        participating_party_id,
        &deal_secret_messages,
        malicious_dealers_by_party,
        malicious_parties,
        setup_parameters,
        &encryption_keys,
        &pvss_base_protocol_context,
        scalar_public_parameters,
        group_public_parameters,
        session_id,
        dealer_access_structure,
        participating_parties_access_structure,
        rng,
    )?;

    // Step 3: Compute E(x+r) from honest dealers' encrypted randomizer contributions
    let encryption_of_masked_secret = compute_encryption_of_masked_secret(
        encryption_of_secret,
        dealing_messages,
        &malicious_parties,
        threshold_encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
    )?;

    // Step 4: Generate decryption shares for E(x+r)
    // In the uniform access structure, the dealer's tangible party ID equals
    // the virtual party ID for the decryption key share.
    let decryption_key_share = DecryptionKeyShareType::new(
        dealer_party_id,
        decryption_key_share,
        decryption_key_share_public_parameters,
        rng,
    )
    .map_err(|_| crate::Error::from(crate::ErrorKind::InternalError))?;

    let (shares, proof) = decryption_key_share
        .generate_decryption_shares(
            vec![encryption_of_masked_secret],
            decryption_key_share_public_parameters,
            false,
            rng,
        )
        .into_option()
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;

    match shares[..] {
        [share] => Ok((malicious_parties, DecryptionShareAndProof { share, proof })),
        _ => Err(Error::from(ErrorKind::InternalError)),
    }
}

// =============================================================================
// Round 4: Combine Decryption Shares
// =============================================================================

/// Combines decryption shares to recover the masked secret (x + r) for a single secret.
///
/// This is the final protocol round for one secret:
/// 1. Computes E(x+r) = E(x) + Σ E(r_i) using honest dealers' encrypted randomizer contributions
/// 2. Combines threshold decryption shares to recover (x + r)
///
/// The caller invokes this function once per secret (e.g., 8 times for 4 curves x 2 secrets).
///
/// # Returns
/// A tuple of (malicious decrypter party IDs, recovered plaintext scalar (x + r),
/// aggregated polynomial commitments from honest dealers)
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn combine_decryption_shares_of_masked_secret<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS> + Copy + std::ops::Neg<Output = GroupElement>,
    EncryptionKeyType: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    DecryptionKeyShareType: homomorphic_encryption::AdditivelyHomomorphicDecryptionKeyShare<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKeyType,
        SecretKeyShare = crate::SecretKeyShareSizedInteger,
        PartialDecryptionProof = crate::decryption_key_share::PartialDecryptionProof<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
>(
    dealings: HashMap<
        PartyID,
        Dealing<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    malicious_dealers: &HashSet<PartyID>,
    encryption_of_secret: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    decryption_shares_and_proofs: HashMap<
        PartyID,
        DecryptionShareAndProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    decryption_key_share_public_parameters: &DecryptionKeyShareType::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<(
    Vec<PartyID>,
    EncryptionKeyType::PlaintextSpaceGroupElement,
    Vec<group::Value<GroupElement>>,
)>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    GroupElement::Scalar: std::ops::Mul<GroupElement, Output = GroupElement>
        + std::ops::Neg<Output = GroupElement::Scalar>,
{
    // Step 1: Aggregate polynomial commitments from honest dealers.
    let honest_commitment_vectors: Vec<_> = dealings
        .iter()
        .filter(|(id, _)| !malicious_dealers.contains(id))
        .map(|(_, dealing)| {
            &dealing
                .randomizer_contribution_dealing_message
                .coefficients_contribution_commitments
        })
        .collect();

    let num_coefficients = honest_commitment_vectors
        .first()
        .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))?
        .len();

    if honest_commitment_vectors
        .iter()
        .any(|commitments| commitments.len() != num_coefficients)
    {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    let neutral = GroupElement::neutral_from_public_parameters(group_public_parameters)?;

    let aggregated_polynomial_commitments = (0..num_coefficients)
        .map(|coefficient_index| {
            honest_commitment_vectors
                .iter()
                .map(|commitments| {
                    GroupElement::new(
                        commitments[coefficient_index].clone(),
                        group_public_parameters,
                    )
                    .map_err(Error::from)
                })
                .collect::<Result<Vec<_>>>()
                .map(|elements| {
                    elements.into_iter().fold(neutral, |acc, commitment| {
                        acc.add_vartime(&commitment, group_public_parameters)
                    })
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Step 2: Compute E(x+r) from honest dealers' encrypted randomizer contributions
    let encryption_of_masked_secret = compute_encryption_of_masked_secret(
        encryption_of_secret,
        dealings,
        malicious_dealers,
        encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
    )?;

    // Step 3: Combine decryption shares to recover (x + r) with malicious security.
    // Decompose DecryptionShareAndProof into (vec![share], proof) tuples for the trait method.
    let decryption_shares_and_proofs = decryption_shares_and_proofs
        .into_iter()
        .map(|(id, DecryptionShareAndProof { share, proof })| (id, (vec![share], proof)))
        .collect();

    let (malicious_decrypters, masked_secret) = DecryptionKeyShareType::combine_decryption_shares(
        vec![encryption_of_masked_secret],
        decryption_shares_and_proofs,
        decryption_key_share_public_parameters,
        false,
        rng,
    )
    .map_err(|_| crate::Error::from(crate::ErrorKind::InternalError))?;

    match masked_secret[..] {
        [masked_secret] => {
            let generator =
                GroupElement::generator_from_public_parameters(group_public_parameters)?;
            let masked_secret_commitment = masked_secret * generator;

            let secret_key_polynomial_commitments = aggregated_polynomial_commitments
                .into_iter()
                .enumerate()
                .map(|(coefficient_index, randomizer_commitment)| {
                    // TODO: @offir explain the transformation
                    if coefficient_index == 0 {
                        Ok(masked_secret_commitment
                            .sub_vartime(&randomizer_commitment, group_public_parameters)
                            .value())
                    } else {
                        Ok(randomizer_commitment.neg().value())
                    }
                })
                .collect::<Result<Vec<_>>>()?;

            Ok((
                malicious_decrypters,
                masked_secret,
                secret_key_polynomial_commitments,
            ))
        }
        _ => Err(Error::from(ErrorKind::InternalError)),
    }
}

// =============================================================================
// Share Derivation: Decrypt + Aggregate + Unmask
// =============================================================================

/// Derives a party's Shamir share of a secret from PVSS dealings and the masked secret.
///
/// This function performs the complete share derivation for a single secret:
/// 1. For each dealing, extracts and decrypts the encrypted share for `party_id`
/// 2. Aggregates (sums) all decrypted randomizer shares: `[r]_i = Σ [r_j]_i`
/// 3. Unmasks: `[x]_i = (x + r) - [r]_i`
///
/// # Arguments
/// * `party_id` - This party's ID (used to look up encrypted shares)
/// * `encryption_scheme_public_parameters` - Encryption scheme parameters
/// * `decryption_key` - This party's PVSS decryption key
/// * `dealings` - Slice of references to dealings from all dealers (for one secret)
/// * `masked_secret_value` - The masked secret `(x + r)` recovered via threshold decryption
///
/// # Returns
/// The Shamir share `[x]_i` as a `Value`
pub fn derive_shamir_share_of_secret<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    party_id: PartyID,
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    decryption_key: Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    dealings: &[&Dealing<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >],
    masked_secret_value: group::Value<GroupElement::Scalar>,
) -> Result<group::Value<GroupElement::Scalar>>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let scalar_public_parameters =
        encryption_scheme_public_parameters.plaintext_space_public_parameters();

    let neutral = GroupElement::Scalar::neutral_from_public_parameters(scalar_public_parameters)?;

    // Step 1: For each dealing, decrypt the encrypted share for this party and sum them.
    let randomizer_share = dealings
        .iter()
        .filter_map(|dealing| {
            dealing
                .randomizer_contribution_dealing_message
                .encryptions_of_secret_shares_and_proofs
                .get(&party_id)
        })
        .map(|dealt_message| -> Result<_> {
            let encryption_of_share =
                CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                    dealt_message.encryption_of_secret_share,
                    encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
                )?;

            decrypt_share::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >(
                encryption_scheme_public_parameters,
                decryption_key,
                &encryption_of_share,
            )
        })
        .try_fold(neutral, |acc, share| -> Result<_> {
            Ok(acc.add_vartime(&share?, scalar_public_parameters))
        })?;

    // Step 2: Unmask: [x]_i = (x + r) - [r]_i
    let masked_secret = GroupElement::Scalar::new(masked_secret_value, scalar_public_parameters)?;
    let secret_key_share =
        masked_secret.sub_constant_time(&randomizer_share, scalar_public_parameters);

    Ok(secret_key_share.value())
}
// =============================================================================
// Aggregation of Encrypted Randomizer Shares
// =============================================================================

/// Homomorphically aggregates, per receiving party, the encrypted randomizer shares dealt by the
/// honest dealers: $\textsf{ct}_i = \sum_j \textsf{ct}_{j,i}$, where $\textsf{ct}_{j,i}$ encrypts
/// dealer $j$'s dealt share $[r_j]_i$ under party $i$'s PVSS encryption key.
///
/// Since Shamir sharings add coefficient-wise, $\textsf{ct}_i$ encrypts party $i$'s share
/// $[r]_i = \sum_j [r_j]_i$ of the aggregated randomizer $r = \sum_j r_j$ — all under the same
/// (per-receiver) encryption key, so a single decryption recovers $[r]_i$.
///
/// The input dealings must ALL be honest: publicly verified (post the accusation round) with
/// malicious dealers already excluded — which holds for every persisted public output, formed
/// after the in-protocol majority vote. Once aggregated, the per-dealer structure and the EncDL
/// proofs are no longer needed, which is what lets the persisted public output store one
/// ciphertext per receiver instead of the full $O(n^2)$ dealing transcript. (When output
/// formation later aggregates eagerly, the caller filters malicious dealers before calling.)
pub fn aggregate_encryptions_of_randomizer_shares<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    dealings: &HashMap<
        PartyID,
        Dealing<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    ciphertext_space_public_parameters: &crate::CiphertextSpacePublicParameters<
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
) -> Result<HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    let honest_dealings: Vec<_> = dealings.values().collect();

    let receiving_parties: HashSet<PartyID> = honest_dealings
        .iter()
        .flat_map(|dealing| {
            dealing
                .randomizer_contribution_dealing_message
                .encryptions_of_secret_shares_and_proofs
                .keys()
                .copied()
        })
        .collect();

    receiving_parties
        .into_iter()
        .map(|receiving_party_id| {
            let encryptions_of_dealt_shares = honest_dealings
                .iter()
                .map(|dealing| {
                    // Every verified dealing covers every receiving party, so a missing entry
                    // means the dealing set passed in was not uniformly verified.
                    dealing
                        .randomizer_contribution_dealing_message
                        .encryptions_of_secret_shares_and_proofs
                        .get(&receiving_party_id)
                        .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))
                        .and_then(|dealt_secret_share_message| {
                            CiphertextSpaceGroupElement::new(
                                dealt_secret_share_message.encryption_of_secret_share,
                                ciphertext_space_public_parameters,
                            )
                            .map_err(Error::from)
                        })
                })
                .collect::<Result<Vec<_>>>()?;

            encryptions_of_dealt_shares
                .into_iter()
                .reduce(|acc, encryption_of_dealt_share| {
                    acc.add_vartime(
                        &encryption_of_dealt_share,
                        ciphertext_space_public_parameters,
                    )
                })
                .map(|encryption_of_randomizer_share| {
                    (receiving_party_id, encryption_of_randomizer_share.value())
                })
                .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))
        })
        .collect()
}

// =============================================================================
// Share Derivation from an Aggregated Encryption: Decrypt + Unmask
// =============================================================================

/// Derives a party's Shamir share of a secret from its aggregated encrypted randomizer share and
/// the masked secret.
///
/// Same derivation as [`derive_shamir_share_of_secret`], but starting from the single
/// per-receiver aggregated ciphertext instead of the per-dealer dealings:
/// 1. Decrypts the aggregated randomizer share: `[r]_i = Σ [r_j]_i`
///    (aggregated homomorphically by [`aggregate_encryptions_of_randomizer_shares`])
/// 2. Unmasks: `[x]_i = (x + r) - [r]_i`
///
/// # Arguments
/// * `encryption_scheme_public_parameters` - Encryption scheme parameters
/// * `decryption_key` - This party's PVSS decryption key
/// * `encryption_of_randomizer_share` - The aggregated encryption of this party's randomizer share
/// * `masked_secret_value` - The masked secret `(x + r)` recovered via threshold decryption
///
/// # Returns
/// The Shamir share `[x]_i` as a `Value`
pub fn derive_shamir_share_of_secret_from_aggregated_encryption<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    decryption_key: Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    encryption_of_randomizer_share: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    masked_secret_value: group::Value<GroupElement::Scalar>,
) -> Result<group::Value<GroupElement::Scalar>>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = crate::equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let scalar_public_parameters =
        encryption_scheme_public_parameters.plaintext_space_public_parameters();

    // Step 1: Decrypt the aggregated randomizer share $[r]_i = \sum_j [r_j]_i$.
    let encryption_of_randomizer_share =
        CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
            encryption_of_randomizer_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    let randomizer_share = decrypt_share::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >(
        encryption_scheme_public_parameters,
        decryption_key,
        &encryption_of_randomizer_share,
    )?;

    // Step 2: Unmask: [x]_i = (x + r) - [r]_i
    let masked_secret = GroupElement::Scalar::new(masked_secret_value, scalar_public_parameters)?;
    let secret_key_share =
        masked_secret.sub_constant_time(&randomizer_share, scalar_public_parameters);

    Ok(secret_key_share.value())
}
