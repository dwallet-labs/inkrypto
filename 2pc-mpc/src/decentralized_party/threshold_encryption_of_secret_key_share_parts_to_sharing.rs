// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Threshold Encryption to Sharing Protocol
//!
//! This module implements a protocol that converts threshold-encrypted secret key shares
//! from DKG/reconfiguration outputs into Shamir secret shares usable by the VSS sign protocol.
//!
//! ## Protocol Overview
//!
//! Given an encryption of a secret $E(x)$ (where parties don't know $x$ but share a decryption key),
//! the protocol produces Shamir shares $[x]_i$ for each party $i$.
//!
//! The core idea uses the additive homomorphic property of the encryption:
//! 1. Each party $i$ samples a randomizer $r_i$ and computes $E(r_i)$
//! 2. The parties compute $E(x + r) = E(x) + \sum_i E(r_i)$
//! 3. Threshold decryption reveals $(x + r)$ (but not $x$ individually)
//! 4. Each party computes their share: $[x]_i = (x + r) - [r]_i$
//!    where $[r]_i = \sum_j [r_j]_i$ is the aggregated randomizer share
//!
//! ## Protocol Rounds
//!
//! - **Round 1 (Dealing)**: Each party samples randomizers, encrypts them, and deals VSS shares
//! - **Round 2 (Accusation)**: Parties verify VSS shares and generate accusations if invalid
//! - **Round 3 (Threshold Decryption)**: Parties generate decryption shares with proofs for $E(x+r)$
//! - **Round 4 (Aggregation)**: Parties aggregate VSS shares and compute final Shamir shares
//!
//! ## Secrets Handled
//!
//! The protocol handles 8 secrets (4 curves × 2 parts):
//! - secp256k1: first_part, second_part
//! - ristretto: first_part, second_part
//! - curve25519: first_part, second_part
//! - secp256r1: first_part, second_part

pub mod accusation;
pub mod aggregated_public_output;
pub mod aggregation;
pub mod dealing;
pub mod decryption;

pub use aggregated_public_output::PublicOutput;

use std::collections::HashMap;

use class_groups::{
    CiphertextSpaceValue, CompactIbqf, RistrettoEncryptionSchemePublicParameters,
    RistrettoSetupParameters, Secp256k1EncryptionSchemePublicParameters, Secp256k1SetupParameters,
    Secp256r1EncryptionSchemePublicParameters, Secp256r1SetupParameters,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use group::{curve25519, ristretto, secp256k1, secp256r1, PartyID};
use mpc::WeightedThresholdAccessStructure;
use serde::{Deserialize, Serialize};

use crate::Result;

// ==================== Protocol Context Secret Names ====================
// These constants define the secret names for each (curve, part) combination.
// They are used consistently across dealing, accusation, and decryption rounds
// to ensure protocol context strings always match exactly.

/// Secret name for secp256k1 first secret key share part.
pub const SECP256K1_FIRST_SECRET_NAME: &str = "secp256k1 Secret Key Share First Part First";
/// Secret name for secp256k1 second secret key share part.
pub const SECP256K1_SECOND_SECRET_NAME: &str = "secp256k1 Secret Key Share First Part Second";
/// Secret name for ristretto first secret key share part.
pub const RISTRETTO_FIRST_SECRET_NAME: &str = "ristretto Secret Key Share First Part First";
/// Secret name for ristretto second secret key share part.
pub const RISTRETTO_SECOND_SECRET_NAME: &str = "ristretto Secret Key Share First Part Second";
/// Secret name for curve25519 first secret key share part.
pub const CURVE25519_FIRST_SECRET_NAME: &str = "curve25519 Secret Key Share First Part First";
/// Secret name for curve25519 second secret key share part.
pub const CURVE25519_SECOND_SECRET_NAME: &str = "curve25519 Secret Key Share First Part Second";
/// Secret name for secp256r1 first secret key share part.
pub const SECP256R1_FIRST_SECRET_NAME: &str = "secp256r1 Secret Key Share First Part First";
/// Secret name for secp256r1 second secret key share part.
pub const SECP256R1_SECOND_SECRET_NAME: &str = "secp256r1 Secret Key Share First Part Second";

/// Public input for the threshold encryption to sharing protocol.
///
/// Contains all public data needed by all parties to execute the protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInput {
    /// Encrypted secret key shares for secp256k1 (first secret).
    pub secp256k1_encryption_of_first_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Encrypted secret key shares for secp256k1 (second secret).
    pub secp256k1_encryption_of_second_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Public key share for secp256k1 (first secret).
    pub secp256k1_first_public_key_share: secp256k1::group_element::Value,
    /// Public key share for secp256k1 (second secret).
    pub secp256k1_second_public_key_share: secp256k1::group_element::Value,
    /// Encryption scheme public parameters for secp256k1.
    pub secp256k1_encryption_scheme_public_parameters: Secp256k1EncryptionSchemePublicParameters,
    /// Public verification keys for secp256k1 threshold decryption.
    pub secp256k1_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    /// Encrypted secret key shares for ristretto (first secret).
    pub ristretto_encryption_of_first_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Encrypted secret key shares for ristretto (second secret).
    pub ristretto_encryption_of_second_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Public key share for ristretto (first secret).
    pub ristretto_first_public_key_share: group::Value<ristretto::GroupElement>,
    /// Public key share for ristretto (second secret).
    pub ristretto_second_public_key_share: group::Value<ristretto::GroupElement>,
    /// Encryption scheme public parameters for ristretto.
    pub ristretto_encryption_scheme_public_parameters: RistrettoEncryptionSchemePublicParameters,
    /// Public verification keys for ristretto threshold decryption.
    pub ristretto_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    /// Encrypted secret key shares for curve25519 (first secret).
    pub curve25519_encryption_of_first_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Encrypted secret key shares for curve25519 (second secret).
    pub curve25519_encryption_of_second_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Encrypted secret key shares for secp256r1 (first secret).
    pub secp256r1_encryption_of_first_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Encrypted secret key shares for secp256r1 (second secret).
    pub secp256r1_encryption_of_second_secret_key_share:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    /// Public key share for secp256r1 (first secret).
    pub secp256r1_first_public_key_share: secp256r1::group_element::Value,
    /// Public key share for secp256r1 (second secret).
    pub secp256r1_second_public_key_share: secp256r1::group_element::Value,
    /// Encryption scheme public parameters for secp256r1.
    pub secp256r1_encryption_scheme_public_parameters: Secp256r1EncryptionSchemePublicParameters,
    /// Public verification keys for secp256r1 threshold decryption.
    pub secp256r1_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    /// The access structure for dealers (current committee).
    /// Used for threshold decryption parameters and authorized subset checks on honest dealers.
    pub dealer_access_structure: WeightedThresholdAccessStructure,
    /// The access structure for participating parties (upcoming committee in reconfiguration).
    /// Used for PVSS dealing polynomial degree and coefficient count validation.
    pub participating_parties_access_structure: WeightedThresholdAccessStructure,
    /// Whether participating parties and dealers are the same set (true for DKG, false for reconfiguration).
    pub participating_and_dealers_match: bool,

    // ==================== PVSS Encryption Keys (per curve) ====================
    // Each party has an encryption key + UC proof per curve for PVSS shares
    /// PVSS encryption keys and proofs for secp256k1 randomizer shares.
    pub secp256k1_pvss_encryption_keys_and_proofs: HashMap<
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

    /// PVSS encryption keys and proofs for ristretto randomizer shares.
    pub ristretto_pvss_encryption_keys_and_proofs: HashMap<
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

    /// PVSS encryption keys and proofs for secp256r1 randomizer shares.
    pub secp256r1_pvss_encryption_keys_and_proofs: HashMap<
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

    /// Pre-derived setup parameters for secp256k1.
    pub secp256k1_setup_parameters: Secp256k1SetupParameters,
    /// Pre-derived setup parameters for ristretto.
    pub ristretto_setup_parameters: RistrettoSetupParameters,
    /// Pre-derived setup parameters for secp256r1.
    pub secp256r1_setup_parameters: Secp256r1SetupParameters,

    /// Decryption key share public parameters for secp256k1 threshold decryption.
    pub secp256k1_decryption_key_share_public_parameters:
        class_groups::Secp256k1DecryptionKeySharePublicParameters,
    /// Decryption key share public parameters for ristretto threshold decryption.
    pub ristretto_decryption_key_share_public_parameters:
        class_groups::RistrettoDecryptionKeySharePublicParameters,
    /// Decryption key share public parameters for secp256r1 threshold decryption.
    pub secp256r1_decryption_key_share_public_parameters:
        class_groups::Secp256r1DecryptionKeySharePublicParameters,
}

/// Private output from the threshold encryption to sharing protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOutput {
    /// Shamir share for secp256k1 secret key (first secret).
    pub secp256k1_first_secret_key_share: group::Value<secp256k1::Scalar>,
    /// Shamir share for secp256k1 secret key (second secret).
    pub secp256k1_second_secret_key_share: group::Value<secp256k1::Scalar>,

    /// Shamir share for ristretto secret key (first secret).
    pub ristretto_first_secret_key_share: group::Value<ristretto::Scalar>,
    /// Shamir share for ristretto secret key (second secret).
    pub ristretto_second_secret_key_share: group::Value<ristretto::Scalar>,

    /// Shamir share for curve25519 secret key (first secret).
    pub curve25519_first_secret_key_share: group::Value<curve25519::Scalar>,
    /// Shamir share for curve25519 secret key (second secret).
    pub curve25519_second_secret_key_share: group::Value<curve25519::Scalar>,

    /// Shamir share for secp256r1 secret key (first secret).
    pub secp256r1_first_secret_key_share: group::Value<secp256r1::Scalar>,
    /// Shamir share for secp256r1 secret key (second secret).
    pub secp256r1_second_secret_key_share: group::Value<secp256r1::Scalar>,
}

/// PVSS dealing for a single secret.
/// Re-exported from class_groups::threshold_encryption_to_sharing.
pub type Dealing<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = class_groups::threshold_encryption_to_sharing::Dealing<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    GroupElement,
>;

/// PVSS dealings for a single curve (two secrets: first and second randomizer contributions).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CurveDealing<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::PrimeGroupElement<SCALAR_LIMBS> + Copy,
> where
    crypto_bigint::Int<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    class_groups::EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        group::GroupElement<
                Value = class_groups::CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    /// PVSS dealing for the first randomizer contribution.
    pub first_randomizer_contribution_dealing: Dealing<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    /// PVSS dealing for the second randomizer contribution.
    pub second_randomizer_contribution_dealing: Dealing<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
}

/// Type alias for secp256k1 curve dealings.
pub type Secp256k1CurveDealing = CurveDealing<
    { secp256k1::SCALAR_LIMBS },
    { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    secp256k1::GroupElement,
>;

/// Type alias for ristretto curve dealings.
pub type RistrettoCurveDealing = CurveDealing<
    { ristretto::SCALAR_LIMBS },
    { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    ristretto::GroupElement,
>;

/// Type alias for curve25519 curve dealings.
pub type Curve25519CurveDealing = CurveDealing<
    { curve25519::SCALAR_LIMBS },
    { class_groups::CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { class_groups::CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    curve25519::GroupElement,
>;

/// Type alias for secp256r1 curve dealings.
pub type Secp256r1CurveDealing = CurveDealing<
    { secp256r1::SCALAR_LIMBS },
    { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
    secp256r1::GroupElement,
>;

/// Message for Round 1: Dealing randomizers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealingRoundMessage {
    /// PVSS dealings for secp256k1 curve (first and second randomizer contributions).
    pub secp256k1_dealing_message: Secp256k1CurveDealing,
    /// PVSS dealings for ristretto curve (first and second randomizer contributions).
    pub ristretto_dealing_message: RistrettoCurveDealing,
    /// PVSS dealings for curve25519 curve (first and second randomizer contributions).
    pub curve25519_dealing_message: Curve25519CurveDealing,
    /// PVSS dealings for secp256r1 curve (first and second randomizer contributions).
    pub secp256r1_dealing_message: Secp256r1CurveDealing,
}

/// Message for Round 2: Accusations.
/// Round 2 message: Set of dealers whose shares this party verified (if online).
///
/// For PVSS Round 2 self-verification optimization:
/// - If party is online: `Some(verified_dealers)` - dealers whose shares passed verification
/// - If party is offline: `None`
pub type AccusationRoundMessage = Option<std::collections::HashSet<PartyID>>;

/// Decryption shares for a single secret with proof.
/// Re-exported from class_groups::threshold_encryption_to_sharing.
pub type CurveDecryptionSharesWithProof =
    class_groups::threshold_encryption_to_sharing::DecryptionShareAndProof<
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >;

/// Message for Round 3: Threshold decryption shares.
///
/// Each curve has separate first/second decryption shares with proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdDecryptionRoundMessage {
    /// Dealers identified as malicious during verification (sorted, deduplicated).
    pub malicious_dealers: Vec<PartyID>,
    /// Decryption shares for secp256k1 first secret.
    pub secp256k1_first_decryption_shares: CurveDecryptionSharesWithProof,
    /// Decryption shares for secp256k1 second secret.
    pub secp256k1_second_decryption_shares: CurveDecryptionSharesWithProof,
    /// Decryption shares for ristretto first secret.
    pub ristretto_first_decryption_shares: CurveDecryptionSharesWithProof,
    /// Decryption shares for ristretto second secret.
    pub ristretto_second_decryption_shares: CurveDecryptionSharesWithProof,
    /// Decryption shares for curve25519 first secret.
    pub curve25519_first_decryption_shares: CurveDecryptionSharesWithProof,
    /// Decryption shares for curve25519 second secret.
    pub curve25519_second_decryption_shares: CurveDecryptionSharesWithProof,
    /// Decryption shares for secp256r1 first secret.
    pub secp256r1_first_decryption_shares: CurveDecryptionSharesWithProof,
    /// Decryption shares for secp256r1 second secret.
    pub secp256r1_second_decryption_shares: CurveDecryptionSharesWithProof,
}

/// Message for Round 4: Aggregation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationRoundMessage;

#[cfg(test)]
mod tests {
    use super::*;
    use group::GroupElement as _;

    #[test]
    fn test_dealing_round_message_structure() {
        let _msg_type_check = |msg: DealingRoundMessage| {
            let _secp256k1 = msg.secp256k1_dealing_message;
            let _ristretto = msg.ristretto_dealing_message;
            let _curve25519 = msg.curve25519_dealing_message;
            let _secp256r1 = msg.secp256r1_dealing_message;
        };
    }

    #[test]
    fn test_private_output_uses_native_scalar_types() {
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let secp256k1_scalar =
            secp256k1::Scalar::neutral_from_public_parameters(&scalar_group_public_parameters)
                .unwrap();

        let ristretto_params = ristretto::scalar::PublicParameters::default();
        let ristretto_scalar =
            ristretto::Scalar::neutral_from_public_parameters(&ristretto_params).unwrap();

        let curve25519_params = curve25519::scalar::PublicParameters::default();
        let curve25519_scalar =
            curve25519::Scalar::neutral_from_public_parameters(&curve25519_params).unwrap();

        let secp256r1_params = secp256r1::scalar::PublicParameters::default();
        let secp256r1_scalar =
            secp256r1::Scalar::neutral_from_public_parameters(&secp256r1_params).unwrap();

        let private_output = PrivateOutput {
            secp256k1_first_secret_key_share: secp256k1_scalar.value(),
            secp256k1_second_secret_key_share: secp256k1_scalar.value(),
            ristretto_first_secret_key_share: ristretto_scalar.value(),
            ristretto_second_secret_key_share: ristretto_scalar.value(),
            curve25519_first_secret_key_share: curve25519_scalar.value(),
            curve25519_second_secret_key_share: curve25519_scalar.value(),
            secp256r1_first_secret_key_share: secp256r1_scalar.value(),
            secp256r1_second_secret_key_share: secp256r1_scalar.value(),
        };

        let _: group::Value<secp256k1::Scalar> = private_output.secp256k1_first_secret_key_share;
        let _: group::Value<ristretto::Scalar> = private_output.ristretto_first_secret_key_share;
        let _: group::Value<curve25519::Scalar> = private_output.curve25519_first_secret_key_share;
        let _: group::Value<secp256r1::Scalar> = private_output.secp256r1_first_secret_key_share;
    }
}
