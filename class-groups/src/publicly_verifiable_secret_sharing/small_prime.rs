// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(type_alias_bounds)]

//! Single-Prime PVSS (Publicly Verifiable Secret Sharing)
//!
//! This module implements PVSS using class groups encryption without CRT (Chinese Remainder Theorem).
//! Unlike the full reconfiguration protocol which uses CRT across multiple primes for security,
//! this simpler version operates on a single prime for threshold encryption to sharing conversion.
//!
//! # Protocol Overview
//!
//! Based on Protocol C.6 from <https://eprint.iacr.org/archive/2025/297/20250522:123428>
//!
//! A dealer wants to share a secret $s$ among $n$ parties with threshold $t$:
//!
//! 1. **Dealing**: Sample polynomial $f(x) = s + a_1 x + \cdots + a_{t-1} x^{t-1}$
//!    - Compute shares: $s_i = f(i)$ for each party $i$
//!    - Compute commitments: $C_j = \bar{g}^{a_j}$ for coefficients
//!    - Encrypt each share: $E(\textsf{pk}_i, s_i)$ using party $i$'s encryption key
//!    - Generate EncDL proof: prove $E(\textsf{pk}_i, s_i)$ encrypts value committed in $\prod_{j=0}^{t-1} C_j^{i^j}$
//!
//! 2. **Verification**: Each party verifies:
//!    - EncDL proofs are valid (public verification)
//!    - Decrypted share matches commitments (private verification after decryption)
//!
//! 3. **Reconstruction**: Combine $t$ valid shares using Lagrange interpolation
//!
//! # Differences from CRT-based PVSS
//!
//! - **No CRT iteration**: Single encryption per share instead of `NUM_PRIMES` encryptions
//! - **Simpler proofs**: Single EncDL proof per share instead of array of proofs
//! - **Direct decryption**: No CRT reconstruction needed
//! - **Single setup**: One set of public parameters instead of per-CRT-prime parameters
//!
//! # Design Pattern
//!
//! This module follows the standard cryptography library pattern:
//! - Fully generic types with const parameters and trait bounds
//! - Functions written generically and instantiated at call sites
//! - Type aliases per curve for convenience

pub mod deal_shares;
pub mod encryption;
pub mod verify_shares;

// Re-export key functions from submodules
pub use deal_shares::{
    deal_secret_shares, deal_secret_shares_with_preverified_encryption_keys, decrypt_share,
    DealSecretSharesOutput,
};
pub use verify_shares::{
    verify_dealt_shares, verify_encryptions_of_secret_shares, verify_shares_dealt_to_specific_party,
};

use std::collections::HashMap;

use crypto_bigint::{Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use commitment;
use group::{curve25519, ristretto, secp256k1, secp256r1, PartyID, PrimeGroupElement};
use maurer::{encryption_of_discrete_log, SOUND_PROOFS_REPETITIONS};

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::{encryption_key, encryption_key::EncryptionKey};
use crate::{
    equivalence_class, CiphertextSpaceValue, CompactIbqf,
    CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS, CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CURVE25519_SCALAR_LIMBS, RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_SCALAR_LIMBS, SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256R1_SCALAR_LIMBS,
};

// ================================================================================================
// Protocol Context
// ================================================================================================

/// Protocol context for single-prime PVSS EncDL proofs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolContext {
    pub dealer_party_id: PartyID,
    pub participating_party_id: PartyID,
    pub session_id: commitment::CommitmentSizedNumber,
    pub base_protocol_context: crate::publicly_verifiable_secret_sharing::BaseProtocolContext,
}

/// Encryption of Discrete Log proof for PVSS.
///
/// Proves that a ciphertext encrypts a discrete log (share value) matching a commitment.
pub type EncryptionOfDiscreteLogProof<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    encryption_of_discrete_log::Language<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        SCALAR_LIMBS, // Share size = scalar size (Shamir mod q)
        homomorphic_encryption::PlaintextSpaceGroupElement<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        GroupElement, // Curve group element for public commitments
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    ProtocolContext,
>;

/// Public parameters for EncDL proof language.
pub type EncryptionOfDiscreteLogPublicParameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
> = encryption_of_discrete_log::PublicParameters<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    SCALAR_LIMBS, // Share size = scalar size (Shamir mod q)
    homomorphic_encryption::PlaintextSpaceGroupElement<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    GroupElement, // Curve group element for public commitments
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// A single dealt secret share with its encryption proof.
///
/// Contains:
/// - Proof $\pi$: EncDL proof that ciphertext encrypts the correct share
/// - Ciphertext $\textsf{ct}$: Encryption of the share value
///
/// This is the serializable form sent over the network.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "")]
pub struct DealtSecretShareMessage<
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
            PublicParameters = equivalence_class::PublicParameters<
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
    >: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = crate::CiphertextSpaceGroupElement<
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
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + crate::encryption_key::public_parameters::Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    /// EncDL proof that ciphertext encrypts the correct share.
    pub encryption_of_secret_share_proof: EncryptionOfDiscreteLogProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    /// Encryption of the share value.
    pub encryption_of_secret_share: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
}

/// Complete dealing message containing commitments and encrypted shares.
///
/// Sent from dealer to all parties, contains:
/// - Commitments to polynomial coefficients $C_j = g^{a_j}$ (curve group commitments)
/// - Encrypted shares + EncDL proofs for each party
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(bound = "")]
pub struct DealSecretMessage<
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
            PublicParameters = equivalence_class::PublicParameters<
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
    >: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = crate::CiphertextSpaceGroupElement<
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
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + crate::encryption_key::public_parameters::Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    /// Commitments to polynomial coefficients: $C_j = g^{a_j}$ for $j \in [0, t-1]$ (curve group)
    pub coefficients_contribution_commitments: Vec<group::Value<GroupElement>>,

    /// Encrypted shares with proofs for each party.
    ///
    /// Structure: `participating_party_id -> DealtSecretShareMessage`
    pub encryptions_of_secret_shares_and_proofs: HashMap<
        PartyID,
        DealtSecretShareMessage<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
}

// ================================================================================================
// Type Aliases per Curve (keeping original exports for compatibility)
// ================================================================================================

// SECP256K1
pub type Secp256k1EncryptionOfDiscreteLogProof = EncryptionOfDiscreteLogProof<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;

pub type Secp256k1EncryptionOfDiscreteLogPublicParameters = EncryptionOfDiscreteLogPublicParameters<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;

pub type Secp256k1DealtSecretShareMessage = DealtSecretShareMessage<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;

pub type Secp256k1DealSecretMessage = DealSecretMessage<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;

// RISTRETTO
pub type RistrettoEncryptionOfDiscreteLogProof = EncryptionOfDiscreteLogProof<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;

pub type RistrettoEncryptionOfDiscreteLogPublicParameters = EncryptionOfDiscreteLogPublicParameters<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;

pub type RistrettoDealtSecretShareMessage = DealtSecretShareMessage<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;

pub type RistrettoDealSecretMessage = DealSecretMessage<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;

// SECP256R1
pub type Secp256r1EncryptionOfDiscreteLogProof = EncryptionOfDiscreteLogProof<
    SECP256R1_SCALAR_LIMBS,
    SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256r1::GroupElement,
>;

pub type Secp256r1EncryptionOfDiscreteLogPublicParameters = EncryptionOfDiscreteLogPublicParameters<
    SECP256R1_SCALAR_LIMBS,
    SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256r1::GroupElement,
>;

pub type Secp256r1DealtSecretShareMessage = DealtSecretShareMessage<
    SECP256R1_SCALAR_LIMBS,
    SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256r1::GroupElement,
>;

pub type Secp256r1DealSecretMessage = DealSecretMessage<
    SECP256R1_SCALAR_LIMBS,
    SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256r1::GroupElement,
>;

// CURVE25519
pub type Curve25519EncryptionOfDiscreteLogProof = EncryptionOfDiscreteLogProof<
    CURVE25519_SCALAR_LIMBS,
    CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    curve25519::GroupElement,
>;

pub type Curve25519EncryptionOfDiscreteLogPublicParameters =
    EncryptionOfDiscreteLogPublicParameters<
        CURVE25519_SCALAR_LIMBS,
        CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        curve25519::GroupElement,
    >;

pub type Curve25519DealtSecretShareMessage = DealtSecretShareMessage<
    CURVE25519_SCALAR_LIMBS,
    CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    curve25519::GroupElement,
>;

pub type Curve25519DealSecretMessage = DealSecretMessage<
    CURVE25519_SCALAR_LIMBS,
    CURVE25519_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CURVE25519_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    curve25519::GroupElement,
>;

// ================================================================================================
// Helper Functions
// ================================================================================================

/// Constructs public parameters for the EncDL proof language.
///
/// Sets up the language parameters for proving that a ciphertext encrypts a discrete log
/// (share value) that matches a commitment.
///
/// # Arguments
/// * `scalar_group_public_parameters` - Parameters for the scalar/share group
/// * `group_public_parameters` - Parameters for the curve group element (for commitments)
/// * `encryption_scheme_public_parameters` - Parameters for the encryption scheme
///
/// # Returns
/// Public parameters for the EncDL proof language
pub fn construct_encryption_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
) -> EncryptionOfDiscreteLogPublicParameters<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    GroupElement,
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
            PublicParameters = equivalence_class::PublicParameters<
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
    >: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = crate::CiphertextSpaceGroupElement<
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
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + crate::encryption_key::public_parameters::Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    let generator = GroupElement::generator_value_from_public_parameters(&group_public_parameters);

    EncryptionOfDiscreteLogPublicParameters::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >::new::<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
        generator,
        None,
    )
}
