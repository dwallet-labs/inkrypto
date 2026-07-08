// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # SSS Schnorr Pre-signing
//!
//! This module implements Protocol 9.2: $\Pi_{\textsf{pres}}^{\textsf{Schnorr}}$
//!
//! ## Protocol Parameters
//!
//! - Elliptic curve group description $(\mathbb{G}, G, q)$
//! - Access structure $\Gamma_B$
//! - Session ID $\textsf{sid}$
//! - VSS public parameters $\textsf{pp}_{\textsf{VSS}}$:
//!   - Generated during DKG setup or presign initialization
//!   - Includes encryption public keys for all parties (each party generates their own keypair)
//!   - Each party broadcasts their encryption public key
//!   - All parties collect the public keys into `party_encryption_keys`
//!   - UC proofs verify knowledge of decryption keys
//!
//! ## Protocol Output
//!
//! - $K_{B,0}, K_{B,1}$: Points on the curve equal to $k_0 \cdot G$ and $k_1 \cdot G$
//! - Each distributed party holds secret shares $[k_0]_i, [k_1]_i$
//!
//! ## Distributed Party ($B_i$) Actions
//!
//! ### Round 1
//!
//! 1. Sample $k_0^i, k_1^i \gets \mathbb{Z}_q$
//! 2. Run VSS on each:
//!    - $(\{C_\ell^0\}_{\ell \in [t]}, \{\textsf{ct}_{i,0}^j\}_{j \in [n]}, \pi_{i,0}^{\textsf{PVSS}}) \gets \textsf{VSS}(k_0^i)$
//!    - $(\{C_\ell^1\}_{\ell \in [t]}, \{\textsf{ct}_{i,1}^j\}_{j \in [n]}, \pi_{i,1}^{\textsf{PVSS}}) \gets \textsf{VSS}(k_1^i)$
//! 3. Broadcast commitments, ciphertexts, and proofs
//!
//! ### Round 2
//!
//! 1. Receive and decrypt to get shares $[k_j]_i$
//! 2. For PVSS: verify proofs, collect valid subset $S_{\textsf{pres}} \in \Gamma_B$
//! 3. For VSS: collect approvals, handle complaints
//! 4. Aggregate:
//!    - $K_{B,0} = \sum_{j \in S_{\textsf{pres}}} C_0^j$
//!    - $K_{B,1} = \sum_{j \in S_{\textsf{pres}}} C_1^j$
//!    - $[k_0]_i = \sum_{j \in S_{\textsf{pres}}} [k_j^0]_i$
//!    - $[k_1]_i = \sum_{j \in S_{\textsf{pres}}} [k_j^1]_i$
//!
//! ## Centralized Party ($A$) Actions
//!
//! 1. Receive $(K_{B,0}, K_{B,1})$ via global broadcast
//! 2. Verify $K_{B,0}, K_{B,1} \in \mathbb{G} \setminus \{0\}$
//! 3. Output $(K_{B,0}, K_{B,1})$

use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, DecryptionKey, EncryptionKey, EquivalenceClass,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use class_groups::MultiFoldNupowAccelerator;
use commitment::CommitmentSizedNumber;
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
};
use serde::{Deserialize, Serialize};

use crate::dkg;
use crate::schnorr::vss::presign::decentralized_party::PublicInput;
use crate::schnorr::VerifyingKey;
use crate::vss::schnorr::Protocol;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use group::StatisticalSecuritySizedNumber;
use mpc::secret_sharing::shamir::known_order::EncryptionPublicKey;

pub mod decentralized_party;

/// The public presign output for VSS-based Schnorr protocols.
///
/// This is simpler than AHE-based presign output as it doesn't include encrypted shares.
/// The centralized party only receives the public nonce shares.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Presign<GroupElementValue> {
    /// The session ID of the Presign protocol.
    pub session_id: CommitmentSizedNumber,
    /// The index of this presign out of the blended presign vector generated in this session.
    pub presign_blending_index: u16,
    /// Public nonce commitment $K_{B,0}$.
    pub decentralized_party_nonce_public_share_first_part: GroupElementValue,
    /// Public nonce commitment $K_{B,1}$.
    pub decentralized_party_nonce_public_share_second_part: GroupElementValue,
}

/// Private output of the presign protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePresignOutput<ScalarValue, GroupElementValue> {
    /// The session ID of the Presign protocol.
    pub session_id: CommitmentSizedNumber,
    /// The index of this presign out of the blended presign vector generated in this session.
    pub presign_blending_index: u16,
    /// The first part of the private nonce share $[k_0]_i$.
    pub nonce_share_first_part: ScalarValue,
    /// The second part of the private nonce share $[k_0]_i$.
    pub nonce_share_second_part: ScalarValue,
    /// Blended polynomial coefficient commitments for the first nonce share part.
    /// Used for signature share verification (DOS protection).
    /// Note: These are public but kept in private output since they are O(threshold)
    /// in size and not needed by the centralized party.
    pub nonce_share_first_part_coefficient_commitments: Vec<GroupElementValue>,
    /// Blended polynomial coefficient commitments for the second nonce share part.
    /// Used for signature share verification (DOS protection).
    /// Note: These are public but kept in private output since they are O(threshold)
    /// in size and not needed by the centralized party.
    pub nonce_share_second_part_coefficient_commitments: Vec<GroupElementValue>,
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > crate::presign::Protocol
    for Protocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
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
    SetupParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: DeriveFromPlaintextPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
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
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
        SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + group::Samplable
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    group::Value<GroupElement::Scalar>: Into<Uint<SCALAR_LIMBS>> + From<Uint<SCALAR_LIMBS>>,
    group::PublicParameters<GroupElement::Scalar>: Default,
{
    type DKGProtocol = crate::class_groups::asynchronous::DKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
    type Presign = Presign<group::Value<GroupElement>>;
    type HPKEEncryptionKey = EncryptionPublicKey;
    type PresignPublicInput =
        PublicInput<<Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters>;
    type PresignPrivateInput = decentralized_party::PrivateInput;
    type PresignParty = decentralized_party::Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
}
