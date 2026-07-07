// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::Reduce;
use crate::{Error, ErrorKind, Result};
use crate::{GroupElement, KnownOrderGroupElement, PrimeGroupElement};
use crypto_bigint::{Encoding, NonZero, U256};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt::{Display, Formatter};

/// Output length, in bytes, of the BLAKE2b digests we produce (truncated to 256 bits).
const BLAKE2B_HASH_LENGTH: usize = 32;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum HashScheme {
    Keccak256,
    SHA256,
    /// A double sha256 hash: h(x) = sha256(sha256(x)). Used by bitcoin
    DoubleSHA256,
    SHA512,
    /// Not a hash-function per-sa, but a STROBE-based transcript construction.
    /// Used in Schnorrkel signatures.
    Merlin,
    /// BLAKE2b truncated to 256 bits, with per-call `personal` and `salt`
    /// bytes (see [`HashContext::Blake2b`]). Used by Zcash sighashes and any
    /// chain that needs domain-separated BLAKE2b.
    Blake2b256,
}

impl Display for HashScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HashScheme::Keccak256 => write!(f, "Keccak256"),
            HashScheme::SHA256 => write!(f, "SHA256"),
            HashScheme::DoubleSHA256 => write!(f, "DoubleSHA256"),
            HashScheme::SHA512 => write!(f, "SHA512"),
            HashScheme::Merlin => write!(f, "Merlin"),
            HashScheme::Blake2b256 => write!(f, "Blake2b256"),
        }
    }
}

/// Per-call data accompanying a [`HashScheme`].
///
/// Kept separate from `HashScheme` (which stays `Copy` and is serialized into
/// many `PublicInput` structs) so that schemes needing per-session data can
/// carry it without bloating the scheme enum or rippling through every MPC
/// trait impl. An enum (rather than a struct with optional fields) so that
/// scheme/context mismatches are a validation error rather than silently
/// ignored data — important for a crypto API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum HashContext {
    /// No per-call context. Compatible with `Keccak256`, `SHA256`,
    /// `DoubleSHA256`, `SHA512` and the secp256k1/curve25519 schnorr
    /// challenge derivations.
    None,
    /// BLAKE2b personalization and salt (each at most 16 bytes per the
    /// BLAKE2b spec).
    Blake2b { personal: Vec<u8>, salt: Vec<u8> },
    /// Schnorrkel sr25519 signing context bytes.
    Schnorrkel { signing_context: Vec<u8> },
}

impl HashContext {
    /// Returns the schnorrkel signing-context bytes, or an error if this
    /// context isn't `Schnorrkel`.
    pub fn schnorrkel_signing_context(&self) -> Result<&[u8]> {
        match self {
            HashContext::Schnorrkel { signing_context } => Ok(signing_context),
            _ => Err(Error::from(ErrorKind::InvalidParameters)),
        }
    }
}

impl HashScheme {
    /// Validates that `context` matches what this scheme requires.
    ///
    /// Returns `InvalidParameters` on a mismatch (e.g. `SHA256` with a
    /// `Blake2b` context, or `Blake2b256` with `None`).
    ///
    /// Internal to this crate — callers go through [`hash`], which validates.
    fn validate_context(&self, context: &HashContext) -> Result<()> {
        match (self, context) {
            (HashScheme::Keccak256, HashContext::None)
            | (HashScheme::SHA256, HashContext::None)
            | (HashScheme::DoubleSHA256, HashContext::None)
            | (HashScheme::SHA512, HashContext::None) => Ok(()),
            (HashScheme::Merlin, HashContext::Schnorrkel { .. }) => Ok(()),
            (HashScheme::Blake2b256, HashContext::Blake2b { personal, salt }) => {
                if personal.len() > 16 || salt.len() > 16 {
                    return Err(Error::from(ErrorKind::InvalidParameters));
                }
                Ok(())
            }
            _ => Err(Error::from(ErrorKind::InvalidParameters)),
        }
    }
}

/// Computes $H(m)$ as bytes.
pub fn hash(message: &[u8], hash_type: HashScheme, hash_context: &HashContext) -> Result<[u8; 32]> {
    hash_type.validate_context(hash_context)?;
    match hash_type {
        HashScheme::Keccak256 => {
            let mut hasher = sha3::Keccak256::new();
            hasher.update(message);
            Ok(hasher.finalize().0)
        }
        HashScheme::SHA256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(message);
            Ok(hasher.finalize().0)
        }
        HashScheme::DoubleSHA256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(message);
            let hash = hasher.finalize().0;

            let mut double_hasher = sha2::Sha256::new();
            double_hasher.update(hash);
            Ok(double_hasher.finalize().0)
        }
        HashScheme::Blake2b256 => {
            let (personal, salt) = match hash_context {
                HashContext::Blake2b { personal, salt } => (personal.as_slice(), salt.as_slice()),
                _ => unreachable!("validate_context guarantees Blake2b context here"),
            };
            // Matches the librustzcash sighash construction
            // (`blake2b_simd::Params::new().hash_length(32).personal(..).to_state()`),
            // which omits `.salt()` entirely. We call `.salt(salt)` unconditionally, but
            // with an empty `salt` the output is byte-for-byte the zcash digest: BLAKE2b
            // mixes the salt only via the zero-initialized parameter block, so an empty
            // salt leaves that field all-zero — bit-identical to never setting it.
            // (This is an output equivalence, not the same call: zcash never sets a salt;
            // a non-empty `salt` is the only thing that would diverge from it.) `salt` is
            // a generic domain-separation extension for chains that do use one.
            let digest = blake2b_simd::Params::new()
                .hash_length(BLAKE2B_HASH_LENGTH)
                .personal(personal)
                .salt(salt)
                .to_state()
                .update(message)
                .finalize();
            let mut out = [0u8; BLAKE2B_HASH_LENGTH];
            out.copy_from_slice(digest.as_bytes());
            Ok(out)
        }
        // SHA512 and Merlin don't produce a 32-byte digest from a plain
        // message — they're consumed by algorithm-specific paths (EdDSA,
        // Schnorrkel) rather than this generic `hash()`.
        HashScheme::Merlin | HashScheme::SHA512 => Err(Error::from(ErrorKind::UnsupportedHashType)),
    }
}

/// Computes a hash of type `hash_type` on `message` and interprets it as a field element (scalar).
///
/// Note: the bits2int function as defined in RFC6979 § 2.3.2  as well as SEC1 §2.3.8
/// requires to truncate hash outputs if they are larger than the size of the field in bits.
/// This conflicts with the implementation of ED25519 which requires to take a Sha512 (512-bit) hash output and reduce it as-is by the field order,
/// which also is the most intuitive solution. As such, it is the one we take in this function,
/// and the caller is responsible to assure it is aligned with this implementation (otherwise, it can simply reject/not support larger-sized hashes).
pub fn hash_to_scalar<const SCALAR_LIMBS: usize, GroupElement: PrimeGroupElement<SCALAR_LIMBS>>(
    message: &[u8],
    hash_type: HashScheme,
    hash_context: &HashContext,
    scalar_group_public_parameters: &crate::PublicParameters<GroupElement::Scalar>,
) -> Result<GroupElement::Scalar> {
    let scalar_group_order = NonZero::new(GroupElement::Scalar::order_from_public_parameters(
        scalar_group_public_parameters,
    ))
    .unwrap();

    let hashed_message = hash(message, hash_type, hash_context)?;

    GroupElement::Scalar::new(
        crate::Value::<GroupElement::Scalar>::from(
            U256::from_be_bytes(hashed_message).reduce(&scalar_group_order),
        ),
        scalar_group_public_parameters,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1;
    use k256::elliptic_curve;
    use secp256k1::{GroupElement, SCALAR_LIMBS};
    use sha2::digest::FixedOutput;

    fn message_digest(message: &[u8], hash_type: HashScheme) -> secp256k1::Scalar {
        let hash = match hash_type {
            HashScheme::Keccak256 => &sha3::Keccak256::new_with_prefix(message).finalize_fixed(),
            HashScheme::SHA256 => &sha2::Sha256::new_with_prefix(message).finalize_fixed(),
            _ => unimplemented!(),
        };

        #[allow(clippy::useless_conversion)]
        let m = <elliptic_curve::Scalar<k256::Secp256k1> as k256::elliptic_curve::ops::Reduce<
            k256::FieldBytes,
        >>::reduce(hash);
        U256::from(m).into()
    }

    #[test]
    fn hashes() {
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let message = b"hash me";

        let sha256_scalar = hash_to_scalar::<SCALAR_LIMBS, GroupElement>(
            message,
            HashScheme::SHA256,
            &HashContext::None,
            &scalar_group_public_parameters,
        )
        .unwrap();

        let expected_sha256_scalar = message_digest(message, HashScheme::SHA256);

        assert_eq!(sha256_scalar, expected_sha256_scalar);

        let keccak256_scalar = hash_to_scalar::<SCALAR_LIMBS, GroupElement>(
            message,
            HashScheme::SHA256,
            &HashContext::None,
            &scalar_group_public_parameters,
        )
        .unwrap();

        let expected_keccak256_scalar = message_digest(message, HashScheme::SHA256);

        assert_eq!(keccak256_scalar, expected_keccak256_scalar);
    }

    #[test]
    fn blake2b256_matches_reference() {
        let message = b"the quick brown fox";
        let personal = b"ZcashSigHash\x00\x00\x00\x00"; // 16 bytes
        let salt: &[u8] = b"";

        let context = HashContext::Blake2b {
            personal: personal.to_vec(),
            salt: salt.to_vec(),
        };

        let got = hash(message, HashScheme::Blake2b256, &context).unwrap();

        let expected = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(personal)
            .salt(salt)
            .to_state()
            .update(message)
            .finalize();

        assert_eq!(&got[..], expected.as_bytes());
    }

    #[test]
    fn validate_context_matrix() {
        // Legal pairs.
        assert!(HashScheme::SHA256
            .validate_context(&HashContext::None)
            .is_ok());
        assert!(HashScheme::Keccak256
            .validate_context(&HashContext::None)
            .is_ok());
        assert!(HashScheme::DoubleSHA256
            .validate_context(&HashContext::None)
            .is_ok());
        assert!(HashScheme::SHA512
            .validate_context(&HashContext::None)
            .is_ok());
        assert!(HashScheme::Merlin
            .validate_context(&HashContext::Schnorrkel {
                signing_context: b"substrate".to_vec()
            })
            .is_ok());
        assert!(HashScheme::Blake2b256
            .validate_context(&HashContext::Blake2b {
                personal: vec![0u8; 16],
                salt: vec![],
            })
            .is_ok());

        // Illegal pairs.
        assert!(HashScheme::SHA256
            .validate_context(&HashContext::Blake2b {
                personal: vec![],
                salt: vec![]
            })
            .is_err());
        assert!(HashScheme::Blake2b256
            .validate_context(&HashContext::None)
            .is_err());
        assert!(HashScheme::Merlin
            .validate_context(&HashContext::None)
            .is_err());
        // Personal too long.
        assert!(HashScheme::Blake2b256
            .validate_context(&HashContext::Blake2b {
                personal: vec![0u8; 17],
                salt: vec![],
            })
            .is_err());
    }
}
