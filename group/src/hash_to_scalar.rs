// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::Reduce;
use crate::{Error, Result};
use crate::{GroupElement, KnownOrderGroupElement, PrimeGroupElement};
use crypto_bigint::{Encoding, NonZero, U256};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt::{Display, Formatter};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub enum HashScheme {
    Keccak256,
    SHA256,
    /// A double sha256 hash: h(x) = sha256(sha256(x)). Used by bitcoin
    DoubleSHA256,
    SHA512,
    /// Not a hash-function per-sa, but a STROBE-based transcript construction.
    /// Used in Schnorrkel signatures.
    Merlin,
}

impl Display for HashScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HashScheme::Keccak256 => write!(f, "Keccak256"),
            HashScheme::SHA256 => write!(f, "SHA256"),
            HashScheme::DoubleSHA256 => write!(f, "DoubleSHA256"),
            HashScheme::SHA512 => write!(f, "SHA512"),
            HashScheme::Merlin => write!(f, "Merlin"),
        }
    }
}

/// Computes $H(m)$ as bytes.
pub fn hash(message: &[u8], hash_type: HashScheme) -> Result<[u8; 32]> {
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
        HashScheme::Merlin | HashScheme::SHA512 => Err(Error::UnsupportedHashType),
    }
}

/// Computes a hash of type `hash_type` on `message` with the given `prefix` and interprets it as a field element (scalar).
///
/// Note: the bits2int function as defined in RFC6979 § 2.3.2  as well as SEC1 §2.3.8
/// requires to truncate hash outputs if they are larger than the size of the field in bits.
/// This conflicts with the implementation of ED25519 which requires to take a Sha512 (512-bit) hash output and reduce it as-is by the field order,
/// which also is the most intuitive solution. As such, it is the one we take in this function,
/// and the caller is responsible to assure it is aligned with this implementation (otherwise, it can simply reject/not support larger-sized hashes).
pub fn hash_to_scalar<const SCALAR_LIMBS: usize, GroupElement: PrimeGroupElement<SCALAR_LIMBS>>(
    message: &[u8],
    hash_type: HashScheme,
    scalar_group_public_parameters: &crate::PublicParameters<GroupElement::Scalar>,
) -> Result<GroupElement::Scalar> {
    let scalar_group_order = NonZero::new(GroupElement::Scalar::order_from_public_parameters(
        scalar_group_public_parameters,
    ))
    .unwrap();

    let hashed_message = hash(message, hash_type)?;

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
            &scalar_group_public_parameters,
        )
        .unwrap();

        let expected_sha256_scalar = message_digest(message, HashScheme::SHA256);

        assert_eq!(sha256_scalar, expected_sha256_scalar);

        let keccak256_scalar = hash_to_scalar::<SCALAR_LIMBS, GroupElement>(
            message,
            HashScheme::SHA256,
            &scalar_group_public_parameters,
        )
        .unwrap();

        let expected_keccak256_scalar = message_digest(message, HashScheme::SHA256);

        assert_eq!(keccak256_scalar, expected_keccak256_scalar);
    }
}
