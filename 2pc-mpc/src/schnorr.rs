// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub mod presign;
pub mod sign;

use crate::sign::EncodableSignature;
use crate::{Error, Result};
use curve25519_dalek::RistrettoPoint;
use ecdsa::elliptic_curve::group::GroupEncoding;
use ecdsa::elliptic_curve::point::AffineCoordinates;
use group::{
    curve25519, ristretto, secp256k1, GroupElement, HashScheme, HashToGroup, PrimeGroupElement,
};
use k256::schnorr::signature::digest::Digest;
use k256::schnorr::signature::Verifier;
pub use presign::Presign;
use schnorrkel::context::{SigningContext, SigningTranscript};
use serde::{Deserialize, Serialize};
use sha2::digest::FixedOutput;
use sha2::Sha256;
use std::fmt::Debug;
use std::ops::Neg;

pub const TAPROOT_CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// A standardized Schnorr verifying key.
pub trait VerifyingKey<const SCALAR_LIMBS: usize>:
    PrimeGroupElement<SCALAR_LIMBS> + HashToGroup
{
    /// A standardized Schnorr signature for a supported elliptic curve.
    /// Should be serialized as defined by the standard.
    type Signature: TryFrom<(Self::Value, group::Value<Self::Scalar>), Error = Error>
        + EncodableSignature;

    fn derive_challenge(
        &self,
        public_nonce: &Self,
        message: &[u8],
        hash_type: HashScheme,
    ) -> Result<Self::Scalar>;

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        signature: &Self::Signature,
    ) -> Result<()>;

    /// Checks whether this point is normalized, as defined by the Taproot standard, which requires a point's `y` coordinate to be even.
    /// Taproot is only defined for `secp256k1`, and so the bench implementation defaults to `true`.
    fn is_taproot_normalized(&self) -> bool {
        true
    }
}

/// Creates a tagged hash as by the Taproot standard.
fn taproot_tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct TaprootSignature(
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    k256::schnorr::SignatureBytes,
);

impl From<TaprootSignature> for k256::schnorr::SignatureBytes {
    fn from(value: TaprootSignature) -> Self {
        value.0
    }
}

impl EncodableSignature for TaprootSignature {
    type Encoding = k256::schnorr::SignatureBytes;
}

impl TryFrom<(secp256k1::group_element::Value, secp256k1::Scalar)> for TaprootSignature {
    type Error = Error;
    fn try_from(
        (public_nonce, response): (secp256k1::group_element::Value, secp256k1::Scalar),
    ) -> std::result::Result<Self, Self::Error> {
        let mut encoded_signature = [0u8; 64];
        let response_inner: k256::Scalar = response.into();
        let (r_bytes, s_bytes) = encoded_signature.split_at_mut(32);
        let r: k256::AffinePoint = public_nonce.into();
        r_bytes.copy_from_slice(&r.x().0);
        s_bytes.copy_from_slice(&response_inner.to_bytes());

        Ok(Self(encoded_signature))
    }
}

impl VerifyingKey<{ secp256k1::SCALAR_LIMBS }> for secp256k1::GroupElement {
    type Signature = TaprootSignature;

    fn derive_challenge(
        &self,
        public_nonce: &Self,
        message: &[u8],
        hash_type: HashScheme,
    ) -> Result<Self::Scalar> {
        if hash_type != HashScheme::SHA256 {
            return Err(Error::Nonstandard);
        }

        let mut digest = taproot_tagged_hash(TAPROOT_CHALLENGE_TAG);

        let r: k256::AffinePoint = public_nonce.value().into();
        let verifying_key: k256::AffinePoint = self.value().into();

        // Encodes the (normalized) `x` coordinate of this point,
        // for both the public nonce and public key,
        // as per the Taproot standard.
        digest.update(r.x());
        digest.update(verifying_key.x());

        // Encode a Sha256 hash on the message, as per the Taproot standard.
        let mut message_digest = Sha256::new();
        message_digest.update(message);
        digest.update(message_digest.finalize_fixed());

        let e = <k256::Scalar as k256::elliptic_curve::ops::Reduce<k256::FieldBytes>>::reduce(
            &digest.finalize(),
        );

        Ok(e.into())
    }

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        signature: &Self::Signature,
    ) -> Result<()> {
        if hash_type != HashScheme::SHA256 {
            return Err(Error::Nonstandard);
        }

        let signature = k256::schnorr::Signature::from_bytes(&signature.0)
            .map_err(|_| Error::SignatureVerification)?;

        // Verify the signature against the normalized public key.
        // If a non-zero group element is not Taproot normalized then its negation will be.
        let public_key = if self.is_taproot_normalized() {
            *self
        } else {
            self.neg()
        };
        let verifying_key: k256::AffinePoint = public_key.value().into();
        let verifying_key = k256::PublicKey::from_affine(verifying_key)
            .map_err(|_| Error::SignatureVerification)?;
        let verifying_key = k256::schnorr::VerifyingKey::try_from(verifying_key)
            .map_err(|_| Error::SignatureVerification)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| Error::SignatureVerification)
    }

    fn is_taproot_normalized(&self) -> bool {
        let affine_point: k256::AffinePoint = self.value().into();

        let y_is_odd: bool =
            <k256::AffinePoint as AffineCoordinates>::y_is_odd(&affine_point).into();

        !y_is_odd
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct EdDSASignature(
    #[serde(with = "group::helpers::const_generic_array_serialization")] ed25519::SignatureBytes,
);

impl From<EdDSASignature> for ed25519::SignatureBytes {
    fn from(value: EdDSASignature) -> Self {
        value.0
    }
}

impl EncodableSignature for EdDSASignature {
    type Encoding = ed25519::SignatureBytes;
}

impl TryFrom<(curve25519::GroupElement, curve25519::Scalar)> for EdDSASignature {
    type Error = Error;
    fn try_from(
        (public_nonce, response): (curve25519::GroupElement, curve25519::Scalar),
    ) -> std::result::Result<Self, Self::Error> {
        let public_nonce: curve25519_dalek::EdwardsPoint = public_nonce.into();
        let response: curve25519_dalek::Scalar = response.into();

        let signature =
            ed25519::Signature::from_components(public_nonce.to_bytes(), *response.as_bytes());

        Ok(Self(signature.into()))
    }
}

impl VerifyingKey<{ curve25519::SCALAR_LIMBS }> for curve25519::GroupElement {
    type Signature = EdDSASignature;

    fn derive_challenge(
        &self,
        public_nonce: &Self,
        message: &[u8],
        hash_type: HashScheme,
    ) -> Result<Self::Scalar> {
        if hash_type != HashScheme::SHA512 {
            return Err(Error::Nonstandard);
        }

        let public_nonce: curve25519_dalek::EdwardsPoint = (*public_nonce).into();
        let verifying_key: curve25519_dalek::EdwardsPoint = (*self).into();

        let mut hasher = sha2::Sha512::new();
        hasher.update(public_nonce.compress().as_bytes());
        hasher.update(verifying_key.compress().as_bytes());
        hasher.update(message);

        let challenge = curve25519_dalek::Scalar::from_hash(hasher);

        Ok(challenge.into())
    }

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        signature: &Self::Signature,
    ) -> Result<()> {
        if hash_type != HashScheme::SHA512 {
            return Err(Error::Nonstandard);
        }

        let signature = ed25519::Signature::from_bytes(&signature.0);

        let verifying_key: curve25519_dalek::EdwardsPoint = (*self).into();
        let verifying_key: ed25519_dalek::VerifyingKey = verifying_key.into();

        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| Error::SignatureVerification)
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrkelSubstrateSignature(
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    [u8; schnorrkel::SIGNATURE_LENGTH],
);

impl From<SchnorrkelSubstrateSignature> for [u8; schnorrkel::SIGNATURE_LENGTH] {
    fn from(value: SchnorrkelSubstrateSignature) -> Self {
        value.0
    }
}

impl EncodableSignature for SchnorrkelSubstrateSignature {
    type Encoding = [u8; schnorrkel::SIGNATURE_LENGTH];
}

impl TryFrom<(ristretto::GroupElement, ristretto::Scalar)> for SchnorrkelSubstrateSignature {
    type Error = Error;
    fn try_from(
        (public_nonce, response): (ristretto::GroupElement, ristretto::Scalar),
    ) -> std::result::Result<Self, Self::Error> {
        let public_nonce: RistrettoPoint = public_nonce.into();
        let response: curve25519_dalek::Scalar = response.into();

        // Serialize the signature into bytes as defined by the `schnorrkel` crate.
        let mut bytes: [u8; schnorrkel::SIGNATURE_LENGTH] = [0u8; schnorrkel::SIGNATURE_LENGTH];
        bytes[..32].copy_from_slice(&public_nonce.compress().as_bytes()[..]);
        bytes[32..].copy_from_slice(&response.as_bytes()[..]);
        bytes[63] |= 128;

        Ok(Self(bytes))
    }
}

impl VerifyingKey<{ ristretto::SCALAR_LIMBS }> for ristretto::GroupElement {
    type Signature = SchnorrkelSubstrateSignature;

    fn derive_challenge(
        &self,
        public_nonce: &Self,
        message: &[u8],
        hash_type: HashScheme,
    ) -> Result<Self::Scalar> {
        if hash_type != HashScheme::Merlin {
            return Err(Error::Nonstandard);
        }

        let public_nonce: RistrettoPoint = (*public_nonce).into();
        let verifying_key: RistrettoPoint = (*self).into();

        let mut t = SigningContext::new(b"substrate").bytes(message);

        t.proto_name(b"Schnorr-sig");
        t.append_message(b"sign:pk", verifying_key.compress().as_bytes().as_slice());
        t.append_message(b"sign:R", public_nonce.compress().as_bytes().as_slice());

        let challenge = t.challenge_scalar(b"sign:c"); // context, message, A/public_key, R=rG

        // Due to dependency version incompatibilities, we have to go through-and-back to bytes here.
        if let Some(challenge) =
            curve25519_dalek::Scalar::from_canonical_bytes(challenge.to_bytes()).into_option()
        {
            Ok(challenge.into())
        } else {
            Err(Error::InternalError)
        }
    }

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        signature: &Self::Signature,
    ) -> Result<()> {
        if hash_type != HashScheme::Merlin {
            return Err(Error::Nonstandard);
        }

        let signature = schnorrkel::Signature::from_bytes(&signature.0)
            .map_err(|_| Error::SignatureVerification)?;

        // Due to dependency version incompatibilities, we have to compress and decompress the point here.
        let verifying_key: RistrettoPoint = (*self).into();
        let compressed_verifying_key = verifying_key.compress().to_bytes();
        let verifying_key = schnorrkel::PublicKey::from_bytes(&compressed_verifying_key)
            .map_err(|_| Error::SignatureVerification)?;

        verifying_key
            .verify_simple(b"substrate", message, &signature)
            .map_err(|_| Error::SignatureVerification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{CyclicGroupElement, OsCsRng, Samplable};

    #[test]
    fn taproot_normalizes() {
        let group_public_parameters = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let secret_key =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let mut public_key = secret_key * generator;

        if !public_key.is_taproot_normalized() {
            public_key = public_key.neg();

            assert!(public_key.is_taproot_normalized());
        } else {
            public_key = public_key.neg();

            assert!(!public_key.is_taproot_normalized());
        }
    }
}
