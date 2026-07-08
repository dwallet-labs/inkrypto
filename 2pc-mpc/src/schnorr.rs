// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Schnorr 2PC-MPC Signature Protocols
//!
//! This module provides two implementations of 2PC-MPC Schnorr signatures:
//!
//! ## AHE-Based Implementation (`ahe` module)
//!
//! Uses Additively Homomorphic Encryption (class groups) for threshold signing.
//! The presign phase produces encrypted nonce shares $\ct_{k_0}, \ct_{k_1}$.
//!
//! ## SSS-Based Implementation (`shamir` module)
//!
//! Uses Shamir Secret Sharing for threshold signing, as described in Section 9
//! of the 2PC-MPC v3 Provisionals document. The presign phase produces
//! secret shares $[k_0]_i, [k_1]_i$ using VSS.

/// AHE-based Schnorr protocol using class groups for threshold encryption.
pub mod ahe;

/// Shared sign protocol components.
pub mod sign;

/// SSS-based Schnorr protocol using Shamir Secret Sharing (Section 9).
pub mod vss;

use crate::sign::EncodableSignature;
use crate::{Error, ErrorKind, Result};
pub use ahe::Presign;
use curve25519_dalek::RistrettoPoint;
use ecdsa::elliptic_curve::group::GroupEncoding;
use ecdsa::elliptic_curve::point::AffineCoordinates;
use group::{
    curve25519, ristretto, secp256k1, GroupElement, HashContext, HashScheme, HashToGroup,
    PrimeGroupElement,
};
use k256::schnorr::signature::digest::Digest;
use k256::schnorr::signature::Verifier;
use schnorrkel::context::{SigningContext, SigningTranscript};
use serde::{Deserialize, Serialize};
use sha2::digest::FixedOutput;
use sha2::Sha256;
use std::fmt::Debug;
use std::ops::Neg;

pub const TAPROOT_CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// A partial Schnorr signature from a party.
///
/// This is the message broadcast by the centralized party in the sign protocol,
/// containing their public nonce share and partial response.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature<GroupElementValue, ScalarValue> {
    /// The party's public nonce share $K_A = k_A \cdot G$ (before normalization).
    pub public_nonce_share_prenormalization: GroupElementValue,
    /// The party's partial response $z_A = k_A + e \cdot x_A$.
    pub partial_response: ScalarValue,
}

/// Generates the `s` part of a Schnorr signature on `message` (optionally) prepended by `prefix`.
pub fn generate_schnorr_signature_response<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    secret_key: GroupElement::Scalar,
    public_key: GroupElement,
    nonce: GroupElement::Scalar,
    public_nonce: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
    hash_context: &HashContext,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> Result<GroupElement::Scalar> {
    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type, hash_context)?;

    generate_schnorr_response::<SCALAR_LIMBS, GroupElement>(
        secret_key,
        nonce,
        challenge,
        scalar_group_public_parameters,
    )
}

/// Generates a partial Schnorr response (the `s` part of the partial signature) on `message` (optionally) prepended by `prefix`.
pub fn generate_partial_schnorr_response<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    secret_key_share: GroupElement::Scalar,
    public_key: GroupElement,
    nonce_share: GroupElement::Scalar,
    public_nonce: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
    hash_context: &HashContext,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> Result<GroupElement::Scalar> {
    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type, hash_context)?;

    generate_schnorr_response::<SCALAR_LIMBS, GroupElement>(
        secret_key_share,
        nonce_share,
        challenge,
        scalar_group_public_parameters,
    )
}

/// Generates the `s` part of a Schnorr signature on `message` (optionally) prepended by `prefix`.
/// Note: this function is also used for generating partial signature,
/// in which case `public_nonce` and `public_key` do not necessarily correspond to `nonce` and `secret_key`,
/// and therefore no correctness checks are performed here, and the responsibility remains on the caller.
pub fn generate_schnorr_response<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    secret_key: GroupElement::Scalar,
    nonce: GroupElement::Scalar,
    challenge: GroupElement::Scalar,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> Result<GroupElement::Scalar> {
    let s = (challenge * secret_key).add_constant_time(&nonce, scalar_group_public_parameters);

    Ok(s)
}

/// Verifies a Schnorr signature on `message` (optionally) prepended by `prefix`.
/// Note: `public_key` and `public_nonce` must be non-unit.
/// Note: `public_nonce` must be normalized, i.e. the `y` value must be even.
/// Note: `public_key` is always interpreted as the corresponding normalized element.
pub fn verify_schnorr_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    // $ s $
    signature_response: GroupElement::Scalar,
    public_nonce: GroupElement,
    public_key: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
    hash_context: &HashContext,
    group_public_parameters: &group::PublicParameters<GroupElement>,
) -> Result<()> {
    // Taproot adds a requirement on Schnorr signatures,
    // that the public nonce is normalized, in the sense that their `y` coordinate is even.
    // it also always interprets the public key as normalized.
    // We check that in our generic implementation, where non-taproot (i.e. `GroupElement` isn't `secp256k1::GroupElement`) simply return `true` for these checks.

    // Verify the signature against the normalized public key.
    // If a group element is not Taproot normalized then its negation will be.
    let public_key = if public_key.is_taproot_normalized() {
        public_key
    } else {
        public_key.neg_constant_time(group_public_parameters)
    };

    // The public nonce must be normalized
    if !public_nonce.is_taproot_normalized() {
        return Err(Error::from(ErrorKind::SignatureVerification));
    }

    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type, hash_context)?;

    verify_schnorr_signature_inner(
        signature_response,
        challenge,
        public_nonce,
        public_key,
        group_public_parameters,
    )
}

/// Verifies a partial Schnorr signature on `message` (optionally) prepended by `prefix`.
/// Note: `public_key` and `public_nonce` must be non-unit.
/// Note: `public_nonce` must be normalized, i.e. the `y` value must be even.
/// Note: `public_key` is always interpreted as the corresponding normalized element.
/// In this case the challenge is derived from the full public_key and public_nonce while
/// the signature_response is expected to hold with respect to the public_key_share and public_nonce_share.
pub fn verify_partial_schnorr_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    // $ s $
    partial_response: GroupElement::Scalar,
    public_nonce_share: GroupElement,
    public_nonce: GroupElement,
    public_key_share: GroupElement,
    public_key: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
    hash_context: &HashContext,
    group_public_parameters: &group::PublicParameters<GroupElement>,
) -> Result<()> {
    // The public nonce must be normalized
    if !public_nonce.is_taproot_normalized() {
        return Err(Error::from(ErrorKind::SignatureVerification));
    }

    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type, hash_context)?;

    verify_schnorr_signature_inner(
        partial_response,
        challenge,
        public_nonce_share,
        public_key_share,
        group_public_parameters,
    )
}

fn verify_schnorr_signature_inner<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    // $ s $
    signature_response: GroupElement::Scalar,
    challenge: GroupElement::Scalar,
    public_nonce: GroupElement,
    public_key: GroupElement,
    group_public_parameters: &group::PublicParameters<GroupElement>,
) -> Result<()> {
    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    let reconstructed_public_nonce = (signature_response * generator)
        .sub_vartime(&(challenge * public_key), group_public_parameters);

    if public_nonce == reconstructed_public_nonce {
        Ok(())
    } else {
        Err(Error::from(ErrorKind::SignatureVerification))
    }
}

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
        hash_context: &HashContext,
    ) -> Result<Self::Scalar>;

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        hash_context: &HashContext,
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
        hash_context: &HashContext,
    ) -> Result<Self::Scalar> {
        if hash_type != HashScheme::SHA256 {
            return Err(Error::from(ErrorKind::Nonstandard));
        }
        if !matches!(hash_context, HashContext::None) {
            return Err(Error::from(ErrorKind::Nonstandard));
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
        hash_context: &HashContext,
        signature: &Self::Signature,
    ) -> Result<()> {
        if hash_type != HashScheme::SHA256 {
            return Err(Error::from(ErrorKind::Nonstandard));
        }
        if !matches!(hash_context, HashContext::None) {
            return Err(Error::from(ErrorKind::Nonstandard));
        }

        let signature = k256::schnorr::Signature::from_bytes(&signature.0)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))?;

        // Verify the signature against the normalized public key.
        // If a non-zero group element is not Taproot normalized then its negation will be.
        let public_key = if self.is_taproot_normalized() {
            *self
        } else {
            self.neg()
        };
        let verifying_key: k256::AffinePoint = public_key.value().into();
        let verifying_key = k256::PublicKey::from_affine(verifying_key)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))?;
        let verifying_key = k256::schnorr::VerifyingKey::try_from(verifying_key)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))
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

impl TryFrom<(curve25519::Value, curve25519::Scalar)> for EdDSASignature {
    type Error = Error;
    fn try_from(
        (public_nonce, response): (curve25519::Value, curve25519::Scalar),
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
        hash_context: &HashContext,
    ) -> Result<Self::Scalar> {
        if hash_type != HashScheme::SHA512 {
            return Err(Error::from(ErrorKind::Nonstandard));
        }
        if !matches!(hash_context, HashContext::None) {
            return Err(Error::from(ErrorKind::Nonstandard));
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
        hash_context: &HashContext,
        signature: &Self::Signature,
    ) -> Result<()> {
        if hash_type != HashScheme::SHA512 {
            return Err(Error::from(ErrorKind::Nonstandard));
        }
        if !matches!(hash_context, HashContext::None) {
            return Err(Error::from(ErrorKind::Nonstandard));
        }

        let signature = ed25519::Signature::from_bytes(&signature.0);

        let verifying_key: curve25519_dalek::EdwardsPoint = (*self).into();
        let verifying_key: ed25519_dalek::VerifyingKey = verifying_key.into();

        verifying_key
            .verify_strict(message, &signature)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct SchnorrkelSignature(
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    [u8; schnorrkel::SIGNATURE_LENGTH],
);

impl From<SchnorrkelSignature> for [u8; schnorrkel::SIGNATURE_LENGTH] {
    fn from(value: SchnorrkelSignature) -> Self {
        value.0
    }
}

impl EncodableSignature for SchnorrkelSignature {
    type Encoding = [u8; schnorrkel::SIGNATURE_LENGTH];
}

impl TryFrom<(ristretto::GroupElement, ristretto::Scalar)> for SchnorrkelSignature {
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
    type Signature = SchnorrkelSignature;

    fn derive_challenge(
        &self,
        public_nonce: &Self,
        message: &[u8],
        hash_type: HashScheme,
        hash_context: &HashContext,
    ) -> Result<Self::Scalar> {
        if hash_type != HashScheme::Merlin {
            return Err(Error::from(ErrorKind::Nonstandard));
        }

        let signing_context = hash_context.schnorrkel_signing_context()?;

        let public_nonce: RistrettoPoint = (*public_nonce).into();
        let verifying_key: RistrettoPoint = (*self).into();

        let mut t = SigningContext::new(signing_context).bytes(message);

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
            Err(Error::from(ErrorKind::InternalError))
        }
    }

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        hash_context: &HashContext,
        signature: &Self::Signature,
    ) -> Result<()> {
        if hash_type != HashScheme::Merlin {
            return Err(Error::from(ErrorKind::Nonstandard));
        }

        let signing_context = hash_context.schnorrkel_signing_context()?;

        let signature = schnorrkel::Signature::from_bytes(&signature.0)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))?;

        // Due to dependency version incompatibilities, we have to compress and decompress the point here.
        let verifying_key: RistrettoPoint = (*self).into();
        let compressed_verifying_key = verifying_key.compress().to_bytes();
        let verifying_key = schnorrkel::PublicKey::from_bytes(&compressed_verifying_key)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))?;

        verifying_key
            .verify_simple(signing_context, message, &signature)
            .map_err(|_| Error::from(ErrorKind::SignatureVerification))
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
