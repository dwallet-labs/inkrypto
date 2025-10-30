// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub mod presign;
pub mod sign;

use crate::sign::EncodableSignature;
use crate::{Error, Result};
use ecdsa::elliptic_curve::point::AffineCoordinates;
use ecdsa::elliptic_curve::scalar::IsHigh;
use ecdsa::signature::digest::Digest;
use ecdsa::signature::{DigestVerifier, Verifier};
use ecdsa::RecoveryId;
use group::{secp256k1, secp256r1, GroupElement, HashScheme, HashToGroup, PrimeGroupElement};
use k256::elliptic_curve::PrimeField;
pub use presign::{Presign, VersionedPresign};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

/// A standardized ECDSA verifying key.
pub trait VerifyingKey<const SCALAR_LIMBS: usize>:
    PrimeGroupElement<SCALAR_LIMBS> + HashToGroup
{
    /// A standardized ECDSA signature for a supported elliptic curve.
    /// Should be serialized as defined by the standard.
    type Signature: TryFrom<(Self, Self::Scalar), Error = Error> + EncodableSignature;

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        signature: &Self::Signature,
    ) -> Result<()>;

    /// Get the affine x-coordinate as a scalar.
    fn x_projected_to_scalar_field(&self) -> Self::Scalar;
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ECDSASecp256k1Signature(
    #[serde(with = "group::helpers::const_generic_array_serialization")] [u8; 65],
);

impl ECDSASecp256k1Signature {
    /// Retrieve the signature.
    pub fn signature(&self) -> Result<k256::ecdsa::Signature> {
        let (_, signature_part) = self.0.split_at(1);

        k256::ecdsa::Signature::try_from(signature_part).map_err(|_| Error::SignatureVerification)
    }

    /// Retrieve the recovery ID.
    pub fn recovery_id(&self) -> Result<RecoveryId> {
        RecoveryId::from_byte(self.0[0]).ok_or(Error::SignatureVerification)
    }
}

impl From<ECDSASecp256k1Signature> for [u8; 65] {
    fn from(value: ECDSASecp256k1Signature) -> Self {
        value.0
    }
}

impl EncodableSignature for ECDSASecp256k1Signature {
    type Encoding = [u8; 65];
}

impl TryFrom<(secp256k1::GroupElement, secp256k1::Scalar)> for ECDSASecp256k1Signature {
    type Error = Error;
    fn try_from(
        (public_nonce, signature_s): (secp256k1::GroupElement, secp256k1::Scalar),
    ) -> std::result::Result<Self, Self::Error> {
        let nonce_x_coordinate = public_nonce.x_projected_to_scalar_field();
        let r: k256::Scalar = nonce_x_coordinate.into();
        let s: k256::Scalar = signature_s.into();

        let signature =
            k256::ecdsa::Signature::from_scalars(r, s).map_err(|_| Error::SignatureVerification)?;

        // Compute recovery ID.
        let public_nonce: k256::AffinePoint = public_nonce.value().into();
        let x_is_reduced = r.to_repr() != public_nonce.x();
        let mut y_is_odd = public_nonce.y_is_odd();
        y_is_odd ^= s.is_high();

        let recovery_id = RecoveryId::new(y_is_odd.into(), x_is_reduced);

        // Attend to malleability by applying low-S normalization.
        // s = min(s', q-s')
        let signature = signature.normalize_s();

        let mut encoded_signature = [0; 65];
        let (recovery_id_part, signature_part) = encoded_signature.split_at_mut(1);
        signature_part.copy_from_slice(&signature.to_bytes());
        recovery_id_part[0] = recovery_id.to_byte();

        Ok(Self(encoded_signature))
    }
}

impl Debug for ECDSASecp256k1Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECDSASecp256k1Signature({:?})", &self.0)
    }
}

impl VerifyingKey<{ secp256k1::SCALAR_LIMBS }> for secp256k1::GroupElement {
    type Signature = ECDSASecp256k1Signature;

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        signature: &Self::Signature,
    ) -> Result<()> {
        let verifying_key = k256::ecdsa::VerifyingKey::from_affine(self.value().into())
            .map_err(|_| Error::SignatureVerification)?;

        let signature = signature.signature()?;

        match hash_type {
            HashScheme::Keccak256 => verifying_key
                .verify_digest(
                    |hasher: &mut sha3::Keccak256| {
                        hasher.update(message);
                        Ok(())
                    },
                    &signature,
                )
                .map_err(|_| Error::SignatureVerification),
            HashScheme::SHA256 => verifying_key
                .verify_digest(
                    |hasher: &mut sha2::Sha256| {
                        hasher.update(message);
                        Ok(())
                    },
                    &signature,
                )
                .map_err(|_| Error::SignatureVerification),
            HashScheme::DoubleSHA256 => {
                let mut hasher = sha2::Sha256::new();

                hasher.update(message);
                let hashed_message = hasher.finalize();

                verifying_key
                    .verify_digest(
                        |double_hasher: &mut sha2::Sha256| {
                            double_hasher.update(hashed_message);
                            Ok(())
                        },
                        &signature,
                    )
                    .map_err(|_| Error::SignatureVerification)
            }
            _ => Err(Error::Nonstandard),
        }
    }

    fn x_projected_to_scalar_field(&self) -> secp256k1::Scalar {
        // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let affine_point: k256::AffinePoint = self.value().into();
        <k256::Scalar as k256::elliptic_curve::ops::Reduce<k256::FieldBytes>>::reduce(
            &affine_point.x(),
        )
        .into()
    }
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ECDSASecp256r1Signature(
    #[serde(with = "group::helpers::const_generic_array_serialization")] [u8; 65],
);

impl ECDSASecp256r1Signature {
    /// Retrieve the signature.
    pub fn signature(&self) -> Result<p256::ecdsa::Signature> {
        let (_, signature_part) = self.0.split_at(1);

        p256::ecdsa::Signature::try_from(signature_part).map_err(|_| Error::SignatureVerification)
    }

    /// Retrieve the recovery ID.
    pub fn recovery_id(&self) -> Result<RecoveryId> {
        RecoveryId::from_byte(self.0[0]).ok_or(Error::SignatureVerification)
    }
}

impl From<ECDSASecp256r1Signature> for [u8; 65] {
    fn from(value: ECDSASecp256r1Signature) -> Self {
        value.0
    }
}

impl EncodableSignature for ECDSASecp256r1Signature {
    type Encoding = [u8; 65];
}

impl TryFrom<(secp256r1::GroupElement, secp256r1::Scalar)> for ECDSASecp256r1Signature {
    type Error = Error;
    fn try_from(
        (public_nonce, signature_s): (secp256r1::GroupElement, secp256r1::Scalar),
    ) -> std::result::Result<Self, Self::Error> {
        let nonce_x_coordinate = public_nonce.x_projected_to_scalar_field();
        let r: p256::Scalar = nonce_x_coordinate.into();
        let s: p256::Scalar = signature_s.into();

        let signature =
            p256::ecdsa::Signature::from_scalars(r, s).map_err(|_| Error::SignatureVerification)?;

        // Compute recovery ID.
        let public_nonce: p256::AffinePoint = public_nonce.value().into();
        let x_is_reduced = r.to_repr() != public_nonce.x();
        let mut y_is_odd = public_nonce.y_is_odd();
        y_is_odd ^= s.is_high();

        let recovery_id = RecoveryId::new(y_is_odd.into(), x_is_reduced);

        // Attend to malleability by applying low-S normalization.
        // s = min(s', q-s')
        let signature = signature.normalize_s();

        let mut encoded_signature = [0; 65];
        let (recovery_id_part, signature_part) = encoded_signature.split_at_mut(1);
        signature_part.copy_from_slice(&signature.to_bytes());
        recovery_id_part[0] = recovery_id.to_byte();

        Ok(Self(encoded_signature))
    }
}
impl Debug for ECDSASecp256r1Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECDSASecp256r1Signature({:?})", &self.0)
    }
}

impl VerifyingKey<{ secp256r1::SCALAR_LIMBS }> for secp256r1::GroupElement {
    type Signature = ECDSASecp256r1Signature;

    fn verify(
        &self,
        message: &[u8],
        hash_type: HashScheme,
        signature: &Self::Signature,
    ) -> Result<()> {
        if hash_type != HashScheme::SHA256 {
            return Err(Error::Nonstandard);
        }

        let verifying_key = p256::ecdsa::VerifyingKey::from_affine(self.value().into())
            .map_err(|_| Error::SignatureVerification)?;

        let signature = signature.signature()?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| Error::SignatureVerification)
    }

    fn x_projected_to_scalar_field(&self) -> secp256r1::Scalar {
        // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let affine_point: p256::AffinePoint = self.value().into();
        <p256::Scalar as p256::elliptic_curve::ops::Reduce<p256::FieldBytes>>::reduce(
            &affine_point.x(),
        )
        .into()
    }
}
