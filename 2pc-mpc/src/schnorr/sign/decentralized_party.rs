// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::schnorr::sign::derive_normalized_public_nonce;
use crate::schnorr::{verify_partial_schnorr_signature, PartialSignature, VerifyingKey};
use crate::sign::SignData;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::{GroupElement, HashContext, HashScheme, StatisticalSecuritySizedNumber};

/// The public key $X$ and public nonce $K$ of a Schnorr sign, Taproot-normalized, and the
/// values derived alongside them.
///
/// Computed by [`derive_normalized_public_key_and_nonce`] from public values only, so it can
/// be recomputed in every round.
pub struct NormalizedPublicKeyAndNonce<const SCALAR_LIMBS: usize, GroupElement> {
    /// Whether the public key was normalized (negated)
    pub key_normalized: bool,
    /// Whether the nonce was normalized (negated)
    pub nonce_normalized: bool,
    /// The presign public randomizer mu_k
    pub presign_public_randomizer: Uint<SCALAR_LIMBS>,
    /// The normalized public key $X$
    pub public_key: GroupElement,
    /// The normalized public nonce $K$
    pub public_nonce: GroupElement,
    /// The centralized party's public key share $X_A$, negated together with $X$
    pub centralized_party_public_key_share: GroupElement,
}

/// The centralized party's partial signature carried by the sign data.
///
/// - `Unverified` and `Verified` → the partial signature they carry
/// - `ToBeEmulated` → the partial signature a non-existent centralized party would have sent
///   (see [`emulated_partial_signature`])
///
/// This only unpacks; it checks nothing. Callers that apply a secret share must first verify an
/// `Unverified` partial signature with [`verify_centralized_party_partial_signature`].
pub(crate) fn partial_signature_from_sign_data<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    sign_data: SignData<
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
    >,
    centralized_party_public_key_share: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> crate::Result<PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>> {
    match sign_data {
        SignData::Unverified(partial_signature) | SignData::Verified(partial_signature) => {
            Ok(partial_signature)
        }
        SignData::ToBeEmulated => emulated_partial_signature::<SCALAR_LIMBS, GroupElement>(
            centralized_party_public_key_share,
            group_public_parameters,
            scalar_group_public_parameters,
        ),
    }
}

/// The partial signature a non-existent centralized party would have sent in threshold mode:
/// the neutral nonce share $K_A = 0$ and the zero response $z_A = 0$.
///
/// Threshold mode requires $x_A = 0$, so this fails unless $X_A$ is the neutral element.
/// Verification of the returned partial signature trivially passes.
pub(crate) fn emulated_partial_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    centralized_party_public_key_share: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> crate::Result<PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>> {
    let centralized_party_public_key_share = GroupElement::new(
        centralized_party_public_key_share.clone(),
        group_public_parameters,
    )?;
    if !bool::from(centralized_party_public_key_share.is_neutral()) {
        return Err(crate::Error::from(crate::ErrorKind::InvalidParameters));
    }

    let identity = GroupElement::neutral_from_public_parameters(group_public_parameters)?;
    let zero =
        GroupElement::Scalar::neutral_from_public_parameters(scalar_group_public_parameters)?;
    Ok(PartialSignature {
        public_nonce_share_prenormalization: identity.value(),
        partial_response: zero.value(),
    })
}

/// Derives the Taproot-normalized public key $X$ and public nonce $K$ of a Schnorr sign.
///
/// This implements step (1b) of the Sign protocol
/// (<https://eprint.iacr.org/archive/2025/297/1747917268.pdf>, Protocol C.5) together with the
/// Taproot normalizations. It checks nothing; see [`verify_centralized_party_partial_signature`].
///
/// If $X$ is not Taproot-normalized, $X$ and $X_A$ are negated. The randomizer $\mu_k$ is hashed
/// from the values before normalization, and $K = K_A + K_{B,0} + \mu_k \cdot K_{B,1}$ is then
/// normalized on its own; see [`derive_normalized_public_nonce()`].
pub(crate) fn derive_normalized_public_key_and_nonce<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    // $m$
    message: &[u8],
    hash_scheme: HashScheme,
    // $ K_{B,0} $
    decentralized_party_nonce_public_share_first_part: GroupElement::Value,
    // $ K_{B,1} $
    decentralized_party_nonce_public_share_second_part: GroupElement::Value,
    // $X_{A}$
    centralized_party_public_key_share: &GroupElement::Value,
    // $K_{A}$, before normalization
    centralized_party_public_nonce_share_prenormalization: &GroupElement::Value,
    // $X$, before normalization
    public_key: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
) -> crate::Result<NormalizedPublicKeyAndNonce<SCALAR_LIMBS, GroupElement>>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    // Save original value for hashing (hashing uses pre-normalization values)
    let public_key_value = public_key;

    // $ X_{A} $
    let centralized_party_public_key_share = GroupElement::new(
        centralized_party_public_key_share.clone(),
        group_public_parameters,
    )?;

    // $ X $
    let public_key = GroupElement::new(public_key_value.clone(), group_public_parameters)?;

    // If a group element is not Taproot-normalized, its negation will be.
    // Continue signing using the negated public_key (now Taproot-normalized) and the corresponding negated secret share encryption.
    let key_normalized = !public_key.is_taproot_normalized();
    let (public_key, centralized_party_public_key_share) = if key_normalized {
        (
            public_key.neg_constant_time(group_public_parameters),
            centralized_party_public_key_share.neg_constant_time(group_public_parameters),
        )
    } else {
        (public_key, centralized_party_public_key_share)
    };

    let result = derive_normalized_public_nonce::<SCALAR_LIMBS, GroupElement>(
        session_id,
        message,
        hash_scheme,
        decentralized_party_nonce_public_share_first_part,
        decentralized_party_nonce_public_share_second_part,
        centralized_party_public_nonce_share_prenormalization,
        public_key_value,
        group_public_parameters,
    )?;

    Ok(NormalizedPublicKeyAndNonce {
        key_normalized,
        nonce_normalized: result.nonce_normalized,
        presign_public_randomizer: result.presign_public_randomizer,
        public_key,
        public_nonce: result.decentralized_party_nonce_public_share,
        centralized_party_public_key_share,
    })
}

/// Verifies the centralized party's partial signature against the normalized public key and
/// nonce.
///
/// This implements step (2b) of the Sign protocol:
/// Verifies that $z_{A}$ is a valid response, i.e. $z_{A} \cdot G = K_{A} + e \cdot X_{A}$.
/// Here, `e` is the challenge derived from the full public key $X$ and public nonce $K$, and
/// $K_A$ and $X_A$ are negated wherever $K$ and $X$ were.
/// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428> Protocol C.5
///
/// If this returns `Ok()`, the decentralized party can generate a valid signature over
/// `message` whenever a threshold of honest parties participates in signing.
pub(crate) fn verify_centralized_party_partial_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    normalized_public_key_and_nonce: &NormalizedPublicKeyAndNonce<SCALAR_LIMBS, GroupElement>,
    centralized_party_partial_signature: PartialSignature<
        GroupElement::Value,
        group::Value<GroupElement::Scalar>,
    >,
    // $m$
    message: &[u8],
    hash_scheme: HashScheme,
    hash_context: &HashContext,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> crate::Result<()> {
    // $ K_{A} $
    let centralized_party_public_nonce_share = GroupElement::new(
        centralized_party_partial_signature.public_nonce_share_prenormalization,
        group_public_parameters,
    )?;
    let centralized_party_public_nonce_share = if normalized_public_key_and_nonce.nonce_normalized {
        centralized_party_public_nonce_share.neg_constant_time(group_public_parameters)
    } else {
        centralized_party_public_nonce_share
    };

    // $ z_{A} $
    let centralized_party_partial_response = GroupElement::Scalar::new(
        centralized_party_partial_signature.partial_response,
        scalar_group_public_parameters,
    )?;

    verify_partial_schnorr_signature(
        centralized_party_partial_response,
        centralized_party_public_nonce_share,
        normalized_public_key_and_nonce.public_nonce,
        normalized_public_key_and_nonce.centralized_party_public_key_share,
        normalized_public_key_and_nonce.public_key,
        message,
        hash_scheme,
        hash_context,
        group_public_parameters,
    )
}
