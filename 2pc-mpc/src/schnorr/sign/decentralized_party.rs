// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::schnorr::sign::derive_normalized_public_nonce;
use crate::schnorr::{verify_partial_schnorr_signature, PartialSignature, VerifyingKey};
use crate::sign::SignData;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::{GroupElement, HashContext, HashScheme, StatisticalSecuritySizedNumber};

/// Result of verifying the centralized party's partial signature
pub struct VerificationResult<const SCALAR_LIMBS: usize, GroupElement> {
    /// Whether the public key was normalized (negated)
    pub key_normalized: bool,
    /// Whether the nonce was normalized (negated)
    pub nonce_normalized: bool,
    /// The presign public randomizer mu_k
    pub presign_public_randomizer: Uint<SCALAR_LIMBS>,
    /// The normalized public key
    pub public_key: GroupElement,
    /// The normalized public nonce
    pub public_nonce: GroupElement,
}

/// Resolve a `SignData` enum into a concrete `PartialSignature` and a `verify` flag.
///
/// - `Unverified` → return the partial signature and `verify = true`
/// - `Verified` → return the partial signature and `verify = false`
/// - `ToBeEmulated` → construct a default partial signature (identity nonce, zero response)
///   and `verify = true` (verification will trivially pass for K_A=0, z_A=0)
pub(crate) fn resolve_sign_data<
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
) -> crate::Result<(
    PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
    bool,
)> {
    match sign_data {
        SignData::Unverified(partial_signature) => Ok((partial_signature, true)),
        SignData::Verified(partial_signature) => Ok((partial_signature, false)),
        SignData::ToBeEmulated => {
            // Validate that the centralized party public key share is the neutral element.
            // ToBeEmulated mode requires x_A = 0, so X_A must be the identity.
            let centralized_party_public_key_share = GroupElement::new(
                centralized_party_public_key_share.clone(),
                group_public_parameters,
            )?;
            if !bool::from(centralized_party_public_key_share.is_neutral()) {
                return Err(crate::Error::from(crate::ErrorKind::InvalidParameters));
            }

            let identity = GroupElement::neutral_from_public_parameters(group_public_parameters)?;
            let zero = GroupElement::Scalar::neutral_from_public_parameters(
                scalar_group_public_parameters,
            )?;
            Ok((
                PartialSignature {
                    public_nonce_share_prenormalization: identity.value(),
                    partial_response: zero.value(),
                },
                true,
            ))
        }
    }
}

/// This function derives the normalized randomized public key $X$ and signature nonce $K$,
/// and then verifies the centralized party partial signature.
///
/// Thereby, this function implements step (2b) of the Sign protocol:
/// Verifies that $z_{A}$ is a valid response, i.e. $z_{A} \cdot G = K_{A} + e \cdot X_{A}$.
/// Here, `e` is the challenge derived from the full public key $X$ and public nonce $K$.
/// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428> Protocol C.5
///
/// See: [`derive_normalized_public_nonce()`].
pub(crate) fn verify_centralized_party_partial_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    // $m$
    message: &[u8],
    hash_scheme: HashScheme,
    hash_context: &HashContext,
    // $ K_{B,0} $
    decentralized_party_nonce_public_share_first_part: GroupElement::Value,
    // $ K_{B,1} $
    decentralized_party_nonce_public_share_second_part: GroupElement::Value,
    // $X_{A}$
    centralized_party_public_key_share: &GroupElement::Value,
    centralized_party_partial_signature: PartialSignature<
        GroupElement::Value,
        group::Value<GroupElement::Scalar>,
    >,
    public_key: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> crate::Result<VerificationResult<SCALAR_LIMBS, GroupElement>>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    normalize_and_optionally_verify_centralized_party_partial_signature::<SCALAR_LIMBS, GroupElement>(
        session_id,
        message,
        hash_scheme,
        hash_context,
        decentralized_party_nonce_public_share_first_part,
        decentralized_party_nonce_public_share_second_part,
        centralized_party_public_key_share,
        centralized_party_partial_signature,
        public_key,
        group_public_parameters,
        scalar_group_public_parameters,
        true,
    )
}

/// This function derives the normalized randomized public key $X$ and signature nonce $K$,
/// and optionally verifies the centralized party partial signature.
///
/// When `verify` is `true`, performs verification of the partial signature (step 2b).
/// When `verify` is `false`, skips verification but still computes normalization.
///
/// See: [`verify_centralized_party_partial_signature()`].
pub(crate) fn normalize_and_optionally_verify_centralized_party_partial_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    session_id: CommitmentSizedNumber,
    // $m$
    message: &[u8],
    hash_scheme: HashScheme,
    hash_context: &HashContext,
    // $ K_{B,0} $
    decentralized_party_nonce_public_share_first_part: GroupElement::Value,
    // $ K_{B,1} $
    decentralized_party_nonce_public_share_second_part: GroupElement::Value,
    // $X_{A}$
    centralized_party_public_key_share: &GroupElement::Value,
    centralized_party_partial_signature: PartialSignature<
        GroupElement::Value,
        group::Value<GroupElement::Scalar>,
    >,
    public_key: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    verify: bool,
) -> crate::Result<VerificationResult<SCALAR_LIMBS, GroupElement>>
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
    let mut centralized_party_public_key_share = GroupElement::new(
        centralized_party_public_key_share.clone(),
        group_public_parameters,
    )?;

    // $ X $
    let mut public_key = GroupElement::new(public_key_value.clone(), group_public_parameters)?;

    // If a group element is not Taproot-normalized, its negation will be.
    // Continue signing using the negated public_key (now Taproot-normalized) and the corresponding negated secret share encryption.
    let key_normalized = if !public_key.is_taproot_normalized() {
        centralized_party_public_key_share =
            centralized_party_public_key_share.neg_constant_time(group_public_parameters);
        public_key = public_key.neg_constant_time(group_public_parameters);

        true
    } else {
        false
    };

    let result = derive_normalized_public_nonce::<SCALAR_LIMBS, GroupElement>(
        session_id,
        message,
        hash_scheme,
        decentralized_party_nonce_public_share_first_part,
        decentralized_party_nonce_public_share_second_part,
        &centralized_party_partial_signature.public_nonce_share_prenormalization,
        public_key_value,
        group_public_parameters,
    )?;

    if verify {
        // $ K_{A} $
        let mut centralized_party_public_nonce_share = GroupElement::new(
            centralized_party_partial_signature.public_nonce_share_prenormalization,
            group_public_parameters,
        )?;

        if result.nonce_normalized {
            centralized_party_public_nonce_share =
                centralized_party_public_nonce_share.neg_constant_time(group_public_parameters);
        }

        // $ z_{A} $
        let centralized_party_partial_response = GroupElement::Scalar::new(
            centralized_party_partial_signature.partial_response,
            scalar_group_public_parameters,
        )?;

        verify_partial_schnorr_signature(
            centralized_party_partial_response,
            centralized_party_public_nonce_share,
            result.decentralized_party_nonce_public_share,
            centralized_party_public_key_share,
            public_key,
            message,
            hash_scheme,
            hash_context,
            group_public_parameters,
        )?;
    }

    Ok(VerificationResult {
        key_normalized,
        nonce_normalized: result.nonce_normalized,
        presign_public_randomizer: result.presign_public_randomizer,
        public_key,
        public_nonce: result.decentralized_party_nonce_public_share,
    })
}
