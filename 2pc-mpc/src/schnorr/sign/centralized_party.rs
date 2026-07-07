// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::schnorr::sign::derive_normalized_public_nonce;
use crate::schnorr::{generate_partial_schnorr_response, PartialSignature, VerifyingKey};
use crate::Result;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::GroupElement as _;
use group::{CsRng, HashContext, HashScheme, Samplable, StatisticalSecuritySizedNumber};

/// Core signing function for the centralized party.
///
/// This function generates a partial Schnorr signature. It is protocol-agnostic
/// and can be used by both AHE and VSS protocols since it takes primitive types
/// rather than protocol-specific Presign structures.
///
/// # Protocol Steps
///
/// 1. Sample nonce $k_A \gets \mathbb{Z}_q$
/// 2. Compute $K_A = k_A \cdot G$
/// 3. Compute $\mu_k$ from the random oracle
/// 4. Compute full nonce: $K = K_{B,0} + \mu_k \cdot K_{B,1} + K_A$
/// 5. Handle Taproot normalization if needed
/// 6. Compute challenge: $e = \mathcal{H}(K, X, \textsf{msg})$
/// 7. Compute partial signature: $z_A = k_A + e \cdot x_A$
pub fn sign<const SCALAR_LIMBS: usize, GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy>(
    secret_key_share: group::Value<GroupElement::Scalar>,
    message: &[u8],
    hash_scheme: HashScheme,
    hash_context: &HashContext,
    session_id: CommitmentSizedNumber,
    public_key: GroupElement::Value,
    decentralized_party_nonce_public_share_first_part: GroupElement::Value,
    decentralized_party_nonce_public_share_second_part: GroupElement::Value,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    let mut secret_key_share =
        GroupElement::Scalar::new(secret_key_share, scalar_group_public_parameters)?;

    // === 1(a) Sample $k_A\gets\mathbb{Z}_q$ ====
    let mut nonce_share = GroupElement::Scalar::sample(scalar_group_public_parameters, rng)?;

    // === 1(a) Set $K_{A}=k_{A}\cdot G$ ===
    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;
    let public_nonce_share_prenormalization = nonce_share * generator;

    let normalized_public_nonce_result = derive_normalized_public_nonce(
        session_id,
        message,
        hash_scheme,
        decentralized_party_nonce_public_share_first_part,
        decentralized_party_nonce_public_share_second_part,
        &public_nonce_share_prenormalization.value(),
        &public_key,
        group_public_parameters,
    )?;
    let normalized = normalized_public_nonce_result.nonce_normalized;
    let public_nonce = normalized_public_nonce_result.decentralized_party_nonce_public_share;

    // If a group element is not Taproot-normalized, its negation will be.
    // Continue signing using the negated public_nonce and public_nonce_share (now Taproot-normalized)
    // and the corresponding negated nonce share.
    if normalized {
        nonce_share = nonce_share.neg_constant_time(scalar_group_public_parameters);
    }

    // $ X $
    let mut public_key = GroupElement::new(public_key, group_public_parameters)?;

    // If a group element is not taproot normalized then its negation will be.
    // We then continue to sign according to the negated public_key (which is now taproot normalized) and the negated secret share.
    if !public_key.is_taproot_normalized() {
        // No need to normalize the public key share, as its not used here. The decentralized party will normalize it in this case.
        secret_key_share = secret_key_share.neg_constant_time(scalar_group_public_parameters);
        public_key = public_key.neg_constant_time(group_public_parameters);
    }

    let partial_response = generate_partial_schnorr_response(
        secret_key_share,
        public_key,
        nonce_share,
        public_nonce,
        message,
        hash_scheme,
        hash_context,
        scalar_group_public_parameters,
    )?;

    let partial_signature = PartialSignature {
        public_nonce_share_prenormalization: public_nonce_share_prenormalization.value(),
        partial_response: partial_response.value(),
    };

    Ok(partial_signature)
}
