// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Shared sign protocol components for Schnorr signatures.
//!
//! This module contains the centralized party implementation which is shared
//! between AHE and VSS protocols.

use crate::schnorr::VerifyingKey;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, NonZero, Uint};
use group::{HashScheme, StatisticalSecuritySizedNumber};
use merlin::Transcript;
use proof::TranscriptProtocol;

pub mod centralized_party;
pub mod decentralized_party;

/// Result of randomizing the decentralized party's public nonce share
pub struct RandomizedNonceShareResult<const SCALAR_LIMBS: usize, GroupElement> {
    /// The presign public randomizer mu_k
    pub presign_public_randomizer: Uint<SCALAR_LIMBS>,
    /// The randomized decentralized party public nonce share K_B
    pub decentralized_party_nonce_public_share: GroupElement,
}

/// Result of deriving the normalized public nonce
pub struct NormalizedPublicNonceResult<const SCALAR_LIMBS: usize, GroupElement> {
    /// Whether the nonce was negated for normalization
    pub nonce_normalized: bool,
    /// The presign public randomizer mu_k
    pub presign_public_randomizer: Uint<SCALAR_LIMBS>,
    /// The randomized decentralized party public nonce share K_B
    pub decentralized_party_nonce_public_share: GroupElement,
}

/// This function derives the public randomizer $\mu_{k}^{0}$ from a hash
/// $\mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,K_A,K_{B,0},K_{B,1})$
pub(crate) fn derive_presign_public_randomizer<
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
    // $ K_{A} $
    centralized_party_public_nonce_share: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
    public_key: &GroupElement::Value,
) -> crate::Result<Uint<SCALAR_LIMBS>>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    // NEVER CHANGE OR "FIX" THIS DOMAIN SEPARATOR. It is wrong — the result of a copy-paste
    // error — but it has no significance over security, and it is deployed in production:
    // values derived from this exact transcript have already been sent on the live network, so
    // every party must keep deriving the identical presign public randomizer from it forever.
    // There is no known migration off it. Do not revert, rename, or "correct" it.
    let mut transcript = Transcript::new(
        b"DKG randomize decentralized party public key share and encryption of secret key share",
    );

    transcript.append_uint::<{ CommitmentSizedNumber::LIMBS }>(b"$ sid $", &session_id);
    transcript.append_message(b"$ msg $", message);
    transcript.serialize_to_transcript_as_json(b"$ H $", &hash_scheme)?;
    transcript.transcribe(b"$ \\GG,G,q $", group_public_parameters.clone())?;
    transcript.serialize_to_transcript_as_json(b"$X$", &public_key)?;
    transcript
        .serialize_to_transcript_as_json(b"$ K_{A}$", &centralized_party_public_nonce_share)?;
    transcript.serialize_to_transcript_as_json(
        b"$ K_{B,0} $",
        &decentralized_party_nonce_public_share_first_part,
    )?;
    transcript.serialize_to_transcript_as_json(
        b"$ K_{B,1} $",
        &decentralized_party_nonce_public_share_second_part,
    )?;

    let group_order = NonZero::new(GroupElement::order_from_public_parameters(
        group_public_parameters,
    ))
    .unwrap();

    let presign_public_randomizer: Uint<SCALAR_LIMBS> = group::Value::<GroupElement::Scalar>::from(
        transcript.uniformly_reduced_challenge::<SCALAR_LIMBS>(b"$\\mu_{k}$", &group_order),
    )
    .into();

    Ok(presign_public_randomizer)
}

/// This function derives the combined signature public nonce share of the decentralized party
/// This function implements step (1b) of the Sign protocol:
/// <https://eprint.iacr.org/archive/2025/297/1747917268.pdf> Protocol C.5
/// $K_B$ from two points $K_{B,0}, K_{B,1}$ by applying a linear combination using the
/// public randomizer $\mu_{k}^{0}$ derived from a hash
/// $\mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,K_A,K_{B,0},K_{B,1})$
///  - $K_{B,0}+\mu_{k}^{1}\cdot K_{B,1}$
pub(crate) fn derive_randomized_decentralized_party_public_nonce_share<
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
    // $ K_{A} $
    centralized_party_public_nonce_share: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
    public_key: &GroupElement::Value,
) -> crate::Result<RandomizedNonceShareResult<SCALAR_LIMBS, GroupElement>>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    let presign_public_randomizer: Uint<SCALAR_LIMBS> =
        derive_presign_public_randomizer::<SCALAR_LIMBS, GroupElement>(
            session_id,
            message,
            hash_scheme,
            decentralized_party_nonce_public_share_first_part.clone(),
            decentralized_party_nonce_public_share_second_part.clone(),
            centralized_party_public_nonce_share,
            group_public_parameters,
            public_key,
        )?;

    // $K_{B,0}$
    let decentralized_party_nonce_public_share_first_part = GroupElement::new(
        decentralized_party_nonce_public_share_first_part,
        group_public_parameters,
    )?;

    // $K_{B,1}$
    let decentralized_party_nonce_public_share_second_part = GroupElement::new(
        decentralized_party_nonce_public_share_second_part,
        group_public_parameters,
    )?;

    //$ K_{B} $
    let decentralized_party_nonce_public_share = decentralized_party_nonce_public_share_first_part
        .add_vartime(
            &decentralized_party_nonce_public_share_second_part
                .scale_vartime(&presign_public_randomizer, group_public_parameters),
            group_public_parameters,
        );

    Ok(RandomizedNonceShareResult {
        presign_public_randomizer,
        decentralized_party_nonce_public_share,
    })
}

/// This function derives the public signature nonce $K$ by first deriving the
/// combined signature public nonce share of the decentralized party
/// This function implements step (1b) of the Sign protocol:
/// <https://eprint.iacr.org/archive/2025/297/1747917268.pdf> Protocol C.5
/// $K_B$ from two points $K_{B,0}, K_{B,1}$ by applying a linear combination using the
/// public randomizer $\mu_{k}^{0}$ derived from a hash
/// $\mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,K_A,K_{B,0},K_{B,1})$
///  - $K_{B,0}+\mu_{k}^{1}\cdot K_{B,1}$
///
/// And then adding it with the user public nonce share $K_A$, and normalizing if needed.
pub(crate) fn derive_normalized_public_nonce<
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
    // $ K_{A} $
    centralized_party_public_nonce_share: &GroupElement::Value,
    public_key: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
) -> crate::Result<NormalizedPublicNonceResult<SCALAR_LIMBS, GroupElement>>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    // === 2(b) $K_{B} = K_{B,0}+\mu_{k}K_{B,1}$ where $\mu_{k}\gets \mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,K_A,K_{B,0},K_{B,1})$
    // The hash includes a fixed prefix and the group public parameters (omitted in the paper) and the ordered is changed.
    // Group elements are hashed in their original form, before any negation for Taproot normalization.
    let result = derive_randomized_decentralized_party_public_nonce_share(
        session_id,
        message,
        hash_scheme,
        decentralized_party_nonce_public_share_first_part,
        decentralized_party_nonce_public_share_second_part,
        centralized_party_public_nonce_share,
        group_public_parameters,
        public_key,
    )?;

    let centralized_party_public_nonce_share = GroupElement::new(
        centralized_party_public_nonce_share.clone(),
        group_public_parameters,
    )?;

    // $ K $
    let mut public_nonce = centralized_party_public_nonce_share.add_vartime(
        &result.decentralized_party_nonce_public_share,
        group_public_parameters,
    );

    // If a group element is not Taproot-normalized, its negation will be.
    // Continue signing using the negated public_nonce and public_nonce_share (now Taproot-normalized)
    // and the corresponding negated nonce share.
    let nonce_normalized = if !public_nonce.is_taproot_normalized() {
        public_nonce = public_nonce.neg_constant_time(group_public_parameters);

        true
    } else {
        false
    };

    Ok(NormalizedPublicNonceResult {
        nonce_normalized,
        presign_public_randomizer: result.presign_public_randomizer,
        decentralized_party_nonce_public_share: public_nonce,
    })
}
