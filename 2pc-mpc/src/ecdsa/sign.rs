// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::too_many_arguments)]

use std::ops::Neg;

use crypto_bigint::{ConcatMixed, Encoding, NonZero, Uint};
use merlin::Transcript;

use crate::ecdsa::VerifyingKey;
use crate::languages::{KnowledgeOfDecommitmentProof, KnowledgeOfDecommitmentUCProof};
use crate::sign::Protocol;
use crate::{ecdsa::presign::Presign, Error};
use commitment::{CommitmentSizedNumber, Pedersen};
use group::{GroupElement as _, Invert, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use proof::TranscriptProtocol;

pub mod centralized_party;

pub mod class_groups;
pub mod decentralized_party;

pub fn verify_signature<const SCALAR_LIMBS: usize, GroupElement: VerifyingKey<SCALAR_LIMBS>>(
    r: GroupElement::Scalar,
    s: GroupElement::Scalar,
    m: GroupElement::Scalar,
    public_key: GroupElement,
) -> crate::Result<()> {
    // Attend to malleability by not accepting non-normalized signatures.
    if s.neg().value() < s.value() {
        return Err(Error::SignatureVerification);
    };

    let generator = public_key.generator();
    let inverted_s: GroupElement::Scalar =
        Option::from(s.invert()).ok_or(Error::SignatureVerification)?;
    if (((m * inverted_s) * generator) + ((r * inverted_s) * public_key))
        .x_projected_to_scalar_field()
        != r
    {
        return Err(Error::SignatureVerification);
    }

    Ok(())
}

/// This function derives the combined signature public nonce share of the decentralized party
/// $R'_B$ and the encryption of its masked signature nonce share $\textsf{ct}_{\gamma\cdot k}$ (i.e. masked discrete
/// log) from two points $R_{B,0}, R_{B,1}$ and encryptions of
/// their masked discrete logs $\textsf{ct}_{\gamma\cdot k_{0}}, \textsf{ct}_{\gamma\cdot k_{1}}$ by applying a linear combination using the
/// public randomizers $\mu_{x}^{0},\mu_{x}^{1},\mu_{x}^{G}$ derived from a hash
/// $\mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,\textsf{pres}_{X,\textsf{sid}},C_{k},C_{kx},X_{B},
/// C_{\alpha},C_{\beta},\pi_{k},\pi_{\alpha},\pi_{\beta})$
///  - $\textsf{ct}_{\gamma\cdot k}=(mu_{k}^{0}\odot \textsf{ct}_{\gamma\cdot k_{0}})\oplus(\mu_{k}^{1}\odot\textsf{ct}_{\gamma\cdot k_{1}}\oplus \mu_{k}^{G}\odot \textsf{ct}_{\gamma})$
///  - $\mu_{k}^{0}\cdotR_{B,0}+\mu_{k}^{1}\cdot R_{B,1}+\mu_{k}^{G}\cdot G$
///
/// This function implements step 2(c) in the Sign Protocol
/// src: <https://eprint.iacr.org/archive/2025/297/20250522:123428> Protocol C.3
/// NOTE: The protocol uses $ /textsf{msg} $ as input to the random oracle but using any strong collision resistant hash instead is safe.
///       Therefore, although this deviates slightly from the protocol, we can safely use here `hashed_message` instead of the message bytes.
#[allow(dead_code)]
fn derive_randomized_decentralized_party_public_nonce_share_and_encryption_of_nonce_share<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    session_id: CommitmentSizedNumber,
    hashed_message: &GroupElement::Scalar,
    presign: Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
    encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    commitment_scheme_public_parameters: &commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    public_key: &GroupElement::Value,
    centralized_party_public_key_share: &GroupElement::Value,
    signature_nonce_share_commitment: &GroupElement,
    alpha_displacer_commitment: &GroupElement,
    beta_displacer_commitment: &GroupElement,
    signature_nonce_share_by_secret_share_commitment: &GroupElement,
    non_zero_commitment_to_signature_nonce_share_proof: &KnowledgeOfDecommitmentProof<
        SCALAR_LIMBS,
        GroupElement,
    >,
    non_zero_commitment_to_alpha_displacer_share_proof: &KnowledgeOfDecommitmentProof<
        SCALAR_LIMBS,
        GroupElement,
    >,
    commitment_to_beta_displacer_share_uc_proof: &KnowledgeOfDecommitmentUCProof<
        SCALAR_LIMBS,
        GroupElement,
    >,
) -> crate::Result<(EncryptionKey::CiphertextSpaceGroupElement, GroupElement)>
where
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    // $\textsf{ct}_{\gamma\cdot k_{0}$
    let encryption_of_masked_decentralized_party_nonce_share_first_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encryption_of_masked_decentralized_party_nonce_share_first_part,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    // $R_{B,0}$
    let decentralized_party_nonce_public_share_first_part = GroupElement::new(
        presign.decentralized_party_nonce_public_share_first_part,
        group_public_parameters,
    )?;

    // $\textsf{ct}_{\gamma\cdot k_{1}}$
    let encryption_of_masked_decentralized_party_nonce_share_second_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encryption_of_masked_decentralized_party_nonce_share_second_part,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    // $R_{B,1}$
    let decentralized_party_nonce_public_share_second_part = GroupElement::new(
        presign.decentralized_party_nonce_public_share_second_part,
        group_public_parameters,
    )?;

    // $ \textsf{ct}_\gamma $
    let encryption_of_mask = EncryptionKey::CiphertextSpaceGroupElement::new(
        presign.encryption_of_mask,
        encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
    )?;

    let mut transcript = Transcript::new(
        b"DKG randomize decentralized party public key share and encryption of secret key share",
    );

    transcript.append_uint::<{ CommitmentSizedNumber::LIMBS }>(b"$ sid $", &session_id);
    transcript.serialize_to_transcript_as_json(b"$ msg $", &hashed_message.value())?;
    transcript.transcribe(b"$ \\GG,G,q $", group_public_parameters.clone())?;
    transcript.transcribe(b"$ G, H $", commitment_scheme_public_parameters.clone())?;
    transcript.serialize_to_transcript_as_json(b"$X$", &public_key)?;
    transcript.serialize_to_transcript_as_json(
        b"$X_{\\CentralizedParty}$ $",
        &centralized_party_public_key_share,
    )?;
    transcript.serialize_to_transcript_as_json(b"$\\pres_{X,\\sid}", &presign)?;
    transcript
        .serialize_to_transcript_as_json(b"$C_{k}$", &signature_nonce_share_commitment.value())?;
    transcript
        .serialize_to_transcript_as_json(b"$C_{\\alpha}$", &alpha_displacer_commitment.value())?;
    transcript
        .serialize_to_transcript_as_json(b"$C_{\\beta}$", &beta_displacer_commitment.value())?;
    transcript.serialize_to_transcript_as_json(
        b"$C_{kx}$",
        &signature_nonce_share_by_secret_share_commitment.value(),
    )?;
    transcript.serialize_to_transcript_as_json(
        b"$\\pi_k$",
        non_zero_commitment_to_signature_nonce_share_proof,
    )?;
    transcript.serialize_to_transcript_as_json(
        b"$\\pi_{\\alpha}$",
        non_zero_commitment_to_alpha_displacer_share_proof,
    )?;
    transcript.serialize_to_transcript_as_json(
        b"$\\pi_{\\beta}$",
        commitment_to_beta_displacer_share_uc_proof,
    )?;

    let group_order = NonZero::new(GroupElement::order_from_public_parameters(
        group_public_parameters,
    ))
    .unwrap();

    let first_decentralized_party_nonce_share_public_randomizer: Uint<SCALAR_LIMBS> =
        group::Value::<GroupElement::Scalar>::from(
            transcript.uniformly_reduced_challenge::<SCALAR_LIMBS>(b"$\\mu_{k}^{0}$", &group_order),
        )
        .into();

    let second_decentralized_party_nonce_share_public_randomizer: Uint<SCALAR_LIMBS> =
        group::Value::<GroupElement::Scalar>::from(
            transcript.uniformly_reduced_challenge::<SCALAR_LIMBS>(b"$\\mu_{k}^{1}$", &group_order),
        )
        .into();

    let free_coefficient_decentralized_party_nonce_share_public_randomizer: Uint<SCALAR_LIMBS> =
        group::Value::<GroupElement::Scalar>::from(
            transcript.uniformly_reduced_challenge::<SCALAR_LIMBS>(b"$\\mu_{k}^{G}$", &group_order),
        )
        .into();

    // Compute $\textsf{ct}_{\gamma\cdot k}=(mu_{k}^{0}\odot \textsf{ct}_{\gamma\cdot k_{0}})\oplus(\mu_{k}^{1}\odot\textsf{ct}_{\gamma\cdot k_{1}}\oplus \mu_{k}^{G}\odot \textsf{ct}_{\gamma})$
    let encryption_of_masked_decentralized_party_nonce_share_before_displacing =
        ((encryption_of_masked_decentralized_party_nonce_share_first_part
            .scale_vartime(&first_decentralized_party_nonce_share_public_randomizer))
        .add_vartime(
            &(encryption_of_masked_decentralized_party_nonce_share_second_part
                .scale_vartime(&second_decentralized_party_nonce_share_public_randomizer)),
        ))
        .add_vartime(
            &(encryption_of_mask.scale_vartime(
                &free_coefficient_decentralized_party_nonce_share_public_randomizer,
            )),
        );

    // Compute $\mu_{k}^{0}\cdotR_{B,0})+\mu_{k}^{1}\cdot R_{B,1}+\mu_{k}^{G}\cdot G$
    let decentralized_party_nonce_public_share_before_displacing =
        ((decentralized_party_nonce_public_share_first_part
            .scale_vartime(&first_decentralized_party_nonce_share_public_randomizer))
        .add_vartime(
            &(decentralized_party_nonce_public_share_second_part
                .scale_vartime(&second_decentralized_party_nonce_share_public_randomizer)),
        ))
        .add_vartime(
            &(generator.scale_vartime(
                &free_coefficient_decentralized_party_nonce_share_public_randomizer,
            )),
        );

    Ok((
        encryption_of_masked_decentralized_party_nonce_share_before_displacing,
        decentralized_party_nonce_public_share_before_displacing,
    ))
}
