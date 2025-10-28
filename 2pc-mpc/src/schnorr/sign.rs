// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::schnorr::{Presign, VerifyingKey};
use crate::{Error, Result};
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, NonZero, Uint};
use group::{GroupElement, HashScheme, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use merlin::Transcript;
use proof::TranscriptProtocol;

pub mod centralized_party;
mod class_groups;
mod decentralized_party;

/// Generates the `s` part of a Schnorr signature on `message` (optionally) prepended by `prefix`.
pub fn generate_schnorr_signature_response<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    secret_key: GroupElement::Scalar,
    public_key: GroupElement,
    nonce: GroupElement::Scalar,
    public_nonce: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
) -> Result<GroupElement::Scalar> {
    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type)?;

    generate_schnorr_response::<SCALAR_LIMBS, GroupElement>(secret_key, nonce, challenge)
}

/// Generates a partial Schnorr response (the `s` part of the partial signature) on `message` (optionally) prepended by `prefix`.
pub fn generate_partial_schnorr_response<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    secret_key_share: GroupElement::Scalar,
    public_key: GroupElement,
    nonce_share: GroupElement::Scalar,
    public_nonce: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
) -> Result<GroupElement::Scalar> {
    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type)?;

    generate_schnorr_response::<SCALAR_LIMBS, GroupElement>(
        secret_key_share,
        nonce_share,
        challenge,
    )
}

/// Generates the `s` part of a Schnorr signature on `message` (optionally) prepended by `prefix`.
/// Note: this function is also used for generating partial signature,
/// in which case `public_nonce` and `public_key` do not necessarily correspond to `nonce` and `secret_key`,
/// and therefore no correctness checks are performed here, and the responsibility remains on the caller.
pub fn generate_schnorr_response<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    secret_key: GroupElement::Scalar,
    nonce: GroupElement::Scalar,
    challenge: GroupElement::Scalar,
) -> Result<GroupElement::Scalar> {
    let s = (challenge * secret_key) + nonce;

    Ok(s)
}

/// Verifies a Schnorr signature on `message` (optionally) prepended by `prefix`.
/// Note: `public_key` and `public_nonce` must be non-unit.
/// Note: `public_nonce` must be normalized, i.e. the `y` value must be even.
/// Note: `public_key` is always interpreted as the corresponding normalized element.
pub fn verify_schnorr_signature<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    // $ s $
    signature_response: GroupElement::Scalar,
    public_nonce: GroupElement,
    public_key: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
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
        public_key.neg()
    };

    // The public nonce must be normalized
    if !public_nonce.is_taproot_normalized() {
        return Err(Error::SignatureVerification);
    }

    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type)?;

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
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    // $ s $
    partial_response: GroupElement::Scalar,
    public_nonce_share: GroupElement,
    public_nonce: GroupElement,
    public_key_share: GroupElement,
    public_key: GroupElement,
    message: &[u8],
    hash_type: HashScheme,
    group_public_parameters: &group::PublicParameters<GroupElement>,
) -> Result<()> {
    // The public nonce must be normalized
    if !public_nonce.is_taproot_normalized() {
        return Err(Error::SignatureVerification);
    }

    let challenge = public_key.derive_challenge(&public_nonce, message, hash_type)?;

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
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    // $ s $
    signature_response: GroupElement::Scalar,
    challenge: GroupElement::Scalar,
    public_nonce: GroupElement,
    public_key: GroupElement,
    group_public_parameters: &group::PublicParameters<GroupElement>,
) -> Result<()> {
    if bool::from(public_nonce.is_neutral()) || bool::from(public_key.is_neutral()) {
        return Err(Error::SignatureVerification);
    }

    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    let reconstructed_public_nonce = (signature_response * generator) - (challenge * public_key);

    if public_nonce == reconstructed_public_nonce {
        Ok(())
    } else {
        Err(Error::SignatureVerification)
    }
}

/// This function derives the combined signature public nonce share of the decentralized party
/// $K_B$ and the encryption of its signature nonce share $\textsf{ct}_{k}$ from two points $K_{B,0}, K_{B,1}$ and encryptions of
/// their discrete logs $\textsf{ct}_{k_{0}}, \textsf{ct}_{k_{1}}$ by applying a linear combination using the
/// public randomizer $\mu_{k}$ derived from a hash
/// $\mathcal{H}(prefix, \textsf{sid},\textsf{msg},X,K_A,K_{B,0},K_{B,1},\mathbb{G},G,q,H)$
///  - $\textsf{ct}_{k}=(\textsf{ct}_{k_{0}})\oplus(\mu_{k}\odot\textsf{ct}_{k_{1}})$
#[allow(dead_code)]
fn derive_randomized_decentralized_party_public_nonce_share_and_encryption_of_nonce_share<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    session_id: CommitmentSizedNumber,
    // $m$
    message: &[u8],
    hash_type: HashScheme,
    presign: Presign<GroupElement::Value, group::Value<EncryptionKey::CiphertextSpaceGroupElement>>,
    // $ K_{A} $
    centralized_party_public_nonce_share: &GroupElement::Value,
    encryption_scheme_public_parameters: &EncryptionKey::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    public_key: &GroupElement::Value,
) -> crate::Result<(EncryptionKey::CiphertextSpaceGroupElement, GroupElement)>
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
            hash_type,
            presign.decentralized_party_nonce_public_share_first_part,
            presign.decentralized_party_nonce_public_share_second_part,
            centralized_party_public_nonce_share,
            group_public_parameters,
            public_key,
        )?;

    // $\textsf{ct}_{k_{0}$
    let encryption_of_decentralized_party_nonce_share_first_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encryption_of_decentralized_party_nonce_share_first_part,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    // $K_{B,0}$
    let decentralized_party_nonce_public_share_first_part = GroupElement::new(
        presign.decentralized_party_nonce_public_share_first_part,
        group_public_parameters,
    )?;

    // $\textsf{ct}_{k_{1}$
    let encryption_of_decentralized_party_nonce_share_second_part =
        EncryptionKey::CiphertextSpaceGroupElement::new(
            presign.encryption_of_decentralized_party_nonce_share_second_part,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    // $K_{B,1}$
    let decentralized_party_nonce_public_share_second_part = GroupElement::new(
        presign.decentralized_party_nonce_public_share_second_part,
        group_public_parameters,
    )?;

    //$ K_{B} $
    let decentralized_party_nonce_public_share = decentralized_party_nonce_public_share_first_part
        .add_vartime(
            &decentralized_party_nonce_public_share_second_part
                .scale_vartime(&presign_public_randomizer),
        );

    // $ \textsf{ct}_{k} $
    let encryption_of_decentralized_party_nonce_share =
        encryption_of_decentralized_party_nonce_share_first_part.add_vartime(
            &encryption_of_decentralized_party_nonce_share_second_part
                .scale_vartime(&presign_public_randomizer),
        );

    Ok((
        encryption_of_decentralized_party_nonce_share,
        decentralized_party_nonce_public_share,
    ))
}

/// This function derives the combined signature public nonce share of the decentralized party
/// This function implements step (1b) of the Sign protocol:
/// <https://eprint.iacr.org/archive/2025/297/1747917268.pdf> Protocol C.5
/// $K_B$ from two points $K_{B,0}, K_{B,1}$ by applying a linear combination using the
/// public randomizer $\mu_{k}^{0}$ derived from a hash
/// $\mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,K_A,K_{B,0},K_{B,1})$
///  - $K_{B,0}+\mu_{k}^{1}\cdot K_{B,1}$
#[allow(dead_code)]
fn derive_randomized_decentralized_party_public_nonce_share<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    session_id: CommitmentSizedNumber,
    // $m$
    message: &[u8],
    hash_type: HashScheme,
    // $ K_{B,0} $
    decentralized_party_nonce_public_share_first_part: GroupElement::Value,
    // $ K_{B,1} $
    decentralized_party_nonce_public_share_second_part: GroupElement::Value,
    // $ K_{A} $
    centralized_party_public_nonce_share: &GroupElement::Value,
    public_key: &GroupElement::Value,
    group_public_parameters: &GroupElement::PublicParameters,
) -> crate::Result<GroupElement>
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
            hash_type,
            decentralized_party_nonce_public_share_first_part,
            decentralized_party_nonce_public_share_second_part,
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
                .scale_vartime(&presign_public_randomizer),
        );

    Ok(decentralized_party_nonce_public_share)
}

/// This function derives the public randomizer $\mu_{k}^{0}$ from a hash
/// $\mathcal{H}(\textsf{sid},\textsf{msg},\mathbb{G},G,q,H,X,K_A,K_{B,0},K_{B,1})$
#[allow(dead_code)]
fn derive_presign_public_randomizer<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS>,
>(
    session_id: CommitmentSizedNumber,
    // $m$
    message: &[u8],
    hash_type: HashScheme,
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
    let mut transcript = Transcript::new(
        b"DKG randomize decentralized party public key share and encryption of secret key share",
    );

    transcript.append_uint::<{ CommitmentSizedNumber::LIMBS }>(b"$ sid $", &session_id);
    transcript.append_message(b"$ msg $", message);
    transcript.serialize_to_transcript_as_json(b"$ H $", &hash_type)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr::{
        EdDSASignature, SchnorrkelSubstrateSignature, TaprootSignature, VerifyingKey,
    };
    use ecdsa::signature::digest::Digest;
    use group::{curve25519, ristretto, secp256k1, CyclicGroupElement, OsCsRng, Samplable};
    use k256::sha2::Sha256;
    use std::ops::Neg;

    #[test]
    fn signs_taproot() {
        let message = b"taprooted!";
        let hashed_message = Sha256::new_with_prefix(message).finalize();

        let group_public_parameters = secp256k1::group_element::PublicParameters::default();
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();

        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let mut secret_key =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();
        let mut nonce =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let mut public_nonce = nonce * generator;
        let mut public_key = secret_key * generator;

        if !public_key.is_taproot_normalized() {
            secret_key = secret_key.neg();
            public_key = public_key.neg();
        }

        if !public_nonce.is_taproot_normalized() {
            nonce = nonce.neg();
            public_nonce = public_nonce.neg();
        }

        let response = generate_schnorr_signature_response(
            secret_key,
            public_key,
            nonce,
            public_nonce,
            &hashed_message,
            HashScheme::SHA256,
        )
        .unwrap();

        let res = verify_schnorr_signature(
            response,
            public_nonce,
            public_key,
            &hashed_message,
            HashScheme::SHA256,
            &group_public_parameters,
        );

        assert!(
            res.is_ok(),
            "generated signatures should be verified internally"
        );

        let signature = TaprootSignature::try_from((public_nonce.value(), response)).unwrap();
        let res = public_key.verify(&hashed_message, HashScheme::SHA256, &signature);

        assert!(
            res.is_ok(),
            "generated signatures should be verified externally, got error {:?}",
            res.err().unwrap()
        );
    }

    #[test]
    fn signs_eddsa() {
        let message = b"hey edD!";

        let group_public_parameters = curve25519::PublicParameters::default();
        let scalar_group_public_parameters = curve25519::scalar::PublicParameters::default();

        let generator =
            curve25519::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let secret_key =
            curve25519::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();
        let nonce =
            curve25519::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let public_nonce = nonce * generator;
        let public_key = secret_key * generator;

        let response = generate_schnorr_signature_response(
            secret_key,
            public_key,
            nonce,
            public_nonce,
            message,
            HashScheme::SHA512,
        )
        .unwrap();

        let res = verify_schnorr_signature(
            response,
            public_nonce,
            public_key,
            message,
            HashScheme::SHA512,
            &group_public_parameters,
        );

        assert!(
            res.is_ok(),
            "generated signatures should be verified internally"
        );

        let signature = EdDSASignature::try_from((public_nonce.value(), response)).unwrap();
        let res = public_key.verify(message, HashScheme::SHA512, &signature);

        assert!(
            res.is_ok(),
            "generated signatures should be verified externally, got error {:?}",
            res.err().unwrap()
        );
    }

    #[test]
    fn signs_schnorrkel() {
        let message = b"schnorrkelling with the Orcas!";

        let group_public_parameters = ristretto::group_element::PublicParameters::default();
        let scalar_group_public_parameters = ristretto::scalar::PublicParameters::default();

        let generator =
            ristretto::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let secret_key =
            ristretto::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();
        let nonce =
            ristretto::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng).unwrap();

        let public_nonce = nonce * generator;
        let public_key = secret_key * generator;

        let response = generate_schnorr_signature_response(
            secret_key,
            public_key,
            nonce,
            public_nonce,
            message,
            HashScheme::Merlin,
        )
        .unwrap();

        let res = verify_schnorr_signature(
            response,
            public_nonce,
            public_key,
            message,
            HashScheme::Merlin,
            &group_public_parameters,
        );

        assert!(
            res.is_ok(),
            "generated signatures should be verified internally"
        );

        let signature =
            SchnorrkelSubstrateSignature::try_from((public_nonce.value(), response)).unwrap();
        let res = public_key.verify(message, HashScheme::Merlin, &signature);

        assert!(
            res.is_ok(),
            "generated signatures should be verified externally, got error {:?}",
            res.err().unwrap()
        );
    }
}
