// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # Decentralized Party Signing
//!
//! Implements the decentralized party ($B_i$) side of Protocol 9.3.
//!
//! ## Round 1
//!
//! 1. Receive $(z_A, K_A)$ from $\mathcal{F}_{\textsf{broadcast}}$
//! 2. Verify $K_A \in \mathbb{G}$, abort if not
//! 3. Verify partial signature: $z_A \cdot G = K_A + e \cdot X_A$
//! 4. Since $z_A$ is public, compute share $[z_A]_i$
//! 5. Query random oracle:
//!    $$\mu_k = \mathcal{H}(\textsf{sid}, X, \textsf{pres}_{X,\textsf{sid}}, K_A, \textsf{msg})$$
//! 6. Compute:
//!    - Combined nonce share: $[k]_i = [k_0]_i + \mu_k \cdot [k_1]_i$
//!    - Full public nonce: $K = K_{B,0} + \mu_k \cdot K_{B,1} + K_A$
//! 7. Compute challenge: $e = \mathcal{H}(K, X, \textsf{msg})$
//! 8. Compute signature share:
//!    $$[\sigma]_i = [k]_i + e \cdot [x_B]_i + [z_A]_i$$
//! 9. Broadcast $[\sigma]_i$
//!
//! ## Broadcast Round
//!
//! 1. Collect signature shares $\{[\sigma]_j\}$
//! 2. Reconstruct $\sigma$ using Lagrange interpolation at $x = 0$:
//!    $$\sigma = \sum_{j \in S} \lambda_j \cdot [\sigma]_j$$
//!    where $\lambda_j = \prod_{k \in S, k \neq j} \frac{k}{k - j}$
//! 3. Global broadcast $\sigma$
//!
//! ## Output
//!
//! Output the reconstructed signature $\sigma$

use super::centralized_party::PartialSignature;
use crate::dkg::decentralized_party::Output;
use crate::schnorr::sign::decentralized_party::normalize_and_optionally_verify_centralized_party_partial_signature;
use crate::schnorr::sign::derive_normalized_public_nonce;
use crate::schnorr::VerifyingKey;
use crate::sign::SignData;
use crate::Result;
use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::{
    GroupElement as _, HashContext, HashScheme, Invert, PartyID, StatisticalSecuritySizedNumber,
};
pub use mpc::secret_sharing::shamir::known_order::lagrange_interpolate_at_zero;
use mpc::secret_sharing::shamir::Polynomial;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A signature share from one party: the scalar value $[\sigma]_i$.
pub type SignatureShare<ScalarValue> = ScalarValue;

/// Computes the signature share for a decentralized party.
///
/// # Protocol Steps
///
/// 1. Verify centralized party's partial signature
/// 2. Compute $\mu_k$ from random oracle for nonce shares
/// 3. Compute combined nonce share: $[k]_i = [k_0]_i + \mu_k \cdot [k_1]_i$
/// 4. Compute combined secret key share using DKG randomizers:
///    $[x_B]_i = \mu_x^0 \cdot [x_0]_i + \mu_x^1 \cdot [x_1]_i + \mu_x^G$
/// 5. Compute full nonce $K$ and challenge $e$
/// 6. Compute signature share: $[\sigma]_i = [k]_i + e \cdot [x_B]_i + [z_A]_i$
///
/// # Arguments
///
/// * `dkg_output` - DKG output from `UniversalPublicDKGOutput`
/// * `first_key_public_randomizer` - Key randomizer $\mu_x^0$ from Universal DKG
/// * `second_key_public_randomizer` - Key randomizer $\mu_x^1$ from Universal DKG
/// * `free_coefficient_key_public_randomizer` - Key randomizer $\mu_x^G$ from Universal DKG
/// * `secret_key_share_first_part` - This party's first secret key share $[x_0]_i$
/// * `secret_key_share_second_part` - This party's second secret key share $[x_1]_i$
/// * `presign_public_nonce_share_first_part` - Public nonce commitment $K_{B,0}$
/// * `presign_public_nonce_share_second_part` - Public nonce commitment $K_{B,1}$
/// * `nonce_share_first_part` - This party's first nonce share $[k_0]_i$
/// * `nonce_share_second_part` - This party's second nonce share $[k_1]_i$
/// * `centralized_partial_signature` - The partial signature from the centralized party
/// * `message` - The message to sign
/// * `session_id` - Session ID for domain separation
/// * `hash_scheme` - Hash scheme to use for challenges
/// * `scalar_group_public_parameters` - Public parameters for the scalar field
/// * `group_public_parameters` - Public parameters for the group
///
/// # Returns
///
/// The signature share to broadcast.
#[allow(clippy::too_many_arguments)]
pub fn compute_signature_share<const SCALAR_LIMBS: usize, GroupElement, CiphertextSpaceValue>(
    session_id: CommitmentSizedNumber,
    hash_scheme: HashScheme,
    hash_context: &HashContext,
    message: &[u8],
    dkg_output: &Output<GroupElement::Value, CiphertextSpaceValue>,
    first_key_public_randomizer: Uint<SCALAR_LIMBS>,
    second_key_public_randomizer: Uint<SCALAR_LIMBS>,
    free_coefficient_key_public_randomizer: Uint<SCALAR_LIMBS>,
    secret_key_share_first_part: group::Value<GroupElement::Scalar>,
    secret_key_share_second_part: group::Value<GroupElement::Scalar>,
    decentralized_party_nonce_public_share_first_part: GroupElement::Value,
    decentralized_party_nonce_public_share_second_part: GroupElement::Value,
    nonce_share_first_part: group::Value<GroupElement::Scalar>,
    nonce_share_second_part: group::Value<GroupElement::Scalar>,
    sign_data: SignData<
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
        PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
    >,
    group_public_parameters: &GroupElement::PublicParameters,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> Result<SignatureShare<group::Value<GroupElement::Scalar>>>
where
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    GroupElement::Value: serde::Serialize,
    GroupElement::PublicParameters: Clone + serde::Serialize,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    let (centralized_party_partial_signature, should_verify) =
        crate::schnorr::sign::decentralized_party::resolve_sign_data::<SCALAR_LIMBS, GroupElement>(
            sign_data,
            &dkg_output.centralized_party_public_key_share,
            group_public_parameters,
            scalar_group_public_parameters,
        )?;

    // $ z_{A} $
    let centralized_party_partial_response = GroupElement::Scalar::new(
        centralized_party_partial_signature.partial_response,
        scalar_group_public_parameters,
    )?;

    let verification_result = normalize_and_optionally_verify_centralized_party_partial_signature::<
        SCALAR_LIMBS,
        GroupElement,
    >(
        session_id,
        message,
        hash_scheme,
        hash_context,
        decentralized_party_nonce_public_share_first_part,
        decentralized_party_nonce_public_share_second_part,
        &dkg_output.centralized_party_public_key_share,
        centralized_party_partial_signature,
        &dkg_output.public_key,
        group_public_parameters,
        scalar_group_public_parameters,
        should_verify,
    )?;

    let presign_public_randomizer =
        GroupElement::Scalar::from(verification_result.presign_public_randomizer);

    // Compute combined nonce share: $[k]_i = [k_0]_i + \mu_k \cdot [k_1]_i$
    let nonce_share_first_part =
        GroupElement::Scalar::new(nonce_share_first_part, scalar_group_public_parameters)?;
    let nonce_share_second_part =
        GroupElement::Scalar::new(nonce_share_second_part, scalar_group_public_parameters)?;

    let mut nonce_share = nonce_share_first_part.add_constant_time(
        &(presign_public_randomizer * nonce_share_second_part),
        scalar_group_public_parameters,
    );

    // If a group element is not Taproot-normalized, its negation will be.
    // Continue signing using the negated public_nonce and the corresponding negated nonce share.
    // This must match what the centralized party did.
    if verification_result.nonce_normalized {
        nonce_share = nonce_share.neg_constant_time(scalar_group_public_parameters);
    }

    let first_key_public_randomizer = GroupElement::Scalar::from(first_key_public_randomizer);
    let second_key_public_randomizer = GroupElement::Scalar::from(second_key_public_randomizer);
    let free_coefficient_key_public_randomizer =
        GroupElement::Scalar::from(free_coefficient_key_public_randomizer);

    // Compute combined secret key share using 3 randomizers from DKG:
    // $[x_B]_i = \mu_x^0 \cdot [x_0]_i + \mu_x^1 \cdot [x_1]_i + \mu_x^G$
    let secret_share_first =
        GroupElement::Scalar::new(secret_key_share_first_part, scalar_group_public_parameters)?;
    let secret_share_second =
        GroupElement::Scalar::new(secret_key_share_second_part, scalar_group_public_parameters)?;

    let mut secret_key_share = (first_key_public_randomizer * secret_share_first)
        .add_constant_time(
            &(second_key_public_randomizer * secret_share_second),
            scalar_group_public_parameters,
        )
        .add_constant_time(
            &free_coefficient_key_public_randomizer,
            scalar_group_public_parameters,
        );

    // If a group element is not taproot normalized then its negation will be.
    // We then continue to sign according to the negated public_key and the negated secret share.
    if verification_result.key_normalized {
        secret_key_share = secret_key_share.neg_constant_time(scalar_group_public_parameters);
    }

    // Compute challenge $e = \mathcal{H}(K, X, msg)$ using normalized values
    let challenge = verification_result.public_key.derive_challenge(
        &verification_result.public_nonce,
        message,
        hash_scheme,
        hash_context,
    )?;

    // Compute signature share: $[\sigma]_i = [k]_i + e \cdot [x_B]_i + z_A$
    // Using the normalized nonce and secret key shares.
    let signature_share = nonce_share
        .add_constant_time(
            &(challenge * secret_key_share),
            scalar_group_public_parameters,
        )
        .add_constant_time(
            &centralized_party_partial_response,
            scalar_group_public_parameters,
        );

    Ok(signature_share.value())
}

/// Finalizes the signature by reconstructing from shares and verifying.
///
/// This is the round 2 logic for the decentralized party sign protocol.
///
/// # Protocol Steps
///
/// 1. Reconstruct signature response $\sigma$ from shares using Lagrange interpolation
/// 2. Compute the full public nonce $K = K_A + K_{B,0} + \mu_k \cdot K_{B,1}$
/// 3. Normalize $K$ if needed for Taproot
/// 4. Create and verify the final signature
///
/// # Arguments
///
/// * `signature_shares` - Exactly `threshold` signature shares (map from party ID to share)
/// * `threshold` - The threshold of the secret sharing scheme (number of shares required)
/// * `centralized_party_public_nonce_share_prenormalization` - $K_A$ before normalization
/// * `decentralized_party_nonce_public_share_first_part` - $K_{B,0}$
/// * `decentralized_party_nonce_public_share_second_part` - $K_{B,1}$
/// * `public_key` - The full public key $X$
/// * `message` - The message that was signed
/// * `session_id` - Session ID for domain separation
/// * `hash_scheme` - Hash scheme used for challenges
/// * `scalar_group_public_parameters` - Public parameters for scalars
/// * `group_public_parameters` - Public parameters for the group
///
/// # Returns
///
/// The verified signature.
///
/// # Errors
///
/// Returns `Error::from(ErrorKind::InvalidParameters)` if the number of shares does not equal `threshold`.
/// Returns an error if signature verification fails.
pub fn finalize_signature<const SCALAR_LIMBS: usize, GroupElement>(
    session_id: CommitmentSizedNumber,
    message: &[u8],
    hash_scheme: HashScheme,
    hash_context: &HashContext,
    signature_shares: &HashMap<PartyID, group::Value<GroupElement::Scalar>>,
    threshold: PartyID,
    centralized_party_public_nonce_share_prenormalization: GroupElement::Value,
    decentralized_party_nonce_public_share_first_part: GroupElement::Value,
    decentralized_party_nonce_public_share_second_part: GroupElement::Value,
    public_key: GroupElement::Value,
    scalar_group_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
) -> Result<GroupElement::Signature>
where
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>
        + Invert,
    GroupElement::Value: serde::Serialize,
    GroupElement::PublicParameters: Clone + serde::Serialize,
    Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    // Reconstruct the signature response using Lagrange interpolation
    let reconstructed_response = lagrange_interpolate_at_zero::<SCALAR_LIMBS, GroupElement::Scalar>(
        signature_shares,
        threshold,
        scalar_group_public_parameters,
    )?;

    // Derive the normalized public nonce and randomizer
    let public_nonce = derive_normalized_public_nonce::<SCALAR_LIMBS, GroupElement>(
        session_id,
        message,
        hash_scheme,
        decentralized_party_nonce_public_share_first_part,
        decentralized_party_nonce_public_share_second_part,
        &centralized_party_public_nonce_share_prenormalization,
        &public_key,
        group_public_parameters,
    )?
    .decentralized_party_nonce_public_share;

    // Verify the reconstructed signature
    let signature =
        GroupElement::Signature::try_from((public_nonce.value(), reconstructed_response))?;
    let public_key = GroupElement::new(public_key, group_public_parameters)?;
    public_key.verify(message, hash_scheme, hash_context, &signature)?;

    Ok(signature)
}

/// Evaluates a polynomial commitment at a given point (party ID).
///
/// Given coefficient commitments $\{C_0, C_1, ..., C_{t-1}\}$ for a polynomial
/// $f(x) = c_0 + c_1 \cdot x + ... + c_{t-1} \cdot x^{t-1}$,
/// this computes $f(i) \cdot G = C_0 + i \cdot C_1 + i^2 \cdot C_2 + ... + i^{t-1} \cdot C_{t-1}$.
///
/// # Arguments
///
/// * `coefficient_commitments` - The polynomial coefficient commitments $\{C_j\}$
/// * `party_id` - The evaluation point $i$
/// * `group_public_parameters` - Group public parameters
///
/// # Returns
///
/// The commitment to the polynomial evaluated at `party_id`: $f(i) \cdot G$.
pub fn evaluate_polynomial_commitment<const SCALAR_LIMBS: usize, GroupElement>(
    coefficient_commitments: Vec<GroupElement>,
    party_id: PartyID,
    group_public_parameters: &GroupElement::PublicParameters,
) -> Result<GroupElement>
where
    GroupElement: group::GroupElement,
    Uint<SCALAR_LIMBS>: Encoding,
{
    // Create polynomial from commitments and evaluate at party_id in variable-time
    let is_evaluation_constant_time = false;
    Ok(
        Polynomial::try_from(coefficient_commitments)?.evaluate_degree(
            party_id,
            is_evaluation_constant_time,
            group_public_parameters,
        ),
    )
}

/// Verifies a signature share using polynomial commitments (DOS protection).
///
/// This function verifies that a party's signature share is correctly computed by checking:
/// $[\sigma]_i \cdot G \stackrel{?}{=} K_i + e \cdot X_{B,i} + z_A \cdot G$
///
/// where:
/// - $K_i = K_{0,i} + \mu_k \cdot K_{1,i}$ is the combined nonce share commitment
/// - $K_{0,i}, K_{1,i}$ are evaluations of nonce polynomial commitments at party_id
/// - $X_{B,i} = \mu_x^0 \cdot X_{0,i} + \mu_x^1 \cdot X_{1,i} + \mu_x^G \cdot G$ is the secret key share commitment
/// - $X_{0,i}, X_{1,i}$ are evaluations of secret key polynomial commitments at party_id
///
/// # Arguments
///
/// * `party_id` - The party whose share to verify
/// * `signature_share` - The signature share value $[\sigma]_i$
/// * `first_nonce_polynomial_commitments` - Commitments for $k_0$ polynomial
/// * `second_nonce_polynomial_commitments` - Commitments for $k_1$ polynomial
/// * `first_secret_key_polynomial_commitments` - Commitments for $x_0$ polynomial
/// * `second_secret_key_polynomial_commitments` - Commitments for $x_1$ polynomial
/// * `presign_public_randomizer` - $\mu_k$ for combining nonce shares
/// * `first_key_public_randomizer` - $\mu_x^0$ for combining secret key shares
/// * `second_key_public_randomizer` - $\mu_x^1$ for combining secret key shares
/// * `free_coefficient_key_public_randomizer` - $\mu_x^G$ (added to all shares)
/// * `challenge` - The Schnorr challenge $e$
/// * `centralized_partial_response` - $z_A$ from the centralized party
/// * `is_nonce_negated` - Whether the nonce was negated during signing (Taproot normalization)
/// * `is_key_negated` - Whether the key was negated during signing (Taproot normalization)
/// * `scalar_group_public_parameters` - Scalar field public parameters
/// * `group_public_parameters` - Group public parameters
///
/// # Returns
///
/// `Ok(())` if the share is valid, `Err(InvalidSignature)` if verification fails.
#[allow(clippy::too_many_arguments)]
pub fn verify_signature_share<const SCALAR_LIMBS: usize, GroupElement>(
    party_id: PartyID,
    signature_share: group::Value<GroupElement::Scalar>,
    first_nonce_polynomial_commitments: Vec<GroupElement>,
    second_nonce_polynomial_commitments: Vec<GroupElement>,
    first_secret_key_polynomial_commitments: Vec<GroupElement>,
    second_secret_key_polynomial_commitments: Vec<GroupElement>,
    presign_public_randomizer: Uint<SCALAR_LIMBS>,
    first_key_public_randomizer: Uint<SCALAR_LIMBS>,
    second_key_public_randomizer: Uint<SCALAR_LIMBS>,
    free_coefficient_key_public_randomizer: Uint<SCALAR_LIMBS>,
    challenge: GroupElement::Scalar,
    centralized_partial_response: group::Value<GroupElement::Scalar>,
    nonce_normalized: bool,
    key_normalized: bool,
    scalar_group_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
) -> Result<()>
where
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy + group::Scale<Uint<SCALAR_LIMBS>>,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    Uint<SCALAR_LIMBS>: Encoding,
{
    // Compute K_i = K_{0,i} + mu_k * K_{1,i}
    let nonce_commitment_first = evaluate_polynomial_commitment::<SCALAR_LIMBS, GroupElement>(
        first_nonce_polynomial_commitments,
        party_id,
        group_public_parameters,
    )?;

    let nonce_commitment_second = evaluate_polynomial_commitment::<SCALAR_LIMBS, GroupElement>(
        second_nonce_polynomial_commitments,
        party_id,
        group_public_parameters,
    )?;

    let mut nonce_commitment = nonce_commitment_first.add_vartime(
        &nonce_commitment_second.scale_vartime(&presign_public_randomizer, group_public_parameters),
        group_public_parameters,
    );

    // Apply Taproot normalization if nonce was negated during signing
    if nonce_normalized {
        nonce_commitment = nonce_commitment.neg_constant_time(group_public_parameters);
    }

    // Compute X_{B,i} = mu_x^0 * X_{0,i} + mu_x^1 * X_{1,i} + mu_x^G * G
    let secret_key_commitment_first = evaluate_polynomial_commitment::<SCALAR_LIMBS, GroupElement>(
        first_secret_key_polynomial_commitments,
        party_id,
        group_public_parameters,
    )?;

    let secret_key_commitment_second = evaluate_polynomial_commitment::<SCALAR_LIMBS, GroupElement>(
        second_secret_key_polynomial_commitments,
        party_id,
        group_public_parameters,
    )?;

    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    let mut secret_key_share_commitment = secret_key_commitment_first
        .scale_vartime(&first_key_public_randomizer, group_public_parameters)
        .add_vartime(
            &secret_key_commitment_second
                .scale_vartime(&second_key_public_randomizer, group_public_parameters),
            group_public_parameters,
        )
        .add_vartime(
            &generator.scale_vartime(
                &free_coefficient_key_public_randomizer,
                group_public_parameters,
            ),
            group_public_parameters,
        );

    // Apply Taproot normalization if key was negated during signing
    if key_normalized {
        secret_key_share_commitment =
            secret_key_share_commitment.neg_constant_time(group_public_parameters);
    }

    // Compute z_A * G
    let partial_response =
        GroupElement::Scalar::new(centralized_partial_response, scalar_group_public_parameters)?;
    let partial_response_commitment = partial_response * generator;

    // Compute expected: K_i + e * X_{B,i} + z_A * G
    let expected = nonce_commitment
        .add_vartime(
            &(challenge * secret_key_share_commitment),
            group_public_parameters,
        )
        .add_vartime(&partial_response_commitment, group_public_parameters);

    // Compute actual: sigma_i * G
    let share = GroupElement::Scalar::new(signature_share, scalar_group_public_parameters)?;
    let actual = share * generator;

    // Verify
    if expected == actual {
        Ok(())
    } else {
        // Verification failed - the signature share is invalid
        Err(crate::Error::from(crate::ErrorKind::InvalidSignatureShare))
    }
}

/// Public input for the decentralized party's sign protocol.
///
/// This adapts the VSS sign interface to the sign::Protocol trait requirements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<DKGOutput, Presign, SignMessage, ProtocolPublicParameters, GroupElementValue>
{
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub hash_context: HashContext,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub centralized_party_partial_signature: SignData<SignMessage, SignMessage>,
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
    /// Blended polynomial coefficient commitments for the first secret key share polynomial.
    /// These commitments allow verifying signature shares by evaluating at a party's ID.
    /// Commitment at index i is to coefficient $c_i$ of the polynomial $x_1(X) = \sum c_i X^i$.
    pub first_secret_key_polynomial_commitments: Vec<GroupElementValue>,
    /// Blended polynomial coefficient commitments for the second secret key share polynomial.
    /// Commitment at index i is to coefficient $c_i$ of the polynomial $x_2(X) = \sum c_i X^i$.
    pub second_secret_key_polynomial_commitments: Vec<GroupElementValue>,
}

/// Public input for the combined DKG + Sign protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DKGSignPublicInput<
    DKGPublicInput,
    PresignType,
    SignMessage,
    ProtocolPublicParameters,
    GroupElementValue,
> {
    pub expected_signers: HashSet<PartyID>,
    pub message: Vec<u8>,
    pub hash_scheme: HashScheme,
    pub hash_context: HashContext,
    pub dkg_public_input: DKGPublicInput,
    pub presign: PresignType,
    pub centralized_party_partial_signature: SignData<SignMessage, SignMessage>,
    pub decryption_key_share_public_parameters: Arc<()>,
    pub protocol_public_parameters: Arc<ProtocolPublicParameters>,
    /// Blended polynomial coefficient commitments for the first secret key share polynomial.
    pub first_secret_key_polynomial_commitments: Vec<GroupElementValue>,
    /// Blended polynomial coefficient commitments for the second secret key share polynomial.
    pub second_secret_key_polynomial_commitments: Vec<GroupElementValue>,
}

pub mod party;
mod signature_finalization_round;

pub use party::{DKGSignParty, PrivateInput, SignParty};

#[cfg(test)]
mod tests {
    use super::*;
    use group::{secp256k1, OsCsRng, Samplable};

    #[test]
    fn test_lagrange_reconstruction_of_constant() {
        // Test that Lagrange interpolation of a constant polynomial returns the constant
        // If f(x) = c for all x, then sum_j lambda_j * f(j) = c
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        // Sample a random constant
        let constant =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // Create "shares" where each share is just the constant
        let threshold: PartyID = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> =
            party_ids.iter().map(|&id| (id, constant.value())).collect();

        // Reconstruct should give back the constant
        let reconstructed = lagrange_interpolate_at_zero::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
        >(&shares, threshold, &scalar_group_public_parameters)
        .unwrap();

        assert_eq!(
            reconstructed,
            constant.value(),
            "Reconstructing a constant should return the constant"
        );
    }

    #[test]
    fn test_lagrange_reconstruction_of_linear_polynomial() {
        // Test that Lagrange interpolation correctly reconstructs a linear polynomial f(x) = a + bx at x=0
        // f(0) = a, so we should get back the constant term
        use crypto_bigint::Uint;

        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let mut rng = OsCsRng;

        // Create polynomial f(x) = a + b*x
        let a = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let b = secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // Evaluate at party IDs 1, 2, 3
        let threshold: PartyID = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let shares: HashMap<PartyID, group::Value<secp256k1::Scalar>> = party_ids
            .iter()
            .map(|&id| {
                let x =
                    secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(id as u64));
                let f_x = a + b * x; // f(x) = a + b*x
                (id, f_x.value())
            })
            .collect();

        // Reconstruct at x=0 should give f(0) = a
        let reconstructed = lagrange_interpolate_at_zero::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
        >(&shares, threshold, &scalar_group_public_parameters)
        .unwrap();

        assert_eq!(
            reconstructed,
            a.value(),
            "Reconstructing linear polynomial at x=0 should return the constant term"
        );
    }
}
