// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # SSS Schnorr Signing
//!
//! This module implements Protocol 9.3: $\Pi_{\textsf{sign}}^{\textsf{SSS-Schnorr}}$
//!
//! ## Protocol Parameters
//!
//! - Elliptic curve group description $(\mathbb{G}, G, q)$
//! - Access structure $\Gamma_B$
//! - Session ID $\textsf{sid}$
//! - Verification key $X$
//! - Pre-sign output: $\textsf{pres} = (K_{B,0} = k_0 \cdot G, K_{B,1} = k_1 \cdot G)$
//! - Each party in $B$ has shares on $x_B, k_0, k_1$
//!
//! ## Protocol Output
//!
//! Valid Schnorr signature $(\sigma, e)$ for verification key $X$
//!
//! ## Centralized Party ($A$) Actions
//!
//! 1. Sample $k_A \gets \mathbb{Z}_q$, compute $K_A = k_A \cdot G$
//! 2. Query random oracle: $\mu_k = \mathcal{H}(\textsf{sid}, X, \textsf{pres}_{X,\textsf{sid}}, K_A, \textsf{msg})$
//! 3. Compute full nonce: $K = K_{B,0} + \mu_k \cdot K_{B,1} + K_A$
//! 4. Compute challenge: $e = \mathcal{H}(K, X, \textsf{msg})$
//! 5. Compute partial signature: $z_A = k_A + e \cdot x_A$
//! 6. Broadcast $(z_A, K_A)$
//!
//! ## Distributed Party ($B_i$) Actions
//!
//! ### Round 1
//!
//! 1. Receive $(z_A, K_A)$ and verify $K_A \in \mathbb{G}$
//! 2. Verify: $z_A \cdot G = K_A + e \cdot X_A$
//! 3. Compute share of $z_A$: $[z_A]_i$ (since $z_A$ is public)
//! 4. Query random oracle to get $\mu_k$
//! 5. Compute:
//!    - $[k]_i = [k_0]_i + \mu_k \cdot [k_1]_i$
//!    - $K = K_{B,0} + \mu_k \cdot K_{B,1} + K_A$
//! 6. Compute challenge: $e = \mathcal{H}(K, X, \textsf{msg})$
//! 7. Compute signature share: $[\sigma]_i = [k]_i + e \cdot [x_B]_i + [z_A]_i$
//! 8. Broadcast $[\sigma]_i$
//!
//! ### Reconstruction
//!
//! 1. Collect shares and reconstruct $\sigma$ using VSS reconstruction
//! 2. Global broadcast $\sigma$
//!
//! ## Output
//!
//! - Centralized party verifies $\sigma$ is valid
//! - Both parties output $\sigma$

pub mod centralized_party;
pub mod decentralized_party;
pub mod protocol;

#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)] // Some imports only used in #[test] functions
pub mod tests {
    use super::centralized_party::sign_with_vss_presign;
    use super::decentralized_party::{
        compute_signature_share, evaluate_polynomial_commitment,
        lagrange_interpolate_at_zero as reconstruct_signature, verify_signature_share,
    };
    use crate::dkg::decentralized_party::VersionedOutput;
    use crate::schnorr::sign::derive_presign_public_randomizer;
    use crate::schnorr::vss::presign::Presign;
    use crate::schnorr::{PartialSignature, VerifyingKey};
    use crate::sign::EncodableSignature;
    use crate::{Error, ErrorKind};
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::{ConcatMixed, Encoding, Uint};
    use group::{
        secp256k1, CsRng, CyclicGroupElement, GroupElement as _, HashContext, HashScheme, OsCsRng,
        PartyID, Samplable, StatisticalSecuritySizedNumber,
    };
    use mpc::secret_sharing::shamir::Polynomial;
    use std::collections::HashMap;
    use std::ops::Neg;

    /// Internal test function for VSS Schnorr signing that can be called with real parameters.
    ///
    /// This allows integration tests to pass real secret key shares from threshold_encryption_to_sharing
    /// instead of using mock values.
    ///
    /// # Arguments
    ///
    /// * `centralized_party_secret_key_share` - The centralized party's secret key share
    /// * `dkg_output` - The DKG output (inner Output struct, not VersionedOutput)
    /// * `first_key_public_randomizer` - Key randomizer μ_x^0 from Universal DKG
    /// * `second_key_public_randomizer` - Key randomizer μ_x^1 from Universal DKG
    /// * `free_coefficient_key_public_randomizer` - Key randomizer μ_x^G from Universal DKG
    /// * `party_secret_key_shares` - Map from party ID to (first_part, second_part) secret key shares
    /// * `presign` - The presign output (session ID and public nonce shares)
    /// * `nonce_shares` - Map from party ID to (first_part, second_part) nonce shares
    /// * `threshold` - Number of shares required to reconstruct
    /// * `message` - The message to sign
    /// * `hash_scheme` - Hash scheme to use
    /// * `scalar_group_public_parameters` - Public parameters for the scalar field
    /// * `group_params` - Public parameters for the group
    /// * `rng` - Cryptographically secure RNG
    ///
    /// # Returns
    ///
    /// The verified Schnorr signature.
    #[allow(clippy::too_many_arguments)]
    pub fn test_vss_signing_internal<
        const SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
        CiphertextSpaceValue: Clone,
    >(
        centralized_party_secret_key_share: group::Value<GroupElement::Scalar>,
        dkg_output: &crate::dkg::decentralized_party::Output<
            GroupElement::Value,
            CiphertextSpaceValue,
        >,
        first_key_public_randomizer: Uint<SCALAR_LIMBS>,
        second_key_public_randomizer: Uint<SCALAR_LIMBS>,
        free_coefficient_key_public_randomizer: Uint<SCALAR_LIMBS>,
        party_secret_key_shares: &HashMap<
            PartyID,
            (
                group::Value<GroupElement::Scalar>,
                group::Value<GroupElement::Scalar>,
            ),
        >,
        presign: &Presign<GroupElement::Value>,
        nonce_shares: &HashMap<
            PartyID,
            (
                group::Value<GroupElement::Scalar>,
                group::Value<GroupElement::Scalar>,
            ),
        >,
        threshold: PartyID,
        message: &[u8],
        hash_scheme: HashScheme,
        hash_context: &HashContext,
        scalar_group_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
        group_params: &GroupElement::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<GroupElement::Signature>
    where
        GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
            + Neg<Output = GroupElement::Scalar>
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
        // Get the party IDs from the secret key shares map
        let party_ids: Vec<PartyID> = party_secret_key_shares.keys().copied().collect();

        // Construct VersionedOutput for functions that need it
        let versioned_output: VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            CiphertextSpaceValue,
        > = VersionedOutput::UniversalPublicDKGOutput {
            output: dkg_output.clone(),
            first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer,
            global_decentralized_party_output_commitment: CommitmentSizedNumber::ZERO,
        };

        // Convert to centralized party's VersionedOutput for sign_with_vss_presign
        let centralized_versioned_output: crate::dkg::centralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
        > = versioned_output.clone().into();

        // Step 1: Centralized party creates partial signature
        let partial_signature = sign_with_vss_presign::<SCALAR_LIMBS, GroupElement>(
            centralized_party_secret_key_share,
            message,
            hash_scheme,
            hash_context,
            &centralized_versioned_output,
            presign,
            scalar_group_public_parameters,
            group_params,
            rng,
        )?;

        // Step 2: Each decentralized party computes their signature share
        let signature_shares: HashMap<PartyID, group::Value<GroupElement::Scalar>> = party_ids
            .iter()
            .map(|&party_id| {
                let (secret_key_share_first, secret_key_share_second) =
                    party_secret_key_shares.get(&party_id).unwrap();
                let (nonce_share_first, nonce_share_second) = nonce_shares.get(&party_id).unwrap();

                let share = compute_signature_share::<SCALAR_LIMBS, GroupElement, _>(
                    presign.session_id,
                    hash_scheme,
                    hash_context,
                    message,
                    dkg_output,
                    first_key_public_randomizer,
                    second_key_public_randomizer,
                    free_coefficient_key_public_randomizer,
                    *secret_key_share_first,
                    *secret_key_share_second,
                    presign
                        .decentralized_party_nonce_public_share_first_part
                        .clone(),
                    presign
                        .decentralized_party_nonce_public_share_second_part
                        .clone(),
                    *nonce_share_first,
                    *nonce_share_second,
                    crate::sign::SignData::Unverified(partial_signature.clone()),
                    group_params,
                    scalar_group_public_parameters,
                )
                .expect("Signature share computation should succeed");

                (party_id, share)
            })
            .collect();

        // Step 3: Reconstruct the signature from shares
        let reconstructed_response = reconstruct_signature::<SCALAR_LIMBS, GroupElement::Scalar>(
            &signature_shares,
            threshold,
            scalar_group_public_parameters,
        )?;

        // Step 4: Verify and output the final signature
        verify_vss_schnorr_signature::<SCALAR_LIMBS, GroupElement, _>(
            reconstructed_response,
            message,
            hash_scheme,
            hash_context,
            &versioned_output,
            presign,
            &partial_signature,
            group_params,
        )
    }

    /// Test helper to verify a VSS Schnorr signature.
    ///
    /// VSS Schnorr requires `UniversalPublicDKGOutput` because the decentralized party's
    /// share is computed as a linear combination using the key randomizers.
    pub fn verify_vss_schnorr_signature<
        const SCALAR_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
        CiphertextSpaceValue,
    >(
        reconstructed_response: group::Value<GroupElement::Scalar>,
        message: &[u8],
        hash_scheme: HashScheme,
        hash_context: &HashContext,
        dkg_output: &VersionedOutput<SCALAR_LIMBS, GroupElement::Value, CiphertextSpaceValue>,
        presign: &Presign<GroupElement::Value>,
        partial_signature: &PartialSignature<
            GroupElement::Value,
            group::Value<GroupElement::Scalar>,
        >,
        group_public_parameters: &GroupElement::PublicParameters,
    ) -> crate::Result<GroupElement::Signature>
    where
        GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
            + std::ops::Mul<Output = GroupElement::Scalar>
            + std::ops::Mul<GroupElement, Output = GroupElement>,
        Uint<SCALAR_LIMBS>: Encoding
            + ConcatMixed<StatisticalSecuritySizedNumber>
            + for<'a> From<
                &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
            >,
    {
        // VSS Schnorr only supports UniversalPublicDKGOutput
        let output = match dkg_output {
            VersionedOutput::UniversalPublicDKGOutput { output, .. } => output,
            VersionedOutput::TargetedPublicDKGOutput(_) => {
                return Err(Error::from(ErrorKind::InvalidParameters));
            }
        };

        let presign_public_randomizer: Uint<SCALAR_LIMBS> =
            derive_presign_public_randomizer::<SCALAR_LIMBS, GroupElement>(
                presign.session_id,
                message,
                hash_scheme,
                presign
                    .decentralized_party_nonce_public_share_first_part
                    .clone(),
                presign
                    .decentralized_party_nonce_public_share_second_part
                    .clone(),
                &partial_signature.public_nonce_share_prenormalization,
                group_public_parameters,
                &output.public_key,
            )?;

        let k_a = GroupElement::new(
            partial_signature
                .public_nonce_share_prenormalization
                .clone(),
            group_public_parameters,
        )?;
        let k_b_first = GroupElement::new(
            presign
                .decentralized_party_nonce_public_share_first_part
                .clone(),
            group_public_parameters,
        )?;
        let k_b_second = GroupElement::new(
            presign
                .decentralized_party_nonce_public_share_second_part
                .clone(),
            group_public_parameters,
        )?;
        let k_b = k_b_first.add_vartime(
            &k_b_second.scale_vartime(&presign_public_randomizer, group_public_parameters),
            group_public_parameters,
        );
        let mut public_nonce = k_a.add_vartime(&k_b, group_public_parameters);

        if !public_nonce.is_taproot_normalized() {
            public_nonce = public_nonce.neg_constant_time(group_public_parameters);
        }

        let signature =
            GroupElement::Signature::try_from((public_nonce.value(), reconstructed_response))?;
        let public_key = GroupElement::new(output.public_key.clone(), group_public_parameters)?;
        public_key.verify(message, hash_scheme, hash_context, &signature)?;

        Ok(signature)
    }

    /// Generates mock keygen outputs for testing (secp256k1-specific).
    ///
    /// Creates secret shares for the decentralized parties that sum to a known
    /// secret key, and corresponding public key shares.
    ///
    /// Returns:
    /// - Centralized party's secret key share (private)
    /// - DKG output (inner Output struct)
    /// - First key public randomizer
    /// - Second key public randomizer
    /// - Free coefficient key public randomizer
    /// - Secret key shares for each party (first_part, second_part)
    #[allow(clippy::type_complexity)]
    pub fn generate_mock_keygen_outputs(
        party_ids: &[PartyID],
        scalar_group_public_parameters: &secp256k1::scalar::PublicParameters,
        group_params: &secp256k1::group_element::PublicParameters,
        rng: &mut impl group::CsRng,
    ) -> (
        group::Value<secp256k1::Scalar>,
        crate::dkg::decentralized_party::Output<group::Value<secp256k1::GroupElement>, ()>,
        Uint<{ secp256k1::SCALAR_LIMBS }>,
        Uint<{ secp256k1::SCALAR_LIMBS }>,
        Uint<{ secp256k1::SCALAR_LIMBS }>,
        HashMap<
            PartyID,
            (
                group::Value<secp256k1::Scalar>,
                group::Value<secp256k1::Scalar>,
            ),
        >,
    ) {
        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(group_params).unwrap();

        // Centralized party's secret key share
        let centralized_party_secret_key_share =
            secp256k1::Scalar::sample(scalar_group_public_parameters, rng).unwrap();
        let centralized_party_public_key_share =
            (centralized_party_secret_key_share * generator).value();

        // First decentralized party's secret polynomial: f_0(x) = x_0 + c_0 * x
        let decentralized_secret_first =
            secp256k1::Scalar::sample(scalar_group_public_parameters, rng).unwrap();
        let secret_first_coefficient =
            secp256k1::Scalar::sample(scalar_group_public_parameters, rng).unwrap();

        // For the second polynomial, we use zero coefficients to simplify the test.
        // This means x_1 = 0 and all x_1 shares are 0, so μ_x blending has no effect.
        let zero = secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::ZERO);

        // Compute shares for each party
        let secret_key_shares = party_ids
            .iter()
            .map(|&party_id| {
                let i = secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(
                    party_id as u64,
                ));
                let secret_share_first = decentralized_secret_first + secret_first_coefficient * i;
                let secret_share_second = zero; // All x_1 shares are 0
                (
                    party_id,
                    (secret_share_first.value(), secret_share_second.value()),
                )
            })
            .collect();

        // Public key shares
        // X_{B,0} = x_0 * G
        let decentralized_public_key_first = (decentralized_secret_first * generator).value();

        // Public key: X = X_A + X_{B,0} + μ_x * X_{B,1} = X_A + X_{B,0} (since X_{B,1} = identity)
        let public_key = (centralized_party_secret_key_share * generator
            + decentralized_secret_first * generator)
            .value();

        // Create decentralized party output
        let output = crate::dkg::decentralized_party::Output {
            public_key_share: decentralized_public_key_first,
            public_key,
            encryption_of_secret_key_share: (),
            centralized_party_public_key_share,
        };

        // For tests, use trivial randomizers: (1, 0, 0) so the formula becomes x_B = 1*x_0 + 0*x_1 + 0
        // This maintains backward compatibility with the simplified test setup where x_1 = 0.
        let first_key_public_randomizer = Uint::<{ secp256k1::SCALAR_LIMBS }>::ONE;
        let second_key_public_randomizer = Uint::<{ secp256k1::SCALAR_LIMBS }>::ZERO;
        let free_coefficient_key_public_randomizer = Uint::<{ secp256k1::SCALAR_LIMBS }>::ZERO;

        (
            centralized_party_secret_key_share.value(),
            output,
            first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer,
            secret_key_shares,
        )
    }

    /// Generates mock presign outputs for testing (secp256k1-specific).
    ///
    /// Returns:
    /// - Presign output (session ID and public nonce shares)
    /// - Secret nonce shares for each party (k_0 share, k_1 share)
    pub fn generate_mock_presign_outputs(
        party_ids: &[PartyID],
        session_id: CommitmentSizedNumber,
        scalar_group_public_parameters: &secp256k1::scalar::PublicParameters,
        group_params: &secp256k1::group_element::PublicParameters,
        rng: &mut impl group::CsRng,
    ) -> (
        Presign<group::Value<secp256k1::GroupElement>>,
        HashMap<
            PartyID,
            (
                group::Value<secp256k1::Scalar>,
                group::Value<secp256k1::Scalar>,
            ),
        >,
    ) {
        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(group_params).unwrap();

        // Nonce k_0: f_0(x) = k_0 + c_0 * x
        let nonce_secret_first =
            secp256k1::Scalar::sample(scalar_group_public_parameters, rng).unwrap();
        let nonce_first_coefficient =
            secp256k1::Scalar::sample(scalar_group_public_parameters, rng).unwrap();

        // Nonce k_1: f_1(x) = k_1 + c_1 * x
        let nonce_secret_second =
            secp256k1::Scalar::sample(scalar_group_public_parameters, rng).unwrap();
        let nonce_second_coefficient =
            secp256k1::Scalar::sample(scalar_group_public_parameters, rng).unwrap();

        // Compute shares for each party
        let nonce_shares = party_ids
            .iter()
            .map(|&party_id| {
                let i = secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(
                    party_id as u64,
                ));
                let nonce_share_first = nonce_secret_first + nonce_first_coefficient * i;
                let nonce_share_second = nonce_secret_second + nonce_second_coefficient * i;
                (
                    party_id,
                    (nonce_share_first.value(), nonce_share_second.value()),
                )
            })
            .collect();

        // Public nonce commitments
        let decentralized_nonce_public_first = (nonce_secret_first * generator).value();
        let decentralized_nonce_public_second = (nonce_secret_second * generator).value();

        let presign = Presign {
            session_id,
            presign_blending_index: 0,
            decentralized_party_nonce_public_share_first_part: decentralized_nonce_public_first,
            decentralized_party_nonce_public_share_second_part: decentralized_nonce_public_second,
        };

        (presign, nonce_shares)
    }

    #[test]
    fn test_full_vss_signing_protocol() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        let threshold: PartyID = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let message = b"Test message for VSS signing";
        let session_id = CommitmentSizedNumber::from(1u64);
        let hash_scheme = HashScheme::SHA256;

        // Generate mock keygen and presign outputs
        let (
            secret_key_share,
            dkg_output,
            first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer,
            party_secret_key_shares,
        ) = generate_mock_keygen_outputs(
            &party_ids,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );
        let (presign, nonce_shares) = generate_mock_presign_outputs(
            &party_ids,
            session_id,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );

        // Call the internal test function with mock data
        let signature =
            test_vss_signing_internal::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, ()>(
                secret_key_share,
                &dkg_output,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                &party_secret_key_shares,
                &presign,
                &nonce_shares,
                threshold,
                message,
                hash_scheme,
                &HashContext::None,
                &scalar_group_public_parameters,
                &group_params,
                &mut rng,
            )
            .expect("Signing should succeed");

        // The signature should be valid (verification is done inside test_vss_signing_internal)
        let sig_bytes: [u8; 64] = signature.to_bytes();
        assert!(
            !sig_bytes.iter().all(|&b| b == 0),
            "Signature should not be all zeros"
        );
    }

    #[test]
    fn test_signing_with_subset_of_parties() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        // All parties participate in keygen/presign
        let all_party_ids: Vec<PartyID> = vec![1, 2, 3, 4, 5];
        // Only a subset participates in signing (threshold = 3)
        let threshold: PartyID = 3;
        let signing_party_ids: Vec<PartyID> = vec![1, 3, 5];
        let message = b"Test message with subset signing";
        let session_id = CommitmentSizedNumber::from(2u64);
        let hash_scheme = HashScheme::SHA256;

        // Generate mock outputs for all parties
        let (
            secret_key_share,
            dkg_output,
            first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer,
            all_party_secret_key_shares,
        ) = generate_mock_keygen_outputs(
            &all_party_ids,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );
        let (presign, all_nonce_shares) = generate_mock_presign_outputs(
            &all_party_ids,
            session_id,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );

        // Filter to only the signing subset
        let signing_party_secret_key_shares: HashMap<_, _> = signing_party_ids
            .iter()
            .map(|&id| (id, *all_party_secret_key_shares.get(&id).unwrap()))
            .collect();
        let signing_nonce_shares: HashMap<_, _> = signing_party_ids
            .iter()
            .map(|&id| (id, *all_nonce_shares.get(&id).unwrap()))
            .collect();

        // Call the internal test function with the subset of parties
        let signature =
            test_vss_signing_internal::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, ()>(
                secret_key_share,
                &dkg_output,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                &signing_party_secret_key_shares,
                &presign,
                &signing_nonce_shares,
                threshold,
                message,
                hash_scheme,
                &HashContext::None,
                &scalar_group_public_parameters,
                &group_params,
                &mut rng,
            )
            .expect("Signing with subset should succeed");

        let sig_bytes: [u8; 64] = signature.to_bytes();
        assert!(
            !sig_bytes.iter().all(|&b| b == 0),
            "Signature should not be all zeros"
        );
    }

    #[test]
    fn test_different_session_ids() {
        // Test that different session IDs produce different signatures
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        let threshold: PartyID = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let message = b"Session ID test message";
        let hash_scheme = HashScheme::SHA256;

        let session_ids = [
            CommitmentSizedNumber::from(10u64),
            CommitmentSizedNumber::from(20u64),
            CommitmentSizedNumber::from(30u64),
        ];

        let signatures: Vec<[u8; 64]> = session_ids
            .into_iter()
            .map(|session_id| {
                let (
                    secret_key_share,
                    dkg_output,
                    first_key_public_randomizer,
                    second_key_public_randomizer,
                    free_coefficient_key_public_randomizer,
                    party_secret_key_shares,
                ) = generate_mock_keygen_outputs(
                    &party_ids,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                );
                let (presign, nonce_shares) = generate_mock_presign_outputs(
                    &party_ids,
                    session_id,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                );

                // Call the internal test function
                let signature = test_vss_signing_internal::<
                    { secp256k1::SCALAR_LIMBS },
                    secp256k1::GroupElement,
                    (),
                >(
                    secret_key_share,
                    &dkg_output,
                    first_key_public_randomizer,
                    second_key_public_randomizer,
                    free_coefficient_key_public_randomizer,
                    &party_secret_key_shares,
                    &presign,
                    &nonce_shares,
                    threshold,
                    message,
                    hash_scheme,
                    &HashContext::None,
                    &scalar_group_public_parameters,
                    &group_params,
                    &mut rng,
                )
                .expect("Signing should succeed");

                signature.to_bytes()
            })
            .collect();

        // Each signature should be different (different keygen/presign outputs)
        assert_ne!(
            signatures[0], signatures[1],
            "Different sessions should produce different signatures"
        );
        assert_ne!(
            signatures[1], signatures[2],
            "Different sessions should produce different signatures"
        );
    }

    #[test]
    fn test_empty_message_signing() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();

        let threshold: PartyID = 3;
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let message = b""; // Empty message
        let session_id = CommitmentSizedNumber::from(100u64);
        let hash_scheme = HashScheme::SHA256;

        let (
            secret_key_share,
            dkg_output,
            first_key_public_randomizer,
            second_key_public_randomizer,
            free_coefficient_key_public_randomizer,
            party_secret_key_shares,
        ) = generate_mock_keygen_outputs(
            &party_ids,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );
        let (presign, nonce_shares) = generate_mock_presign_outputs(
            &party_ids,
            session_id,
            &scalar_group_public_parameters,
            &group_params,
            &mut rng,
        );

        // Call the internal test function with empty message
        let signature =
            test_vss_signing_internal::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, ()>(
                secret_key_share,
                &dkg_output,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                &party_secret_key_shares,
                &presign,
                &nonce_shares,
                threshold,
                message,
                hash_scheme,
                &HashContext::None,
                &scalar_group_public_parameters,
                &group_params,
                &mut rng,
            )
            .expect("Empty message signing should succeed");

        let sig_bytes: [u8; 64] = signature.to_bytes();
        assert!(
            !sig_bytes.iter().all(|&b| b == 0),
            "Signature should not be all zeros"
        );
    }

    /// Tests that malicious signature shares are detected via polynomial commitment verification.
    ///
    /// This test validates that the secret key polynomial commitments are computed correctly by:
    /// 1. Creating valid secret key shares and their polynomial commitments
    /// 2. Computing valid signature shares for honest parties
    /// 3. Computing an INVALID signature share for a malicious party
    /// 4. Verifying that `verify_signature_share`:
    ///    - PASSES for honest parties (proving commitments are correct)
    ///    - FAILS for the malicious party (proving the verification works)
    #[test]
    fn malicious_sign_share_is_detected_via_polynomial_commitments() {
        let mut rng = OsCsRng;
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_params = secp256k1::group_element::PublicParameters::default();
        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_params).unwrap();

        // Setup: threshold=2, 3 parties
        let party_ids: Vec<PartyID> = vec![1, 2, 3];
        let malicious_party_id: PartyID = 3;

        // Step 1: Create secret key polynomial f(x) = s_0 + s_1*x
        // where s_0 is the secret key and s(i) = s_0 + s_1*i is party i's share
        let secret_key =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let secret_key_coefficient =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // Compute secret key shares for each party: [x]_i = s_0 + s_1 * i
        let secret_key_shares: HashMap<PartyID, secp256k1::Scalar> = party_ids
            .iter()
            .map(|&party_id| {
                let i = secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(
                    party_id as u64,
                ));
                let share = secret_key + secret_key_coefficient * i;
                (party_id, share)
            })
            .collect();

        // Secret key polynomial commitments: S_0 = s_0 * G, S_1 = s_1 * G
        let secret_key_polynomial_commitments = [
            (secret_key * generator).value(),
            (secret_key_coefficient * generator).value(),
        ];

        // Verify polynomial commitment evaluation matches share commitment for each party
        // This validates that evaluate_polynomial_commitment works correctly
        for &party_id in &party_ids {
            let expected_share_commitment =
                (*secret_key_shares.get(&party_id).unwrap() * generator).value();

            let commitments: Vec<secp256k1::GroupElement> = secret_key_polynomial_commitments
                .iter()
                .map(|&c| secp256k1::GroupElement::new(c, &group_params).unwrap())
                .collect();

            let evaluated_commitment = evaluate_polynomial_commitment::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
            >(commitments, party_id, &group_params)
            .unwrap();

            assert_eq!(
                expected_share_commitment,
                evaluated_commitment.value(),
                "Polynomial commitment evaluation should match share commitment for party {party_id}"
            );
        }

        // Step 2: Create nonce polynomial k(x) = k_0 + k_1*x
        let nonce_secret =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();
        let nonce_coefficient =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // Compute nonce shares for each party: [k]_i = k_0 + k_1 * i
        let nonce_shares: HashMap<PartyID, secp256k1::Scalar> = party_ids
            .iter()
            .map(|&party_id| {
                let i = secp256k1::Scalar::from(Uint::<{ secp256k1::SCALAR_LIMBS }>::from(
                    party_id as u64,
                ));
                let share = nonce_secret + nonce_coefficient * i;
                (party_id, share)
            })
            .collect();

        // Nonce polynomial commitments: K_0 = k_0 * G, K_1 = k_1 * G
        let nonce_polynomial_commitments = [
            (nonce_secret * generator).value(),
            (nonce_coefficient * generator).value(),
        ];

        // Step 3: Compute the challenge (simplified - in real protocol this is from hash)
        let challenge =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // For this simplified test, use trivial key randomizers (1, 0, 0)
        // This means the combined secret key share is just the first share
        let first_key_public_randomizer = Uint::<{ secp256k1::SCALAR_LIMBS }>::ONE;
        let second_key_public_randomizer = Uint::<{ secp256k1::SCALAR_LIMBS }>::ZERO;
        let free_coefficient_key_public_randomizer = Uint::<{ secp256k1::SCALAR_LIMBS }>::ZERO;
        let presign_public_randomizer = Uint::<{ secp256k1::SCALAR_LIMBS }>::ONE;

        // Centralized party partial response (simplified)
        let centralized_partial_response =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // Step 4: Compute signature shares
        // Formula: σ_i = [k]_i + e * [x]_i + z_A
        // (With trivial randomizers, nonce and key are just the first part)
        let signature_shares: HashMap<PartyID, secp256k1::Scalar> = party_ids
            .iter()
            .map(|&party_id| {
                let nonce_share = *nonce_shares.get(&party_id).unwrap();
                let secret_key_share = *secret_key_shares.get(&party_id).unwrap();
                let share =
                    nonce_share + challenge * secret_key_share + centralized_partial_response;
                (party_id, share)
            })
            .collect();

        // Step 5: Verify that verify_signature_share PASSES for honest parties
        let nonce_commitments: Vec<secp256k1::GroupElement> = nonce_polynomial_commitments
            .iter()
            .map(|&c| secp256k1::GroupElement::new(c, &group_params).unwrap())
            .collect();
        let secret_key_commitments: Vec<secp256k1::GroupElement> =
            secret_key_polynomial_commitments
                .iter()
                .map(|&c| secp256k1::GroupElement::new(c, &group_params).unwrap())
                .collect();

        // For simplicity, use same commitments for both first and second (second not used with zero randomizer)
        let empty_second_commitments: Vec<secp256k1::GroupElement> = vec![
            secp256k1::GroupElement::neutral_from_public_parameters(&group_params).unwrap(),
            secp256k1::GroupElement::neutral_from_public_parameters(&group_params).unwrap(),
        ];

        for &party_id in &[1, 2] {
            // Honest parties
            let result =
                verify_signature_share::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                    party_id,
                    signature_shares.get(&party_id).unwrap().value(),
                    nonce_commitments.clone(),
                    empty_second_commitments.clone(),
                    secret_key_commitments.clone(),
                    empty_second_commitments.clone(),
                    presign_public_randomizer,
                    first_key_public_randomizer,
                    second_key_public_randomizer,
                    free_coefficient_key_public_randomizer,
                    challenge,
                    centralized_partial_response.value(),
                    false, // nonce_normalized
                    false, // key_normalized
                    &scalar_group_public_parameters,
                    &group_params,
                );

            assert!(
                result.is_ok(),
                "Signature share verification should PASS for honest party {party_id}"
            );
        }

        // Step 6: Create a MALICIOUS signature share (wrong value)
        let malicious_share =
            secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut rng).unwrap();

        // Step 7: Verify that verify_signature_share FAILS for the malicious party
        let malicious_result =
            verify_signature_share::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                malicious_party_id,
                malicious_share.value(),
                nonce_commitments.clone(),
                empty_second_commitments.clone(),
                secret_key_commitments.clone(),
                empty_second_commitments.clone(),
                presign_public_randomizer,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                challenge,
                centralized_partial_response.value(),
                false, // nonce_normalized
                false, // key_normalized
                &scalar_group_public_parameters,
                &group_params,
            );

        assert!(
            malicious_result.is_err(),
            "Signature share verification should FAIL for malicious party {malicious_party_id}"
        );

        // Step 8: Also verify that the CORRECT share from party 3 passes
        // (to confirm the commitments are correct, not that verification always fails)
        let honest_party_three_result =
            verify_signature_share::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                malicious_party_id,
                signature_shares.get(&malicious_party_id).unwrap().value(),
                nonce_commitments,
                empty_second_commitments.clone(),
                secret_key_commitments,
                empty_second_commitments,
                presign_public_randomizer,
                first_key_public_randomizer,
                second_key_public_randomizer,
                free_coefficient_key_public_randomizer,
                challenge,
                centralized_partial_response.value(),
                false, // nonce_normalized
                false, // key_normalized
                &scalar_group_public_parameters,
                &group_params,
            );

        assert!(
            honest_party_three_result.is_ok(),
            "Signature share verification should PASS for party 3 when using correct share"
        );
    }
}
