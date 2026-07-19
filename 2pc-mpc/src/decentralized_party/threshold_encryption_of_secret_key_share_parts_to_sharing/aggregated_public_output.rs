// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! The primary (aggregated) threshold encryption to sharing `PublicOutput`.
//!
//! The protocol's public output persists every honest dealer's full PVSS dealing — per-receiver
//! class-group ciphertext + EncDL proof per (curve, key-share part), plus per-dealer polynomial
//! commitments — which is O(n²) class-group material. The proofs are only consumed in-protocol
//! (public verification + the malicious-dealer majority vote); nothing needs them afterwards.
//! Since all dealers encrypt receiver i's share under i's single PVSS encryption key and Shamir
//! sharings add coefficient-wise, [`super::NonAggregatedPublicOutput::upgrade`] homomorphically sums each
//! receiver's encrypted shares across the dealers into one ciphertext per (curve, key-share
//! part): $\textsf{ct}_i$ encrypts $[r]_i = \sum_j [r_j]_i$. The aggregated output is O(n), and
//! share derivation from it needs a single class-group decryption instead of n.
//!
//! The protocol's rounds still form [`super::NonAggregatedPublicOutput`] (the pre-aggregation
//! shape, kept for backward compatibility only — it is the deployed wire format the gated
//! reconfiguration rollout must keep emitting byte-identically); this aggregated form is the
//! primary type consumers use, reached via `upgrade()`. bcs rejects trailing or missing bytes,
//! so parsing bytes of one format as the other fails — consumers can discriminate the two
//! formats by trying one and falling back to the other.

use std::collections::HashMap;

use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    CiphertextSpaceValue, RistrettoSetupParameters, Secp256k1SetupParameters,
    Secp256r1SetupParameters, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use group::{curve25519, ristretto, secp256k1, secp256r1, PartyID};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Public output from the threshold encryption to sharing protocol, in the aggregated form.
///
/// Contains all public data needed for parties to compute their Shamir shares.
/// Stores, per receiving party, the homomorphically aggregated encryption of its randomizer
/// share (summed across all honest dealers' verified PVSS dealings) and the masked secrets
/// (x + r), allowing parties to decrypt their shares individually later. The per-dealer
/// dealings and their proofs served public verification in-protocol and are not retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicOutput {
    /// Public key share commitment for secp256k1 (first secret).
    pub secp256k1_first_public_key_share: secp256k1::group_element::Value,
    /// Public key share commitment for secp256k1 (second secret).
    pub secp256k1_second_public_key_share: secp256k1::group_element::Value,
    /// Secret key polynomial commitments for secp256k1 first secret (for Shamir share verification).
    pub secp256k1_first_secret_polynomial_commitments: Vec<secp256k1::group_element::Value>,
    /// Secret key polynomial commitments for secp256k1 second secret (for Shamir share verification).
    pub secp256k1_second_secret_polynomial_commitments: Vec<secp256k1::group_element::Value>,

    /// Public key share commitment for ristretto (first secret).
    pub ristretto_first_public_key_share: group::Value<ristretto::GroupElement>,
    /// Public key share commitment for ristretto (second secret).
    pub ristretto_second_public_key_share: group::Value<ristretto::GroupElement>,
    /// Secret key polynomial commitments for ristretto first secret (for Shamir share verification).
    pub ristretto_first_secret_polynomial_commitments: Vec<group::Value<ristretto::GroupElement>>,
    /// Secret key polynomial commitments for ristretto second secret (for Shamir share verification).
    pub ristretto_second_secret_polynomial_commitments: Vec<group::Value<ristretto::GroupElement>>,

    /// Public key share commitment for curve25519 (first secret).
    pub curve25519_first_public_key_share: group::Value<curve25519::GroupElement>,
    /// Public key share commitment for curve25519 (second secret).
    pub curve25519_second_public_key_share: group::Value<curve25519::GroupElement>,
    /// Secret key polynomial commitments for curve25519 first secret (for Shamir share verification).
    pub curve25519_first_secret_polynomial_commitments: Vec<group::Value<curve25519::GroupElement>>,
    /// Secret key polynomial commitments for curve25519 second secret (for Shamir share verification).
    pub curve25519_second_secret_polynomial_commitments:
        Vec<group::Value<curve25519::GroupElement>>,

    /// Public key share commitment for secp256r1 (first secret).
    pub secp256r1_first_public_key_share: secp256r1::group_element::Value,
    /// Public key share commitment for secp256r1 (second secret).
    pub secp256r1_second_public_key_share: secp256r1::group_element::Value,
    /// Secret key polynomial commitments for secp256r1 first secret (for Shamir share verification).
    pub secp256r1_first_secret_polynomial_commitments: Vec<secp256r1::group_element::Value>,
    /// Secret key polynomial commitments for secp256r1 second secret (for Shamir share verification).
    pub secp256r1_second_secret_polynomial_commitments: Vec<secp256r1::group_element::Value>,

    // ==================== Aggregated Encrypted Randomizer Shares ====================
    // Per receiving party, the homomorphic sum of the encrypted randomizer shares dealt to it by
    // all honest dealers: $\textsf{ct}_i$ encrypts $[r]_i = \sum_j [r_j]_i$ under party $i$'s
    // PVSS encryption key, so each party recovers its randomizer share with a single decryption.
    /// Aggregated encryptions of randomizer shares for secp256k1 (first secret).
    pub secp256k1_first_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    /// Aggregated encryptions of randomizer shares for secp256k1 (second secret).
    pub secp256k1_second_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    /// Aggregated encryptions of randomizer shares for ristretto (first secret).
    pub ristretto_first_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    /// Aggregated encryptions of randomizer shares for ristretto (second secret).
    pub ristretto_second_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    /// Aggregated encryptions of randomizer shares for curve25519 (first secret).
    pub curve25519_first_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    /// Aggregated encryptions of randomizer shares for curve25519 (second secret).
    pub curve25519_second_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    /// Aggregated encryptions of randomizer shares for secp256r1 (first secret).
    pub secp256r1_first_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    /// Aggregated encryptions of randomizer shares for secp256r1 (second secret).
    pub secp256r1_second_encryptions_of_randomizer_shares:
        HashMap<PartyID, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    // ==================== Masked Secrets (x + r) ====================
    // These are recovered via threshold decryption and are safe to store publicly
    // since the randomizer r masks the secret key x.
    // To compute the final Shamir share: [x]_i = (x + r) - [r]_i
    /// Masked secret (x + r) for secp256k1 first secret.
    pub secp256k1_first_masked_secret_key_share_part: group::Value<secp256k1::Scalar>,
    /// Masked secret (x + r) for secp256k1 second secret.
    pub secp256k1_second_masked_secret_key_share_part: group::Value<secp256k1::Scalar>,
    /// Masked secret (x + r) for ristretto first secret.
    pub ristretto_first_masked_secret_key_share_part: group::Value<ristretto::Scalar>,
    /// Masked secret (x + r) for ristretto second secret.
    pub ristretto_second_masked_secret_key_share_part: group::Value<ristretto::Scalar>,
    /// Masked secret (x + r) for curve25519 first secret.
    pub curve25519_first_masked_secret_key_share_part: group::Value<curve25519::Scalar>,
    /// Masked secret (x + r) for curve25519 second secret.
    pub curve25519_second_masked_secret_key_share_part: group::Value<curve25519::Scalar>,
    /// Masked secret (x + r) for secp256r1 first secret.
    pub secp256r1_first_masked_secret_key_share_part: group::Value<secp256r1::Scalar>,
    /// Masked secret (x + r) for secp256r1 second secret.
    pub secp256r1_second_masked_secret_key_share_part: group::Value<secp256r1::Scalar>,
}

impl super::NonAggregatedPublicOutput {
    /// Upgrades to the aggregated [`PublicOutput`] by homomorphically aggregating, per
    /// receiving party, the encrypted randomizer shares across the persisted dealings — which
    /// are honest-only by construction: malicious dealers were excluded by the in-protocol
    /// majority vote before this output was formed.
    pub fn upgrade(self) -> Result<PublicOutput> {
        let secp256k1_setup_parameters =
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;
        let ristretto_setup_parameters =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;
        let secp256r1_setup_parameters =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let (secp256k1_first_dealings, secp256k1_second_dealings): (HashMap<_, _>, HashMap<_, _>) =
            self.secp256k1_randomizer_dealings
                .into_iter()
                .map(|(dealer_party_id, curve_dealing)| {
                    (
                        (
                            dealer_party_id,
                            curve_dealing.first_randomizer_contribution_dealing,
                        ),
                        (
                            dealer_party_id,
                            curve_dealing.second_randomizer_contribution_dealing,
                        ),
                    )
                })
                .unzip();

        let (ristretto_first_dealings, ristretto_second_dealings): (HashMap<_, _>, HashMap<_, _>) =
            self.ristretto_randomizer_dealings
                .into_iter()
                .map(|(dealer_party_id, curve_dealing)| {
                    (
                        (
                            dealer_party_id,
                            curve_dealing.first_randomizer_contribution_dealing,
                        ),
                        (
                            dealer_party_id,
                            curve_dealing.second_randomizer_contribution_dealing,
                        ),
                    )
                })
                .unzip();

        let (curve25519_first_dealings, curve25519_second_dealings): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = self
            .curve25519_randomizer_dealings
            .into_iter()
            .map(|(dealer_party_id, curve_dealing)| {
                (
                    (
                        dealer_party_id,
                        curve_dealing.first_randomizer_contribution_dealing,
                    ),
                    (
                        dealer_party_id,
                        curve_dealing.second_randomizer_contribution_dealing,
                    ),
                )
            })
            .unzip();

        let (secp256r1_first_dealings, secp256r1_second_dealings): (HashMap<_, _>, HashMap<_, _>) =
            self.secp256r1_randomizer_dealings
                .into_iter()
                .map(|(dealer_party_id, curve_dealing)| {
                    (
                        (
                            dealer_party_id,
                            curve_dealing.first_randomizer_contribution_dealing,
                        ),
                        (
                            dealer_party_id,
                            curve_dealing.second_randomizer_contribution_dealing,
                        ),
                    )
                })
                .unzip();

        let secp256k1_first_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &secp256k1_first_dealings,
                secp256k1_setup_parameters.ciphertext_space_public_parameters(),
            )?;
        let secp256k1_second_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &secp256k1_second_dealings,
                secp256k1_setup_parameters.ciphertext_space_public_parameters(),
            )?;
        let ristretto_first_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &ristretto_first_dealings,
                ristretto_setup_parameters.ciphertext_space_public_parameters(),
            )?;
        let ristretto_second_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &ristretto_second_dealings,
                ristretto_setup_parameters.ciphertext_space_public_parameters(),
            )?;
        // Curve25519 uses the ristretto encryption scheme (same scalar field).
        let curve25519_first_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &curve25519_first_dealings,
                ristretto_setup_parameters.ciphertext_space_public_parameters(),
            )?;
        let curve25519_second_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &curve25519_second_dealings,
                ristretto_setup_parameters.ciphertext_space_public_parameters(),
            )?;
        let secp256r1_first_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &secp256r1_first_dealings,
                secp256r1_setup_parameters.ciphertext_space_public_parameters(),
            )?;
        let secp256r1_second_encryptions_of_randomizer_shares =
            class_groups::threshold_encryption_to_sharing::aggregate_encryptions_of_randomizer_shares(
                &secp256r1_second_dealings,
                secp256r1_setup_parameters.ciphertext_space_public_parameters(),
            )?;

        Ok(PublicOutput {
            secp256k1_first_public_key_share: self.secp256k1_first_public_key_share,
            secp256k1_second_public_key_share: self.secp256k1_second_public_key_share,
            secp256k1_first_secret_polynomial_commitments: self
                .secp256k1_first_secret_polynomial_commitments,
            secp256k1_second_secret_polynomial_commitments: self
                .secp256k1_second_secret_polynomial_commitments,
            ristretto_first_public_key_share: self.ristretto_first_public_key_share,
            ristretto_second_public_key_share: self.ristretto_second_public_key_share,
            ristretto_first_secret_polynomial_commitments: self
                .ristretto_first_secret_polynomial_commitments,
            ristretto_second_secret_polynomial_commitments: self
                .ristretto_second_secret_polynomial_commitments,
            curve25519_first_public_key_share: self.curve25519_first_public_key_share,
            curve25519_second_public_key_share: self.curve25519_second_public_key_share,
            curve25519_first_secret_polynomial_commitments: self
                .curve25519_first_secret_polynomial_commitments,
            curve25519_second_secret_polynomial_commitments: self
                .curve25519_second_secret_polynomial_commitments,
            secp256r1_first_public_key_share: self.secp256r1_first_public_key_share,
            secp256r1_second_public_key_share: self.secp256r1_second_public_key_share,
            secp256r1_first_secret_polynomial_commitments: self
                .secp256r1_first_secret_polynomial_commitments,
            secp256r1_second_secret_polynomial_commitments: self
                .secp256r1_second_secret_polynomial_commitments,
            secp256k1_first_encryptions_of_randomizer_shares,
            secp256k1_second_encryptions_of_randomizer_shares,
            ristretto_first_encryptions_of_randomizer_shares,
            ristretto_second_encryptions_of_randomizer_shares,
            curve25519_first_encryptions_of_randomizer_shares,
            curve25519_second_encryptions_of_randomizer_shares,
            secp256r1_first_encryptions_of_randomizer_shares,
            secp256r1_second_encryptions_of_randomizer_shares,
            secp256k1_first_masked_secret_key_share_part: self
                .secp256k1_first_masked_secret_key_share_part,
            secp256k1_second_masked_secret_key_share_part: self
                .secp256k1_second_masked_secret_key_share_part,
            ristretto_first_masked_secret_key_share_part: self
                .ristretto_first_masked_secret_key_share_part,
            ristretto_second_masked_secret_key_share_part: self
                .ristretto_second_masked_secret_key_share_part,
            curve25519_first_masked_secret_key_share_part: self
                .curve25519_first_masked_secret_key_share_part,
            curve25519_second_masked_secret_key_share_part: self
                .curve25519_second_masked_secret_key_share_part,
            secp256r1_first_masked_secret_key_share_part: self
                .secp256r1_first_masked_secret_key_share_part,
            secp256r1_second_masked_secret_key_share_part: self
                .secp256r1_second_masked_secret_key_share_part,
        })
    }
}

/// Generic function to compute Shamir shares of secret key share parts for any curve, from the
/// aggregated form of the public output.
///
/// Delegates to the subprotocol's `derive_shamir_share_of_secret_from_aggregated_encryption` for
/// each secret, looking up this party's aggregated encrypted randomizer share per secret.
///
/// A party with no aggregated entry received no dealt shares — the same situation the
/// pre-aggregation derivation treats as a neutral randomizer (its per-dealing lookup finds
/// nothing to sum), so the share is the masked secret itself. Mirroring that here keeps
/// derivation semantics identical across [`super::PublicOutput`] and its upgrade.
///
/// Callers parameterize by curve via const generics and pass the curve-specific
/// fields (aggregated encryptions of randomizer shares, masked secrets) from
/// [`PublicOutput`].
pub fn derive_shamir_shares_of_secret_key_share_parts_from_aggregated_encryptions<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: group::PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    party_id: PartyID,
    encryption_scheme_public_parameters: &class_groups::encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    pvss_decryption_key: crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    first_encryptions_of_randomizer_shares: &HashMap<
        PartyID,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    second_encryptions_of_randomizer_shares: &HashMap<
        PartyID,
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    first_masked_secret_key_share_part_value: group::Value<GroupElement::Scalar>,
    second_masked_secret_key_share_part_value: group::Value<GroupElement::Scalar>,
) -> Result<(
    group::Value<GroupElement::Scalar>,
    group::Value<GroupElement::Scalar>,
)>
where
    crypto_bigint::Int<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<SCALAR_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    crypto_bigint::Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: crypto_bigint::Encoding,
    class_groups::EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        group::GroupElement<
                Value = class_groups::CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                PublicParameters = class_groups::equivalence_class::PublicParameters<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            > + class_groups::equivalence_class::EquivalenceClassOps<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MultiFoldNupowAccelerator = class_groups::MultiFoldNupowAccelerator<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
    class_groups::EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = class_groups::encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = class_groups::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = class_groups::CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    class_groups::encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                class_groups::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + class_groups::encryption_key::public_parameters::Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    class_groups::DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: homomorphic_encryption::AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        class_groups::EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = crypto_bigint::Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let first_share = match first_encryptions_of_randomizer_shares.get(&party_id) {
        Some(first_encryption_of_randomizer_share) => {
            class_groups::threshold_encryption_to_sharing::derive_shamir_share_of_secret_from_aggregated_encryption::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >(
                encryption_scheme_public_parameters,
                pvss_decryption_key,
                *first_encryption_of_randomizer_share,
                first_masked_secret_key_share_part_value,
            )?
        }
        None => first_masked_secret_key_share_part_value,
    };

    let second_share = match second_encryptions_of_randomizer_shares.get(&party_id) {
        Some(second_encryption_of_randomizer_share) => {
            class_groups::threshold_encryption_to_sharing::derive_shamir_share_of_secret_from_aggregated_encryption::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >(
                encryption_scheme_public_parameters,
                pvss_decryption_key,
                *second_encryption_of_randomizer_share,
                second_masked_secret_key_share_part_value,
            )?
        }
        None => second_masked_secret_key_share_part_value,
    };

    Ok((first_share, second_share))
}

#[cfg(test)]
mod tests {
    use group::GroupElement as _;

    use super::super::NonAggregatedPublicOutput;
    use super::*;

    /// A structurally-valid all-neutral/empty pre-aggregation sharing output.
    fn neutral_public_output() -> NonAggregatedPublicOutput {
        let secp256k1_point = secp256k1::GroupElement::neutral_from_public_parameters(
            &secp256k1::group_element::PublicParameters::default(),
        )
        .unwrap()
        .value();
        let secp256r1_point = secp256r1::GroupElement::neutral_from_public_parameters(
            &secp256r1::group_element::PublicParameters::default(),
        )
        .unwrap()
        .value();
        let ristretto_point = ristretto::GroupElement::neutral_from_public_parameters(
            &ristretto::group_element::PublicParameters::default(),
        )
        .unwrap()
        .value();
        let curve25519_point = curve25519::GroupElement::neutral_from_public_parameters(
            &curve25519::PublicParameters::default(),
        )
        .unwrap()
        .value();

        let secp256k1_scalar = secp256k1::Scalar::neutral_from_public_parameters(
            &secp256k1::scalar::PublicParameters::default(),
        )
        .unwrap()
        .value();
        let secp256r1_scalar = secp256r1::Scalar::neutral_from_public_parameters(
            &secp256r1::scalar::PublicParameters::default(),
        )
        .unwrap()
        .value();
        let ristretto_scalar = ristretto::Scalar::neutral_from_public_parameters(
            &ristretto::scalar::PublicParameters::default(),
        )
        .unwrap()
        .value();
        let curve25519_scalar = curve25519::Scalar::neutral_from_public_parameters(
            &curve25519::scalar::PublicParameters::default(),
        )
        .unwrap()
        .value();

        NonAggregatedPublicOutput {
            secp256k1_first_public_key_share: secp256k1_point,
            secp256k1_second_public_key_share: secp256k1_point,
            secp256k1_first_secret_polynomial_commitments: vec![],
            secp256k1_second_secret_polynomial_commitments: vec![],
            ristretto_first_public_key_share: ristretto_point,
            ristretto_second_public_key_share: ristretto_point,
            ristretto_first_secret_polynomial_commitments: vec![],
            ristretto_second_secret_polynomial_commitments: vec![],
            curve25519_first_public_key_share: curve25519_point,
            curve25519_second_public_key_share: curve25519_point,
            curve25519_first_secret_polynomial_commitments: vec![],
            curve25519_second_secret_polynomial_commitments: vec![],
            secp256r1_first_public_key_share: secp256r1_point,
            secp256r1_second_public_key_share: secp256r1_point,
            secp256r1_first_secret_polynomial_commitments: vec![],
            secp256r1_second_secret_polynomial_commitments: vec![],
            secp256k1_randomizer_dealings: HashMap::new(),
            ristretto_randomizer_dealings: HashMap::new(),
            curve25519_randomizer_dealings: HashMap::new(),
            secp256r1_randomizer_dealings: HashMap::new(),
            secp256k1_first_masked_secret_key_share_part: secp256k1_scalar,
            secp256k1_second_masked_secret_key_share_part: secp256k1_scalar,
            ristretto_first_masked_secret_key_share_part: ristretto_scalar,
            ristretto_second_masked_secret_key_share_part: ristretto_scalar,
            curve25519_first_masked_secret_key_share_part: curve25519_scalar,
            curve25519_second_masked_secret_key_share_part: curve25519_scalar,
            secp256r1_first_masked_secret_key_share_part: secp256r1_scalar,
            secp256r1_second_masked_secret_key_share_part: secp256r1_scalar,
        }
    }

    #[test]
    fn upgrades_pre_aggregation_output_and_formats_reject_each_others_bytes() {
        let pre_aggregation_output = neutral_public_output();

        let pre_aggregation_bytes = bcs::to_bytes(&pre_aggregation_output).unwrap();
        let deserialized: NonAggregatedPublicOutput =
            bcs::from_bytes(&pre_aggregation_bytes).unwrap();
        assert_eq!(pre_aggregation_output, deserialized);

        let upgraded = deserialized.upgrade().unwrap();
        assert!(upgraded
            .secp256k1_first_encryptions_of_randomizer_shares
            .is_empty());
        assert_eq!(
            upgraded.secp256k1_first_masked_secret_key_share_part,
            pre_aggregation_output.secp256k1_first_masked_secret_key_share_part
        );
        assert_eq!(
            upgraded.secp256k1_first_public_key_share,
            pre_aggregation_output.secp256k1_first_public_key_share
        );

        // The formats must reject each other's bytes, so consumers can discriminate by trying
        // one format and falling back to the other.
        let aggregated_bytes = bcs::to_bytes(&upgraded).unwrap();
        assert!(bcs::from_bytes::<NonAggregatedPublicOutput>(&aggregated_bytes).is_err());
        assert!(bcs::from_bytes::<PublicOutput>(&pre_aggregation_bytes).is_err());
    }
}
