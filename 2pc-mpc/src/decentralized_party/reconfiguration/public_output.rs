// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::Uint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    encryption_key,
    publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    },
    CiphertextSpaceValue, CompactIbqf, Curve25519DecryptionKeySharePublicParameters,
    Curve25519EncryptionSchemePublicParameters, Curve25519SetupParameters, EquivalenceClass,
    RistrettoDecryptionKeySharePublicParameters, RistrettoEncryptionSchemePublicParameters,
    RistrettoSetupParameters, Secp256k1DecryptionKeySharePublicParameters,
    Secp256k1EncryptionSchemePublicParameters, Secp256k1SetupParameters,
    Secp256r1DecryptionKeySharePublicParameters, Secp256r1EncryptionSchemePublicParameters,
    Secp256r1SetupParameters, SecretKeyShareSizedInteger, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use group::secp256k1::SCALAR_LIMBS;
use group::{curve25519, ristretto, secp256k1, secp256r1, GroupElement, PartyID};
use mpc::WeightedThresholdAccessStructure;

use crate::{decentralized_party::dkg, Result};

/// The Reconfiguration public output without the Shamir sharing of the secret key share
/// parts.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicOutputCore {
    pub(crate) secp256k1_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256k1_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256k1_public_key_share_first_part: secp256k1::group_element::Value,
    pub(crate) secp256k1_public_key_share_second_part: secp256k1::group_element::Value,
    secp256k1_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    secp256k1_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    pub(crate) ristretto_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) ristretto_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) ristretto_public_key_share_first_part: ristretto::GroupElement,
    pub(crate) ristretto_public_key_share_second_part: ristretto::GroupElement,
    ristretto_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ristretto_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    pub(crate) curve25519_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) curve25519_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub curve25519_public_key_share_first_part: curve25519::Value,
    pub curve25519_public_key_share_second_part: curve25519::Value,

    pub(crate) secp256r1_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256r1_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256r1_public_key_share_first_part: secp256r1::group_element::Value,
    pub(crate) secp256r1_public_key_share_second_part: secp256r1::group_element::Value,
    secp256r1_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    secp256r1_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    masked_decryption_key_by_n_factorial: SecretKeyShareSizedInteger,
    encryptions_of_randomizer_shares_per_crt_prime: HashMap<
        PartyID,
        [CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; NUM_SECRET_SHARE_PRIMES],
    >,
}

impl PublicOutputCore {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        inner_protocol_public_output: class_groups::reconfiguration::PublicOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256k1_encryption_of_secret_key_share_first_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256k1_encryption_of_secret_key_share_second_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256k1_public_key_share_first_part: secp256k1::group_element::Value,
        secp256k1_public_key_share_second_part: secp256k1::group_element::Value,
        ristretto_encryption_of_secret_key_share_first_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        ristretto_encryption_of_secret_key_share_second_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        ristretto_public_key_share_first_part: ristretto::GroupElement,
        ristretto_public_key_share_second_part: ristretto::GroupElement,
        ristretto_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ristretto_reconstructed_commitments_to_randomizer_contribution_sharing: HashMap<
            PartyID,
            HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        curve25519_encryption_of_secret_key_share_first_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        curve25519_encryption_of_secret_key_share_second_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        curve25519_public_key_share_first_part: curve25519::Value,
        curve25519_public_key_share_second_part: curve25519::Value,
        secp256r1_encryption_of_secret_key_share_first_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256r1_encryption_of_secret_key_share_second_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256r1_public_key_share_first_part: secp256r1::group_element::Value,
        secp256r1_public_key_share_second_part: secp256r1::group_element::Value,
        secp256r1_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing: HashMap<
            PartyID,
            HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        ristretto_public_verification_key_base: EquivalenceClass<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256r1_public_verification_key_base: EquivalenceClass<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        equivalence_class_public_parameters: &class_groups::equivalence_class::PublicParameters<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> Result<Self> {
        let masked_decryption_key_by_n_factorial =
            inner_protocol_public_output.masked_decryption_key_by_n_factorial;
        let encryptions_of_randomizer_shares_per_crt_prime =
            inner_protocol_public_output.encryptions_of_randomizer_shares_per_crt_prime;

        let secp256k1_encryption_key = inner_protocol_public_output.encryption_key;
        let secp256k1_public_verification_keys =
            inner_protocol_public_output.public_verification_keys;

        let ristretto_public_verification_keys =
            ::class_groups::reconfiguration::PublicOutput::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::compute_public_verification_keys::<ristretto::GroupElement>(
                upcoming_access_structure,
                masked_decryption_key_by_n_factorial,
                ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
                ristretto_public_verification_key_base,
                equivalence_class_public_parameters,
            );

        let secp256r1_public_verification_keys =
            ::class_groups::reconfiguration::PublicOutput::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::compute_public_verification_keys::<secp256r1::GroupElement>(
                upcoming_access_structure,
                masked_decryption_key_by_n_factorial,
                secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
                secp256r1_public_verification_key_base,
                equivalence_class_public_parameters,
            );

        Ok(Self {
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            secp256k1_encryption_key,
            secp256k1_public_verification_keys,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            ristretto_encryption_key,
            ristretto_public_verification_keys,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
            secp256r1_encryption_key,
            secp256r1_public_verification_keys,
            masked_decryption_key_by_n_factorial,
            encryptions_of_randomizer_shares_per_crt_prime,
        })
    }

    pub fn secp256k1_encryption_scheme_public_parameters(
        &self,
    ) -> Result<Secp256k1EncryptionSchemePublicParameters> {
        let mut setup_parameters =
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<secp256k1::scalar::PublicParameters>(
            &mut setup_parameters,
            self.secp256k1_encryption_of_secret_key_share_first_part,
        )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<secp256k1::scalar::PublicParameters>(
            &mut setup_parameters,
            self.secp256k1_encryption_of_secret_key_share_second_part,
        )?;

        let encryption_key = EquivalenceClass::new(
            self.secp256k1_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new_maximally_accelerated(
                setup_parameters.clone(),
                encryption_key,
            )?;

        Ok(encryption_scheme_public_parameters)
    }

    pub fn secp256k1_decryption_key_share_public_parameters(
        &self,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<Secp256k1DecryptionKeySharePublicParameters> {
        let encryption_scheme_public_parameters =
            self.secp256k1_encryption_scheme_public_parameters()?;

        let decryption_key_share_public_parameters =
            Secp256k1DecryptionKeySharePublicParameters::new::<secp256k1::GroupElement>(
                access_structure.threshold,
                access_structure.number_of_virtual_parties(),
                encryption_scheme_public_parameters
                    .setup_parameters
                    .h
                    .value(),
                self.secp256k1_public_verification_keys.clone(),
                encryption_scheme_public_parameters,
            )?;

        Ok(decryption_key_share_public_parameters)
    }

    pub fn secp256k1_protocol_public_parameters(
        &self,
    ) -> Result<crate::secp256k1::class_groups::ProtocolPublicParameters> {
        let encryption_scheme_public_parameters =
            self.secp256k1_encryption_scheme_public_parameters()?;

        Ok(
            crate::secp256k1::class_groups::ProtocolPublicParameters::new::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                secp256k1::GroupElement,
            >(
                self.secp256k1_public_key_share_first_part,
                self.secp256k1_public_key_share_second_part,
                self.secp256k1_encryption_of_secret_key_share_first_part,
                self.secp256k1_encryption_of_secret_key_share_second_part,
                encryption_scheme_public_parameters,
            ),
        )
    }

    pub fn ristretto_encryption_scheme_public_parameters(
        &self,
    ) -> Result<RistrettoEncryptionSchemePublicParameters> {
        let mut setup_parameters =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<ristretto::scalar::PublicParameters>(
            &mut setup_parameters,
            self.ristretto_encryption_of_secret_key_share_first_part,
        )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<ristretto::scalar::PublicParameters>(
            &mut setup_parameters,
            self.ristretto_encryption_of_secret_key_share_second_part,
        )?;

        let encryption_key = EquivalenceClass::new(
            self.ristretto_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new_maximally_accelerated(
                setup_parameters.clone(),
                encryption_key,
            )?;

        Ok(encryption_scheme_public_parameters)
    }

    pub fn ristretto_decryption_key_share_public_parameters(
        &self,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<RistrettoDecryptionKeySharePublicParameters> {
        let encryption_scheme_public_parameters =
            self.ristretto_encryption_scheme_public_parameters()?;

        let decryption_key_share_public_parameters =
            RistrettoDecryptionKeySharePublicParameters::new::<ristretto::GroupElement>(
                access_structure.threshold,
                access_structure.number_of_virtual_parties(),
                encryption_scheme_public_parameters
                    .setup_parameters
                    .h
                    .value(),
                self.ristretto_public_verification_keys.clone(),
                encryption_scheme_public_parameters,
            )?;

        Ok(decryption_key_share_public_parameters)
    }

    pub fn ristretto_protocol_public_parameters(
        &self,
    ) -> Result<crate::ristretto::class_groups::ProtocolPublicParameters> {
        let encryption_scheme_public_parameters =
            self.ristretto_encryption_scheme_public_parameters()?;

        Ok(
            crate::ristretto::class_groups::ProtocolPublicParameters::new::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                ristretto::GroupElement,
            >(
                self.ristretto_public_key_share_first_part,
                self.ristretto_public_key_share_second_part,
                self.ristretto_encryption_of_secret_key_share_first_part,
                self.ristretto_encryption_of_secret_key_share_second_part,
                encryption_scheme_public_parameters,
            ),
        )
    }

    pub fn curve25519_encryption_scheme_public_parameters(
        &self,
    ) -> Result<Curve25519EncryptionSchemePublicParameters> {
        let mut setup_parameters =
            Curve25519SetupParameters::derive_from_plaintext_parameters::<curve25519::Scalar>(
                curve25519::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<curve25519::scalar::PublicParameters>(
            &mut setup_parameters,
            self.curve25519_encryption_of_secret_key_share_first_part,
        )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<curve25519::scalar::PublicParameters>(
            &mut setup_parameters,
            self.curve25519_encryption_of_secret_key_share_second_part,
        )?;

        // Curve25519 and Ristretto uses the same Scalar field and thus the same encryption key.
        let encryption_key = EquivalenceClass::new(
            self.ristretto_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new_maximally_accelerated(
                setup_parameters.clone(),
                encryption_key,
            )?;

        Ok(encryption_scheme_public_parameters)
    }

    pub fn curve25519_decryption_key_share_public_parameters(
        &self,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<Curve25519DecryptionKeySharePublicParameters> {
        // Curve25519 and Ristretto uses the same Scalar field and thus the same encryption key and public verification keys.
        self.ristretto_decryption_key_share_public_parameters(access_structure)
    }

    pub fn curve25519_protocol_public_parameters(
        &self,
    ) -> Result<crate::curve25519::class_groups::ProtocolPublicParameters> {
        let encryption_scheme_public_parameters =
            self.curve25519_encryption_scheme_public_parameters()?;

        Ok(
            crate::curve25519::class_groups::ProtocolPublicParameters::new::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                curve25519::GroupElement,
            >(
                self.curve25519_public_key_share_first_part,
                self.curve25519_public_key_share_second_part,
                self.curve25519_encryption_of_secret_key_share_first_part,
                self.curve25519_encryption_of_secret_key_share_second_part,
                encryption_scheme_public_parameters,
            ),
        )
    }

    pub fn secp256r1_encryption_scheme_public_parameters(
        &self,
    ) -> Result<Secp256r1EncryptionSchemePublicParameters> {
        let mut setup_parameters =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<secp256r1::scalar::PublicParameters>(
            &mut setup_parameters,
            self.secp256r1_encryption_of_secret_key_share_first_part,
        )?;

        dkg::PublicOutputCore::accelerate_ciphertext::<secp256r1::scalar::PublicParameters>(
            &mut setup_parameters,
            self.secp256r1_encryption_of_secret_key_share_second_part,
        )?;

        let encryption_key = EquivalenceClass::new(
            self.secp256r1_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new_maximally_accelerated(
                setup_parameters.clone(),
                encryption_key,
            )?;

        Ok(encryption_scheme_public_parameters)
    }

    pub fn secp256r1_decryption_key_share_public_parameters(
        &self,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<Secp256r1DecryptionKeySharePublicParameters> {
        let encryption_scheme_public_parameters =
            self.secp256r1_encryption_scheme_public_parameters()?;

        let decryption_key_share_public_parameters =
            Secp256r1DecryptionKeySharePublicParameters::new::<secp256r1::GroupElement>(
                access_structure.threshold,
                access_structure.number_of_virtual_parties(),
                encryption_scheme_public_parameters
                    .setup_parameters
                    .h
                    .value(),
                self.secp256r1_public_verification_keys.clone(),
                encryption_scheme_public_parameters,
            )?;

        Ok(decryption_key_share_public_parameters)
    }

    pub fn secp256r1_protocol_public_parameters(
        &self,
    ) -> Result<crate::secp256r1::class_groups::ProtocolPublicParameters> {
        let encryption_scheme_public_parameters =
            self.secp256r1_encryption_scheme_public_parameters()?;

        Ok(
            crate::secp256r1::class_groups::ProtocolPublicParameters::new::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                secp256r1::GroupElement,
            >(
                self.secp256r1_public_key_share_first_part,
                self.secp256r1_public_key_share_second_part,
                self.secp256r1_encryption_of_secret_key_share_first_part,
                self.secp256r1_encryption_of_secret_key_share_second_part,
                encryption_scheme_public_parameters,
            ),
        )
    }

    /// Returns the secp256k1 encryption key (compact form).
    pub fn secp256k1_encryption_key(&self) -> CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.secp256k1_encryption_key
    }

    /// Returns the secp256k1 public verification keys.
    pub fn secp256k1_public_verification_keys(
        &self,
    ) -> HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>> {
        self.secp256k1_public_verification_keys.clone()
    }

    /// Returns the ristretto encryption key (compact form).
    pub fn ristretto_encryption_key(&self) -> CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.ristretto_encryption_key
    }

    /// Returns the ristretto public verification keys.
    pub fn ristretto_public_verification_keys(
        &self,
    ) -> HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>> {
        self.ristretto_public_verification_keys.clone()
    }

    /// Returns the secp256r1 encryption key (compact form).
    pub fn secp256r1_encryption_key(&self) -> CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        self.secp256r1_encryption_key
    }

    /// Returns the secp256r1 public verification keys.
    pub fn secp256r1_public_verification_keys(
        &self,
    ) -> HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>> {
        self.secp256r1_public_verification_keys.clone()
    }
}

/// Real network-key threshold decryption.
#[cfg(not(feature = "unsafe_mock"))]
impl PublicOutputCore {
    /// The final share is computed as $n_{new}!\cdot (r+s)-[r]_{i_{R}}$.
    pub fn decrypt_decryption_key_shares(
        &self,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    ) -> Result<HashMap<PartyID, SecretKeyShareSizedInteger>> {
        let decryption_key_shares =
            ::class_groups::reconfiguration::PublicOutput::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::decrypt_decryption_key_shares_internal::<secp256k1::GroupElement>(
                tangible_party_id,
                access_structure,
                decryption_key_per_crt_prime,
                self.masked_decryption_key_by_n_factorial,
                self.encryptions_of_randomizer_shares_per_crt_prime.clone(),
            )?;

        Ok(decryption_key_shares)
    }
}

/// INSECURE `unsafe_mock`: the network key is never threshold-decrypted (per-dWallet signing uses the
/// constant mock key `x = 42`), so return deterministic dummy shares for every virtual party.
#[cfg(feature = "unsafe_mock")]
impl PublicOutputCore {
    /// The final share is computed as $n_{new}!\cdot (r+s)-[r]_{i_{R}}$.
    pub fn decrypt_decryption_key_shares(
        &self,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        _decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    ) -> Result<HashMap<PartyID, SecretKeyShareSizedInteger>> {
        Ok(crate::mock::network_dkg::mock_decryption_key_shares(
            access_structure,
            tangible_party_id,
        ))
    }
}

/// The Reconfiguration public output in the aggregated form: the same [`PublicOutputCore`]
/// plus the aggregated threshold-encryption-to-sharing output (one summed randomizer-share
/// ciphertext per receiver instead of every dealer's full PVSS dealing — see
/// [`crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::aggregated_public_output`]).
///
/// This is the Party's wire output: the per-receiver aggregation happens at
/// output formation (fourth round), and it is what all consumers persist and
/// read.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicOutput {
    pub core: PublicOutputCore,

    /// Protocol 0.1 output in aggregated form (Shamir shares data, one ciphertext per receiver).
    pub(crate) threshold_encryption_to_sharing_output:
        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::aggregated_public_output::PublicOutput,
}

impl std::ops::Deref for PublicOutput {
    type Target = PublicOutputCore;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl PublicOutput {
    /// Computes secp256k1 Shamir shares of secret key share parts for a party.
    ///
    /// Returns the Shamir shares `([x_0]_i, [x_1]_i)` computed as `(x + r) - [r]_i`.
    pub fn compute_secp256k1_shamir_shares_of_secret_key_share_parts(
        &self,
        party_id: PartyID,
        pvss_decryption_key: crypto_bigint::Uint<
            { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >,
        pvss_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<(
        group::Value<secp256k1::Scalar>,
        group::Value<secp256k1::Scalar>,
    )> {
        let setup_parameters =
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let pvss_encryption_key = EquivalenceClass::new(
            pvss_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new(setup_parameters, pvss_encryption_key)?;

        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::aggregated_public_output::derive_shamir_shares_of_secret_key_share_parts_from_aggregated_encryptions::<
            { secp256k1::SCALAR_LIMBS },
            { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
        >(
            party_id,
            &encryption_scheme_public_parameters,
            pvss_decryption_key,
            &self.threshold_encryption_to_sharing_output.secp256k1_first_encryptions_of_randomizer_shares,
            &self.threshold_encryption_to_sharing_output.secp256k1_second_encryptions_of_randomizer_shares,
            self.threshold_encryption_to_sharing_output.secp256k1_first_masked_secret_key_share_part,
            self.threshold_encryption_to_sharing_output.secp256k1_second_masked_secret_key_share_part,
        )
    }

    /// Computes ristretto Shamir shares of secret key share parts for a party.
    ///
    /// Returns the Shamir shares `([x_0]_i, [x_1]_i)` computed as `(x + r) - [r]_i`.
    pub fn compute_ristretto_shamir_shares_of_secret_key_share_parts(
        &self,
        party_id: PartyID,
        pvss_decryption_key: crypto_bigint::Uint<
            { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >,
        pvss_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<(
        group::Value<ristretto::Scalar>,
        group::Value<ristretto::Scalar>,
    )> {
        let setup_parameters =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let pvss_encryption_key = EquivalenceClass::new(
            pvss_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new(setup_parameters, pvss_encryption_key)?;

        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::aggregated_public_output::derive_shamir_shares_of_secret_key_share_parts_from_aggregated_encryptions::<
            { ristretto::SCALAR_LIMBS },
            { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            ristretto::GroupElement,
        >(
            party_id,
            &encryption_scheme_public_parameters,
            pvss_decryption_key,
            &self.threshold_encryption_to_sharing_output.ristretto_first_encryptions_of_randomizer_shares,
            &self.threshold_encryption_to_sharing_output.ristretto_second_encryptions_of_randomizer_shares,
            self.threshold_encryption_to_sharing_output.ristretto_first_masked_secret_key_share_part,
            self.threshold_encryption_to_sharing_output.ristretto_second_masked_secret_key_share_part,
        )
    }

    /// Computes curve25519 Shamir shares of secret key share parts for a party.
    ///
    /// Returns the Shamir shares `([x_0]_i, [x_1]_i)` computed as `(x + r) - [r]_i`.
    ///
    /// Note: curve25519 uses ristretto encryption parameters since they share the same scalar field.
    pub fn compute_curve25519_shamir_shares_of_secret_key_share_parts(
        &self,
        party_id: PartyID,
        pvss_decryption_key: crypto_bigint::Uint<
            { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >,
        pvss_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<(
        group::Value<curve25519::Scalar>,
        group::Value<curve25519::Scalar>,
    )> {
        let setup_parameters =
            Curve25519SetupParameters::derive_from_plaintext_parameters::<curve25519::Scalar>(
                curve25519::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let pvss_encryption_key = EquivalenceClass::new(
            pvss_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new(setup_parameters, pvss_encryption_key)?;

        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::aggregated_public_output::derive_shamir_shares_of_secret_key_share_parts_from_aggregated_encryptions::<
            { curve25519::SCALAR_LIMBS },
            { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            curve25519::GroupElement,
        >(
            party_id,
            &encryption_scheme_public_parameters,
            pvss_decryption_key,
            &self.threshold_encryption_to_sharing_output.curve25519_first_encryptions_of_randomizer_shares,
            &self.threshold_encryption_to_sharing_output.curve25519_second_encryptions_of_randomizer_shares,
            self.threshold_encryption_to_sharing_output.curve25519_first_masked_secret_key_share_part,
            self.threshold_encryption_to_sharing_output.curve25519_second_masked_secret_key_share_part,
        )
    }

    /// Computes secp256r1 Shamir shares of secret key share parts for a party.
    ///
    /// Returns the Shamir shares `([x_0]_i, [x_1]_i)` computed as `(x + r) - [r]_i`.
    pub fn compute_secp256r1_shamir_shares_of_secret_key_share_parts(
        &self,
        party_id: PartyID,
        pvss_decryption_key: crypto_bigint::Uint<
            { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >,
        pvss_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<(
        group::Value<secp256r1::Scalar>,
        group::Value<secp256r1::Scalar>,
    )> {
        let setup_parameters =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let pvss_encryption_key = EquivalenceClass::new(
            pvss_encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new(setup_parameters, pvss_encryption_key)?;

        crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::aggregated_public_output::derive_shamir_shares_of_secret_key_share_parts_from_aggregated_encryptions::<
            { secp256r1::SCALAR_LIMBS },
            { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256r1::GroupElement,
        >(
            party_id,
            &encryption_scheme_public_parameters,
            pvss_decryption_key,
            &self.threshold_encryption_to_sharing_output.secp256r1_first_encryptions_of_randomizer_shares,
            &self.threshold_encryption_to_sharing_output.secp256r1_second_encryptions_of_randomizer_shares,
            self.threshold_encryption_to_sharing_output.secp256r1_first_masked_secret_key_share_part,
            self.threshold_encryption_to_sharing_output.secp256r1_second_masked_secret_key_share_part,
        )
    }

    /// Returns the polynomial commitments for secp256k1.
    pub fn secp256k1_polynomial_commitments(
        &self,
    ) -> (
        &Vec<secp256k1::group_element::Value>,
        &Vec<secp256k1::group_element::Value>,
    ) {
        (
            &self
                .threshold_encryption_to_sharing_output
                .secp256k1_first_secret_polynomial_commitments,
            &self
                .threshold_encryption_to_sharing_output
                .secp256k1_second_secret_polynomial_commitments,
        )
    }

    /// Returns the polynomial commitments for ristretto.
    pub fn ristretto_polynomial_commitments(
        &self,
    ) -> (
        &Vec<group::Value<ristretto::GroupElement>>,
        &Vec<group::Value<ristretto::GroupElement>>,
    ) {
        (
            &self
                .threshold_encryption_to_sharing_output
                .ristretto_first_secret_polynomial_commitments,
            &self
                .threshold_encryption_to_sharing_output
                .ristretto_second_secret_polynomial_commitments,
        )
    }

    /// Returns the polynomial commitments for curve25519.
    pub fn curve25519_polynomial_commitments(
        &self,
    ) -> (
        &Vec<group::Value<curve25519::GroupElement>>,
        &Vec<group::Value<curve25519::GroupElement>>,
    ) {
        (
            &self
                .threshold_encryption_to_sharing_output
                .curve25519_first_secret_polynomial_commitments,
            &self
                .threshold_encryption_to_sharing_output
                .curve25519_second_secret_polynomial_commitments,
        )
    }

    /// Returns the polynomial commitments for secp256r1.
    pub fn secp256r1_polynomial_commitments(
        &self,
    ) -> (
        &Vec<secp256r1::group_element::Value>,
        &Vec<secp256r1::group_element::Value>,
    ) {
        (
            &self
                .threshold_encryption_to_sharing_output
                .secp256r1_first_secret_polynomial_commitments,
            &self
                .threshold_encryption_to_sharing_output
                .secp256r1_second_secret_polynomial_commitments,
        )
    }
}
