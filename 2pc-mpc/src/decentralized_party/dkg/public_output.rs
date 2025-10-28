// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::Uint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES, NUM_SECRET_SHARE_PRIMES,
};
use class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
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
    HIGHEST_ACCELERATOR_FOLDING_DEGREE,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
use group::secp256k1::SCALAR_LIMBS;
use group::{curve25519, ristretto, secp256k1, secp256r1, GroupElement, PartyID};
use mpc::WeightedThresholdAccessStructure;

use crate::Result;

/// The Public Input of the Reconfiguration party.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicOutput {
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
    pub(crate) curve25519_public_key_share_first_part: curve25519::GroupElement,
    pub(crate) curve25519_public_key_share_second_part: curve25519::GroupElement,

    pub(crate) secp256r1_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256r1_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256r1_public_key_share_first_part: secp256r1::group_element::Value,
    pub(crate) secp256r1_public_key_share_second_part: secp256r1::group_element::Value,
    secp256r1_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    secp256r1_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    pub(crate) encryptions_of_shares_per_crt_prime: HashMap<
        PartyID,
        [CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; NUM_SECRET_SHARE_PRIMES],
    >,
    pub(crate) threshold_encryption_of_decryption_key_per_crt_prime:
        [CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
    pub(crate) threshold_encryption_key_per_crt_prime:
        [CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
}

impl PublicOutput {
    pub(crate) fn new(
        inner_protocol_public_output: class_groups::dkg::PublicOutput<
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
        ristretto_public_verification_keys: HashMap<
            PartyID,
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        curve25519_encryption_of_secret_key_share_first_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        curve25519_encryption_of_secret_key_share_second_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        curve25519_public_key_share_first_part: curve25519::GroupElement,
        curve25519_public_key_share_second_part: curve25519::GroupElement,
        secp256r1_encryption_of_secret_key_share_first_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256r1_encryption_of_secret_key_share_second_part: CiphertextSpaceValue<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        secp256r1_public_key_share_first_part: secp256r1::group_element::Value,
        secp256r1_public_key_share_second_part: secp256r1::group_element::Value,
        secp256r1_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secp256r1_public_verification_keys: HashMap<
            PartyID,
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    ) -> Result<Self> {
        let encryptions_of_shares_per_crt_prime =
            inner_protocol_public_output.encryptions_of_shares_per_crt_prime;
        let threshold_encryption_of_decryption_key_per_crt_prime =
            inner_protocol_public_output.threshold_encryption_of_decryption_key_per_crt_prime;
        let threshold_encryption_key_per_crt_prime =
            inner_protocol_public_output.threshold_encryption_key_per_crt_prime;

        let secp256k1_encryption_key = inner_protocol_public_output.encryption_key;
        let secp256k1_public_verification_keys =
            inner_protocol_public_output.public_verification_keys;

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
            encryptions_of_shares_per_crt_prime,
            threshold_encryption_of_decryption_key_per_crt_prime,
            threshold_encryption_key_per_crt_prime,
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

        Self::accelerate_ciphertext::<secp256k1::scalar::PublicParameters>(
            &mut setup_parameters,
            self.secp256k1_encryption_of_secret_key_share_first_part,
        )?;

        Self::accelerate_ciphertext::<secp256k1::scalar::PublicParameters>(
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

        Self::accelerate_ciphertext::<ristretto::scalar::PublicParameters>(
            &mut setup_parameters,
            self.ristretto_encryption_of_secret_key_share_first_part,
        )?;

        Self::accelerate_ciphertext::<ristretto::scalar::PublicParameters>(
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

        Self::accelerate_ciphertext::<curve25519::scalar::PublicParameters>(
            &mut setup_parameters,
            self.curve25519_encryption_of_secret_key_share_first_part,
        )?;

        Self::accelerate_ciphertext::<curve25519::scalar::PublicParameters>(
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

        Self::accelerate_ciphertext::<secp256r1::scalar::PublicParameters>(
            &mut setup_parameters,
            self.secp256r1_encryption_of_secret_key_share_first_part,
        )?;

        Self::accelerate_ciphertext::<secp256r1::scalar::PublicParameters>(
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

    pub fn accelerate_ciphertext<ScalarPublicParameters>(
        setup_parameters: &mut SetupParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        ciphertext: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<()> {
        let [ct1, ct2] = ciphertext.into();
        let ct1 =
            EquivalenceClass::new(ct1, setup_parameters.equivalence_class_public_parameters())?;
        let ct2 =
            EquivalenceClass::new(ct2, setup_parameters.equivalence_class_public_parameters())?;

        let equivalence_class_public_parameters =
            setup_parameters.equivalence_class_public_parameters_mut();

        let ct1_accelerators = [
            Uint::<SCALAR_LIMBS>::BITS,
            Uint::<SCALAR_LIMBS>::BITS + MAURER_RANDOMIZER_DIFF_BITS,
        ]
        .into_iter()
        .map(|target_bits| {
            ct1.get_multifold_accelerator_vartime(HIGHEST_ACCELERATOR_FOLDING_DEGREE, target_bits)
        })
        .collect::<class_groups::Result<_>>()?;

        equivalence_class_public_parameters
            .insert_accelerators_for(*ct1.representative(), ct1_accelerators);

        let ct2_accelerators = [
            Uint::<SCALAR_LIMBS>::BITS,
            Uint::<SCALAR_LIMBS>::BITS + MAURER_RANDOMIZER_DIFF_BITS,
        ]
        .into_iter()
        .map(|target_bits| {
            ct2.get_multifold_accelerator_vartime(HIGHEST_ACCELERATOR_FOLDING_DEGREE, target_bits)
        })
        .collect::<class_groups::Result<_>>()?;

        equivalence_class_public_parameters
            .insert_accelerators_for(*ct2.representative(), ct2_accelerators);

        Ok(())
    }

    /// The final share is computed as $n_{new}!\cdot (r+s)-[r]_{i_{R}}$.
    pub fn decrypt_decryption_key_shares(
        &self,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    ) -> Result<HashMap<PartyID, SecretKeyShareSizedInteger>> {
        let decryption_key_shares =
            ::class_groups::dkg::PublicOutput::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::decrypt_decryption_key_shares_internal::<secp256k1::GroupElement>(
                tangible_party_id,
                access_structure,
                decryption_key_per_crt_prime,
                self.encryptions_of_shares_per_crt_prime.clone(),
            )?;

        Ok(decryption_key_shares)
    }
}

impl From<PublicOutput>
    for ::class_groups::dkg::PublicOutput<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >
{
    fn from(public_output: PublicOutput) -> Self {
        Self {
            encryption_key: public_output.secp256k1_encryption_key,
            threshold_encryption_key_per_crt_prime: public_output
                .threshold_encryption_key_per_crt_prime,
            public_verification_keys: public_output.secp256k1_public_verification_keys,
            encryptions_of_shares_per_crt_prime: public_output.encryptions_of_shares_per_crt_prime,
            threshold_encryption_of_decryption_key_per_crt_prime: public_output
                .threshold_encryption_of_decryption_key_per_crt_prime,
        }
    }
}
