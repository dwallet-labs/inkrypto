// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

mod first_round;
mod fourth_round;
mod public_output;
mod second_round;
mod third_round;

use crate::decentralized_party::dkg::{
    EqualityOfCoefficientsCommitmentsProof, EQUALITY_OF_COEFFICIENTS_COMMITMENTS_PROOF_NAME,
};
use crate::languages::construct_equality_of_discrete_log_public_parameters;
use crate::Error;
use crate::{decentralized_party, BaseProtocolContext};
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::KnowledgeOfDiscreteLogUCProof;
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    },
    CiphertextSpaceValue, CompactIbqf, Curve25519SetupParameters, EquivalenceClass,
    RistrettoSetupParameters, Secp256r1SetupParameters, SecretKeyShareSizedInteger,
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::direct_product::ThreeWayGroupElement;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{
    bounded_integers_group, curve25519, direct_product, ristretto, secp256k1, secp256r1, CsRng,
    GroupElement as _, PartyID,
};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};
pub use public_output::PublicOutput;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub struct Party {}

/// The Message of the Reconfiguration protocol.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Message {
    DealRandomizerContributionAndProveCoefficientCommitments {
        deal_randomizer_message: class_groups::reconfiguration::Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        equality_of_coefficients_commitments_proof: EqualityOfCoefficientsCommitmentsProof,
        coefficients_commitments: Vec<
            direct_product::Value<
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
    },
    VerifiedRandomizerDealers(
        class_groups::reconfiguration::Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ),
    ThresholdDecryptShares {
        threshold_decrypt_message: class_groups::reconfiguration::Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        malicious_coefficients_committers: HashSet<PartyID>,
    },
}

/// The Public Input of the Reconfiguration party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicInput {
    class_groups_public_input: class_groups::reconfiguration::PublicInput<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<Scalar>,
    >,
    secp256k1_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    secp256k1_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    secp256k1_public_key_share_first_part: secp256k1::group_element::Value,
    secp256k1_public_key_share_second_part: secp256k1::group_element::Value,
    ristretto_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ristretto_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ristretto_public_key_share_first_part: ristretto::GroupElement,
    ristretto_public_key_share_second_part: ristretto::GroupElement,
    ristretto_setup_parameters: RistrettoSetupParameters,
    curve25519_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    curve25519_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    curve25519_public_key_share_first_part: curve25519::GroupElement,
    curve25519_public_key_share_second_part: curve25519::GroupElement,
    curve25519_setup_parameters: Curve25519SetupParameters,
    secp256r1_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    secp256r1_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    secp256r1_public_key_share_first_part: secp256r1::group_element::Value,
    secp256r1_public_key_share_second_part: secp256r1::group_element::Value,
    secp256r1_setup_parameters: Secp256r1SetupParameters,
}

impl PublicInput {
    pub fn new_from_reconfiguration_output(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: WeightedThresholdAccessStructure,
        current_encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
        upcoming_encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        dkg_output: class_groups::dkg::PublicOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        public_output: PublicOutput,
    ) -> crate::Result<Self> {
        let ristretto_setup_parameters =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let curve25519_setup_parameters =
            Curve25519SetupParameters::derive_from_plaintext_parameters::<curve25519::Scalar>(
                group::curve25519::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let secp256r1_setup_parameters =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let secp256k1_decryption_key_share_public_parameters = public_output
            .secp256k1_decryption_key_share_public_parameters(current_access_structure)?;

        let class_groups_public_input =
            class_groups::reconfiguration::PublicInput::new::<secp256k1::GroupElement>(
                current_access_structure,
                upcoming_access_structure,
                secp256k1::scalar::PublicParameters::default(),
                current_encryption_key_values_and_proofs_per_crt_prime,
                upcoming_encryption_key_values_and_proofs_per_crt_prime,
                secp256k1_decryption_key_share_public_parameters,
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                current_tangible_party_id_to_upcoming,
                dkg_output,
            )?;

        Ok(Self {
            class_groups_public_input,
            secp256k1_encryption_of_secret_key_share_first_part: public_output
                .secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part: public_output
                .secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part: public_output
                .secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part: public_output
                .secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part: public_output
                .ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part: public_output
                .ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part: public_output
                .ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part: public_output
                .ristretto_public_key_share_second_part,
            ristretto_setup_parameters,
            curve25519_encryption_of_secret_key_share_first_part: public_output
                .curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part: public_output
                .curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part: public_output
                .curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part: public_output
                .curve25519_public_key_share_second_part,
            curve25519_setup_parameters,
            secp256r1_encryption_of_secret_key_share_first_part: public_output
                .secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part: public_output
                .secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part: public_output
                .secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part: public_output
                .secp256r1_public_key_share_second_part,
            secp256r1_setup_parameters,
        })
    }

    pub fn new_from_dkg_output(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: WeightedThresholdAccessStructure,
        current_encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
        upcoming_encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        universal_public_output: decentralized_party::dkg::PublicOutput,
    ) -> crate::Result<Self> {
        let ristretto_setup_parameters =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let curve25519_setup_parameters =
            Curve25519SetupParameters::derive_from_plaintext_parameters::<curve25519::Scalar>(
                group::curve25519::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let secp256r1_setup_parameters =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )?;

        let secp256k1_decryption_key_share_public_parameters = universal_public_output
            .secp256k1_decryption_key_share_public_parameters(current_access_structure)?;

        let class_groups_public_input =
            class_groups::reconfiguration::PublicInput::new::<secp256k1::GroupElement>(
                current_access_structure,
                upcoming_access_structure,
                secp256k1::scalar::PublicParameters::default(),
                current_encryption_key_values_and_proofs_per_crt_prime,
                upcoming_encryption_key_values_and_proofs_per_crt_prime,
                secp256k1_decryption_key_share_public_parameters,
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                current_tangible_party_id_to_upcoming,
                universal_public_output.clone().into(),
            )?;

        Ok(Self {
            class_groups_public_input,
            secp256k1_encryption_of_secret_key_share_first_part: universal_public_output
                .secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part: universal_public_output
                .secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part: universal_public_output
                .secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part: universal_public_output
                .secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part: universal_public_output
                .ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part: universal_public_output
                .ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part: universal_public_output
                .ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part: universal_public_output
                .ristretto_public_key_share_second_part,
            ristretto_setup_parameters,
            curve25519_encryption_of_secret_key_share_first_part: universal_public_output
                .curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part: universal_public_output
                .curve25519_encryption_of_secret_key_share_second_part,
            curve25519_public_key_share_first_part: universal_public_output
                .curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part: universal_public_output
                .curve25519_public_key_share_second_part,
            curve25519_setup_parameters,
            secp256r1_encryption_of_secret_key_share_first_part: universal_public_output
                .secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part: universal_public_output
                .secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part: universal_public_output
                .secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part: universal_public_output
                .secp256r1_public_key_share_second_part,
            secp256r1_setup_parameters,
        })
    }
}

impl mpc::Party for Party {
    type Error = Error;
    type PublicInput = PublicInput;
    type PrivateOutput = ();
    type PublicOutputValue = PublicOutput;
    type PublicOutput = Self::PublicOutputValue;
    type Message = Message;
}

impl AsynchronouslyAdvanceable for Party {
    type PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;

    fn advance(
        session_id: CommitmentSizedNumber,
        tangible_party_id: PartyID,
        current_access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let (
            decryption_key_shares,
            current_decryption_key_share_bits,
            randomizer_contribution_bits,
            randomizer_share_bits,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
            randomizer_contribution_to_upcoming_pvss_party,
        ) = class_groups::reconfiguration::Party::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::prepare_advance(
            session_id,
            tangible_party_id,
            current_access_structure,
            private_input,
            &public_input.class_groups_public_input,
        )?;

        // Generating public verification keys for threshold encryptions:
        //
        // In order for us to maintain the structure of the code we do not use $h_{q}$ as a verification key to the threshold encryptions defined by the different CRT primes.
        // Instead, each virtual current party compute $\textsf{vk}_{Q'_{m'}}^{i_{T}}=h_{Q'_{m'}}^{[s]_{i_{T}}}$ and prove equality of discrete log between this new verification per CRT prime to the original verification key.
        // Then they use this verification key to prove correct decryption as typicaly happens in threshold decryption.
        let discrete_log_group_public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound(
                randomizer_share_bits,
            )?;

        let secp256k1_setup_parameters = &public_input.class_groups_public_input.setup_parameters;

        let hidden_order_group_public_parameters = (
            (
                secp256k1_setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
                public_input
                    .ristretto_setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
            )
                .into(),
            public_input
                .secp256r1_setup_parameters
                .equivalence_class_public_parameters()
                .clone(),
        )
            .into();

        let base: ThreeWayGroupElement<_, _, _> = (
            (
                secp256k1_setup_parameters.h,
                public_input.ristretto_setup_parameters.h,
            )
                .into(),
            public_input.secp256r1_setup_parameters.h,
        )
            .into();

        let equality_of_coefficients_commitments_language_public_parameters =
            construct_equality_of_discrete_log_public_parameters::<
                SECRET_KEY_SHARE_LIMBS,
                ThreeWayGroupElement<
                    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                >,
            >(
                discrete_log_group_public_parameters,
                hidden_order_group_public_parameters,
                base.value(),
            );

        let equality_of_coefficients_commitments_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal Reconfiguration V2".to_string(),
            round_name: "1 - Deal Randomizer Contribution and Prove Coefficients Commitments"
                .to_string(),
            proof_name: EQUALITY_OF_COEFFICIENTS_COMMITMENTS_PROOF_NAME.to_string(),
        };

        match &messages[..] {
            [] => Self::advance_first_round(
                tangible_party_id,
                session_id,
                randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                public_input,
                equality_of_coefficients_commitments_language_public_parameters,
                &randomizer_contribution_to_upcoming_pvss_party,
                equality_of_coefficients_commitments_base_protocol_context,
                randomizer_contribution_bits,
                rng,
            ),
            [deal_randomizer_and_prove_coefficient_commitments_messages] => {
                Self::advance_second_round(
                    tangible_party_id,
                    public_input,
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    rng,
                )
            }
            [deal_randomizer_and_prove_coefficient_commitments_messages, verified_dealers_messages] => {
                Self::advance_third_round(
                    tangible_party_id,
                    session_id,
                    randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                    current_access_structure,
                    equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                    public_input,
                    equality_of_coefficients_commitments_language_public_parameters,
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    verified_dealers_messages.clone(),
                    decryption_key_shares,
                    equality_of_coefficients_commitments_base_protocol_context,
                    current_decryption_key_share_bits,
                    randomizer_contribution_bits,
                    rng,
                )
            }
            [deal_randomizer_and_prove_coefficient_commitments_messages, _, threshold_decrypt_messages] => {
                Self::advance_fourth_round(
                    tangible_party_id,
                    session_id,
                    current_access_structure,
                    equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                    public_input,
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    threshold_decrypt_messages.clone(),
                    current_decryption_key_share_bits,
                    rng,
                )
            }
            _ => Err(Error::InvalidParameters),
        }
    }

    fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
        match failed_round {
            3 => Some(1),
            4 => Some(3),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_helpers::mock_decentralized_party_dkg;
    use class_groups::dkg::test_helpers::mock_dkg_output;
    use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::construct_setup_parameters_per_crt_prime;
    use class_groups::test_helpers::{
        deal_trusted_shares, get_setup_parameters_curve25519_112_bits_deterministic,
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
        get_setup_parameters_secp256r1_112_bits_deterministic, setup_reconfig_secp256k1,
    };
    use class_groups::{
        Curve25519EncryptionKey, RistrettoDecryptionKey, RistrettoEncryptionKey,
        Secp256k1DecryptionKey, Secp256k1EncryptionKey, Secp256r1DecryptionKey,
        Secp256r1EncryptionKey,
    };
    use group::OsCsRng;
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;

    #[test]
    fn reconfigures() {
        let threshold = 4;
        let current_party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);
        let upcoming_party_to_weight = HashMap::from([(1, 1), (2, 2), (3, 2)]);

        let current_access_structure =
            WeightedThresholdAccessStructure::new(threshold, current_party_to_weight).unwrap();

        let upcoming_access_structure =
            WeightedThresholdAccessStructure::new(threshold, upcoming_party_to_weight).unwrap();

        let current_tangible_party_id_to_upcoming =
            HashMap::from([(1, Some(2)), (2, None), (3, Some(3))]);

        reconfigures_internal(
            current_access_structure,
            upcoming_access_structure,
            current_tangible_party_id_to_upcoming,
            false,
        );
    }

    fn reconfigures_internal(
        current_access_structure: WeightedThresholdAccessStructure,
        upcoming_access_structure: WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        bench: bool,
    ) -> PublicOutput {
        let secp256k1_setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (secp256k1_encryption_scheme_public_parameters, secp256k1_decryption_key) =
            Secp256k1DecryptionKey::generate_with_setup_parameters(
                secp256k1_setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();

        let (secp256k1_decryption_key_share_public_parameters, secp256k1_decryption_key_shares) =
            deal_trusted_shares::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                secp256k1::GroupElement,
            >(
                current_access_structure.threshold,
                current_access_structure.number_of_virtual_parties(),
                secp256k1_encryption_scheme_public_parameters.clone(),
                secp256k1_decryption_key.decryption_key,
                secp256k1_setup_parameters.h,
                secp256k1_setup_parameters.decryption_key_bits(),
            );

        let (
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >(
            secp256k1::group_element::PublicParameters::default(),
            secp256k1::scalar::PublicParameters::default(),
            &secp256k1_encryption_scheme_public_parameters,
        );

        let ristretto_setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let (ristretto_encryption_scheme_public_parameters, _) =
            RistrettoDecryptionKey::generate_with_setup_parameters(
                ristretto_setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();

        let (
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { ristretto::SCALAR_LIMBS },
            { ristretto::SCALAR_LIMBS },
            ristretto::GroupElement,
            RistrettoEncryptionKey,
        >(
            ristretto::group_element::PublicParameters::default(),
            ristretto::scalar::PublicParameters::default(),
            &ristretto_encryption_scheme_public_parameters,
        );

        let curve25519_setup_parameters = get_setup_parameters_curve25519_112_bits_deterministic();

        let (
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { curve25519::SCALAR_LIMBS },
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
            Curve25519EncryptionKey,
        >(
            curve25519::PublicParameters::default(),
            curve25519::scalar::PublicParameters::default(),
            &ristretto_encryption_scheme_public_parameters,
        );

        let secp256r1_setup_parameters = get_setup_parameters_secp256r1_112_bits_deterministic();
        let (secp256r1_encryption_scheme_public_parameters, _) =
            Secp256r1DecryptionKey::generate_with_setup_parameters(
                secp256r1_setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();

        let (
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
        ) = mock_decentralized_party_dkg::<
            { secp256r1::SCALAR_LIMBS },
            { secp256r1::SCALAR_LIMBS },
            secp256r1::GroupElement,
            Secp256r1EncryptionKey,
        >(
            secp256r1::group_element::PublicParameters::default(),
            secp256r1::scalar::PublicParameters::default(),
            &secp256r1_encryption_scheme_public_parameters,
        );

        let dkg_output = mock_dkg_output::<
            SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >(
            secp256k1_decryption_key.decryption_key,
            secp256k1_decryption_key_share_public_parameters.clone(),
        );

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let (session_id, private_inputs, _, public_inputs) = setup_reconfig_secp256k1(
            &current_access_structure,
            &upcoming_access_structure,
            current_tangible_party_id_to_upcoming,
            secp256k1_encryption_scheme_public_parameters,
            secp256k1_decryption_key,
            secp256k1_decryption_key_share_public_parameters,
            secp256k1_decryption_key_shares,
            dkg_output,
            setup_parameters_per_crt_prime,
            true,
        );

        let class_groups_public_input = public_inputs.values().next().unwrap().clone();

        let public_input = PublicInput {
            class_groups_public_input,
            secp256k1_encryption_of_secret_key_share_first_part,
            secp256k1_encryption_of_secret_key_share_second_part,
            secp256k1_public_key_share_first_part,
            secp256k1_public_key_share_second_part,
            ristretto_encryption_of_secret_key_share_first_part,
            ristretto_encryption_of_secret_key_share_second_part,
            ristretto_public_key_share_first_part,
            ristretto_public_key_share_second_part,
            ristretto_setup_parameters,
            curve25519_public_key_share_first_part,
            curve25519_public_key_share_second_part,
            curve25519_encryption_of_secret_key_share_first_part,
            curve25519_encryption_of_secret_key_share_second_part,
            curve25519_setup_parameters,
            secp256r1_encryption_of_secret_key_share_first_part,
            secp256r1_encryption_of_secret_key_share_second_part,
            secp256r1_public_key_share_first_part,
            secp256r1_public_key_share_second_part,
            secp256r1_setup_parameters,
        };

        reconfigures_internal_internal(
            session_id,
            current_access_structure,
            private_inputs,
            public_input,
            bench,
        )
    }

    pub(crate) fn reconfigures_internal_internal(
        session_id: CommitmentSizedNumber,
        current_access_structure: WeightedThresholdAccessStructure,
        private_inputs: HashMap<PartyID, HashMap<PartyID, SecretKeyShareSizedInteger>>,
        public_input: PublicInput,
        bench: bool,
    ) -> PublicOutput {
        let public_inputs = current_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| (party_id, public_input.clone()))
            .collect();

        let (_, _, public_output) = asynchronous_session_terminates_successfully_internal::<Party>(
            session_id,
            &current_access_structure,
            private_inputs,
            public_inputs,
            4,
            HashMap::from([(
                2,
                HashSet::from_iter(
                    1..=(current_access_structure.number_of_tangible_parties() - 1)
                        .max(current_access_structure.threshold),
                ),
            )]),
            bench,
            true,
        );

        public_output
    }
}
