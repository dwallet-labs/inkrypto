// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

mod first_round;
mod fourth_round;
mod public_output;
mod second_round;
mod third_round;

use crate::languages::{
    construct_equality_of_discrete_log_public_parameters,
    EqualityOfDiscreteLogsInHiddenOrderGroupProof,
    EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters,
};
use crate::Error;
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::KnowledgeOfDiscreteLogUCProof;
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    },
    CompactIbqf, Curve25519SetupParameters, EquivalenceClass, RistrettoSetupParameters,
    Secp256k1SetupParameters, Secp256r1SetupParameters, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS,
};
use commitment::CommitmentSizedNumber;
use crypto_bigint::Uint;
use group::direct_product::ThreeWayGroupElement;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{
    bounded_integers_group, curve25519, direct_product, ristretto, secp256k1, secp256r1, CsRng,
    GroupElement as _, PartyID,
};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::BaseProtocolContext;
pub use public_output::PublicOutput;

pub struct Party {}

pub const EQUALITY_OF_COEFFICIENTS_COMMITMENTS_PROOF_NAME: &str =
    "Equality of Coefficients Commitments Proof";

/// An Equality of Coefficients Commitments proof.
/// Used to prove the commitments to the coefficients of the decryption key (or randomizer) contribution are equal under different hidden-order groups.
///
/// We use a single integer secret decryption key that is shared over the integers,
/// across all threshold encryption schemes.
/// Therefore, we could have had a single verification key per party.
/// However, this would imply that decryption share proofs would prove equality of discrete logs between different groups,
/// as the unique verification key may not belong to the same group of the relevant threshold encryption scheme public parameter under which the ciphertext and decryption shares are defined.
///
/// While this is possible, it requires a major change with respect to the current version, that assume the verification keys and decryption shares lie in the same hidden order group.
///
/// In order for us to maintain the structure of the code we generate verification keys
/// per elliptic curve order (which corresponds to a specific class-group parameters).
///
/// This is done by commiting to the secret sharing contributions in all class-groups.
/// Consistency is proven by:
///     1. Prove the PVSS with respect to secp256k1 corresponding class-group
///     2. Prove equality of discrete logs on the commitments to the coefficients from different class-groups.
///
/// Verification keys will be computed as usual from the commitments to coefficients and the masked key.
pub type EqualityOfCoefficientsCommitmentsProof = EqualityOfDiscreteLogsInHiddenOrderGroupProof<
    SECRET_KEY_SHARE_LIMBS,
    ThreeWayGroupElement<
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
>;

/// The public parameters of an Equality of Coefficients Commitments proof.
/// See [`EqualityOfDiscreteLogsInHiddenOrderGroupProof`].
pub type EqualityOfCoefficientsCommitmentsPublicParameters =
    EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
        SECRET_KEY_SHARE_LIMBS,
        ThreeWayGroupElement<
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >;

/// The Message of the Reconfiguration protocol.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Message {
    DealDecryptionKeyContributionAndProveCoefficientCommitments {
        deal_decryption_key_contribution_message: class_groups::dkg::Message<
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
    VerifiedDecryptionKeyContributionDealers(
        class_groups::dkg::Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ),
    EncryptDecryptionKeySharesAndSecretKeyShares {
        encrypt_decryption_key_shares_message: class_groups::dkg::Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        malicious_coefficients_committers: HashSet<PartyID>,
        secp256k1_encryption_of_secret_key_shares_message: <crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        ristretto_encryption_of_secret_key_shares_message: <crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        curve25519_encryption_of_secret_key_shares_message: <crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        secp256r1_encryption_of_secret_key_shares_message: <crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
    },
}

/// The Public Input of the DKG party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicInput {
    class_groups_public_input: class_groups::dkg::PublicInput<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<Scalar>,
    >,
    ristretto_setup_parameters: RistrettoSetupParameters,
    curve25519_setup_parameters: Curve25519SetupParameters,
    secp256r1_setup_parameters: Secp256r1SetupParameters,
}

impl PublicInput {
    pub fn new(
        access_structure: &WeightedThresholdAccessStructure,
        encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
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

        let class_groups_public_input =
            class_groups::dkg::PublicInput::new::<secp256k1::GroupElement>(
                access_structure,
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                encryption_key_values_and_proofs_per_crt_prime,
            )?;

        Ok(Self {
            class_groups_public_input,
            ristretto_setup_parameters,
            curve25519_setup_parameters,
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
    type PrivateInput = [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES];

    fn advance(
        session_id: CommitmentSizedNumber,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let (
            decryption_key_share_bits,
            decryption_key_per_crt_prime,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            encryption_of_decryption_key_base_protocol_context,
            decryption_key_contribution_pvss_party,
        ) = class_groups::dkg::Party::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::prepare_advance(
            session_id,
            tangible_party_id,
            access_structure,
            private_input,
            &public_input.class_groups_public_input,
        )?;

        let equality_of_coefficients_commitments_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal DKG V2".to_string(),
            round_name: "1 - Deal Decryption Key Contribution and Prove Coefficients Commitments"
                .to_string(),
            proof_name: EQUALITY_OF_COEFFICIENTS_COMMITMENTS_PROOF_NAME.to_string(),
        };

        let secp256k1_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal DKG V2".to_string(),
            round_name: "1 - Deal Decryption Key Contribution and Prove Coefficient Commitments"
                .to_string(),
            proof_name: "Encryption of Secp256k1 Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        let ristretto_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal DKG V2".to_string(),
            round_name: "1 - Deal Decryption Key Contribution and Prove Coefficient Commitments"
                .to_string(),
            proof_name: "Encryption of Ristretto Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        let curve25519_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal DKG V2".to_string(),
            round_name: "1 - Deal Decryption Key Contribution and Prove Coefficient Commitments"
                .to_string(),
            proof_name: "Encryption of Curve25519 Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        let secp256r1_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal DKG V2".to_string(),
            round_name: "1 - Deal Decryption Key Contribution and Prove Coefficient Commitments"
                .to_string(),
            proof_name: "Encryption of Secp256r1 Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        let equality_of_coefficients_commitments_language_public_parameters =
            Self::prepare_coefficients_commitments_proof(
                decryption_key_share_bits,
                &public_input.class_groups_public_input.setup_parameters,
                &public_input.ristretto_setup_parameters,
                &public_input.secp256r1_setup_parameters,
            )?;

        match &messages[..] {
            [] => Self::advance_first_round(
                tangible_party_id,
                session_id,
                equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                public_input,
                equality_of_coefficients_commitments_language_public_parameters,
                &decryption_key_contribution_pvss_party,
                equality_of_coefficients_commitments_base_protocol_context,
                rng,
            ),
            [deal_randomizer_and_prove_coefficient_commitments_messages] => {
                Self::advance_second_round(
                    tangible_party_id,
                    access_structure,
                    public_input,
                    &decryption_key_contribution_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    rng,
                )
            }
            [deal_randomizer_and_prove_coefficient_commitments_messages, verified_dealers_messages] => {
                Self::advance_third_round(
                    tangible_party_id,
                    session_id,
                    encryption_of_decryption_key_base_protocol_context,
                    access_structure,
                    equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                    public_input,
                    equality_of_coefficients_commitments_language_public_parameters,
                    &decryption_key_contribution_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    verified_dealers_messages.clone(),
                    decryption_key_per_crt_prime,
                    equality_of_coefficients_commitments_base_protocol_context,
                    secp256k1_encryption_of_secret_key_share_base_protocol_context,
                    ristretto_encryption_of_secret_key_share_base_protocol_context,
                    curve25519_encryption_of_secret_key_share_base_protocol_context,
                    secp256r1_encryption_of_secret_key_share_base_protocol_context,
                    decryption_key_share_bits,
                    rng,
                )
            }
            [deal_randomizer_and_prove_coefficient_commitments_messages, _, threshold_decrypt_messages] => {
                Self::advance_fourth_round(
                    tangible_party_id,
                    session_id,
                    access_structure,
                    encryption_of_decryption_key_base_protocol_context,
                    public_input,
                    &decryption_key_contribution_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    threshold_decrypt_messages.clone(),
                    secp256k1_encryption_of_secret_key_share_base_protocol_context,
                    ristretto_encryption_of_secret_key_share_base_protocol_context,
                    curve25519_encryption_of_secret_key_share_base_protocol_context,
                    secp256r1_encryption_of_secret_key_share_base_protocol_context,
                    decryption_key_share_bits,
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

impl Party {
    /// Generates the public parameters for the equality of coefficients commitments proof,
    /// used to prove the commitments to the coefficients used for the decryption key contribution
    /// are equal under the corresponding `h` base of the class-groups setup for the different groups: secp256k1, ristretto and secp256r1.
    ///
    /// See [`EqualityOfDiscreteLogsInHiddenOrderGroupProof`].
    pub fn prepare_coefficients_commitments_proof(
        secret_share_bits: u32,
        secp256k1_setup_parameters: &Secp256k1SetupParameters,
        ristretto_setup_parameters: &RistrettoSetupParameters,
        secp256r1_setup_parameters: &Secp256r1SetupParameters,
    ) -> crate::Result<
        EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
    > {
        let discrete_log_group_public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound(
                secret_share_bits,
            )?;

        let hidden_order_group_public_parameters = (
            (
                secp256k1_setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
                ristretto_setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
            )
                .into(),
            secp256r1_setup_parameters
                .equivalence_class_public_parameters()
                .clone(),
        )
            .into();

        let base: ThreeWayGroupElement<_, _, _> = (
            (secp256k1_setup_parameters.h, ristretto_setup_parameters.h).into(),
            secp256r1_setup_parameters.h,
        )
            .into();

        let equality_of_discrete_logs_language_public_parameters =
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

        Ok(equality_of_discrete_logs_language_public_parameters)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::construct_setup_parameters_per_crt_prime;
    use class_groups::test_helpers::{
        get_setup_parameters_curve25519_112_bits_deterministic,
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256r1_112_bits_deterministic, setup_dkg_secp256k1,
    };
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;

    #[test]
    fn generates_universal_distributed_key() {
        let threshold = 4;
        let current_party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, current_party_to_weight).unwrap();

        generates_universal_distributed_key_internal(access_structure);
    }

    pub(crate) fn generates_universal_distributed_key_internal(
        access_structure: WeightedThresholdAccessStructure,
    ) -> PublicOutput {
        let ristretto_setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let curve25519_setup_parameters = get_setup_parameters_curve25519_112_bits_deterministic();
        let secp256r1_setup_parameters = get_setup_parameters_secp256r1_112_bits_deterministic();

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let (session_id, private_inputs, public_inputs) =
            setup_dkg_secp256k1(&access_structure, setup_parameters_per_crt_prime, true);

        let class_groups_public_input = public_inputs.values().next().unwrap().clone();

        let public_input = PublicInput {
            class_groups_public_input,
            ristretto_setup_parameters,
            curve25519_setup_parameters,
            secp256r1_setup_parameters,
        };

        let public_inputs = access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| (party_id, public_input.clone()))
            .collect();

        let (_, _, public_output) = asynchronous_session_terminates_successfully_internal::<Party>(
            session_id,
            &access_structure,
            private_inputs,
            public_inputs,
            4,
            HashMap::from([(
                2,
                HashSet::from_iter(
                    1..=(access_structure.number_of_tangible_parties() - 1)
                        .max(access_structure.threshold),
                ),
            )]),
            false,
            true,
        );

        public_output
    }
}
