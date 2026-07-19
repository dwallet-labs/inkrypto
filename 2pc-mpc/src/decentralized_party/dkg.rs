// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

mod fifth_round;
mod first_round;
mod fourth_round;
mod public_output;
mod second_round;
mod seventh_round;
mod sixth_round;
mod third_round;

use crate::languages::{
    construct_equality_of_discrete_log_public_parameters,
    EqualityOfDiscreteLogsInHiddenOrderGroupProof,
    EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters,
};
use crate::{Error, ErrorKind};
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::KnowledgeOfDiscreteLogUCProof;
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    },
    CiphertextSpaceValue, CompactIbqf, Curve25519SetupParameters, EquivalenceClass,
    RistrettoSetupParameters, Secp256k1SetupParameters, Secp256r1SetupParameters,
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use commitment::CommitmentSizedNumber;
use crypto_bigint::Uint;
use group::direct_product::ThreeWayGroupElement;
use group::{
    bounded_integers_group, curve25519, direct_product, ristretto, secp256k1, secp256r1, CsRng,
    GroupElement as _, PartyID,
};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::BaseProtocolContext;
pub use public_output::{NonAggregatedPublicOutput, PublicOutput, PublicOutputCore};

#[cfg(not(feature = "unsafe_mock"))]
pub struct Party {}
/// INSECURE `unsafe_mock`: the real multi-round, multi-CRT-prime network DKG party is replaced by an
/// instant mock that finalizes with the canonical `NETWORK_KEY_SEED` output.
#[cfg(feature = "unsafe_mock")]
pub use crate::mock::network_dkg::MockNetworkDKGParty as Party;

/// Private input for the DKG protocol.
///
/// Contains the party's CRT decryption key for the class groups threshold decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateInput {
    /// Decryption key per CRT prime for class groups threshold decryption.
    pub decryption_key_per_crt_prime: [Uint<
        {
            class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS
        },
    >; MAX_PRIMES],
}

/// The deterministic output of CG DKG Round 4 computation.
///
/// All parties compute this identically from broadcast R1 and R3 messages.
/// It is sent in the `VerifiedDealers` message and majority-voted in R5/R6.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FourthRoundInternalOutput {
    pub(crate) inner_protocol_public_output: class_groups::dkg::PublicOutput<
        { secp256k1::SCALAR_LIMBS },
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    pub(crate) ristretto_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    pub(crate) ristretto_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256r1_public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    pub(crate) secp256r1_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256k1_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256k1_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256k1_public_key_share_first_part: secp256k1::group_element::Value,
    pub(crate) secp256k1_public_key_share_second_part: secp256k1::group_element::Value,
    pub(crate) ristretto_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) ristretto_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) ristretto_public_key_share_first_part: ristretto::GroupElement,
    pub(crate) ristretto_public_key_share_second_part: ristretto::GroupElement,
    pub(crate) curve25519_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) curve25519_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) curve25519_public_key_share_first_part: curve25519::Value,
    pub(crate) curve25519_public_key_share_second_part: curve25519::Value,
    pub(crate) secp256r1_encryption_of_secret_key_share_first_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256r1_encryption_of_secret_key_share_second_part:
        CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) secp256r1_public_key_share_first_part: secp256r1::group_element::Value,
    pub(crate) secp256r1_public_key_share_second_part: secp256r1::group_element::Value,
}

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
    SECRET_KEY_SHARE_WITNESS_LIMBS,
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
            { secp256k1::SCALAR_LIMBS },
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
            { secp256k1::SCALAR_LIMBS },
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ),
    EncryptDecryptionKeySharesAndSecretKeyShares {
        encrypt_decryption_key_shares_message: class_groups::dkg::Message<
            { secp256k1::SCALAR_LIMBS },
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        malicious_coefficients_committers: HashSet<PartyID>,
        secp256k1_encryption_of_secret_key_shares_message: <crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        ristretto_encryption_of_secret_key_shares_message: <crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        curve25519_encryption_of_secret_key_shares_message: <crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        secp256r1_encryption_of_secret_key_shares_message: <crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
    },
    VerifiedDealers {
        fourth_round_output: FourthRoundInternalOutput,
        threshold_encryption_of_secret_key_share_parts_to_sharing_dealing_message:
            crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::DealingRoundMessage,
    },
    AccusedDealers {
        threshold_encryption_of_secret_key_share_parts_to_sharing_accusation_message:
            crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::AccusationRoundMessage,
    },
    ThresholdDecryptSecretKeyShares {
        threshold_encryption_of_secret_key_share_parts_to_sharing_decryption_round_message:
            crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::ThresholdDecryptionRoundMessage,
    },
}

/// The Public Input of the DKG party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicInput {
    pub access_structure: WeightedThresholdAccessStructure,
    class_groups_public_input: class_groups::dkg::PublicInput<
        { secp256k1::SCALAR_LIMBS },
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<secp256k1::Scalar>,
    >,
    ristretto_setup_parameters: RistrettoSetupParameters,
    curve25519_setup_parameters: Curve25519SetupParameters,
    secp256r1_setup_parameters: Secp256r1SetupParameters,
    // Protocol 0.1: PVSS encryption keys for randomizer dealing
    secp256k1_pvss_encryption_keys_and_proofs: HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
    ristretto_pvss_encryption_keys_and_proofs: HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
    secp256r1_pvss_encryption_keys_and_proofs: HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                {
                    class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                },
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
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
        secp256k1_pvss_encryption_keys_and_proofs: HashMap<
            PartyID,
            (
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            ),
        >,
        ristretto_pvss_encryption_keys_and_proofs: HashMap<
            PartyID,
            (
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            ),
        >,
        secp256r1_pvss_encryption_keys_and_proofs: HashMap<
            PartyID,
            (
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            ),
        >,
        backward_compatible: bool,
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
                backward_compatible,
            )?;

        Ok(Self {
            access_structure: access_structure.clone(),
            class_groups_public_input,
            ristretto_setup_parameters,
            curve25519_setup_parameters,
            secp256r1_setup_parameters,
            secp256k1_pvss_encryption_keys_and_proofs,
            ristretto_pvss_encryption_keys_and_proofs,
            secp256r1_pvss_encryption_keys_and_proofs,
        })
    }
}

#[cfg(not(feature = "unsafe_mock"))]
impl mpc::Party for Party {
    type Error = Error;
    type PublicInput = PublicInput;
    type PrivateOutput = ();
    type PublicOutputValue = PublicOutput;
    type PublicOutput = Self::PublicOutputValue;
    type Message = Message;
}

#[cfg(not(feature = "unsafe_mock"))]
impl AsynchronouslyAdvanceable for Party {
    type PrivateInput = PrivateInput;

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
        // Extract CRT decryption key from PrivateInput
        let decryption_key_per_crt_prime_option =
            private_input.map(|input| input.decryption_key_per_crt_prime);

        let (
            decryption_key_share_bits,
            decryption_key_per_crt_prime,
            equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
            encryption_of_decryption_key_base_protocol_context,
            decryption_key_contribution_pvss_party,
        ) = class_groups::dkg::Party::<
            { secp256k1::SCALAR_LIMBS },
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >::prepare_advance(
            session_id,
            tangible_party_id,
            access_structure,
            decryption_key_per_crt_prime_option,
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
                public_input.class_groups_public_input.backward_compatible,
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
            [deal_randomizer_and_prove_coefficient_commitments_messages, _, encrypt_messages] => {
                Self::advance_fourth_round(
                    tangible_party_id,
                    session_id,
                    access_structure,
                    encryption_of_decryption_key_base_protocol_context,
                    public_input,
                    &decryption_key_contribution_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    encrypt_messages.clone(),
                    secp256k1_encryption_of_secret_key_share_base_protocol_context,
                    ristretto_encryption_of_secret_key_share_base_protocol_context,
                    curve25519_encryption_of_secret_key_share_base_protocol_context,
                    secp256r1_encryption_of_secret_key_share_base_protocol_context,
                    decryption_key_share_bits,
                    rng,
                )
            }
            [_, _, _, verified_dealers_messages] => Self::advance_fifth_round(
                tangible_party_id,
                session_id,
                access_structure,
                public_input,
                verified_dealers_messages.clone(),
                rng,
            ),
            [_, _, _, verified_dealers_messages, accused_dealers_messages] => {
                Self::advance_sixth_round(
                    tangible_party_id,
                    session_id,
                    access_structure,
                    public_input,
                    verified_dealers_messages.clone(),
                    accused_dealers_messages.clone(),
                    decryption_key_per_crt_prime,
                    rng,
                )
            }
            [_, _, _, verified_dealers_messages, _, threshold_decrypt_messages] => {
                Self::advance_seventh_round(
                    access_structure,
                    public_input,
                    verified_dealers_messages.clone(),
                    threshold_decrypt_messages.clone(),
                    rng,
                )
            }
            _ => Err(Error::from(ErrorKind::InvalidParameters)),
        }
    }

    fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
        match failed_round {
            3 => Some(1),
            4 => Some(3),
            5 => Some(4),
            6 => Some(5),
            7 => Some(6),
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
        backward_compatible: bool,
        secp256k1_setup_parameters: &Secp256k1SetupParameters,
        ristretto_setup_parameters: &RistrettoSetupParameters,
        secp256r1_setup_parameters: &Secp256r1SetupParameters,
    ) -> crate::Result<
        EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
    > {
        // The bounds public parameters are transcribed whole into Fiat–Shamir. Under
        // `backward_compatible` we select the `-10` relaxed bound the deployed network (inkrypto
        // `37bb549f`) uses; otherwise the strict bound. A mismatch makes peers reject the proof and
        // flag the dealer malicious.
        let discrete_log_group_public_parameters =
            bounded_integers_group::PublicParameters::new_with_randomizer_upper_bound_selected(
                secret_share_bits,
                backward_compatible,
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
                SECRET_KEY_SHARE_WITNESS_LIMBS,
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

    /// Performs a weighted majority vote on `FourthRoundInternalOutput` values.
    ///
    /// Groups parties by their output, selects the group with the highest total weight,
    /// and returns the majority output along with the list of disagreeing (malicious) parties.
    pub(crate) fn majority_vote_fourth_round_output(
        outputs: HashMap<PartyID, FourthRoundInternalOutput>,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> crate::Result<(FourthRoundInternalOutput, Vec<PartyID>)> {
        let groups = outputs.into_iter().fold(
            Vec::<(FourthRoundInternalOutput, Vec<PartyID>)>::new(),
            |mut acc, (party_id, output)| {
                match acc.iter_mut().find(|(ref_output, _)| *ref_output == output) {
                    Some(group) => group.1.push(party_id),
                    None => acc.push((output, vec![party_id])),
                }
                acc
            },
        );

        let (majority_idx, _) = groups
            .iter()
            .enumerate()
            .max_by_key(|(_, (_, parties))| -> mpc::Weight {
                parties
                    .iter()
                    .filter_map(|p| access_structure.party_to_weight.get(p).copied())
                    .sum()
            })
            .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;

        let malicious_parties: Vec<PartyID> = groups
            .iter()
            .enumerate()
            .filter(|&(idx, _)| idx != majority_idx)
            .flat_map(|(_, (_, parties))| parties.iter().copied())
            .collect();

        let majority_output = groups
            .into_iter()
            .nth(majority_idx)
            .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?
            .0;

        Ok((majority_output, malicious_parties))
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod tests {
    use super::*;
    use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::construct_setup_parameters_per_crt_prime;
    #[cfg(test)]
    use class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::generate_and_prove_encryption_keypair;
    #[cfg(test)]
    use class_groups::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use class_groups::test_helpers::{
        get_setup_parameters_curve25519_112_bits_deterministic,
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256r1_112_bits_deterministic, setup_dkg_secp256k1,
    };
    use class_groups::DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER;
    #[cfg(test)]
    use class_groups::SECRET_KEY_SHARE_SIZE_UPPER_BOUND;
    #[cfg(test)]
    use group::bounded_natural_numbers_group::MAURER_PROOFS_DIFF_UPPER_BOUND_BITS;
    #[cfg(test)]
    use group::OsCsRng;
    #[cfg(test)]
    use itertools::multiunzip;
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;
    #[cfg(test)]
    use proof::GroupsPublicParametersAccessors;

    #[cfg(test)]
    fn generates_universal_distributed_key_with_mode(backward_compatible: bool) {
        let threshold = 3;
        let number_of_parties = 5;

        let access_structure = WeightedThresholdAccessStructure::uniform(
            threshold,
            number_of_parties,
            number_of_parties,
            &mut OsCsRng,
        )
        .unwrap();

        let secp256k1_setup_parameters_for_pvss =
            class_groups::Secp256k1SetupParameters::derive_from_plaintext_parameters::<
                secp256k1::Scalar,
            >(
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let ristretto_setup_parameters_for_pvss =
            class_groups::RistrettoSetupParameters::derive_from_plaintext_parameters::<
                ristretto::Scalar,
            >(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let secp256r1_setup_parameters_for_pvss =
            class_groups::Secp256r1SetupParameters::derive_from_plaintext_parameters::<
                secp256r1::Scalar,
            >(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let (
            secp256k1_pvss_encryption_keys_and_proofs,
            ristretto_pvss_encryption_keys_and_proofs,
            secp256r1_pvss_encryption_keys_and_proofs,
        ): (HashMap<_, _>, HashMap<_, _>, HashMap<_, _>) = multiunzip(
            access_structure.party_to_weight.keys().map(|&party_id| {
                let (secp256k1_key, secp256k1_proof, _) = generate_and_prove_encryption_keypair::<
                    { secp256k1::SCALAR_LIMBS },
                    { class_groups::SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U1024::LIMBS },
                    { class_groups::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crypto_bigint::U4096::LIMBS },
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    secp256k1::GroupElement,
                >(&secp256k1_setup_parameters_for_pvss, &mut OsCsRng)
                .unwrap();

                let (ristretto_key, ristretto_proof, _) =
                    generate_and_prove_encryption_keypair::<
                        { ristretto::SCALAR_LIMBS },
                        { class_groups::RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                        { crypto_bigint::U1024::LIMBS },
                        { class_groups::RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                        { crypto_bigint::U4096::LIMBS },
                        {
                            class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                        },
                        ristretto::GroupElement,
                    >(&ristretto_setup_parameters_for_pvss, &mut OsCsRng)
                    .unwrap();

                let (secp256r1_key, secp256r1_proof, _) =
                    generate_and_prove_encryption_keypair::<
                        { secp256r1::SCALAR_LIMBS },
                        { class_groups::SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                        { crypto_bigint::U1024::LIMBS },
                        { class_groups::SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                        { crypto_bigint::U4096::LIMBS },
                        {
                            class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                        },
                        secp256r1::GroupElement,
                    >(&secp256r1_setup_parameters_for_pvss, &mut OsCsRng)
                    .unwrap();

                (
                    (party_id, (secp256k1_key, secp256k1_proof)),
                    (party_id, (ristretto_key, ristretto_proof)),
                    (party_id, (secp256r1_key, secp256r1_proof)),
                )
            }),
        );

        generates_universal_distributed_key_internal(
            access_structure,
            secp256k1_pvss_encryption_keys_and_proofs,
            ristretto_pvss_encryption_keys_and_proofs,
            secp256r1_pvss_encryption_keys_and_proofs,
            backward_compatible,
        );
    }

    #[test]
    fn generates_universal_distributed_key() {
        generates_universal_distributed_key_with_mode(false);
    }

    /// TEMPORARY (remove with the rest of the `backward_compatible` mechanism, once the network has
    /// fully migrated off the inkrypto `37bb549f` wire format): the whole DKG must also complete in
    /// `backward_compatible = true` mode, i.e. with every discrete-log bound selecting the `-10`
    /// relaxed variant. This proves the flag is threaded consistently to every proof site — a
    /// `false` leak at any site would desync the Fiat–Shamir transcript and flag a party malicious.
    #[test]
    fn generates_universal_distributed_key_backward_compatible() {
        generates_universal_distributed_key_with_mode(true);
    }

    pub fn generates_universal_distributed_key_internal(
        access_structure: WeightedThresholdAccessStructure,
        secp256k1_pvss_encryption_keys_and_proofs: HashMap<
            PartyID,
            (
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            ),
        >,
        ristretto_pvss_encryption_keys_and_proofs: HashMap<
            PartyID,
            (
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            ),
        >,
        secp256r1_pvss_encryption_keys_and_proofs: HashMap<
            PartyID,
            (
                CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                class_groups::publicly_verifiable_secret_sharing::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof<
                    {
                        class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS
                    },
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            ),
        >,
        backward_compatible: bool,
    ) -> PublicOutput {
        let ristretto_setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let curve25519_setup_parameters = get_setup_parameters_curve25519_112_bits_deterministic();
        let secp256r1_setup_parameters = get_setup_parameters_secp256r1_112_bits_deterministic();

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let (session_id, crt_private_inputs, public_inputs) =
            setup_dkg_secp256k1(&access_structure, setup_parameters_per_crt_prime, true);

        let mut class_groups_public_input = public_inputs.values().next().unwrap().clone();
        // TEMPORARY (remove with the rest of the `backward_compatible` mechanism): exercise the
        // `-10` deployed-network bound end-to-end.
        class_groups_public_input.backward_compatible = backward_compatible;

        let private_inputs: HashMap<PartyID, PrivateInput> = crt_private_inputs
            .into_iter()
            .map(|(party_id, decryption_key_per_crt_prime)| {
                (
                    party_id,
                    PrivateInput {
                        decryption_key_per_crt_prime,
                    },
                )
            })
            .collect();

        let public_input = PublicInput {
            class_groups_public_input,
            ristretto_setup_parameters,
            curve25519_setup_parameters,
            secp256r1_setup_parameters,
            secp256k1_pvss_encryption_keys_and_proofs,
            ristretto_pvss_encryption_keys_and_proofs,
            secp256r1_pvss_encryption_keys_and_proofs,
            access_structure: access_structure.clone(),
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
            7,
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

    /// Regression: the equality-of-coefficients proof must be constructible over
    /// `SECRET_KEY_SHARE_WITNESS_LIMBS` (48) at the largest supported committee, where
    /// `sample_bits = SECRET_KEY_SHARE_SIZE_UPPER_BOUND`. This mirrors the live-network bound used
    /// by `prepare_coefficients_commitments_proof` (`new_with_randomizer_upper_bound_backward_compatible`,
    /// i.e. `sample_bits + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS - 10`). The 32-limb witness group
    /// cannot hold that upper bound at this size and fails with `InvalidPublicParameters` — the bug
    /// the 48-limb widening fixes.
    #[cfg(test)]
    #[test]
    fn equality_of_coefficients_bound_holds_for_largest_committee() {
        let sample_bits = SECRET_KEY_SHARE_SIZE_UPPER_BOUND;

        assert!(
            bounded_integers_group::PublicParameters::<SECRET_KEY_SHARE_WITNESS_LIMBS>::new_with_randomizer_upper_bound_backward_compatible(
                sample_bits,
            )
            .is_ok(),
            "the 48-limb witness group must accommodate the live-network bound at the largest committee"
        );

        assert!(
            bounded_integers_group::PublicParameters::<SECRET_KEY_SHARE_LIMBS>::new_with_randomizer_upper_bound_backward_compatible(
                sample_bits,
            )
            .is_err(),
            "the 32-limb witness group cannot hold the live-network bound at the largest committee (the regression)"
        );
    }

    /// Path-level pin: `prepare_coefficients_commitments_proof` must transcribe the `-10` relaxed
    /// upper bound under `backward_compatible = true` (matching the deployed network, inkrypto
    /// `37bb549f`) and the strict bound under `false`. The integration tests are self-consistent
    /// (prover and verifier share parameters) so they pass under *any* matched bound; this asserts
    /// the actual value produced per mode, catching a silent drift of the selector — exactly the
    /// kind of drift that flagged upgraded nodes as malicious in reconfiguration round 1.
    #[cfg(test)]
    #[test]
    fn live_path_equality_of_coefficients_bound_pinned() {
        let sample_bits = 1000u32;

        let language_public_parameters = |backward_compatible| {
            Party::prepare_coefficients_commitments_proof(
                sample_bits,
                backward_compatible,
                &get_setup_parameters_secp256k1_112_bits_deterministic(),
                &get_setup_parameters_ristretto_112_bits_deterministic(),
                &get_setup_parameters_secp256r1_112_bits_deterministic(),
            )
            .unwrap()
        };

        assert_eq!(
            language_public_parameters(true)
                .witness_space_public_parameters()
                .upper_bound_bits,
            sample_bits + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS - 10
        );
        assert_eq!(
            language_public_parameters(false)
                .witness_space_public_parameters()
                .upper_bound_bits,
            sample_bits + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS
        );
        assert_eq!(
            language_public_parameters(true)
                .witness_space_public_parameters()
                .sample_bits,
            sample_bits
        );
    }
}
