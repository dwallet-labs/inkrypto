// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;

use itertools::multiunzip;
use serde::{Deserialize, Serialize};

use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::KnowledgeOfDiscreteLogUCProof;
use class_groups::setup::DeriveFromPlaintextPublicParameters;
use class_groups::{
    publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    },
    CompactIbqf, Curve25519SetupParameters, RistrettoSetupParameters,
    Secp256k1DecryptionKeySharePublicParameters, Secp256r1SetupParameters,
    SecretKeyShareSizedInteger, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::helpers::DeduplicateAndSort;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{ristretto, secp256k1, secp256r1, CsRng, GroupElement as _, PartyID};
use mpc::{
    AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages,
    WeightedThresholdAccessStructure,
};

use crate::decentralized_party::dkg::EQUALITY_OF_COEFFICIENTS_COMMITMENTS_PROOF_NAME;
use crate::decentralized_party::reconfiguration::PublicOutput;
use crate::decentralized_party::{dkg, reconfiguration};
use crate::{curve25519, BaseProtocolContext, Error};

pub struct Party {}

/// The Message of the Reconfiguration V1 to V2 protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Message {
    DealRandomizerContributionAndProveCoefficientCommitments(reconfiguration::Message),
    VerifiedRandomizerDealers(reconfiguration::Message),
    ThresholdDecryptShares(reconfiguration::Message),
    EncryptSecretKeyShareShare {
        secp256k1_encryption_of_secret_key_share_share_message: <crate::secp256k1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        ristretto_encryption_of_secret_key_share_share_message: <crate::ristretto::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        curve25519_encryption_of_secret_key_share_share_message: <crate::curve25519::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
        secp256r1_encryption_of_secret_key_share_share_message: <crate::secp256r1::class_groups::EncryptionOfSecretKeyShareParty as mpc::Party>::Message,
    }
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
    ristretto_setup_parameters: RistrettoSetupParameters,
    curve25519_setup_parameters: Curve25519SetupParameters,
    secp256r1_setup_parameters: Secp256r1SetupParameters,
}

impl PublicInput {
    pub fn new(
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
        secp256k1_decryption_key_share_public_parameters: Secp256k1DecryptionKeySharePublicParameters,
        dkg_output: class_groups::dkg::PublicOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
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

        let equality_of_discrete_logs_language_public_parameters =
            dkg::Party::prepare_coefficients_commitments_proof(
                randomizer_share_bits,
                &public_input.class_groups_public_input.setup_parameters,
                &public_input.ristretto_setup_parameters,
                &public_input.secp256r1_setup_parameters,
            )?;

        let equality_of_coefficients_commitments_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal Reconfiguration V1-to-V2"
                .to_string(),
            round_name: "1 - Deal Randomizer Contribution and Prove Coefficients Commitments"
                .to_string(),
            proof_name: EQUALITY_OF_COEFFICIENTS_COMMITMENTS_PROOF_NAME.to_string(),
        };

        let secp256k1_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal Reconfiguration V1-to-V2"
                .to_string(),
            round_name: "1 - Deal Randomizer Contribution and Prove Coefficients Commitments"
                .to_string(),
            proof_name: "Encryption of Secp256k1 Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        let ristretto_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal Reconfiguration V1-to-V2"
                .to_string(),
            round_name: "1 - Deal Randomizer Contribution and Prove Coefficient Commitments"
                .to_string(),
            proof_name: "Encryption of Ristretto Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        let curve25519_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal Reconfiguration V1-to-V2"
                .to_string(),
            round_name: "1 - Deal Randomizer Contribution and Prove Coefficient Commitments"
                .to_string(),
            proof_name: "Encryption of Curve25519 Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        let secp256r1_encryption_of_secret_key_share_base_protocol_context = BaseProtocolContext {
            protocol_name: "2PC-MPC Decentralized Party's Universal Reconfiguration V1-to-V2"
                .to_string(),
            round_name: "1 - Deal Randomizer Contribution and Prove Coefficient Commitments"
                .to_string(),
            proof_name: "Encryption of Secp256r1 Secret Key Share and Public Key Share Proof"
                .to_string(),
        };

        match &messages[..] {
            [] => reconfiguration::Party::advance_first_round_internal(
                tangible_party_id,
                session_id,
                randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                &public_input.class_groups_public_input,
                equality_of_discrete_logs_language_public_parameters,
                &randomizer_contribution_to_upcoming_pvss_party,
                equality_of_coefficients_commitments_base_protocol_context,
                randomizer_contribution_bits,
                rng,
            )
            .map(
                |(malicious_parties, message)| AsynchronousRoundResult::Advance {
                    malicious_parties,
                    message: Message::DealRandomizerContributionAndProveCoefficientCommitments(
                        message,
                    ),
                },
            ),
            [deal_randomizer_and_prove_coefficient_commitments_messages] => {
                // Make sure everyone sent the first round message.
                let (
                    parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
                    deal_randomizer_and_prove_coefficient_commitments_messages,
                ) = deal_randomizer_and_prove_coefficient_commitments_messages
                    .iter()
                    .map(|(&dealer_party_id, message)| {
                        let res = match message {
                            Message::DealRandomizerContributionAndProveCoefficientCommitments(
                                message,
                            ) => Ok(message.clone()),
                            _ => Err(Error::InvalidMessage),
                        };

                        (dealer_party_id, res)
                    })
                    .handle_invalid_messages_async();

                reconfiguration::Party::advance_second_round_internal(
                    tangible_party_id,
                    &public_input.class_groups_public_input,
                    &public_input.ristretto_setup_parameters,
                    &public_input.secp256r1_setup_parameters,
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    rng,
                ).map(|(malicious_parties, message)| {
                    let malicious_parties =
                        malicious_parties
                            .into_iter()
                            .chain(parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages)
                            .deduplicate_and_sort();

                    AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message: Message::VerifiedRandomizerDealers(message)
                    }
                })
            }
            [deal_randomizer_and_prove_coefficient_commitments_messages, verified_dealers_messages] =>
            {
                // Make sure everyone sent the first round message.
                let (
                    parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
                    deal_randomizer_and_prove_coefficient_commitments_messages,
                ) = deal_randomizer_and_prove_coefficient_commitments_messages
                    .iter()
                    .map(|(&dealer_party_id, message)| {
                        let res = match message {
                            Message::DealRandomizerContributionAndProveCoefficientCommitments(
                                message,
                            ) => Ok(message.clone()),
                            _ => Err(Error::InvalidMessage),
                        };

                        (dealer_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Make sure everyone sent the second round message.
                let (parties_sending_invalid_verified_dealers_messages, verified_dealers_messages) =
                    verified_dealers_messages
                        .iter()
                        .map(|(&dealer_party_id, message)| {
                            let res = match message {
                                Message::VerifiedRandomizerDealers(message) => Ok(message.clone()),
                                _ => Err(Error::InvalidMessage),
                            };

                            (dealer_party_id, res)
                        })
                        .handle_invalid_messages_async();

                reconfiguration::Party::advance_third_round_internal(
                    tangible_party_id,
                    session_id,
                    randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
                    current_access_structure,
                    equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                    &public_input.class_groups_public_input,
                    &public_input.ristretto_setup_parameters,
                    &public_input.secp256r1_setup_parameters,
                    equality_of_discrete_logs_language_public_parameters,
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages.clone(),
                    verified_dealers_messages.clone(),
                    decryption_key_shares,
                    equality_of_coefficients_commitments_base_protocol_context,
                    current_decryption_key_share_bits,
                    randomizer_contribution_bits,
                    rng,
                ).map(|(malicious_parties, message)| {
                    let malicious_parties =
                        malicious_parties
                            .into_iter()
                            .chain(parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages)
                            .chain(parties_sending_invalid_verified_dealers_messages)
                            .deduplicate_and_sort();

                    AsynchronousRoundResult::Advance {
                        malicious_parties,
                        message: Message::ThresholdDecryptShares(message)
                    }
                })
            }
            [deal_randomizer_and_prove_coefficient_commitments_messages, _, threshold_decrypt_messages] =>
            {
                // Make sure everyone sent the first round message.
                let (
                    parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
                    deal_randomizer_and_prove_coefficient_commitments_messages,
                ) = deal_randomizer_and_prove_coefficient_commitments_messages
                    .iter()
                    .map(|(&dealer_party_id, message)| {
                        let res = match message {
                            Message::DealRandomizerContributionAndProveCoefficientCommitments(
                                message,
                            ) => Ok(message.clone()),
                            _ => Err(Error::InvalidMessage),
                        };

                        (dealer_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Make sure everyone sent the third round message.
                let (
                    parties_sending_invalid_threshold_decrypt_messages,
                    threshold_decrypt_messages,
                ) = threshold_decrypt_messages
                    .iter()
                    .map(|(&dealer_party_id, message)| {
                        let res = match message {
                            Message::ThresholdDecryptShares(message) => Ok(message.clone()),
                            _ => Err(Error::InvalidMessage),
                        };
                        (dealer_party_id, res)
                    })
                    .handle_invalid_messages_async();

                let (
                    malicious_parties,
                    _,
                    _,
                    ristretto_encryption_key,
                    _,
                    secp256r1_encryption_key,
                ) = reconfiguration::Party::advance_fourth_round_internal(
                    tangible_party_id,
                    session_id,
                    current_access_structure,
                    equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                    &public_input.class_groups_public_input,
                    &public_input.ristretto_setup_parameters,
                    &public_input.secp256r1_setup_parameters,
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages,
                    threshold_decrypt_messages,
                    current_decryption_key_share_bits,
                    rng,
                )?;

                let (
                    secp256k1_encryption_of_secret_key_share_message,
                    ristretto_encryption_of_secret_key_share_message,
                    curve25519_encryption_of_secret_key_share_message,
                    secp256r1_encryption_of_secret_key_share_message,
                ) = dkg::Party::encrypt_secret_key_shares(
                    tangible_party_id,
                    session_id,
                    secp256k1_encryption_of_secret_key_share_base_protocol_context,
                    ristretto_encryption_of_secret_key_share_base_protocol_context,
                    curve25519_encryption_of_secret_key_share_base_protocol_context,
                    secp256r1_encryption_of_secret_key_share_base_protocol_context,
                    public_input
                        .class_groups_public_input
                        .setup_parameters
                        .clone(),
                    public_input.ristretto_setup_parameters.clone(),
                    public_input.curve25519_setup_parameters.clone(),
                    public_input.secp256r1_setup_parameters.clone(),
                    public_input
                        .class_groups_public_input
                        .decryption_key_share_public_parameters
                        .encryption_scheme_public_parameters
                        .encryption_key,
                    ristretto_encryption_key,
                    secp256r1_encryption_key,
                    rng,
                )?;

                let malicious_parties =
                    malicious_parties
                        .into_iter()
                        .chain(parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages)
                        .chain(parties_sending_invalid_threshold_decrypt_messages)
                        .deduplicate_and_sort();

                Ok(AsynchronousRoundResult::Advance {
                    malicious_parties,
                    message: Message::EncryptSecretKeyShareShare {
                        secp256k1_encryption_of_secret_key_share_share_message:
                            secp256k1_encryption_of_secret_key_share_message,
                        ristretto_encryption_of_secret_key_share_share_message:
                            ristretto_encryption_of_secret_key_share_message,
                        curve25519_encryption_of_secret_key_share_share_message:
                            curve25519_encryption_of_secret_key_share_message,
                        secp256r1_encryption_of_secret_key_share_share_message:
                            secp256r1_encryption_of_secret_key_share_message,
                    },
                })
            }
            [deal_randomizer_and_prove_coefficient_commitments_messages, _, threshold_decrypt_messages, encrypt_secret_key_share_share_messages] =>
            {
                // Make sure everyone sent the first round message.
                let (
                    parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
                    deal_randomizer_and_prove_coefficient_commitments_messages,
                ) = deal_randomizer_and_prove_coefficient_commitments_messages
                    .iter()
                    .map(|(&dealer_party_id, message)| {
                        let res = match message {
                            Message::DealRandomizerContributionAndProveCoefficientCommitments(
                                message,
                            ) => Ok(message.clone()),
                            _ => Err(Error::InvalidMessage),
                        };

                        (dealer_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Make sure everyone sent the third round message.
                let (
                    parties_sending_invalid_threshold_decrypt_messages,
                    threshold_decrypt_messages,
                ) = threshold_decrypt_messages
                    .iter()
                    .map(|(&dealer_party_id, message)| {
                        let res = match message {
                            Message::ThresholdDecryptShares(message) => Ok(message.clone()),
                            _ => Err(Error::InvalidMessage),
                        };
                        (dealer_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Make sure everyone sent the fourth round message.
                let (
                    parties_sending_invalid_encrypt_secret_key_share_share_messages,
                    encrypt_secret_key_share_share_messages,
                ) = encrypt_secret_key_share_share_messages
                    .iter()
                    .map(|(&dealer_party_id, message)| {
                        let res = match message {
                            Message::EncryptSecretKeyShareShare {
                                secp256k1_encryption_of_secret_key_share_share_message:
                                    secp256k1_encryption_of_secret_key_share_message,
                                ristretto_encryption_of_secret_key_share_share_message:
                                    ristretto_encryption_of_secret_key_share_message,
                                curve25519_encryption_of_secret_key_share_share_message:
                                    curve25519_encryption_of_secret_key_share_message,
                                secp256r1_encryption_of_secret_key_share_share_message:
                                    secp256r1_encryption_of_secret_key_share_message,
                            } => Ok((
                                secp256k1_encryption_of_secret_key_share_message.clone(),
                                ristretto_encryption_of_secret_key_share_message.clone(),
                                curve25519_encryption_of_secret_key_share_message.clone(),
                                secp256r1_encryption_of_secret_key_share_message.clone(),
                            )),
                            _ => Err(Error::InvalidMessage),
                        };
                        (dealer_party_id, res)
                    })
                    .handle_invalid_messages_async();

                let (
                    secp256k1_encryption_of_secret_key_shares_messages,
                    ristretto_encryption_of_secret_key_shares_messages,
                    curve25519_encryption_of_secret_key_shares_messages,
                    secp256r1_encryption_of_secret_key_shares_messages,
                ): (HashMap<_, _>, HashMap<_, _>, HashMap<_, _>, HashMap<_, _>) =
                    multiunzip(encrypt_secret_key_share_share_messages.into_iter().map(
                        |(
                            dealer_party_id,
                            (
                                secp256k1_encryption_of_secret_key_share_message,
                                ristretto_encryption_of_secret_key_share_message,
                                curve25519_encryption_of_secret_key_share_message,
                                secp256r1_encryption_of_secret_key_share_message,
                            ),
                        )| {
                            (
                                (
                                    dealer_party_id,
                                    secp256k1_encryption_of_secret_key_share_message,
                                ),
                                (
                                    dealer_party_id,
                                    ristretto_encryption_of_secret_key_share_message,
                                ),
                                (
                                    dealer_party_id,
                                    curve25519_encryption_of_secret_key_share_message,
                                ),
                                (
                                    dealer_party_id,
                                    secp256r1_encryption_of_secret_key_share_message,
                                ),
                            )
                        },
                    ));

                // I am re-running the round logic instead of majority voting values,
                // its safe since its deterministic and uses same inputs; we don't care about performance,
                // as this protocol runs just once.
                let (
                    malicious_parties,
                    inner_protocol_public_output,
                    ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
                    ristretto_encryption_key,
                    secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
                    secp256r1_encryption_key,
                ) = reconfiguration::Party::advance_fourth_round_internal(
                    tangible_party_id,
                    session_id,
                    current_access_structure,
                    equality_of_discrete_log_in_hidden_order_group_base_protocol_context,
                    &public_input.class_groups_public_input,
                    &public_input.ristretto_setup_parameters,
                    &public_input.secp256r1_setup_parameters,
                    &randomizer_contribution_to_upcoming_pvss_party,
                    deal_randomizer_and_prove_coefficient_commitments_messages,
                    threshold_decrypt_messages,
                    current_decryption_key_share_bits,
                    rng,
                )?;

                let (
                    malicious_encryption_of_secret_key_shares_parties,
                    secp256k1_encryption_of_secret_key_share_first_part,
                    secp256k1_encryption_of_secret_key_share_second_part,
                    secp256k1_public_key_share_first_part,
                    secp256k1_public_key_share_second_part,
                    ristretto_encryption_of_secret_key_share_first_part,
                    ristretto_encryption_of_secret_key_share_second_part,
                    ristretto_public_key_share_first_part,
                    ristretto_public_key_share_second_part,
                    curve25519_encryption_of_secret_key_share_first_part,
                    curve25519_encryption_of_secret_key_share_second_part,
                    curve25519_public_key_share_first_part,
                    curve25519_public_key_share_second_part,
                    secp256r1_encryption_of_secret_key_share_first_part,
                    secp256r1_encryption_of_secret_key_share_second_part,
                    secp256r1_public_key_share_first_part,
                    secp256r1_public_key_share_second_part,
                ) = dkg::Party::verify_and_aggregate_encryptions_of_secret_key_shares(
                    session_id,
                    current_access_structure,
                    secp256k1_encryption_of_secret_key_share_base_protocol_context,
                    ristretto_encryption_of_secret_key_share_base_protocol_context,
                    curve25519_encryption_of_secret_key_share_base_protocol_context,
                    secp256r1_encryption_of_secret_key_share_base_protocol_context,
                    public_input
                        .class_groups_public_input
                        .setup_parameters
                        .clone(),
                    public_input.ristretto_setup_parameters.clone(),
                    public_input.curve25519_setup_parameters.clone(),
                    public_input.secp256r1_setup_parameters.clone(),
                    public_input
                        .class_groups_public_input
                        .decryption_key_share_public_parameters
                        .encryption_scheme_public_parameters
                        .encryption_key,
                    ristretto_encryption_key,
                    secp256r1_encryption_key,
                    secp256k1_encryption_of_secret_key_shares_messages,
                    ristretto_encryption_of_secret_key_shares_messages,
                    curve25519_encryption_of_secret_key_shares_messages,
                    secp256r1_encryption_of_secret_key_shares_messages,
                    rng,
                )?;

                let malicious_parties =
                    malicious_parties
                        .into_iter()
                        .chain(parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages)
                        .chain(parties_sending_invalid_threshold_decrypt_messages)
                        .chain(parties_sending_invalid_encrypt_secret_key_share_share_messages)
                        .chain(malicious_encryption_of_secret_key_shares_parties)
                        .deduplicate_and_sort();

                let public_output = PublicOutput::new(
                    inner_protocol_public_output,
                    secp256k1_encryption_of_secret_key_share_first_part,
                    secp256k1_encryption_of_secret_key_share_second_part,
                    secp256k1_public_key_share_first_part,
                    secp256k1_public_key_share_second_part,
                    ristretto_encryption_of_secret_key_share_first_part,
                    ristretto_encryption_of_secret_key_share_second_part,
                    ristretto_public_key_share_first_part,
                    ristretto_public_key_share_second_part,
                    ristretto_encryption_key.value(),
                    ristretto_reconstructed_commitments_to_randomizer_contribution_sharing,
                    curve25519_encryption_of_secret_key_share_first_part,
                    curve25519_encryption_of_secret_key_share_second_part,
                    curve25519_public_key_share_first_part,
                    curve25519_public_key_share_second_part,
                    secp256r1_encryption_of_secret_key_share_first_part,
                    secp256r1_encryption_of_secret_key_share_second_part,
                    secp256r1_public_key_share_first_part,
                    secp256r1_public_key_share_second_part,
                    secp256r1_encryption_key.value(),
                    secp256r1_reconstructed_commitments_to_randomizer_contribution_sharing,
                    public_input.ristretto_setup_parameters.h,
                    public_input.secp256r1_setup_parameters.h,
                    &public_input
                        .class_groups_public_input
                        .upcoming_access_structure,
                )?;

                Ok(AsynchronousRoundResult::Finalize {
                    malicious_parties,
                    private_output: (),
                    public_output,
                })
            }
            _ => Err(Error::InvalidParameters),
        }
    }

    fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
        match failed_round {
            3 => Some(1),
            4 => Some(3),
            5 => Some(4),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use class_groups::dkg::test_helpers::mock_dkg_output;
    use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::construct_setup_parameters_per_crt_prime;
    use class_groups::test_helpers::{
        deal_trusted_shares, get_setup_parameters_secp256k1_112_bits_deterministic,
        setup_reconfig_secp256k1,
    };
    use class_groups::Secp256k1DecryptionKey;
    use group::OsCsRng;
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;

    #[test]
    fn reconfigures_v1_to_v2() {
        let current_party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);
        let upcoming_party_to_weight = HashMap::from([(1, 2), (2, 2), (3, 2), (4, 1), (5, 1)]);
        let upcoming2_party_to_weight = HashMap::from([(1, 2), (2, 2), (3, 4), (4, 1)]);

        let current_access_structure =
            WeightedThresholdAccessStructure::new(4, current_party_to_weight).unwrap();

        let upcoming_access_structure =
            WeightedThresholdAccessStructure::new(6, upcoming_party_to_weight).unwrap();

        let current_tangible_party_id_to_upcoming =
            HashMap::from([(1, Some(2)), (2, None), (3, Some(3))]);

        let upcoming2_access_structure =
            WeightedThresholdAccessStructure::new(7, upcoming2_party_to_weight).unwrap();

        let upcoming_tangible_party_id_to_upcoming2 =
            HashMap::from([(1, Some(1)), (2, None), (3, None), (4, Some(2)), (5, None)]);

        reconfigures_v1_to_v2_internal(
            current_access_structure,
            upcoming_access_structure,
            upcoming2_access_structure,
            current_tangible_party_id_to_upcoming,
            upcoming_tangible_party_id_to_upcoming2,
            false,
        )
    }

    pub(crate) fn reconfigures_v1_to_v2_internal(
        current_access_structure: WeightedThresholdAccessStructure,
        upcoming_access_structure: WeightedThresholdAccessStructure,
        upcoming2_access_structure: WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        upcoming_tangible_party_id_to_upcoming2: HashMap<PartyID, Option<PartyID>>,
        bench: bool,
    ) {
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

        let (session_id, private_inputs, upcoming_decryption_keys, public_inputs) =
            setup_reconfig_secp256k1(
                &current_access_structure,
                &upcoming_access_structure,
                current_tangible_party_id_to_upcoming.clone(),
                secp256k1_encryption_scheme_public_parameters.clone(),
                secp256k1_decryption_key,
                secp256k1_decryption_key_share_public_parameters,
                secp256k1_decryption_key_shares.clone(),
                dkg_output.clone(),
                setup_parameters_per_crt_prime.clone(),
                true,
            );

        let ristretto_setup_parameters =
            RistrettoSetupParameters::derive_from_plaintext_parameters::<ristretto::Scalar>(
                ristretto::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let curve25519_setup_parameters =
            Curve25519SetupParameters::derive_from_plaintext_parameters::<curve25519::Scalar>(
                group::curve25519::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let secp256r1_setup_parameters =
            Secp256r1SetupParameters::derive_from_plaintext_parameters::<secp256r1::Scalar>(
                secp256r1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let class_groups_public_input = public_inputs.values().next().unwrap().clone();

        let public_input = PublicInput {
            class_groups_public_input: class_groups_public_input.clone(),
            ristretto_setup_parameters,
            curve25519_setup_parameters,
            secp256r1_setup_parameters,
        };

        let public_inputs = current_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| (party_id, public_input.clone()))
            .collect();

        // do v1 to v2
        let (_, _, public_output) = asynchronous_session_terminates_successfully_internal::<Party>(
            session_id,
            &current_access_structure,
            private_inputs,
            public_inputs,
            5,
            HashMap::new(),
            bench,
            true,
        );

        // Now do v2
        // Switch the order: we are after first reconfiguration, so the upcoming is now the current.

        let secp256k1_decryption_key_shares: HashMap<_, _> = upcoming_decryption_keys
            .into_iter()
            .map(|(tangible_party_id, decryption_key_per_crt_prime)| {
                (
                    tangible_party_id,
                    public_output
                        .decrypt_decryption_key_shares(
                            tangible_party_id,
                            &upcoming_access_structure,
                            decryption_key_per_crt_prime,
                        )
                        .unwrap(),
                )
            })
            .collect();

        let encryption_key_value_and_proof_per_crt_prime = class_groups_public_input
            .upcoming_encryption_key_values_and_proofs_per_crt_prime
            .values()
            .next()
            .unwrap()
            .clone();
        let upcoming_encryption_key_values_and_proofs_per_crt_prime = upcoming2_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| {
                (
                    party_id,
                    encryption_key_value_and_proof_per_crt_prime.clone(),
                )
            })
            .collect();

        let public_input = reconfiguration::PublicInput::new_from_reconfiguration_output(
            &upcoming_access_structure,
            upcoming2_access_structure,
            class_groups_public_input.upcoming_encryption_key_values_and_proofs_per_crt_prime,
            upcoming_encryption_key_values_and_proofs_per_crt_prime,
            upcoming_tangible_party_id_to_upcoming2,
            dkg_output,
            public_output,
        )
        .unwrap();

        let public_inputs = upcoming_access_structure
            .party_to_weight
            .keys()
            .map(|&party_id| (party_id, public_input.clone()))
            .collect();

        let (_, _, _) =
            asynchronous_session_terminates_successfully_internal::<reconfiguration::Party>(
                session_id,
                &upcoming_access_structure,
                secp256k1_decryption_key_shares,
                public_inputs,
                4,
                HashMap::new(),
                bench,
                true,
            );
    }
}
