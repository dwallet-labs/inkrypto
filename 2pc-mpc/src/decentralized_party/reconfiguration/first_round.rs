// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use super::{EqualityOfCoefficientsCommitmentsProof, PublicInput};
use crate::decentralized_party::reconfiguration::Message;
use crate::decentralized_party::reconfiguration::PublicOutput;
use crate::languages::EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters;
use crate::{decentralized_party::dkg, Error, Result};
use class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::NUM_SECRET_SHARE_PRIMES;
use class_groups::{
    publicly_verifiable_secret_sharing, EquivalenceClass, RistrettoSetupParameters,
    Secp256k1SetupParameters, Secp256r1SetupParameters,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use commitment::CommitmentSizedNumber;
use group::direct_product::ThreeWayGroupElement;
use group::secp256k1::{GroupElement, Scalar, SCALAR_LIMBS};
use group::{CsRng, GroupElement as _, PartyID};
use mpc::{AsynchronousRoundResult, HandleInvalidMessages};
use std::collections::HashMap;

impl super::Party {
    pub(crate) fn advance_first_round(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        randomizer_contribution_to_threshold_encryption_key_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        public_input: &PublicInput,
        equality_of_coefficients_commitments_language_public_parameters: EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        equality_of_coefficients_commitments_base_protocol_context: crate::BaseProtocolContext,
        randomizer_contribution_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<AsynchronousRoundResult<Message, (), PublicOutput>> {
        Self::advance_first_round_internal(
            tangible_party_id,
            session_id,
            randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
            &public_input.class_groups_public_input,
            equality_of_coefficients_commitments_language_public_parameters,
            randomizer_contribution_to_upcoming_pvss_party,
            equality_of_coefficients_commitments_base_protocol_context,
            randomizer_contribution_bits,
            rng,
        )
        .map(
            |(malicious_parties, message)| AsynchronousRoundResult::Advance {
                malicious_parties,
                message,
            },
        )
    }

    pub(crate) fn advance_first_round_internal(
        tangible_party_id: PartyID,
        session_id: CommitmentSizedNumber,
        randomizer_contribution_to_threshold_encryption_key_base_protocol_context: publicly_verifiable_secret_sharing::BaseProtocolContext,
        class_groups_public_input: &class_groups::reconfiguration::PublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<Scalar>,
        >,
        equality_of_coefficients_commitments_language_public_parameters: EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
            SECRET_KEY_SHARE_LIMBS,
            ThreeWayGroupElement<
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
        randomizer_contribution_to_upcoming_pvss_party: &publicly_verifiable_secret_sharing::Party<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        equality_of_coefficients_commitments_base_protocol_context: crate::BaseProtocolContext,
        randomizer_contribution_bits: u32,
        rng: &mut impl CsRng,
    ) -> Result<(Vec<PartyID>, Message)> {
        let (
            malicious_parties,
            coefficients_for_commitments,
            deal_randomizer_contribution_to_upcoming_parties_message,
            threshold_encryption_of_randomizer_contribution_and_proof,
        ) = class_groups::reconfiguration::Party::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::advance_first_round_internal(
            tangible_party_id,
            session_id,
            randomizer_contribution_to_threshold_encryption_key_base_protocol_context,
            class_groups_public_input,
            &class_groups_public_input.setup_parameters,
            randomizer_contribution_to_upcoming_pvss_party,
            randomizer_contribution_bits,
            rng,
        )?;

        let (equality_of_coefficients_commitments_proof, coefficients_commitments) =
            dkg::Party::prove_equality_of_coefficients_commitments(
                tangible_party_id,
                session_id,
                equality_of_coefficients_commitments_base_protocol_context,
                equality_of_coefficients_commitments_language_public_parameters,
                coefficients_for_commitments,
                rng,
            )?;

        let message = Message::DealRandomizerContributionAndProveCoefficientCommitments {
            deal_randomizer_message: class_groups::reconfiguration::Message::DealRandomizer {
                deal_randomizer_contribution_to_upcoming_parties_message,
                threshold_encryption_of_randomizer_contribution_and_proof,
            },
            equality_of_coefficients_commitments_proof,
            coefficients_commitments,
        };

        Ok((malicious_parties, message))
    }

    pub(crate) fn handle_first_round_messages(
        secp256k1_setup_parameters: &Secp256k1SetupParameters,
        ristretto_setup_parameters: &RistrettoSetupParameters,
        secp256r1_setup_parameters: &Secp256r1SetupParameters,
        deal_randomizer_and_prove_coefficient_commitments_messages: HashMap<PartyID, Message>,
    ) -> Result<(
        Vec<PartyID>,
        HashMap<
            PartyID,
            class_groups::reconfiguration::Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        HashMap<
            PartyID,
            (
                EqualityOfCoefficientsCommitmentsProof,
                Vec<
                    ThreeWayGroupElement<
                        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    >,
                >,
            ),
        >,
    )> {
        // Make sure everyone sent the first round message.
        let (
            parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
            deal_randomizer_and_prove_coefficient_commitments_messages,
        ) = deal_randomizer_and_prove_coefficient_commitments_messages
            .into_iter()
            .map(|(dealer_party_id, message)| {
                let res = match message {
                    Message::DealRandomizerContributionAndProveCoefficientCommitments {
                        deal_randomizer_message,
                        equality_of_coefficients_commitments_proof,
                        coefficients_commitments,
                    } => {
                        if let class_groups::reconfiguration::Message::DealRandomizer {
                            deal_randomizer_contribution_to_upcoming_parties_message,
                            threshold_encryption_of_randomizer_contribution_and_proof: _,
                        } = &deal_randomizer_message
                        {
                            let secp256k1_coefficient_commitments =
                                deal_randomizer_contribution_to_upcoming_parties_message
                                    .coefficients_contribution_commitments
                                    .clone();

                            if secp256k1_coefficient_commitments.len()
                                == coefficients_commitments.len()
                            {
                                // Take the coefficients commitments for `secp256k1` from the inner protocol's messages, and the one for `ristretto` and `secp256r1` from this protocol's message.
                                let coefficients_commitments = coefficients_commitments
                                    .into_iter()
                                    .zip(secp256k1_coefficient_commitments)
                                    .map(
                                        |(
                                            coefficient_commitments,
                                            secp256k1_coefficient_commitment,
                                        )| {
                                            let (
                                                ristretto_coefficient_commitment,
                                                secp256r1_coefficient_commitment,
                                            ) = coefficient_commitments.into();

                                            let secp256k1_coefficient_commitment =
                                                EquivalenceClass::new(
                                                    secp256k1_coefficient_commitment,
                                                    secp256k1_setup_parameters
                                                        .equivalence_class_public_parameters(),
                                                )?;

                                            let ristretto_coefficient_commitment =
                                                EquivalenceClass::new(
                                                    ristretto_coefficient_commitment,
                                                    ristretto_setup_parameters
                                                        .equivalence_class_public_parameters(),
                                                )?;

                                            let secp256r1_coefficient_commitment =
                                                EquivalenceClass::new(
                                                    secp256r1_coefficient_commitment,
                                                    secp256r1_setup_parameters
                                                        .equivalence_class_public_parameters(),
                                                )?;

                                            let coefficient_commitments = (
                                                (
                                                    secp256k1_coefficient_commitment,
                                                    ristretto_coefficient_commitment,
                                                )
                                                    .into(),
                                                secp256r1_coefficient_commitment,
                                            )
                                                .into();

                                            Ok(coefficient_commitments)
                                        },
                                    )
                                    .collect::<Result<_>>();

                                coefficients_commitments.map(|coefficients_commitments| {
                                    (
                                        deal_randomizer_message,
                                        equality_of_coefficients_commitments_proof,
                                        coefficients_commitments,
                                    )
                                })
                            } else {
                                Err(Error::InvalidMessage)
                            }
                        } else {
                            Err(Error::InvalidMessage)
                        }
                    }
                    _ => Err(Error::InvalidMessage),
                };

                (dealer_party_id, res)
            })
            .handle_invalid_messages_async();

        let (
            deal_randomizer_messages,
            equality_of_coefficients_commitments_proofs_and_statements
        ): (HashMap<_, _>, HashMap<_, _>) = deal_randomizer_and_prove_coefficient_commitments_messages
            .into_iter()
            .map(
                |(
                     dealer_tangible_party_id,
                     (
                         deal_randomizer_message,
                         equality_of_coefficients_commitments_proof,
                         coefficient_commitments
                     ),
                 )| {
                    (
                        (
                            dealer_tangible_party_id,
                            deal_randomizer_message,
                        ),
                        (
                            dealer_tangible_party_id,
                            (
                                equality_of_coefficients_commitments_proof,
                                  coefficient_commitments
                            ),
                        ),
                    )
                },
            )
            .unzip();

        Ok((
            parties_sending_invalid_deal_randomizer_and_prove_coefficient_commitments_messages,
            deal_randomizer_messages,
            equality_of_coefficients_commitments_proofs_and_statements,
        ))
    }
}
