// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Encryption of Secret Key Share round party for Paillier

pub mod asynchronous {
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::marker::PhantomData;

    use crypto_bigint::rand_core::CryptoRngCore;
    use serde::{Deserialize, Serialize};

    use commitment::CommitmentSizedNumber;
    use group::{GroupElement, PartyID, PrimeGroupElement, PublicParameters};
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure,
    };

    use crate::languages::paillier::{
        construct_encryption_of_discrete_log_public_parameters,
        EncryptionOfDiscreteLogEnhancedLanguage,
    };
    use crate::paillier::EncryptionOfSecretKeyShareAndPublicKeyShare;
    use crate::Error;
    use crate::{
        languages::paillier::EncryptionOfDiscreteLogProof,
        paillier::bulletproofs::PaillierProtocolPublicParameters,
        paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS},
    };

    use super::super::*;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Party<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement,
    >(PhantomData<GroupElement>);

    impl<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > mpc::Party
        for Party<RANGE_CLAIMS_PER_SCALAR, NUM_RANGE_CLAIMS, SCALAR_LIMBS, GroupElement>
    {
        type Error = Error;
        type PublicInput = PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = (
            [EncryptionOfSecretKeyShareAndPublicKeyShare<SCALAR_LIMBS, GroupElement>; 2],
            CommitmentSizedNumber,
        );
        type PublicOutput = Self::PublicOutputValue;
        type Message = proof::aggregation::asynchronous::Message<
            EncryptionOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
        >;
    }

    impl<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > AsynchronouslyAdvanceable
        for Party<RANGE_CLAIMS_PER_SCALAR, NUM_RANGE_CLAIMS, SCALAR_LIMBS, GroupElement>
    {
        type PrivateInput = ();

        fn advance(
            session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            _private_input: Option<Self::PrivateInput>,
            paillier_protocol_public_parameters: &Self::PublicInput,
            rng: &mut impl CryptoRngCore,
        ) -> std::result::Result<
            AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
            Self::Error,
        > {
            let enhanced_language_public_parameters =
                construct_encryption_of_discrete_log_public_parameters::<
                    SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    GroupElement,
                >(
                    paillier_protocol_public_parameters
                        .protocol_public_parameters
                        .group_public_parameters
                        .clone(),
                    paillier_protocol_public_parameters
                        .protocol_public_parameters
                        .encryption_scheme_public_parameters
                        .clone(),
                    paillier_protocol_public_parameters
                        .unbounded_encdl_witness_public_parameters
                        .clone(),
                    paillier_protocol_public_parameters
                        .range_proof_enc_dl_public_parameters
                        .clone(),
                )?;

            let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
                protocol_context: protocol_context(session_id),
                public_parameters: enhanced_language_public_parameters,
                batch_size: 2,
            };

            let private_input = match &messages[..] {
                [] => {
                    let share_of_decentralized_party_secret_key_share_witnesses =
                        super::super::Party::sample_secret_key_share_parts::<
                            SCALAR_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            GroupElement,
                            EncryptionKey,
                        >(
                            &paillier_protocol_public_parameters.protocol_public_parameters,
                            rng,
                        )?;

                    // === Map (x_i, \rho_i) ====
                    // map (x_i, \rho_i) to the triple
                    // * [commitment_message]    cm_i = x_i
                    // * [commitment_randomness] cr_i = randomly sampled value
                    // * [unbounded_witness]     uw_i = \rho_i
                    let share_of_decentralized_party_secret_key_share_witness =
                        EncryptionOfDiscreteLogEnhancedLanguage::<
                            SCALAR_LIMBS,
                            RANGE_CLAIMS_PER_SCALAR,
                            GroupElement,
                        >::generate_witnesses(
                            share_of_decentralized_party_secret_key_share_witnesses,
                            &aggregation_public_input.public_parameters,
                            rng,
                        )?;

                    Ok(Some(share_of_decentralized_party_secret_key_share_witness))
                }
                [_] => Ok(None),
                _ => Err(Error::InvalidParameters),
            }?;

            match <proof::aggregation::asynchronous::Party<
                EncryptionOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
            > as AsynchronouslyAdvanceable>::advance(
                session_id,
                party_id,
                access_structure,
                messages,
                private_input,
                &aggregation_public_input,
                rng,
            )? {
                AsynchronousRoundResult::Advance {
                    malicious_parties,
                    message,
                } => Ok(AsynchronousRoundResult::Advance {
                    malicious_parties,
                    message,
                }),
                AsynchronousRoundResult::Finalize {
                    malicious_parties,
                    private_output,
                    public_output,
                } => match &public_output[..] {
                    [first_part_statement, second_part_statement] => {
                        // Ignore the range proof commitment, keep only the Maurer statement
                        let (_, first_part_maurer_statement) = first_part_statement.into();
                        let (_, second_part_maurer_statement) = second_part_statement.into();
                        Ok(AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output,
                            public_output: (
                                [
                                    first_part_maurer_statement.value(),
                                    second_part_maurer_statement.value(),
                                ],
                                session_id,
                            ),
                        })
                    }
                    _ => Err(Error::InternalError),
                },
            }
        }

        fn round_causing_threshold_not_reached(failed_round: usize) -> Option<usize> {
            <proof::aggregation::asynchronous::Party<
                EncryptionOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
            > as AsynchronouslyAdvanceable>::round_causing_threshold_not_reached(
                failed_round
            )
        }
    }
}
