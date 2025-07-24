// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Encryption of Secret Key Share round party for Class Groups

pub mod asynchronous {
    use std::collections::{HashMap, HashSet};
    use std::fmt::Debug;
    use std::marker::PhantomData;

    use super::super::*;
    use crate::class_groups::{
        EncryptionOfSecretKeyShareAndPublicKeyShare, ProtocolPublicParameters,
    };
    use crate::languages::class_groups::{
        construct_encryption_of_discrete_log_public_parameters, EncryptionOfDiscreteLogProof,
    };
    use crate::Error;
    use ::class_groups::equivalence_class::EquivalenceClassOps;
    use ::class_groups::MultiFoldNupowAccelerator;
    use ::class_groups::{encryption_key, CiphertextSpaceGroupElement, EncryptionKey};
    use ::class_groups::{equivalence_class, RandomnessSpaceGroupElement};
    use ::class_groups::{CiphertextSpacePublicParameters, RandomnessSpacePublicParameters};
    use ::class_groups::{CompactIbqf, EquivalenceClass};
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::{Encoding, Int, Uint};
    use group::{PartyID, PrimeGroupElement};
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure,
    };

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Party<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement,
    >(PhantomData<GroupElement>)
    where
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding;

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > mpc::Party
        for Party<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicEncryptionKey<
            SCALAR_LIMBS,
            PublicParameters = encryption_key::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            PlaintextSpaceGroupElement = GroupElement::Scalar,
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
            CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
    {
        type Error = Error;
        type PublicInput = ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = (
            [EncryptionOfSecretKeyShareAndPublicKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >; 2],
            CommitmentSizedNumber,
        );
        type PublicOutput = Self::PublicOutputValue;
        type Message = proof::aggregation::asynchronous::Message<
            EncryptionOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
                ProtocolContext,
            >,
        >;
    }

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > AsynchronouslyAdvanceable
        for Party<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
                Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                PublicParameters = equivalence_class::PublicParameters<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            > + EquivalenceClassOps<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicEncryptionKey<
            SCALAR_LIMBS,
            PublicParameters = encryption_key::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            PlaintextSpaceGroupElement = GroupElement::Scalar,
            RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
            CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
        encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        >,
    {
        type PrivateInput = ();

        fn advance(
            session_id: CommitmentSizedNumber,
            party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            _private_input: Option<Self::PrivateInput>,
            protocol_public_parameters: &Self::PublicInput,
            malicious_parties_by_round: HashMap<u64, HashSet<PartyID>>,
            rng: &mut impl CsRng,
        ) -> Result<AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>>
        {
            let private_input = match &messages[..] {
                [] => {
                    let share_of_decentralized_party_secret_key_share_witnesses =
                        super::super::Party::sample_secret_key_share_parts::<
                            SCALAR_LIMBS,
                            SCALAR_LIMBS,
                            GroupElement,
                            ::class_groups::EncryptionKey<
                                SCALAR_LIMBS,
                                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                GroupElement,
                            >,
                        >(protocol_public_parameters, rng)?;

                    Ok(Some(
                        share_of_decentralized_party_secret_key_share_witnesses,
                    ))
                }
                [_] => Ok(None),
                _ => Err(Error::InvalidParameters),
            }?;

            let language_public_parameters = construct_encryption_of_discrete_log_public_parameters::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >(
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
                protocol_public_parameters
                    .encryption_scheme_public_parameters
                    .clone(),
            );

            let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
                protocol_context: protocol_context(session_id),
                public_parameters: language_public_parameters,
                batch_size: 2,
            };

            match <proof::aggregation::asynchronous::Party<
                EncryptionOfDiscreteLogProof<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                    ProtocolContext,
                >,
            > as AsynchronouslyAdvanceable>::advance(
                session_id,
                party_id,
                access_structure,
                messages,
                private_input,
                &aggregation_public_input,
                malicious_parties_by_round,
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
                        Ok(AsynchronousRoundResult::Finalize {
                            malicious_parties,
                            private_output,
                            public_output: (
                                [first_part_statement.value(), second_part_statement.value()],
                                session_id,
                            ),
                        })
                    }
                    _ => Err(Error::InternalError),
                },
            }
        }

        fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
            <proof::aggregation::asynchronous::Party<
                EncryptionOfDiscreteLogProof<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                    ProtocolContext,
                >,
            > as AsynchronouslyAdvanceable>::round_causing_threshold_not_reached(
                failed_round
            )
        }
    }
}
