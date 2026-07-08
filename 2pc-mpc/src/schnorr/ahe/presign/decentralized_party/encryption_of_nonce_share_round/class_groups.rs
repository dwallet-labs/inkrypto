// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Encryption of Nonce Share round party for Class Groups

pub mod asynchronous {
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use super::super::*;
    use crate::languages::class_groups::{
        construct_encryption_of_discrete_log_public_parameters, EncryptionOfDiscreteLogProof,
    };
    use crate::{Error, ErrorKind};
    use ::class_groups::equivalence_class::EquivalenceClassOps;
    use ::class_groups::MultiFoldNupowAccelerator;
    use ::class_groups::{encryption_key, CiphertextSpaceGroupElement, EncryptionKey};
    use ::class_groups::{equivalence_class, RandomnessSpaceGroupElement};
    use ::class_groups::{CiphertextSpacePublicParameters, RandomnessSpacePublicParameters};
    use ::class_groups::{CompactIbqf, EquivalenceClass};
    use commitment::CommitmentSizedNumber;
    use crypto_bigint::{Encoding, Int, Uint};
    use group::{GroupElement, PartyID};
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure,
    };

    use crate::class_groups::schnorr::Presign;
    use crate::schnorr::ahe::presign::decentralized_party::PublicInput;
    use crate::schnorr::VerifyingKey;

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
            GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
        type PublicInput = PublicInput<
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;

        type PrivateOutput = ();
        type PublicOutputValue = Vec<
            Presign<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;
        type PublicOutput = Self::PublicOutputValue;
        type Message = proof_aggregation::asynchronous::Message<
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
            GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
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
            public_input: &Self::PublicInput,
            rng: &mut impl CsRng,
        ) -> Result<AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>>
        {
            let protocol_public_parameters = &public_input.protocol_public_parameters;

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

            let aggregation_public_input = proof_aggregation::asynchronous::PublicInput {
                protocol_context: protocol_context(session_id),
                public_parameters: language_public_parameters,
                batch_size: 2,
            };

            match &messages[..] {
                [] => {
                    let private_input = match &messages[..] {
                        [] => {
                            // Sample $k_{0}, k_{1}$ and encryption randomness $\eta_{0}, \eta_{1}$
                            let share_of_decentralized_party_nonce_share_witnesses =
                                super::super::Party::sample_nonce_share_parts::<
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

                            Ok(Some(share_of_decentralized_party_nonce_share_witnesses))
                        }
                        [_] => Ok(None),
                        _ => Err(Error::from(ErrorKind::InvalidParameters)),
                    }?;

                    let (proof, statement_values) = proof_aggregation::asynchronous::Party::<
                        EncryptionOfDiscreteLogProof<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                            ProtocolContext,
                        >,
                    >::advance_first_round(
                        session_id,
                        party_id,
                        private_input,
                        &aggregation_public_input,
                        rng,
                    )?;

                    Ok(AsynchronousRoundResult::Advance {
                        malicious_parties: vec![],
                        message: (proof, statement_values),
                    })
                }
                [encryption_of_nonce_share_proofs_and_statements] => {
                    let (malicious_parties, aggregated_statements) =
                        proof_aggregation::asynchronous::Party::<
                            EncryptionOfDiscreteLogProof<
                                SCALAR_LIMBS,
                                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                GroupElement,
                                ProtocolContext,
                            >,
                        >::advance_second_round_with_blending(
                            session_id,
                            access_structure,
                            &aggregation_public_input,
                            encryption_of_nonce_share_proofs_and_statements.clone(),
                            rng,
                        )?;

                    let global_decentralized_party_output_commitment = protocol_public_parameters
                        .global_decentralized_party_output_commitment(
                    )?;

                    let presigns = aggregated_statements
                        .into_iter()
                        .map(|statements| match &statements[..] {
                            [first_part_statement, second_part_statement] => Ok(Presign::<
                                SCALAR_LIMBS,
                                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                                GroupElement,
                            >::new(
                                session_id,
                                [first_part_statement.value(), second_part_statement.value()],
                                global_decentralized_party_output_commitment,
                            )),
                            _ => Err(Error::from(ErrorKind::InternalError)),
                        })
                        .collect::<Result<_>>()?;

                    Ok(AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output: (),
                        public_output: presigns,
                    })
                }
                _ => Err(Error::from(ErrorKind::InternalError)),
            }
        }

        fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
            <proof_aggregation::asynchronous::Party<
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
