// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Encryption of Secret Key Share round party for Class Groups

pub mod asynchronous {
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use super::super::*;
    use crate::class_groups::EncryptionOfSecretKeyShareAndPublicKeyShare;
    use crate::languages::class_groups::{
        construct_encryption_of_discrete_log_public_parameters, EncryptionOfDiscreteLogProof,
        EncryptionOfDiscreteLogPublicParameters,
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
        type PublicInput = super::super::PublicInput<
            group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
            group::PublicParameters<GroupElement>,
            homomorphic_encryption::PublicParameters<
                SCALAR_LIMBS,
                EncryptionKey<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >,
            >,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = [EncryptionOfSecretKeyShareAndPublicKeyShare<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >; 2];
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
            public_input: &Self::PublicInput,
            rng: &mut impl CsRng,
        ) -> Result<AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>>
        {
            match &messages[..] {
                [] => Self::advance_first_round(session_id, party_id, public_input, rng).map(
                    |message| AsynchronousRoundResult::Advance {
                        malicious_parties: vec![],
                        message,
                    },
                ),
                [proofs_and_statements] => Self::advance_second_round(
                    session_id,
                    access_structure,
                    public_input,
                    proofs_and_statements.clone(),
                    rng,
                )
                .map(
                    |(malicious_parties, public_output)| AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output: (),
                        public_output,
                    },
                ),
                _ => Err(Error::InternalError),
            }
        }

        fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
            match failed_round {
                2 => Some(1),
                _ => None,
            }
        }
    }

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        >
        Party<
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
        pub fn aggregation_public_input(
            session_id: CommitmentSizedNumber,
            public_input: &super::super::PublicInput<
                group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
                group::PublicParameters<GroupElement>,
                homomorphic_encryption::PublicParameters<
                    SCALAR_LIMBS,
                    EncryptionKey<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >,
                >,
            >,
        ) -> proof::aggregation::asynchronous::PublicInput<
            ProtocolContext,
            EncryptionOfDiscreteLogPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        > {
            let language_public_parameters = construct_encryption_of_discrete_log_public_parameters::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >(
                public_input.scalar_group_public_parameters.clone(),
                public_input.group_public_parameters.clone(),
                public_input.encryption_scheme_public_parameters.clone(),
            );

            proof::aggregation::asynchronous::PublicInput {
                protocol_context: public_input
                    .base_protocol_context
                    .with_session_id(session_id),
                public_parameters: language_public_parameters,
                batch_size: 2,
            }
        }

        pub fn advance_first_round(
            session_id: CommitmentSizedNumber,
            party_id: PartyID,
            public_input: &super::super::PublicInput<
                group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
                group::PublicParameters<GroupElement>,
                homomorphic_encryption::PublicParameters<
                    SCALAR_LIMBS,
                    EncryptionKey<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >,
                >,
            >,
            rng: &mut impl CsRng,
        ) -> Result<<Self as mpc::Party>::Message> {
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
                >(public_input, rng)?;

            let private_input = Some(share_of_decentralized_party_secret_key_share_witnesses);

            let aggregation_public_input = Self::aggregation_public_input(session_id, public_input);

            let (proof, statement_values) = proof::aggregation::asynchronous::Party::<
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

            Ok((proof, statement_values))
        }

        pub fn advance_second_round(
            session_id: CommitmentSizedNumber,
            access_structure: &WeightedThresholdAccessStructure,
            public_input: &super::super::PublicInput<
                group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
                group::PublicParameters<GroupElement>,
                homomorphic_encryption::PublicParameters<
                    SCALAR_LIMBS,
                    EncryptionKey<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >,
                >,
            >,
            proofs_and_statements: HashMap<PartyID, <Self as mpc::Party>::Message>,
            rng: &mut impl CsRng,
        ) -> Result<(Vec<PartyID>, <Self as mpc::Party>::PublicOutput)> {
            let aggregation_public_input = Self::aggregation_public_input(session_id, public_input);

            let (malicious_parties, aggregated_statements) =
                proof::aggregation::asynchronous::Party::<
                    EncryptionOfDiscreteLogProof<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                        ProtocolContext,
                    >,
                >::advance_second_round(
                    session_id,
                    access_structure,
                    &aggregation_public_input,
                    proofs_and_statements,
                    rng,
                )?;

            match &aggregated_statements[..] {
                [first_part_statement, second_part_statement] => {
                    let public_output =
                        [first_part_statement.value(), second_part_statement.value()];

                    Ok((malicious_parties, public_output))
                }
                _ => Err(Error::InternalError),
            }
        }
    }
}
