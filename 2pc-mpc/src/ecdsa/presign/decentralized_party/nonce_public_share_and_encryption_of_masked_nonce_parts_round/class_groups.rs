// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the Nonce Public Share and Encryption of Masked Nonce Round for Class Groups

use crate::class_groups::ecdsa::{Presign, UniversalPresign, VersionedPresign};
use crate::ecdsa::presign::decentralized_party::class_groups::asynchronous::{Message, Party};
use crate::ecdsa::presign::decentralized_party::{
    nonce_public_share_and_encryption_of_masked_nonce_parts_round, PublicInput,
};
use crate::ecdsa::VerifyingKey;
use crate::languages::class_groups::{
    construct_scaling_of_discrete_log_public_parameters, ScalingOfDiscreteLogProof,
    ScalingOfDiscreteLogPublicParameters,
};
use crate::{Error, ProtocolContext, Result};
use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CiphertextSpaceValue, CompactIbqf, EncryptionKey,
    EquivalenceClass, MultiFoldNupowAccelerator, RandomnessSpaceGroupElement,
    RandomnessSpacePublicParameters,
};
use commitment::CommitmentSizedNumber;
use crypto_bigint::{Encoding, Int, Uint};
use group::helpers::DeduplicateAndSort;
use group::{CsRng, GroupElement, PartyID};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use mpc::{HandleInvalidMessages, WeightedThresholdAccessStructure};
use std::collections::HashMap;

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS>,
    >
    Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
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
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    Uint<MESSAGE_LIMBS>: Encoding,
{
    pub(crate) fn nonce_public_share_and_encryption_of_masked_nonce_aggregation_public_input(
        session_id: CommitmentSizedNumber,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        encryption_of_mask: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> Result<
        proof::aggregation::asynchronous::PublicInput<
            ProtocolContext,
            ScalingOfDiscreteLogPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
    > {
        let language_public_parameters = construct_scaling_of_discrete_log_public_parameters::<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >(
            encryption_of_mask,
            public_input
                .protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            public_input
                .protocol_public_parameters
                .group_public_parameters
                .clone(),
            public_input
                .protocol_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
        )?;

        let aggregation_public_input = proof::aggregation::asynchronous::PublicInput {
            protocol_context: public_input
                .nonce_public_share_and_encryption_of_masked_nonce_round_protocol_context_v1(
                    session_id,
                ),
            public_parameters: language_public_parameters,
            batch_size: 2,
        };

        Ok(aggregation_public_input)
    }

    pub(crate) fn advance_nonce_public_share_and_encryption_of_masked_nonce_proof_round(
        session_id: CommitmentSizedNumber,
        party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        encryption_of_mask_and_masked_key_share_messages: HashMap<
            PartyID,
            Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(
        Vec<PartyID>,
        Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
    )> {
        let private_input =
            Some(nonce_public_share_and_encryption_of_masked_nonce_parts_round::Party::initialize_proof_aggregation::<
                SCALAR_LIMBS,
                SCALAR_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
                ::class_groups::EncryptionKey<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >,
            >(&public_input.protocol_public_parameters, rng)?);

        let (disagreeing_parties, encryption_of_mask) = Self::majority_vote_encryption_of_mask(
            access_structure,
            encryption_of_mask_and_masked_key_share_messages,
            public_input,
        )?;

        let aggregation_public_input =
            Self::nonce_public_share_and_encryption_of_masked_nonce_aggregation_public_input(
                session_id,
                public_input,
                encryption_of_mask,
            )?;

        let (proof, statement_values) = proof::aggregation::asynchronous::Party::<
            ScalingOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >::advance_first_round(
            session_id,
            party_id,
            private_input,
            &aggregation_public_input,
            rng,
        )?;

        Ok((
            disagreeing_parties,
            Message::NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof((
                proof,
                statement_values,
            )),
        ))
    }

    pub(crate) fn advance_nonce_public_share_and_encryption_of_masked_nonce_proof_verification_round(
        session_id: CommitmentSizedNumber,
        access_structure: &WeightedThresholdAccessStructure,
        public_input: &PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        encryption_of_mask_and_masked_key_share_messages: HashMap<
            PartyID,
            Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
        nonce_public_share_and_encryption_of_masked_nonce_proofs_and_statements: HashMap<
            PartyID,
            Message<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(
        Vec<PartyID>,
        VersionedPresign<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    )> {
        // Make sure everyone sent the nonce public share and encryption of masked nonce share and proof message.
        let (
            parties_sending_invalid_nonce_public_share_and_encryption_of_masked_nonce_share_messages,
            nonce_public_share_and_encryption_of_masked_nonce_share_messages,
        ) = nonce_public_share_and_encryption_of_masked_nonce_proofs_and_statements
            .into_iter()
            .map(|(party_id, message)| {
                let res = match message {
                    Message::NoncePublicShareAndEncryptionOfMaskedNonceShareAndProof(message) => {
                        Ok(message)
                    }
                    _ => Err(Error::InvalidParameters),
                };

                (party_id, res)
            })
            .handle_invalid_messages_async();

        let (disagreeing_parties, encryption_of_mask) = Self::majority_vote_encryption_of_mask(
            access_structure,
            encryption_of_mask_and_masked_key_share_messages.clone(),
            public_input,
        )?;

        let aggregation_public_input =
            Self::nonce_public_share_and_encryption_of_masked_nonce_aggregation_public_input(
                session_id,
                public_input,
                encryption_of_mask,
            )?;

        let (malicious_provers, aggregated_statements) = proof::aggregation::asynchronous::Party::<
            ScalingOfDiscreteLogProof<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >,
        >::advance_second_round(
            session_id,
            access_structure,
            &aggregation_public_input,
            nonce_public_share_and_encryption_of_masked_nonce_share_messages,
            rng,
        )?;

        let nonce_public_share_and_encryption_of_masked_nonce_share_parts =
            match &aggregated_statements[..] {
                [first_statement, second_statement] => {
                    Ok([first_statement.value(), second_statement.value()])
                }
                _ => Err(Error::InternalError),
            }?;

        let malicious_parties = parties_sending_invalid_nonce_public_share_and_encryption_of_masked_nonce_share_messages
            .into_iter()
            .chain(disagreeing_parties)
            .chain(malicious_provers)
            .deduplicate_and_sort();

        match public_input.dkg_output.clone() {
            Some(dkg_output) => {
                // We are re-executing the same majority vote,
                // because the first-round statement is of a different type for the targeted and universal presign protocols,
                // and in Rust we cannot have a dynamically-typed variable.
                //
                // We previously took the shared part of the statement (the encryption of mask) and the disagreeing parties;
                // no need to account for the disagreeing parties twice,
                // as they are the same (came out of the exact same computation) - and are generically accounted for in `malicious_parties` above.
                let (_, encryption_of_mask_and_masked_key_share) =
                    Self::majority_vote_encryption_of_mask_and_masked_key_share(
                        access_structure,
                        encryption_of_mask_and_masked_key_share_messages,
                    )?;

                let presign = Presign::<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >::new(
                    session_id,
                    encryption_of_mask_and_masked_key_share,
                    nonce_public_share_and_encryption_of_masked_nonce_share_parts,
                    dkg_output.public_key,
                );

                Ok((
                    malicious_parties,
                    crate::ecdsa::presign::VersionedPresign::TargetedPresign(presign),
                ))
            }
            None => {
                let global_decentralized_party_output_commitment = public_input
                    .protocol_public_parameters
                    .global_decentralized_party_output_commitment()?;

                // See above comment about ignoring `disagreeing_parties`.
                let (_, encryption_of_mask_and_masked_key_share_parts) =
                    Self::majority_vote_encryption_of_mask_and_masked_key_share_parts(
                        access_structure,
                        encryption_of_mask_and_masked_key_share_messages,
                    )?;

                let presign = UniversalPresign::<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >::new(
                    session_id,
                    encryption_of_mask_and_masked_key_share_parts,
                    nonce_public_share_and_encryption_of_masked_nonce_share_parts,
                    global_decentralized_party_output_commitment,
                );

                Ok((
                    malicious_parties,
                    crate::ecdsa::presign::VersionedPresign::UniversalPresign(presign),
                ))
            }
        }
    }
}
