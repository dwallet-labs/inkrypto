// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Sign` decentralized party for Class Groups

pub mod asynchronous {
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};

    use ::class_groups::encryption_key::public_parameters::Instantiate;
    use ::class_groups::equivalence_class::EquivalenceClassOps;
    use ::class_groups::CiphertextSpaceValue;
    use ::class_groups::DecryptionKeyShare;
    use ::class_groups::MultiFoldNupowAccelerator;
    use ::class_groups::{decryption_key_share, SecretKeyShareSizedInteger};
    use ::class_groups::{
        encryption_key, CiphertextSpaceGroupElement, CompactIbqf, EncryptionKey, EquivalenceClass,
    };
    use ::class_groups::{
        equivalence_class, CiphertextSpacePublicParameters, RandomnessSpaceGroupElement,
        RandomnessSpacePublicParameters,
    };
    use ::class_groups::{DecryptionKey, DiscreteLogInF};
    use commitment::CommitmentSizedNumber;
    use group::helpers::{DeduplicateAndSort, TryCollectHashMap};
    use group::{hash_to_scalar, CsRng, PartyID, StatisticalSecuritySizedNumber};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKeyShare, AdditivelyHomomorphicEncryptionKey,
    };
    use mpc::secret_sharing::shamir::over_the_integers::AdjustedLagrangeCoefficientSizedNumber;
    use mpc::{
        AsynchronousRoundResult, AsynchronouslyAdvanceable, HandleInvalidMessages,
        WeightedThresholdAccessStructure,
    };

    use super::super::*;
    use crate::class_groups::ecdsa::{DKGSignPartyPublicInput, SignPartyPublicInput};
    use crate::class_groups::{DKGDecentralizedParty, DecryptionShare, PartialDecryptionProof};
    use crate::dkg::class_groups::asynchronous::verify_centralized_party_key_share;
    use crate::dkg::decentralized_party::VersionedOutput;
    use crate::ecdsa::sign::centralized_party::message::class_groups::VerifiedSignDataRaw;
    use crate::ecdsa::VerifyingKey;
    use crate::languages::{KnowledgeOfDecommitmentProof, KnowledgeOfDecommitmentUCProof};
    use crate::sign::SignData;
    use crate::{Error, ErrorKind};
    use commitment::GroupsPublicParametersAccessors as CommitmentGroupsPublicParametersAccessors;
    use group::GroupElement as _;
    use homomorphic_encryption::GroupsPublicParametersAccessors;

    /// A party participating in the decentralized party's Asynchronous Sign protocol.
    pub struct Party<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    >(PhantomData<GroupElement>);

    /// A party participating in the decentralized party's Asynchronous DKG followed by a Sign protocol.
    pub struct DKGSignParty<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    >(PhantomData<GroupElement>);

    #[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
    pub enum Message<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
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
    {
        DecryptionShares(
            HashMap<
                PartyID,
                (
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                ),
            >,
        ),
        DecryptionSharesAndProof(
            HashMap<
                PartyID,
                (
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    DecryptionShare<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                    PartialDecryptionProof<SCALAR_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                ),
            >,
        ),
    }

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
        > mpc::Party
        for Party<
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
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        type Error = Error;
        type PublicInput = SignPartyPublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = GroupElement::Signature;
        type PublicOutput = Self::PublicOutputValue;
        type Message = Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >;
    }

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
        > mpc::Party
        for DKGSignParty<
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
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        type Error = Error;
        type PublicInput = DKGSignPartyPublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >;
        type PrivateOutput = ();
        type PublicOutputValue = (
            VersionedOutput<
                SCALAR_LIMBS,
                GroupElement::Value,
                CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
            GroupElement::Signature,
        );
        type PublicOutput = Self::PublicOutputValue;
        type Message = Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >;
    }

    impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > AsynchronouslyAdvanceable
    for Party<
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
        Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        DecryptionKeyShare<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicDecryptionKeyShare<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            PublicParameters = decryption_key_share::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            SecretKeyShare = SecretKeyShareSizedInteger,
            PartialDecryptionProof = decryption_key_share::PartialDecryptionProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber,
            Error = ::class_groups::Error
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        type PrivateInput = HashMap<
            PartyID,
            SecretKeyShareSizedInteger
        >;

        fn advance(
            _session_id: CommitmentSizedNumber,
            tangible_party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            virtual_party_id_to_decryption_key_share: Option<Self::PrivateInput>,
            public_input: &Self::PublicInput,
            rng: &mut impl CsRng,
        ) -> Result<
            AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
            Self::Error,
        > {
            advance_sign_party::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >(tangible_party_id, access_structure, messages, virtual_party_id_to_decryption_key_share, public_input, rng)
        }

        fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
            match failed_round {
                3 => Some(2),
                _ => None
            }
        }
    }

    impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > AsynchronouslyAdvanceable
    for DKGSignParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding
        + ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        > + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
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
        encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        DecryptionKeyShare<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicDecryptionKeyShare<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            PublicParameters = decryption_key_share::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            SecretKeyShare = SecretKeyShareSizedInteger,
            PartialDecryptionProof = decryption_key_share::PartialDecryptionProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber,
            Error = ::class_groups::Error
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        type PrivateInput = HashMap<
            PartyID,
            SecretKeyShareSizedInteger
        >;

        fn advance(
            session_id: CommitmentSizedNumber,
            tangible_party_id: PartyID,
            access_structure: &WeightedThresholdAccessStructure,
            messages: Vec<HashMap<PartyID, Self::Message>>,
            virtual_party_id_to_decryption_key_share: Option<Self::PrivateInput>,
            public_input: &Self::PublicInput,
            rng: &mut impl CsRng,
        ) -> Result<
            AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
            Self::Error,
        > {
            let protocol_public_parameters = public_input.protocol_public_parameters.as_ref();

            let dkg_output = DKGDecentralizedParty::<          SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,>::verify_proof_of_centralized_party_public_key_share(
                public_input.dkg_public_input.public_key_share_and_proof.clone(),
                protocol_public_parameters
                    .encryption_of_decentralized_party_secret_key_share_first_part,
                protocol_public_parameters
                    .encryption_of_decentralized_party_secret_key_share_second_part,
                protocol_public_parameters.decentralized_party_public_key_share_first_part.clone(),
                protocol_public_parameters.decentralized_party_public_key_share_second_part.clone(),
                &public_input.protocol_public_parameters,
                session_id,
            )?;

            if messages.is_empty() {
                // Only needed once, at the first round.
                verify_centralized_party_key_share::<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                >(
                    &public_input.protocol_public_parameters,
                    dkg_output.clone(),
                    public_input
                        .dkg_public_input
                        .centralized_party_secret_key_share_verification
                        .clone(),
                )?;
            }

            let public_input = super::super::PublicInput {
                expected_decrypters: public_input.expected_decrypters.clone(),
                message: public_input.message.clone(),
                hash_type: public_input.hash_type,
                hash_context: public_input.hash_context.clone(),
                dkg_output: dkg_output.clone(),
                presign: public_input.presign.clone(),
                sign_message: public_input.sign_message.clone(),
                decryption_key_share_public_parameters: public_input.decryption_key_share_public_parameters.clone(),
                protocol_public_parameters: public_input.protocol_public_parameters.clone(),
            };

            advance_sign_party::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >(tangible_party_id, access_structure, messages, virtual_party_id_to_decryption_key_share, &public_input, rng).map(|res| match res {
                AsynchronousRoundResult::Advance { malicious_parties, message } => AsynchronousRoundResult::Advance { malicious_parties, message },
                AsynchronousRoundResult::Finalize {
                    malicious_parties,
                    private_output,
                    public_output: signature,
                } => {
                    AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output,
                        public_output: (dkg_output, signature)
                    }
                }
            })
        }

        fn round_causing_threshold_not_reached(failed_round: u64) -> Option<u64> {
            match failed_round {
                3 => Some(2),
                _ => None
            }
        }
    }

    /// Resolve `SignData` to `VerifiedSignDataRaw` without performing any verification.
    ///
    /// - `Unverified`: extracts the three ciphertext/nonce fields from the full message (caller
    ///   is responsible for having verified the proofs in a previous round).
    /// - `Verified`: returns the pre-verified data as-is.
    /// - `ToBeEmulated`: emulates the verified sign data via
    ///   [`emulate_threshold_verified_sign_data`].
    fn resolve_sign_data<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    >(
        sign_data: crate::ecdsa::sign::centralized_party::message::class_groups::SignData<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        hashed_message: GroupElement::Scalar,
        presign: crate::ecdsa::presign::Presign<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        dkg_output: &crate::dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    ) -> crate::Result<
        VerifiedSignDataRaw<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding
            + ConcatMixed<StatisticalSecuritySizedNumber>
            + for<'a> From<
                &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
            >,
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
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        match sign_data {
            SignData::Unverified(msg) => Ok(VerifiedSignDataRaw {
                public_signature_nonce: msg.public_signature_nonce,
                encryption_of_partial_signature: msg.encryption_of_partial_signature,
                encryption_of_displaced_decentralized_party_nonce_share: msg
                    .encryption_of_displaced_decentralized_party_nonce_share,
            }),
            SignData::Verified(data) => Ok(data),
            SignData::ToBeEmulated => emulate_threshold_verified_sign_data::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                MESSAGE_LIMBS,
                GroupElement,
            >(
                hashed_message,
                presign,
                protocol_public_parameters,
                dkg_output,
            ),
        }
    }

    /// Resolve `SignData` to `VerifiedSignDataRaw`, **verifying the centralized party's proofs
    /// for the `Unverified` variant**.
    ///
    /// This function MUST be used instead of [`resolve_sign_data`] whenever the sign data has not
    /// yet been verified in a previous protocol round. It performs:
    ///
    /// - `Unverified`: calls
    ///   [`verify_encryption_of_signature_parts_prehash_class_groups`] to validate all ZK proofs
    ///   ($\pi_k, \pi_\alpha, \pi_\beta$, commitment equality, encryption proofs), then extracts
    ///   the three ciphertext/nonce fields.
    /// - `Verified`: returns the pre-verified data as-is.
    /// - `ToBeEmulated`: emulates the verified sign data via
    ///   [`emulate_threshold_verified_sign_data`].
    ///
    /// After this function returns `Ok`, the caller can proceed directly with
    /// `partially_decrypt_encryption_of_signature_parts_prehash_semi_honest` — there is no need
    /// to use the `_class_groups` wrapper which combines verification and decryption.
    fn emulate_or_verify_or_unpack_sign_data<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    >(
        sign_data: crate::ecdsa::sign::centralized_party::message::class_groups::SignData<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        hashed_message: GroupElement::Scalar,
        presign: crate::ecdsa::presign::Presign<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        dkg_output: &crate::dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    ) -> crate::Result<
        VerifiedSignDataRaw<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        match sign_data {
            SignData::Unverified(sign_message) => {
                let dkg_output_ref: crate::dkg::decentralized_party::Output<
                    GroupElement::Value,
                    group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
                > = dkg_output.clone().into();

                signature_partial_decryption_round::Party::verify_encryption_of_signature_parts_prehash_class_groups::<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                >(
                    protocol_public_parameters,
                    dkg_output_ref,
                    presign,
                    sign_message.clone(),
                    hashed_message,
                )?;

                Ok(VerifiedSignDataRaw {
                    public_signature_nonce: sign_message.public_signature_nonce,
                    encryption_of_partial_signature: sign_message.encryption_of_partial_signature,
                    encryption_of_displaced_decentralized_party_nonce_share: sign_message
                        .encryption_of_displaced_decentralized_party_nonce_share,
                })
            }
            other => resolve_sign_data(
                other,
                hashed_message,
                presign,
                protocol_public_parameters,
                dkg_output,
            ),
        }
    }

    /// Compute the `VerifiedSignDataRaw` for threshold mode (no centralized party).
    ///
    /// With $x_A=0, k_A=1, \alpha=1, \beta=0$:
    /// - Derives $\mu_k^{0},\mu_k^{1}, \mu_k^{G}$ randomizers from Fiat-Shamir using default commitments/proofs
    /// - $R = R_B = \mu_k^0 \cdot R_{B,0} + \mu_k^1 \cdot R_{B,1} + \mu_k^G \cdot G$
    /// - $r = R.x$
    /// - $\textsf{ct}_A = m \cdot \textsf{ct}_{\gamma} + r \cdot \textsf{ct}_{\gamma\cdot x_B}$ (vartime homomorphic evaluation)
    /// - $\textsf{ct}_{\alpha,\beta}$: combined encryption_of_masked_decentralized_party_nonce_share
    ///   (since $\alpha=1, \beta=0$, no displacement)
    pub(crate) fn emulate_threshold_verified_sign_data<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    >(
        hashed_message: GroupElement::Scalar,
        presign: crate::ecdsa::presign::Presign<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        protocol_public_parameters: &crate::class_groups::ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        dkg_output: &crate::dkg::decentralized_party::VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    ) -> crate::Result<
        VerifiedSignDataRaw<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding
            + ConcatMixed<StatisticalSecuritySizedNumber>
            + for<'a> From<
                &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
            >,
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
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        let dkg_output_ref: crate::dkg::decentralized_party::Output<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        > = dkg_output.clone().into();

        // Validate that the centralized party public key share is the neutral element.
        // ToBeEmulated mode requires $x_A = 0$, so $X_A$ must be neutral.
        let centralized_party_public_key_share = GroupElement::new(
            dkg_output_ref.centralized_party_public_key_share.clone(),
            &protocol_public_parameters.group_public_parameters,
        )?;
        if !bool::from(centralized_party_public_key_share.is_neutral()) {
            return Err(crate::Error::from(crate::ErrorKind::InvalidParameters));
        }

        // Construct default commitments (neutral elements) for the Fiat-Shamir transcript.
        // In threshold mode, no centralized party generates these, so we use deterministic defaults.
        let commitment_scheme_public_parameters =
            commitment::pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
            )?;

        let neutral_commitment = GroupElement::neutral_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )?;

        // Construct default proofs for the Fiat-Shamir transcript.
        // In threshold mode, no centralized party generates proofs, so we use neutral defaults.
        // Witness space = DirectProduct(message_space, randomness_space), statement space = commitment_space.
        let witness_space_public_parameters = group::direct_product::PublicParameters(
            commitment_scheme_public_parameters
                .message_space_public_parameters()
                .clone(),
            commitment_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );
        let statement_space_public_parameters = commitment_scheme_public_parameters
            .commitment_space_public_parameters()
            .clone();

        let default_decommitment_proof =
            KnowledgeOfDecommitmentProof::<SCALAR_LIMBS, GroupElement>::new_default(
                &witness_space_public_parameters,
                &statement_space_public_parameters,
            )?;

        let default_uc_decommitment_proof =
            KnowledgeOfDecommitmentUCProof::<SCALAR_LIMBS, GroupElement>::new_default(
                &witness_space_public_parameters,
                &statement_space_public_parameters,
            )?;

        // Derive the randomizers $\mu_{k}^{0}, \mu_{k}^{1}, \mu_{k}^{G}$ and compute $R_B, \textsf{ct}_{\gamma\cdot k}$ using the same Fiat-Shamir
        // transcript as the centralized party code, but with default (neutral) commitments/proofs.
        let (
            encryption_of_masked_decentralized_party_nonce_share_before_displacing,
            decentralized_party_nonce_public_share_before_displacing,
        ) = crate::ecdsa::sign::derive_randomized_decentralized_party_public_nonce_share_and_encryption_of_nonce_share::<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >(
            presign.session_id,
            &hashed_message,
            presign.clone(),
            &protocol_public_parameters.encryption_scheme_public_parameters,
            &protocol_public_parameters.group_public_parameters,
            &commitment_scheme_public_parameters,
            &dkg_output_ref.public_key,
            &dkg_output_ref.centralized_party_public_key_share,
            // $C_k$ — neutral because $k_A = 1$ with zero randomness in threshold mode.
            &neutral_commitment,
            // $C_\alpha$ — neutral because $\alpha = 1$ with zero randomness in threshold mode.
            &neutral_commitment,
            // $C_\beta$ — neutral because $\beta = 0$ with zero randomness in threshold mode.
            &neutral_commitment,
            // $C_{kx}$ — neutral because $k_A \cdot x_A = 0$ in threshold mode ($x_A = 0$).
            &neutral_commitment,
            // $\pi_k$ — default proof (no real decommitment to prove in threshold mode).
            &default_decommitment_proof,
            // $\pi_\alpha$ — default proof.
            &default_decommitment_proof,
            // $\pi_\beta$ — default UC proof.
            &default_uc_decommitment_proof,
        )?;

        // $R = k_A^{-1} \cdot R_B = 1 \cdot R_B = R_B$ (since $k_A = 1$)
        let public_signature_nonce = decentralized_party_nonce_public_share_before_displacing;

        // $r = R.x$
        let nonce_x_coordinate = public_signature_nonce.x_projected_to_scalar_field();

        let ciphertext_space_public_parameters = protocol_public_parameters
            .encryption_scheme_public_parameters
            .ciphertext_space_public_parameters();

        // $\textsf{ct}_{\gamma}$
        let encryption_of_mask =
            CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                presign.encryption_of_mask,
                ciphertext_space_public_parameters,
            )?;

        // $\textsf{ct}_{\gamma\cdot x_B}$
        let encryption_of_masked_decentralized_party_key_share =
            CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                presign.encryption_of_masked_decentralized_party_key_share,
                ciphertext_space_public_parameters,
            )?;

        // Convert r and m to Uint for vartime scaling
        let nonce_x_coordinate_uint: Uint<SCALAR_LIMBS> = nonce_x_coordinate.value().into();
        let hashed_message_uint: Uint<SCALAR_LIMBS> = hashed_message.value().into();

        // $\textsf{ct}_A = m \cdot \textsf{ct}_{\gamma} + r \cdot \textsf{ct}_{\gamma\cdot x_B}$
        // This is the partial signature encryption: $(m + r\cdot x_B) \cdot \gamma$
        let encryption_of_partial_signature = encryption_of_mask
            .scale_vartime(&hashed_message_uint, ciphertext_space_public_parameters)
            .add_vartime(
                &encryption_of_masked_decentralized_party_key_share
                    .scale_vartime(&nonce_x_coordinate_uint, ciphertext_space_public_parameters),
                ciphertext_space_public_parameters,
            );

        // $\textsf{ct}_{\alpha,\beta} = \alpha \cdot \textsf{ct}_{\gamma\cdot k} + \beta \cdot \textsf{ct}_{\gamma}$
        // With $\alpha=1, \beta=0$: $\textsf{ct}_{\alpha,\beta} = \textsf{ct}_{\gamma\cdot k}$ (no displacement)
        let encryption_of_displaced_decentralized_party_nonce_share =
            encryption_of_masked_decentralized_party_nonce_share_before_displacing;

        Ok(VerifiedSignDataRaw {
            public_signature_nonce: public_signature_nonce.value(),
            encryption_of_partial_signature: encryption_of_partial_signature.value(),
            encryption_of_displaced_decentralized_party_nonce_share:
                encryption_of_displaced_decentralized_party_nonce_share.value(),
        })
    }

    fn advance_sign_party<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    >(
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >>>,
        virtual_party_id_to_decryption_key_share: Option<HashMap<
            PartyID,
            SecretKeyShareSizedInteger
        >>,
        public_input: &SignPartyPublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        rng: &mut impl CsRng,
    ) -> Result<
        AsynchronousRoundResult<Message<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >, (), GroupElement::Signature>,
        Error,
    >  where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: DiscreteLogInF<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        DecryptionKeyShare<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicDecryptionKeyShare<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            PublicParameters = decryption_key_share::PublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
            SecretKeyShare = SecretKeyShareSizedInteger,
            PartialDecryptionProof = decryption_key_share::PartialDecryptionProof<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber,
            Error = ::class_groups::Error
        >,
        Uint<MESSAGE_LIMBS>: Encoding,
        GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    {
        if public_input.dkg_output != *public_input.protocol_public_parameters
            || public_input.presign != *public_input.protocol_public_parameters
            || public_input.presign != public_input.dkg_output
        {
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

        let targeted_presign = public_input
            .presign
            .derive_targeted::<SCALAR_LIMBS, SCALAR_LIMBS, GroupElement, EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >>(
                public_input.protocol_public_parameters.as_ref(),
                public_input.dkg_output.clone().into(),
            )?;

        let virtual_party_id_to_decryption_key_share = virtual_party_id_to_decryption_key_share
            .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))?;

        let virtual_party_id_to_decryption_key_share = virtual_party_id_to_decryption_key_share
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                DecryptionKeyShare::new(
                    virtual_party_id,
                    decryption_key_share,
                    &public_input.decryption_key_share_public_parameters,
                    rng,
                )
                .map(|decryption_key_share| (virtual_party_id, decryption_key_share))
            })
            .try_collect_hash_map()?;

        let hashed_message = hash_to_scalar::<SCALAR_LIMBS, GroupElement>(
            &public_input.message,
            public_input.hash_type,
            &public_input.hash_context,
            &public_input
                .protocol_public_parameters
                .scalar_group_public_parameters,
        )?;

        match &messages[..] {
            [] => {
                let verified_data = emulate_or_verify_or_unpack_sign_data::<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                >(
                    public_input.sign_message.clone(),
                    hashed_message,
                    targeted_presign,
                    &public_input.protocol_public_parameters,
                    &public_input.dkg_output,
                )?;

                signature_partial_decryption_round::Party::partially_decrypt_encryption_of_signature_parts_prehash_semi_honest::<
                    SCALAR_LIMBS,
                    ::class_groups::EncryptionKey<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >,
                    ::class_groups::DecryptionKeyShare<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >,
                >(
                    public_input.expected_decrypters.clone(),
                    verified_data.encryption_of_partial_signature,
                    verified_data.encryption_of_displaced_decentralized_party_nonce_share,
                    &public_input.decryption_key_share_public_parameters,
                    virtual_party_id_to_decryption_key_share,
                    tangible_party_id,
                    access_structure,
                    &public_input.protocol_public_parameters.encryption_scheme_public_parameters,
                ).map(|message| AsynchronousRoundResult::Advance { malicious_parties: vec![], message: Message::DecryptionShares(message) })
            }
            [first_round_messages] => {
                // Make sure everyone sent the first round message for each virtual party in their virtual subset.
                let (malicious_parties, decryption_shares) = first_round_messages
                    .clone()
                    .into_iter()
                    .map(|(tangible_party_id, message)| {
                        let res = match message {
                            Message::DecryptionShares(decryption_shares)
                                if Some(&decryption_shares.keys().copied().collect())
                                    == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) =>
                            {
                                Ok(decryption_shares)
                            }
                            _ => Err(Error::from(ErrorKind::InvalidParameters)),
                        };

                        (tangible_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Map to virtual parties
                let decryption_shares = decryption_shares.into_values().flat_map(|decryption_shares| decryption_shares.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share))| (virtual_party_id, vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share])).collect::<Vec<_>>()).collect();

                // Verification was already performed in the first round; just unpack/emulate.
                let verified_data = resolve_sign_data::<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    MESSAGE_LIMBS,
                    GroupElement,
                >(
                    public_input.sign_message.clone(),
                    hashed_message,
                    targeted_presign.clone(),
                    &public_input.protocol_public_parameters,
                    &public_input.dkg_output,
                )?;

                let (
                    public_signature_nonce,
                    encryption_of_partial_signature,
                    encryption_of_displaced_decentralized_party_nonce_share,
                ) = (
                    verified_data.public_signature_nonce,
                    verified_data.encryption_of_partial_signature,
                    verified_data.encryption_of_displaced_decentralized_party_nonce_share,
                );

                if let Ok(signature) = signature_threshold_decryption_round::Party::decrypt_signature_semi_honest_class_groups(public_input.expected_decrypters.clone(), decryption_shares, hashed_message, public_input.dkg_output.clone(), public_signature_nonce, encryption_of_partial_signature, encryption_of_displaced_decentralized_party_nonce_share, &public_input.decryption_key_share_public_parameters, &public_input.protocol_public_parameters, access_structure) {
                    // Happy-flow: no party maliciously decrypted the message and we were able to finalize the signature in the semi-honest flow.
                    Ok(AsynchronousRoundResult::Finalize {
                        malicious_parties,
                        private_output: (),
                        public_output: signature,
                    })
                } else {
                    // Sad-flow (infrequent): at least one party maliciously decrypted the message and we were unable to finalize the signature in the semi-honest flow.
                    // Therefore, we must perform an additional round where we verifiably decrypt the signature reconstruct the maliciously generated decryption shares, identifying the malicious parties in retrospect.

                    let verified_data = emulate_or_verify_or_unpack_sign_data::<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        MESSAGE_LIMBS,
                        GroupElement,
                    >(
                        public_input.sign_message.clone(),
                        hashed_message,
                        targeted_presign,
                        &public_input.protocol_public_parameters,
                        &public_input.dkg_output,
                    )?;

                    signature_partial_decryption_round::Party::partially_decrypt_encryption_of_signature_parts_prehash::<
                        SCALAR_LIMBS,
                        ::class_groups::EncryptionKey<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >,
                        ::class_groups::DecryptionKeyShare<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >,
                    >(
                        verified_data.encryption_of_partial_signature,
                        verified_data.encryption_of_displaced_decentralized_party_nonce_share,
                        &public_input.decryption_key_share_public_parameters,
                        virtual_party_id_to_decryption_key_share,
                        tangible_party_id,
                        access_structure,
                        &public_input.protocol_public_parameters.encryption_scheme_public_parameters,
                        rng,
                    ).map(|message| AsynchronousRoundResult::Advance { malicious_parties, message: Message::DecryptionSharesAndProof(message) })
                }
            }
            [first_round_messages, second_round_messages] => {
                // Make sure everyone sent the first round message for each virtual party in their virtual subset.
                let (
                    parties_sending_invalid_first_round_messages,
                    invalid_semi_honest_decryption_shares,
                ) = first_round_messages
                    .clone()
                    .into_iter()
                    .map(|(tangible_party_id, message)| {
                        let res = match message {
                            Message::DecryptionShares(decryption_shares)
                                if Some(&decryption_shares.keys().copied().collect())
                                    == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) =>
                            {
                                Ok(decryption_shares)
                            }
                            _ => Err(Error::from(ErrorKind::InvalidParameters)),
                        };

                        (tangible_party_id, res)
                    })
                    .handle_invalid_messages_async();

                // Next make sure everyone sent the second round message.
                let (parties_sending_invalid_second_round_messages, decryption_shares_and_proofs) =
                    second_round_messages
                        .clone()
                        .into_iter()
                        .map(|(tangible_party_id, message)| {
                            let res = match message {
                                Message::DecryptionSharesAndProof(decryption_shares_and_proofs)
                                    if Some(
                                        &decryption_shares_and_proofs.keys().copied().collect(),
                                    ) == access_structure
                                        .party_to_virtual_parties()
                                        .get(&tangible_party_id) =>
                                {
                                    Ok(decryption_shares_and_proofs)
                                }
                                _ => Err(Error::from(ErrorKind::InvalidParameters)),
                            };

                            (tangible_party_id, res)
                        })
                        .handle_invalid_messages_async();

                // Map to virtual parties
                let invalid_semi_honest_decryption_shares = invalid_semi_honest_decryption_shares.into_values().flat_map(|decryption_shares| decryption_shares.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share))| (virtual_party_id, vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share])).collect::<Vec<_>>()).collect();
                let decryption_shares_and_proofs = decryption_shares_and_proofs.into_values().flat_map(|decryption_shares_and_proofs| decryption_shares_and_proofs.into_iter().map(|(virtual_party_id, (partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share, proof))| (virtual_party_id, (vec![partial_signature_decryption_share, displaced_decentralized_party_nonce_share_decryption_share], proof))).collect::<Vec<_>>()).collect();

                // Verification was already performed in the first round (either via the `Unverified`
                // path which verifies inline, or via prior `verify_centralized_party_partial_signature`
                // for the `Verified` path). Here we only need to extract the data from the enum;
                // no divergence in code flow between the two cases.
                let (
                    public_signature_nonce,
                    encryption_of_partial_signature,
                    encryption_of_displaced_decentralized_party_nonce_share,
                    // Verification was already performed in a previous round; just unpack/emulate.
                ) = {
                    let verified_data = resolve_sign_data::<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        MESSAGE_LIMBS,
                        GroupElement,
                    >(
                        public_input.sign_message.clone(),
                        hashed_message,
                        targeted_presign,
                        &public_input.protocol_public_parameters,
                        &public_input.dkg_output,
                    )?;
                    (
                        verified_data.public_signature_nonce,
                        verified_data.encryption_of_partial_signature,
                        verified_data.encryption_of_displaced_decentralized_party_nonce_share,
                    )
                };

                let (malicious_decrypters, signature) =
                    signature_threshold_decryption_round::Party::decrypt_signature_class_groups(
                        public_input.expected_decrypters.clone(),
                        invalid_semi_honest_decryption_shares,
                        decryption_shares_and_proofs,
                        hashed_message,
                        public_input.dkg_output.clone(),
                        public_signature_nonce,
                        encryption_of_partial_signature,
                        encryption_of_displaced_decentralized_party_nonce_share,
                        &public_input.decryption_key_share_public_parameters,
                        access_structure,
                        &public_input.protocol_public_parameters,
                        rng,
                    )?;

                let malicious_parties = parties_sending_invalid_first_round_messages
                    .into_iter()
                    .chain(parties_sending_invalid_second_round_messages)
                    .chain(malicious_decrypters)
                    .deduplicate_and_sort();

                Ok(AsynchronousRoundResult::Finalize {
                    malicious_parties,
                    private_output: (),
                    public_output: signature,
                })
            }
            _ => Err(Error::from(ErrorKind::InvalidParameters)),
        }
    }
}

#[cfg(test)]
mod tests {
    use ::class_groups::{CiphertextSpaceGroupElement, DecryptionKey};
    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, GroupElement as _, Samplable};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
    };

    use crate::ecdsa::VerifyingKey;
    use crate::presign::tests::mock_ecdsa_presign_deterministic;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::asynchronous::emulate_threshold_verified_sign_data;

    type Secp256k1EncryptionKey = ::class_groups::Secp256k1EncryptionKey;

    /// Verify that `emulate_threshold_verified_sign_data` produces correct ciphertexts
    /// by decrypting its output and comparing with expected plaintext values.
    ///
    /// Uses a deterministic seeded RNG so μ_k challenges are stable across runs.
    /// Hardcoded μ_k values (derived once from seed 0):
    ///   mu_k_first  = 2FE1EE2230B3DA8B7F393E29A4C66927D3014049241F7297EFD0B66970E0EC95
    ///   mu_k_second = 8E06C87732D7DA21B0FFFA16678D8C5F548CF4A461EB42A05566CD5E0F530E07
    ///   mu_k_free   = 72CCEB20EFD721F512C933409024AFF5333D6D1F19D254A451C44AF703F8AE38
    #[test]
    fn emulate_threshold_verified_sign_data_produces_correct_ciphertexts() {
        use crypto_bigint::Uint;

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        let (protocol_public_parameters, raw_decryption_key) =
            crate::test_helpers::setup_class_groups_secp256k1_with_rng(&mut rng);

        let session_id = CommitmentSizedNumber::from(42u64);

        let decentralized_dkg_output =
            crate::dkg::decentralized_party::Party::<
                { secp256k1::SCALAR_LIMBS },
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                Secp256k1EncryptionKey,
                crate::class_groups::ProtocolPublicParameters<
                    { secp256k1::SCALAR_LIMBS },
                    { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
                    secp256k1::GroupElement,
                >,
                (),
            >::threshold_dkg_output(&protocol_public_parameters, session_id)
            .unwrap();

        let (presign, _mask, nonce_share_first_part, nonce_share_second_part) =
            mock_ecdsa_presign_deterministic::<
                { secp256k1::SCALAR_LIMBS },
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                Secp256k1EncryptionKey,
            >(
                session_id,
                decentralized_dkg_output.clone(),
                &protocol_public_parameters,
                &mut rng,
            );

        let crate::ecdsa::presign::VersionedPresign::TargetedPresign(presign) = presign else {
            panic!("mock should return TargetedPresign");
        };

        let encryption_scheme_pp = &protocol_public_parameters.encryption_scheme_public_parameters;
        let ciphertext_space_pp = encryption_scheme_pp.ciphertext_space_public_parameters();

        let decryption_key = DecryptionKey::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            secp256k1::GroupElement,
        >::new(raw_decryption_key.decryption_key, encryption_scheme_pp)
        .unwrap();

        // Decrypt γ and γ·x_B from presign for ct_A verification.
        let ct_gamma = CiphertextSpaceGroupElement::<
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >::new(presign.encryption_of_mask, ciphertext_space_pp)
        .unwrap();
        let gamma: secp256k1::Scalar =
            Option::from(decryption_key.decrypt(&ct_gamma, encryption_scheme_pp)).unwrap();

        let ct_gamma_x_b = CiphertextSpaceGroupElement::<
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >::new(
            presign.encryption_of_masked_decentralized_party_key_share,
            ciphertext_space_pp,
        )
        .unwrap();
        let gamma_x_b: secp256k1::Scalar =
            Option::from(decryption_key.decrypt(&ct_gamma_x_b, encryption_scheme_pp)).unwrap();

        // Deterministic message hash (from seeded rng).
        let hashed_message = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut rng,
        )
        .unwrap();

        // Call the function under test.
        let verified_sign_data = emulate_threshold_verified_sign_data::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >(
            hashed_message,
            presign.clone(),
            &protocol_public_parameters,
            &decentralized_dkg_output,
        )
        .unwrap();

        // === Verify ct_A ===
        let ct_a = CiphertextSpaceGroupElement::<
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >::new(
            verified_sign_data.encryption_of_partial_signature,
            ciphertext_space_pp,
        )
        .unwrap();
        let decrypted_partial_signature: secp256k1::Scalar =
            Option::from(decryption_key.decrypt(&ct_a, encryption_scheme_pp)).unwrap();

        let public_signature_nonce = secp256k1::GroupElement::new(
            verified_sign_data.public_signature_nonce,
            &protocol_public_parameters.group_public_parameters,
        )
        .unwrap();
        let nonce_x_coordinate = public_signature_nonce.x_projected_to_scalar_field();

        let expected_partial_signature = (hashed_message * gamma).add_constant_time(
            &(nonce_x_coordinate * gamma_x_b),
            &protocol_public_parameters.scalar_group_public_parameters,
        );

        assert_eq!(
            decrypted_partial_signature.value(),
            expected_partial_signature.value(),
            "ct_A should decrypt to m*gamma + r*gamma_x_b"
        );

        // === Verify ct_{alpha,beta} using hardcoded μ_k values ===
        // With alpha=1, beta=0: ct_{alpha,beta} decrypts to
        //   mu_k_first * (gamma * k_0) + mu_k_second * (gamma * k_1) + mu_k_free * gamma
        let mu_k_first = Uint::<{ secp256k1::SCALAR_LIMBS }>::from_be_hex(
            "2FE1EE2230B3DA8B7F393E29A4C66927D3014049241F7297EFD0B66970E0EC95",
        );
        let mu_k_second = Uint::<{ secp256k1::SCALAR_LIMBS }>::from_be_hex(
            "8E06C87732D7DA21B0FFFA16678D8C5F548CF4A461EB42A05566CD5E0F530E07",
        );
        let mu_k_free = Uint::<{ secp256k1::SCALAR_LIMBS }>::from_be_hex(
            "72CCEB20EFD721F512C933409024AFF5333D6D1F19D254A451C44AF703F8AE38",
        );

        let gamma_k_first = gamma * nonce_share_first_part;
        let gamma_k_second = gamma * nonce_share_second_part;

        let mu_k_first_scalar = secp256k1::Scalar::new(
            mu_k_first.into(),
            &protocol_public_parameters.scalar_group_public_parameters,
        )
        .unwrap();
        let mu_k_second_scalar = secp256k1::Scalar::new(
            mu_k_second.into(),
            &protocol_public_parameters.scalar_group_public_parameters,
        )
        .unwrap();
        let mu_k_free_scalar = secp256k1::Scalar::new(
            mu_k_free.into(),
            &protocol_public_parameters.scalar_group_public_parameters,
        )
        .unwrap();

        let expected_nonce = (mu_k_first_scalar * gamma_k_first)
            .add_constant_time(
                &(mu_k_second_scalar * gamma_k_second),
                &protocol_public_parameters.scalar_group_public_parameters,
            )
            .add_constant_time(
                &(mu_k_free_scalar * gamma),
                &protocol_public_parameters.scalar_group_public_parameters,
            );

        let ct_nonce = CiphertextSpaceGroupElement::<
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        >::new(
            verified_sign_data.encryption_of_displaced_decentralized_party_nonce_share,
            ciphertext_space_pp,
        )
        .unwrap();
        let decrypted_nonce: secp256k1::Scalar =
            Option::from(decryption_key.decrypt(&ct_nonce, encryption_scheme_pp)).unwrap();

        assert_eq!(
            decrypted_nonce.value(),
            expected_nonce.value(),
            "ct_alpha_beta should decrypt to mu_k_first*(gamma*k_0) + mu_k_second*(gamma*k_1) + mu_k_free*gamma"
        );
    }

    /// Verify that `emulate_threshold_verified_sign_data` rejects a DKG output
    /// where the centralized party public key share is not the neutral element.
    #[test]
    fn emulate_threshold_rejects_non_neutral_public_key_share() {
        use crate::dkg::tests::mock_targeted_dkg_output;

        let (protocol_public_parameters, _raw_decryption_key) =
            crate::test_helpers::setup_class_groups_secp256k1();

        let session_id = CommitmentSizedNumber::from(42u64);

        // Use standard mock DKG which has a random (non-neutral) X_A.
        let (_, _, non_neutral_dkg_output) = mock_targeted_dkg_output::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >(&protocol_public_parameters);

        let presign = crate::presign::tests::mock_ecdsa_presign::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >(
            session_id,
            non_neutral_dkg_output.clone(),
            &protocol_public_parameters,
        );

        let crate::ecdsa::presign::VersionedPresign::TargetedPresign(presign) = presign else {
            panic!("mock should return TargetedPresign");
        };

        let hashed_message = secp256k1::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            &mut group::OsCsRng,
        )
        .unwrap();

        let result = emulate_threshold_verified_sign_data::<
            { secp256k1::SCALAR_LIMBS },
            { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >(
            hashed_message,
            presign,
            &protocol_public_parameters,
            &non_neutral_dkg_output,
        );

        assert!(
            result.is_err(),
            "emulate_threshold_verified_sign_data should reject non-neutral public key share"
        );
    }
}
