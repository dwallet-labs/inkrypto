// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `DKG` protocol trait for Class Groups

pub mod asynchronous {
    use std::marker::PhantomData;

    use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};

    use ::class_groups::{
        encryption_key, equivalence_class, CiphertextSpaceGroupElement, CompactIbqf, EncryptionKey,
        EquivalenceClass,
    };
    use ::class_groups::{
        CiphertextSpacePublicParameters, RandomnessSpaceGroupElement,
        RandomnessSpacePublicParameters,
    };
    use class_groups::encryption_key::public_parameters::Instantiate;
    use class_groups::encryption_key::PublicParameters;
    use class_groups::equivalence_class::EquivalenceClassOps;
    use class_groups::CiphertextSpaceValue;
    use class_groups::MultiFoldNupowAccelerator;
    use group::{CsRng, GroupElement, PrimeGroupElement, StatisticalSecuritySizedNumber};
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;

    use crate::class_groups::{
        asynchronous::Protocol, EncryptionOfSecretKeyShareAndPublicKeyShare,
        EncryptionOfSecretKeyShareRoundAsyncParty, ProtocolPublicParameters,
    };
    use crate::dkg::centralized_party::SecretKeyShare;
    use crate::dkg::{centralized_party, decentralized_party};
    use crate::languages::class_groups::{
        prove_encryption_of_discrete_log, verify_encryption_of_discrete_log,
        EncryptionOfDiscreteLogProof,
    };
    use crate::languages::{KnowledgeOfDiscreteLogProof, KnowledgeOfDiscreteLogUCProof};
    use crate::{dkg, Error, ProtocolContext};

    impl<
            const SCALAR_LIMBS: usize,
            const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
            const MESSAGE_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
        > super::super::Protocol
        for Protocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >
    where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
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
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        type ProtocolPublicParameters = ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type ProtocolContext = ProtocolContext;
        type EncryptionKey = EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
        type SecretKey = group::Value<GroupElement::Scalar>;
        type CentralizedPartySecretKeyShare = SecretKeyShare<group::Value<GroupElement::Scalar>>;
        type CentralizedPartyDKGPublicOutput =
            crate::class_groups::DKGCentralizedPartyOutput<SCALAR_LIMBS, GroupElement>;
        type DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type EncryptionOfSecretKeyShareAndPublicKeyShare =
            EncryptionOfSecretKeyShareAndPublicKeyShare<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >;
        type EncryptionOfSecretKeyShareRoundParty = EncryptionOfSecretKeyShareRoundAsyncParty<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type ProofVerificationRoundPublicInput =
            crate::class_groups::ProofVerificationRoundPublicInput<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >;
        type ProofVerificationRoundParty = crate::class_groups::ProofVerificationRoundParty<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type DKGCentralizedPartyPublicInput =
            dkg::centralized_party::PublicInput<Self::ProtocolPublicParameters>;
        type PublicKeyShareAndProof = dkg::centralized_party::PublicKeyShareAndProof<
            group::Value<GroupElement>,
            KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        >;
        type DKGCentralizedPartyRound = crate::class_groups::DKGCentralizedParty<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type EncryptedSecretKeyShareMessage = (EncryptionOfDiscreteLogProof<SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement, PhantomData<()>>, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>);

        fn encrypt_and_prove_centralized_party_share(protocol_public_parameters: &Self::ProtocolPublicParameters, encryption_key: Self::EncryptionKey, centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare, rng: &mut impl CsRng,) -> crate::Result<Self::EncryptedSecretKeyShareMessage> {
            let centralized_party_secret_key_share = GroupElement::Scalar::new(centralized_party_secret_key_share.0, &protocol_public_parameters.scalar_group_public_parameters)?;
            let encryption_scheme_public_parameters = PublicParameters::new(protocol_public_parameters.encryption_scheme_public_parameters.setup_parameters.clone(), encryption_key)?;

            let (encryption_of_secret_key_share_proof, encryption_of_secret_key_share) = prove_encryption_of_discrete_log(
                protocol_public_parameters.scalar_group_public_parameters.clone(),
                protocol_public_parameters.group_public_parameters.clone(),
                encryption_scheme_public_parameters,
                &PhantomData,
                centralized_party_secret_key_share,
                rng
            )?;

            Ok((encryption_of_secret_key_share_proof, encryption_of_secret_key_share.value()))
        }

        fn verify_encryption_of_centralized_party_share_proof(protocol_public_parameters: &Self::ProtocolPublicParameters, dkg_output: Self::DecentralizedPartyDKGOutput, encryption_key: Self::EncryptionKey, encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage, _rng: &mut impl CsRng,) -> crate::Result<()> {
            let (encryption_of_centralized_party_secret_key_share_proof, encryption_of_centralized_party_secret_key_share) = encrypted_secret_key_share_message;
            let encryption_scheme_public_parameters = PublicParameters::new(protocol_public_parameters.encryption_scheme_public_parameters.setup_parameters.clone(), encryption_key)?;

            verify_encryption_of_discrete_log(
                protocol_public_parameters.scalar_group_public_parameters.clone(),
                protocol_public_parameters.group_public_parameters.clone(),
                encryption_scheme_public_parameters,
                &PhantomData,
                encryption_of_centralized_party_secret_key_share_proof,
                dkg_output.centralized_party_public_key_share,
                encryption_of_centralized_party_secret_key_share,
            )
        }

        fn verify_centralized_party_secret_key_share(protocol_public_parameters: &Self::ProtocolPublicParameters, dkg_output: Self::DecentralizedPartyDKGOutput, centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare) -> crate::Result<()> {
            let centralized_party_secret_key_share = GroupElement::Scalar::new(centralized_party_secret_key_share.0, &protocol_public_parameters.scalar_group_public_parameters)?;
            let generator = GroupElement::generator_from_public_parameters(&protocol_public_parameters.group_public_parameters)?;
            let centralized_party_public_key_share = GroupElement::new(dkg_output.centralized_party_public_key_share, &protocol_public_parameters.group_public_parameters)?;

            if centralized_party_secret_key_share * generator == centralized_party_public_key_share {
                Ok(())
            } else {
                Err(Error::InvalidPublicCentralizedKeyShare)
            }
        }

        type DealTrustedShareMessage = centralized_party::trusted_dealer::class_groups::Message<
            KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement,>,
            EncryptionOfDiscreteLogProof<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
                ProtocolContext
            >, GroupElement::Value, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, >;

        type TrustedDealerDKGCentralizedPartyRound = centralized_party::trusted_dealer::Party<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,>;

        type TrustedDealerDKGDecentralizedPublicInput = decentralized_party::trusted_dealer::PublicInput<
            centralized_party::trusted_dealer::class_groups::Message<
                KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement,>,
                EncryptionOfDiscreteLogProof<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                    ProtocolContext
                >,GroupElement::Value,
                CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
            ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;

        type TrustedDealerDKGDecentralizedParty = decentralized_party::trusted_dealer::Party<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            centralized_party::trusted_dealer::class_groups::Message<
                KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement,>,
                EncryptionOfDiscreteLogProof<
                    SCALAR_LIMBS,
                    FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    GroupElement,
                 ProtocolContext
                >,GroupElement::Value,
                CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
            ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >;
    }
}
