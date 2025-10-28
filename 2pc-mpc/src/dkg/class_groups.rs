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
    use class_groups::setup::DeriveFromPlaintextPublicParameters;
    use class_groups::setup::SetupParameters;
    use class_groups::MultiFoldNupowAccelerator;
    use class_groups::DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER;
    use class_groups::{CiphertextSpaceValue, DecryptionKey};
    use group::{CsRng, GroupElement, PrimeGroupElement, StatisticalSecuritySizedNumber};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
        GroupsPublicParametersAccessors,
    };

    use crate::class_groups::CentralizedPartyKeyShareVerification;
    use crate::class_groups::ProtocolPublicParameters;
    use crate::dkg::centralized_party::SecretKeyShare;
    use crate::dkg::{centralized_party, decentralized_party};
    use crate::languages::class_groups::{
        prove_encryption_of_discrete_log, verify_encryption_of_discrete_log,
        EncryptionOfDiscreteLogProof,
    };
    use crate::languages::{KnowledgeOfDiscreteLogProof, KnowledgeOfDiscreteLogUCProof};
    use crate::{dkg, Error, ProtocolContext};

    pub(crate) fn verify_centralized_party_key_share<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
        >,
      dkg_output: crate::class_groups::DKGDecentralizedPartyVersionedOutput<
          SCALAR_LIMBS,
          FUNDAMENTAL_DISCRIMINANT_LIMBS,
          NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
          GroupElement,
      >,
      centralized_party_secret_key_share_verification: CentralizedPartyKeyShareVerification<
          SCALAR_LIMBS,
          FUNDAMENTAL_DISCRIMINANT_LIMBS,
          NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
          GroupElement,
      >,
    ) -> crate::Result<()>               where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
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
                group::PublicParameters::<GroupElement::Scalar>,
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
    {
        match centralized_party_secret_key_share_verification {
            CentralizedPartyKeyShareVerification::Encrypted {
                encryption_key_value,
                encrypted_secret_key_share_message,
            } => verify_encryption_of_centralized_party_share_proof::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >(
                protocol_public_parameters,
                dkg_output,
                encryption_key_value,
                encrypted_secret_key_share_message,
            ),
            CentralizedPartyKeyShareVerification::Public {
                centralized_party_secret_key_share,
            } => verify_centralized_party_public_key_share::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >(
                protocol_public_parameters,
                dkg_output,
                centralized_party_secret_key_share,
            ),
            CentralizedPartyKeyShareVerification::None => Ok(()),
        }
    }

    pub(crate) fn verify_encryption_of_centralized_party_share_proof<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    >(protocol_public_parameters: &ProtocolPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
      dkg_output: crate::class_groups::DKGDecentralizedPartyVersionedOutput<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
      >,
      encryption_key_value: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
      encrypted_secret_key_share_message:     (EncryptionOfDiscreteLogProof<SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement, PhantomData<()>>, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>)
    ) -> crate::Result<()>               where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
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
    {
        if &dkg_output != protocol_public_parameters {
            return Err(Error::InvalidParameters);
        }

        let dkg_output = decentralized_party::Output::from(dkg_output);

        let (
            encryption_of_centralized_party_secret_key_share_proof,
            encryption_of_centralized_party_secret_key_share,
        ) = encrypted_secret_key_share_message;

        let encryption_key = EquivalenceClass::new(
            encryption_key_value,
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .setup_parameters
                .equivalence_class_public_parameters(),
        )?;

        let encryption_scheme_public_parameters = PublicParameters::new(
            protocol_public_parameters
                .encryption_scheme_public_parameters
                .setup_parameters
                .clone(),
            encryption_key,
        )?;

        verify_encryption_of_discrete_log(
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            encryption_scheme_public_parameters,
            &PhantomData,
            encryption_of_centralized_party_secret_key_share_proof,
            dkg_output.centralized_party_public_key_share,
            encryption_of_centralized_party_secret_key_share,
        )
    }

    pub(crate) fn verify_centralized_party_public_key_share<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        dkg_output: crate::class_groups::DKGDecentralizedPartyVersionedOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        centralized_party_secret_key_share: SecretKeyShare<group::Value<GroupElement::Scalar>>,
    ) -> crate::Result<()> where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
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
    >,{
        if &dkg_output != protocol_public_parameters {
            return Err(Error::InvalidParameters);
        }

        let dkg_output = decentralized_party::Output::from(dkg_output);
        let centralized_party_secret_key_share = GroupElement::Scalar::new(
            centralized_party_secret_key_share.0,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;
        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )?;
        let centralized_party_public_key_share = GroupElement::new(
            dkg_output.centralized_party_public_key_share,
            &protocol_public_parameters.group_public_parameters,
        )?;

        if centralized_party_secret_key_share * generator == centralized_party_public_key_share {
            Ok(())
        } else {
            Err(Error::InvalidPublicCentralizedKeyShare)
        }
    }

    pub(crate) fn verify_and_decrypt_encryption_of_centralized_party_share_proof<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    >(
        protocol_public_parameters: &ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        dkg_output: crate::class_groups::DKGDecentralizedPartyVersionedOutput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        encrypted_secret_key_share_message:     (EncryptionOfDiscreteLogProof<SCALAR_LIMBS, FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, GroupElement, PhantomData<()>>, CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>),
        decryption_key: ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>
    ) -> crate::Result<SecretKeyShare<group::Value<GroupElement::Scalar>>>               where
        Int<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding,
        Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
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
        DecryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >: AdditivelyHomomorphicDecryptionKey<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>
        >,
    {
        let setup_parameters = protocol_public_parameters
            .encryption_scheme_public_parameters
            .setup_parameters
            .clone();

        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >::new_from_secret_key(setup_parameters, decryption_key)?;

        let (_, encryption_of_centralized_party_secret_key_share) =
            &encrypted_secret_key_share_message;

        let encryption_of_centralized_party_secret_key_share =
            *encryption_of_centralized_party_secret_key_share;

        verify_encryption_of_centralized_party_share_proof(
            protocol_public_parameters,
            dkg_output,
            encryption_scheme_public_parameters.encryption_key.value(),
            encrypted_secret_key_share_message,
        )?;

        let encryption_of_centralized_party_secret_key_share = CiphertextSpaceGroupElement::new(
            encryption_of_centralized_party_secret_key_share,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

        let decryption_key =
            DecryptionKey::new(decryption_key, &encryption_scheme_public_parameters)?;

        // We verified the proof, so this must be a correct encryption and decryption cannot fail.
        let centralized_party_secret_key_share: GroupElement::Scalar =
            Option::from(decryption_key.decrypt(
                &encryption_of_centralized_party_secret_key_share,
                &encryption_scheme_public_parameters,
            ))
            .ok_or(Error::InternalError)?;

        Ok(SecretKeyShare(centralized_party_secret_key_share.value()))
    }

    macro_rules! impl_class_groups_dkg_protocol_for_types {
        ($($t:ty),*) => {
            $(
                impl<
                        const SCALAR_LIMBS: usize,
                        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
                        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
                        const MESSAGE_LIMBS: usize,
                        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
                    > super::super::Protocol
                    for $t
                where
                    Int<SCALAR_LIMBS>: Encoding,
                    Uint<SCALAR_LIMBS>: Encoding,
                    Uint<SCALAR_LIMBS>: Encoding + ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
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
                    SetupParameters<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        group::PublicParameters<GroupElement::Scalar>,
                    >: DeriveFromPlaintextPublicParameters<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        group::PublicParameters<GroupElement::Scalar>,
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
                    DecryptionKey<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >: AdditivelyHomomorphicDecryptionKey<
                        SCALAR_LIMBS,
                        EncryptionKey<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >,
                        SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>
                    >,
                    Uint<MESSAGE_LIMBS>: Encoding,
                    group::PublicParameters<GroupElement::Scalar>: Default,
                {
                    type ProtocolPublicParameters = ProtocolPublicParameters<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >;
                    type ProtocolContext = ProtocolContext;
                    type EncryptionKeyValue = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
                    type DecryptionKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>;
                    type SecretKey = group::Value<GroupElement::Scalar>;
                    type CentralizedPartySecretKeyShare = SecretKeyShare<group::Value<GroupElement::Scalar>>;
                    type CentralizedPartyDKGOutput =
                        crate::class_groups::DKGCentralizedPartyVersionedOutput<SCALAR_LIMBS, GroupElement>;
                    type CentralizedPartyTargetedDKGOutput =
                        crate::class_groups::DKGCentralizedPartyOutput<SCALAR_LIMBS, GroupElement>;
                    type DecentralizedPartyDKGOutput = crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >;
                    type DecentralizedPartyTargetedDKGOutput = crate::class_groups::DKGDecentralizedPartyOutput<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >;
                    type DKGDecentralizedPartyPublicInput =
                        crate::class_groups::DKGDecentralizedPartyPublicInput<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >;
                    type DKGDecentralizedParty = crate::class_groups::DKGDecentralizedParty<
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

                    fn generate_decryption_key(
                        rng: &mut impl CsRng,
                    ) -> crate::Result<Self::DecryptionKey> {
                        let plaintext_space_public_parameters = group::PublicParameters::<GroupElement::Scalar>::default();

                        let decryption_key = DecryptionKey::generate(
                            plaintext_space_public_parameters,
                            rng
                        )?;

                        Ok(decryption_key.decryption_key)
                    }

                    fn encryption_key_from_decryption_key(
                        decryption_key: Self::DecryptionKey,
                    ) -> crate::Result<Self::EncryptionKeyValue> {
                       let plaintext_space_public_parameters = group::PublicParameters::<GroupElement::Scalar>::default();

                        let setup_parameters = SetupParameters::<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            group::PublicParameters<GroupElement::Scalar>,
                        >::derive_from_plaintext_parameters::<GroupElement::Scalar>(
                            plaintext_space_public_parameters,
                            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                        )?;

                        let encryption_scheme_public_parameters = encryption_key::PublicParameters::new_from_secret_key(setup_parameters, decryption_key)?;

                        Ok(encryption_scheme_public_parameters.encryption_key.value())
                    }

                    fn encrypt_and_prove_centralized_party_share(protocol_public_parameters: &Self::ProtocolPublicParameters, encryption_key_value: Self::EncryptionKeyValue, centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare, rng: &mut impl CsRng,) -> crate::Result<Self::EncryptedSecretKeyShareMessage> {
                        let centralized_party_secret_key_share = GroupElement::Scalar::new(centralized_party_secret_key_share.0, &protocol_public_parameters.scalar_group_public_parameters)?;
                        let encryption_key = EquivalenceClass::new(
                            encryption_key_value,
                            protocol_public_parameters.encryption_scheme_public_parameters.setup_parameters.equivalence_class_public_parameters()
                        )?;
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

                    fn verify_encryption_of_centralized_party_share_proof(protocol_public_parameters: &Self::ProtocolPublicParameters, dkg_output: Self::DecentralizedPartyDKGOutput, encryption_key_value: Self::EncryptionKeyValue, encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage, _rng: &mut impl CsRng,) -> crate::Result<()> {
                       verify_encryption_of_centralized_party_share_proof::<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >(protocol_public_parameters, dkg_output, encryption_key_value, encrypted_secret_key_share_message)
                    }

                    fn verify_and_decrypt_encryption_of_centralized_party_share_proof(
                        protocol_public_parameters: &Self::ProtocolPublicParameters,
                        dkg_output: Self::DecentralizedPartyDKGOutput,
                        encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage,
                        decryption_key: Self::DecryptionKey,
                        _rng: &mut impl CsRng,
                    ) -> crate::Result<Self::CentralizedPartySecretKeyShare> {
                       verify_and_decrypt_encryption_of_centralized_party_share_proof::<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >(protocol_public_parameters, dkg_output, encrypted_secret_key_share_message, decryption_key)
                    }

                    fn verify_centralized_party_public_key_share(protocol_public_parameters: &Self::ProtocolPublicParameters, dkg_output: Self::DecentralizedPartyDKGOutput, centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare) -> crate::Result<()> {
                        verify_centralized_party_public_key_share::<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >(protocol_public_parameters, dkg_output, centralized_party_secret_key_share)
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
                        CentralizedPartyKeyShareVerification<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            GroupElement,
                        >,
                    >;

                    type TrustedDealerDKGDecentralizedParty = crate::class_groups::TrustedDealerDKGDecentralizedParty<
                        SCALAR_LIMBS,
                        FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        GroupElement,
                    >;
                }
            )*
        };
    }

    impl_class_groups_dkg_protocol_for_types!(
        crate::class_groups::ecdsa::asynchronous::Protocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > ,
        crate::class_groups::schnorr::asynchronous::Protocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >
    );
}
