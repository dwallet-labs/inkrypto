// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `DKG` protocol trait for Class Groups

pub mod asynchronous {
    use crate::class_groups::{
        asynchronous::Protocol, EncryptionOfSecretKeyShareAndPublicKeyShare,
        EncryptionOfSecretKeyShareRoundAsyncParty, ProtocolPublicParameters,
    };
    use crate::dkg::centralized_party::SecretKeyShare;
    use crate::languages::KnowledgeOfDiscreteLogUCProof;
    use crate::{dkg, ProtocolContext};
    use ::class_groups::{
        encryption_key, equivalence_class, CiphertextSpaceGroupElement, CompactIbqf, EncryptionKey,
        EquivalenceClass,
    };
    use ::class_groups::{
        CiphertextSpacePublicParameters, RandomnessSpaceGroupElement,
        RandomnessSpacePublicParameters,
    };
    use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
    use group::{PrimeGroupElement, StatisticalSecuritySizedNumber};
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;

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
    {
        type ProtocolPublicParameters = ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
        type ProtocolContext = ProtocolContext;
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
        type DKGCentralizedParty = crate::class_groups::DKGCentralizedParty<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >;
    }
}
