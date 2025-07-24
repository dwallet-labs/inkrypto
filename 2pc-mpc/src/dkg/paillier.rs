// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `DKG` protocol trait for Paillier

pub mod asynchronous {
    use std::marker::PhantomData;

    use crypto_bigint::{ConcatMixed, Uint};

    use group::{CsRng, GroupElement, PrimeGroupElement, Scale, StatisticalSecuritySizedNumber};
    use tiresias::{CiphertextSpaceValue, LargeBiPrimeSizedNumber};

    use crate::bulletproofs::{RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS};
    use crate::dkg::centralized_party::SecretKeyShare;
    use crate::dkg::{centralized_party, decentralized_party};
    use crate::languages::paillier::prove_encryption_of_discrete_log;
    use crate::languages::paillier::{
        verify_encryption_of_discrete_log, EncryptionOfDiscreteLogProof,
    };
    use crate::languages::{KnowledgeOfDiscreteLogProof, KnowledgeOfDiscreteLogUCProof};
    use crate::paillier::asynchronous::Protocol;
    use crate::paillier::{
        bulletproofs::PaillierProtocolPublicParameters,
        EncryptionOfSecretKeyShareAndPublicKeyShare, EncryptionOfSecretKeyShareRoundAsyncParty,
        PublicParameters,
    };
    use crate::paillier::{EncryptionKey, PLAINTEXT_SPACE_SCALAR_LIMBS};
    use crate::{dkg, Error, ProtocolContext};

    impl<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const RANGE_CLAIMS_PER_MASK: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Scale<LargeBiPrimeSizedNumber>,
        > super::super::Protocol
        for Protocol<
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            NUM_RANGE_CLAIMS,
            SCALAR_LIMBS,
            GroupElement,
    > where Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput> + for<'a> From<&'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput>,
    {
        type ProtocolPublicParameters = PaillierProtocolPublicParameters<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
        >;

        type ProtocolContext = ProtocolContext;
        type CentralizedPartyDKGPublicOutput =
            crate::paillier::DKGCentralizedPartyOutput<SCALAR_LIMBS, GroupElement>;
        type DecentralizedPartyDKGOutput =
            crate::paillier::DKGDecentralizedPartyOutput<GroupElement>;
        type EncryptionOfSecretKeyShareAndPublicKeyShare =
            EncryptionOfSecretKeyShareAndPublicKeyShare<SCALAR_LIMBS, GroupElement>;
        type EncryptionOfSecretKeyShareRoundParty = EncryptionOfSecretKeyShareRoundAsyncParty<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >;
        type ProofVerificationRoundPublicInput = crate::paillier::ProofVerificationRoundPublicInput<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >;
        type ProofVerificationRoundParty = crate::paillier::ProofVerificationRoundParty<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >;
        type DKGCentralizedPartyPublicInput =
            dkg::centralized_party::PublicInput<Self::ProtocolPublicParameters>;
        type PublicKeyShareAndProof = dkg::centralized_party::PublicKeyShareAndProof<
            group::Value<GroupElement>,
            KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
        >;
        type CentralizedPartySecretKeyShare = SecretKeyShare<group::Value<GroupElement::Scalar>>;
        type DKGCentralizedPartyRound = crate::paillier::DKGCentralizedParty<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >;

        fn verify_centralized_party_secret_key_share(protocol_public_parameters: &Self::ProtocolPublicParameters, dkg_output: Self::DecentralizedPartyDKGOutput, centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare) -> crate::Result<()> {
            let centralized_party_secret_key_share = GroupElement::Scalar::new(centralized_party_secret_key_share.0, &protocol_public_parameters.protocol_public_parameters.scalar_group_public_parameters)?;
            let generator = GroupElement::generator_from_public_parameters(&protocol_public_parameters.protocol_public_parameters.group_public_parameters)?;
            let centralized_party_public_key_share = GroupElement::new(dkg_output.centralized_party_public_key_share, &protocol_public_parameters.protocol_public_parameters.group_public_parameters)?;

            if centralized_party_secret_key_share * generator == centralized_party_public_key_share {
                Ok(())
            } else {
                Err(Error::InvalidPublicCentralizedKeyShare)
            }
        }

        type SecretKey = group::Value<GroupElement::Scalar>;

        type DealTrustedShareMessage = centralized_party::trusted_dealer::paillier::Message<
            KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement,>,
            EncryptionOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement, ProtocolContext>,
            GroupElement::Value,
            proof::range::CommitmentSchemeCommitmentSpaceValue<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                RangeProof,
            >,
            CiphertextSpaceValue,>;

        type TrustedDealerDKGCentralizedPartyRound = centralized_party::trusted_dealer::Party<        SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            PaillierProtocolPublicParameters<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                NUM_RANGE_CLAIMS,
                group::PublicParameters<GroupElement::Scalar>,
                GroupElement::PublicParameters,
            >,>;

        type TrustedDealerDKGDecentralizedPublicInput = decentralized_party::trusted_dealer::PublicInput<
            centralized_party::trusted_dealer::paillier::Message<
                KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement,>,
                EncryptionOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement, ProtocolContext>,
                GroupElement::Value,
                proof::range::CommitmentSchemeCommitmentSpaceValue<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    RangeProof,
                >,
                CiphertextSpaceValue,
            >,
            PaillierProtocolPublicParameters<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                NUM_RANGE_CLAIMS,
                group::PublicParameters<GroupElement::Scalar>,
                GroupElement::PublicParameters,
            >,
        >;

        type TrustedDealerDKGDecentralizedParty = decentralized_party::trusted_dealer::Party<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
            centralized_party::trusted_dealer::paillier::Message<
                KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement,>,
                EncryptionOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement, ProtocolContext>,
                GroupElement::Value,
                proof::range::CommitmentSchemeCommitmentSpaceValue<
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RANGE_CLAIMS_PER_SCALAR,
                    RangeProof,
                >,
                CiphertextSpaceValue,
            >,
            PaillierProtocolPublicParameters<
                SCALAR_LIMBS,
                RANGE_CLAIMS_PER_SCALAR,
                NUM_RANGE_CLAIMS,
                group::PublicParameters<GroupElement::Scalar>,
                GroupElement::PublicParameters,
            >,
        >;
        type EncryptionKey = LargeBiPrimeSizedNumber;
        type EncryptedSecretKeyShareMessage = (
            EncryptionOfDiscreteLogProof<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement, PhantomData<()>>,
            proof::range::CommitmentSchemeCommitmentSpaceValue<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RangeProof,
        >,
            CiphertextSpaceValue
        );

        fn encrypt_and_prove_centralized_party_share(protocol_public_parameters: &Self::ProtocolPublicParameters, encryption_key: Self::EncryptionKey, centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare, rng: &mut impl CsRng,) -> crate::Result<Self::EncryptedSecretKeyShareMessage> {
            let centralized_party_secret_key_share = GroupElement::Scalar::new(centralized_party_secret_key_share.0, &protocol_public_parameters.protocol_public_parameters.scalar_group_public_parameters)?;
            let encryption_scheme_public_parameters = PublicParameters::new(encryption_key)?;

            let (encryption_of_secret_key_share_proof, range_proof_commitment, encryption_of_secret_key_share) = prove_encryption_of_discrete_log(
                protocol_public_parameters.protocol_public_parameters.group_public_parameters.clone(),
                encryption_scheme_public_parameters,
                protocol_public_parameters.unbounded_encdl_witness_public_parameters.clone(),
                protocol_public_parameters.range_proof_enc_dl_public_parameters.clone(),
                &PhantomData,
                centralized_party_secret_key_share,
                rng
            )?;

            Ok((encryption_of_secret_key_share_proof, range_proof_commitment.value(), encryption_of_secret_key_share.value()))
        }

        fn verify_encryption_of_centralized_party_share_proof(protocol_public_parameters: &Self::ProtocolPublicParameters, dkg_output: Self::DecentralizedPartyDKGOutput, encryption_key: Self::EncryptionKey,encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage, rng: &mut impl CsRng,) -> crate::Result<()> {
            let (encryption_of_centralized_party_secret_key_share_proof, range_proof_commitment, encryption_of_centralized_party_secret_key_share) = encrypted_secret_key_share_message;
            let encryption_scheme_public_parameters = PublicParameters::new(encryption_key)?;

            verify_encryption_of_discrete_log(
                protocol_public_parameters.protocol_public_parameters.group_public_parameters.clone(),
                encryption_scheme_public_parameters,
                protocol_public_parameters.unbounded_encdl_witness_public_parameters.clone(),
                protocol_public_parameters.range_proof_enc_dl_public_parameters.clone(),
                &PhantomData,
                encryption_of_centralized_party_secret_key_share_proof,
                dkg_output.centralized_party_public_key_share,
                range_proof_commitment,
                encryption_of_centralized_party_secret_key_share,
                rng
            )
        }
    }
}
