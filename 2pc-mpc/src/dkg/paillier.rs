// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `DKG` protocol trait for Paillier

pub mod asynchronous {
    use crypto_bigint::{ConcatMixed, Uint};
    use group::{PrimeGroupElement, StatisticalSecuritySizedNumber};

    use crate::dkg::centralized_party::SecretKeyShare;
    use crate::languages::KnowledgeOfDiscreteLogUCProof;
    use crate::paillier::asynchronous::Protocol;
    use crate::paillier::{
        bulletproofs::PaillierProtocolPublicParameters,
        EncryptionOfSecretKeyShareAndPublicKeyShare, EncryptionOfSecretKeyShareRoundAsyncParty,
    };
    use crate::{dkg, ProtocolContext};

    impl<
            const RANGE_CLAIMS_PER_SCALAR: usize,
            const RANGE_CLAIMS_PER_MASK: usize,
            const NUM_RANGE_CLAIMS: usize,
            const SCALAR_LIMBS: usize,
            GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
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
        type DKGCentralizedParty = crate::paillier::DKGCentralizedParty<
            SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            NUM_RANGE_CLAIMS,
            GroupElement,
        >;
    }
}
