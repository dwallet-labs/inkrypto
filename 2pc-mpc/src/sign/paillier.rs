// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Sign` protocol trait for Paillier

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{ConcatMixed, Encoding, Uint};
use group::{AffineXCoordinate, HashToGroup, PrimeGroupElement, StatisticalSecuritySizedNumber};
use serde::{Deserialize, Serialize};

use crate::paillier;
use crate::paillier::bulletproofs::SignMessage;
use crate::paillier::{asynchronous::Protocol, PLAINTEXT_SPACE_SCALAR_LIMBS};
use crate::sign::decentralized_party::signature_partial_decryption_round;

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    > super::Protocol
    for Protocol<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        GroupElement,
    >
where
    Uint<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        > + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    Uint<RANGE_CLAIMS_PER_SCALAR>: Encoding,
    GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
{
    type HashedMessage = GroupElement::Scalar;
    type Signature = (GroupElement::Scalar, GroupElement::Scalar);
    type DecryptionKeyShare = tiresias::DecryptionKeyShare;
    type DecryptionKeySharePublicParameters = tiresias::decryption_key_share::PublicParameters;
    type SignDecentralizedPartyPublicInput = super::decentralized_party::PublicInput<
        GroupElement::Scalar,
        Self::DecentralizedPartyDKGOutput,
        Self::Presign,
        Self::SignMessage,
        Self::DecryptionKeySharePublicParameters,
        Self::ProtocolPublicParameters,
    >;
    type SignDecentralizedParty = super::decentralized_party::paillier::asynchronous::Party<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        GroupElement,
    >;
    type SignCentralizedPartyPublicInput =
        super::centralized_party::signature_homomorphic_evaluation_round::PublicInput<
            GroupElement::Scalar,
            Self::CentralizedPartyDKGPublicOutput,
            Self::Presign,
            Self::ProtocolPublicParameters,
        >;
    type SignMessage = SignMessage<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        GroupElement,
    >;
    type SignCentralizedParty =
        super::centralized_party::signature_homomorphic_evaluation_round::Party<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            paillier::EncryptionKey,
            Self::SignMessage,
            Self::ProtocolPublicParameters,
        >;

    fn verify_encryption_of_signature_parts_prehash(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        dkg_output: Self::DecentralizedPartyDKGOutput,
        presign: Self::Presign,
        sign_message: Self::SignMessage,
        hashed_message: Self::HashedMessage,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<()> {
        signature_partial_decryption_round::Party::verify_encryption_of_signature_parts_prehash_paillier(protocol_public_parameters, dkg_output, presign, sign_message, hashed_message, rng)
    }
}
