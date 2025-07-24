// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Sign` protocol trait for Class Groups

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use crate::class_groups::{asynchronous::Protocol, DecryptionKeySharePublicParameters};
use crate::sign::centralized_party::message::class_groups::Message;
use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, DecryptionKeyShare, EncryptionKey,
    EquivalenceClass, RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use ::class_groups::{DecryptionKey, DiscreteLogInF};
use group::{AffineXCoordinate, HashToGroup, PrimeGroupElement, StatisticalSecuritySizedNumber};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use sign::decentralized_party::signature_partial_decryption_round;

use crate::sign;

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + HashToGroup,
    > super::Protocol
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
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
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
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
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
    Uint<MESSAGE_LIMBS>: Encoding,
    GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
{
    type HashedMessage = GroupElement::Scalar;
    type Signature = (GroupElement::Scalar, GroupElement::Scalar);
    type DecryptionKeyShare = DecryptionKeyShare<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
    type DecryptionKeySharePublicParameters = DecryptionKeySharePublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
    type SignDecentralizedPartyPublicInput = super::decentralized_party::PublicInput<
        GroupElement::Scalar,
        Self::DecentralizedPartyDKGOutput,
        Self::Presign,
        Self::SignMessage,
        Self::DecryptionKeySharePublicParameters,
        Self::ProtocolPublicParameters,
    >;
    type SignDecentralizedParty = super::decentralized_party::class_groups::asynchronous::Party<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >;
    type SignCentralizedPartyPublicInput =
        super::centralized_party::signature_homomorphic_evaluation_round::PublicInput<
            GroupElement::Scalar,
            Self::CentralizedPartyDKGPublicOutput,
            Self::Presign,
            Self::ProtocolPublicParameters,
        >;
    type SignMessage = Message<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >;
    type SignCentralizedParty =
        super::centralized_party::signature_homomorphic_evaluation_round::Party<
            SCALAR_LIMBS,
            SCALAR_LIMBS,
            GroupElement,
            ::class_groups::EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            Self::SignMessage,
            Self::ProtocolPublicParameters,
        >;

    fn verify_encryption_of_signature_parts_prehash(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        dkg_output: Self::DecentralizedPartyDKGOutput,
        presign: Self::Presign,
        sign_message: Self::SignMessage,
        hashed_message: Self::HashedMessage,
        _rng: &mut impl CryptoRngCore,
    ) -> crate::Result<()> {
        signature_partial_decryption_round::Party::verify_encryption_of_signature_parts_prehash_class_groups(protocol_public_parameters, dkg_output, presign, sign_message, hashed_message)
    }
}
