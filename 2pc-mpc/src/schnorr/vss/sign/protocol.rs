// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Sign` protocol trait for VSS-based Schnorr signatures.
//!
//! Unlike AHE-based protocols that use threshold decryption, VSS-based protocols
//! use Shamir secret sharing reconstruction directly.

#![allow(clippy::type_complexity)]

use super::centralized_party::{
    Party as CentralizedParty, PublicInput as CentralizedPartyPublicInput,
};
use super::decentralized_party::{
    DKGSignParty, DKGSignPublicInput, PrivateInput as VSSPrivateInput,
    PublicInput as DecentralizedPartyPublicInput, SignParty,
};
use crate::dkg;
use crate::schnorr::sign::decentralized_party::verify_centralized_party_partial_signature;
use crate::schnorr::{PartialSignature, VerifyingKey};
use crate::vss::schnorr::Protocol;
use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, DecryptionKey, EncryptionKey, EquivalenceClass,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use class_groups::MultiFoldNupowAccelerator;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use group::{CsRng, HashScheme, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
};
use serde::{Deserialize, Serialize};

/// Implementation of `sign::Protocol` for VSS-based Schnorr.
impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy + group::Scale<Uint<SCALAR_LIMBS>>,
    > crate::sign::Protocol
    for Protocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
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
        > + Instantiate<
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
        SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    GroupElement::Scalar: From<Uint<SCALAR_LIMBS>>
        + group::Samplable
        + group::Invert
        + std::ops::Mul<Output = GroupElement::Scalar>
        + std::ops::Mul<GroupElement, Output = GroupElement>,
    group::Value<GroupElement::Scalar>: Into<Uint<SCALAR_LIMBS>> + From<Uint<SCALAR_LIMBS>>,
    group::PublicParameters<GroupElement::Scalar>: Default,
    GroupElement::Value: Serialize + for<'a> Deserialize<'a>,
    GroupElement::PublicParameters: Clone + Serialize + for<'a> Deserialize<'a> + PartialEq + Eq,
    <GroupElement::Scalar as group::GroupElement>::PublicParameters:
        Clone + Serialize + for<'a> Deserialize<'a> + PartialEq + Eq,
    group::Value<GroupElement::Scalar>: Serialize + for<'a> Deserialize<'a>,
{
    type Signature = GroupElement::Signature;

    type SignDecentralizedPartyPrivateInput =
        VSSPrivateInput<group::Value<GroupElement::Scalar>, GroupElement::Value>;

    type SignDecentralizedPartyPublicInput = DecentralizedPartyPublicInput<
        <Self::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
        Self::Presign,
        Self::SignMessage,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
        GroupElement::Value,
    >;

    type SignDecentralizedParty = SignParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;

    type DKGSignDecentralizedPartyPublicInput = DKGSignPublicInput<
        <Self::DKGProtocol as dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        Self::Presign,
        Self::SignMessage,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
        GroupElement::Value,
    >;

    type DKGSignDecentralizedParty = DKGSignParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;

    type SignCentralizedPartyPublicInput = CentralizedPartyPublicInput<
        <Self::DKGProtocol as dkg::Protocol>::CentralizedPartyDKGOutput,
        Self::Presign,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
    >;

    type SignMessage = PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>;
    type VerifiedSignData = Self::SignMessage;

    type SignCentralizedParty = CentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;

    fn verify_centralized_party_partial_signature(
        message: &[u8],
        hash_scheme: HashScheme,
        hash_context: &group::HashContext,
        dkg_output: <Self::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
        presign: Self::Presign,
        centralized_party_partial_signature: Self::SignMessage,
        protocol_public_parameters: &<Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
        _rng: &mut impl CsRng,
    ) -> crate::Result<Self::VerifiedSignData> {
        let dkg_output = dkg::decentralized_party::Output::from(dkg_output.clone());

        verify_centralized_party_partial_signature::<SCALAR_LIMBS, GroupElement>(
            presign.session_id,
            message,
            hash_scheme,
            hash_context,
            presign.decentralized_party_nonce_public_share_first_part,
            presign.decentralized_party_nonce_public_share_second_part,
            &dkg_output.centralized_party_public_key_share,
            centralized_party_partial_signature.clone(),
            &dkg_output.public_key,
            &protocol_public_parameters.group_public_parameters,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        Ok(centralized_party_partial_signature)
    }
}
