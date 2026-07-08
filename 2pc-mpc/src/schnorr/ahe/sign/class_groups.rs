// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Sign` protocol trait for Class Groups

use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use ::class_groups::{decryption_key_share, SecretKeyShareSizedInteger};
use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, DecryptionKeyShare, EncryptionKey,
    EquivalenceClass, RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use ::class_groups::{DecryptionKey, DiscreteLogInF};
use class_groups::encryption_key::public_parameters::Instantiate;
use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use class_groups::MultiFoldNupowAccelerator;
use group::{CsRng, HashScheme, PartyID, StatisticalSecuritySizedNumber};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicDecryptionKeyShare,
    AdditivelyHomomorphicEncryptionKey,
};
use mpc::secret_sharing::shamir::over_the_integers::AdjustedLagrangeCoefficientSizedNumber;

use crate::class_groups::{schnorr::asynchronous::Protocol, DecryptionKeySharePublicParameters};
use crate::schnorr::sign::decentralized_party::verify_centralized_party_partial_signature;
use crate::schnorr::{PartialSignature, VerifyingKey};
use crate::{dkg, Error, ErrorKind};

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > crate::sign::Protocol
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
    >: AdditivelyHomomorphicDecryptionKey<
            SCALAR_LIMBS,
            EncryptionKey<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        > + DiscreteLogInF<
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
        PartialDecryptionProof = decryption_key_share::PartialDecryptionProof<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        DecryptionShare = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        LagrangeCoefficient = AdjustedLagrangeCoefficientSizedNumber,
        Error = ::class_groups::Error,
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
    GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
    Uint<MESSAGE_LIMBS>: Encoding,
    group::PublicParameters<GroupElement::Scalar>: Default,
{
    type Signature = GroupElement::Signature;
    type SignDecentralizedPartyPrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;
    type SignDecentralizedPartyPublicInput = super::decentralized_party::PublicInput<
        <Self::DKGProtocol as dkg::Protocol>::DecentralizedPartyDKGOutput,
        Self::Presign,
        Self::SignMessage,
        DecryptionKeySharePublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
    >;
    type SignDecentralizedParty = super::decentralized_party::Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
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
        >,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
    >;
    type DKGSignDecentralizedPartyPublicInput = super::decentralized_party::DKGSignPublicInput<
        <Self::DKGProtocol as dkg::Protocol>::DKGDecentralizedPartyPublicInput,
        Self::Presign,
        Self::SignMessage,
        DecryptionKeySharePublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
    >;
    type DKGSignDecentralizedParty = super::decentralized_party::class_groups::DKGSignParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >;
    type SignCentralizedPartyPublicInput = super::centralized_party::PublicInput<
        <Self::DKGProtocol as dkg::Protocol>::CentralizedPartyDKGOutput,
        Self::Presign,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
    >;
    type SignMessage = PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>;
    type VerifiedSignData = Self::SignMessage;
    type SignCentralizedParty = super::centralized_party::Party<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        <Self::DKGProtocol as dkg::Protocol>::ProtocolPublicParameters,
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
        if &dkg_output != protocol_public_parameters || &presign != protocol_public_parameters {
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

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
