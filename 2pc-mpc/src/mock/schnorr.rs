// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! INSECURE deterministic Schnorr signing (Taproot / EdDSA / Schnorrkel) for the `unsafe_mock`
//! feature.
//!
//! Every dWallet uses the constant key `x = 42` ([`crate::mock::MOCK_SECRET_KEY`]) and a constant
//! nonce `k` ([`crate::mock::MOCK_NONCE`]); the produced signature `s = k + e·x` verifies under
//! `public_key = 42·G`. Taproot's even-`y` normalization of the public key and nonce is handled here
//! (a no-op for EdDSA/Schnorrkel, whose `is_taproot_normalized` is always `true`).

use std::collections::HashMap;
use std::marker::PhantomData;

use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use group::{
    CsRng, GroupElement as _, HashContext, HashScheme, PartyID, StatisticalSecuritySizedNumber,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicDecryptionKeyShare,
    AdditivelyHomomorphicEncryptionKey,
};
use mpc::secret_sharing::shamir::over_the_integers::AdjustedLagrangeCoefficientSizedNumber;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use ::class_groups::encryption_key::public_parameters::Instantiate;
use ::class_groups::equivalence_class::EquivalenceClassOps;
use ::class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use ::class_groups::{
    decryption_key_share, encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CompactIbqf, DecryptionKey, DecryptionKeyShare,
    DiscreteLogInF, EncryptionKey, EquivalenceClass, MultiFoldNupowAccelerator,
    RandomnessSpaceGroupElement, RandomnessSpacePublicParameters, SecretKeyShareSizedInteger,
};

use crate::class_groups::{DecryptionKeySharePublicParameters, ProtocolPublicParameters};
use crate::schnorr::{generate_schnorr_signature_response, PartialSignature, VerifyingKey};

/// Produce an INSECURE but valid Schnorr signature over `message` under the constant mock key `42·G`.
///
/// Deterministic in `(message, hash_type, hash_context)`, so every validator computes the
/// byte-identical signature.
pub(crate) fn mock_sign<
    const SCALAR_LIMBS: usize,
    GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
>(
    message: &[u8],
    hash_type: HashScheme,
    hash_context: &HashContext,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
) -> crate::Result<GroupElement::Signature>
where
    Uint<SCALAR_LIMBS>: Encoding,
{
    let secret_key =
        crate::mock::mock_secret_key::<SCALAR_LIMBS, GroupElement>(scalar_group_public_parameters)?;
    let nonce =
        crate::mock::mock_nonce::<SCALAR_LIMBS, GroupElement>(scalar_group_public_parameters)?;

    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;

    // Taproot interprets the public key as normalized (even y); normalize here so our challenge
    // matches. No-op for EdDSA/Schnorrkel.
    let public_key = secret_key * generator;
    let (secret_key, public_key) = if public_key.is_taproot_normalized() {
        (secret_key, public_key)
    } else {
        (
            secret_key.neg_constant_time(scalar_group_public_parameters),
            public_key.neg_constant_time(group_public_parameters),
        )
    };

    // Taproot requires the public nonce to be normalized (even y); negate if needed. No-op otherwise.
    let public_nonce = nonce * generator;
    let (nonce, public_nonce) = if public_nonce.is_taproot_normalized() {
        (nonce, public_nonce)
    } else {
        (
            nonce.neg_constant_time(scalar_group_public_parameters),
            public_nonce.neg_constant_time(group_public_parameters),
        )
    };

    let signature_response = generate_schnorr_signature_response::<SCALAR_LIMBS, GroupElement>(
        secret_key,
        public_key,
        nonce,
        public_nonce,
        message,
        hash_type,
        hash_context,
        scalar_group_public_parameters,
    )?;

    GroupElement::Signature::try_from((public_nonce.value(), signature_response.value()))
}

// ===================================================================================================
// Schnorr-AHE presign
// ===================================================================================================

/// The real Schnorr-AHE presign decentralized party this mock stands in for.
type RealPresignAsyncSchnorrParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = crate::schnorr::ahe::presign::decentralized_party::encryption_of_nonce_share_round::class_groups::asynchronous::Party<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the Schnorr-AHE presign party — finalizes round 1 with a single dummy presign
/// (identity nonce points, reused ciphertexts, dummy commitment); the mocked constant-nonce sign
/// ignores the presign entirely.
pub struct MockPresignAsyncSchnorrParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > mpc::Party
    for MockPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    GroupElement: group::Scale<
        <<GroupElement as group::KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar as group::NumbersGroupElement<SCALAR_LIMBS>>::ValueExt,
    >,
    RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: mpc::Party,
{
    type Error = <RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::Error;
    type PublicInput = <RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicInput;
    type PrivateOutput = <RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PrivateOutput;
    type PublicOutput = <RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutput;
    type PublicOutputValue = <RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutputValue;
    // The mock simulates the round structure but sends only a magic `u64` each
    // round (see `crate::mock::MOCK_HONEST_MESSAGE`); the message type need not
    // match the real protocol's.
    type Message = u64;
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > AsynchronouslyAdvanceable
    for MockPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    GroupElement: group::Scale<
        <<GroupElement as group::KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar as group::NumbersGroupElement<SCALAR_LIMBS>>::ValueExt,
    >,
    RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: mpc::Party<Error = crate::Error>,
    RealPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AsynchronouslyAdvanceable<
        PrivateInput = (),
        PublicInput = crate::schnorr::ahe::presign::decentralized_party::PublicInput<
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        PublicOutput = Vec<
            crate::schnorr::ahe::presign::Presign<
                GroupElement::Value,
                group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        PrivateOutput = (),
    >,
{
    type PrivateInput = ();

    fn advance(
        session_id: CommitmentSizedNumber,
        _party_id: PartyID,
        _access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        // Schnorr-AHE presign decentralized party is a 2-round protocol.
        crate::mock::mock_advance_result(&messages, 2, || {
            let protocol_public_parameters = &*public_input.protocol_public_parameters;
            let identity_point = GroupElement::neutral_from_public_parameters(
                &protocol_public_parameters.group_public_parameters,
            )?
            .value();
            let dummy_ciphertext = protocol_public_parameters
                .encryption_of_decentralized_party_secret_key_share_first_part;
            let presign = crate::schnorr::ahe::presign::Presign {
                session_id,
                encryption_of_decentralized_party_nonce_share_first_part: dummy_ciphertext,
                encryption_of_decentralized_party_nonce_share_second_part: dummy_ciphertext,
                decentralized_party_nonce_public_share_first_part: identity_point.clone(),
                decentralized_party_nonce_public_share_second_part: identity_point,
                global_decentralized_party_output_commitment: CommitmentSizedNumber::ZERO,
            };
            Ok(((), vec![presign]))
        })
    }

    fn round_causing_threshold_not_reached(current_round: u64) -> Option<u64> {
        crate::mock::mock_round_causing_threshold_not_reached(current_round)
    }
}

// ===================================================================================================
// Schnorr-AHE sign
// ===================================================================================================

/// The real Schnorr-AHE (standalone) sign decentralized party this mock stands in for.
type RealSignDecentralizedSchnorrParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = crate::schnorr::ahe::sign::decentralized_party::Party<
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
    ProtocolPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// INSECURE mock of the Schnorr-AHE (standalone) sign party — finalizes round 1 with the
/// deterministic constant-key (`x = 42`) Schnorr signature over the requested message.
pub struct MockSignDecentralizedSchnorrParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > mpc::Party
    for MockSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
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
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: mpc::Party,
{
    type Error = <RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::Error;
    type PublicInput = <RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicInput;
    type PrivateOutput = <RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PrivateOutput;
    type PublicOutput = <RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutput;
    type PublicOutputValue = <RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutputValue;
    // The mock simulates the round structure but sends only a magic `u64` each
    // round (see `crate::mock::MOCK_HONEST_MESSAGE`); the message type need not
    // match the real protocol's.
    type Message = u64;
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > AsynchronouslyAdvanceable
    for MockSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
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
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: mpc::Party<Error = crate::Error>,
    RealSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AsynchronouslyAdvanceable<
        PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>,
        PublicInput = crate::schnorr::ahe::sign::decentralized_party::PublicInput<
            crate::dkg::decentralized_party::VersionedOutput<
                SCALAR_LIMBS,
                GroupElement::Value,
                group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
            crate::schnorr::ahe::presign::Presign<
                GroupElement::Value,
                group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
            PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
            DecryptionKeySharePublicParameters<
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
            >,
        >,
        PublicOutput = GroupElement::Signature,
        PrivateOutput = (),
    >,
{
    type PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;

    fn advance(
        _session_id: CommitmentSizedNumber,
        _party_id: PartyID,
        _access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        // Schnorr-AHE sign decentralized party is a 2-round protocol (happy-flow).
        crate::mock::mock_advance_result(&messages, 2, || {
            let protocol_public_parameters = &*public_input.protocol_public_parameters;
            let signature = mock_sign::<SCALAR_LIMBS, GroupElement>(
                &public_input.message,
                public_input.hash_scheme,
                &public_input.hash_context,
                &protocol_public_parameters.scalar_group_public_parameters,
                &protocol_public_parameters.group_public_parameters,
            )?;
            Ok(((), signature))
        })
    }

    fn round_causing_threshold_not_reached(current_round: u64) -> Option<u64> {
        crate::mock::mock_round_causing_threshold_not_reached(current_round)
    }
}

// ===================================================================================================
// Schnorr-AHE fused DKG + sign
// ===================================================================================================

/// The real Schnorr-AHE fused DKG+sign decentralized party this mock stands in for.
type RealDKGSignDecentralizedSchnorrParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = crate::schnorr::ahe::sign::decentralized_party::class_groups::DKGSignParty<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the Schnorr-AHE fused DKG+sign party — finalizes round 1 with the constant-key
/// (`x = 42`) mock DKG output paired with the deterministic constant-key Schnorr signature.
pub struct MockDKGSignDecentralizedSchnorrParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > mpc::Party
    for MockDKGSignDecentralizedSchnorrParty<
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
        >,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
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
    GroupElement: group::Scale<
        <<GroupElement as group::KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar as group::NumbersGroupElement<SCALAR_LIMBS>>::ValueExt,
    >,
    RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party,
{
    type Error = <RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::Error;
    type PublicInput = <RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicInput;
    type PrivateOutput = <RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PrivateOutput;
    type PublicOutput = <RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutput;
    type PublicOutputValue = <RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutputValue;
    // The mock simulates the round structure but sends only a magic `u64` each
    // round (see `crate::mock::MOCK_HONEST_MESSAGE`); the message type need not
    // match the real protocol's.
    type Message = u64;
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > AsynchronouslyAdvanceable
    for MockDKGSignDecentralizedSchnorrParty<
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
        >,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
    GroupElement::Value: Serialize,
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
    GroupElement: group::Scale<
        <<GroupElement as group::KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar as group::NumbersGroupElement<SCALAR_LIMBS>>::ValueExt,
    >,
    RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party<Error = crate::Error>,
    RealDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: AsynchronouslyAdvanceable<
        PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>,
        PublicInput = crate::schnorr::ahe::sign::decentralized_party::DKGSignPublicInput<
            crate::class_groups::DKGDecentralizedPartyPublicInput<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            crate::class_groups::schnorr::Presign<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            crate::schnorr::PartialSignature<GroupElement::Value, group::Value<GroupElement::Scalar>>,
            crate::class_groups::DecryptionKeySharePublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        PublicOutput = (
            crate::class_groups::DKGDecentralizedPartyVersionedOutput<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            GroupElement::Signature,
        ),
        PrivateOutput = (),
    >,
{
    type PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;

    fn advance(
        _session_id: CommitmentSizedNumber,
        _party_id: PartyID,
        _access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        // The fused Schnorr DKG+sign decentralized party shares the sign protocol's 2-round
        // (happy-flow) structure.
        crate::mock::mock_advance_result(&messages, 2, || {
            let protocol_public_parameters = &*public_input.protocol_public_parameters;
            let dkg_output = crate::mock::dkg::mock_dkg_output::<SCALAR_LIMBS, GroupElement, _, _>(
                protocol_public_parameters,
            )?;
            let signature = mock_sign::<SCALAR_LIMBS, GroupElement>(
                &public_input.message,
                public_input.hash_scheme,
                &public_input.hash_context,
                &protocol_public_parameters.scalar_group_public_parameters,
                &protocol_public_parameters.group_public_parameters,
            )?;
            Ok(((), (dkg_output, signature)))
        })
    }

    fn round_causing_threshold_not_reached(current_round: u64) -> Option<u64> {
        crate::mock::mock_round_causing_threshold_not_reached(current_round)
    }
}

// ===================================================================================================
// MockSchnorrProtocol — redirected from the per-curve Taproot/EdDSA/Schnorrkel `*Protocol` aliases.
// ===================================================================================================

/// The real class-groups Schnorr `Protocol` this mock delegates its non-overridden associated types to.
type RealSchnorrProtocol<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = crate::class_groups::schnorr::asynchronous::Protocol<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the Schnorr `sign`/`presign` `Protocol` (Taproot / EdDSA / Schnorrkel). Delegates
/// every associated type to [`RealSchnorrProtocol`] EXCEPT `DKGProtocol` (→ the mock DKG), the party
/// types (→ the mock parties), and `verify_centralized_party_partial_signature` (skips proofs). It is
/// selected purely via the per-curve `*Protocol` aliases in `lib.rs`; no production impl is touched.
pub struct MockSchnorrProtocol<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > crate::presign::Protocol
    for MockSchnorrProtocol<
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
        SecretKey = ::class_groups::SecretKey<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<MESSAGE_LIMBS>: Encoding,
    group::PublicParameters<GroupElement::Scalar>: Default,
{
    type DKGProtocol = crate::mock::dkg::MockDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
    type Presign = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::Presign;
    type HPKEEncryptionKey = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::HPKEEncryptionKey;
    type PresignPublicInput = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::PresignPublicInput;
    type PresignPrivateInput = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::PresignPrivateInput;
    type PresignParty = MockPresignAsyncSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: VerifyingKey<SCALAR_LIMBS> + Copy,
    > crate::sign::Protocol
    for MockSchnorrProtocol<
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
    type SignDecentralizedPartyPrivateInput = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignDecentralizedPartyPrivateInput;
    type VerifiedSignData = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::VerifiedSignData;
    type SignDecentralizedPartyPublicInput = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignDecentralizedPartyPublicInput;
    type SignDecentralizedParty = MockSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
    type DKGSignDecentralizedPartyPublicInput = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::DKGSignDecentralizedPartyPublicInput;
    type DKGSignDecentralizedParty = MockDKGSignDecentralizedSchnorrParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >;
    type SignCentralizedPartyPublicInput = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignCentralizedPartyPublicInput;
    type SignMessage = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignMessage;
    type SignCentralizedParty = <RealSchnorrProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignCentralizedParty;

    /// INSECURE: skip the centralized partial-signature verification and return it unchanged. The
    /// mocked decentralized sign ignores this entirely (and under `ToBeEmulated` it is not called).
    fn verify_centralized_party_partial_signature(
        _message: &[u8],
        _hash_scheme: HashScheme,
        _hash_context: &HashContext,
        _dkg_output: <<Self as crate::presign::Protocol>::DKGProtocol as crate::dkg::Protocol>::DecentralizedPartyDKGOutput,
        _presign: Self::Presign,
        centralized_party_partial_signature: Self::SignMessage,
        _protocol_public_parameters: &<<Self as crate::presign::Protocol>::DKGProtocol as crate::dkg::Protocol>::ProtocolPublicParameters,
        _rng: &mut impl CsRng,
    ) -> crate::Result<Self::VerifiedSignData> {
        Ok(centralized_party_partial_signature)
    }
}

#[cfg(test)]
mod tests {
    use group::{curve25519, CyclicGroupElement as _, GroupElement as _, HashContext, HashScheme};

    use crate::schnorr::VerifyingKey as _;

    /// The mock's deterministic EdDSA (curve25519) signature must verify under the constant mock
    /// public key `42·G`.
    #[test]
    fn mock_curve25519_eddsa_signature_verifies() {
        let scalar_group_public_parameters = curve25519::scalar::PublicParameters::default();
        let group_public_parameters = curve25519::PublicParameters::default();

        let message = b"unsafe_mock eddsa verifies";
        let hash_type = HashScheme::SHA512;
        let hash_context = HashContext::None;

        let signature = super::mock_sign::<{ curve25519::SCALAR_LIMBS }, curve25519::GroupElement>(
            message,
            hash_type,
            &hash_context,
            &scalar_group_public_parameters,
            &group_public_parameters,
        )
        .unwrap();

        let secret_key = crate::mock::mock_secret_key::<
            { curve25519::SCALAR_LIMBS },
            curve25519::GroupElement,
        >(&scalar_group_public_parameters)
        .unwrap();
        let generator =
            curve25519::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();
        let public_key = secret_key * generator;

        public_key
            .verify(message, hash_type, &hash_context, &signature)
            .expect("mock EdDSA signature must verify under the constant mock public key 42·G");
    }
}
