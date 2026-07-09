// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! INSECURE deterministic ECDSA signing for the `unsafe_mock` feature.
//!
//! Every dWallet uses the constant key `x = 42` ([`crate::mock::MOCK_SECRET_KEY`]) and a constant
//! nonce `k` ([`crate::mock::MOCK_NONCE`]); the produced signature verifies under `public_key = 42·G`
//! (which the mocked DKG output carries). No key recovery, no threshold decryption — just
//! `s = k^{-1}·(z + r·x)`.

use std::collections::HashMap;
use std::marker::PhantomData;

use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use group::{
    hash_to_scalar, CsRng, GroupElement as _, HashContext, HashScheme, Invert, PartyID,
    StatisticalSecuritySizedNumber,
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

use crate::class_groups::ecdsa::{DKGSignPartyPublicInput, SignPartyPublicInput};
use crate::ecdsa::VerifyingKey;

/// Produce an INSECURE but valid ECDSA signature over `message` under the constant mock key `42·G`.
///
/// Deterministic in `(message, hash_type, hash_context)` — no per-party or secret inputs — so every
/// validator computes the byte-identical signature.
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
    GroupElement::Scalar: Invert,
{
    let secret_key =
        crate::mock::mock_secret_key::<SCALAR_LIMBS, GroupElement>(scalar_group_public_parameters)?;
    let nonce =
        crate::mock::mock_nonce::<SCALAR_LIMBS, GroupElement>(scalar_group_public_parameters)?;

    // z: the message hash reduced into the scalar field, exactly as the verifier reduces it.
    let hashed_message = hash_to_scalar::<SCALAR_LIMBS, GroupElement>(
        message,
        hash_type,
        hash_context,
        scalar_group_public_parameters,
    )?;

    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;
    let public_nonce: GroupElement = nonce * generator;
    let nonce_x_coordinate: GroupElement::Scalar = public_nonce.x_projected_to_scalar_field();

    let nonce_inverse: GroupElement::Scalar = Option::from(nonce.invert())
        .ok_or_else(|| crate::Error::from(crate::ErrorKind::InternalError))?;

    // s = k^{-1} · (z + r·x)
    let signature_s: GroupElement::Scalar = hashed_message.add_constant_time(
        &(nonce_x_coordinate * secret_key),
        scalar_group_public_parameters,
    ) * nonce_inverse;

    GroupElement::Signature::try_from((public_nonce, signature_s))
}

// ===================================================================================================
// ECDSA presign
// ===================================================================================================

/// The real ECDSA presign decentralized party this mock stands in for.
type RealPresignAsyncECDSAParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = crate::ecdsa::presign::decentralized_party::class_groups::asynchronous::Party<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the ECDSA presign party — finalizes round 1 with a single dummy presign whose
/// nonce public shares are the neutral point and whose ciphertext fields reuse a public-parameters
/// ciphertext (the mocked constant-nonce sign ignores the presign entirely).
pub struct MockPresignAsyncECDSAParty<
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
    for MockPresignAsyncECDSAParty<
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
    RealPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party,
{
    type Error = <RealPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::Error;
    type PublicInput = <RealPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicInput;
    type PrivateOutput = <RealPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PrivateOutput;
    type PublicOutput = <RealPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutput;
    type PublicOutputValue = <RealPresignAsyncECDSAParty<
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
    for MockPresignAsyncECDSAParty<
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
    RealPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party<Error = crate::Error>,
    RealPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: AsynchronouslyAdvanceable<
        PrivateInput = (),
        PublicInput = crate::ecdsa::presign::decentralized_party::PublicInput<
            GroupElement::Value,
            group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            crate::class_groups::ProtocolPublicParameters<
                SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
        >,
        PublicOutput = Vec<
            crate::ecdsa::presign::VersionedPresign<
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
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        // ECDSA presign decentralized party is a 4-round protocol.
        crate::mock::mock_advance_result(access_structure, &messages, 4, || {
            let protocol_public_parameters = &*public_input.protocol_public_parameters;
            let identity_point = GroupElement::neutral_from_public_parameters(
                &protocol_public_parameters.group_public_parameters,
            )?
            .value();
            // Reuse a stored ciphertext as the dummy ciphertext (never read — the mocked sign uses
            // the constant nonce and ignores the presign).
            let dummy_ciphertext = protocol_public_parameters
                .encryption_of_decentralized_party_secret_key_share_first_part;
            let presign = crate::ecdsa::presign::Presign {
                session_id,
                encryption_of_mask: dummy_ciphertext,
                encryption_of_masked_decentralized_party_key_share: dummy_ciphertext,
                encryption_of_masked_decentralized_party_nonce_share_first_part: dummy_ciphertext,
                encryption_of_masked_decentralized_party_nonce_share_second_part: dummy_ciphertext,
                decentralized_party_nonce_public_share_first_part: identity_point.clone(),
                decentralized_party_nonce_public_share_second_part: identity_point.clone(),
                public_key: identity_point,
            };
            Ok((
                (),
                vec![crate::ecdsa::presign::VersionedPresign::TargetedPresign(
                    presign,
                )],
            ))
        })
    }

    fn round_causing_threshold_not_reached(current_round: u64) -> Option<u64> {
        crate::mock::mock_round_causing_threshold_not_reached(current_round)
    }
}

// ===================================================================================================
// ECDSA sign
// ===================================================================================================

/// The real ECDSA sign decentralized party this mock stands in for.
type RealSignDecentralizedECDSAParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = crate::ecdsa::sign::decentralized_party::class_groups::asynchronous::Party<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the ECDSA sign party — finalizes round 1 with the deterministic constant-key
/// (`x = 42`) ECDSA signature over the requested message.
pub struct MockSignDecentralizedECDSAParty<
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
    for MockSignDecentralizedECDSAParty<
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
    RealSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party,
{
    type Error = <RealSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::Error;
    type PublicInput = <RealSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicInput;
    type PrivateOutput = <RealSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PrivateOutput;
    type PublicOutput = <RealSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutput;
    type PublicOutputValue = <RealSignDecentralizedECDSAParty<
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
    for MockSignDecentralizedECDSAParty<
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
    GroupElement::Scalar: Invert,
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
    RealSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party<Error = crate::Error>,
    RealSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: AsynchronouslyAdvanceable<
        PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>,
        PublicInput = SignPartyPublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
        >,
        PublicOutput = GroupElement::Signature,
        PrivateOutput = (),
    >,
{
    type PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;

    fn advance(
        _session_id: CommitmentSizedNumber,
        _party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        // ECDSA sign decentralized party is a 2-round protocol (happy-flow).
        crate::mock::mock_advance_result(access_structure, &messages, 2, || {
            let protocol_public_parameters = &*public_input.protocol_public_parameters;
            let signature = mock_sign::<SCALAR_LIMBS, GroupElement>(
                &public_input.message,
                public_input.hash_type,
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
// ECDSA fused DKG + sign
// ===================================================================================================

/// The real ECDSA fused DKG+sign decentralized party this mock stands in for.
type RealDKGSignDecentralizedECDSAParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = crate::ecdsa::sign::decentralized_party::class_groups::asynchronous::DKGSignParty<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the ECDSA fused DKG+sign party — finalizes round 1 with the constant-key
/// (`x = 42`) mock DKG output paired with the deterministic constant-key ECDSA signature.
pub struct MockDKGSignDecentralizedECDSAParty<
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
    for MockDKGSignDecentralizedECDSAParty<
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
    RealDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party,
{
    type Error = <RealDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::Error;
    type PublicInput = <RealDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicInput;
    type PrivateOutput = <RealDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PrivateOutput;
    type PublicOutput = <RealDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutput;
    type PublicOutputValue = <RealDKGSignDecentralizedECDSAParty<
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
    for MockDKGSignDecentralizedECDSAParty<
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
    GroupElement::Scalar: Invert,
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
    RealDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: mpc::Party<Error = crate::Error>,
    RealDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >: AsynchronouslyAdvanceable<
        PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>,
        PublicInput = DKGSignPartyPublicInput<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MESSAGE_LIMBS,
            GroupElement,
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
        access_structure: &WeightedThresholdAccessStructure,
        messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        // The fused ECDSA DKG+sign decentralized party shares the sign protocol's 2-round
        // (happy-flow) structure.
        crate::mock::mock_advance_result(access_structure, &messages, 2, || {
            let protocol_public_parameters = &*public_input.protocol_public_parameters;
            let dkg_output = crate::mock::dkg::mock_dkg_output::<SCALAR_LIMBS, GroupElement, _, _>(
                protocol_public_parameters,
            )?;
            let signature = mock_sign::<SCALAR_LIMBS, GroupElement>(
                &public_input.message,
                public_input.hash_type,
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
// MockECDSAProtocol — redirected from the per-curve `ECDSAProtocol` alias under `unsafe_mock`.
// ===================================================================================================

/// The real class-groups ECDSA `Protocol` this mock delegates its non-overridden associated types to.
type RealECDSAProtocol<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = crate::class_groups::ecdsa::asynchronous::Protocol<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the ECDSA `sign`/`presign` `Protocol`. Delegates every associated type to
/// [`RealECDSAProtocol`] EXCEPT `DKGProtocol` (→ [`crate::mock::dkg::MockDKGProtocol`]), the party
/// types (→ the mock parties), and `verify_centralized_party_partial_signature` (skips proofs). It is
/// selected purely via the per-curve `ECDSAProtocol` alias in `lib.rs`; no production impl is touched.
pub struct MockECDSAProtocol<
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
    for MockECDSAProtocol<
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
    type Presign = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::Presign;
    type HPKEEncryptionKey = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::HPKEEncryptionKey;
    type PresignPublicInput = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::PresignPublicInput;
    type PresignPrivateInput = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::presign::Protocol>::PresignPrivateInput;
    type PresignParty = MockPresignAsyncECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
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
    for MockECDSAProtocol<
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
    Uint<MESSAGE_LIMBS>: Encoding,
    group::PublicParameters<GroupElement::Scalar>: Default,
    GroupElement::Scalar: Serialize + for<'a> Deserialize<'a>,
{
    type Signature = GroupElement::Signature;
    type SignDecentralizedPartyPrivateInput = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignDecentralizedPartyPrivateInput;
    type VerifiedSignData = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::VerifiedSignData;
    type SignDecentralizedPartyPublicInput = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignDecentralizedPartyPublicInput;
    type SignDecentralizedParty = MockSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >;
    type DKGSignDecentralizedPartyPublicInput = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::DKGSignDecentralizedPartyPublicInput;
    type DKGSignDecentralizedParty = MockDKGSignDecentralizedECDSAParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >;
    type SignCentralizedPartyPublicInput = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignCentralizedPartyPublicInput;
    type SignMessage = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignMessage;
    type SignCentralizedParty = <RealECDSAProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    > as crate::sign::Protocol>::SignCentralizedParty;

    /// INSECURE: skip the centralized partial-signature proof verification and return the sign data.
    /// The mocked decentralized sign ignores this entirely (and under `ToBeEmulated` it is not called).
    fn verify_centralized_party_partial_signature(
        _message: &[u8],
        _hash_type: HashScheme,
        _hash_context: &HashContext,
        _dkg_output: <<Self as crate::presign::Protocol>::DKGProtocol as crate::dkg::Protocol>::DecentralizedPartyDKGOutput,
        _presign: Self::Presign,
        sign_message: Self::SignMessage,
        _protocol_public_parameters: &<<Self as crate::presign::Protocol>::DKGProtocol as crate::dkg::Protocol>::ProtocolPublicParameters,
        _rng: &mut impl CsRng,
    ) -> crate::Result<Self::VerifiedSignData> {
        Ok(
            crate::ecdsa::sign::centralized_party::message::class_groups::VerifiedSignDataRaw {
                public_signature_nonce: sign_message.public_signature_nonce,
                encryption_of_partial_signature: sign_message.encryption_of_partial_signature,
                encryption_of_displaced_decentralized_party_nonce_share: sign_message
                    .encryption_of_displaced_decentralized_party_nonce_share,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use group::{secp256k1, CyclicGroupElement as _, GroupElement as _, HashContext, HashScheme};

    use crate::ecdsa::VerifyingKey as _;

    /// The mock's deterministic ECDSA signature must verify under the constant mock public key `42·G`.
    #[test]
    fn mock_secp256k1_ecdsa_signature_verifies() {
        let scalar_group_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_public_parameters = secp256k1::group_element::PublicParameters::default();

        let message = b"unsafe_mock verifies";
        let hash_type = HashScheme::SHA256;
        let hash_context = HashContext::None;

        let signature = super::mock_sign::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
            message,
            hash_type,
            &hash_context,
            &scalar_group_public_parameters,
            &group_public_parameters,
        )
        .unwrap();

        // Two independent "validators" must derive the byte-identical signature.
        let signature_again =
            super::mock_sign::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                message,
                hash_type,
                &hash_context,
                &scalar_group_public_parameters,
                &group_public_parameters,
            )
            .unwrap();
        assert_eq!(
            bcs::to_bytes(&signature).unwrap(),
            bcs::to_bytes(&signature_again).unwrap(),
            "mock signatures must be deterministic across validators"
        );

        // Public key = 42·G.
        let secret_key = crate::mock::mock_secret_key::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >(&scalar_group_public_parameters)
        .unwrap();
        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();
        let public_key = secret_key * generator;

        public_key
            .verify(message, hash_type, &signature)
            .expect("mock signature must verify under the constant mock public key 42·G");
    }
}
