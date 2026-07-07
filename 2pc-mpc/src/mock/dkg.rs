// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! INSECURE deterministic DKG mocks for the `unsafe_mock` feature.
//!
//! The mocked DKG produces, for every dWallet, the constant key `x = 42`
//! ([`crate::mock::MOCK_SECRET_KEY`]): `public_key = X_B = 42·G`, centralized share `X_A = neutral`
//! (so the `SignData::ToBeEmulated` `x_A = 0` invariant holds), and a dummy `Enc(x_B)` (never read —
//! signing uses the constant key). The decentralized party, the centralized DKG round, and the
//! `dkg::Protocol::threshold_dkg_output` method all yield the same output.

use std::marker::PhantomData;

use commitment::CommitmentSizedNumber;
use crypto_bigint::{ConcatMixed, Encoding, Int, Uint};
use serde::Serialize;

use group::{
    GroupElement as _, PartyID, PrimeGroupElement, StatisticalSecuritySizedNumber, Transcribeable,
};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
};
use mpc::{
    two_party, AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure,
};

use ::class_groups::encryption_key::public_parameters::Instantiate;
use ::class_groups::equivalence_class::EquivalenceClassOps;
use ::class_groups::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use ::class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CiphertextSpaceValue, CompactIbqf, DecryptionKey,
    EncryptionKey, EquivalenceClass, MultiFoldNupowAccelerator, RandomnessSpaceGroupElement,
    RandomnessSpacePublicParameters,
};

use crate::class_groups::{CentralizedPartyKeyShareVerification, ProtocolPublicParameters};
use crate::dkg::centralized_party;
use crate::dkg::decentralized_party::VersionedOutput;
use crate::languages::KnowledgeOfDiscreteLogUCProof;

/// The real decentralized DKG party this mock stands in for (its associated I/O types are reused).
type RealDKGDecentralizedParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = crate::dkg::decentralized_party::Party<
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
    >,
    CentralizedPartyKeyShareVerification<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// Build the INSECURE constant-key (`x = 42`) decentralized DKG output from the (common) protocol
/// public parameters. `public_key = X_B = 42·G`, `X_A = neutral`, dummy `Enc`. Deterministic, so
/// byte-identical across all validators.
///
/// Generic over the public-parameters *field* types (not the class-group const-generics) so it needs
/// only light bounds — it builds `42·G` and reuses a stored ciphertext, doing no class-group work.
pub(crate) fn mock_dkg_output<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    CiphertextValue: Clone + Serialize,
    EncryptionSchemePublicParameters: Transcribeable + Clone,
>(
    protocol_public_parameters: &crate::ProtocolPublicParameters<
        group::PublicParameters<GroupElement::Scalar>,
        GroupElement::PublicParameters,
        GroupElement::Value,
        CiphertextValue,
        EncryptionSchemePublicParameters,
    >,
) -> crate::Result<VersionedOutput<SCALAR_LIMBS, GroupElement::Value, CiphertextValue>>
where
    Uint<SCALAR_LIMBS>: Encoding,
    GroupElement::Value: Serialize,
{
    let secret_key = crate::mock::mock_secret_key::<SCALAR_LIMBS, GroupElement>(
        &protocol_public_parameters.scalar_group_public_parameters,
    )?;
    let generator = GroupElement::generator_from_public_parameters(
        &protocol_public_parameters.group_public_parameters,
    )?;
    // X_B = 42·G, and (with X_A = neutral) the full public key is also 42·G.
    let public_key_share = (secret_key * generator).value();
    let neutral = GroupElement::neutral_from_public_parameters(
        &protocol_public_parameters.group_public_parameters,
    )?
    .value();

    let output = crate::dkg::decentralized_party::Output {
        public_key_share: public_key_share.clone(),
        public_key: public_key_share,
        // Dummy: reuse a valid ciphertext from the public parameters — never decrypted (signing
        // uses the constant key), only stored/serialized.
        encryption_of_secret_key_share: protocol_public_parameters
            .encryption_of_decentralized_party_secret_key_share_first_part
            .clone(),
        centralized_party_public_key_share: neutral,
    };

    // Mirror the real `threshold_dkg_output`'s `UniversalPublicDKGOutput` shape (dummy randomizers;
    // only the mocked VSS path would read them, and it ignores them).
    Ok(VersionedOutput::UniversalPublicDKGOutput {
        output,
        first_key_public_randomizer: Uint::ONE,
        second_key_public_randomizer: Uint::ONE,
        free_coefficient_key_public_randomizer: Uint::ONE,
        global_decentralized_party_output_commitment: protocol_public_parameters
            .global_decentralized_party_output_commitment()?,
    })
}

/// INSECURE mock of the decentralized DKG party — finalizes round 1 with [`mock_dkg_output`].
pub struct MockDKGDecentralizedParty<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    > mpc::Party
    for MockDKGDecentralizedParty<
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
    RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: mpc::Party,
{
    type Error = <RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::Error;
    type PublicInput = <RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicInput;
    type PrivateOutput = <RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PrivateOutput;
    type PublicOutput = <RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutput;
    type PublicOutputValue = <RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::PublicOutputValue;
    type Message = <RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as mpc::Party>::Message;
}

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    > AsynchronouslyAdvanceable
    for MockDKGDecentralizedParty<
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
    RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: mpc::Party<Error = crate::Error>,
    RealDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AsynchronouslyAdvanceable<
        PrivateInput = (),
        PublicInput = crate::dkg::decentralized_party::PublicInput<
            GroupElement::Value,
            crate::languages::KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
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
        >,
        PublicOutput = VersionedOutput<
            SCALAR_LIMBS,
            GroupElement::Value,
            CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        PrivateOutput = (),
    >,
{
    type PrivateInput = ();

    fn advance(
        _session_id: CommitmentSizedNumber,
        _party_id: PartyID,
        _access_structure: &WeightedThresholdAccessStructure,
        _messages: Vec<std::collections::HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        public_input: &Self::PublicInput,
        _rng: &mut impl group::CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: (),
            public_output: mock_dkg_output::<SCALAR_LIMBS, GroupElement, _, _>(
                &public_input.protocol_public_parameters,
            )?,
        })
    }

    fn round_causing_threshold_not_reached(_current_round: u64) -> Option<u64> {
        None
    }
}

/// INSECURE mock of the DKG centralized-party round (`mpc::two_party::Round`) — finalizes the single
/// two-party round with the constant-key (`x = 42`) values consistent with [`mock_dkg_output`]:
/// centralized public-key share `X_A = neutral`, `public_key = 42·G`,
/// `decentralized_party_public_key_share = 42·G`, a default (all-neutral) knowledge-of-discrete-log
/// UC proof, and a neutral centralized secret-key share.
pub struct MockDKGCentralizedRound<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    > two_party::Round
    for MockDKGCentralizedRound<
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
{
    type Error = crate::Error;
    type PrivateInput = ();
    type PublicInput = centralized_party::PublicInput<
        ProtocolPublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >;
    type PrivateOutput = centralized_party::SecretKeyShare<group::Value<GroupElement::Scalar>>;
    type PublicOutputValue = Self::PublicOutput;
    type PublicOutput = centralized_party::VersionedOutput<SCALAR_LIMBS, GroupElement::Value>;
    type IncomingMessage = ();
    type OutgoingMessage = centralized_party::PublicKeyShareAndProof<
        GroupElement::Value,
        KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
    >;

    fn advance(
        _incoming_message: Self::IncomingMessage,
        _private_input: &Self::PrivateInput,
        public_input: &Self::PublicInput,
        _rng: &mut impl group::CsRng,
    ) -> std::result::Result<
        two_party::RoundResult<Self::OutgoingMessage, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        let protocol_public_parameters = &public_input.protocol_public_parameters;

        let secret_key = crate::mock::mock_secret_key::<SCALAR_LIMBS, GroupElement>(
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;
        let generator = GroupElement::generator_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )?;
        // 42·G — matches the (decentralized) `mock_dkg_output`'s `public_key`.
        let public_key = (secret_key * generator).value();
        // X_A = neutral (the centralized side is emulated with x_A = 0).
        let neutral_point = GroupElement::neutral_from_public_parameters(
            &protocol_public_parameters.group_public_parameters,
        )?
        .value();
        let neutral_scalar = GroupElement::Scalar::neutral_from_public_parameters(
            &protocol_public_parameters.scalar_group_public_parameters,
        )?
        .value();

        // Deterministic all-neutral default proof (no real centralized party to prove knowledge).
        let default_proof =
            KnowledgeOfDiscreteLogUCProof::<SCALAR_LIMBS, GroupElement>::new_default(
                &protocol_public_parameters.scalar_group_public_parameters,
                &protocol_public_parameters.group_public_parameters,
            )?;

        let outgoing_message = centralized_party::PublicKeyShareAndProof {
            proof: default_proof,
            public_key_share: neutral_point.clone(),
        };

        // X_A = neutral, public_key = 42·G, X_B = 42·G — consistent with `mock_dkg_output`.
        let output = centralized_party::Output {
            public_key_share: neutral_point,
            public_key: public_key.clone(),
            decentralized_party_public_key_share: public_key,
        };

        // Mirror the real round's `UniversalPublicDKGOutput` shape with the same dummy randomizers /
        // commitment that `mock_dkg_output` uses.
        let public_output = centralized_party::VersionedOutput::UniversalPublicDKGOutput {
            output,
            first_key_public_randomizer: Uint::ONE,
            second_key_public_randomizer: Uint::ONE,
            free_coefficient_key_public_randomizer: Uint::ONE,
            global_decentralized_party_output_commitment: protocol_public_parameters
                .global_decentralized_party_output_commitment()?,
        };

        Ok(two_party::RoundResult {
            outgoing_message,
            private_output: centralized_party::SecretKeyShare::from(neutral_scalar),
            public_output,
        })
    }
}

/// The real class-groups DKG `Protocol` this mock delegates its (non-overridden) associated types
/// and methods to.
type RealDKGProtocol<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = crate::class_groups::asynchronous::DKGProtocol<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    GroupElement,
>;

/// INSECURE mock of the DKG [`crate::dkg::Protocol`]. Every associated type and every method delegates
/// to [`RealDKGProtocol`] (so the party associated types resolve to the mock parties via the redirected
/// `lib.rs` aliases), EXCEPT the three methods that must reflect the constant-key (`x = 42`) mock:
/// `threshold_dkg_output` builds the mock output, and the two centralized-party-share verifications
/// become no-ops (the centralized side is emulated with `x_A = 0`).
pub struct MockDKGProtocol<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
>(PhantomData<GroupElement>);

impl<
        const SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
    > crate::dkg::Protocol
    for MockDKGProtocol<
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
    group::PublicParameters<GroupElement::Scalar>: Default,
    GroupElement::Value: Serialize,
{
    type ProtocolPublicParameters = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::ProtocolPublicParameters;
    type ProtocolContext = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::ProtocolContext;
    type EncryptionKeyValue = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::EncryptionKeyValue;
    type DecryptionKey = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::DecryptionKey;
    type SecretKey = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::SecretKey;
    type CentralizedPartySecretKeyShare = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::CentralizedPartySecretKeyShare;
    type CentralizedPartyDKGOutput = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::CentralizedPartyDKGOutput;
    type CentralizedPartyTargetedDKGOutput = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::CentralizedPartyTargetedDKGOutput;
    type DecentralizedPartyDKGOutput = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::DecentralizedPartyDKGOutput;
    type DecentralizedPartyTargetedDKGOutput = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::DecentralizedPartyTargetedDKGOutput;
    type DKGDecentralizedPartyPublicInput = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::DKGDecentralizedPartyPublicInput;
    type DKGDecentralizedParty = MockDKGDecentralizedParty<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
    type DKGCentralizedPartyPublicInput = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::DKGCentralizedPartyPublicInput;
    type PublicKeyShareAndProof = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::PublicKeyShareAndProof;
    type DKGCentralizedPartyRound = MockDKGCentralizedRound<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >;
    type EncryptedSecretKeyShareMessage = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::EncryptedSecretKeyShareMessage;
    type DealTrustedShareMessage = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::DealTrustedShareMessage;
    type TrustedDealerDKGCentralizedPartyRound = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::TrustedDealerDKGCentralizedPartyRound;
    type TrustedDealerDKGDecentralizedPublicInput = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::TrustedDealerDKGDecentralizedPublicInput;
    type TrustedDealerDKGDecentralizedParty = <RealDKGProtocol<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    > as crate::dkg::Protocol>::TrustedDealerDKGDecentralizedParty;

    fn generate_decryption_key(rng: &mut impl group::CsRng) -> crate::Result<Self::DecryptionKey> {
        <RealDKGProtocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        > as crate::dkg::Protocol>::generate_decryption_key(rng)
    }

    fn encryption_key_from_decryption_key(
        decryption_key: Self::DecryptionKey,
    ) -> crate::Result<Self::EncryptionKeyValue> {
        <RealDKGProtocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        > as crate::dkg::Protocol>::encryption_key_from_decryption_key(decryption_key)
    }

    fn encrypt_and_prove_centralized_party_share(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        encryption_key_value: Self::EncryptionKeyValue,
        secret_key_share: Self::CentralizedPartySecretKeyShare,
        rng: &mut impl group::CsRng,
    ) -> crate::Result<Self::EncryptedSecretKeyShareMessage> {
        <RealDKGProtocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        > as crate::dkg::Protocol>::encrypt_and_prove_centralized_party_share(
            protocol_public_parameters,
            encryption_key_value,
            secret_key_share,
            rng,
        )
    }

    /// INSECURE: skip verifying the (emulated) centralized party's encrypted key-share proof.
    fn verify_encryption_of_centralized_party_share_proof(
        _protocol_public_parameters: &Self::ProtocolPublicParameters,
        _dkg_output: Self::DecentralizedPartyDKGOutput,
        _encryption_key_value: Self::EncryptionKeyValue,
        _encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage,
        _rng: &mut impl group::CsRng,
    ) -> crate::Result<()> {
        Ok(())
    }

    fn verify_and_decrypt_encryption_of_centralized_party_share_proof(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        dkg_output: Self::DecentralizedPartyDKGOutput,
        encrypted_secret_key_share_message: Self::EncryptedSecretKeyShareMessage,
        decryption_key: Self::DecryptionKey,
        rng: &mut impl group::CsRng,
    ) -> crate::Result<Self::CentralizedPartySecretKeyShare> {
        <RealDKGProtocol<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        > as crate::dkg::Protocol>::verify_and_decrypt_encryption_of_centralized_party_share_proof(
            protocol_public_parameters,
            dkg_output,
            encrypted_secret_key_share_message,
            decryption_key,
            rng,
        )
    }

    /// INSECURE: skip verifying the (emulated, `x_A = 0`) centralized party's public key share.
    fn verify_centralized_party_public_key_share(
        _protocol_public_parameters: &Self::ProtocolPublicParameters,
        _dkg_output: Self::DecentralizedPartyDKGOutput,
        _centralized_party_secret_key_share: Self::CentralizedPartySecretKeyShare,
    ) -> crate::Result<()> {
        Ok(())
    }

    /// INSECURE: return the deterministic constant-key (`x = 42`) mock DKG output.
    fn threshold_dkg_output(
        protocol_public_parameters: &Self::ProtocolPublicParameters,
        _session_id: CommitmentSizedNumber,
    ) -> crate::Result<Self::DecentralizedPartyDKGOutput> {
        mock_dkg_output::<SCALAR_LIMBS, GroupElement, _, _>(protocol_public_parameters)
    }
}
