// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! INSECURE deterministic network-DKG mock for the `unsafe_mock` feature.
//!
//! The network DKG normally runs a heavy multi-round, multi-CRT-prime class-group protocol to
//! produce a [`crate::decentralized_party::dkg::PublicOutput`] holding the network's threshold
//! encryption key and per-curve public data. Under `unsafe_mock` nothing is ever encrypted to or
//! decrypted under the network key (signing uses the constant key `x = 42`), so we skip all of it
//! and return a single deterministic output whose per-curve fields are all NEUTRAL elements: the
//! public key shares and encryption key are identities, the ciphertexts are pairs of identities.
//! The extraction methods (`*_protocol_public_parameters` etc.) stay unchanged — they derive the
//! class-group setup parameters deterministically and validate the stored (neutral) values, so
//! whatever protocol public parameters ika extracts are valid-typed and byte-identical across
//! validators.
//!
//! The multi-CRT-prime fields (used only by threshold decryption, which the mock sign ignores) are
//! filled with defaults, and [`super::super::decentralized_party::dkg::PublicOutput`]'s
//! `decrypt_decryption_key_shares` is separately mocked to return dummy shares.

use std::collections::HashMap;
use std::sync::OnceLock;

use crypto_bigint::Uint;

use commitment::CommitmentSizedNumber;
use group::{curve25519, ristretto, secp256k1, secp256r1, CsRng, GroupElement as _, PartyID};
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable, WeightedThresholdAccessStructure};

use ::class_groups::dkg::PublicOutput as ClassGroupsDkgPublicOutput;
use ::class_groups::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
};
use ::class_groups::reconfiguration::PublicOutput as ClassGroupsReconfigPublicOutput;
use ::class_groups::setup::DeriveFromPlaintextPublicParameters;
use ::class_groups::{
    equivalence_class, CiphertextSpaceGroupElement, CiphertextSpaceValue, CompactIbqf,
    EquivalenceClass, Secp256k1SetupParameters, SecretKeyShareSizedInteger,
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS as FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};

use crate::decentralized_party::dkg::{PublicOutput, PublicOutputCore};
use crate::decentralized_party::reconfiguration::{
    PublicOutput as ReconfigPublicOutput, PublicOutputCore as ReconfigPublicOutputCore,
};
use crate::decentralized_party::threshold_encryption_of_secret_key_share_parts_to_sharing::PublicOutput as SharingPublicOutput;

/// The deterministically-derived equivalence-class public parameters and the neutral values used
/// for every class-group field of the mock outputs. The setup parameters are derived EXACTLY as
/// the `PublicOutputCore` extraction methods derive them, so extraction accepts the stored values.
/// Return-only; immediately destructured.
struct NeutralClassGroupValues {
    equivalence_class_public_parameters:
        equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    neutral_element: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    neutral_encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    neutral_ciphertext: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
}

fn neutral_class_group_values() -> NeutralClassGroupValues {
    let setup_parameters =
        Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
            secp256k1::scalar::PublicParameters::default(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
        .expect("deterministic setup-parameter derivation must succeed");
    let equivalence_class_public_parameters = setup_parameters
        .equivalence_class_public_parameters()
        .clone();
    let neutral_element =
        EquivalenceClass::neutral_from_public_parameters(&equivalence_class_public_parameters)
            .expect("the neutral element is constructible from valid public parameters");
    let neutral_ciphertext =
        CiphertextSpaceGroupElement::from([neutral_element, neutral_element]).value();

    NeutralClassGroupValues {
        equivalence_class_public_parameters,
        neutral_encryption_key: neutral_element.value(),
        neutral_element,
        neutral_ciphertext,
    }
}

/// Build the deterministic mock network-DKG public output, cached process-wide.
///
/// Per-curve fields are all neutral (identity public key shares and encryption key, identity-pair
/// ciphertexts); CRT-prime and Shamir-sharing fields are defaults. None of them is ever read by
/// the mock signing path — they must only be well-typed for storage, serialization and public
/// parameter extraction.
pub(crate) fn mock_network_dkg_public_output() -> &'static PublicOutput {
    static OUTPUT: OnceLock<PublicOutput> = OnceLock::new();
    OUTPUT.get_or_init(build_mock_network_dkg_public_output)
}

pub(crate) fn build_mock_network_dkg_public_output() -> PublicOutput {
    let NeutralClassGroupValues {
        neutral_encryption_key,
        neutral_ciphertext,
        ..
    } = neutral_class_group_values();

    let secp256k1_neutral_point = secp256k1::GroupElement::neutral_from_public_parameters(
        &secp256k1::group_element::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let secp256r1_neutral_point = secp256r1::GroupElement::neutral_from_public_parameters(
        &secp256r1::group_element::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let ristretto_neutral_point = ristretto::GroupElement::neutral_from_public_parameters(
        &ristretto::group_element::PublicParameters::default(),
    )
    .unwrap();
    let curve25519_neutral_point = curve25519::GroupElement::neutral_from_public_parameters(
        &curve25519::PublicParameters::default(),
    )
    .unwrap()
    .value();

    let inner = ClassGroupsDkgPublicOutput::<
        { secp256k1::SCALAR_LIMBS },
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    > {
        encryption_key: neutral_encryption_key,
        threshold_encryption_key_per_crt_prime: Default::default(),
        public_verification_keys: HashMap::new(),
        encryptions_of_shares_per_crt_prime: HashMap::new(),
        threshold_encryption_of_decryption_key_per_crt_prime: Default::default(),
    };

    let core = PublicOutputCore::new(
        inner,
        neutral_ciphertext,
        neutral_ciphertext,
        secp256k1_neutral_point,
        secp256k1_neutral_point,
        neutral_ciphertext,
        neutral_ciphertext,
        ristretto_neutral_point,
        ristretto_neutral_point,
        neutral_encryption_key,
        HashMap::new(),
        neutral_ciphertext,
        neutral_ciphertext,
        curve25519_neutral_point,
        curve25519_neutral_point,
        neutral_ciphertext,
        neutral_ciphertext,
        secp256r1_neutral_point,
        secp256r1_neutral_point,
        neutral_encryption_key,
        HashMap::new(),
    )
    .expect("building the mock network DKG output core must succeed");

    PublicOutput {
        core,
        threshold_encryption_to_sharing_output: neutral_sharing_output(),
    }
}

/// Build the deterministic mock network-reconfiguration public output for `upcoming_access_structure`.
///
/// Reconfiguration re-shares the SAME network key to a new committee, so — exactly as with the DKG
/// mock — per-curve fields are all neutral and randomizer/CRT data is empty (never read by the mock
/// signing path). Deterministic in the (common) upcoming access structure, so byte-identical across
/// validators.
pub(crate) fn mock_network_reconfiguration_public_output(
    upcoming_access_structure: &mpc::WeightedThresholdAccessStructure,
) -> ReconfigPublicOutput {
    let NeutralClassGroupValues {
        equivalence_class_public_parameters,
        neutral_element,
        neutral_encryption_key,
        neutral_ciphertext,
    } = neutral_class_group_values();

    let secp256k1_neutral_point = secp256k1::GroupElement::neutral_from_public_parameters(
        &secp256k1::group_element::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let secp256r1_neutral_point = secp256r1::GroupElement::neutral_from_public_parameters(
        &secp256r1::group_element::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let ristretto_neutral_point = ristretto::GroupElement::neutral_from_public_parameters(
        &ristretto::group_element::PublicParameters::default(),
    )
    .unwrap();
    let curve25519_neutral_point = curve25519::GroupElement::neutral_from_public_parameters(
        &curve25519::PublicParameters::default(),
    )
    .unwrap()
    .value();

    let inner = ClassGroupsReconfigPublicOutput::<
        { secp256k1::SCALAR_LIMBS },
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    > {
        encryption_key: neutral_encryption_key,
        masked_decryption_key_by_n_factorial: SecretKeyShareSizedInteger::ZERO,
        public_verification_keys: HashMap::new(),
        encryptions_of_randomizer_shares_per_crt_prime: HashMap::new(),
    };

    let core = ReconfigPublicOutputCore::new(
        inner,
        neutral_ciphertext,
        neutral_ciphertext,
        secp256k1_neutral_point,
        secp256k1_neutral_point,
        neutral_ciphertext,
        neutral_ciphertext,
        ristretto_neutral_point,
        ristretto_neutral_point,
        neutral_encryption_key,
        HashMap::new(),
        neutral_ciphertext,
        neutral_ciphertext,
        curve25519_neutral_point,
        curve25519_neutral_point,
        neutral_ciphertext,
        neutral_ciphertext,
        secp256r1_neutral_point,
        secp256r1_neutral_point,
        neutral_encryption_key,
        HashMap::new(),
        // The (unused) verification-key base must only be a valid class-group element.
        neutral_element,
        neutral_element,
        upcoming_access_structure,
        &equivalence_class_public_parameters,
    )
    .expect("building the mock network reconfiguration output core must succeed");

    ReconfigPublicOutput {
        core,
        threshold_encryption_to_sharing_output: neutral_sharing_output(),
    }
}

/// A structurally-valid all-neutral/empty sharing sub-output. Only `derive_shamir_*` and
/// `*_polynomial_commitments` read it, and the mock signing path calls neither.
fn neutral_sharing_output() -> SharingPublicOutput {
    let secp256k1_point = secp256k1::GroupElement::neutral_from_public_parameters(
        &secp256k1::group_element::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let secp256r1_point = secp256r1::GroupElement::neutral_from_public_parameters(
        &secp256r1::group_element::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let ristretto_point = ristretto::GroupElement::neutral_from_public_parameters(
        &ristretto::group_element::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let curve25519_point = curve25519::GroupElement::neutral_from_public_parameters(
        &curve25519::PublicParameters::default(),
    )
    .unwrap()
    .value();

    let secp256k1_scalar = secp256k1::Scalar::neutral_from_public_parameters(
        &secp256k1::scalar::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let secp256r1_scalar = secp256r1::Scalar::neutral_from_public_parameters(
        &secp256r1::scalar::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let ristretto_scalar = ristretto::Scalar::neutral_from_public_parameters(
        &ristretto::scalar::PublicParameters::default(),
    )
    .unwrap()
    .value();
    let curve25519_scalar = curve25519::Scalar::neutral_from_public_parameters(
        &curve25519::scalar::PublicParameters::default(),
    )
    .unwrap()
    .value();

    SharingPublicOutput {
        secp256k1_first_public_key_share: secp256k1_point,
        secp256k1_second_public_key_share: secp256k1_point,
        secp256k1_first_secret_polynomial_commitments: vec![],
        secp256k1_second_secret_polynomial_commitments: vec![],
        ristretto_first_public_key_share: ristretto_point,
        ristretto_second_public_key_share: ristretto_point,
        ristretto_first_secret_polynomial_commitments: vec![],
        ristretto_second_secret_polynomial_commitments: vec![],
        curve25519_first_public_key_share: curve25519_point,
        curve25519_second_public_key_share: curve25519_point,
        curve25519_first_secret_polynomial_commitments: vec![],
        curve25519_second_secret_polynomial_commitments: vec![],
        secp256r1_first_public_key_share: secp256r1_point,
        secp256r1_second_public_key_share: secp256r1_point,
        secp256r1_first_secret_polynomial_commitments: vec![],
        secp256r1_second_secret_polynomial_commitments: vec![],
        secp256k1_randomizer_dealings: HashMap::new(),
        ristretto_randomizer_dealings: HashMap::new(),
        curve25519_randomizer_dealings: HashMap::new(),
        secp256r1_randomizer_dealings: HashMap::new(),
        secp256k1_first_masked_secret_key_share_part: secp256k1_scalar,
        secp256k1_second_masked_secret_key_share_part: secp256k1_scalar,
        ristretto_first_masked_secret_key_share_part: ristretto_scalar,
        ristretto_second_masked_secret_key_share_part: ristretto_scalar,
        curve25519_first_masked_secret_key_share_part: curve25519_scalar,
        curve25519_second_masked_secret_key_share_part: curve25519_scalar,
        secp256r1_first_masked_secret_key_share_part: secp256r1_scalar,
        secp256r1_second_masked_secret_key_share_part: secp256r1_scalar,
    }
}

/// Deterministic dummy threshold decryption-key shares (one zero share per virtual party).
///
/// The mock signing path recovers the whole signing key by decrypting `Enc(x_B)` with the
/// canonical network key and never uses these shares, so their value is irrelevant — they must only
/// be well-typed and present for every virtual party ika expects.
pub(crate) fn mock_decryption_key_shares(
    access_structure: &mpc::WeightedThresholdAccessStructure,
    tangible_party_id: group::PartyID,
) -> HashMap<group::PartyID, ::class_groups::SecretKeyShareSizedInteger> {
    access_structure
        .party_to_virtual_parties()
        .get(&tangible_party_id)
        .into_iter()
        .flatten()
        .map(|&virtual_party_id| {
            (
                virtual_party_id,
                ::class_groups::SecretKeyShareSizedInteger::ZERO,
            )
        })
        .collect()
}

/// INSECURE mock of the network-DKG party — finalizes round 1 with the cached deterministic mock
/// network-DKG output (the canonical `NETWORK_KEY_SEED` key). Ignores all inputs.
pub struct MockNetworkDKGParty;

impl mpc::Party for MockNetworkDKGParty {
    type Error = crate::Error;
    type PublicInput = crate::decentralized_party::dkg::PublicInput;
    type PrivateOutput = ();
    type PublicOutputValue = PublicOutput;
    type PublicOutput = Self::PublicOutputValue;
    type Message = crate::decentralized_party::dkg::Message;
}

impl AsynchronouslyAdvanceable for MockNetworkDKGParty {
    type PrivateInput = crate::decentralized_party::dkg::PrivateInput;

    fn advance(
        _session_id: CommitmentSizedNumber,
        _tangible_party_id: PartyID,
        _access_structure: &WeightedThresholdAccessStructure,
        _messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        _public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: (),
            public_output: mock_network_dkg_public_output().clone(),
        })
    }

    fn round_causing_threshold_not_reached(_current_round: u64) -> Option<u64> {
        None
    }
}

/// INSECURE mock of the network-reconfiguration party — finalizes round 1 with the deterministic
/// mock reconfiguration output (re-shares the SAME canonical `NETWORK_KEY_SEED` key). Ignores all
/// inputs except the (common) access structure it re-shares to.
pub struct MockNetworkReconfigurationParty;

impl mpc::Party for MockNetworkReconfigurationParty {
    type Error = crate::Error;
    type PublicInput = crate::decentralized_party::reconfiguration::PublicInput;
    type PrivateOutput = ();
    type PublicOutputValue = ReconfigPublicOutput;
    type PublicOutput = Self::PublicOutputValue;
    type Message = crate::decentralized_party::reconfiguration::Message;
}

impl AsynchronouslyAdvanceable for MockNetworkReconfigurationParty {
    type PrivateInput = HashMap<PartyID, ::class_groups::SecretKeyShareSizedInteger>;

    fn advance(
        _session_id: CommitmentSizedNumber,
        _tangible_party_id: PartyID,
        current_access_structure: &WeightedThresholdAccessStructure,
        _messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        _public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: (),
            public_output: mock_network_reconfiguration_public_output(current_access_structure),
        })
    }

    fn round_causing_threshold_not_reached(_current_round: u64) -> Option<u64> {
        None
    }
}

// ===================================================================================================
// Backward-compatible (V2) network DKG + reconfiguration twins
// ===================================================================================================
//
// The pre-Protocol-0.1 (V2) network DKG / reconfiguration parties produce the *core* public output
// (the `PublicOutputCore` shape, without the Protocol-0.1 Shamir-sharing sub-output). Their
// `PublicOutput` re-exports the V3 core, so these mocks finalize with the `core` of the same cached
// canonical `NETWORK_KEY_SEED` output the V3 mocks return.

/// INSECURE mock of the backward-compatible (V2) network-DKG party — finalizes round 1 with the
/// `core` of the cached deterministic mock network-DKG output.
pub struct MockNetworkDKGPartyV2;

impl mpc::Party for MockNetworkDKGPartyV2 {
    type Error = crate::Error;
    type PublicInput = crate::decentralized_party_backward_compatible::dkg::PublicInput;
    type PrivateOutput = ();
    type PublicOutputValue = crate::decentralized_party_backward_compatible::dkg::PublicOutput;
    type PublicOutput = Self::PublicOutputValue;
    type Message = crate::decentralized_party_backward_compatible::dkg::Message;
}

impl AsynchronouslyAdvanceable for MockNetworkDKGPartyV2 {
    type PrivateInput = [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES];

    fn advance(
        _session_id: CommitmentSizedNumber,
        _tangible_party_id: PartyID,
        _access_structure: &WeightedThresholdAccessStructure,
        _messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        _public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: (),
            public_output: mock_network_dkg_public_output().core.clone(),
        })
    }

    fn round_causing_threshold_not_reached(_current_round: u64) -> Option<u64> {
        None
    }
}

/// INSECURE mock of the backward-compatible (V2) network-reconfiguration party — finalizes round 1
/// with the `core` of the deterministic mock reconfiguration output (re-shares the SAME canonical
/// `NETWORK_KEY_SEED` key).
pub struct MockNetworkReconfigurationPartyV2;

impl mpc::Party for MockNetworkReconfigurationPartyV2 {
    type Error = crate::Error;
    type PublicInput = crate::decentralized_party_backward_compatible::reconfiguration::PublicInput;
    type PrivateOutput = ();
    type PublicOutputValue =
        crate::decentralized_party_backward_compatible::reconfiguration::PublicOutput;
    type PublicOutput = Self::PublicOutputValue;
    type Message = crate::decentralized_party_backward_compatible::reconfiguration::Message;
}

impl AsynchronouslyAdvanceable for MockNetworkReconfigurationPartyV2 {
    type PrivateInput = HashMap<PartyID, SecretKeyShareSizedInteger>;

    fn advance(
        _session_id: CommitmentSizedNumber,
        _tangible_party_id: PartyID,
        current_access_structure: &WeightedThresholdAccessStructure,
        _messages: Vec<HashMap<PartyID, Self::Message>>,
        _private_input: Option<Self::PrivateInput>,
        _public_input: &Self::PublicInput,
        _rng: &mut impl CsRng,
    ) -> std::result::Result<
        AsynchronousRoundResult<Self::Message, Self::PrivateOutput, Self::PublicOutput>,
        Self::Error,
    > {
        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties: vec![],
            private_output: (),
            public_output: mock_network_reconfiguration_public_output(current_access_structure)
                .core,
        })
    }

    fn round_causing_threshold_not_reached(_current_round: u64) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mpc::WeightedThresholdAccessStructure;

    /// The unchanged extraction methods must accept the all-neutral mock output: they derive the
    /// setup parameters deterministically, then validate and accelerate the stored (identity)
    /// encryption key and ciphertexts. This is exactly the path ika takes to obtain the protocol
    /// public parameters from the mocked network DKG.
    #[test]
    fn extracts_protocol_public_parameters_from_neutral_mock_outputs() {
        let output = super::mock_network_dkg_public_output();

        output.secp256k1_protocol_public_parameters().unwrap();
        output.ristretto_protocol_public_parameters().unwrap();
        output.curve25519_protocol_public_parameters().unwrap();
        output.secp256r1_protocol_public_parameters().unwrap();

        let access_structure = WeightedThresholdAccessStructure::new(
            3,
            HashMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]),
        )
        .unwrap();
        super::mock_network_reconfiguration_public_output(&access_structure);
    }
}
