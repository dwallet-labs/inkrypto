// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! TEMPORARY — remove together with the rest of the `backward_compatible` mechanism once the
//! network has fully migrated off the inkrypto `37bb549f` wire format and backward compatibility is
//! no longer required.
//!
//! Pins for the `decentralized_party_backward_compatible` wire format, which must reproduce inkrypto
//! `37bb549f`'s `decentralized_party` (mainnet v1.1.8) byte-for-byte — its equality-of-coefficients
//! proof is **48-limb** (`SECRET_KEY_SHARE_WITNESS_LIMBS`) with the `-10` relaxed bound
//! (`sample_bits + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS - 10`). `bounded_integers_group::
//! PublicParameters` has `CanonicalRepresentation = Self`, so its limb width (`order_bits`) and
//! `upper_bound_bits` are transcribed into the Fiat–Shamir challenge; the incident was this proof
//! being built at 32 limbs instead of 48, which desynced the challenge and flagged the upgraded node
//! as malicious in reconfiguration round 1.

use commitment::CommitmentSizedNumber;
use crypto_bigint::Int;
use group::direct_product::ThreeWayGroupElement;
use group::{
    bounded_integers_group, bounded_natural_numbers_group::MAURER_PROOFS_DIFF_UPPER_BOUND_BITS,
    Samplable,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use class_groups::test_helpers::{
    get_setup_parameters_ristretto_112_bits_deterministic,
    get_setup_parameters_secp256k1_112_bits_deterministic,
    get_setup_parameters_secp256r1_112_bits_deterministic,
};
use class_groups::{
    EquivalenceClass,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS as NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use proof::GroupsPublicParametersAccessors;

use crate::decentralized_party_backward_compatible::dkg::Party;
use crate::languages::prove_equality_of_discrete_log;
use crate::BaseProtocolContext;

/// Batch size (number of coefficients) of the pinned proof; the serialized length is fully
/// determined by this with the limb widths and repetition count, independent of witness values.
const PINNED_BATCH_SIZE: usize = 3;
/// A fixed, valid `sample_bits`: must satisfy `sample_bits + 519 < 3072` (48-limb `order_bits`).
const PINNED_SAMPLE_BITS: u32 = 1000;
/// Exact bcs byte length of a real backward-compatible (now 48-limb) equality-of-coefficients proof
/// over [`PINNED_BATCH_SIZE`] coefficients. Recorded from the current build; drift of the limb
/// width, repetition count, or batch encoding changes it — the pin the incident lacked.
const EXPECTED_BACKWARD_COMPATIBLE_PROOF_BYTE_LENGTH: usize = 1160;

#[test]
fn constants_pinned() {
    assert_eq!(MAURER_PROOFS_DIFF_UPPER_BOUND_BITS, 529);
    assert_eq!(SECRET_KEY_SHARE_LIMBS, 32);
    assert_eq!(SECRET_KEY_SHARE_WITNESS_LIMBS, 48);

    // The witness limb widths fix the on-wire response byte size: 32 limbs -> 256 raw bytes
    // (258 under bcs, including a 2-byte ULEB128 length prefix), 48 limbs -> 384 raw bytes (386).
    assert_eq!(Int::<SECRET_KEY_SHARE_LIMBS>::BITS, 2048);
    assert_eq!(Int::<SECRET_KEY_SHARE_WITNESS_LIMBS>::BITS, 3072);
    assert_eq!(
        bcs::to_bytes(&Int::<SECRET_KEY_SHARE_LIMBS>::ONE)
            .unwrap()
            .len(),
        258
    );
    assert_eq!(
        bcs::to_bytes(&Int::<SECRET_KEY_SHARE_WITNESS_LIMBS>::ONE)
            .unwrap()
            .len(),
        386
    );
}

#[test]
fn bound_formulas_pinned() {
    for sample_bits in [100u32, 1000, 1518] {
        let backward_compatible = bounded_integers_group::PublicParameters::<
            SECRET_KEY_SHARE_WITNESS_LIMBS,
        >::new_with_randomizer_upper_bound_backward_compatible(
            sample_bits
        )
        .unwrap();
        assert_eq!(
            backward_compatible.upper_bound_bits,
            sample_bits + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS - 10
        );

        let strict = bounded_integers_group::PublicParameters::<SECRET_KEY_SHARE_WITNESS_LIMBS>::new_with_randomizer_upper_bound(
            sample_bits,
        )
        .unwrap();
        assert_eq!(
            strict.upper_bound_bits,
            sample_bits + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS
        );
    }
}

/// Path-level pin: the backward-compatible equality-of-coefficients proof must be built over the
/// **48-limb** witness group (return type enforces the width at compile time) with the `-10` bound.
/// This directly guards the incident: a revert to 32 limbs or the strict bound fails here.
#[test]
fn backward_compatible_coefficients_language_is_48_limb_relaxed() {
    let language_public_parameters = Party::prepare_coefficients_commitments_proof(
        PINNED_SAMPLE_BITS,
        &get_setup_parameters_secp256k1_112_bits_deterministic(),
        &get_setup_parameters_ristretto_112_bits_deterministic(),
        &get_setup_parameters_secp256r1_112_bits_deterministic(),
    )
    .unwrap();

    // Return type is `...<SECRET_KEY_SHARE_WITNESS_LIMBS, _>`, so the witness group is 48-limb.
    let witness_space_public_parameters =
        language_public_parameters.witness_space_public_parameters();
    assert_eq!(
        witness_space_public_parameters.sample_bits,
        PINNED_SAMPLE_BITS
    );
    assert_eq!(
        witness_space_public_parameters.upper_bound_bits,
        PINNED_SAMPLE_BITS + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS - 10
    );
}

/// Serialized-length canary over a real backward-compatible proof (48-limb responses, `-10` bound).
/// The length is deterministic (every component is a fixed-width integer under bcs); a limb-width,
/// repetition-count, or batch-encoding drift changes it. This is the test the incident lacked.
#[test]
fn backward_compatible_proof_serialized_length_pinned() {
    let language_public_parameters = Party::prepare_coefficients_commitments_proof(
        PINNED_SAMPLE_BITS,
        &get_setup_parameters_secp256k1_112_bits_deterministic(),
        &get_setup_parameters_ristretto_112_bits_deterministic(),
        &get_setup_parameters_secp256r1_112_bits_deterministic(),
    )
    .unwrap();

    // Coefficients are produced at their natural 32-limb width; the proof widens them to 48.
    let discrete_log_group_public_parameters = bounded_integers_group::PublicParameters::<
        SECRET_KEY_SHARE_LIMBS,
    >::new_with_randomizer_upper_bound_backward_compatible(
        PINNED_SAMPLE_BITS
    )
    .unwrap();

    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let coefficients_for_commitments = (0..PINNED_BATCH_SIZE)
        .map(|_| {
            bounded_integers_group::GroupElement::<SECRET_KEY_SHARE_LIMBS>::sample(
                &discrete_log_group_public_parameters,
                &mut rng,
            )
        })
        .collect::<group::Result<_>>()
        .unwrap();

    let base_protocol_context = BaseProtocolContext {
        protocol_name: "Backward Compatible Wire Format Pin".to_string(),
        round_name: "Pin".to_string(),
        proof_name: "Equality of Coefficients Commitments".to_string(),
    };
    let protocol_context =
        base_protocol_context.with_party_id_and_session_id(1, CommitmentSizedNumber::ONE);

    let (proof, _base_by_discrete_logs) = prove_equality_of_discrete_log::<
        SECRET_KEY_SHARE_LIMBS,
        SECRET_KEY_SHARE_WITNESS_LIMBS,
        ThreeWayGroupElement<
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >(
        language_public_parameters,
        coefficients_for_commitments,
        &protocol_context,
        &mut rng,
    )
    .unwrap();

    assert_eq!(
        bcs::to_bytes(&proof).unwrap().len(),
        EXPECTED_BACKWARD_COMPATIBLE_PROOF_BYTE_LENGTH,
        "backward-compatible proof serialized length drifted from the v1.1.8-matching 48-limb format"
    );
}
