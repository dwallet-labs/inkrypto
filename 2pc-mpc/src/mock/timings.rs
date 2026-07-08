// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Wall-clock timing report for the INSECURE mock protocol operations (`unsafe_mock`).
//!
//! Not a benchmark suite — a single always-passing test that prints per-operation timings (run
//! with `--nocapture`) so the mock's speed can be reported and tracked. The real protocols take
//! seconds-to-minutes per operation; every mocked operation must stay micro/milliseconds (the
//! network-output builders are allowed the one-off cost of deriving the deterministic class-group
//! setup parameters).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use commitment::CommitmentSizedNumber;
use group::{
    curve25519, ristretto, secp256k1, secp256r1, HashContext, HashScheme, OsCsRng, PartyID,
};
use mpc::{AsynchronouslyAdvanceable as _, WeightedThresholdAccessStructure};

/// Run `operation` once unmeasured (warm-up), then `iterations` times measured, and print the
/// mean wall-clock time per operation.
fn report<R>(label: &str, iterations: u32, mut operation: impl FnMut() -> R) {
    std::hint::black_box(operation());
    let start = Instant::now();
    for _ in 0..iterations {
        std::hint::black_box(operation());
    }
    let per_operation = start.elapsed() / iterations;
    println!("{label:<72} {per_operation:>12.2?}");
}

#[test]
fn mock_protocol_timings_report() {
    let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
    let secp256k1_group_public_parameters = secp256k1::group_element::PublicParameters::default();
    let secp256r1_scalar_public_parameters = secp256r1::scalar::PublicParameters::default();
    let secp256r1_group_public_parameters = secp256r1::group_element::PublicParameters::default();
    let curve25519_scalar_public_parameters = curve25519::scalar::PublicParameters::default();
    let curve25519_group_public_parameters = curve25519::PublicParameters::default();
    let ristretto_scalar_public_parameters = ristretto::scalar::PublicParameters::default();
    let ristretto_group_public_parameters = ristretto::group_element::PublicParameters::default();

    let message = b"unsafe_mock timing";
    let schnorrkel_hash_context = HashContext::Schnorrkel {
        signing_context: b"substrate".to_vec(),
    };

    println!();
    println!("== INSECURE mock protocol timings (mean per operation) ==");

    report(
        "ECDSA sign (secp256k1): deterministic mock signature",
        200,
        || {
            crate::mock::ecdsa::mock_sign::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                message,
                HashScheme::SHA256,
                &HashContext::None,
                &secp256k1_scalar_public_parameters,
                &secp256k1_group_public_parameters,
            )
            .unwrap()
        },
    );
    report(
        "ECDSA sign (secp256r1): deterministic mock signature",
        200,
        || {
            crate::mock::ecdsa::mock_sign::<{ secp256r1::SCALAR_LIMBS }, secp256r1::GroupElement>(
                message,
                HashScheme::SHA256,
                &HashContext::None,
                &secp256r1_scalar_public_parameters,
                &secp256r1_group_public_parameters,
            )
            .unwrap()
        },
    );
    report(
        "Schnorr sign Taproot (secp256k1): deterministic mock signature",
        200,
        || {
            crate::mock::schnorr::mock_sign::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement>(
                message,
                HashScheme::SHA256,
                &HashContext::None,
                &secp256k1_scalar_public_parameters,
                &secp256k1_group_public_parameters,
            )
            .unwrap()
        },
    );
    report(
        "Schnorr sign EdDSA (curve25519): deterministic mock signature",
        200,
        || {
            crate::mock::schnorr::mock_sign::<{ curve25519::SCALAR_LIMBS }, curve25519::GroupElement>(
            message,
            HashScheme::SHA512,
            &HashContext::None,
            &curve25519_scalar_public_parameters,
            &curve25519_group_public_parameters,
        )
        .unwrap()
        },
    );
    report(
        "Schnorr sign Schnorrkel (ristretto): deterministic mock signature",
        200,
        || {
            crate::mock::schnorr::mock_sign::<{ ristretto::SCALAR_LIMBS }, ristretto::GroupElement>(
                message,
                HashScheme::Merlin,
                &schnorrkel_hash_context,
                &ristretto_scalar_public_parameters,
                &ristretto_group_public_parameters,
            )
            .unwrap()
        },
    );

    // The dWallet DKG and presign mocks now simulate the real protocols' round structure; the timed
    // output construction happens only on the final `advance` round (driven below with the requisite
    // number of empty prior-round message maps).
    let (protocol_public_parameters, _) = crate::test_helpers::setup_class_groups_secp256k1();
    report(
        "dWallet DKG (secp256k1): decentralized output (public key 42*G)",
        200,
        || {
            crate::mock::dkg::mock_dkg_output::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
                _,
                _,
            >(&protocol_public_parameters)
            .unwrap()
        },
    );

    type MockSecp256k1PresignParty = crate::mock::ecdsa::MockPresignAsyncECDSAParty<
        { secp256k1::SCALAR_LIMBS },
        { crate::secp256k1::class_groups::FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { crate::secp256k1::class_groups::NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
        { crate::secp256k1::MESSAGE_LIMBS },
        secp256k1::GroupElement,
    >;
    let access_structure =
        WeightedThresholdAccessStructure::new(3, HashMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]))
            .unwrap();
    let session_id = CommitmentSizedNumber::from(42u64);
    let presign_public_input = crate::ecdsa::presign::decentralized_party::PublicInput {
        dkg_output: None,
        protocol_public_parameters: Arc::new(protocol_public_parameters.clone()),
    };
    // ECDSA presign is a 4-round protocol; drive the final round (three empty prior-round message
    // maps) so the timed `advance` performs the presign output construction rather than the
    // round-simulation bookkeeping of an intermediate round.
    report(
        "ECDSA presign (secp256k1): full party advance (finalize final round)",
        200,
        || {
            MockSecp256k1PresignParty::advance(
                session_id,
                1 as PartyID,
                &access_structure,
                vec![HashMap::new(), HashMap::new(), HashMap::new()],
                Some(()),
                &presign_public_input,
                &mut OsCsRng,
            )
            .unwrap()
        },
    );

    report(
        "network DKG: full output build (all-neutral, uncached)",
        3,
        crate::mock::network_dkg::build_mock_network_dkg_public_output,
    );
    report("network DKG: cached output access", 1000, || {
        crate::mock::network_dkg::mock_network_dkg_public_output()
    });
    let network_dkg_output = crate::mock::network_dkg::mock_network_dkg_public_output();
    report(
        "network pp extraction (secp256k1): derive + validate + accelerate",
        2,
        || {
            network_dkg_output
                .secp256k1_protocol_public_parameters()
                .unwrap()
        },
    );
    report(
        "network pp extraction (secp256r1): derive + validate + accelerate",
        2,
        || {
            network_dkg_output
                .secp256r1_protocol_public_parameters()
                .unwrap()
        },
    );
    report(
        "network pp extraction (ristretto): derive + validate + accelerate",
        2,
        || {
            network_dkg_output
                .ristretto_protocol_public_parameters()
                .unwrap()
        },
    );
    report(
        "network pp extraction (curve25519): derive + validate + accelerate",
        2,
        || {
            network_dkg_output
                .curve25519_protocol_public_parameters()
                .unwrap()
        },
    );
    report(
        "network reconfiguration: full output build (four validators)",
        3,
        || crate::mock::network_dkg::mock_network_reconfiguration_public_output(&access_structure),
    );
    report(
        "network decrypt_decryption_key_shares: dummy shares",
        1000,
        || crate::mock::network_dkg::mock_decryption_key_shares(&access_structure, 1),
    );
}
