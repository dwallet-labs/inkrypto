// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # INSECURE deterministic protocol mocks (`unsafe_mock` feature)
//!
//! This module provides functional-but-**completely insecure** stand-ins for the 2PC-MPC
//! protocols, used to massively speed up downstream integration tests (e.g. the ika network).
//!
//! ## Design
//! Under the `unsafe_mock` feature the exported protocol party/`Protocol` aliases are redirected to
//! the mock party types defined here (see `crate::mock::{dkg, ecdsa, schnorr, vss, network_dkg}`);
//! the real protocol `advance`/method bodies are left completely untouched. Each mock party
//! simulates its real protocol's round structure — trivial [`MOCK_HONEST_MESSAGE`] rounds with
//! malicious-sender detection and threshold enforcement (see [`mock_advance_result`]) — and
//! finalizes on the last round, deterministically, from the common public inputs alone.
//!
//! ## What it gives up
//! **All security.** Every dWallet uses the SAME constant signing key `x = 42`
//! ([`MOCK_SECRET_KEY`]) and a constant nonce, so anyone can forge signatures and every dWallet
//! shares the public key `42·G`. The user (centralized) side does no real cryptography either:
//! under threshold mode it is emulated (`SignData::ToBeEmulated`, `x_A = 0`), and for user-signed
//! flows the centralized sign parties are mocked (`MockSignCentralized*Party`) — they emit a
//! deterministic, structurally-valid partial signature that the mocked decentralized sign ignores.
//! This must never be enabled in production — only in tests.

pub(crate) mod dkg;
pub(crate) mod ecdsa;
pub(crate) mod network_dkg;
pub(crate) mod schnorr;
#[cfg(test)]
mod timings;
pub(crate) mod vss;

use std::collections::{HashMap, HashSet};

use crypto_bigint::Uint;

use group::helpers::DeduplicateAndSort;
use group::{GroupElement as _, PartyID, PrimeGroupElement};
use mpc::{AsynchronousRoundResult, WeightedThresholdAccessStructure};

/// The magic value every honest party's mock protocol message carries. The mock
/// parties simulate the real round structure (advancing round-by-round, finalizing
/// only on the last round) but with a trivial payload: a `u64` equal to this
/// constant. A received message whose value differs marks the sender **malicious**,
/// which lets the mocked flow exercise malicious-party detection.
pub(crate) const MOCK_HONEST_MESSAGE: u64 = 0xDEAD_BEEF;

/// Shared mock round bookkeeping, used by every mock party's `advance` so the
/// round-simulation + malicious-detection logic lives in one place.
///
/// `messages` is the ordered list of prior rounds' messages (the `i`th entry holds
/// round `i`'s `PartyID -> u64` map); `total_rounds` is the real protocol's round
/// count. Returns the malicious parties (any sender that ever sent a value other
/// than [`MOCK_HONEST_MESSAGE`]) and whether the current round
/// (`messages.len() + 1`) is the protocol's final round.
pub(crate) fn mock_round_bookkeeping(
    messages: &[HashMap<PartyID, u64>],
    total_rounds: usize,
) -> (Vec<PartyID>, bool) {
    let malicious_parties = messages
        .iter()
        .flat_map(|round| {
            round
                .iter()
                .filter(|(_, &message)| message != MOCK_HONEST_MESSAGE)
                .map(|(&party_id, _)| party_id)
        })
        .collect::<Vec<_>>()
        .deduplicate_and_sort();

    let is_final_round = messages.len() + 1 >= total_rounds;

    (malicious_parties, is_final_round)
}

/// Build the mock `advance` result: [`AsynchronousRoundResult::Advance`] carrying a
/// [`MOCK_HONEST_MESSAGE`] for all but the final round, otherwise
/// [`AsynchronousRoundResult::Finalize`] with the outputs from `finalize` (called
/// only on the final round; its error is propagated). Threads the detected
/// `malicious_parties` through either arm.
///
/// Mimics the real protocols' threshold-not-reached behavior: an advance first
/// filters protocol-invalid (malicious) contributions, then requires the remaining
/// senders of the latest completed round to form an authorized subset — otherwise it
/// aborts with [`mpc::ErrorKind::ThresholdNotReached`], which the
/// guaranteed-output-delivery layer converts into a `ThresholdNotReached` message and
/// a retried advance (attributed to the previous round, see
/// [`mock_round_causing_threshold_not_reached`]).
pub(crate) fn mock_advance_result<PrivateOutput, PublicOutput, Error: From<mpc::Error>>(
    access_structure: &WeightedThresholdAccessStructure,
    messages: &[HashMap<PartyID, u64>],
    total_rounds: usize,
    finalize: impl FnOnce() -> Result<(PrivateOutput, PublicOutput), Error>,
) -> Result<AsynchronousRoundResult<u64, PrivateOutput, PublicOutput>, Error> {
    let (malicious_parties, is_final_round) = mock_round_bookkeeping(messages, total_rounds);
    if let Some(latest_round_messages) = messages.last() {
        let honest_senders = latest_round_messages
            .keys()
            .filter(|party_id| !malicious_parties.contains(party_id))
            .copied()
            .collect::<HashSet<_>>();
        access_structure
            .is_authorized_subset(&honest_senders)
            .map_err(Error::from)?;
    }
    if is_final_round {
        let (private_output, public_output) = finalize()?;
        Ok(AsynchronousRoundResult::Finalize {
            malicious_parties,
            private_output,
            public_output,
        })
    } else {
        Ok(AsynchronousRoundResult::Advance {
            malicious_parties,
            message: MOCK_HONEST_MESSAGE,
        })
    }
}

/// Generic mock of [`mpc::AsynchronouslyAdvanceable::round_causing_threshold_not_reached`]:
/// any round after the first verifies the previous round's messages, so a
/// threshold-not-reached abort at `current_round` is attributed to `current_round - 1`.
pub(crate) fn mock_round_causing_threshold_not_reached(current_round: u64) -> Option<u64> {
    current_round.checked_sub(1).filter(|&round| round >= 1)
}

/// The INSECURE constant signing key: `x = 42` for every dWallet on every curve.
/// Public key is therefore `42·G` everywhere.
pub(crate) const MOCK_SECRET_KEY: u64 = 42;

/// The INSECURE constant signing nonce `k`. Any fixed nonzero scalar yields a valid (if
/// catastrophically insecure — reused across every signature) ECDSA/Schnorr signature.
pub(crate) const MOCK_NONCE: u64 = 0x0DEC_0DE4_2BAD_5EED;

/// The constant mock signing key `x = 42` as a scalar of `GroupElement`'s field.
pub(crate) fn mock_secret_key<const SCALAR_LIMBS: usize, GroupElement>(
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> crate::Result<GroupElement::Scalar>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
{
    scalar_constant::<SCALAR_LIMBS, GroupElement>(MOCK_SECRET_KEY, scalar_group_public_parameters)
}

/// The constant mock nonce `k` as a scalar of `GroupElement`'s field.
pub(crate) fn mock_nonce<const SCALAR_LIMBS: usize, GroupElement>(
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> crate::Result<GroupElement::Scalar>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
{
    scalar_constant::<SCALAR_LIMBS, GroupElement>(MOCK_NONCE, scalar_group_public_parameters)
}

/// Build a scalar from a small `u64` constant (reduced into the scalar field).
fn scalar_constant<const SCALAR_LIMBS: usize, GroupElement>(
    constant: u64,
    scalar_group_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
) -> crate::Result<GroupElement::Scalar>
where
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
{
    let value =
        group::Value::<GroupElement::Scalar>::from(Uint::<SCALAR_LIMBS>::from_u64(constant));
    GroupElement::Scalar::new(value, scalar_group_public_parameters).map_err(Into::into)
}
