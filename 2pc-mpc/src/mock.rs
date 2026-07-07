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
//! finalizes in a single round, deterministically, from the common public inputs alone.
//!
//! ## What it gives up
//! **All security.** Every dWallet uses the SAME constant signing key `x = 42`
//! ([`MOCK_SECRET_KEY`]) and a constant nonce, so anyone can forge signatures and every dWallet
//! shares the public key `42·G`. The user (centralized) side is emulated (`SignData::ToBeEmulated`,
//! `x_A = 0`). This must never be enabled in production — only in tests.

pub(crate) mod dkg;
pub(crate) mod ecdsa;
pub(crate) mod network_dkg;
pub(crate) mod schnorr;
#[cfg(test)]
mod timings;
pub(crate) mod vss;

use crypto_bigint::Uint;

use group::{GroupElement as _, PrimeGroupElement};

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
