// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore};
#[cfg(any(test, feature = "os_rng"))]
use rand_core::{OsRng, TryRngCore};

pub use rand_core::SeedableRng;

/// A Cryptographically Secure Random Generator (CSRNG).
/// We use this trait in any exported functionality, in order to force consumers to use allowed random-generators.
///
/// Rust rules specify that you cannot implement a foreign trait for a foreign struct, and we count on that to force an allow-list.
/// This of-course could be circumvented, but we urge consumers not to.
///
/// We currently support ChaCha20 and OsRng.
pub trait CsRng: RngCore + CryptoRng + Send + Sync {}

/// A wrapper around `rand_core::OsRng` which implements `CsRng` by panicking on potential errors.
#[derive(Clone, Copy, Debug, Default)]
#[cfg(any(test, feature = "os_rng"))]
pub struct OsCsRng;

#[cfg(any(test, feature = "os_rng"))]
impl RngCore for OsCsRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        OsRng.try_next_u32().unwrap()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        OsRng.try_next_u64().unwrap()
    }

    #[inline]
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        OsRng.try_fill_bytes(dst).unwrap()
    }
}

#[cfg(any(test, feature = "os_rng"))]
impl CryptoRng for OsCsRng {}

#[cfg(any(test, feature = "os_rng"))]
impl CsRng for OsCsRng {}

impl CsRng for ChaCha20Rng {}
