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

/// TEMPORARY (two crypto-bigint versions): presents a workspace RNG (rand_core 0.9) to the curve
/// crates and the Bulletproofs fork, which take rand_core 0.10 RNGs. Every byte comes from the
/// wrapped RNG, in the same order, so a seeded RNG produces through this adapter exactly the
/// bytes it produces without it.
///
/// Why it exists: our crypto-bigint rc.9 implements its RNG traits for rand_core 0.9, so the
/// workspace stays on rand 0.9, while k256 and p256 0.14.0, curve25519-dalek 5.0.0 and the
/// Bulletproofs fork are built on rand_core 0.10. The adapter is the only way one RNG value
/// serves both until the two crypto-bigint copies are one crate again.
///
/// Revert: when our crypto-bigint moves to the version k256 and p256 use (rand_core 0.10),
/// move rand, rand_core and rand_chacha to 0.10, delete this type, its re-export in `lib.rs`
/// and the `rand_core_010` dependency, and pass `rng` directly at every `Rng010(...)` call
/// site. The marker at the top of this comment is on every one of them.
pub struct Rng010<'a, R: CsRng + ?Sized>(pub &'a mut R);

impl<R: CsRng + ?Sized> rand_core_010::TryRng for Rng010<'_, R> {
    type Error = core::convert::Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    #[inline]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R: CsRng + ?Sized> rand_core_010::TryCryptoRng for Rng010<'_, R> {}
