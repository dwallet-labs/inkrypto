// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Sampling that must reproduce values generated in the past.
//!
//! A decryption key derived from a stored seed (a user's root seed, a validator's root seed)
//! must come out the same forever, which means the exact way the sampler consumes the seeded
//! RNG must never change. crypto-bigint does not keep that stable: its `random_mod` was
//! rewritten after the revision this workspace was deployed with. So the seeded pathway does
//! not sample with whatever crypto-bigint the workspace currently uses. It samples with the
//! deployed revision of the fork, compiled in as a second crate (`crypto-bigint-legacy`,
//! pinned to `ycscaly/crypto-bigint` at `8aabcee5`), and converts the operands through machine
//! words. Nothing is transcribed, so there is nothing to get wrong and no foreign license in
//! this file.
//!
//! The RNG is the workspace's ChaCha20 (`rand_chacha::ChaCha20Rng`, deployed at rand_chacha
//! 0.9.0), the same one the deployed callers seeded. Its stream is a fixed standard, so today
//! it needs no pin; the transcript test below pins the RNG and the sampler together. Every
//! legacy entry point takes the 32-byte seed itself, not an RNG, and builds the RNG with
//! [`legacy_seeded_rng`], exactly as the deployed callers did. The RNG is handed to the pinned
//! crypto-bigint directly: both speak rand_core 0.9.
//!
//! **If rand_chacha ever changes behaviour or stops fitting the pinned crypto-bigint**, this
//! pathway must not be moved to the changed version. Pin rand_chacha to the last compatible
//! version (0.9.0, the deployed one) as a second crate for this module alone, the way
//! `crypto-bigint-legacy` is pinned; once the workspace is on another version the two are
//! different packages and Cargo allows both. The transcript test must keep passing unchanged.
//!
//! **The legacy pathway is not compatible between 32-bit and 64-bit targets.** The deployed
//! sampler drew whole machine words: 64-bit words on native, 32-bit words on `wasm32`. The same
//! seed therefore gave a different key on each, and the legacy pathway reproduces a key only on
//! a target with the same word width as the one that first derived it. That is the deployed
//! behaviour, kept on purpose.
//!
//! **The production sampler draws 64-bit words on every target.** The workspace crypto-bigint
//! (the fork at `c6a32050`, the deployed revision plus the sampler commit and six upstream fixes) runs the deployed algorithm
//! in 64-bit words whatever the limb width is, so a new seeded key is the same on native and
//! on `wasm32`, and equals what the deployed native build derived from that seed. The same
//! fork reproduces the deployed `wasm32` draw on any target through
//! `Uint::random_mod_with_word_width` with `RandomModWordWidth::ThirtyTwo`. The tests below
//! pin both against the digests captured on the deployed builds.

use crypto_bigint::{NonZero, Uint};
use crypto_bigint_legacy::RandomMod;
use rand_chacha::ChaCha20Rng;

use crate::SeedableRng;

/// A fresh ChaCha20 RNG seeded with the 32-byte `seed`, with nothing drawn from it yet:
/// `ChaCha20Rng::from_seed(seed)`, which is how the deployed callers built their RNG from the
/// seed they derived from a root seed. The RNG every legacy entry point draws from.
///
/// This RNG is part of what the legacy pathway reproduces. A future breaking change to
/// `ChaCha20Rng` (its stream, its seeding, or its rand_core traits) must be met by pinning
/// rand_chacha to the last compatible version, 0.9.0, as a second crate used only here, never
/// by updating this function to the changed version; see the module documentation.
pub fn legacy_seeded_rng(seed: [u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed)
}

/// Sample uniformly below `modulus` exactly as the deployed revision of crypto-bigint did:
/// its own `Uint::random_mod`, run in that crate, drawing whole machine words from `rng`.
///
/// Use this only on a pathway that must reproduce a value sampled in the past, with an RNG
/// from [`legacy_seeded_rng`]. Fresh randomness should use the current crypto-bigint sampler.
/// Not compatible between 32-bit and 64-bit targets; see the module documentation.
pub fn legacy_random_mod<const LIMBS: usize>(
    rng: &mut ChaCha20Rng,
    modulus: &NonZero<Uint<LIMBS>>,
) -> Uint<LIMBS> {
    // Both crypto-bigint crates use the same machine word on a given target, so the words
    // carry over.
    let legacy_modulus = crypto_bigint_legacy::NonZero::new(
        crypto_bigint_legacy::Uint::<LIMBS>::from_words(*modulus.as_words()),
    )
    .unwrap();
    let value = crypto_bigint_legacy::Uint::<LIMBS>::random_mod(rng, &legacy_modulus);

    Uint::<LIMBS>::from_words(*value.as_words())
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{
        Limb, NonZero, RandomBits, RandomMod, RandomModWordWidth, Uint, U1024, U128, U2048, U256,
        U4096, U512, U64,
    };
    use rand_core::RngCore;
    use sha2::{Digest, Sha256};

    use super::{legacy_random_mod, legacy_seeded_rng};

    // Captured with the deployed fork revision 8aabcee5 and rand_chacha 0.9.0 on native 64-bit.
    const DEPLOYED_NATIVE_DIGEST: [u8; 32] = [
        228, 113, 111, 117, 78, 145, 145, 50, 15, 197, 158, 157, 169, 56, 24, 57, 0, 174, 105, 21,
        171, 55, 182, 49, 132, 242, 87, 248, 87, 246, 174, 75,
    ];

    // Captured with the same code on a real wasm32 build (32-bit draws).
    const DEPLOYED_WASM32_DIGEST: [u8; 32] = [
        116, 128, 55, 67, 39, 200, 115, 213, 49, 105, 21, 89, 141, 75, 95, 97, 14, 145, 178, 50,
        128, 49, 138, 152, 101, 127, 154, 13, 130, 88, 220, 222,
    ];

    /// The word width the deployed sampler used on this target.
    const DEPLOYED_WIDTH: RandomModWordWidth = if Limb::BITS == 64 {
        RandomModWordWidth::SixtyFour
    } else {
        RandomModWordWidth::ThirtyTwo
    };

    const MODULI: [U256; 8] = [
        U256::ONE,
        U256::from_u8(42),
        U256::from_u64(u64::MAX),
        U256::ONE.shl_vartime(64),
        U256::ONE.shl_vartime(65).wrapping_add(&U256::ONE),
        U256::ONE.shl_vartime(128),
        U256::ONE.shl_vartime(255),
        U256::MAX,
    ];

    fn transcript_digest() -> [u8; 32] {
        let mut digest = Sha256::new();
        for seed in [0u8, 1, 42, 255] {
            for modulus in MODULI {
                let modulus = NonZero::new(modulus).unwrap();
                let mut rng = legacy_seeded_rng([seed; 32]);
                for _ in 0..100 {
                    digest.update(legacy_random_mod(&mut rng, &modulus).to_le_bytes());
                    digest.update(rng.next_u64().to_le_bytes());
                }
            }
        }
        digest.finalize().into()
    }

    /// The same transcript drawn through the workspace crypto-bigint, with the given word width.
    fn workspace_transcript_digest(width: RandomModWordWidth) -> [u8; 32] {
        let mut digest = Sha256::new();
        for seed in [0u8, 1, 42, 255] {
            for modulus in MODULI {
                let modulus = NonZero::new(modulus).unwrap();
                let mut rng = legacy_seeded_rng([seed; 32]);
                for _ in 0..100 {
                    digest.update(
                        U256::random_mod_with_word_width(&mut rng, &modulus, width).to_le_bytes(),
                    );
                    digest.update(rng.next_u64().to_le_bytes());
                }
            }
        }
        digest.finalize().into()
    }

    // The legacy pathway: the pinned revision reproduces the deployed draw of this target. If
    // the pinned revision or the RNG stream ever changes behaviour, this fails.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn matches_deployed_native_values_and_rng_state() {
        assert_eq!(transcript_digest(), DEPLOYED_NATIVE_DIGEST);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn matches_deployed_wasm32_values_and_rng_state() {
        assert_eq!(transcript_digest(), DEPLOYED_WASM32_DIGEST);
    }

    // The production sampler draws the deployed native values on every target, and leaves the
    // RNG in the deployed state after each draw. No target guard: this must hold on native and
    // on wasm32 alike.
    #[test]
    fn workspace_sampler_matches_deployed_native_values_and_rng_state() {
        assert_eq!(
            workspace_transcript_digest(RandomModWordWidth::SixtyFour),
            DEPLOYED_NATIVE_DIGEST
        );
    }

    // `random_mod` is the 64-bit draw: the same transcript through the trait method.
    #[test]
    fn workspace_random_mod_is_the_sixty_four_bit_draw() {
        let mut digest = Sha256::new();
        for seed in [0u8, 1, 42, 255] {
            for modulus in MODULI {
                let modulus = NonZero::new(modulus).unwrap();
                let mut rng = legacy_seeded_rng([seed; 32]);
                for _ in 0..100 {
                    digest.update(U256::random_mod(&mut rng, &modulus).to_le_bytes());
                    digest.update(rng.next_u64().to_le_bytes());
                }
            }
        }
        let digest: [u8; 32] = digest.finalize().into();
        assert_eq!(digest, DEPLOYED_NATIVE_DIGEST);
    }

    // The 32-bit variant draws the deployed wasm32 values on every target.
    #[test]
    fn thirty_two_bit_sampler_matches_deployed_wasm32_values_and_rng_state() {
        assert_eq!(
            workspace_transcript_digest(RandomModWordWidth::ThirtyTwo),
            DEPLOYED_WASM32_DIGEST
        );
    }

    /// Draws `count` values below `modulus` through the workspace sampler at this target's
    /// deployed width and through the pinned revision, from identical RNG streams, asserting
    /// equal values and an equal RNG state after each draw.
    fn assert_matches_pinned_crate<const LIMBS: usize>(
        modulus: Uint<LIMBS>,
        seed: u8,
        count: usize,
    ) {
        let modulus = NonZero::new(modulus).unwrap();
        let mut rng = legacy_seeded_rng([seed; 32]);
        let mut pinned_rng = legacy_seeded_rng([seed; 32]);
        for _ in 0..count {
            let value =
                Uint::<LIMBS>::random_mod_with_word_width(&mut rng, &modulus, DEPLOYED_WIDTH);
            let pinned = legacy_random_mod(&mut pinned_rng, &modulus);
            assert_eq!(value, pinned);
            assert!(value < *modulus);
            assert_eq!(rng.next_u64(), pinned_rng.next_u64());
        }
    }

    /// Checks fixed edge moduli and one random modulus of every bit length, so that every
    /// top-word mask width occurs.
    fn check_every_modulus<const LIMBS: usize>(seed: u8, count: usize) {
        let fixed = [
            Uint::<LIMBS>::ONE,
            Uint::<LIMBS>::from(42u8),
            Uint::<LIMBS>::from(u32::MAX),
            Uint::<LIMBS>::from(u64::MAX),
            Uint::<LIMBS>::ONE.shl_vartime(32),
            Uint::<LIMBS>::ONE.shl_vartime(33).wrapping_add(&Uint::ONE),
            Uint::<LIMBS>::ONE.shl_vartime(Uint::<LIMBS>::BITS - 1),
            Uint::<LIMBS>::MAX,
        ];
        for modulus in fixed {
            assert_matches_pinned_crate(modulus, seed, count);
        }
        let mut rng = legacy_seeded_rng([seed ^ 0xA5; 32]);
        for bits in 1..=Uint::<LIMBS>::BITS {
            let modulus = Uint::<LIMBS>::random_bits(&mut rng, bits)
                | Uint::<LIMBS>::ONE.shl_vartime(bits - 1);
            assert_matches_pinned_crate(modulus, seed, count);
        }
    }

    // On this target, the workspace sampler at the deployed width equals the pinned deployed
    // revision for every modulus bit length at every integer size the workspace uses. On native
    // this checks the 64-bit path, on wasm32 the 32-bit path.
    #[test]
    fn workspace_sampler_matches_the_pinned_crate_on_this_target() {
        check_every_modulus::<{ U64::LIMBS }>(1, 8);
        check_every_modulus::<{ U128::LIMBS }>(2, 8);
        check_every_modulus::<{ U256::LIMBS }>(3, 8);
        check_every_modulus::<{ U512::LIMBS }>(4, 4);
        check_every_modulus::<{ U1024::LIMBS }>(5, 2);
        check_every_modulus::<{ U2048::LIMBS }>(6, 2);
        check_every_modulus::<{ U4096::LIMBS }>(7, 1);
    }
}
