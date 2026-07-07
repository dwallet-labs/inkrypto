// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use rand::Rng;
use rand_chacha::{ChaCha20Core, ChaCha20Rng};
use rand_core::SeedableRng;

use crate::CsRng;

/// A seedable collection.
pub trait SeedableCollection<T>: IntoIterator<Item = T> {
    /// Seed a collection with a unique `ChaCha20Rng` per-item.
    /// Useful for working with `rayon` and parallelism, where `rng` cannot be shared between threads,
    /// but each individual rng can be used for that thread normally.
    fn seed(self, rng: &mut impl CsRng) -> Vec<(T, ChaCha20Rng)>;
}

impl<T, I: IntoIterator<Item = T>> SeedableCollection<T> for I {
    fn seed(self, rng: &mut impl CsRng) -> Vec<(T, ChaCha20Rng)> {
        self.into_iter()
            .map(|item| {
                let seed = rng.random();

                let seeded_rng = ChaCha20Rng::from(ChaCha20Core::from_seed(seed));

                (item, seeded_rng)
            })
            .collect()
    }
}
