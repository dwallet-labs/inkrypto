// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::Sub;

use crypto_bigint::subtle::ConstantTimeLess;
use crypto_bigint::ConstantTimeSelect;
use sha3::{Digest, Sha3_256};

pub(crate) mod limbs;
pub(crate) mod lookup;
pub(crate) mod math;
pub(crate) mod partial_xgcd;
pub(crate) mod vartime_div;
pub(crate) mod vartime_mul;

/// Compute the `SHA3-256` hash of a byte sequence.
pub(crate) fn sha3_256_hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub trait CtMinMax: ConstantTimeSelect + ConstantTimeLess + Sub<Output = Self> {
    /// Compute the minimum of `self` and `other` in constant time.
    fn ct_min(&self, other: &Self) -> Self {
        Self::ct_select(other, self, self.ct_lt(other))
    }

    /// Compute the maximum of `self` and `other` in constant time.
    fn ct_max(&self, other: &Self) -> Self {
        Self::ct_select(self, other, self.ct_lt(other))
    }

    /// Compute the absolute difference between `self` and `other` in constant time.
    fn ct_abs_diff(&self, other: &Self) -> Self {
        Self::ct_max(self, other) - Self::ct_min(self, other)
    }
}

impl CtMinMax for u32 {}
