// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use sha3::{Digest, Sha3_256};

pub(crate) mod lookup;
pub(crate) mod math;

/// Compute the `SHA3-256` hash of a byte sequence.
pub(crate) fn sha3_256_hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
