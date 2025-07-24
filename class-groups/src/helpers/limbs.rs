// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{Limb, Uint};

/// Calculate the number of leading zero limbs in the binary representation of this number in
/// variable-time with respect to `limbs`.
#[inline(always)]
pub(crate) const fn leading_zero_limbs_vartime(limbs: &[Limb]) -> usize {
    let mut count = 0;
    let mut i = limbs.len();
    while i > 0 {
        i -= 1;
        if limbs[i].0 != 0 {
            return count;
        }
        count += 1;
    }
    count
}

pub(crate) trait Limbs: Sized {
    /// Calculate the minimal number of limbs needed to represent this number.
    /// Executes in variable-time with respect to `self`.
    fn limbs_vartime(&self) -> usize;
}

impl<const LIMBS: usize> Limbs for Uint<LIMBS> {
    fn limbs_vartime(&self) -> usize {
        LIMBS - leading_zero_limbs_vartime(self.as_limbs())
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::U256;

    use crate::helpers::limbs::Limbs;

    #[test]
    fn test_limbs_vartime() {
        assert_eq!(U256::ZERO.limbs_vartime(), 0);
        assert_eq!(U256::ONE.limbs_vartime(), 1);
        assert_eq!(U256::ONE.shl(127).limbs_vartime(), U256::LIMBS / 2);
        assert_eq!(U256::MAX.limbs_vartime(), U256::LIMBS);
    }
}
