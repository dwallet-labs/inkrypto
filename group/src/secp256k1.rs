// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::U256;
pub use group_element::GroupElement;
pub use scalar::Scalar;

pub mod group_element;
pub mod scalar;

pub const SCALAR_LIMBS: usize = U256::LIMBS;

/// The order `q` of the secp256k1 group.
///
/// TEMPORARY (two crypto-bigint versions): written as a literal because k256's
/// `<Secp256k1 as Curve>::ORDER` is a `U256` of k256's own crypto-bigint 0.7.5, which to the
/// compiler is a different type from our rc.9 `U256`. The test at the bottom of this file checks
/// the literal against the crate's constant byte for byte. Revert to
/// `*<Secp256k1 as Curve>::ORDER.as_ref()`, and delete that test, once both are one crate.
pub const ORDER: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
/// The modulus `p` of the secp256k1 group
pub const MODULUS: U256 =
    U256::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

// Any Weierstrass elliptic curve can be represented as an equation in the following template:
// $y^2 = x^3 + ax^ + b mod(p)$.
// For secp256k1 specifically, $a = 0$ and $b = 7$, yielding the equation
// $y^2 = x^3 + 7 mod(p)$.
pub const CURVE_EQUATION_A: U256 = U256::ZERO;
pub const CURVE_EQUATION_B: U256 =
    U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000007");

#[cfg(test)]
mod tests {
    use k256::{elliptic_curve::Curve, Secp256k1};

    use super::ORDER;

    /// TEMPORARY (two crypto-bigint versions): guards the literal `ORDER` above; delete with it.
    #[test]
    fn order_matches_the_curve_crate() {
        let theirs: [u8; 32] = <Secp256k1 as Curve>::ORDER.as_ref().to_be_bytes().into();
        assert_eq!(ORDER.to_be_bytes(), theirs);
    }
}
