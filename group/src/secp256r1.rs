// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::U256;
pub use group_element::GroupElement;
use p256::{elliptic_curve::Curve, NistP256};
pub use scalar::Scalar;

pub mod group_element;
pub mod scalar;

pub const SCALAR_LIMBS: usize = U256::LIMBS;

/// The order `q` of the secp256r1 group
pub const ORDER: U256 = *<NistP256 as Curve>::ORDER.as_ref();
/// The modulus `p` of the secp256r1 group
/// p = 2^{224}(2^{32} − 1) + 2^{192} + 2^{96} − 1
pub const MODULUS: U256 =
    U256::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

// Any Weierstrass elliptic curve can be represented as an equation in the following template:
// $y^2 = x^3 + ax^ + b mod(p)$.
// For secp256r1 specifically, $a = -3$, yielding the equation
// $y^2 = x^3 − 3x + b mod(p)$.
pub const CURVE_EQUATION_A: U256 =
    U256::from_be_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
pub const CURVE_EQUATION_B: U256 =
    U256::from_be_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
