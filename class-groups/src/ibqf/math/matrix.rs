// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
//
// The contents of this file were adapted from the `ruint` library, licensed under MIT.
// Ref: [ruint](https://github.com/recmo/uint/tree/898a955).

use std::mem;

use crypto_bigint::{Uint, U64};

/// Lehmer update matrix
///
/// Signs are implicit, the boolean `.4` encodes which of two sign
/// patterns applies. The signs and layout of the matrix are:
///
/// ```text
///     true          false
///  [ .0  -.1]    [-.0   .1]
///  [-.2   .3]    [ .2  -.3]
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Matrix<const LIMBS: usize>(
    pub Uint<LIMBS>,
    pub Uint<LIMBS>,
    pub Uint<LIMBS>,
    pub Uint<LIMBS>,
    pub bool,
);

impl<const LIMBS: usize> Matrix<LIMBS> {
    pub const IDENTITY: Self = Self(Uint::ONE, Uint::ZERO, Uint::ZERO, Uint::ONE, true);

    /// Perform matrix-vector multiplication
    ///
    /// ```text
    /// ⌈ .0 .1 ⌉ ⌈ a ⌉
    /// ⌊ .2 .3 ⌋ ⌊ b ⌋
    ///```
    #[inline]
    pub fn apply<const RHS_LIMBS: usize>(&self, a: &mut Uint<RHS_LIMBS>, b: &mut Uint<RHS_LIMBS>) {
        let (c, d) = if self.4 {
            (
                a.wrapping_mul(&self.0)
                    .wrapping_sub(&b.wrapping_mul(&self.1)),
                b.wrapping_mul(&self.3)
                    .wrapping_sub(&a.wrapping_mul(&self.2)),
            )
        } else {
            (
                b.wrapping_mul(&self.1)
                    .wrapping_sub(&a.wrapping_mul(&self.0)),
                a.wrapping_mul(&self.2)
                    .wrapping_sub(&b.wrapping_mul(&self.3)),
            )
        };
        *a = c;
        *b = d;
    }

    /// Left multiply `self` with the upper triangular matrix whose top-right element is `-q` and
    /// store the result in `self`.
    ///
    /// In other words, perform the multiplication
    /// ```text
    /// ⌈  1 -q ⌉ ⌈ .0 .1 ⌉
    /// ⌊  0  1 ⌋ ⌊ .2 .3 ⌋
    /// ```
    pub fn left_mul_upper_triangular<const FACTOR_LIMBS: usize>(&mut self, q: Uint<FACTOR_LIMBS>) {
        self.0 = self.0.wrapping_add(&self.2.wrapping_mul(&q));
        self.1 = self.1.wrapping_add(&self.3.wrapping_mul(&q));
    }

    /// Multiply `self` and `rhs`, storing the result in `rhs`.
    #[inline]
    pub fn mul<const RHS_LIMBS: usize>(&self, rhs: &mut Matrix<RHS_LIMBS>) {
        (rhs.0, rhs.1, rhs.2, rhs.3) = (
            rhs.0
                .wrapping_mul(&self.0)
                .wrapping_add(&rhs.2.wrapping_mul(&self.1)),
            rhs.1
                .wrapping_mul(&self.0)
                .wrapping_add(&rhs.3.wrapping_mul(&self.1)),
            rhs.0
                .wrapping_mul(&self.2)
                .wrapping_add(&rhs.2.wrapping_mul(&self.3)),
            rhs.1
                .wrapping_mul(&self.2)
                .wrapping_add(&rhs.3.wrapping_mul(&self.3)),
        );
        rhs.4 = self.4 == rhs.4;
    }

    /// Swap the rows of this matrix
    #[inline]
    pub fn swap_rows(&mut self) {
        mem::swap(&mut self.0, &mut self.2);
        mem::swap(&mut self.1, &mut self.3);
        self.4 = !self.4;
    }

    /// Whether this matrix has a positive determinant.
    #[inline]
    pub fn has_positive_determinant(&self) -> bool {
        self.4
    }

    /// Returns the `adjoint` matrix of `self`, deconstructed into the absolute values of the
    /// adjoint matrix, and a `bool` indicating whether all the values in the adjoint are
    /// non-negative.
    #[inline]
    pub fn adjoint(&self) -> ((Uint<LIMBS>, Uint<LIMBS>, Uint<LIMBS>, Uint<LIMBS>), bool) {
        let all_matrix_values_are_non_negative = self.has_positive_determinant();
        (
            (self.3, self.1, self.2, self.0),
            all_matrix_values_are_non_negative,
        )
    }
}

impl Matrix<{ U64::LIMBS }> {
    pub(crate) fn new(m00: u64, m01: u64, m10: u64, m11: u64, pattern: bool) -> Self {
        Matrix(
            U64::from(m00),
            U64::from(m01),
            U64::from(m10),
            U64::from(m11),
            pattern,
        )
    }

    /// Compute a Lehmer update matrix from two `Uint`s.
    ///
    /// # Panics
    ///
    /// Panics if `b > a`.
    #[inline]
    #[must_use]
    pub fn from<const RHS_LIMBS: usize>(a: &Uint<RHS_LIMBS>, b: &Uint<RHS_LIMBS>) -> Self {
        debug_assert!(a >= b);

        // Grab the first 64 bits.
        let s = a.bits_vartime();
        if s <= 64 {
            Self::from_u64(
                a.resize::<{ U64::LIMBS }>().into(),
                b.resize::<{ U64::LIMBS }>().into(),
            )
        } else {
            let offset = s.saturating_sub(64);
            let a = a.shr_vartime(offset).resize::<{ U64::LIMBS }>();
            let b = b.shr_vartime(offset).resize::<{ U64::LIMBS }>();
            Self::from_u64_prefix(a.into(), b.into())
        }
    }

    /// Compute the Lehmer update matrix for small values.
    ///
    /// This is essentially Euclids extended GCD algorithm for 64 bits.
    ///
    /// # Panics
    ///
    /// Panics if `r0 < r1`.
    #[inline]
    #[must_use]
    pub fn from_u64(mut r0: u64, mut r1: u64) -> Self {
        debug_assert!(r0 >= r1);
        if r1 == 0_u64 {
            return Matrix::IDENTITY;
        }
        let mut q00 = 1_u64;
        let mut q01 = 0_u64;
        let mut q10 = 0_u64;
        let mut q11 = 1_u64;
        loop {
            // Loop is unrolled once to avoid swapping variables and tracking parity.
            let q = r0 / r1;
            r0 -= q * r1;
            q00 += q * q10;
            q01 += q * q11;
            if r0 == 0_u64 {
                return Matrix::new(q10, q11, q00, q01, false);
            }
            let q = r1 / r0;
            r1 -= q * r0;
            q10 += q * q00;
            q11 += q * q01;
            if r1 == 0_u64 {
                return Matrix::new(q00, q01, q10, q11, true);
            }
        }
    }

    /// Compute the largest valid Lehmer update matrix for a prefix.
    ///
    /// Compute the Lehmer update matrix for a0 and a1 such that the matrix is
    /// valid for any two large integers starting with the bits of a0 and
    /// a1.
    ///
    /// See also `mpn_hgcd2` in GMP, but ours handles the double precision bit
    /// separately in `lehmer_double`.
    /// <https://gmplib.org/repo/gmp-6.1/file/tip/mpn/generic/hgcd2.c#l226>
    ///
    /// # Panics
    ///
    /// Panics if
    /// - `a0` does not have the highest bit set, or
    /// - `a0 < a1`.
    #[inline]
    #[must_use]
    #[allow(clippy::redundant_else)]
    #[allow(clippy::cognitive_complexity)] // REFACTOR: Improve
    pub fn from_u64_prefix(a0: u64, mut a1: u64) -> Self {
        debug_assert!(a0 >= 1_u64 << 63);
        debug_assert!(a0 >= a1);

        const LIMIT: u64 = 1_u64 << 32;
        if a1 < LIMIT {
            return Matrix::IDENTITY;
        }

        // Here we do something original: The cofactors undergo identical
        // operations which makes them a candidate for SIMD instructions.
        // They also never exceed 32 bit, so we can SWAR them in a single u64.
        let mut k0 = 1_u64 << 32; // u0 = 1, v0 = 0
        let mut k1 = 1_u64; // u1 = 0, v1 = 1
        let mut even = true;

        // Compute a2
        let q = a0 / a1;
        let mut a2 = a0 - q * a1;
        let mut k2 = k0 + q * k1;
        if a2 < LIMIT {
            let u2 = k2 >> 32;
            let v2 = k2 % LIMIT;

            // Test i + 1 (odd)
            if a2 >= v2 && a1 - a2 >= u2 {
                return Matrix::new(0, 1, u2, v2, false);
            } else {
                return Matrix::IDENTITY;
            }
        }

        // Compute a3
        let q = a1 / a2;
        let mut a3 = a1 - q * a2;
        let mut k3 = k1 + q * k2;

        // Loop until a3 < LIMIT, maintaining the last three values
        // of a and the last four values of k.
        while a3 >= LIMIT {
            a1 = a2;
            a2 = a3;
            a3 = a1;
            k0 = k1;
            k1 = k2;
            k2 = k3;
            k3 = k1;
            debug_assert!(a2 < a3);
            debug_assert!(a2 > 0);
            let q = a3 / a2;
            a3 -= q * a2;
            k3 += q * k2;
            if a3 < LIMIT {
                even = false;
                break;
            }

            a1 = a2;
            a2 = a3;
            a3 = a1;
            k0 = k1;
            k1 = k2;
            k2 = k3;
            k3 = k1;
            debug_assert!(a2 < a3);
            debug_assert!(a2 > 0);
            let q = a3 / a2;
            a3 -= q * a2;
            k3 += q * k2;
        }
        // Unpack k into cofactors u and v
        let u0 = k0 >> 32;
        let u1 = k1 >> 32;
        let u2 = k2 >> 32;
        let u3 = k3 >> 32;
        let v0 = k0 % LIMIT;
        let v1 = k1 % LIMIT;
        let v2 = k2 % LIMIT;
        let v3 = k3 % LIMIT;
        debug_assert!(a2 >= LIMIT);
        debug_assert!(a3 < LIMIT);

        // Use Jebelean's exact condition to determine which outputs are correct.
        // Statistically, i + 2 should be correct about two-thirds of the time.
        if even {
            // Test i + 1 (odd)
            debug_assert!(a2 >= v2);
            if a1 - a2 >= u2 + u1 {
                // Test i + 2 (even)
                if a3 >= u3 && a2 - a3 >= v3 + v2 {
                    // Correct value is i + 2
                    Matrix::new(u2, v2, u3, v3, true)
                } else {
                    // Correct value is i + 1
                    Matrix::new(u1, v1, u2, v2, false)
                }
            } else {
                // Correct value is i
                Matrix::new(u0, v0, u1, v1, true)
            }
        } else {
            // Test i + 1 (even)
            debug_assert!(a2 >= u2);
            if a1 - a2 >= v2 + v1 {
                // Test i + 2 (odd)
                if a3 >= v3 && a2 - a3 >= u3 + u2 {
                    // Correct value is i + 2
                    Matrix::new(u2, v2, u3, v3, false)
                } else {
                    // Correct value is i + 1
                    Matrix::new(u1, v1, u2, v2, true)
                }
            } else {
                // Correct value is i
                Matrix::new(u0, v0, u1, v1, false)
            }
        }
    }
}
