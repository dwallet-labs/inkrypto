// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::Mul;

use crypto_bigint::{ConstChoice, Limb, Uint};

/// The matrix representation used in the partial extended gcd algorithm.
///
/// Instead of using Ints to represent the internal state, this matrix uses [Uint]s and a
/// [ConstChoice] indicating the pattern of the signs in the matrix. This is because during the
/// execution of the partial extended gcd algorithm, the signs of the elements in the matrix
/// always adhere to one of the following two patterns:
/// ```text
///   true            false
/// [ + - ]          [ - + ]
/// [ - + ]    or    [ + - ]
/// ```
/// The `pattern` attribute indicates which of the two patterns is active.
///
/// Secondly, the determinant of this matrix is always `+/- 1`. The `pattern` attribute moreover
/// indicates whether the sign of this determinant is `1` (`true`) or `-1` (`false`).
#[derive(Debug, PartialEq)]
pub struct PxgcdMatrix<const LIMBS: usize> {
    m00: Uint<LIMBS>,
    m01: Uint<LIMBS>,
    m10: Uint<LIMBS>,
    m11: Uint<LIMBS>,
    pattern: ConstChoice,
}

impl<const LIMBS: usize> PxgcdMatrix<LIMBS> {
    /// The unit / identity matrix
    const UNIT: Self = Self {
        m00: Uint::ONE,
        m01: Uint::ZERO,
        m10: Uint::ZERO,
        m11: Uint::ONE,
        pattern: ConstChoice::TRUE,
    };

    /// Construct the adjugate of this matrix.
    ///
    /// Returns the absolute values of the adjugate matrix elements, as well as a `ConstChoice`
    /// indicating the signs of the elements: all four values are negative whenever it is `truthy`.
    ///
    /// Recall that
    /// ```text
    ///     ( [ m00 m01 ] )   [  m11 -m01 ]
    /// Adj ( [ m10 m11 ] ) = [ -m10  m00 ]
    /// ```
    pub const fn adjugate(
        &self,
    ) -> (
        (Uint<LIMBS>, Uint<LIMBS>, Uint<LIMBS>, Uint<LIMBS>),
        ConstChoice,
    ) {
        ((self.m11, self.m01, self.m10, self.m00), self.pattern.not())
    }

    /// Swap the rows of this matrix if `swap` is truthy. Otherwise, do nothing.
    ///
    /// Note: this operation preserves the fact that `det(self) = +/-1`.
    #[inline]
    fn swap_rows_if(&mut self, swap: ConstChoice) {
        Uint::conditional_swap(&mut self.m00, &mut self.m10, swap);
        Uint::conditional_swap(&mut self.m01, &mut self.m11, swap);
        self.pattern = self.pattern.xor(swap);
    }

    /// Subtract the bottom row of this matrix `2^k` times from the top row if `sub` is set.
    /// Otherwise, do nothing.
    ///
    /// In matrix notation, execute
    /// ```text
    /// [ 1 -2^k ] [ m00 m01 ]
    /// [ 0    1 ] [ m10 m11 ]
    /// ```
    /// if `mul.is_true()`, and nothing otherwise.
    ///
    /// Note: this operation preserves the fact that `det(self) = +/-1`.
    #[inline]
    fn conditional_subtract_bottom_row_2k_times_from_top_row(&mut self, k: u32, sub: ConstChoice) {
        // Note: these are additions (and not subtractions like the function name suggests) because
        // of how the sign-information of this matrix is stored in `pattern`.
        self.m00 = Uint::select(&self.m00, &self.m00.wrapping_add(&self.m10.shl(k)), sub);
        self.m01 = Uint::select(&self.m01, &self.m01.wrapping_add(&self.m11.shl(k)), sub);
    }

    /// Subtract the bottom row of this matrix from the top row if `sub` is set.
    /// Otherwise, do nothing.
    ///
    /// Note: this operation preserves the fact that `det(self) = +/-1`.
    #[inline]
    fn conditional_subtract_bottom_row_from_top_row(&mut self, sub: ConstChoice) {
        // Note: these are additions (and not subtractions like the function name suggests) because
        // of how the sign-information of this matrix is stored in `pattern`.
        self.m00 = self
            .m00
            .wrapping_add(&Uint::select(&Uint::ZERO, &self.m10, sub));
        self.m01 = self
            .m01
            .wrapping_add(&Uint::select(&Uint::ZERO, &self.m11, sub));
    }

    /// Multiply the bottom row by `2^k`.
    ///
    /// Note: this operation preserves the fact that `det(self) = +/-1`.
    #[inline]
    fn double_bottom_row_k_times(&mut self, k: u32) {
        self.m10 = self.m10.wrapping_shl(k);
        self.m11 = self.m11.wrapping_shl(k);
    }

    /// Divide the values in the bottom row by `2^k`.
    ///
    /// Note: this operation preserves the fact that `det(self) = +/-1`.
    #[inline]
    fn half_bottom_row_k_times(&mut self, k: u32) {
        // Safe to vartime; is variable only in the shift, which is a constant
        self.m10 = self.m10.wrapping_shr(k);
        self.m11 = self.m11.wrapping_shr(k);
    }

    /// Double the values in the bottom row if `double`, else do nothing
    ///
    /// Note: this operation preserves the fact that `det(self) = +/-1`.
    #[inline]
    fn double_bottom_row_if(&mut self, double: ConstChoice) {
        // Safe to vartime; is variable only in the shift, which is a constant
        self.m10 = Uint::select(&self.m10, &self.m10.overflowing_shl1().0, double);
        self.m11 = Uint::select(&self.m11, &self.m11.overflowing_shl1().0, double);
    }

    /// Divide the values in the bottom row by two if `half`, else do nothing.
    ///
    /// Note: this operation preserves the fact that `det(self) = +/-1`.
    #[inline]
    fn half_bottom_row_if(&mut self, half: ConstChoice) {
        // Safe to vartime; is variable only in the shift, which is a constant
        self.m10 = Uint::select(&self.m10, &self.m10.shr1(), half);
        self.m11 = Uint::select(&self.m11, &self.m11.shr1(), half);
    }
}

pub(crate) trait PartialXGCD: Sized {
    type Matrix;

    #[allow(dead_code)]
    /// Extended GCD-reduce `self` and `rhs` until both can be represented using `threshold` bits.
    fn partial_xgcd(&self, other: &Self, threshold: u32) -> (Self, Self, Self::Matrix);

    /// Extended GCD-reduce `self` and `rhs` until both can be represented using `threshold` bits.
    ///
    /// Executes in variable time with respect to
    /// 1. `bits_upper_bound`: an upper bound on the bit size of `self` and `rhs`, and
    /// 2. `threshold`.
    ///
    /// Note that this algorithm becomes constant time when a static upper `bits_upper_bound` is
    /// passed.
    fn bounded_partial_xgcd(
        &self,
        rhs: &Self,
        bits_upper_bound: u32,
        threshold: u32,
    ) -> (Self, Self, Self::Matrix);

    /// Extended GCD-reduce `self` and `rhs` until both can be represented using `threshold` bits,
    /// where `threshold ≥ threshold_lower_bound`.
    ///
    /// Executes in variable time with respect to
    /// 1. `bits_upper_bound`: an upper bound on the bit size of `self` and `rhs`, and
    /// 2. `threshold_lower_bound`.
    ///
    /// Note that this algorithm becomes constant time when a static upper `bits_upper_bound` is
    /// passed.
    fn bounded_partial_xgcd_with_bounded_threshold(
        &self,
        rhs: &Self,
        bits_upper_bound: u32,
        threshold: u32,
        threshold_lower_bound: u32,
    ) -> (Self, Self, Self::Matrix);

    /// XGCD reduce `self` and `rhs` until both can be represented with `threshold` bits.
    ///
    /// Executes in variable time w.r.t. `threshold`.
    ///
    /// Requires that the most significant bit of `self` and `rhs` is NOT set.
    ///
    /// Assumes `self` and `rhs` to be random elements, i.e., at no point in the process will `a`
    /// and `b` differ more than 63 bits in size.
    #[allow(dead_code)]
    fn partial_xgcd_randomized(
        &self,
        rhs: &Self,
        threshold: u32,
    ) -> (Self, Self, Self::Matrix, u32);

    /// Variation to [Self::partial_xgcd_randomized] that allows one to specify an `upper_bound` on
    /// the bit-sizes of `self` and `rhs`, enabling an execution speed up.
    fn partial_xgcd_bounded_randomized(
        &self,
        rhs: &Self,
        bits_upper_bound: u32,
        threshold: u32,
    ) -> (Self, Self, Self::Matrix, u32);

    /// Variation to [Self::partial_xgcd_bounded_randomized] that allows one to specify a
    /// `threshold_lower_bound` value of `threshold`.
    ///
    /// Executes in variable time w.r.t. `threshold_lower_bound` instead of `threshold`.
    fn partial_xgcd_bounded_randomized_with_bounded_threshold(
        &self,
        rhs: &Self,
        bits_upper_bound: u32,
        threshold: u32,
        threshold_lower_bound: u32,
    ) -> (Self, Self, Self::Matrix, u32);
}

impl<const LIMBS: usize> PartialXGCD for Uint<LIMBS> {
    type Matrix = PxgcdMatrix<LIMBS>;

    fn partial_xgcd(&self, rhs: &Uint<LIMBS>, threshold: u32) -> (Self, Self, Self::Matrix) {
        self.bounded_partial_xgcd(rhs, Uint::<LIMBS>::BITS, threshold)
    }

    fn bounded_partial_xgcd(
        &self,
        rhs: &Uint<LIMBS>,
        bits_upper_bound: u32,
        threshold: u32,
    ) -> (Self, Self, Self::Matrix) {
        self.bounded_partial_xgcd_with_bounded_threshold(
            rhs,
            bits_upper_bound,
            threshold,
            threshold,
        )
    }

    fn bounded_partial_xgcd_with_bounded_threshold(
        &self,
        rhs: &Uint<LIMBS>,
        bits_upper_bound: u32,
        threshold: u32,
        threshold_lower_bound: u32,
    ) -> (Self, Self, Self::Matrix) {
        assert!(bool::from(ConstChoice::from_u32_le(
            threshold_lower_bound,
            threshold
        )));

        let (mut a, mut b) = (*self, *rhs);
        let (mut a_bits, mut b_bits) = (a.bits(), b.bits());
        let mut matrix = PxgcdMatrix::UNIT;

        // Make sure a >= b
        let a_lt_b = Uint::lt(&a, &b);
        Uint::conditional_swap(&mut a, &mut b, a_lt_b);
        a_lt_b.conditional_swap_u32(&mut a_bits, &mut b_bits);
        matrix.swap_rows_if(a_lt_b);

        // TODO: we think we can prove that 7/4 * (upperbound - threshold) + C iterations will
        //  suffice (as long as the gap between upperbound and threshold is large enough?)
        let iterations = bits_upper_bound
            .saturating_sub(threshold_lower_bound)
            .saturating_mul(2)
            .saturating_sub(1);
        let mut i = 0;
        while i < iterations {
            i += 1;

            debug_assert!(a >= b);
            let loop_is_active = ConstChoice::from_u32_lt(threshold, a_bits);

            // Find the largest k such that a >= b*2^k
            let mut k = a_bits - b_bits;
            let mut b_2k = b.shl(k);
            let overshoot = Uint::gt(&b_2k, &a);
            k -= overshoot.select_u32(0, 1);
            b_2k = Uint::select(&b_2k, &b_2k.shr_vartime(1), overshoot);

            // Subtract b*2^k from a
            a = Uint::select(&a, &a.wrapping_sub(&b_2k), loop_is_active);
            matrix.conditional_subtract_bottom_row_2k_times_from_top_row(k, loop_is_active);
            a_bits = a.bits();

            // Make sure a >= b
            let a_lt_b = Uint::lt(&a, &b);
            Uint::conditional_swap(&mut a, &mut b, a_lt_b);
            a_lt_b.conditional_swap_u32(&mut a_bits, &mut b_bits);
            matrix.swap_rows_if(a_lt_b);
        }

        // Make sure the matrix has a positive determinant
        Uint::conditional_swap(&mut a, &mut b, matrix.pattern.not());
        matrix.swap_rows_if(matrix.pattern.not());

        (a, b, matrix)
    }

    fn partial_xgcd_randomized(
        &self,
        rhs: &Uint<LIMBS>,
        threshold: u32,
    ) -> (Self, Self, Self::Matrix, u32) {
        Self::partial_xgcd_bounded_randomized(self, rhs, Uint::<LIMBS>::BITS, threshold)
    }

    fn partial_xgcd_bounded_randomized(
        &self,
        rhs: &Uint<LIMBS>,
        bits_upper_bound: u32,
        threshold: u32,
    ) -> (Self, Self, Self::Matrix, u32) {
        self.partial_xgcd_bounded_randomized_with_bounded_threshold(
            rhs,
            bits_upper_bound,
            threshold,
            threshold,
        )
    }

    fn partial_xgcd_bounded_randomized_with_bounded_threshold(
        &self,
        rhs: &Uint<LIMBS>,
        bits_upper_bound: u32,
        threshold: u32,
        threshold_lower_bound: u32,
    ) -> (Self, Self, Self::Matrix, u32) {
        assert!(bool::from(ConstChoice::from_u32_le(
            threshold_lower_bound,
            threshold
        )));

        // TODO: deal with situations where a and b have their top bit set
        assert!(self.as_int().is_negative().not().to_bool_vartime());
        assert!(rhs.as_int().is_negative().not().to_bool_vartime());

        let (mut a, mut b) = (*self, *rhs);
        let mut matrix = PxgcdMatrix::UNIT;

        // Make sure a >= b
        let a_lt_b = Uint::lt(&a, &b);
        Uint::conditional_swap(&mut a, &mut b, a_lt_b);
        matrix.swap_rows_if(a_lt_b);

        // Loop invariant: c = b · 2^k
        let mut k = a.bits() - b.bits();
        let mut c = b.shl(k);
        matrix.double_bottom_row_k_times(k);

        let threshold_mask = Uint::<LIMBS>::MAX
            .shr_vartime(Uint::<LIMBS>::BITS.saturating_sub(threshold))
            .not();
        let iterations = bits_upper_bound
            .saturating_sub(threshold_lower_bound)
            .mul(12)
            .div_ceil(5);
        for _ in 0..iterations {
            // Only perform an action when ||a|| > threshold and b ≠ 0.
            let a_bits_gt_threshold = a.bitand(&threshold_mask).is_nonzero();
            let b_bits_gt_threshold = b.bitand(&threshold_mask).is_nonzero();
            let alive = a_bits_gt_threshold.or(b_bits_gt_threshold);

            let (a_sub_c, borrow) = a.borrowing_sub(&c, Limb::ZERO);
            let c_lte_a = ConstChoice::from_word_mask(borrow.0).not();

            let half_c = c.shr1();
            // note: this does not overflow, as neither a nor b has its top bit set at this point.
            let (double_c, _) = c.overflowing_shl1();
            let double_c_lte_a = Uint::lte(&double_c, &a);

            // Subtract c from a when a ∈ [c, 2c)
            let subtract_c_from_a = c_lte_a.and(double_c_lte_a.not()).and(alive);
            a = Uint::select(&a, &a_sub_c, subtract_c_from_a);
            matrix.conditional_subtract_bottom_row_from_top_row(subtract_c_from_a);

            // c = b · 2^k, so c > b iff k > 0
            let c_gt_b = ConstChoice::from_u32_nonzero(k);

            // c <- { 2·c if 2c ≤ a
            //      { c/2 if 2c > a (as long as c > b)
            let do_double = double_c_lte_a.and(alive);
            c = Uint::select(&half_c, &double_c, do_double);
            k = do_double.select_u32(k, k.saturating_add(1));
            matrix.double_bottom_row_if(do_double);
            let do_half = double_c_lte_a.not().and(c_gt_b).and(alive);
            k = do_half.select_u32(k, k.saturating_sub(1));
            matrix.half_bottom_row_if(do_half);

            // Swap a and b whenever k=0
            let do_swap = ConstChoice::from_u32_nonzero(k).not().and(alive);
            Uint::conditional_swap(&mut a, &mut b, do_swap);
            matrix.swap_rows_if(do_swap);
            c = Uint::select(&c, &b, do_swap);
        }
        matrix.half_bottom_row_k_times(k);

        // Make sure the matrix has a positive determinant
        Uint::conditional_swap(&mut a, &mut b, matrix.pattern.not());
        matrix.swap_rows_if(matrix.pattern.not());

        (a, b, matrix, iterations)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{ConstChoice, Uint};

    use crate::helpers::partial_xgcd::PxgcdMatrix;

    type Vector<const LIMBS: usize> = (Uint<LIMBS>, Uint<LIMBS>);

    impl<const LIMBS: usize> PxgcdMatrix<LIMBS> {
        /// Construct a [PxgcdMatrix].
        const fn new(
            m00: Uint<LIMBS>,
            m01: Uint<LIMBS>,
            m10: Uint<LIMBS>,
            m11: Uint<LIMBS>,
            pattern: ConstChoice,
        ) -> Self {
            Self {
                m00,
                m01,
                m10,
                m11,
                pattern,
            }
        }

        /// Wrapping apply this matrix to `vector` and return the result.
        fn wrapping_apply(&self, vector: Vector<LIMBS>) -> Vector<LIMBS> {
            let (a, b) = vector;
            (
                self.m00
                    .wrapping_mul(&a)
                    .wrapping_sub(&self.m01.wrapping_mul(&b))
                    .wrapping_neg_if(self.pattern.not()),
                self.m10
                    .wrapping_mul(&a)
                    .wrapping_sub(&self.m11.wrapping_mul(&b))
                    .wrapping_neg_if(self.pattern),
            )
        }
    }

    mod test_pxgcd_matrix {
        use crypto_bigint::{ConstChoice, Uint, U64};

        use crate::helpers::partial_xgcd::PxgcdMatrix;

        const MATRIX: PxgcdMatrix<{ U64::LIMBS }> = PxgcdMatrix::new(
            Uint::from_u64(3u64),
            Uint::from_u64(2u64),
            Uint::ONE,
            Uint::ZERO,
            ConstChoice::TRUE,
        );

        #[test]
        fn test_swap() {
            let mut matrix = MATRIX;
            matrix.swap_rows_if(ConstChoice::FALSE);
            assert_eq!(matrix, MATRIX);

            matrix.swap_rows_if(ConstChoice::TRUE);
            assert_eq!(
                matrix,
                PxgcdMatrix::new(
                    Uint::ONE,
                    Uint::ZERO,
                    Uint::from(3u64),
                    Uint::from(2u64),
                    ConstChoice::FALSE
                )
            );
        }

        #[test]
        fn test_conditional_upper_triangular_left_mul() {
            let mut matrix = MATRIX;
            matrix.conditional_subtract_bottom_row_2k_times_from_top_row(1, ConstChoice::FALSE);
            assert_eq!(matrix, MATRIX);

            matrix.conditional_subtract_bottom_row_2k_times_from_top_row(1, ConstChoice::TRUE);
            assert_eq!(
                matrix,
                PxgcdMatrix::new(
                    Uint::from(5u64),
                    Uint::from(2u64),
                    Uint::ONE,
                    Uint::ZERO,
                    ConstChoice::TRUE
                )
            );
        }

        #[test]
        fn test_apply() {
            let matrix = PxgcdMatrix::new(
                U64::from(8u64),
                U64::from(2u64),
                U64::from(3u64),
                U64::from(7u64),
                ConstChoice::TRUE,
            );
            let (a, b) = (U64::from(55u64), U64::from(61u64));
            let (a, b) = matrix.wrapping_apply((a, b));
            assert_eq!(a, U64::from(318u64));
            assert_eq!(b, U64::from(262u64));
        }

        #[test]
        fn test_adjugate() {
            let mut x = MATRIX;
            let (matrix, sign) = x.adjugate();
            assert_eq!(
                matrix,
                (
                    Uint::ZERO,
                    Uint::from_u64(2u64),
                    Uint::ONE,
                    Uint::from_u64(3u64)
                ),
            );
            assert_eq!(sign, ConstChoice::FALSE);

            x.swap_rows_if(ConstChoice::TRUE);
            let (matrix, sign) = x.adjugate();
            assert_eq!(
                matrix,
                (
                    Uint::from_u64(2u64),
                    Uint::ZERO,
                    Uint::from_u64(3u64),
                    Uint::ONE,
                )
            );
            assert_eq!(sign, ConstChoice::TRUE);
        }
    }

    mod test_pxgcd {
        use crypto_bigint::{ConstChoice, U1024, U64};

        use crate::helpers::partial_xgcd::{PartialXGCD, PxgcdMatrix};

        #[test]
        fn text_partial_xgcd_unit() {
            let (a, b, matrix) = U64::ONE.partial_xgcd(&U64::ZERO, 1);
            assert_eq!(a, U64::ONE);
            assert_eq!(b, U64::ZERO);
            assert_eq!(matrix, PxgcdMatrix::UNIT);
        }

        #[test]
        fn text_partial_xgcd_unit_swapped() {
            let (a, b, matrix) = U64::ZERO.partial_xgcd(&U64::ONE, 1);
            assert_eq!(a, U64::ZERO);
            assert_eq!(b, U64::ONE);
            assert_eq!(matrix, PxgcdMatrix::UNIT);
        }

        #[test]
        fn test_partial_xgcd_non_unitary_elements() {
            let (a, b, matrix) = U64::from(2u64).partial_xgcd(&U64::ONE, 1);
            assert_eq!(a, U64::ZERO);
            assert_eq!(b, U64::ONE);
            assert_eq!(
                matrix,
                PxgcdMatrix::new(
                    U64::ONE,
                    U64::from_u64(2u64),
                    U64::ZERO,
                    U64::ONE,
                    ConstChoice::TRUE
                )
            );
        }

        #[test]
        fn test_partial_xgcd_zero() {
            let threshold = 6;

            let (a, b) = (U64::from(554u64), U64::ZERO);
            let (partial_a, partial_b, matrix) = a.partial_xgcd(&b, threshold);
            assert_eq!(partial_a, U64::from(554u64));
            assert_eq!(partial_b, U64::ZERO);
            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));

            let (partial_a, partial_b, matrix) = b.partial_xgcd(&a, threshold);

            assert_eq!(partial_a, U64::ZERO);
            assert_eq!(partial_b, U64::from(554u64));
            assert_eq!(matrix.wrapping_apply((b, a)), (partial_a, partial_b));
        }

        #[test]
        fn test_partial_xgcd() {
            let threshold = 6;

            let (a, b) = (U64::from(554u64), U64::from(3321u64));
            let (partial_a, partial_b, matrix) = a.partial_xgcd(&b, threshold);

            assert_eq!(partial_a, U64::from(3u64));
            assert_eq!(partial_b, U64::from(23u64));

            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));
        }

        #[test]
        fn test_partial_xgcd_large() {
            let threshold = 512;

            let (a, b) = (U1024::MAX, U1024::ONE.shl(750));
            let (partial_a, partial_b, matrix) = a.partial_xgcd(&b, threshold);

            assert!(partial_a.bits() <= threshold);
            assert!(partial_b.bits() <= threshold);

            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));
        }

        #[test]
        fn test_partial_xgcd_no_threshold_underflow() {
            let threshold = 700;
            let (a, b) = (U64::ONE, U64::ZERO);
            let (partial_a, partial_b, matrix) = a.partial_xgcd(&b, threshold);

            assert!(partial_a.bits() <= threshold);
            assert!(partial_b.bits() <= threshold);

            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));
        }
    }

    mod test_pxgcd_randomized {
        use crypto_bigint::{ConstChoice, RandomMod, Uint, U1024, U64};

        use group::OsCsRng;

        use crate::helpers::partial_xgcd::{PartialXGCD, PxgcdMatrix};

        #[test]
        fn test_pxgcd_randomized_unit() {
            let (a, b, matrix, ..) = U64::ONE.partial_xgcd_randomized(&U64::ZERO, 1);
            assert_eq!(a, U64::ONE);
            assert_eq!(b, U64::ZERO);
            assert_eq!(matrix, PxgcdMatrix::UNIT);
        }

        #[test]
        fn test_pxgcd_randomized_unit_swapped() {
            let (a, b, matrix, ..) = U64::ZERO.partial_xgcd_randomized(&U64::ONE, 1);
            assert_eq!(a, U64::ZERO);
            assert_eq!(b, U64::ONE);
            assert_eq!(matrix, PxgcdMatrix::UNIT);
        }

        #[test]
        fn test_pxgcd_randomized_non_unitary_elements() {
            let (a, b, matrix, ..) = U64::from(2u64).partial_xgcd_randomized(&U64::ONE, 1);
            assert_eq!(a, U64::ZERO);
            assert_eq!(b, U64::ONE);
            assert_eq!(
                matrix,
                PxgcdMatrix::new(
                    U64::ONE,
                    U64::from_u64(2u64),
                    U64::ZERO,
                    U64::ONE,
                    ConstChoice::TRUE
                )
            );
        }

        #[test]
        fn test_pxgcd_randomized_zero() {
            let threshold = 6;

            let (a, b) = (U64::from(554u64), U64::ZERO);
            let (partial_a, partial_b, matrix, ..) = a.partial_xgcd_randomized(&b, threshold);
            assert_eq!(partial_a, U64::from(554u64));
            assert_eq!(partial_b, U64::ZERO);
            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));

            let (partial_a, partial_b, matrix, ..) = b.partial_xgcd_randomized(&a, threshold);

            assert_eq!(partial_a, U64::ZERO);
            assert_eq!(partial_b, U64::from(554u64));
            assert_eq!(matrix.wrapping_apply((b, a)), (partial_a, partial_b));
        }

        #[test]
        fn test_pxgcd_randomized() {
            let threshold = 6;

            let (a, b) = (U64::from(554u64), U64::from(3321u64));
            let (partial_a, partial_b, matrix, ..) = a.partial_xgcd_randomized(&b, threshold);

            assert_eq!(partial_a, U64::from(3u64));
            assert_eq!(partial_b, U64::from(23u64));

            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));
        }

        #[test]
        fn test_pxgcd_randomized_large() {
            let threshold = 512;

            let a = U1024::from_be_hex(concat![
                "5DD7D2A26628253140D3B3FF6FB58D90EDD2453E349B10D2126E45E496BC77FA",
                "2B57C249D4E9ADACE90489C9CC7CBDC4398B9789BCD953CD035918578C935420",
                "4363C09A549AC89C1B9228B0D3E916EC48DDDD9907C21931634EF8389C62942A",
                "46968524A431F19DF85D5CDCAF372359E039DE505DD0DD2AD30F609C85C5DFA1"
            ]);
            let b = U1024::from_be_hex(concat![
                "6A4DD9B62DB7A17E9A7A90F436EFD05019AB3D1153C5FD49040A3AE98B42C505",
                "2172F081D126E34615B1B793CB6C023B7B75B264164483CEB717F22A4DA641D2",
                "4BC370207E0707ABC3945F08E3F2F1354BE3F5F84165EFEBF4DCB27C359CC83A",
                "1F82699B459EEFCF2777DED206EFEC05C8F27522DDE036CDB3611D4290416BEA"
            ]);
            let (partial_a, partial_b, matrix, ..) = a.partial_xgcd_randomized(&b, threshold);

            assert!(partial_a.bits() <= threshold);
            assert!(partial_b.bits() <= threshold);

            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));
        }

        #[test]
        fn test_pxgcd_randomized_no_threshold_underflow() {
            let threshold = 700;
            let (a, b) = (U64::ONE, U64::ZERO);
            let (partial_a, partial_b, matrix, ..) = a.partial_xgcd_randomized(&b, threshold);

            assert!(partial_a.bits() <= threshold);
            assert!(partial_b.bits() <= threshold);

            assert_eq!(matrix.wrapping_apply((a, b)), (partial_a, partial_b));
        }

        #[test]
        fn test_pxgcd_randomized_output_size() {
            let threshold = 527;
            let modulus = U1024::ONE.shl_vartime(930).to_nz().unwrap();
            for _ in 0..1000 {
                let a = Uint::random_mod(&mut OsCsRng, &modulus);
                let b = Uint::random_mod(&mut OsCsRng, &modulus);

                let (partial_a, partial_b, ..) = a.partial_xgcd_randomized(&b, threshold);

                assert!(partial_a.bits() <= threshold);
                assert!(partial_b.bits() <= threshold);
            }
        }
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::time::Duration;

    use criterion::{BatchSize, Criterion};
    use crypto_bigint::{Random, I1024};

    use group::OsCsRng;

    use crate::helpers::partial_xgcd::PartialXGCD;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let mut g = _c.benchmark_group("ibqf/secp256k1");
        g.warm_up_time(Duration::from_secs(10));
        g.measurement_time(Duration::from_secs(30));

        g.bench_function("partial_xgcd_bounded_randomized", |b| {
            b.iter_batched(
                || {
                    (
                        I1024::random(&mut OsCsRng).abs(),
                        I1024::random(&mut OsCsRng).abs(),
                    )
                },
                |(x, y)| x.partial_xgcd_bounded_randomized(&y, 930, 463),
                BatchSize::SmallInput,
            )
        });
    }
}
