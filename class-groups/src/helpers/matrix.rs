// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{ConstChoice, Int, Uint};

use crate::helpers::extension::ExtendedInt;

type Vector<T> = (T, T);

/// Matrix used to compute the Extended GCD using the Binary Extended GCD algorithm.
///
/// The internal state represents the matrix
/// ```text
///      true                       false
/// [  m00 -m01 ]               [ -m00  m01 ]
/// [ -m10  m11 ] / 2^k   or    [  m10 -m11 ] / 2^k
/// ```
/// depending on whether `pattern` is respectively truthy or not.
///
/// Since some of the operations conditionally increase `k`, this struct furthermore keeps track of
/// `k_upper_bound`; an upper bound on the value of `k`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct BinXgcdMatrix<const LIMBS: usize> {
    m00: Uint<LIMBS>,
    m01: Uint<LIMBS>,
    m10: Uint<LIMBS>,
    m11: Uint<LIMBS>,
    pattern: ConstChoice,
    k: u32,
    k_upper_bound: u32,
}

impl<const LIMBS: usize> BinXgcdMatrix<LIMBS> {
    /// The unit matrix.
    pub(crate) const UNIT: Self = Self::new(
        Uint::ONE,
        Uint::ZERO,
        Uint::ZERO,
        Uint::ONE,
        ConstChoice::TRUE,
        0,
        0,
    );

    pub(crate) const fn new(
        m00: Uint<LIMBS>,
        m01: Uint<LIMBS>,
        m10: Uint<LIMBS>,
        m11: Uint<LIMBS>,
        pattern: ConstChoice,
        k: u32,
        k_upper_bound: u32,
    ) -> Self {
        Self {
            m00,
            m01,
            m10,
            m11,
            pattern,
            k,
            k_upper_bound,
        }
    }

    pub(crate) const fn as_elements(
        &self,
    ) -> (
        &Uint<LIMBS>,
        &Uint<LIMBS>,
        &Uint<LIMBS>,
        &Uint<LIMBS>,
        ConstChoice,
        u32,
        u32,
    ) {
        (
            &self.m00,
            &self.m01,
            &self.m10,
            &self.m11,
            self.pattern,
            self.k,
            self.k_upper_bound,
        )
    }

    pub(crate) fn as_elements_mut(
        &mut self,
    ) -> (
        &mut Uint<LIMBS>,
        &mut Uint<LIMBS>,
        &mut Uint<LIMBS>,
        &mut Uint<LIMBS>,
        &mut ConstChoice,
        &mut u32,
        &mut u32,
    ) {
        (
            &mut self.m00,
            &mut self.m01,
            &mut self.m10,
            &mut self.m11,
            &mut self.pattern,
            &mut self.k,
            &mut self.k_upper_bound,
        )
    }

    /// Apply this matrix to a vector of [Uint]s, returning the result as a vector of
    /// [ExtendedInt]s.
    #[inline]
    pub(crate) fn extended_apply_to<const VEC_LIMBS: usize>(
        &self,
        vec: Vector<Uint<VEC_LIMBS>>,
    ) -> Vector<ExtendedInt<VEC_LIMBS, LIMBS>> {
        let (a, b) = vec;
        let m00a = ExtendedInt::from_unsigned_product(a, self.m00);
        let m10a = ExtendedInt::from_unsigned_product(a, self.m10);
        let m01b = ExtendedInt::from_unsigned_product(b, self.m01);
        let m11b = ExtendedInt::from_unsigned_product(b, self.m11);
        (
            m00a.wrapping_sub(&m01b)
                .div_2k(self.k)
                .wrapping_neg_if(self.pattern.not()),
            m11b.wrapping_sub(&m10a)
                .div_2k(self.k)
                .wrapping_neg_if(self.pattern.not()),
        )
    }

    /// Swap the rows of this matrix if `swap` is truthy. Otherwise, do nothing.
    #[inline]
    pub(crate) fn conditional_swap_rows(&mut self, swap: ConstChoice) {
        Uint::conditional_swap(&mut self.m00, &mut self.m10, swap);
        Uint::conditional_swap(&mut self.m01, &mut self.m11, swap);
        self.pattern = self.pattern.xor(swap);
    }

    /// Swap the rows of this matrix.
    #[inline]
    pub(crate) fn swap_rows(&mut self) {
        self.conditional_swap_rows(ConstChoice::TRUE);
    }

    /// Subtract the bottom row from the top if `subtract` is truthy. Otherwise, do nothing.
    #[inline]
    pub(crate) fn conditional_subtract_bottom_row_from_top(&mut self, subtract: ConstChoice) {
        // Note: because the signs of the internal representation are stored in `pattern`,
        // subtracting one row from another involves _adding_ these rows instead.
        self.m00 = Uint::select(&self.m00, &self.m00.wrapping_add(&self.m10), subtract);
        self.m01 = Uint::select(&self.m01, &self.m01.wrapping_add(&self.m11), subtract);
    }

    /// Subtract the right column from the left if `subtract` is truthy. Otherwise, do nothing.
    #[inline]
    pub(crate) fn conditional_subtract_right_column_from_left(&mut self, subtract: ConstChoice) {
        // Note: because the signs of the internal representation are stored in `pattern`,
        // subtracting one column from another involves _adding_ these columns instead.
        self.m00 = Uint::select(&self.m00, &self.m00.wrapping_add(&self.m01), subtract);
        self.m10 = Uint::select(&self.m10, &self.m10.wrapping_add(&self.m11), subtract);
    }

    /// If `add` is truthy, add the right column to the left. Otherwise, do nothing.
    #[inline]
    pub(crate) fn conditional_add_right_column_to_left(&mut self, add: ConstChoice) {
        // Note: because the signs of the internal representation are stored in `pattern`,
        // subtracting one column from another involves _adding_ these columns instead.
        self.m00 = Uint::select(&self.m00, &self.m01.wrapping_sub(&self.m00), add);
        self.m10 = Uint::select(&self.m10, &self.m11.wrapping_sub(&self.m10), add);
    }

    /// Double the bottom row of this matrix if `double` is truthy. Otherwise, do nothing.
    #[inline]
    pub(crate) fn conditional_double_bottom_row(&mut self, double: ConstChoice) {
        // safe to vartime; shr_vartime is variable in the value of shift only. Since this shift
        // is a public constant, the constant time property of this algorithm is not impacted.
        self.m10 = Uint::select(&self.m10, &self.m10.shl_vartime(1), double);
        self.m11 = Uint::select(&self.m11, &self.m11.shl_vartime(1), double);
        self.k = double.select_u32(self.k, self.k + 1);
        self.k_upper_bound += 1;
    }

    /// Negate the elements in this matrix if `negate` is truthy. Otherwise, do nothing.
    #[inline]
    pub(crate) fn conditional_negate(&mut self, negate: ConstChoice) {
        self.pattern = self.pattern.xor(negate);
    }
}

/// Variation of [BinXgcdMatrix] that operates on [IntUintMix]s instead of [Uint]s
#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) struct IntBinXgcdMatrix<const LIMBS: usize> {
    m00: Int<LIMBS>,
    m01: Int<LIMBS>,
    m10: Int<LIMBS>,
    m11: Int<LIMBS>,
    k: u32,
    k_upper_bound: u32,
}

impl<const LIMBS: usize> IntBinXgcdMatrix<LIMBS> {
    pub(crate) const UNIT: Self = Self::new(Int::ONE, Int::ZERO, Int::ZERO, Int::ONE, 0, 0);

    pub(crate) const fn new(
        m00: Int<LIMBS>,
        m01: Int<LIMBS>,
        m10: Int<LIMBS>,
        m11: Int<LIMBS>,
        k: u32,
        k_upper_bound: u32,
    ) -> Self {
        Self {
            m00,
            m01,
            m10,
            m11,
            k,
            k_upper_bound,
        }
    }

    pub(crate) const fn to_elements(
        self,
    ) -> (Int<LIMBS>, Int<LIMBS>, Int<LIMBS>, Int<LIMBS>, u32, u32) {
        (
            self.m00,
            self.m01,
            self.m10,
            self.m11,
            self.k,
            self.k_upper_bound,
        )
    }

    /// Wrapping left multiply this matrix with `lhs`.
    ///
    /// If `last_round` is set, ignore the signs of the bottom row elements.
    #[inline]
    pub(crate) const fn wrapping_left_mul<const LHS_LIMBS: usize>(
        &self,
        lhs: &BinXgcdMatrix<LHS_LIMBS>,
    ) -> Self {
        let a = ExtendedInt::from_product(self.m00, lhs.m00)
            .wrapping_sub(&ExtendedInt::from_product(self.m10, lhs.m01))
            .wrapping_neg_if(lhs.pattern.not())
            .wrapping_drop_extension();

        let b = ExtendedInt::from_product(self.m01, lhs.m00)
            .wrapping_sub(&ExtendedInt::from_product(self.m11, lhs.m01))
            .wrapping_neg_if(lhs.pattern.not())
            .wrapping_drop_extension();

        let c = ExtendedInt::from_product(self.m10, lhs.m11)
            .wrapping_sub(&ExtendedInt::from_product(self.m00, lhs.m10))
            .wrapping_neg_if(lhs.pattern.not())
            .wrapping_drop_extension();

        let d = ExtendedInt::from_product(self.m11, lhs.m11)
            .wrapping_sub(&ExtendedInt::from_product(self.m01, lhs.m10))
            .wrapping_neg_if(lhs.pattern.not())
            .wrapping_drop_extension();

        Self {
            m00: a,
            m01: b,
            m10: c,
            m11: d,
            k: self.k + lhs.k,
            k_upper_bound: self.k_upper_bound + lhs.k_upper_bound,
        }
    }

    /// Negate the top row of the matrix if `negate` is truthy. Otherwise, do nothing.
    pub(crate) fn conditional_negate_top_row(&mut self, negate: ConstChoice) {
        self.m00 = self.m00.wrapping_neg_if(negate);
        self.m01 = self.m01.wrapping_neg_if(negate);
    }

    /// Negate the bottom row of the matrix if `negate` is truthy. Otherwise, do nothing.
    pub(crate) fn conditional_negate_bottom_row(&mut self, negate: ConstChoice) {
        self.m10 = self.m10.wrapping_neg_if(negate);
        self.m11 = self.m11.wrapping_neg_if(negate);
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{ConstChoice, Uint, U256, U64};

    use crate::helpers::matrix::BinXgcdMatrix;

    const X: BinXgcdMatrix<{ U256::LIMBS }> = BinXgcdMatrix::new(
        U256::from_u64(1u64),
        U256::from_u64(7u64),
        U256::from_u64(23u64),
        U256::from_u64(53u64),
        ConstChoice::TRUE,
        1,
        2,
    );

    #[test]
    fn test_wrapping_apply_to() {
        let a = U64::from_be_hex("CA048AFA63CD6A1F");
        let b = U64::from_be_hex("AE693BF7BE8E5566");
        let matrix = BinXgcdMatrix {
            m00: U64::from_be_hex("0000000000000120"),
            m01: U64::from_be_hex("00000000000000D0"),
            m10: U64::from_be_hex("0000000000000136"),
            m11: U64::from_be_hex("00000000000002A7"),
            pattern: ConstChoice::TRUE,
            k: 17,
            k_upper_bound: 17,
        };

        let (a_, b_) = matrix.extended_apply_to((a, b));
        assert_eq!(
            a_.split_drop_extension().0,
            Uint::from_be_hex("002AC7CDD032B9B9")
        );
        assert_eq!(
            b_.split_drop_extension().0,
            Uint::from_be_hex("006CFBCEE172C863")
        );
    }

    #[test]
    fn test_swap() {
        let mut y = X;
        y.swap_rows();
        assert_eq!(
            y,
            BinXgcdMatrix::new(
                Uint::from(23u32),
                Uint::from(53u32),
                Uint::from(1u32),
                Uint::from(7u32),
                ConstChoice::FALSE,
                1,
                2
            )
        );
    }

    #[test]
    fn test_conditional_swap() {
        let mut y = X;
        y.conditional_swap_rows(ConstChoice::FALSE);
        assert_eq!(y, X);
        y.conditional_swap_rows(ConstChoice::TRUE);
        assert_eq!(
            y,
            BinXgcdMatrix::new(
                Uint::from(23u32),
                Uint::from(53u32),
                Uint::from(1u32),
                Uint::from(7u32),
                ConstChoice::FALSE,
                1,
                2
            )
        );
    }

    #[test]
    fn test_conditional_add_right_column_to_left() {
        let mut y = X;
        y.conditional_add_right_column_to_left(ConstChoice::FALSE);
        assert_eq!(y, X);
        y.conditional_add_right_column_to_left(ConstChoice::TRUE);
        assert_eq!(
            y,
            BinXgcdMatrix::new(
                Uint::from(6u32),
                Uint::from(7u32),
                Uint::from(30u32),
                Uint::from(53u32),
                ConstChoice::TRUE,
                1,
                2
            )
        );
    }

    #[test]
    fn test_conditional_subtract_bottom_row_from_top() {
        let mut y = X;
        y.conditional_subtract_bottom_row_from_top(ConstChoice::FALSE);
        assert_eq!(y, X);
        y.conditional_subtract_bottom_row_from_top(ConstChoice::TRUE);
        assert_eq!(
            y,
            BinXgcdMatrix::new(
                Uint::from(24u32),
                Uint::from(60u32),
                Uint::from(23u32),
                Uint::from(53u32),
                ConstChoice::TRUE,
                1,
                2
            )
        );
    }

    #[test]
    fn test_conditional_subtract_right_column_from_left() {
        let mut y = X;
        y.conditional_subtract_right_column_from_left(ConstChoice::FALSE);
        assert_eq!(y, X);
        y.conditional_subtract_right_column_from_left(ConstChoice::TRUE);
        assert_eq!(
            y,
            BinXgcdMatrix::new(
                Uint::from(8u32),
                Uint::from(7u32),
                Uint::from(76u32),
                Uint::from(53u32),
                ConstChoice::TRUE,
                1,
                2
            )
        );
    }

    #[test]
    fn test_conditional_double() {
        let mut y = X;
        y.conditional_double_bottom_row(ConstChoice::FALSE);
        assert_eq!(
            y,
            BinXgcdMatrix::new(
                Uint::from(1u32),
                Uint::from(7u32),
                Uint::from(23u32),
                Uint::from(53u32),
                ConstChoice::TRUE,
                1,
                3
            )
        );
        y.conditional_double_bottom_row(ConstChoice::TRUE);
        assert_eq!(
            y,
            BinXgcdMatrix::new(
                Uint::from(1u32),
                Uint::from(7u32),
                Uint::from(46u32),
                Uint::from(106u32),
                ConstChoice::TRUE,
                2,
                4
            )
        );
    }
}
