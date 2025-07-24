// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{ConstChoice, Int, NonZero, Odd, Uint, U128, U64};

use crate::helpers::matrix::{BinXgcdMatrix, IntBinXgcdMatrix};
use crate::helpers::tools::BoundedDivMod2k;
use crate::helpers::tools::{const_max, const_min, Compact};

/// Container for the raw output of the Binary XGCD algorithm.
pub(crate) struct RawOddUintBinxgcdOutput<const LIMBS: usize> {
    gcd: Odd<Uint<LIMBS>>,
    matrix: BinXgcdMatrix<LIMBS>,
}

impl<const LIMBS: usize> RawOddUintBinxgcdOutput<LIMBS> {
    /// Process raw output, constructing an [UintBinxgcdOutput] object.
    pub(crate) fn process(&mut self) -> OddUintBinxgcdOutput<LIMBS> {
        self.remove_matrix_factors();
        let (x, y) = self.bezout_coefficients();
        let (lhs_on_gcd, rhs_on_gcd) = self.quotients();
        OddUintBinxgcdOutput {
            gcd: self.gcd,
            x,
            y,
            lhs_on_gcd,
            rhs_on_gcd,
        }
    }

    /// Divide `self.matrix` by `2^self.matrix.k`, i.e., remove the excess doublings from
    /// `self.matrix`.
    ///
    /// The performed divisions are modulo `lhs` and `rhs` to maintain the correctness of the XGCD
    /// state.
    ///
    /// This operation is 'fast' since it only applies the division to the top row of the matrix.
    /// This is allowed since it is assumed that `self.matrix * (lhs, rhs) = (gcd, 0)`; dividing
    /// the bottom row of the matrix by a constant has no impact since its inner-product with the
    /// input vector is zero.
    fn remove_matrix_factors(&mut self) {
        let (lhs_div_gcd, rhs_div_gcd) = self.quotients();
        let (x, y, .., k, k_upper_bound) = self.matrix.as_elements_mut();
        if *k_upper_bound > 0 {
            *x = x.bounded_div_2k_mod_q(
                *k,
                *k_upper_bound,
                &rhs_div_gcd.to_odd().expect("odd by construction"),
            );
            *y = y.bounded_div_2k_mod_q(
                *k,
                *k_upper_bound,
                &lhs_div_gcd.to_odd().expect("odd by construction"),
            );
            *k = 0;
            *k_upper_bound = 0;
        }
    }

    /// Obtain the bezout coefficients `(x, y)` such that `lhs * x + rhs * y = gcd`.
    const fn bezout_coefficients(&self) -> (Int<LIMBS>, Int<LIMBS>) {
        let (m00, m01, m10, m11, pattern, ..) = self.matrix.as_elements();
        let m10_sub_m00 = m10.wrapping_sub(m00);
        let m11_sub_m01 = m11.wrapping_sub(m01);
        let apply = Uint::lte(&m10_sub_m00, m00).and(Uint::lte(&m11_sub_m01, m01));
        let m00 = *Uint::select(m00, &m10_sub_m00, apply)
            .wrapping_neg_if(apply.xor(pattern.not()))
            .as_int();
        let m01 = *Uint::select(m01, &m11_sub_m01, apply)
            .wrapping_neg_if(apply.xor(pattern))
            .as_int();
        (m00, m01)
    }

    /// Obtain the quotients `lhs/gcd` and `rhs/gcd` from `matrix`.
    const fn quotients(&self) -> (Uint<LIMBS>, Uint<LIMBS>) {
        let (.., rhs_div_gcd, lhs_div_gcd, _, _, _) = self.matrix.as_elements();
        (*lhs_div_gcd, *rhs_div_gcd)
    }
}

/// Output of the Binary XGCD algorithm applied to two [Uint]s.
pub type UintBinxgcdOutput<const LIMBS: usize> = BaseUintBinxgcdOutput<Uint<LIMBS>, LIMBS>;

/// Output of the Binary XGCD algorithm applied to two [`NonZero<Uint<LIMBS>>`]s.
pub type NonZeroUintBinxgcdOutput<const LIMBS: usize> =
    BaseUintBinxgcdOutput<NonZero<Uint<LIMBS>>, LIMBS>;

/// Output of the Binary XGCD algorithm applied to two [`Odd<Uint<LIMBS>>`]s.
pub type OddUintBinxgcdOutput<const LIMBS: usize> = BaseUintBinxgcdOutput<Odd<Uint<LIMBS>>, LIMBS>;

/// Container for the processed output of the Binary XGCD algorithm.
#[derive(Debug)]
pub struct BaseUintBinxgcdOutput<T: Copy, const LIMBS: usize> {
    pub gcd: T,
    pub x: Int<LIMBS>,
    pub y: Int<LIMBS>,
    pub lhs_on_gcd: Uint<LIMBS>,
    pub rhs_on_gcd: Uint<LIMBS>,
}

/// Number of bits used by [Odd::<Uint<{LIMBS}>>::optimized_binxgcd] to represent a "compact" [Uint].
const SUMMARY_BITS: u32 = U64::BITS;

/// Number of limbs used to represent [Self::SUMMARY_BITS].
const SUMMARY_LIMBS: usize = U64::LIMBS;

/// Twice the number of limbs used to represent [Self::SUMMARY_BITS], i.e., two times
/// [Self::SUMMARY_LIMBS].
const DOUBLE_SUMMARY_LIMBS: usize = U128::LIMBS;

pub(crate) trait PartialBinXgcd<Rhs = Self>: Sized {
    /// Executes the optimized Binary GCD inner loop.
    ///
    /// Ref: Pornin, Optimized Binary GCD for Modular Inversion, Algorithm 2.
    /// <https://eprint.iacr.org/2020/972.pdf>.
    ///
    /// The function outputs the reduced values `(a, b)` for the input values `(self, rhs)` as well
    /// as the matrix that yields the former two when multiplied with the latter two.
    ///
    /// Additionally, the number doublings that were executed is returned. By construction, each
    /// element in `M` lies in the interval `(-2^doublings, 2^doublings]`.
    ///
    /// Note: this implementation deviates slightly from the paper, in that it can be instructed to
    /// "run in place" (i.e., execute iterations that do nothing) once `a` becomes zero.
    /// This is done by passing a truthy `halt_at_zero`.
    ///
    /// The function executes in time variable in `iterations`.
    fn partial_binxgcd_vartime<const UPDATE_LIMBS: usize>(
        &self,
        rhs: &Rhs,
        iterations: u32,
        halt_at_zero: ConstChoice,
    ) -> (Self, Rhs, BinXgcdMatrix<UPDATE_LIMBS>);
}

impl<const LIMBS: usize> PartialBinXgcd<Uint<LIMBS>> for Odd<Uint<LIMBS>> {
    fn partial_binxgcd_vartime<const UPDATE_LIMBS: usize>(
        &self,
        rhs: &Uint<LIMBS>,
        iterations: u32,
        halt_at_zero: ConstChoice,
    ) -> (Self, Uint<LIMBS>, BinXgcdMatrix<UPDATE_LIMBS>) {
        let (mut a, mut b) = (*self.as_ref(), *rhs);
        // This matrix corresponds with (f0, g0, f1, g1) in the paper.
        let mut matrix = BinXgcdMatrix::UNIT;

        // Compute the update matrix.
        // Note: to be consistent with the paper, the `binxgcd_step` algorithm requires the second
        // argument to be odd. Here, we have `a` odd, so we have to swap a and b before and after
        // calling the subroutine. The columns of the matrix have to be swapped accordingly.
        Uint::swap(&mut a, &mut b);
        matrix.swap_rows();

        let mut j = 0;
        while j < iterations {
            binxgcd_step(&mut a, &mut b, &mut matrix, halt_at_zero);
            j += 1;
        }

        // Undo swap
        Uint::swap(&mut a, &mut b);
        matrix.swap_rows();

        let a = a.to_odd().expect("a is always odd");
        (a, b, matrix)
    }
}

trait ClassicBinXgcd<Rhs = Self>: Sized {
    type Output;

    const MIN_CLASSIC_BINGCD_ITERATIONS: u32;

    /// Execute the classic Binary Extended GCD algorithm.
    ///
    /// Given `(self, rhs)`, computes `(g, x, y)` s.t. `self * x + rhs * y = g = gcd(self, rhs)`.
    ///
    /// Ref: Pornin, Optimized Binary GCD for Modular Inversion, Algorithm 1.
    /// <https://eprint.iacr.org/2020/972.pdf>.
    fn classic_binxgcd(&self, rhs: &Rhs) -> Self::Output;
}

impl<const LIMBS: usize> ClassicBinXgcd for Odd<Uint<LIMBS>> {
    type Output = RawOddUintBinxgcdOutput<LIMBS>;

    const MIN_CLASSIC_BINGCD_ITERATIONS: u32 = 2 * Self::BITS - 1;

    fn classic_binxgcd(&self, rhs: &Self) -> Self::Output {
        let (gcd, _, matrix) = self.partial_binxgcd_vartime::<LIMBS>(
            rhs.as_ref(),
            Self::MIN_CLASSIC_BINGCD_ITERATIONS,
            ConstChoice::TRUE,
        );

        RawOddUintBinxgcdOutput { gcd, matrix }
    }
}

trait OptimizedBinXgcd<Rhs = Self>: Sized {
    type Output;

    const MIN_OPTIMIZED_BINGCD_ITERATIONS: u32;

    /// Given `(self, rhs)`, computes `(g, x, y)` s.t. `self * x + rhs * y = g = gcd(self, rhs)`,
    /// leveraging the Binary Extended GCD algorithm.
    ///
    /// **Warning**: `self` and `rhs` must be contained in an [U128] or larger.
    ///
    /// Note: this algorithm becomes more efficient than the classical algorithm for [Uint]s with
    /// relatively many `LIMBS`. A best-effort threshold is presented in [Self::binxgcd_].
    ///
    /// Note: the full algorithm has an additional parameter; this function selects the best-effort
    /// value for this parameter. You might be able to further tune your performance by calling the
    /// [Self::optimized_bingcd_] function directly.
    ///
    /// Ref: Pornin, Optimized Binary GCD for Modular Inversion, Algorithm 2.
    /// <https://eprint.iacr.org/2020/972.pdf>.
    fn optimized_binxgcd(&self, rhs: &Rhs) -> Self::Output;

    /// Given `(self, rhs)`, computes `(g, x, y)`, s.t. `self * x + rhs * y = g = gcd(self, rhs)`,
    /// leveraging the optimized Binary Extended GCD algorithm.
    ///
    /// Ref: Pornin, Optimized Binary GCD for Modular Inversion, Algorithm 2.
    /// <https://eprint.iacr.org/2020/972.pdf>
    ///
    /// In summary, the optimized algorithm does not operate on `self` and `rhs` directly, but
    /// instead of condensed summaries that fit in few registers. Based on these summaries, an
    /// update matrix is constructed by which `self` and `rhs` are updated in larger steps.
    ///
    /// This function is generic over the following three values:
    /// - `K`: the number of bits used when summarizing `self` and `rhs` for the inner loop. The
    ///   `K+1` top bits and `K-1` least significant bits are selected. It is recommended to keep
    ///   `K` close to a (multiple of) the number of bits that fit in a single register.
    /// - `LIMBS_K`: should be chosen as the minimum number s.t. `Uint::<LIMBS>::BITS ≥ K`,
    /// - `LIMBS_2K`: should be chosen as the minimum number s.t. `Uint::<LIMBS>::BITS ≥ 2K`.
    fn optimized_binxgcd_<const K: u32, const LIMBS_K: usize, const LIMBS_2K: usize>(
        &self,
        rhs: &Rhs,
    ) -> Self::Output;
}

impl<const LIMBS: usize> OptimizedBinXgcd for Odd<Uint<LIMBS>> {
    type Output = RawOddUintBinxgcdOutput<LIMBS>;

    const MIN_OPTIMIZED_BINGCD_ITERATIONS: u32 = 2 * Self::BITS - 1;

    fn optimized_binxgcd(&self, rhs: &Self) -> Self::Output {
        assert!(Self::BITS >= U128::BITS);
        self.optimized_binxgcd_::<SUMMARY_BITS, SUMMARY_LIMBS, DOUBLE_SUMMARY_LIMBS>(rhs)
    }

    /// Given `(self, rhs)`, computes `(g, x, y)`, s.t. `self * x + rhs * y = g = gcd(self, rhs)`,
    /// leveraging the optimized Binary Extended GCD algorithm.
    ///
    /// Ref: Pornin, Optimized Binary GCD for Modular Inversion, Algorithm 2.
    /// <https://eprint.iacr.org/2020/972.pdf>
    ///
    /// In summary, the optimized algorithm does not operate on `self` and `rhs` directly, but
    /// instead of condensed summaries that fit in few registers. Based on these summaries, an
    /// update matrix is constructed by which `self` and `rhs` are updated in larger steps.
    ///
    /// This function is generic over the following three values:
    /// - `K`: the number of bits used when summarizing `self` and `rhs` for the inner loop. The
    ///   `K+1` top bits and `K-1` least significant bits are selected. It is recommended to keep
    ///   `K` close to a (multiple of) the number of bits that fit in a single register.
    /// - `LIMBS_K`: should be chosen as the minimum number s.t. `Uint::<LIMBS>::BITS ≥ K`,
    /// - `LIMBS_2K`: should be chosen as the minimum number s.t. `Uint::<LIMBS>::BITS ≥ 2K`.
    fn optimized_binxgcd_<const K: u32, const LIMBS_K: usize, const LIMBS_2K: usize>(
        &self,
        rhs: &Self,
    ) -> Self::Output {
        let (mut a, mut b) = (*self.as_ref(), *rhs.as_ref());
        let mut matrix = IntBinXgcdMatrix::UNIT;

        let (mut a_sgn, mut b_sgn);
        let mut i = 0;
        while i < Self::MIN_OPTIMIZED_BINGCD_ITERATIONS.div_ceil(K - 1) {
            // Loop invariants:
            //  i) each iteration of this loop, `a.bits() + b.bits()` shrinks by at least K-1,
            //     until `b = 0`.
            // ii) `a` is odd.
            i += 1;

            // Construct compact_a and compact_b as the summary of a and b, respectively.
            let b_bits = b.bits();
            let n = const_max(2 * K, const_max(a.bits(), b_bits));
            let compact_a = a.compact::<K, LIMBS_2K>(n);
            let compact_b = b.compact::<K, LIMBS_2K>(n);
            let b_eq_compact_b =
                ConstChoice::from_u32_le(b_bits, K - 1).or(ConstChoice::from_u32_eq(n, 2 * K));

            // Compute the K-1 iteration update matrix from a_ and b_
            let (.., update_matrix) = compact_a
                .to_odd()
                .expect("a is always odd")
                .partial_binxgcd_vartime::<LIMBS_K>(&compact_b, K - 1, b_eq_compact_b);

            // Update `a` and `b` using the update matrix
            let (updated_a, updated_b) = update_matrix.extended_apply_to((a, b));
            matrix = matrix.wrapping_left_mul(&update_matrix);

            (a, a_sgn) = updated_a.split_drop_extension();
            matrix.conditional_negate_top_row(a_sgn);

            (b, b_sgn) = updated_b.split_drop_extension();
            matrix.conditional_negate_bottom_row(b_sgn);
        }

        // Convert the matrix to an `BinXgcdMatrix`.
        // Recall that, at this point, b = 0. This implies that the signs of the two elements on the
        // bottom row are not the same. Moreover, it is safe to negate both elements. We can therefore
        // take move the IntBinxgcdMatrix into a BinXgcdMatrix.
        let (m00, m01, m10, m11, k, k_upper_bound) = matrix.to_elements();
        let (abs_m00, sgn_m00) = m00.abs_sign();
        let (abs_m01, sgn_m01) = m01.abs_sign();
        debug_assert!(abs_m00
            .is_nonzero()
            .not()
            .or(abs_m01.is_nonzero().not())
            .or(sgn_m00.ne(sgn_m01))
            .to_bool_vartime());
        let pattern = abs_m00
            .is_nonzero()
            .and(sgn_m00.not())
            .or(abs_m01.is_nonzero().and(sgn_m01));
        let matrix = BinXgcdMatrix::new(
            abs_m00,
            abs_m01,
            m10.abs(),
            m11.abs(),
            pattern,
            k,
            k_upper_bound,
        );

        let gcd = a
            .to_odd()
            .expect("gcd of an odd value with something else is always odd");

        RawOddUintBinxgcdOutput { gcd, matrix }
    }
}

trait BinXgcdInternal: Sized {
    type Output;

    /// Given `(self, rhs)`, computes `(g, x, y)` s.t. `self * x + rhs * y = g = gcd(self, rhs)`,
    /// leveraging the Binary Extended GCD algorithm.
    fn binxgcd_internal(&self, rhs: &Self) -> Self::Output;
}

impl<const LIMBS: usize> BinXgcdInternal for Odd<Uint<LIMBS>> {
    type Output = RawOddUintBinxgcdOutput<LIMBS>;

    fn binxgcd_internal(&self, rhs: &Self) -> Self::Output {
        if LIMBS < 4 {
            self.classic_binxgcd(rhs)
        } else {
            self.optimized_binxgcd(rhs)
        }
    }
}

pub(crate) trait BinXgcd<Rhs = Self>: Sized {
    type Output;

    /// Given `(self, rhs)`, computes `(g, x, y)` s.t. `self * x + rhs * y = g = gcd(self, rhs)`,
    /// leveraging the Binary Extended GCD algorithm.
    fn binxgcd(&self, rhs: &Rhs) -> Self::Output;
}

impl<const LIMBS: usize> BinXgcd<NonZero<Uint<LIMBS>>> for Odd<Uint<LIMBS>> {
    type Output = OddUintBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &NonZero<Uint<LIMBS>>) -> Self::Output {
        let (lhs_, rhs_) = (self.as_ref(), rhs.as_ref());

        // The `binxgcd` subroutine requires `rhs` needs to be odd. We leverage the equality
        // gcd(lhs, rhs) = gcd(lhs, |lhs-rhs|) to deal with the case that `rhs` is even.
        let rhs_gt_lhs = Uint::gt(rhs_, lhs_);
        let rhs_is_even = rhs_.is_odd_const().not();
        let abs_lhs_sub_rhs = Uint::select(
            &lhs_.wrapping_sub(rhs_),
            &rhs_.wrapping_sub(lhs_),
            rhs_gt_lhs,
        );
        let rhs_ = Uint::select(rhs.as_ref(), &abs_lhs_sub_rhs, rhs_is_even)
            .to_odd()
            .expect("rhs is odd by construction");

        let mut output = self.binxgcd_internal(&rhs_);
        output.remove_matrix_factors();

        // Modify the output to negate the transformation applied to the input.
        let matrix = &mut output.matrix;
        let case_one = rhs_is_even.and(rhs_gt_lhs);
        matrix.conditional_subtract_right_column_from_left(case_one);
        let case_two = rhs_is_even.and(rhs_gt_lhs.not());
        matrix.conditional_add_right_column_to_left(case_two);
        matrix.conditional_negate(case_two);

        output.process()
    }
}

impl<const LIMBS: usize> BinXgcd for Odd<Uint<LIMBS>> {
    type Output = OddUintBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &Self) -> Self::Output {
        self.binxgcd_internal(rhs).process()
    }
}

impl<const LIMBS: usize> BinXgcd for NonZero<Uint<LIMBS>> {
    type Output = NonZeroUintBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &Self) -> Self::Output {
        let (mut lhs, mut rhs) = (*self.as_ref(), *rhs.as_ref());

        // Leverage the property that gcd(2^k * a, 2^k *b) = 2^k * gcd(a, b)
        let i = lhs.trailing_zeros();
        let j = rhs.trailing_zeros();
        let k = const_min(i, j);
        lhs = lhs.shr(k);
        rhs = rhs.shr(k);

        // Note: at this point, either lhs or rhs is odd (or both).
        // Swap to make sure lhs is odd.
        let swap = ConstChoice::from_u32_lt(j, i);
        Uint::conditional_swap(&mut lhs, &mut rhs, swap);
        let lhs = lhs.to_odd().expect("odd by construction");

        let rhs = rhs.to_nz().expect("non-zero by construction");
        let OddUintBinxgcdOutput {
            gcd,
            mut x,
            mut y,
            mut lhs_on_gcd,
            mut rhs_on_gcd,
        } = lhs.binxgcd(&rhs);

        let gcd = gcd
            .as_ref()
            .shl(k)
            .to_nz()
            .expect("is non-zero by construction");
        Int::conditional_swap(&mut x, &mut y, swap);
        Uint::conditional_swap(&mut lhs_on_gcd, &mut rhs_on_gcd, swap);

        NonZeroUintBinxgcdOutput {
            gcd,
            x,
            y,
            lhs_on_gcd,
            rhs_on_gcd,
        }
    }
}

impl<const LIMBS: usize> BinXgcd for Uint<LIMBS> {
    type Output = UintBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &Self) -> Self::Output {
        // Make sure `self` and `rhs` are nonzero.
        let self_is_zero = self.is_nonzero().not();
        let self_nz = Uint::select(self, &Uint::ONE, self_is_zero)
            .to_nz()
            .expect("self is non zero by construction");
        let rhs_is_zero = rhs.is_nonzero().not();
        let rhs_nz = Uint::select(rhs, &Uint::ONE, rhs_is_zero)
            .to_nz()
            .expect("rhs is non zero by construction");

        let NonZeroUintBinxgcdOutput {
            gcd,
            mut x,
            mut y,
            mut lhs_on_gcd,
            mut rhs_on_gcd,
        } = self_nz.binxgcd(&rhs_nz);

        // Correct the gcd in case self and/or rhs was zero
        let mut gcd = *gcd.as_ref();
        gcd = Uint::select(&gcd, rhs, self_is_zero);
        gcd = Uint::select(&gcd, self, rhs_is_zero);

        // Correct the Bézout coefficients in case self and/or rhs was zero.
        x = Int::select(&x, &Int::ZERO, self_is_zero);
        y = Int::select(&y, &Int::ONE, self_is_zero);
        x = Int::select(&x, &Int::ONE, rhs_is_zero);
        y = Int::select(&y, &Int::ZERO, rhs_is_zero);

        // Correct the quotients in case self and/or rhs was zero.
        lhs_on_gcd = Uint::select(&lhs_on_gcd, &Uint::ZERO, self_is_zero);
        rhs_on_gcd = Uint::select(&rhs_on_gcd, &Uint::ONE, self_is_zero);
        lhs_on_gcd = Uint::select(&lhs_on_gcd, &Uint::ONE, rhs_is_zero);
        rhs_on_gcd = Uint::select(&rhs_on_gcd, &Uint::ZERO, rhs_is_zero);

        UintBinxgcdOutput {
            gcd,
            x,
            y,
            lhs_on_gcd,
            rhs_on_gcd,
        }
    }
}

#[derive(Debug)]
pub struct BaseIntBinxgcdOutput<T: Copy, const LIMBS: usize> {
    pub gcd: T,
    pub x: Int<LIMBS>,
    pub y: Int<LIMBS>,
    pub lhs_on_gcd: Int<LIMBS>,
    pub rhs_on_gcd: Int<LIMBS>,
}

/// Output of the Binary XGCD algorithm applied to two [Int]s.
pub type IntBinxgcdOutput<const LIMBS: usize> = BaseIntBinxgcdOutput<Uint<LIMBS>, LIMBS>;

/// Output of the Binary XGCD algorithm applied to two [`NonZero<Int<LIMBS>>`]s.
pub type NonZeroIntBinxgcdOutput<const LIMBS: usize> =
    BaseIntBinxgcdOutput<NonZero<Uint<LIMBS>>, LIMBS>;

/// Output of the Binary XGCD algorithm applied to two [`Odd<Int<LIMBS>>`]s.
pub type OddIntBinxgcdOutput<const LIMBS: usize> = BaseIntBinxgcdOutput<Odd<Uint<LIMBS>>, LIMBS>;

impl<const LIMBS: usize> BinXgcd for Int<LIMBS> {
    type Output = IntBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &Self) -> Self::Output {
        // Make sure `self` and `rhs` are nonzero.
        let self_is_zero = self.is_nonzero().not();
        let self_nz = Int::select(self, &Int::ONE, self_is_zero)
            .to_nz()
            .expect("self is non zero by construction");
        let rhs_is_zero = rhs.is_nonzero().not();
        let rhs_nz = Int::select(rhs, &Int::ONE, rhs_is_zero)
            .to_nz()
            .expect("rhs is non zero by construction");

        let NonZeroIntBinxgcdOutput {
            gcd,
            mut x,
            mut y,
            mut lhs_on_gcd,
            mut rhs_on_gcd,
        } = self_nz.binxgcd(&rhs_nz);

        // Correct the gcd in case self and/or rhs was zero
        let mut gcd = *gcd.as_ref();
        gcd = Uint::select(&gcd, &rhs.abs(), self_is_zero);
        gcd = Uint::select(&gcd, &self.abs(), rhs_is_zero);

        // Correct the Bézout coefficients in case self and/or rhs was zero.
        let signum_self = Int::new_from_abs_sign(Uint::ONE, self.is_negative()).expect("+/- 1");
        let signum_rhs = Int::new_from_abs_sign(Uint::ONE, rhs.is_negative()).expect("+/- 1");
        x = Int::select(&x, &Int::ZERO, self_is_zero);
        y = Int::select(&y, &signum_rhs, self_is_zero);
        x = Int::select(&x, &signum_self, rhs_is_zero);
        y = Int::select(&y, &Int::ZERO, rhs_is_zero);

        // Correct the quotients in case self and/or rhs was zero.
        lhs_on_gcd = Int::select(&lhs_on_gcd, &signum_self, rhs_is_zero);
        lhs_on_gcd = Int::select(&lhs_on_gcd, &Int::ZERO, self_is_zero);
        rhs_on_gcd = Int::select(&rhs_on_gcd, &signum_rhs, self_is_zero);
        rhs_on_gcd = Int::select(&rhs_on_gcd, &Int::ZERO, rhs_is_zero);

        IntBinxgcdOutput {
            gcd,
            x,
            y,
            lhs_on_gcd,
            rhs_on_gcd,
        }
    }
}

impl<const LIMBS: usize> BinXgcd for NonZero<Int<LIMBS>> {
    type Output = NonZeroIntBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &Self) -> Self::Output {
        let (mut lhs, mut rhs) = (*self.as_ref(), *rhs.as_ref());

        // Leverage the property that gcd(2^k * a, 2^k *b) = 2^k * gcd(a, b)
        let i = lhs.as_uint().trailing_zeros();
        let j = rhs.as_uint().trailing_zeros();
        let k = const_min(i, j);
        lhs = lhs.shr(k);
        rhs = rhs.shr(k);

        // Note: at this point, either lhs or rhs is odd (or both).
        // Swap to make sure lhs is odd.
        let swap = ConstChoice::from_u32_lt(j, i);
        Int::conditional_swap(&mut lhs, &mut rhs, swap);
        let lhs = lhs.to_odd().expect("odd by construction");

        let rhs = rhs.to_nz().expect("non-zero by construction");
        let OddIntBinxgcdOutput {
            gcd,
            mut x,
            mut y,
            mut lhs_on_gcd,
            mut rhs_on_gcd,
        } = lhs.binxgcd(&rhs);

        // Account for the parameter swap
        Int::conditional_swap(&mut x, &mut y, swap);
        Int::conditional_swap(&mut lhs_on_gcd, &mut rhs_on_gcd, swap);

        // Reintroduce the factor 2^k to the gcd.
        let gcd = gcd
            .as_ref()
            .shl(k)
            .to_nz()
            .expect("is non-zero by construction");

        NonZeroIntBinxgcdOutput {
            gcd,
            x,
            y,
            lhs_on_gcd,
            rhs_on_gcd,
        }
    }
}

impl<const LIMBS: usize> BinXgcd for Odd<Int<LIMBS>> {
    type Output = OddIntBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &Self) -> Self::Output {
        self.binxgcd(rhs.as_nz_ref())
    }
}

impl<const LIMBS: usize> BinXgcd<NonZero<Int<LIMBS>>> for Odd<Int<LIMBS>> {
    type Output = OddIntBinxgcdOutput<LIMBS>;

    fn binxgcd(&self, rhs: &NonZero<Int<LIMBS>>) -> Self::Output {
        let (abs_lhs, sgn_lhs) = self.abs_sign();
        let (abs_rhs, sgn_rhs) = rhs.abs_sign();

        let OddUintBinxgcdOutput {
            gcd,
            mut x,
            mut y,
            lhs_on_gcd: abs_lhs_on_gcd,
            rhs_on_gcd: abs_rhs_on_gcd,
        } = abs_lhs.binxgcd(&abs_rhs);

        x = x.wrapping_neg_if(sgn_lhs);
        y = y.wrapping_neg_if(sgn_rhs);
        let lhs_on_gcd = Int::new_from_abs_sign(abs_lhs_on_gcd, sgn_lhs).expect("no overflow");
        let rhs_on_gcd = Int::new_from_abs_sign(abs_rhs_on_gcd, sgn_rhs).expect("no overflow");

        OddIntBinxgcdOutput {
            gcd,
            x,
            y,
            lhs_on_gcd,
            rhs_on_gcd,
        }
    }
}

/// Binary XGCD update step.
///
/// This is a condensed, constant time execution of the following algorithm:
/// ```text
/// if a mod 2 == 1
///    if a < b
///        (a, b) ← (b, a)
///        (f0, g0, f1, g1) ← (f1, g1, f0, g0)
///    a ← a - b
///    (f0, g0) ← (f0 - f1, g0 - g1)
/// if a > 0
///     a ← a/2
///     (f1, g1) ← (2f1, 2g1)
/// ```
/// where `matrix` represents
/// ```text
///  (f0 g0)
///  (f1 g1).
/// ```
///
/// Note: this algorithm assumes `b` to be an odd integer. The algorithm will likely not yield
/// the correct result when this is not the case.
///
/// Ref: Pornin, Algorithm 2, L8-17, <https://eprint.iacr.org/2020/972.pdf>.
#[inline]
pub(crate) fn binxgcd_step<const LIMBS: usize, const MATRIX_LIMBS: usize>(
    a: &mut Uint<LIMBS>,
    b: &mut Uint<LIMBS>,
    matrix: &mut BinXgcdMatrix<MATRIX_LIMBS>,
    halt_at_zero: ConstChoice,
) {
    let a_odd = a.is_odd_const();
    let a_lt_b = Uint::lt(a, b);

    // swap if a odd and a < b
    let swap = a_odd.and(a_lt_b);
    Uint::conditional_swap(a, b, swap);
    matrix.conditional_swap_rows(swap);

    // subtract b from a when a is odd
    *a = a.wrapping_sub(&Uint::select(&Uint::ZERO, b, a_odd));
    matrix.conditional_subtract_bottom_row_from_top(a_odd);

    // Div a by 2.
    let double = a.is_nonzero().or(halt_at_zero.not());
    // safe to vartime; shr_vartime is variable in the value of shift only. Since this shift
    // is a public constant, the constant time property of this algorithm is not impacted.
    *a = a.shr_vartime(1);

    // Double the bottom row of the matrix when a was ≠ 0 and when not halting.
    matrix.conditional_double_bottom_row(double);
}

#[cfg(test)]
mod tests {
    use core::ops::Div;

    use crypto_bigint::{ConcatMixed, Gcd, Int, Uint, Zero};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::helpers::binxgcd::{
        BaseIntBinxgcdOutput, BaseUintBinxgcdOutput, IntBinxgcdOutput, NonZeroIntBinxgcdOutput,
        OddIntBinxgcdOutput, OddUintBinxgcdOutput,
    };

    impl<T: Copy, const LIMBS: usize> BaseUintBinxgcdOutput<T, LIMBS> {
        /// Obtain a copy of the Bézout coefficients.
        pub const fn bezout_coefficients(&self) -> (Int<LIMBS>, Int<LIMBS>) {
            (self.x, self.y)
        }
    }

    impl<T: Copy, const LIMBS: usize> BaseIntBinxgcdOutput<T, LIMBS> {
        /// Return the quotients `lhs.gcd` and `rhs/gcd`.
        pub const fn quotients(&self) -> (Int<LIMBS>, Int<LIMBS>) {
            (self.lhs_on_gcd, self.rhs_on_gcd)
        }

        /// Return the Bézout coefficients `x` and `y` s.t. `lhs * x + rhs * y = gcd`.
        pub const fn bezout_coefficients(&self) -> (Int<LIMBS>, Int<LIMBS>) {
            (self.x, self.y)
        }
    }

    impl<const LIMBS: usize> From<NonZeroIntBinxgcdOutput<LIMBS>> for IntBinxgcdOutput<LIMBS> {
        fn from(value: NonZeroIntBinxgcdOutput<LIMBS>) -> Self {
            let NonZeroIntBinxgcdOutput {
                gcd,
                x,
                y,
                lhs_on_gcd,
                rhs_on_gcd,
            } = value;
            IntBinxgcdOutput {
                gcd: *gcd.as_ref(),
                x,
                y,
                lhs_on_gcd,
                rhs_on_gcd,
            }
        }
    }

    impl<const LIMBS: usize> From<OddIntBinxgcdOutput<LIMBS>> for IntBinxgcdOutput<LIMBS> {
        fn from(value: OddIntBinxgcdOutput<LIMBS>) -> Self {
            let OddIntBinxgcdOutput {
                gcd,
                x,
                y,
                lhs_on_gcd,
                rhs_on_gcd,
            } = value;
            IntBinxgcdOutput {
                gcd: *gcd.as_ref(),
                x,
                y,
                lhs_on_gcd,
                rhs_on_gcd,
            }
        }
    }

    pub(crate) fn make_rng() -> ChaChaRng {
        ChaChaRng::from_seed([0; 32])
    }

    fn binxgcd_test<const LIMBS: usize, const DOUBLE: usize>(
        lhs: Int<LIMBS>,
        rhs: Int<LIMBS>,
        output: IntBinxgcdOutput<LIMBS>,
    ) where
        Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        let gcd = lhs.bingcd(&rhs);
        assert_eq!(gcd, output.gcd);

        // Test quotients
        let (lhs_on_gcd, rhs_on_gcd) = output.quotients();
        if gcd.is_zero().into() {
            assert_eq!(lhs_on_gcd, Int::ZERO);
            assert_eq!(rhs_on_gcd, Int::ZERO);
        } else {
            assert_eq!(lhs_on_gcd, lhs.div_uint(&gcd.to_nz().unwrap()));
            assert_eq!(rhs_on_gcd, rhs.div_uint(&gcd.to_nz().unwrap()));
        }

        // Test the Bezout coefficients on minimality
        let (x, y) = output.bezout_coefficients();
        assert!(x.abs() <= rhs_on_gcd.abs() || rhs_on_gcd.is_zero().into());
        assert!(y.abs() <= lhs_on_gcd.abs() || lhs_on_gcd.is_zero().into());
        if lhs.abs() != rhs.abs() {
            assert!(x.abs() <= rhs_on_gcd.abs().shr(1) || rhs_on_gcd.is_zero().into());
            assert!(y.abs() <= lhs_on_gcd.abs().shr(1) || lhs_on_gcd.is_zero().into());
        }

        // Test the Bezout coefficients for correctness
        assert_eq!(
            x.concatenating_mul(&lhs)
                .wrapping_add(&y.concatenating_mul(&rhs)),
            *gcd.resize().as_int()
        );
    }

    mod test_int_binxgcd {
        use crypto_bigint::{
            ConcatMixed, Int, Random, Uint, U1024, U128, U192, U2048, U256, U384, U4096, U512, U64,
            U768, U8192,
        };

        use crate::helpers::binxgcd::tests::{binxgcd_test, make_rng};
        use crate::helpers::binxgcd::BinXgcd;

        fn int_binxgcd_test<const LIMBS: usize, const DOUBLE: usize>(
            lhs: Int<LIMBS>,
            rhs: Int<LIMBS>,
        ) where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            binxgcd_test(lhs, rhs, lhs.binxgcd(&rhs))
        }

        fn int_binxgcd_randomized_tests<const LIMBS: usize, const DOUBLE: usize>(iterations: u32)
        where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut rng = make_rng();
            for _ in 0..iterations {
                let x = Int::random(&mut rng);
                let y = Int::random(&mut rng);
                int_binxgcd_test(x, y);
            }
        }

        fn int_binxgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
        where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            int_binxgcd_test(Int::MIN, Int::MIN);
            int_binxgcd_test(Int::MIN, Int::MINUS_ONE);
            int_binxgcd_test(Int::MIN, Int::ZERO);
            int_binxgcd_test(Int::MIN, Int::ONE);
            int_binxgcd_test(Int::MIN, Int::MAX);
            int_binxgcd_test(Int::ONE, Int::MIN);
            int_binxgcd_test(Int::ONE, Int::MINUS_ONE);
            int_binxgcd_test(Int::ONE, Int::ZERO);
            int_binxgcd_test(Int::ONE, Int::ONE);
            int_binxgcd_test(Int::ONE, Int::MAX);
            int_binxgcd_test(Int::ZERO, Int::MIN);
            int_binxgcd_test(Int::ZERO, Int::MINUS_ONE);
            int_binxgcd_test(Int::ZERO, Int::ZERO);
            int_binxgcd_test(Int::ZERO, Int::ONE);
            int_binxgcd_test(Int::ZERO, Int::MAX);
            int_binxgcd_test(Int::ONE, Int::MIN);
            int_binxgcd_test(Int::ONE, Int::MINUS_ONE);
            int_binxgcd_test(Int::ONE, Int::ZERO);
            int_binxgcd_test(Int::ONE, Int::ONE);
            int_binxgcd_test(Int::ONE, Int::MAX);
            int_binxgcd_test(Int::MAX, Int::MIN);
            int_binxgcd_test(Int::MAX, Int::MINUS_ONE);
            int_binxgcd_test(Int::MAX, Int::ZERO);
            int_binxgcd_test(Int::MAX, Int::ONE);
            int_binxgcd_test(Int::MAX, Int::MAX);

            int_binxgcd_randomized_tests(100);
        }

        #[test]
        fn test_int_binxgcd() {
            int_binxgcd_tests::<{ U64::LIMBS }, { U128::LIMBS }>();
            int_binxgcd_tests::<{ U128::LIMBS }, { U256::LIMBS }>();
            int_binxgcd_tests::<{ U192::LIMBS }, { U384::LIMBS }>();
            int_binxgcd_tests::<{ U256::LIMBS }, { U512::LIMBS }>();
            int_binxgcd_tests::<{ U384::LIMBS }, { U768::LIMBS }>();
            int_binxgcd_tests::<{ U512::LIMBS }, { U1024::LIMBS }>();
            int_binxgcd_tests::<{ U1024::LIMBS }, { U2048::LIMBS }>();
            int_binxgcd_tests::<{ U2048::LIMBS }, { U4096::LIMBS }>();
            int_binxgcd_tests::<{ U4096::LIMBS }, { U8192::LIMBS }>();
        }
    }

    mod test_nonzero_int_binxgcd {
        use crypto_bigint::{
            ConcatMixed, Int, Random, Uint, U1024, U128, U192, U2048, U256, U384, U4096, U512, U64,
            U768, U8192,
        };

        use crate::helpers::binxgcd::tests::{binxgcd_test, make_rng};
        use crate::helpers::binxgcd::BinXgcd;

        fn nz_int_binxgcd_test<const LIMBS: usize, const DOUBLE: usize>(
            lhs: Int<LIMBS>,
            rhs: Int<LIMBS>,
        ) where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let output = lhs.to_nz().unwrap().binxgcd(&rhs.to_nz().unwrap());
            binxgcd_test(lhs, rhs, output.into());
        }

        fn nz_int_binxgcd_randomized_tests<const LIMBS: usize, const DOUBLE: usize>(iterations: u32)
        where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut rng = make_rng();
            for _ in 0..iterations {
                let x = *Uint::random(&mut rng).as_int();
                let y = *Uint::random(&mut rng).as_int();
                nz_int_binxgcd_test(x, y);
            }
        }

        fn nz_int_binxgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
        where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            nz_int_binxgcd_test(Int::MIN, Int::MIN);
            nz_int_binxgcd_test(Int::MIN, Int::MINUS_ONE);
            nz_int_binxgcd_test(Int::MIN, Int::ONE);
            nz_int_binxgcd_test(Int::MIN, Int::MAX);
            nz_int_binxgcd_test(Int::MINUS_ONE, Int::MIN);
            nz_int_binxgcd_test(Int::MINUS_ONE, Int::MINUS_ONE);
            nz_int_binxgcd_test(Int::MINUS_ONE, Int::ONE);
            nz_int_binxgcd_test(Int::MINUS_ONE, Int::MAX);
            nz_int_binxgcd_test(Int::ONE, Int::MIN);
            nz_int_binxgcd_test(Int::ONE, Int::MINUS_ONE);
            nz_int_binxgcd_test(Int::ONE, Int::ONE);
            nz_int_binxgcd_test(Int::ONE, Int::MAX);
            nz_int_binxgcd_test(Int::MAX, Int::MIN);
            nz_int_binxgcd_test(Int::MAX, Int::MINUS_ONE);
            nz_int_binxgcd_test(Int::MAX, Int::ONE);
            nz_int_binxgcd_test(Int::MAX, Int::MAX);

            nz_int_binxgcd_randomized_tests(100);
        }

        #[test]
        fn test_nz_int_binxgcd() {
            nz_int_binxgcd_tests::<{ U64::LIMBS }, { U128::LIMBS }>();
            nz_int_binxgcd_tests::<{ U128::LIMBS }, { U256::LIMBS }>();
            nz_int_binxgcd_tests::<{ U192::LIMBS }, { U384::LIMBS }>();
            nz_int_binxgcd_tests::<{ U256::LIMBS }, { U512::LIMBS }>();
            nz_int_binxgcd_tests::<{ U384::LIMBS }, { U768::LIMBS }>();
            nz_int_binxgcd_tests::<{ U512::LIMBS }, { U1024::LIMBS }>();
            nz_int_binxgcd_tests::<{ U1024::LIMBS }, { U2048::LIMBS }>();
            nz_int_binxgcd_tests::<{ U2048::LIMBS }, { U4096::LIMBS }>();
            nz_int_binxgcd_tests::<{ U4096::LIMBS }, { U8192::LIMBS }>();
        }
    }

    mod test_odd_int_binxgcd {
        use crypto_bigint::{
            ConcatMixed, Int, Random, Uint, U1024, U128, U192, U2048, U256, U384, U4096, U512, U64,
            U768, U8192,
        };

        use crate::helpers::binxgcd::tests::{binxgcd_test, make_rng};
        use crate::helpers::binxgcd::BinXgcd;

        fn odd_int_binxgcd_test<const LIMBS: usize, const DOUBLE: usize>(
            lhs: Int<LIMBS>,
            rhs: Int<LIMBS>,
        ) where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let output = lhs.to_odd().unwrap().binxgcd(&rhs.to_nz().unwrap());
            binxgcd_test(lhs, rhs, output.into());
        }

        fn odd_int_binxgcd_randomized_tests<const LIMBS: usize, const DOUBLE: usize>(
            iterations: u32,
        ) where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut rng = make_rng();
            for _ in 0..iterations {
                let x = Int::<LIMBS>::random(&mut rng).bitor(&Int::ONE);
                let y = Int::<LIMBS>::random(&mut rng);
                odd_int_binxgcd_test(x, y);
            }
        }

        fn odd_int_binxgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
        where
            Uint<LIMBS>: ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let neg_max = Int::MAX.wrapping_neg();
            odd_int_binxgcd_test(neg_max, neg_max);
            odd_int_binxgcd_test(neg_max, Int::MINUS_ONE);
            odd_int_binxgcd_test(neg_max, Int::ONE);
            odd_int_binxgcd_test(neg_max, Int::MAX);
            odd_int_binxgcd_test(Int::ONE, neg_max);
            odd_int_binxgcd_test(Int::ONE, Int::MINUS_ONE);
            odd_int_binxgcd_test(Int::ONE, Int::ONE);
            odd_int_binxgcd_test(Int::ONE, Int::MAX);
            odd_int_binxgcd_test(Int::MAX, neg_max);
            odd_int_binxgcd_test(Int::MAX, Int::MINUS_ONE);
            odd_int_binxgcd_test(Int::MAX, Int::ONE);
            odd_int_binxgcd_test(Int::MAX, Int::MAX);

            odd_int_binxgcd_randomized_tests(100);
        }

        #[test]
        fn test_odd_int_binxgcd() {
            odd_int_binxgcd_tests::<{ U64::LIMBS }, { U128::LIMBS }>();
            odd_int_binxgcd_tests::<{ U128::LIMBS }, { U256::LIMBS }>();
            odd_int_binxgcd_tests::<{ U192::LIMBS }, { U384::LIMBS }>();
            odd_int_binxgcd_tests::<{ U256::LIMBS }, { U512::LIMBS }>();
            odd_int_binxgcd_tests::<{ U384::LIMBS }, { U768::LIMBS }>();
            odd_int_binxgcd_tests::<{ U512::LIMBS }, { U1024::LIMBS }>();
            odd_int_binxgcd_tests::<{ U1024::LIMBS }, { U2048::LIMBS }>();
            odd_int_binxgcd_tests::<{ U2048::LIMBS }, { U4096::LIMBS }>();
            odd_int_binxgcd_tests::<{ U4096::LIMBS }, { U8192::LIMBS }>();
        }
    }

    mod test_extract_quotients {
        use crypto_bigint::{ConstChoice, Uint, U64};

        use crate::helpers::binxgcd::RawOddUintBinxgcdOutput;
        use crate::helpers::matrix::BinXgcdMatrix;

        fn raw_binxgcdoutput_setup<const LIMBS: usize>(
            matrix: BinXgcdMatrix<LIMBS>,
        ) -> RawOddUintBinxgcdOutput<LIMBS> {
            RawOddUintBinxgcdOutput {
                gcd: Uint::<LIMBS>::ONE.to_odd().unwrap(),
                matrix,
            }
        }

        #[test]
        fn test_extract_quotients_unit() {
            let output = raw_binxgcdoutput_setup(BinXgcdMatrix::<{ U64::LIMBS }>::UNIT);
            let (lhs_on_gcd, rhs_on_gcd) = output.quotients();
            assert_eq!(lhs_on_gcd, Uint::ONE);
            assert_eq!(rhs_on_gcd, Uint::ZERO);
        }

        #[test]
        fn test_extract_quotients_basic() {
            let output = raw_binxgcdoutput_setup(BinXgcdMatrix::<{ U64::LIMBS }>::new(
                Uint::ZERO,
                Uint::ZERO,
                Uint::from(5u32),
                Uint::from(7u32),
                ConstChoice::FALSE,
                0,
                0,
            ));
            let (lhs_on_gcd, rhs_on_gcd) = output.quotients();
            assert_eq!(lhs_on_gcd, Uint::from(7u32));
            assert_eq!(rhs_on_gcd, Uint::from(5u32));

            let output = raw_binxgcdoutput_setup(BinXgcdMatrix::<{ U64::LIMBS }>::new(
                Uint::ZERO,
                Uint::ZERO,
                Uint::from(7u32),
                Uint::from(5u32),
                ConstChoice::TRUE,
                0,
                0,
            ));
            let (lhs_on_gcd, rhs_on_gcd) = output.quotients();
            assert_eq!(lhs_on_gcd, Uint::from(5u32));
            assert_eq!(rhs_on_gcd, Uint::from(7u32));
        }
    }

    mod test_derive_bezout_coefficients {
        use crypto_bigint::{ConstChoice, Int, Uint, U64};

        use crate::helpers::binxgcd::RawOddUintBinxgcdOutput;
        use crate::helpers::matrix::BinXgcdMatrix;

        #[test]
        fn test_derive_bezout_coefficients_unit() {
            let mut output = RawOddUintBinxgcdOutput {
                gcd: Uint::ONE.to_odd().unwrap(),
                matrix: BinXgcdMatrix::<{ U64::LIMBS }>::UNIT,
            };
            output.remove_matrix_factors();
            let (x, y) = output.bezout_coefficients();
            assert_eq!(x, Int::ONE);
            assert_eq!(y, Int::ZERO);
        }

        #[test]
        fn test_derive_bezout_coefficients_basic() {
            let mut output = RawOddUintBinxgcdOutput {
                gcd: Uint::ONE.to_odd().unwrap(),
                matrix: BinXgcdMatrix::new(
                    U64::from(2u32),
                    U64::from(3u32),
                    U64::from(4u32),
                    U64::from(5u32),
                    ConstChoice::TRUE,
                    0,
                    0,
                ),
            };
            output.remove_matrix_factors();
            let (x, y) = output.bezout_coefficients();
            assert_eq!(x, Int::from(-2i32));
            assert_eq!(y, Int::from(2i32));

            let mut output = RawOddUintBinxgcdOutput {
                gcd: Uint::ONE.to_odd().unwrap(),
                matrix: BinXgcdMatrix::new(
                    U64::from(2u32),
                    U64::from(3u32),
                    U64::from(3u32),
                    U64::from(5u32),
                    ConstChoice::FALSE,
                    0,
                    1,
                ),
            };
            output.remove_matrix_factors();
            let (x, y) = output.bezout_coefficients();
            assert_eq!(x, Int::from(1i32));
            assert_eq!(y, Int::from(-2i32));
        }

        #[test]
        fn test_derive_bezout_coefficients_removes_doublings_easy() {
            let mut output = RawOddUintBinxgcdOutput {
                gcd: Uint::ONE.to_odd().unwrap(),
                matrix: BinXgcdMatrix::new(
                    U64::from(2u32),
                    U64::from(6u32),
                    U64::from(3u32),
                    U64::from(5u32),
                    ConstChoice::TRUE,
                    1,
                    1,
                ),
            };
            output.remove_matrix_factors();
            let (x, y) = output.bezout_coefficients();
            assert_eq!(x, Int::ONE);
            assert_eq!(y, Int::from(-3i32));

            let mut output = RawOddUintBinxgcdOutput {
                gcd: Uint::ONE.to_odd().unwrap(),
                matrix: BinXgcdMatrix::new(
                    U64::from(120u32),
                    U64::from(64u32),
                    U64::from(7u32),
                    U64::from(5u32),
                    ConstChoice::FALSE,
                    5,
                    6,
                ),
            };
            output.remove_matrix_factors();
            let (x, y) = output.bezout_coefficients();
            assert_eq!(x, Int::from(-9i32));
            assert_eq!(y, Int::from(2i32));
        }

        #[test]
        fn test_derive_bezout_coefficients_removes_doublings_for_odd_numbers() {
            let mut output = RawOddUintBinxgcdOutput {
                gcd: Uint::ONE.to_odd().unwrap(),
                matrix: BinXgcdMatrix::new(
                    U64::from(2u32),
                    U64::from(6u32),
                    U64::from(7u32),
                    U64::from(5u32),
                    ConstChoice::FALSE,
                    3,
                    7,
                ),
            };
            output.remove_matrix_factors();
            let (x, y) = output.bezout_coefficients();
            assert_eq!(x, Int::from(-2i32));
            assert_eq!(y, Int::from(2i32));
        }
    }

    mod test_partial_binxgcd {
        use crypto_bigint::{ConstChoice, Odd, U64};

        use crate::helpers::binxgcd::PartialBinXgcd;
        use crate::helpers::matrix::BinXgcdMatrix;

        const A: Odd<U64> = U64::from_be_hex("CA048AFA63CD6A1F").to_odd().expect("odd");
        const B: U64 = U64::from_be_hex("AE693BF7BE8E5566");

        #[test]
        fn test_partial_binxgcd() {
            let (.., matrix) =
                A.partial_binxgcd_vartime::<{ U64::LIMBS }>(&B, 5, ConstChoice::TRUE);
            let (.., k, _) = matrix.as_elements();
            assert_eq!(k, 5);
            assert_eq!(
                matrix,
                BinXgcdMatrix::new(
                    U64::from(8u64),
                    U64::from(4u64),
                    U64::from(2u64),
                    U64::from(5u64),
                    ConstChoice::TRUE,
                    5,
                    5
                )
            );
        }

        #[test]
        fn test_partial_binxgcd_constructs_correct_matrix() {
            let target_a = U64::from_be_hex("1CB3FB3FA1218FDB").to_odd().unwrap();
            let target_b = U64::from_be_hex("0EA028AF0F8966B6");

            let (new_a, new_b, matrix) =
                A.partial_binxgcd_vartime::<{ U64::LIMBS }>(&B, 5, ConstChoice::TRUE);

            assert_eq!(new_a, target_a);
            assert_eq!(new_b, target_b);

            let (computed_a, computed_b) = matrix.extended_apply_to((A.get(), B));
            let computed_a = computed_a.split_drop_extension().0;
            let computed_b = computed_b.split_drop_extension().0;

            assert_eq!(computed_a, target_a);
            assert_eq!(computed_b, target_b);
        }

        const SMALL_A: Odd<U64> = U64::from_be_hex("0000000003CD6A1F").to_odd().expect("odd");
        const SMALL_B: U64 = U64::from_be_hex("000000000E8E5566");

        #[test]
        fn test_partial_binxgcd_halts() {
            let (gcd, _, matrix) =
                SMALL_A.partial_binxgcd_vartime::<{ U64::LIMBS }>(&SMALL_B, 60, ConstChoice::TRUE);
            let (.., k, k_upper_bound) = matrix.as_elements();
            assert_eq!(k, 35);
            assert_eq!(k_upper_bound, 60);
            assert_eq!(gcd.get(), SMALL_A.gcd(&SMALL_B));
        }

        #[test]
        fn test_partial_binxgcd_does_not_halt() {
            let (gcd, .., matrix) =
                SMALL_A.partial_binxgcd_vartime::<{ U64::LIMBS }>(&SMALL_B, 60, ConstChoice::FALSE);
            let (.., k, k_upper_bound) = matrix.as_elements();
            assert_eq!(k, 60);
            assert_eq!(k_upper_bound, 60);
            assert_eq!(gcd.get(), SMALL_A.gcd(&SMALL_B));
        }
    }

    /// Helper function to effectively test xgcd.
    fn test_xgcd<const LIMBS: usize, const DOUBLE: usize>(
        lhs: Uint<LIMBS>,
        rhs: Uint<LIMBS>,
        output: OddUintBinxgcdOutput<LIMBS>,
    ) where
        Uint<LIMBS>:
            Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
    {
        // Test the gcd
        assert_eq!(lhs.gcd(&rhs), output.gcd, "{lhs} {rhs}");

        // Test the quotients
        assert_eq!(output.lhs_on_gcd, lhs.div(output.gcd.as_nz_ref()));
        assert_eq!(output.rhs_on_gcd, rhs.div(output.gcd.as_nz_ref()));

        // Test the Bezout coefficients for correctness
        let (x, y) = output.bezout_coefficients();
        assert_eq!(
            x.concatenating_mul_uint(&lhs) + y.concatenating_mul_uint(&rhs),
            *output.gcd.resize().as_int(),
            "{lhs:?}\n{rhs:?}"
        );

        // Test the Bezout coefficients for minimality
        assert!(x.abs() <= rhs.div(output.gcd.as_nz_ref()));
        assert!(y.abs() <= lhs.div(output.gcd.as_nz_ref()));
        if lhs != rhs {
            assert!(x.abs() <= output.rhs_on_gcd.shr(1) || output.rhs_on_gcd.is_zero().into());
            assert!(y.abs() <= output.lhs_on_gcd.shr(1) || output.lhs_on_gcd.is_zero().into());
        }
    }

    mod test_binxgcd_nz {
        use crypto_bigint::{
            ConcatMixed, Gcd, Int, RandomMod, Uint, U1024, U128, U192, U2048, U256, U384, U4096,
            U512, U64, U768, U8192,
        };

        use crate::helpers::binxgcd::tests::{make_rng, test_xgcd};
        use crate::helpers::binxgcd::BinXgcd;

        fn binxgcd_nz_test<const LIMBS: usize, const DOUBLE: usize>(
            lhs: Uint<LIMBS>,
            rhs: Uint<LIMBS>,
        ) where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let output = lhs.to_odd().unwrap().binxgcd(&rhs.to_nz().unwrap());
            test_xgcd(lhs, rhs, output);
        }

        fn binxgcd_nz_randomized_tests<const LIMBS: usize, const DOUBLE: usize>(iterations: u32)
        where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut rng = make_rng();
            let bound = Int::MIN.abs().to_nz().unwrap();
            for _ in 0..iterations {
                let x = Uint::random_mod(&mut rng, &bound).bitor(&Uint::ONE);
                let y = Uint::random_mod(&mut rng, &bound).saturating_add(&Uint::ONE);
                binxgcd_nz_test(x, y);
            }
        }

        fn binxgcd_nz_tests<const LIMBS: usize, const DOUBLE: usize>()
        where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            // Edge cases
            let odd_upper_bound = *Int::MAX.as_uint();
            let even_upper_bound = Int::MIN.abs();
            binxgcd_nz_test(Uint::ONE, Uint::ONE);
            binxgcd_nz_test(Uint::ONE, odd_upper_bound);
            binxgcd_nz_test(Uint::ONE, even_upper_bound);
            binxgcd_nz_test(odd_upper_bound, Uint::ONE);
            binxgcd_nz_test(odd_upper_bound, odd_upper_bound);
            binxgcd_nz_test(odd_upper_bound, even_upper_bound);

            binxgcd_nz_randomized_tests(100);
        }

        #[test]
        fn test_binxgcd_nz() {
            binxgcd_nz_tests::<{ U64::LIMBS }, { U128::LIMBS }>();
            binxgcd_nz_tests::<{ U128::LIMBS }, { U256::LIMBS }>();
            binxgcd_nz_tests::<{ U192::LIMBS }, { U384::LIMBS }>();
            binxgcd_nz_tests::<{ U256::LIMBS }, { U512::LIMBS }>();
            binxgcd_nz_tests::<{ U384::LIMBS }, { U768::LIMBS }>();
            binxgcd_nz_tests::<{ U512::LIMBS }, { U1024::LIMBS }>();
            binxgcd_nz_tests::<{ U1024::LIMBS }, { U2048::LIMBS }>();
            binxgcd_nz_tests::<{ U2048::LIMBS }, { U4096::LIMBS }>();
            binxgcd_nz_tests::<{ U4096::LIMBS }, { U8192::LIMBS }>();
        }
    }

    mod test_classic_binxgcd {
        use crypto_bigint::{
            ConcatMixed, Gcd, Int, Random, Uint, U1024, U128, U192, U2048, U256, U384, U4096, U512,
            U64, U768, U8192,
        };

        use crate::helpers::binxgcd::tests::{make_rng, test_xgcd};
        use crate::helpers::binxgcd::ClassicBinXgcd;

        fn classic_binxgcd_test<const LIMBS: usize, const DOUBLE: usize>(
            lhs: Uint<LIMBS>,
            rhs: Uint<LIMBS>,
        ) where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut output = lhs
                .to_odd()
                .unwrap()
                .classic_binxgcd(&rhs.to_odd().unwrap());
            test_xgcd(lhs, rhs, output.process());
        }

        fn classic_binxgcd_randomized_tests<const LIMBS: usize, const DOUBLE: usize>(
            iterations: u32,
        ) where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut rng = make_rng();
            for _ in 0..iterations {
                let x = Uint::<LIMBS>::random(&mut rng).bitor(&Uint::ONE);
                let y = Uint::<LIMBS>::random(&mut rng).bitor(&Uint::ONE);
                classic_binxgcd_test(x, y);
            }
        }

        fn classic_binxgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
        where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            // Edge cases
            let upper_bound = *Int::MAX.as_uint();
            classic_binxgcd_test(Uint::ONE, Uint::ONE);
            classic_binxgcd_test(Uint::ONE, upper_bound);
            classic_binxgcd_test(upper_bound, Uint::ONE);
            classic_binxgcd_test(upper_bound, upper_bound);

            classic_binxgcd_randomized_tests(100);
        }

        #[test]
        fn test_classic_binxgcd() {
            classic_binxgcd_tests::<{ U64::LIMBS }, { U128::LIMBS }>();
            classic_binxgcd_tests::<{ U128::LIMBS }, { U256::LIMBS }>();
            classic_binxgcd_tests::<{ U192::LIMBS }, { U384::LIMBS }>();
            classic_binxgcd_tests::<{ U256::LIMBS }, { U512::LIMBS }>();
            classic_binxgcd_tests::<{ U384::LIMBS }, { U768::LIMBS }>();
            classic_binxgcd_tests::<{ U512::LIMBS }, { U1024::LIMBS }>();
            classic_binxgcd_tests::<{ U1024::LIMBS }, { U2048::LIMBS }>();
            classic_binxgcd_tests::<{ U2048::LIMBS }, { U4096::LIMBS }>();
            classic_binxgcd_tests::<{ U4096::LIMBS }, { U8192::LIMBS }>();
        }
    }

    mod test_optimized_binxgcd {
        use crypto_bigint::RandomMod;
        use crypto_bigint::{
            ConcatMixed, Gcd, Int, Uint, U1024, U128, U192, U2048, U256, U384, U4096, U512, U64,
            U768, U8192,
        };

        use crate::helpers::binxgcd::tests::{make_rng, test_xgcd};
        use crate::helpers::binxgcd::{
            OptimizedBinXgcd, DOUBLE_SUMMARY_LIMBS, SUMMARY_BITS, SUMMARY_LIMBS,
        };
        use crate::helpers::tools::Compact;

        fn optimized_binxgcd_test<const LIMBS: usize, const DOUBLE: usize>(
            lhs: Uint<LIMBS>,
            rhs: Uint<LIMBS>,
        ) where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut output = lhs
                .to_odd()
                .unwrap()
                .optimized_binxgcd(&rhs.to_odd().unwrap());
            test_xgcd(lhs, rhs, output.process());
        }

        fn optimized_binxgcd_randomized_tests<const LIMBS: usize, const DOUBLE: usize>(
            iterations: u32,
        ) where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            let mut rng = make_rng();
            let bound = Int::MIN.abs().to_nz().unwrap();
            for _ in 0..iterations {
                let x = Uint::<LIMBS>::random_mod(&mut rng, &bound).bitor(&Uint::ONE);
                let y = Uint::<LIMBS>::random_mod(&mut rng, &bound).bitor(&Uint::ONE);
                optimized_binxgcd_test(x, y);
            }
        }

        fn optimized_binxgcd_tests<const LIMBS: usize, const DOUBLE: usize>()
        where
            Uint<LIMBS>:
                Gcd<Output = Uint<LIMBS>> + ConcatMixed<Uint<LIMBS>, MixedOutput = Uint<DOUBLE>>,
        {
            // Edge cases
            let upper_bound = *Int::MAX.as_uint();
            optimized_binxgcd_test(Uint::ONE, Uint::ONE);
            optimized_binxgcd_test(Uint::ONE, upper_bound);
            optimized_binxgcd_test(upper_bound, Uint::ONE);
            optimized_binxgcd_test(upper_bound, upper_bound);

            optimized_binxgcd_randomized_tests(100);
        }

        #[test]
        fn test_optimized_binxgcd_edge_cases() {
            // If one of these tests fails, you have probably tweaked the SUMMARY_BITS,
            // SUMMARY_LIMBS or DOUBLE_SUMMARY_LIMBS settings. Please make sure to update these
            // tests accordingly.
            assert_eq!(SUMMARY_BITS, 64);
            assert_eq!(SUMMARY_LIMBS, U64::LIMBS);
            assert_eq!(DOUBLE_SUMMARY_LIMBS, U128::LIMBS);

            // Case #1: a > b but a.compact() < b.compact()
            let a = U256::from_be_hex(
                "1234567890ABCDEF80000000000000000000000000000000BEDCBA0987654321",
            );
            let b = U256::from_be_hex(
                "1234567890ABCDEF800000000000000000000000000000007EDCBA0987654321",
            );
            assert!(a > b);
            assert!(
                a.compact::<SUMMARY_BITS, DOUBLE_SUMMARY_LIMBS>(U256::BITS)
                    < b.compact::<SUMMARY_BITS, DOUBLE_SUMMARY_LIMBS>(U256::BITS)
            );
            optimized_binxgcd_test(a, b);

            // Case #2: a < b but a.compact() > b.compact()
            optimized_binxgcd_test(b, a);

            // Case #3: a > b but a.compact() = b.compact()
            let a = U256::from_be_hex(
                "1234567890ABCDEF80000000000000000000000000000000FEDCBA0987654321",
            );
            let b = U256::from_be_hex(
                "1234567890ABCDEF800000000000000000000000000000007EDCBA0987654321",
            );
            assert!(a > b);
            assert_eq!(
                a.compact::<SUMMARY_BITS, DOUBLE_SUMMARY_LIMBS>(U256::BITS),
                b.compact::<SUMMARY_BITS, DOUBLE_SUMMARY_LIMBS>(U256::BITS)
            );
            optimized_binxgcd_test(a, b);

            // Case #4: a < b but a.compact() = b.compact()
            optimized_binxgcd_test(b, a);
        }

        #[test]
        fn test_optimized_binxgcd() {
            optimized_binxgcd_tests::<{ U128::LIMBS }, { U256::LIMBS }>();
            optimized_binxgcd_tests::<{ U192::LIMBS }, { U384::LIMBS }>();
            optimized_binxgcd_tests::<{ U256::LIMBS }, { U512::LIMBS }>();
            optimized_binxgcd_tests::<{ U384::LIMBS }, { U768::LIMBS }>();
            optimized_binxgcd_tests::<{ U512::LIMBS }, { U1024::LIMBS }>();
            optimized_binxgcd_tests::<{ U1024::LIMBS }, { U2048::LIMBS }>();
            optimized_binxgcd_tests::<{ U2048::LIMBS }, { U4096::LIMBS }>();
            optimized_binxgcd_tests::<{ U4096::LIMBS }, { U8192::LIMBS }>();
        }
    }
}
