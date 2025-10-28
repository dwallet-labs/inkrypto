// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{div3by2, ConstChoice, Int, Limb, NonZero, Reciprocal, Uint};

use crate::helpers::limbs::Limbs;

pub(crate) trait FullVartimeDiv<Rhs = Self>: Sized {
    type Quotient;
    type Remainder;

    fn div_rem_full_vartime(&self, rhs: &Rhs) -> (Self::Quotient, Self::Remainder);

    fn div_full_vartime(&self, rhs: &Rhs) -> Self::Quotient {
        self.div_rem_full_vartime(rhs).0
    }

    fn rem_full_vartime(&self, rhs: &Rhs) -> Self::Remainder {
        self.div_rem_full_vartime(rhs).1
    }
}

impl<const NUM_LIMBS: usize, const DENOM_LIMBS: usize> FullVartimeDiv<NonZero<Uint<DENOM_LIMBS>>>
    for Uint<NUM_LIMBS>
{
    type Quotient = Self;
    type Remainder = Uint<DENOM_LIMBS>;

    fn div_rem_full_vartime(
        &self,
        denominator: &NonZero<Uint<DENOM_LIMBS>>,
    ) -> (Self::Quotient, Self::Remainder) {
        // Based on Section 4.3.1, of The Art of Computer Programming, Volume 2, by Donald E. Knuth.
        // Further explanation at https://janmr.com/blog/2014/04/basic-multiple-precision-long-division/
        let numerator_limbs = self.limbs_vartime();
        let denominator_bits = denominator.as_ref().bits_vartime();
        let denominator_limbs = denominator_bits.div_ceil(Limb::BITS) as usize;

        // Short circuit for small or extra large divisors
        if denominator_limbs == 1 {
            // If the divisor is a single limb, use limb division
            let (q, r) = self.div_rem_limb_with_reciprocal(&Reciprocal::new(
                denominator.as_limbs()[0].to_nz().expect("zero divisor"),
            ));
            return (q, Uint::from_word(r.0));
        }
        if denominator_limbs > numerator_limbs {
            // Divisor is greater than dividend. Return zero and the dividend as the
            // quotient and remainder
            return (Uint::ZERO, self.resize::<DENOM_LIMBS>());
        }

        // The shift needed to set the MSB of the highest nonzero limb of the divisor.
        // 2^shift == d in the algorithm above.
        let shift = (Limb::BITS - (denominator_bits % Limb::BITS)) % Limb::BITS;

        let (x, mut x_hi) = self.shl_limb_vartime(shift, numerator_limbs);
        let mut x = x.to_limbs();
        let (y, _) = denominator
            .as_ref()
            .shl_limb_vartime(shift, denominator_limbs);
        let mut y = y.to_limbs();

        let reciprocal = Reciprocal::new(y[denominator_limbs - 1].to_nz().expect("zero divisor"));

        let mut i;

        let mut xi = numerator_limbs - 1;

        loop {
            // Divide high dividend words by the high divisor word to estimate the quotient word
            let mut quo = div3by2(
                x_hi.0,
                x[xi].0,
                x[xi - 1].0,
                &reciprocal,
                y[denominator_limbs - 2].0,
            );

            // Subtract q*divisor from the dividend
            let borrow = {
                let mut carry = Limb::ZERO;
                let mut borrow = Limb::ZERO;
                let mut tmp;
                i = 0;
                while i < denominator_limbs {
                    (tmp, carry) = y[i].carrying_mul_add(Limb(quo), Limb::ZERO, carry);
                    (x[xi + i + 1 - denominator_limbs], borrow) =
                        x[xi + i + 1 - denominator_limbs].borrowing_sub(tmp, borrow);
                    i += 1;
                }
                (_, borrow) = x_hi.borrowing_sub(carry, borrow);
                borrow
            };

            // If the subtraction borrowed, then decrement q and add back the divisor
            // The probability of this being needed is very low, about 2/(Limb::MAX+1)
            quo = {
                let ct_borrow = ConstChoice::from_word_mask(borrow.0);
                let mut carry = Limb::ZERO;
                i = 0;
                while i < denominator_limbs {
                    (x[xi + i + 1 - denominator_limbs], carry) = x[xi + i + 1 - denominator_limbs]
                        .carrying_add(Limb::select(Limb::ZERO, y[i], ct_borrow), carry);
                    i += 1;
                }
                ct_borrow.select_word(quo, quo.wrapping_sub(1))
            };

            // Store the quotient within dividend and set x_hi to the current highest word
            x_hi = x[xi];
            x[xi] = Limb(quo);

            if xi == denominator_limbs - 1 {
                break;
            }
            xi -= 1;
        }

        // Copy the remainder to divisor
        i = 0;
        while i < denominator_limbs - 1 {
            y[i] = x[i];
            i += 1;
        }
        y[denominator_limbs - 1] = x_hi;

        // Unshift the remainder from the earlier adjustment
        let y = Uint::new(y).shr_limb_vartime(shift, denominator_limbs);

        // Shift the quotient to the low limbs within dividend
        i = 0;
        while i < numerator_limbs {
            if i <= (numerator_limbs - denominator_limbs) {
                x[i] = x[i + denominator_limbs - 1];
            } else {
                x[i] = Limb::ZERO;
            }
            i += 1;
        }

        (Uint::new(x), y)
    }
}

impl<const NUM_LIMBS: usize, const DENOM_LIMBS: usize> FullVartimeDiv<NonZero<Uint<DENOM_LIMBS>>>
    for NonZero<Uint<NUM_LIMBS>>
{
    type Quotient = Uint<NUM_LIMBS>;
    type Remainder = Uint<DENOM_LIMBS>;

    fn div_rem_full_vartime(
        &self,
        rhs: &NonZero<Uint<DENOM_LIMBS>>,
    ) -> (Self::Quotient, Self::Remainder) {
        self.as_ref().div_rem_full_vartime(rhs)
    }
}

trait BaseFullVartimeDiv<Rhs = Self>: Sized {
    type Output;

    fn div_rem_base_full_vartime(&self, rhs: &Rhs) -> Self::Output;
}

impl<const NUM_LIMBS: usize, const DENOM_LIMBS: usize>
    BaseFullVartimeDiv<NonZero<Uint<DENOM_LIMBS>>> for Int<NUM_LIMBS>
{
    type Output = (Uint<NUM_LIMBS>, Uint<DENOM_LIMBS>, ConstChoice);

    fn div_rem_base_full_vartime(&self, rhs: &NonZero<Uint<DENOM_LIMBS>>) -> Self::Output {
        let (lhs_mag, lhs_sgn) = self.abs_sign();
        let (quotient, remainder) = lhs_mag.div_rem_full_vartime(rhs);
        (quotient, remainder, lhs_sgn)
    }
}

impl<const NUM_LIMBS: usize, const DENOM_LIMBS: usize> FullVartimeDiv<NonZero<Uint<DENOM_LIMBS>>>
    for Int<NUM_LIMBS>
{
    type Quotient = Self;
    type Remainder = Int<DENOM_LIMBS>;

    fn div_rem_full_vartime(
        &self,
        rhs: &NonZero<Uint<DENOM_LIMBS>>,
    ) -> (Self::Quotient, Self::Remainder) {
        let (quotient, remainder, lhs_sgn) = Self::div_rem_base_full_vartime(self, rhs);
        (
            quotient.as_int().wrapping_neg_if(lhs_sgn),
            remainder.as_int().wrapping_neg_if(lhs_sgn),
        )
    }
}

trait DivToFlooredDiv<Denominator = Self>: Sized {
    type Denominator;
    type Quotient;
    type Remainder;
    type Output;

    fn div_uint_to_floored_div_uint(
        denominator: &Self::Denominator,
        quotient: Self::Quotient,
        remainder: Self::Remainder,
        numerator_sgn: ConstChoice,
    ) -> Self::Output;
}

impl<const NUM_LIMBS: usize, const DENOM_LIMBS: usize> DivToFlooredDiv<Int<DENOM_LIMBS>>
    for Int<NUM_LIMBS>
{
    type Denominator = NonZero<Uint<DENOM_LIMBS>>;
    type Quotient = Uint<NUM_LIMBS>;
    type Remainder = Uint<DENOM_LIMBS>;
    type Output = (Self, Uint<DENOM_LIMBS>);

    fn div_uint_to_floored_div_uint(
        denominator: &Self::Denominator,
        quotient: Self::Quotient,
        remainder: Self::Remainder,
        numerator_sgn: ConstChoice,
    ) -> Self::Output {
        // Increase the quotient by one when the numerator is negative and there is a non-zero remainder.
        let modify = remainder.is_nonzero().and(numerator_sgn);
        let quotient = Uint::select(&quotient, &quotient.wrapping_add(&Uint::ONE), modify);

        // Invert the remainder when self is negative and there is a non-zero remainder.
        let remainder = Uint::select(&remainder, &denominator.wrapping_sub(&remainder), modify);

        // Negate if applicable
        let quotient = quotient.as_int().wrapping_neg_if(numerator_sgn);

        (quotient, remainder)
    }
}

pub(crate) trait FullVartimeFlooredDiv<Rhs = Self>: Sized {
    type Output;

    /// Fully variable time equivalent of [Self::div_rem_floor_uint].
    ///
    /// This is variable with respect to both `self` and `rhs`.
    fn div_rem_floor_full_vartime(&self, rhs: &Rhs) -> Self::Output;
}

impl<const NUM_LIMBS: usize, const DENOM_LIMBS: usize>
    FullVartimeFlooredDiv<NonZero<Uint<DENOM_LIMBS>>> for Int<NUM_LIMBS>
{
    type Output = (Self, Uint<DENOM_LIMBS>);

    fn div_rem_floor_full_vartime(&self, rhs: &NonZero<Uint<DENOM_LIMBS>>) -> Self::Output {
        let (quotient, remainder, numerator_sgn) = self.div_rem_base_full_vartime(rhs);
        Self::div_uint_to_floored_div_uint(rhs, quotient, remainder, numerator_sgn)
    }
}
