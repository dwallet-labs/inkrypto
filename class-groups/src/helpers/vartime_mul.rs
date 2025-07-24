// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::subtle::CtOption;
use crypto_bigint::{ConcatMixed, Int, Limb, Uint, Zero};

use crate::helpers::limbs::Limbs;

#[inline(always)]
const fn modified_schoolbook_multiplication(
    lhs: &[Limb],
    rhs: &[Limb],
    lo: &mut [Limb],
    hi: &mut [Limb],
) {
    if lhs.len() + rhs.len() > lo.len() + hi.len() {
        panic!("schoolbook multiplication length mismatch");
    }

    let mut i = 0;
    while i < lhs.len() {
        let mut j = 0;
        let mut carry = Limb::ZERO;
        let xi = lhs[i];

        while j < rhs.len() {
            let k = i + j;

            if k >= lo.len() {
                (hi[k - lo.len()], carry) = xi.carrying_mul_add(rhs[j], hi[k - lo.len()], carry);
            } else {
                (lo[k], carry) = xi.carrying_mul_add(rhs[j], lo[k], carry);
            }

            j += 1;
        }

        if i + j >= lo.len() {
            hi[i + j - lo.len()] = carry;
        } else {
            lo[i + j] = carry;
        }
        i += 1;
    }
}

/// Helper method to perform schoolbook multiplication
#[inline]
pub const fn modified_uint_mul_limbs<const LIMBS: usize, const RHS_LIMBS: usize>(
    lhs: &[Limb],
    rhs: &[Limb],
) -> (Uint<LIMBS>, Uint<RHS_LIMBS>) {
    debug_assert!(lhs.len() + rhs.len() <= LIMBS + RHS_LIMBS);
    let mut lo: Uint<LIMBS> = Uint::<LIMBS>::ZERO;
    let mut hi = Uint::<RHS_LIMBS>::ZERO;
    modified_schoolbook_multiplication(lhs, rhs, lo.as_mut_limbs(), hi.as_mut_limbs());
    (lo, hi)
}

pub(crate) trait BoundedWideningMul<Rhs = Self>: Sized {
    type Output;

    fn bounded_widening_mul(
        &self,
        rhs: &Rhs,
        lhs_limbs_bound: usize,
        rhs_limbs_bound: usize,
    ) -> Self::Output;
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize> BoundedWideningMul<Uint<RHS_LIMBS>>
    for Uint<LHS_LIMBS>
{
    type Output = (Uint<LHS_LIMBS>, Uint<RHS_LIMBS>);

    fn bounded_widening_mul(
        &self,
        rhs: &Uint<RHS_LIMBS>,
        lhs_limbs_bound: usize,
        rhs_limbs_bound: usize,
    ) -> Self::Output {
        modified_uint_mul_limbs(
            &self.as_limbs()[..lhs_limbs_bound],
            &rhs.as_limbs()[..rhs_limbs_bound],
        )
    }
}

pub(crate) trait WideningMulVartime<Rhs = Self>: Sized {
    type Output;

    fn widening_mul_vartime(&self, rhs: &Rhs) -> Self::Output;
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize> WideningMulVartime<Uint<RHS_LIMBS>>
    for Uint<LHS_LIMBS>
{
    type Output = (Uint<LHS_LIMBS>, Uint<RHS_LIMBS>);

    fn widening_mul_vartime(&self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        self.bounded_widening_mul(rhs, self.limbs_vartime(), rhs.limbs_vartime())
    }
}

pub(crate) trait ConcatenatingMulVartime<Rhs = Self>: Sized {
    type Output;

    fn concatenating_mul_vartime(&self, rhs: &Rhs) -> Self::Output;
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize, const WIDE_LIMBS: usize>
    ConcatenatingMulVartime<Uint<RHS_LIMBS>> for Uint<LHS_LIMBS>
where
    Self: ConcatMixed<Uint<RHS_LIMBS>, MixedOutput = Uint<WIDE_LIMBS>>,
{
    type Output = Uint<WIDE_LIMBS>;

    fn concatenating_mul_vartime(&self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        let (lo, hi) = self.widening_mul_vartime(rhs);
        Uint::concat_mixed(&lo, &hi)
    }
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize, const WIDE_LIMBS: usize>
    ConcatenatingMulVartime<Uint<RHS_LIMBS>> for Int<LHS_LIMBS>
where
    Uint<LHS_LIMBS>: ConcatMixed<Uint<RHS_LIMBS>, MixedOutput = Uint<WIDE_LIMBS>>,
{
    type Output = Int<WIDE_LIMBS>;

    fn concatenating_mul_vartime(&self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        let (abs_lhs, lhs_is_negative) = self.abs_sign();
        let product_abs = abs_lhs.concatenating_mul_vartime(rhs);
        *product_abs.wrapping_neg_if(lhs_is_negative).as_int()
    }
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize, const WIDE_LIMBS: usize>
    ConcatenatingMulVartime<Int<RHS_LIMBS>> for Int<LHS_LIMBS>
where
    Uint<LHS_LIMBS>: ConcatMixed<Uint<RHS_LIMBS>, MixedOutput = Uint<WIDE_LIMBS>>,
{
    type Output = Int<WIDE_LIMBS>;

    fn concatenating_mul_vartime(&self, rhs: &Int<RHS_LIMBS>) -> Int<WIDE_LIMBS> {
        let (lhs_abs, lhs_is_negative) = self.abs_sign();
        let (rhs_abs, rhs_is_negative) = rhs.abs_sign();
        let product_abs = lhs_abs.concatenating_mul_vartime(&rhs_abs);
        let product_is_negative = lhs_is_negative.xor(rhs_is_negative);
        *product_abs.wrapping_neg_if(product_is_negative).as_int()
    }
}

pub(crate) trait CheckedMulVartime<Rhs = Self>: Sized {
    type Output;

    fn checked_mul_vartime(&self, rhs: &Rhs) -> Self::Output;
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize> CheckedMulVartime<Uint<RHS_LIMBS>>
    for Uint<LHS_LIMBS>
{
    type Output = CtOption<Self>;

    fn checked_mul_vartime(&self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        let (lo, hi) = self.widening_mul_vartime(rhs);
        CtOption::new(lo, hi.is_zero())
    }
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize> CheckedMulVartime<Int<RHS_LIMBS>>
    for Uint<LHS_LIMBS>
{
    type Output = CtOption<Int<LHS_LIMBS>>;

    fn checked_mul_vartime(&self, rhs: &Int<RHS_LIMBS>) -> CtOption<Int<LHS_LIMBS>> {
        let (abs_rhs, rhs_is_negative) = rhs.abs_sign();
        self.checked_mul_vartime(&abs_rhs)
            .map(|res| *res.wrapping_neg_if(rhs_is_negative).as_int())
    }
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize> CheckedMulVartime<Int<RHS_LIMBS>>
    for Int<LHS_LIMBS>
{
    type Output = CtOption<Int<LHS_LIMBS>>;

    fn checked_mul_vartime(&self, rhs: &Int<RHS_LIMBS>) -> Self::Output {
        let (abs_lhs, lhs_is_negative) = self.abs_sign();
        let (abs_rhs, rhs_is_negative) = rhs.abs_sign();
        let res_is_negative = lhs_is_negative.xor(rhs_is_negative);
        abs_lhs
            .checked_mul_vartime(&abs_rhs)
            .map(|res| *res.wrapping_neg_if(res_is_negative).as_int())
    }
}

impl<const LHS_LIMBS: usize, const RHS_LIMBS: usize> CheckedMulVartime<Uint<RHS_LIMBS>>
    for Int<LHS_LIMBS>
{
    type Output = CtOption<Int<LHS_LIMBS>>;

    fn checked_mul_vartime(&self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        let (abs_lhs, lhs_is_negative) = self.abs_sign();
        abs_lhs
            .checked_mul_vartime(rhs)
            .map(|res| *res.wrapping_neg_if(lhs_is_negative).as_int())
    }
}
