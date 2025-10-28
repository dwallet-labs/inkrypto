// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::mem;
use std::ops::Mul;

use crypto_bigint::subtle::{ConditionallySelectable, ConstantTimeLess, CtOption};
use crypto_bigint::{
    CheckedMul, CheckedSub, Concat, ConstChoice, Encoding, Int, IntXgcdOutput, NonZero,
    NonZeroUintXgcdOutput, Split, Uint, I128,
};

use crate::helpers::partial_xgcd::PartialXGCD;
use crate::helpers::vartime_div::{FullVartimeDiv, FullVartimeFlooredDiv};
use crate::helpers::vartime_mul::{CheckedMulVartime, ConcatenatingMulVartime};
use crate::ibqf::unreduced::UnreducedIbqf;
use crate::ibqf::{math, Ibqf, PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD};
use crate::Error;

impl<const HALF: usize, const LIMBS: usize, const DOUBLE: usize> Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<LIMBS>>,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    /// Inverse compose `self` with `rhs`, i.e, `self / rhs`.
    ///
    /// ### Panics
    /// May panic if `self` and `rhs` do not have the same discriminant
    pub fn nucompinv(&self, rhs: Self) -> Self {
        self.nucomp(rhs.inverse())
    }

    /// Variable time equivalent of [Ibqf::nucompinv].
    ///
    /// ### Panics
    /// May panic if `self` and `rhs` do not have the same discriminant
    pub fn nucompinv_vartime(&self, rhs: &Self) -> Self {
        self.nucomp_vartime(rhs.inverse())
    }

    /// Compose two quadratic forms, i.e., `self * rhs`.
    /// Assumes both forms have the same discriminant and are reduced.
    ///
    /// Ref: [Binary Quadratic Forms, Section 6.1.1](https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf).
    ///
    /// The composite of primitive forms is still primitive.
    /// Ref: Pg. 242 in "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    ///
    /// ### Panics
    /// May panic if `self` and `rhs` do not have the same discriminant
    pub fn nucomp(&self, rhs: Self) -> Self {
        self.nucomp_unreduced::<false, false>(rhs)
            .into_option()
            .ok_or(Error::InvalidParameters)
            .unwrap()
            .reduce()
    }

    /// Variant of [Ibqf::nucomp] that assumes both `self` and `rhs` are random forms.
    /// In particular, this means that
    /// - the bit lengths of their `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - the faster [Ibqf::reduce_randomized] operation can be used to reduce the output.
    ///
    /// ### Panics
    /// May panic
    /// - if `self` and `rhs` do not have the same discriminant, or
    /// - if either form is not randomized.
    pub fn nucomp_randomized(&self, rhs: Self) -> Self {
        self.nucomp_unreduced::<true, false>(rhs)
            .into_option()
            .ok_or(Error::InvalidParameters)
            .unwrap()
            .reduce_randomized()
            .into_option()
            .ok_or(Error::FormNotRandomized)
            .unwrap()
    }

    /// Variant of [Ibqf::nucomp_randomized] that additionally assumes `self ≠ base`.
    ///
    /// ### Panics
    /// May panic if
    /// - `self = rhs`,
    /// - `self` and `rhs` do not have the same discriminant, or
    /// - either form is not randomized.
    pub fn nucomp_randomized_pair(&self, rhs: Self) -> Self {
        self.nucomp_unreduced::<true, true>(rhs)
            .into_option()
            .ok_or(Error::InvalidParameters)
            .unwrap()
            .reduce_randomized()
            .into_option()
            .ok_or(Error::FormNotRandomized)
            .unwrap()
    }

    /// Variable time equivalent of [Ibqf::nucomp].
    ///
    /// ### Panics
    /// May panic if `self` and `rhs` do not have the same discriminant
    pub fn nucomp_vartime(&self, rhs: Self) -> Self {
        self.nucomp_unreduced_vartime(rhs)
            .expect("can compose forms")
            .reduce_vartime()
            .expect("can reduce composed forms")
    }

    /// Non-reduced core for [Ibqf::nucomp].
    #[allow(non_snake_case)]
    pub(crate) fn nucomp_unreduced<const RANDOMIZED: bool, const RANDOMIZED_PAIR: bool>(
        mut self,
        mut rhs: Self,
    ) -> CtOption<UnreducedIbqf<LIMBS>> {
        // Arrange `self` and `rhs` such that `self.a > rhs.a`
        let do_swap = self.a.ct_lt(&rhs.a);
        Ibqf::conditional_swap(&mut self, &mut rhs, do_swap);

        // Since this form is assumed reduced, a is positive and smaller than ║∆║/2.
        let a1 = self.a.as_uint().resize::<HALF>().to_nz().unwrap();
        let a2 = rhs.a.as_uint().resize::<HALF>().to_nz().unwrap();

        // Since this form is assumed reduced, |b| is smaller than ║∆║/2.
        let b1 = self.b.resize::<HALF>();
        let b2 = rhs.b.resize::<HALF>();

        // Since this form is assumed reduced, c is positive.
        let c1 = self.c.as_uint();
        let c2 = rhs.c.as_uint();

        let s = CtOption::from(b1.checked_add(&b2))
            .map(|b1_b2| b1_b2.shr_vartime(1))
            .expect("no overflow; b < a < |Δ|/2");
        let m = b2.checked_sub(&s).expect("no overflow; b < a < |Δ|/2");

        // a1 * u + a2 * v = gcd(a1, a2);
        let NonZeroUintXgcdOutput {
            gcd: gcd_a1_a2,
            x: u,
            y: v,
            lhs_on_gcd: a1_div_gcd_a1_a2,
            rhs_on_gcd: a2_div_gcd_a1_a2,
        } = a1.xgcd(&a2);

        let IntXgcdOutput {
            gcd: gcd_a1_a2_s,
            x: Y,
            lhs_on_gcd: s_div_gcd_a1_a2_s,
            rhs_on_gcd: gcd_a1_a2_div_gcd_a1_a2_s,
            ..
        } = if RANDOMIZED_PAIR {
            assert!(*gcd_a1_a2 <= *I128::MAX.resize::<HALF>().as_uint());

            let (s_div_gcd, s_mod_gcd) = s.div_rem_uint(&gcd_a1_a2);
            let s_mod_gcd_ = s_mod_gcd.resize::<{ I128::LIMBS }>();
            let gcd_a1_a2_ = gcd_a1_a2.resize::<{ I128::LIMBS }>();

            // Compute xgcd(s mod gcd, gcd)
            let IntXgcdOutput {
                gcd,
                x,
                lhs_on_gcd,
                rhs_on_gcd,
                ..
            } = s_mod_gcd_.xgcd(gcd_a1_a2_.as_int());

            // Reconstruct xgcd(s, gcd) from xgcd(s mod gcd, gcd)
            IntXgcdOutput {
                // > gcd is correct; gcd(a, b) = gcd(a mod b, b) = G
                gcd: gcd.resize::<HALF>(),
                // > x is correct: (a - qb)·x + b·y = a·x + b·(y-qx) = G
                x: x.resize::<HALF>(),
                // > we do not care about y;
                y: Int::ZERO,
                // > s/gcd(a1,a2,s) needs to be modified:
                //   a/G = a/G - qb/G + qb/G = (a-qb)/G + qb/G = (a mod b)/G + q·b/G
                lhs_on_gcd: lhs_on_gcd
                    .resize::<HALF>()
                    .wrapping_add(&s_div_gcd.mul(&rhs_on_gcd)),
                // > gcd(a1,a2)/gcd(a1,a2,s) is correct.
                rhs_on_gcd: rhs_on_gcd.resize::<HALF>(),
            }
        } else {
            s.xgcd(gcd_a1_a2.as_int())
        };

        let w = gcd_a1_a2_div_gcd_a1_a2_s
            .as_uint()
            .to_nz()
            .expect("division of a non-zero value by a proper divisor is non-zero");

        // [ Ax; Ay ] = [ gcd(a1, a2, s); 0 ]
        let Ax = gcd_a1_a2_s
            .to_nz()
            .expect("gcd of at least one non-zero value is non-zero");

        // [ Bx; By ] = [ (((c1v + c2u) * Y * By) % w + mv ) / w; gcd(a1, a2) / gcd(a1, a2, s) ]
        let By = gcd_a1_a2_div_gcd_a1_a2_s
            .checked_mul(&a1_div_gcd_a1_a2)
            .expect("no overflow; result is smaller than a1")
            .as_uint()
            .to_nz()
            .expect("division of a non-zero value by a proper divisor is non-zero");
        let vc1 = c1
            .checked_mul_int(&v)
            .expect("no overflow; v * c1 < a1 * c1 < |Δ|");
        let uc2 = c2
            .checked_mul_int(&u)
            .expect("no overflow; u * c2 < a2 * c2 < |Δ|");
        let Bx = CtOption::from(vc1.checked_add(&uc2))
            .map(|x| x.rem_uint(&w))
            .map(|x| x.concatenating_mul(&Y))
            .map(|x| x.rem_uint(&w))
            .map(|x| x.concatenating_mul_uint(&By))
            .and_then(|x| x.checked_add(&m.concatenating_mul(&v)).into())
            .map(|x| x.div_uint(&w))
            .expect("no overflow; is smaller than |Δ|");

        // [ Cx; Cy ] = [ 0; a2 / gcd(a1, a2, s) ]
        let Cy = gcd_a1_a2_div_gcd_a1_a2_s
            .checked_mul(&a2_div_gcd_a1_a2)
            .expect("no overflow; result is smaller than a1")
            .as_uint()
            .to_nz()
            .expect("division of a non-zero value by a proper divisor is non-zero");

        // [ Dx; Dy ] = [ 0; s / gcd(a1, a2, s) ]
        let Dy = s_div_gcd_a1_a2_s;

        // Update Bx and By.
        let threshold = self.nucomp_partial_reduction_threshold(a1.as_ref(), a2.as_ref());
        let threshold_lower_bound = self.partial_reduction_lower_bound();
        let bits_upper_bound = self.discriminant_bits.div_ceil(2);

        let (_, Bx) = Bx.div_rem_floor_uint(&By);
        let (Bx, new_By, matrix) = if RANDOMIZED {
            let (Bx, new_By, matrix, _) = Bx
                .partial_xgcd_bounded_randomized_with_bounded_threshold(
                    &By,
                    bits_upper_bound,
                    threshold,
                    threshold_lower_bound,
                );
            (Bx, new_By, matrix)
        } else {
            Bx.bounded_partial_xgcd_with_bounded_threshold(
                &By,
                bits_upper_bound,
                threshold,
                threshold_lower_bound,
            )
        };

        let (adjugate, negate) = matrix.adjugate();
        assert_eq!(negate, ConstChoice::FALSE);
        let (.., neg_m10, m00) = adjugate;

        // Multiply matrix with [ Ax; Ay ]
        let (Ax, Ay) = (
            m00.concatenating_mul(&Ax)
                .try_into_int()
                .expect("no overflow; << |Δ|"),
            neg_m10
                .concatenating_mul(&Ax)
                .try_into_int()
                .expect("no overflow; << |Δ|")
                .checked_neg()
                .expect("no overflow; << |Δ|"),
        );

        // Update Cx and Cy
        let Cx = CtOption::from(Bx.concatenating_mul(&Cy).try_into_int())
            .and_then(|BxCy| BxCy.checked_sub(&m.concatenating_mul_uint(&m00)))
            .map(|BxCy_m11m| BxCy_m11m.div_uint(&By));
        let Cy = CtOption::from(new_By.concatenating_mul(&a2).try_into_int())
            .and_then(|ByA2| Ay.checked_mul(&m).and_then(|mAy| ByA2.checked_sub(&mAy)))
            .map(|ByA2_mAy| ByA2_mAy.div_uint(&a1));

        // Update Dx and Dy
        let (lo, hi) = c2.widening_mul(&m00);
        let hi = hi.resize::<LIMBS>();
        let m00c2 = *lo.concat(&hi).as_int();

        let Dx = Dy
            .concatenating_mul_uint(&Bx)
            .resize::<DOUBLE>()
            .checked_sub(&m00c2)
            .map(|DyBx_sub_m00c2| DyBx_sub_m00c2.div_uint(&By))
            .map(|Dy| Dy.resize::<LIMBS>());
        let m00_nz = CtOption::from(m00.to_nz());
        let Dy = Dx
            .and_then(|Dx| {
                let (lo, hi, sgn) = Dx.widening_mul_uint(&neg_m10);
                let hi = hi.resize::<LIMBS>();
                Int::new_from_abs_sign(lo.concat(&hi), sgn).into()
            })
            .and_then(|neg_m10Dx| Dy.resize::<DOUBLE>().checked_sub(&neg_m10Dx))
            .and_then(|Dy_plus_m10Dx| m00_nz.map(|m00_nz| Dy_plus_m10Dx.div_uint(&m00_nz)))
            .map(|Dy| Dy.resize::<LIMBS>());

        // Compute AxDx, AyDy and AxDy + AyDx using only three multiplications.
        let (AxDx, AxDy_AyDx, AyDy) = math::three_way_mul(Ax, Ay, Dx, Dy);
        // Compute BxCx, ByCy and BxCy + ByCx using only three multiplications.
        let (BxCx, BxCy_ByCx, ByCy) = math::three_way_mul_uint(Bx, new_By, Cx, Cy);

        // A = Cy * By - Dy * Ay
        let a = ByCy
            .and_then(|ByCy| AyDy.and_then(|AyDy| ByCy.checked_sub(&AyDy)))
            .and_then(|a| a.to_nz().into());
        // B = Ax * Dy + Ay * Dx - Cy * Bx - Cx * By
        let b = AxDy_AyDx.and_then(|AxDy_AyDx| {
            BxCy_ByCx.and_then(|BxCy_ByCx| AxDy_AyDx.checked_sub(&BxCy_ByCx))
        });
        // C = Cx * Bx - Ax * Dx
        let c = BxCx
            .and_then(|BxCx| AxDx.and_then(|AxDx| BxCx.checked_sub(&AxDx)))
            .and_then(|c| c.to_nz().into());

        a.and_then(|a| {
            b.and_then(|b| {
                c.map(|c| UnreducedIbqf {
                    a,
                    b,
                    c,
                    discriminant_bits: self.discriminant_bits,
                })
            })
        })
    }

    /// Vartime implementation of non-reduced core for [Ibqf::nucomp].
    ///
    /// Here, `L` should be the group-constant `log2((|∆/4|)^(1/4)) = log2(|∆/4|)/4`, rounded up
    /// to the nearest multiple of `Word::SIZE`.
    ///
    /// This is an adaptation of [`BICYCL`'s `nucomp` implementation](https://gite.lirmm.fr/crypto/bicycl/-/blob/68f62cc/src/bicycl/arith/qfi.inl#L689).
    #[allow(non_snake_case)]
    pub(crate) fn nucomp_unreduced_vartime(
        mut self,
        mut rhs: Self,
    ) -> Result<UnreducedIbqf<LIMBS>, Error> {
        // Arrange `self` and `rhs` such that `self.a > rhs.a`
        if self.a < rhs.a {
            mem::swap(&mut self, &mut rhs)
        }

        // Since this form is assumed reduced, a is positive and smaller than ║∆║/2.
        let a1 = self.a.as_uint().resize::<HALF>().to_nz().unwrap();
        let a2 = rhs.a.as_uint().resize::<HALF>().to_nz().unwrap();

        // Since this form is assumed reduced, |b| is smaller than ║∆║/2.
        let b1 = self.b.resize::<HALF>();
        let b2 = rhs.b.resize::<HALF>();

        // Since this form is assumed reduced, c is positive.
        let c1 = self.c.as_uint();
        let c2 = rhs.c.as_uint();

        let s = CtOption::from(b1.checked_add(&b2))
            .map(|b1_b2| b1_b2.shr_vartime(1))
            .into_option()
            .ok_or(Error::InternalError)?;
        let m = b2
            .checked_sub(&s)
            .into_option()
            .ok_or(Error::InternalError)?;

        // a1 * U + a2 * V = F = gcd(a1, a2);
        let (F, U, V, a1_div_F, a2_div_F) = math::xgcd_vartime(a1, *a2);
        // [ Ax; Ay ] = [ gcd(a1, a2, g); 0 ]
        let (Ax, Bx, By, Cy) = if F == NonZero::ONE || s.rem_uint_vartime(&F) == Int::ZERO {
            (F, m.concatenating_mul(&V), a1_div_F, a2_div_F)
        } else {
            let (Ax, Y, w) = math::half_int_xgcd_vartime(s, F);

            // safe to unwrap; Ax is a divisor of non-zero F and non-zero a1.
            let By = a1.div_rem_vartime(&Ax).0.to_nz().unwrap();

            // Bx = {[(c1 * V + C2 * U) * Y * By] % w + h * V} / w
            let Bx = c1
                .checked_mul_vartime(&V)
                .and_then(|c1V| {
                    c2.checked_mul_vartime(&U)
                        .and_then(|c2U| c2U.checked_add(&c1V).into())
                })
                .map(|x| x.rem_full_vartime(&w))
                .map(|x| x.concatenating_mul_vartime(&Y))
                .map(|x| x.rem_full_vartime(&w))
                .map(|x| x.concatenating_mul_vartime(By.as_ref()))
                .and_then(|x| x.checked_add(&m.concatenating_mul_vartime(&V)).into())
                .map(|x| x.div_full_vartime(&w))
                .into_option()
                .ok_or(Error::InternalError)?;

            let (Cy, _) = a2.div_rem_vartime(&Ax);

            (Ax, Bx, By, Cy)
        };
        let Dy = s.div_uint_vartime(&Ax);

        // Update Bx and By.
        // Note: we have to account for the spread of the partial xgcd vartime output bit size.
        let threshold = self.nucomp_partial_reduction_threshold(a1.as_ref(), a2.as_ref())
            + PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD / 2;

        let (_, Bx) = Bx.div_rem_floor_full_vartime(&By);
        let ((.., m10, m11), Bx, new_By) = math::partial_xgcd_vartime(Bx, *By, threshold);

        // Update Ax and Ay
        let (Ax, Ay) = (
            m11.concatenating_mul_vartime(&Ax),
            CtOption::from(m10.concatenating_mul_vartime(&Ax).as_int().checked_neg())
                .into_option()
                .ok_or(Error::InternalError)?,
        );

        // Update Cx and Cy
        let Cx = CtOption::from(Bx.concatenating_mul_vartime(&Cy).try_into_int())
            .and_then(|BxCy| BxCy.checked_sub(&m.concatenating_mul_vartime(&m11)))
            .map(|BxCy_m11m| BxCy_m11m.div_full_vartime(&By))
            .into_option()
            .ok_or(Error::InternalError)?;
        let Cy = if Bx == Uint::ZERO {
            CtOption::from(new_By.concatenating_mul_vartime(&a2).try_into_int())
                .and_then(|ByA2| {
                    Ay.checked_mul_vartime(&m)
                        .and_then(|mAy| ByA2.checked_sub(&mAy))
                })
                .map(|ByA2_mAy| ByA2_mAy.div_full_vartime(&a1))
                .into_option()
                .ok_or(Error::InternalError)?
        } else {
            let Bx_nz = Bx.to_nz().expect("Bx is non-zero due to if-statement");
            Cx.checked_mul_vartime(&new_By)
                .and_then(|CxBy| CxBy.checked_add(&m.resize::<LIMBS>()).into())
                .map(|CxBy_m| CxBy_m.div_full_vartime(&Bx_nz))
                .into_option()
                .ok_or(Error::InternalError)?
        };

        /* Update Dx and Dy */
        let m11c2 = *m11.resize::<LIMBS>().concatenating_mul_vartime(c2).as_int();
        let Dx = Dy
            .concatenating_mul_uint(&Bx)
            .resize::<DOUBLE>()
            .wrapping_sub(&m11c2)
            .div_full_vartime(&By)
            .resize::<LIMBS>();

        let m11_nz = CtOption::from(m11.to_nz())
            .into_option()
            .ok_or(Error::InternalError)?;
        let Dy = Dy
            .resize::<DOUBLE>()
            .wrapping_sub(&Dx.concatenating_mul_vartime(&m10.resize::<LIMBS>()))
            .div_full_vartime(&m11_nz)
            .resize::<LIMBS>();

        // Compute AxDx, AyDy and AxDy + AyDx using only three multiplications.
        let (AxDx, AxDy_AyDx, AyDy) = math::three_way_mul_vartime(*Ax.as_int(), Ay, Dx, Dy)?;
        // Compute BxCx, ByCy and BxCy + ByCx using only three multiplications.
        let (BxCx, BxCy_ByCx, ByCy) = math::three_way_mul_vartime(
            Cx,
            Cy,
            CtOption::from(Bx.try_into_int())
                .into_option()
                .ok_or(Error::InternalError)?,
            CtOption::from(new_By.try_into_int())
                .into_option()
                .ok_or(Error::InternalError)?,
        )?;

        // A = Cy * By - Dy * Ay
        let a = ByCy
            .checked_sub(&AyDy)
            .and_then(|a| a.to_nz().into())
            .into_option()
            .ok_or(Error::InternalError)?;
        // B = Ax * Dy + Ay * Dx - Cy * Bx - Cx * By
        let b = AxDy_AyDx
            .checked_sub(&BxCy_ByCx)
            .into_option()
            .ok_or(Error::InternalError)?;
        // C = Cx * Bx - Ax * Dx
        let c = BxCx
            .checked_sub(&AxDx)
            .and_then(|c| c.to_nz().into())
            .into_option()
            .ok_or(Error::InternalError)?;

        Ok(UnreducedIbqf {
            a,
            b,
            c,
            discriminant_bits: self.discriminant_bits,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::discriminant::Discriminant;
    use crate::ibqf::test_helpers::{
        get_deterministic_secp256k1_form, get_deterministic_secp256k1_forms, Ibqf128,
    };
    use crate::ibqf::Ibqf;
    use crypto_bigint::I128;

    #[test]
    fn test_nucomp_forms_with_prime_discriminant_maintains_discriminant() {
        // This test case involves forms with a discriminant ∆ = -503.
        // Note that
        //  ∆ = 1 mod 4, and
        // -∆ = 503 (prime, and thus square free)

        let discriminant = (503, 0, 1);
        let f1 = Ibqf::new_reduced_64(9, 17, discriminant).unwrap();
        let f2 = Ibqf::new_reduced_64(4, 5, discriminant).unwrap();

        let discriminant = Discriminant::<{ I128::LIMBS }>::new_u64(503, 0, 1).unwrap();
        assert_eq!(f1.discriminant().unwrap(), discriminant.get());
        assert_eq!(f2.discriminant().unwrap(), discriminant.get());

        let f3 = f1.nucomp(f2);
        assert_eq!(f3.discriminant().unwrap(), discriminant.get());
    }

    #[test]
    fn test_nucompinv_is_inverse_of_nucomp() {
        let discriminant = (7, 0, 317);
        let f1 = Ibqf128::new_reduced_64(23, 9, discriminant).unwrap();
        let f2 = Ibqf128::new_reduced_64(3, 13, discriminant).unwrap();

        let f3 = f1.nucomp(f2).nucompinv(f2);
        assert_eq!(f3, f1);

        let f3 = f1.nucompinv(f2).nucomp(f2);
        assert_eq!(f3, f1);

        let f3 = f1.nucomp(f1).nucompinv(f1);
        assert_eq!(f3, f1);

        let f3 = f1.nucompinv(f1).nucomp(f1);
        assert_eq!(f3, f1);

        let f3 = f2.nucompinv(f1).nucomp(f1);
        assert_eq!(f3, f2);

        let f3 = f2.nucomp(f1).nucompinv(f1);
        assert_eq!(f3, f2);

        let f3 = f2.nucompinv(f2).nucomp(f2);
        assert_eq!(f3, f2);

        let f3 = f2.nucomp(f2).nucompinv(f2);
        assert_eq!(f3, f2);
    }

    #[test]
    fn test_nucomp() {
        let (form, double, triple) = get_deterministic_secp256k1_forms();
        assert_eq!(form.nucomp(double), triple);
    }

    #[test]
    fn test_nucomp_randomized() {
        let (form, double, triple) = get_deterministic_secp256k1_forms();
        assert_eq!(form.nucomp_randomized(double), triple);
    }

    #[test]
    fn test_nucomp_randomized_pair() {
        let (form, double, triple) = get_deterministic_secp256k1_forms();
        assert_eq!(form.nucomp_randomized_pair(double), triple);
    }

    #[test]
    fn test_nucomp_vartime() {
        let (form, double, triple) = get_deterministic_secp256k1_forms();
        assert_eq!(form.nucomp_vartime(double), triple);
    }

    #[test]
    fn test_nucomp_forms_with_1_mod_4_discriminant_maintains_discriminant() {
        // This test case involves forms with a discriminant ∆ = -2219.
        // Note that
        //  ∆ = 1 mod 4, and
        // -∆ = 2 * 317 (and thus square free)

        let discriminant = (7, 0, 317);
        let f1 = Ibqf::new_reduced_64(23, 9, discriminant).unwrap();
        let f2 = Ibqf::new_reduced_64(3, 13, discriminant).unwrap();

        let discriminant = Discriminant::<{ I128::LIMBS }>::new_u64(7, 0, 317).unwrap();
        assert_eq!(f2.discriminant().unwrap(), discriminant.get());
        assert_eq!(f1.discriminant().unwrap(), discriminant.get());

        let f3 = f1.nucomp(f2);
        assert_eq!(f3.discriminant().unwrap(), discriminant.get());
    }

    #[test]
    fn test_nucomp_forms_with_0_mod_4_discriminant_maintains_discriminant() {
        // This test case involves forms with a discriminant ∆ = -2868.
        // Note that
        //  ∆ = 0 mod 4
        //  ∆/4 = 3 mod 4, and
        // -∆ = 3 * 239 (and thus square free)

        let discriminant = (239, 0, 12);
        let f1 = Ibqf::new_reduced_64(11, 16, discriminant).unwrap();
        let f2 = Ibqf::new_reduced_64(7, 4, discriminant).unwrap();

        let discriminant = Discriminant::<{ I128::LIMBS }>::new_u64(239, 0, 12).unwrap();
        assert_eq!(f1.discriminant().unwrap(), discriminant.get());
        assert_eq!(f2.discriminant().unwrap(), discriminant.get());

        let f3 = f1.nucomp(f2);
        assert_eq!(f3.discriminant().unwrap(), discriminant.get());
    }

    #[test]
    fn test_nucomp_reduces() {
        let discriminant = (239, 0, 12);
        let f1 = Ibqf::new_reduced_64(11, 16, discriminant).unwrap();
        let f2 = Ibqf::new_reduced_64(7, 4, discriminant).unwrap();

        let discriminant = Discriminant::<{ I128::LIMBS }>::new_u64(239, 0, 12).unwrap();
        assert_eq!(f1.discriminant().unwrap(), discriminant.get());
        assert_eq!(f2.discriminant().unwrap(), discriminant.get());

        let f3 = f1.nucomp(f2);
        let target = Ibqf::from_64(21, -18, 38);
        assert_eq!(f3, target);
    }

    #[test]
    fn test_ct_vs_vartime() {
        const COUNT: usize = 50;
        let form = get_deterministic_secp256k1_form();

        let (mut ct_res, mut vt_res) = (form, form);
        for _ in 0..COUNT {
            ct_res = ct_res.nucomp(form);
            vt_res = vt_res.nucomp_vartime(form);
            assert_eq!(vt_res, ct_res);
        }
    }

    #[test]
    #[should_panic]
    fn test_randomized_pair() {
        let form = get_deterministic_secp256k1_form();
        form.nucomp_randomized_pair(form);
    }

    #[test]
    fn test_randomized_vs_randomized_pair() {
        let form = get_deterministic_secp256k1_form();

        let (mut rt_res, mut rt_pair_res) = (form.nudupl_vartime(), form.nudupl_vartime());
        for _ in 0..50 {
            rt_res = rt_res.nucomp_randomized(form);
            rt_pair_res = rt_pair_res.nucomp_randomized_pair(form);
            assert_eq!(rt_pair_res, rt_res);
        }
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::hint::black_box;

    use criterion::measurement::WallTime;
    use criterion::BenchmarkGroup;
    use crypto_bigint::{Concat, Encoding, Int, Split, Uint};

    use crate::EquivalenceClass;

    pub(crate) fn benchmark_nucomp<const HALF: usize, const LIMBS: usize, const DOUBLE: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        form: EquivalenceClass<LIMBS>,
    ) where
        Int<LIMBS>: Encoding,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>,
        Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        let form = *form.representative();
        let other = form.nudupl();
        let unit = form.unit();
        g.bench_function("nucomp (unreduced, ct)", |b| {
            b.iter(|| {
                black_box(form.nucomp_unreduced::<false, false>(other).unwrap());
            })
        });
        g.bench_function("nucomp (unreduced, rt)", |b| {
            b.iter(|| {
                black_box(form.nucomp_unreduced::<true, false>(other).unwrap());
            })
        });
        g.bench_function("nucomp (unreduced, rt-pair)", |b| {
            b.iter(|| {
                black_box(form.nucomp_unreduced::<true, true>(other).unwrap());
            })
        });
        g.bench_function("nucomp (unreduced, vt)", |b| {
            b.iter(|| {
                black_box(form.nucomp_unreduced_vartime(other).unwrap());
            })
        });
        g.bench_function("nucomp(unit) (unreduced, vt)", |b| {
            b.iter(|| {
                black_box(form.nucomp_unreduced_vartime(unit).unwrap());
            })
        });

        let mut other = form;
        g.bench_function("nucomp (reduced, ct)", |b| {
            b.iter(|| {
                other = other.nucomp(form);
            })
        });
        g.bench_function("nucomp (reduced, rt)", |b| {
            b.iter(|| {
                other = other.nucomp_randomized(form);
            })
        });
        g.bench_function("nucomp (reduced, rt-pair)", |b| {
            b.iter(|| {
                other = other.nucomp_randomized_pair(form);
            })
        });
        g.bench_function("nucomp (reduced, vt)", |b| {
            b.iter(|| {
                other = other.nucomp_vartime(form);
            })
        });
        g.bench_function("nucomp(unit) (reduced, vt)", |b| {
            b.iter(|| {
                other = other.nucomp_vartime(unit);
            })
        });
    }
}
