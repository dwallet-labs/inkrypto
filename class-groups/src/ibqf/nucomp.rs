// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::subtle::CtOption;
use crypto_bigint::{
    CheckedAdd, CheckedMul, CheckedSub, Concat, ConstChoice, Encoding, Gcd, Int, IntBinxgcdOutput,
    InvMod, NonZero, NonZeroUintBinxgcdOutput, Split, Uint,
};

use crate::ibqf::{math, Ibqf, PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD};
use crate::Error;

impl<const HALF: usize, const LIMBS: usize, const DOUBLE_LIMBS: usize> Ibqf<LIMBS>
where
    Int<HALF>: InvMod<Modulus = NonZero<Uint<HALF>>, Output = Uint<HALF>>,
    Uint<HALF>: Concat<Output = Uint<LIMBS>>
        + Gcd<Output = Uint<HALF>>
        + InvMod<Modulus = Uint<HALF>, Output = Uint<HALF>>,

    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>> + Split<Output = Uint<HALF>>,

    Int<DOUBLE_LIMBS>: Encoding,
    Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    /// Inverse compose `self` with `rhs`, i.e, `self / rhs`.
    pub fn nucompinv(&self, rhs: &Self) -> Result<Self, Error> {
        self.nucomp(&rhs.inverse())
    }

    /// Variable time equivalent of [Ibqf::nucompinv].
    pub fn nucompinv_vartime(&self, rhs: &Self) -> Result<Self, Error> {
        self.nucomp_vartime(&rhs.inverse())
    }

    /// Compose two quadratic forms, i.e., `self * rhs`.
    /// Assumes both forms have the same discriminant and are reduced.
    ///
    /// Ref: [Binary Quadratic Forms, Section 6.1.1](https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf).
    ///
    /// The composite of primitive forms is still primitive.
    /// Ref: Pg. 242 in "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    pub fn nucomp(&self, rhs: &Self) -> Result<Self, Error> {
        self.nucomp_unreduced(rhs)
            .into_option()
            .ok_or(Error::InternalError)?
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
    pub fn nucomp_randomized(&self, rhs: &Self) -> Result<Self, Error> {
        // TODO: utilize a `partial_xgcd` algorithm that leverages the random input assumption
        self.nucomp_unreduced(rhs)
            .into_option()
            .ok_or(Error::InternalError)?
            .reduce_randomized()
    }

    /// Variable time equivalent of [Ibqf::nucomp].
    pub fn nucomp_vartime(&self, rhs: &Self) -> Result<Self, Error> {
        self.nucomp_unreduced_vartime(rhs)?.reduce_vartime()
    }

    /// Non-reduced core for [Ibqf::nucomp].
    #[allow(non_snake_case)]
    pub(crate) fn nucomp_unreduced(&self, rhs: &Self) -> CtOption<Self> {
        // Since this form is assumed reduced, a is positive and smaller than ║∆║/2.
        let a1 = self.a.as_uint().resize::<HALF>().to_nz().unwrap();
        let a2 = rhs.a.as_uint().resize::<HALF>().to_nz().unwrap();

        // Since this form is assumed reduced, |b| is smaller than ║∆║/2.
        let b1 = self.b.resize::<HALF>();
        let b2 = rhs.b.resize::<HALF>();

        // Since this form is assumed reduced, c is positive.
        let c1 = self.c.as_uint();
        let c2 = rhs.c.as_uint();

        let s = b1
            .checked_add(&b2)
            .map(|b1_b2| b1_b2.shr_vartime(1))
            .expect("no overflow; b < a < |Δ|/2");
        let m = b2.checked_sub(&s).expect("no overflow; b < a < |Δ|/2");

        // a1 * u + a2 * v = gcd(a1, a2);
        let NonZeroUintBinxgcdOutput {
            gcd: gcd_a1_a2,
            x: u,
            y: v,
            lhs_on_gcd: a1_div_gcd_a1_a2,
            rhs_on_gcd: a2_div_gcd_a1_a2,
        } = a1.binxgcd(&a2);

        let IntBinxgcdOutput {
            gcd: gcd_a1_a2_s,
            x: Y,
            lhs_on_gcd: s_div_gcd_a1_a2_s,
            rhs_on_gcd: gcd_a1_a2_div_gcd_a1_a2_s,
            ..
        } = s.binxgcd(&gcd_a1_a2.as_int());

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
            .checked_mul_uint(&a1_div_gcd_a1_a2)
            .expect("no overflow; result is smaller than a1")
            .as_uint()
            .to_nz()
            .expect("division of a non-zero value by a proper divisor is non-zero");
        let vc1 = v
            .checked_mul_uint_right(c1)
            .expect("no overflow; v * c1 < a1 * c1 < |Δ|");
        let uc2 = u
            .checked_mul_uint_right(c2)
            .expect("no overflow; u * c2 < a2 * c2 < |Δ|");
        let Bx = vc1
            .checked_add(&uc2)
            .map(|x| x.rem_uint(&w))
            .map(|x| x.widening_mul(&Y))
            .map(|x| x.rem_uint(&w))
            .map(|x| x.widening_mul_uint(&By))
            .and_then(|x| x.checked_add(&m.widening_mul(&v)))
            .map(|x| x.div_uint(&w))
            .expect("no overflow; is smaller than |Δ|");

        // [ Cx; Cy ] = [ 0; a2 / gcd(a1, a2, s) ]
        let Cy = gcd_a1_a2_div_gcd_a1_a2_s
            .checked_mul_uint(&a2_div_gcd_a1_a2)
            .expect("no overflow; result is smaller than a1")
            .as_uint()
            .to_nz()
            .expect("division of a non-zero value by a proper divisor is non-zero");

        // [ Dx; Dy ] = [ 0; s / gcd(a1, a2, s) ]
        let Dy = s_div_gcd_a1_a2_s;

        // Update Bx and By.
        let bits_upper_bound = self.discriminant_bits.div_ceil(2);
        let threshold = self.partial_reduction_bound();
        let (_, Bx) = Bx.div_rem_floor_uint(&By);
        let (Bx, new_By, matrix) = Bx.bounded_partial_xgcd(&By, threshold, bits_upper_bound);

        let (adjugate, negate) = matrix.adjugate();
        assert_eq!(negate, ConstChoice::FALSE);
        let (.., neg_m10, m00) = adjugate;

        // Multiply matrix with [ Ax; Ay ]
        let (Ax, Ay) = (
            m00.widening_mul(&Ax).to_int().expect("no overflow; << |Δ|"),
            neg_m10
                .widening_mul(&Ax)
                .to_int()
                .expect("no overflow; << |Δ|")
                .checked_neg()
                .expect("no overflow; << |Δ|"),
        );

        // Update Cx and Cy
        let Cx = CtOption::from(Bx.widening_mul(&Cy).to_int())
            .and_then(|BxCy| BxCy.checked_sub(&m.widening_mul_uint(&m00)))
            .map(|BxCy_m11m| BxCy_m11m.div_uint(&By));
        let Cy = CtOption::from(new_By.widening_mul(&a2).to_int())
            .and_then(|ByA2| Ay.checked_mul(&m).and_then(|mAy| ByA2.checked_sub(&mAy)))
            .map(|ByA2_mAy| ByA2_mAy.div_uint(&a1));

        // Update Dx and Dy
        let (lo, hi) = c2.split_mul(&m00);
        let hi = hi.resize::<LIMBS>();
        let m00c2 = lo.concat(&hi).as_int();

        let Dx = Dy
            .widening_mul_uint(&Bx)
            .resize::<DOUBLE_LIMBS>()
            .checked_sub(&m00c2)
            .map(|DyBx_sub_m00c2| DyBx_sub_m00c2.div_uint(&By))
            .map(|Dy| Dy.resize::<LIMBS>());
        let m00_nz = CtOption::from(m00.to_nz());
        let Dy = Dx
            .and_then(|Dx| {
                let (lo, hi, sgn) = Dx.split_mul_uint(&neg_m10);
                let hi = hi.resize::<LIMBS>();
                Int::new_from_abs_sign(lo.concat(&hi), sgn).into()
            })
            .and_then(|neg_m10Dx| Dy.resize::<DOUBLE_LIMBS>().checked_sub(&neg_m10Dx))
            .and_then(|Dy_plus_m10Dx| m00_nz.map(|m00_nz| Dy_plus_m10Dx.div_uint(&m00_nz)))
            .map(|Dy| Dy.resize::<LIMBS>());

        // Compute AxDx, AyDy and AxDy + AyDx using only three multiplications.
        let (AxDx, AxDy_AyDx, AyDy) = math::three_way_mul(Ax, Ay, Dx, Dy);
        // Compute BxCx, ByCy and BxCy + ByCx using only three multiplications.
        let (BxCx, BxCy_ByCx, ByCy) = math::three_way_mul_uint(Bx, new_By, Cx, Cy);

        // A = Cy * By - Dy * Ay
        let a = ByCy.and_then(|ByCy| AyDy.and_then(|AyDy| ByCy.checked_sub(&AyDy)));
        // B = Ax * Dy + Ay * Dx - Cy * Bx - Cx * By
        let b = AxDy_AyDx.and_then(|AxDy_AyDx| {
            BxCy_ByCx.and_then(|BxCy_ByCx| AxDy_AyDx.checked_sub(&BxCy_ByCx))
        });
        // C = Cx * Bx - Ax * Dx
        let c = BxCx.and_then(|BxCx| AxDx.and_then(|AxDx| BxCx.checked_sub(&AxDx)));

        a.and_then(|a| a.to_nz().into()).and_then(|a| {
            b.and_then(|b| {
                c.and_then(|c| c.to_nz().into()).map(|c| Ibqf {
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
    pub(crate) fn nucomp_unreduced_vartime(&self, rhs: &Self) -> Result<Self, Error> {
        // Since this form is assumed reduced, a is positive and smaller than ║∆║/2.
        let a1 = self.a.as_uint().resize::<HALF>().to_nz().unwrap();
        let a2 = rhs.a.as_uint().resize::<HALF>().to_nz().unwrap();

        // Since this form is assumed reduced, |b| is smaller than ║∆║/2.
        let b1 = self.b.resize::<HALF>();
        let b2 = rhs.b.resize::<HALF>();

        // Since this form is assumed reduced, c is positive.
        let c1 = self.c.as_uint();
        let c2 = rhs.c.as_uint();

        let s = b1
            .checked_add(&b2)
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
            (F, m.widening_mul(&V), a1_div_F, a2_div_F)
        } else {
            let (Ax, Y, w) = math::half_int_xgcd_vartime(s, F);

            // safe to unwrap; Ax is a divisor of non-zero F and non-zero a1.
            let By = a1.div_rem_vartime(&Ax).0.to_nz().unwrap();

            // Bx = {[(c1 * V + C2 * U) * Y * By] % w + h * V} / w
            let Bx = V
                .checked_mul_uint_right_vartime(c1)
                .and_then(|c1V| {
                    U.checked_mul_uint_right_vartime(c2)
                        .and_then(|c2U| c2U.checked_add(&c1V))
                })
                .map(|x| x.rem_uint_full_vartime(&w))
                .map(|x| x.widening_mul(&Y))
                .map(|x| x.rem_uint_full_vartime(&w))
                .map(|x| x.widening_mul_uint(&By))
                .and_then(|x| x.checked_add(&m.widening_mul(&V)))
                .map(|x| x.div_uint_full_vartime(&w))
                .into_option()
                .ok_or(Error::InternalError)?;

            let (Cy, _) = a2.div_rem_vartime(&Ax);

            (Ax, Bx, By, Cy)
        };
        let Dy = s.div_uint_vartime(&Ax);

        // Update Bx and By.
        // Note: we have to account for the spread of the partial xgcd vartime output bit size.
        let threshold =
            self.partial_reduction_bound() + PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD / 2;
        let (_, Bx) = Bx.div_rem_floor_uint_vartime(&By);
        let ((.., m10, m11), Bx, new_By) = math::partial_xgcd_vartime(Bx, *By, threshold);

        // Update Ax and Ay
        let (Ax, Ay) = (
            m11.widening_mul_vartime(&Ax),
            CtOption::from(m10.widening_mul_vartime(&Ax).as_int().checked_neg())
                .into_option()
                .ok_or(Error::InternalError)?,
        );

        // Update Cx and Cy
        let Cx = CtOption::from(Bx.widening_mul_vartime(&Cy).to_int())
            .and_then(|BxCy| BxCy.checked_sub(&m.widening_mul_uint_vartime(&m11)))
            .map(|BxCy_m11m| BxCy_m11m.div_uint_full_vartime(&By))
            .into_option()
            .ok_or(Error::InternalError)?;
        let Cy = if Bx == Uint::ZERO {
            CtOption::from(new_By.widening_mul_vartime(&a2).to_int())
                .and_then(|ByA2| {
                    Ay.checked_mul_vartime(&m)
                        .and_then(|mAy| ByA2.checked_sub(&mAy))
                })
                .map(|ByA2_mAy| ByA2_mAy.div_uint_full_vartime(&a1))
                .into_option()
                .ok_or(Error::InternalError)?
        } else {
            // safe to unwrap; Bx is non-zero due to if-statement.
            let Bx_nz = Bx.to_nz().unwrap();
            Cx.checked_mul_uint_vartime(&new_By)
                .and_then(|CxBy| CxBy.checked_add(&m.resize::<LIMBS>()))
                .map(|CxBy_m| CxBy_m.div_uint_full_vartime(&Bx_nz))
                .into_option()
                .ok_or(Error::InternalError)?
        };

        /* Update Dx and Dy */
        let m11c2 = m11.resize::<LIMBS>().widening_mul_vartime(c2).as_int();
        let Dx = Dy
            .widening_mul_uint(&Bx)
            .resize::<DOUBLE_LIMBS>()
            .wrapping_sub(&m11c2)
            .div_uint_full_vartime(&By)
            .resize::<LIMBS>();

        let m11_nz = CtOption::from(m11.to_nz())
            .into_option()
            .ok_or(Error::InternalError)?;
        let Dy = Dy
            .resize::<DOUBLE_LIMBS>()
            .wrapping_sub(&Dx.widening_mul_uint_vartime(&m10.resize::<LIMBS>()))
            .div_uint_full_vartime(&m11_nz)
            .resize::<LIMBS>();

        // Compute AxDx, AyDy and AxDy + AyDx using only three multiplications.
        let (AxDx, AxDy_AyDx, AyDy) = math::three_way_mul_vartime(Ax.as_int(), Ay, Dx, Dy)?;
        // Compute BxCx, ByCy and BxCy + ByCx using only three multiplications.
        let (BxCx, BxCy_ByCx, ByCy) = math::three_way_mul_vartime(
            Cx,
            Cy,
            CtOption::from(Bx.to_int())
                .into_option()
                .ok_or(Error::InternalError)?,
            CtOption::from(new_By.to_int())
                .into_option()
                .ok_or(Error::InternalError)?,
        )?;

        // A = Cy * By - Dy * Ay
        let a = ByCy - AyDy;
        // B = Ax * Dy + Ay * Dx - Cy * Bx - Cx * By
        let b = AxDy_AyDx - BxCy_ByCx;
        // C = Cx * Bx - Ax * Dx
        let c = BxCx - AxDx;

        Ok(Ibqf {
            a: CtOption::from(a.to_nz())
                .into_option()
                .ok_or(Error::InternalError)?,
            b,
            c: CtOption::from(c.to_nz())
                .into_option()
                .ok_or(Error::InternalError)?,
            discriminant_bits: self.discriminant_bits,
        })
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::I128;

    use crate::ibqf::Ibqf;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;

    #[test]
    fn test_nucomp_forms_with_prime_discriminant_maintains_discriminant() {
        // This test case involves forms with a discriminant ∆ = -503.
        // Note that
        //  ∆ = 1 mod 4, and
        // -∆ = 503 (prime, and thus square free)

        let discriminant = I128::from_i32(-503).to_nz().unwrap().try_into().unwrap();
        let f1 = Ibqf::new_reduced(
            I128::from_i32(9).to_nz().unwrap(),
            I128::from_i32(17),
            &discriminant,
        )
        .unwrap();
        let f2 = Ibqf::new_reduced(
            I128::from_i32(4).to_nz().unwrap(),
            I128::from_i32(5),
            &discriminant,
        )
        .unwrap();
        assert_eq!(f1.discriminant().unwrap(), **discriminant);
        assert_eq!(f2.discriminant().unwrap(), **discriminant);

        let f3 = f1.nucomp(&f2).unwrap();
        assert_eq!(f3.discriminant().unwrap(), **discriminant);
    }

    #[test]
    fn test_nucompinv_is_inverse_of_nucomp() {
        let discriminant = I128::from_i32(-2219).to_nz().unwrap().try_into().unwrap();
        let f1 = Ibqf::new_reduced(
            I128::from_i32(23).to_nz().unwrap(),
            I128::from_i32(9),
            &discriminant,
        )
        .unwrap();
        let f2 = Ibqf::new_reduced(
            I128::from_i32(3).to_nz().unwrap(),
            I128::from_i32(13),
            &discriminant,
        )
        .unwrap();

        let f3 = f1.nucomp(&f2).unwrap().nucompinv(&f2).unwrap();
        assert_eq!(f3, f1);

        let f3 = f1.nucompinv(&f2).unwrap().nucomp(&f2).unwrap();
        assert_eq!(f3, f1);

        let f3 = f1.nucomp(&f1).unwrap().nucompinv(&f1).unwrap();
        assert_eq!(f3, f1);

        let f3 = f1.nucompinv(&f1).unwrap().nucomp(&f1).unwrap();
        assert_eq!(f3, f1);

        let f3 = f2.nucompinv(&f1).unwrap().nucomp(&f1).unwrap();
        assert_eq!(f3, f2);

        let f3 = f2.nucomp(&f1).unwrap().nucompinv(&f1).unwrap();
        assert_eq!(f3, f2);

        let f3 = f2.nucompinv(&f2).unwrap().nucomp(&f2).unwrap();
        assert_eq!(f3, f2);

        let f3 = f2.nucomp(&f2).unwrap().nucompinv(&f2).unwrap();
        assert_eq!(f3, f2);
    }

    #[test]
    fn test_nucomp_forms_with_1_mod_4_discriminant_maintains_discriminant() {
        // This test case involves forms with a discriminant ∆ = -2219.
        // Note that
        //  ∆ = 1 mod 4, and
        // -∆ = 2 * 317 (and thus square free)

        let discriminant = I128::from_i32(-2219).to_nz().unwrap().try_into().unwrap();
        let f1 = Ibqf::new_reduced(
            I128::from_i32(23).to_nz().unwrap(),
            I128::from_i32(9),
            &discriminant,
        )
        .unwrap();
        let f2 = Ibqf::new_reduced(
            I128::from_i32(3).to_nz().unwrap(),
            I128::from_i32(13),
            &discriminant,
        )
        .unwrap();
        assert_eq!(f1.discriminant().unwrap(), **discriminant);
        assert_eq!(f2.discriminant().unwrap(), **discriminant);

        let f3 = f1.nucomp(&f2).unwrap();
        assert_eq!(f3.discriminant().unwrap(), **discriminant);
    }

    #[test]
    fn test_nucomp_forms_with_0_mod_4_discriminant_maintains_discriminant() {
        // This test case involves forms with a discriminant ∆ = -2868.
        // Note that
        //  ∆ = 0 mod 4
        //  ∆/4 = 3 mod 4, and
        // -∆ = 3 * 239 (and thus square free)

        let discriminant = I128::from_i32(-2868).to_nz().unwrap().try_into().unwrap();
        let f1 = Ibqf::new_reduced(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(16),
            &discriminant,
        )
        .unwrap();
        let f2 = Ibqf::new_reduced(
            I128::from_i32(7).to_nz().unwrap(),
            I128::from_i32(4),
            &discriminant,
        )
        .unwrap();
        assert_eq!(f1.discriminant().unwrap(), **discriminant);
        assert_eq!(f2.discriminant().unwrap(), **discriminant);

        let f3 = f1.nucomp(&f2).unwrap();
        assert_eq!(f3.discriminant().unwrap(), **discriminant);
    }

    #[test]
    fn test_nucomp_reduces() {
        let discriminant = I128::from_i32(-2868).to_nz().unwrap().try_into().unwrap();
        let f1 = Ibqf::new_reduced(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(16),
            &discriminant,
        )
        .unwrap();
        let f2 = Ibqf::new_reduced(
            I128::from_i32(7).to_nz().unwrap(),
            I128::from_i32(4),
            &discriminant,
        )
        .unwrap();
        assert_eq!(f1.discriminant().unwrap(), **discriminant);
        assert_eq!(f2.discriminant().unwrap(), **discriminant);

        let f3 = f1.nucomp(&f2).unwrap();
        assert!(f3.is_normal_vartime());
        assert!(f3.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_ct_vs_vartime() {
        const COUNT: usize = 50;
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = *setup_parameters.h.representative();

        let (mut ct_res, mut vt_res) = (form, form);
        for _ in 0..COUNT {
            ct_res = ct_res.nucomp(&form).unwrap();
            vt_res = vt_res.nucomp_vartime(&form).unwrap();
            assert_eq!(vt_res, ct_res);
        }
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::measurement::WallTime;
    use criterion::{black_box, BenchmarkGroup};
    use crypto_bigint::{Concat, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};

    use crate::EquivalenceClass;

    pub(crate) fn benchmark_nucomp<
        const HALF: usize,
        const LIMBS: usize,
        const DOUBLE_LIMBS: usize,
    >(
        g: &mut BenchmarkGroup<WallTime>,
        form: EquivalenceClass<LIMBS>,
    ) where
        Int<HALF>: InvMod<Modulus = NonZero<Uint<HALF>>, Output = Uint<HALF>>,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>
            + Gcd<Output = Uint<HALF>>
            + InvMod<Modulus = Uint<HALF>, Output = Uint<HALF>>,

        Int<LIMBS>: Encoding + InvMod<Modulus = NonZero<Uint<LIMBS>>, Output = Uint<LIMBS>>,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>>
            + Gcd<Output = Uint<LIMBS>>
            + Split<Output = Uint<HALF>>,

        Int<DOUBLE_LIMBS>: Encoding,
        Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        let form = *form.representative();
        let other = form.nudupl().unwrap();
        g.bench_function("nucomp (unreduced, ct)", |b| {
            b.iter(|| {
                black_box(form.nucomp_unreduced(&other).unwrap());
            })
        });
        g.bench_function("nucomp (unreduced, vt)", |b| {
            b.iter(|| {
                black_box(form.nucomp_unreduced_vartime(&other).unwrap());
            })
        });
        let mut other = form;
        g.bench_function("nucomp (reduced, ct)", |b| {
            b.iter(|| {
                other = other.nucomp(&form).unwrap();
            })
        });
        g.bench_function("nucomp (reduced, vt)", |b| {
            b.iter(|| {
                other = other.nucomp_vartime(&form).unwrap();
            })
        });
    }
}
