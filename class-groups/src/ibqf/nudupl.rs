// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::subtle::CtOption;
use crypto_bigint::{
    CheckedMul, CheckedSub, Concat, ConstChoice, Encoding, Gcd, Int, IntBinxgcdOutput, InvMod,
    NonZero, Split, Uint,
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
    /// Duplicate `self`, i.e., compose `self` with `self`.
    ///
    /// Assumes `self` to be reduced.
    ///
    /// Modified from [Binary Quadratic Forms, Section 6.3](https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf)
    /// to also work with forms that do NOT have a prime discriminant.
    ///
    /// The composite of primitive forms is still primitive.
    /// Ref: Pg. 242 in "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    pub fn nudupl(&self) -> Result<Self, Error> {
        self.nudupl_unreduced()
            .into_option()
            .ok_or(Error::InternalError)?
            .reduce()
    }

    /// Variant of [Ibqf::nudupl] that assumes both `self` and `rhs` are random forms.
    /// In particular, this means that
    /// - the bit lengths of their `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - the faster [Ibqf::reduce_randomized] operation can be used to reduce the output.
    pub fn nudupl_randomized(&self) -> Result<Self, Error> {
        // TODO: utilize a `partial_xgcd` algorithm that leverages the random input assumption
        self.nudupl_unreduced()
            .into_option()
            .ok_or(Error::InternalError)?
            .reduce_randomized()
    }

    /// Variable time equivalent of [Ibqf::nudupl].
    pub fn nudupl_vartime(&self) -> Result<Self, Error> {
        self.nudupl_unreduced_vartime()?.reduce_vartime()
    }

    /// Unreduced core of [Ibqf::nudupl].
    ///
    /// Doubles the value of this class-group element, which is expected to belong to a discriminant
    /// of size `discriminant_bits`.
    ///
    /// This is an adaptation of [`BICYCL`'s `nudupl` implementation](https://gite.lirmm.fr/crypto/bicycl/-/blob/68f62cc/src/bicycl/arith/qfi.inl#L867).
    #[allow(non_snake_case)]
    pub fn nudupl_unreduced(&self) -> CtOption<Self> {
        debug_assert!(self.is_reduced_vartime());

        let a = self.a.resize::<HALF>();
        let b = self.b.resize::<HALF>();
        let c = *self.c.as_uint();

        let IntBinxgcdOutput {
            gcd: gcd_a_b,
            x: u,
            y: v,
            lhs_on_gcd: a_div_gcd,
            rhs_on_gcd: b_div_gcd,
        } = a.binxgcd(&b);

        // [ Ax; Ay ] = [ gcd(a,b); 0 ]
        let Ax = gcd_a_b;

        // [ Bx; By ] = [ vc, a/gcd(a,b) ]
        let Bx = v
            .checked_mul_uint_right(&c)
            .expect("no overflow; vc < ac < Δ");
        let By = a_div_gcd
            .as_uint()
            .to_nz()
            .expect("a is non-zero; a divided by gcd is non-zero");

        // [ Dx; Dy ] = [ -uc, b/gcd(a,b) ]
        let Dx = u
            .checked_mul_uint_right(&c)
            .expect("no overflow; uc < bc/gcd < ac < Δ")
            .checked_neg()
            .expect("no overflow; ||-uc|| < ||uc|| + 1 < ||ac|| + 1 < ||Δ||");
        let Dy = b_div_gcd;

        // Compute q = Bx/By and apply matrix [[1, -q] [0, 1]] to [ Bx; By ] and [ Dx; Dy ]
        let (q, Bx) = Bx.div_rem_floor_uint(&By);
        let qDy = q
            .checked_mul(&Dy)
            .expect("no overflow; q * Dy ≤ vc/(a/gcd) * b/gcd = vcb/a < bc/gcd < ac < |Δ|");
        let Dx = Dx.checked_sub(&qDy);

        // Partially reduce [ Bx; By ], until both elements can be represented using ||Δ||/4 bits.
        let bits_upper_bound = self.discriminant_bits.div_ceil(2);
        let threshold = self.partial_reduction_bound();
        let (Bx, By, matrix) = Bx.bounded_partial_xgcd(&By, threshold, bits_upper_bound);

        let (adjugate, negative_values) = matrix.adjugate();
        assert_eq!(negative_values, ConstChoice::FALSE);
        // Note: we have to extract the matrix values from its adjugate.
        // One can compute the adjugate of a matrix as follows:
        //    ([ m00 m01 ])     [  m11 -m01 ]
        // adj([ m10 m11 ])  =  [ -m10  m00 ]
        let (m11, neg_m01, neg_m10, m00) = adjugate;

        // Multiply matrix with [ Ax; Ay ]
        let (Ax, Ay) = (
            m00.widening_mul(&Ax)
                .to_int()
                .expect("no overflow; ||m00|| < ||a||"),
            neg_m10
                .widening_mul(&Ax)
                .to_int()
                .expect("no overflow; ||m10|| < ||a||")
                .checked_neg()
                .expect("no overflow; ||m10|| < ||a||"),
        );

        // Multiply the matrix with [ Dx; Dy ]
        let (Dx, Dy) = (
            Dx.and_then(|Dx| {
                Dx.checked_mul_uint(&m00)
                    .and_then(|m00Dx| m00Dx.checked_sub(&Dy.widening_mul_uint(&neg_m01)))
            }),
            Dx.and_then(|Dx| {
                Dx.checked_mul_uint(&neg_m10)
                    .and_then(|neg_m10Dx| Dy.widening_mul_uint(&m11).checked_sub(&neg_m10Dx))
            }),
        );

        // Compute AxDx, AyDy and AxDy + AyDx using only three multiplications.
        let (AxDx, AxDy_AyDx, AyDy) = math::three_way_mul(Ax, Ay, Dx, Dy);

        // A = By² - AyDy
        let By_squared: CtOption<Int<LIMBS>> = By.widening_square().to_int().into();
        let a =
            By_squared.and_then(|By_squared| AyDy.and_then(|AyDy| By_squared.checked_sub(&AyDy)));

        // B = AxDy + AyDx - 2*BxBy
        let two_BxBy: CtOption<Int<LIMBS>> = Bx.widening_mul(&By).shl_vartime(1).to_int().into();
        let b = AxDy_AyDx.and_then(|AxDy_plus_AyDx| {
            two_BxBy.and_then(|two_BxBy| AxDy_plus_AyDx.checked_sub(&two_BxBy))
        });

        // C = Bx² - AxDx
        let Bx_squared: CtOption<Int<LIMBS>> = Bx.widening_square().to_int().into();
        let c =
            Bx_squared.and_then(|Bx_squared| AxDx.and_then(|AxDx| Bx_squared.checked_sub(&AxDx)));

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

    /// Variable time implementation of the unreduced core of [Ibqf::nudupl].
    ///
    /// This is an adaptation of [`BICYCL`'s `nudupl` implementation](https://gite.lirmm.fr/crypto/bicycl/-/blob/68f62cc/src/bicycl/arith/qfi.inl#L867).
    #[allow(non_snake_case)]
    pub fn nudupl_unreduced_vartime(&self) -> Result<Self, Error> {
        // safe to cast; a and c are expected to be greater than zero.
        // safe to resize; a and b are expected to be HALF size.
        let a = self.a.as_uint().resize::<HALF>().to_nz().unwrap();
        let b = self.b.resize::<HALF>();
        let c = self.c.as_uint().to_nz().unwrap();

        let (gcd_a_b, U, V, a_div_gcd, b_div_gcd) = math::int_xgcd_vartime(a, b);

        // [ Ax; Ay ] = [ gcd(a,b); 0 ]
        let Ax = gcd_a_b;

        // [ Bx; By ] = [ Vc, a/gcd(a,b) ]
        let Bx = V
            .checked_mul_uint_right_vartime(&c)
            .into_option()
            .ok_or(Error::InternalError)?;
        let By = a_div_gcd;

        // [ Dx; Dy ] = [ -Uc, b/gcd(a,b) ]
        let mut Dx = U
            .checked_mul_uint_right_vartime(&c)
            .and_then(|Uc| Uc.checked_neg().into())
            .into_option()
            .ok_or(Error::InternalError)?;
        let Dy = b_div_gcd;

        // Compute q = Bx/By and apply matrix [[1, -q] [0, 1]] to [ Bx; By ] and [ Dx; Dy ]
        let (q, Bx) = Bx.div_rem_floor_uint_vartime(&By);
        Dx = q
            .checked_mul_vartime(&Dy)
            .and_then(|qDy| Dx.checked_sub(&qDy))
            .into_option()
            .ok_or(Error::InternalError)?;

        // Partially reduce [ Bx; By ], until both elements can be represented using ||∆||/4 bits.
        // Note: we have to account for the spread of the partial xgcd vartime output bit size.
        let threshold =
            self.discriminant_bits.div_ceil(4) + PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD / 2;
        let (matrix, Bx, By) = math::partial_xgcd_vartime(Bx, *By, threshold);
        let (m00, m01, m10, m11) = matrix;

        // Multiply the adj(matrix) with [ Ax; Ay ] and [ Dx; Dy ]
        let (Ax, Ay) = (
            m11.widening_mul_vartime(&Ax),
            CtOption::from(m10.widening_mul_vartime(&Ax).as_int().checked_neg())
                .into_option()
                .ok_or(Error::InternalError)?,
        );
        let (Dx, Dy) = (
            Dx.checked_mul_uint_vartime(&m11)
                .and_then(|m11Dx| m11Dx.checked_sub(&Dy.widening_mul_uint_vartime(&m01)))
                .into_option()
                .ok_or(Error::InternalError)?,
            Dx.checked_mul_uint_vartime(&m10)
                .and_then(|m10Dx| Dy.widening_mul_uint_vartime(&m00).checked_sub(&m10Dx))
                .into_option()
                .ok_or(Error::InternalError)?,
        );

        // Compute AxDx, AyDy and AxDy + AyDx using only three multiplications.
        let (AxDx, AxDy_AyDx, AyDy) = math::three_way_mul_vartime(Ax.as_int(), Ay, Dx, Dy)?;

        // A = By² - AyDy
        let a = CtOption::from(By.widening_square().to_int())
            .and_then(|By_squared| By_squared.checked_sub(&AyDy))
            .into_option()
            .ok_or(Error::InternalError)?;

        // B = AxDy + AyDx - 2*BxBy
        let b = CtOption::from(Bx.widening_mul_vartime(&By).shl_vartime(1).to_int())
            .and_then(|BxBy| AxDy_AyDx.checked_sub(&BxBy))
            .into_option()
            .ok_or(Error::InternalError)?;

        // C = Bx² - AxDx
        let c = CtOption::from(Bx.widening_square().to_int())
            .and_then(|Bx_squared| Bx_squared.checked_sub(&AxDx))
            .into_option()
            .ok_or(Error::InternalError)?;

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
    use crypto_bigint::{I1024, I128, I2048};

    use crate::ibqf::Ibqf;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;

    #[test]
    fn test_nudupl_maintains_discriminant() {
        let discriminant = I128::from_i32(-2868).to_nz().unwrap().try_into().unwrap();
        let f = Ibqf::new_reduced(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(16),
            &discriminant,
        )
        .unwrap();
        assert_eq!(f.discriminant().unwrap(), **discriminant);

        let f2 = f.nudupl().unwrap();
        assert_eq!(f2.discriminant().unwrap(), **discriminant);
    }

    #[test]
    fn test_nudupl_equals_nucomp_with_self() {
        let discriminant = I128::from_i32(-2868).to_nz().unwrap().try_into().unwrap();
        let f = Ibqf::new_reduced(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(16),
            &discriminant,
        )
        .unwrap();
        assert_eq!(f.discriminant().unwrap(), **discriminant);

        let f2 = f.nucomp(&f).unwrap();
        let f2p = f.nudupl().unwrap();
        assert_eq!(f2, f2p);
    }

    #[test]
    fn test_ct_vs_vartime() {
        const COUNT: usize = 50;
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = *setup_parameters.h.representative();

        let (mut ct_res, mut vt_res) = (form, form);
        for _ in 0..COUNT {
            ct_res = ct_res.nudupl().unwrap();
            vt_res = vt_res.nudupl_vartime().unwrap();
            assert_eq!(vt_res, ct_res);
        }
    }

    /// Regression test
    /// These cases trigger specific cases in math::partial_xgcd
    #[test]
    fn test_ct_vs_vt_regression() {
        let x = Ibqf {
            a: I1024::from_be_hex(concat![
                "00000000000000000000000149496622110E26E5B53BC20111D740F063B7D718",
                "161C7A7EC058E5FD84B9D1CEFD43EEB8C7A4E7578A7A1E6106B13F10AD7EE07D",
                "1F5315DA10D9FA531AB0F3DF8DF5B20228752ECC38643E36C8D8617F5E1E4DA8",
                "A51A7E5B5EE6CC0E2FBAC062F15D3CC0022C8C16317985F53F61FCC866938ABD"
            ])
            .resize::<{ I2048::LIMBS }>()
            .to_nz()
            .unwrap(),
            b: I1024::from_be_hex(concat![
                "00000000000000000000000026C48DD8CE03E08AAC9FF03B96198F8416FFC298",
                "E2397E1AAD352D2FB64DC66957B837957B3C4132B226B397FB27BE6E128593B8",
                "4FCD9CEF6A0EA94A2A0D463E76099F055C83C7F9F5247FD1B8FC5BB197FA0B54",
                "704CB5201FACF541E734D6D022E13E7F2FE2717C164E7469A90FEA1B42029483"
            ])
            .resize::<{ I2048::LIMBS }>(),
            c: I1024::from_be_hex(concat![
                "000000000000000000000002482DD29F6ED16E3DF468F75A4E63F90741DF1CB2",
                "A05BDCBADEE98345C8E11BFDFAF5057251FB9EE3043B628EB2397DFCCDA3121F",
                "9CA1BCA2A6ECD25EBF9BD8216DE3487DD2C15346D14C2E54A6F86C66A4CF787E",
                "FB32F7DBF7BFCAA1207346B81F9CED70A2D51067E9A1D705FF20F307AAAFF60B"
            ])
            .resize::<{ I2048::LIMBS }>()
            .to_nz()
            .unwrap(),
            discriminant_bits: 1860,
        };
        assert_eq!(x.nudupl().unwrap(), x.nudupl_vartime().unwrap());

        let x = Ibqf {
            a: I1024::from_be_hex(concat![
                "0000000000000000000000012F1509F735D4E3C5057E051EE982C8448B999AAF",
                "4BCDA52721F23029BE8A883F500BB72EB21A5A5685555BA439B2C799027AD7AB",
                "157259A912F4013406C9897463735A22480BDE16B86F936DAE1BC44BD0C13A54",
                "7A4A30A1F4482EB9AFBF4580732B634E170F582D09A80672438F3EDE9DF1BBAD"
            ])
            .resize::<{ I2048::LIMBS }>()
            .to_nz()
            .unwrap(),
            b: I1024::from_be_hex(concat![
                "000000000000000000000000AB1E75984E6E6D14DA2C63B01EF437BF7464DCEB",
                "38B92C6DA5564526359709E056E3DEE3F9C489C00177E25171918E8C64A5DDCC",
                "9FBB20A60744BE33C188A775ECCFE0D928B0F4E6EE4AC1215EFB1AE472587467",
                "87FDD3B46D26CAA080B5136C4E5F9FF6E965789226FB5DF955A81100406F3F85"
            ])
            .resize::<{ I2048::LIMBS }>(),
            c: I1024::from_be_hex(concat![
                "0000000000000000000000029199CB36A925784F4C1A1DDAB5C128A9CB0CF343",
                "BE50364D0E7397774A99933F8012A2E92E7391A32A6935869C8289E127F418F2",
                "B96DD835E82FEFC30AA8C3A21C197D300C70265580204B6D3409EE3FE35A69E3",
                "AC13E5BF0640022294811CABD9EA6131195325A1A7C6B65B0898D9C967D0C90F"
            ])
            .resize::<{ I2048::LIMBS }>()
            .to_nz()
            .unwrap(),
            discriminant_bits: 1860,
        };
        assert_eq!(x.nudupl().unwrap(), x.nudupl_vartime().unwrap());
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::hint::black_box;

    use criterion::measurement::WallTime;
    use criterion::BenchmarkGroup;
    use crypto_bigint::{Concat, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};

    use crate::EquivalenceClass;

    pub(crate) fn benchmark_nudupl<
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

        g.bench_function("nudupl (unreduced, ct)", |b| {
            b.iter(|| {
                black_box(form.nudupl_unreduced().unwrap());
            })
        });
        g.bench_function("nudupl (unreduced, vt)", |b| {
            b.iter(|| {
                black_box(form.nudupl_unreduced_vartime().unwrap());
            })
        });
        let mut form = form;
        g.bench_function("nudupl (reduced, ct)", |b| {
            b.iter(|| {
                form = form.nudupl().unwrap();
            })
        });
        g.bench_function("nudupl (reduced, vt)", |b| {
            b.iter(|| {
                form = form.nudupl_vartime().unwrap();
            })
        });
    }
}
