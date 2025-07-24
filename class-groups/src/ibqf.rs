// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::ops::BitAnd;

use crypto_bigint::subtle::{Choice, ConstantTimeEq, CtOption};
use crypto_bigint::{
    CheckedMul, CheckedSub, Concat, Encoding, Int, NonZero, NonZeroUint, Split, Uint, Zero, I64,
    U64,
};
use serde::{Deserialize, Serialize};

use crate::discriminant::Discriminant;
use crate::helpers::CtMinMax;
pub(crate) use crate::ibqf::math::PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD;
use crate::ibqf::unreduced::UnreducedIbqf;

pub(crate) mod compact;

mod math;
mod nucomp;
mod nudupl;
mod nupow;
mod traits;
mod unreduced;

/// Primitive Integral Binary Quadratic Form
/// Represents $f(x) = aX² + bXY + cY²$.
///
/// This struct represents a reduced form. Use [`UnreducedIbqf`] for unreduced forms.
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
///  Use [`CompactIbqf`] instead.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ibqf<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
{
    a: NonZero<Int<LIMBS>>,
    b: Int<LIMBS>,
    c: NonZero<Int<LIMBS>>,
    discriminant_bits: u32,
}

impl<const LIMBS: usize, const DOUBLE: usize> Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE>>,
    Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    /// Construct a new reduced form `(a, b, c)`, given `(a, b)` and discriminant `∆`.
    ///
    /// Upon success, this form has the following properties:
    /// - it has a negative discriminant,
    /// - it is primitive
    pub fn new(
        a: NonZeroUint<LIMBS>,
        b: Int<LIMBS>,
        discriminant: &Discriminant<LIMBS>,
    ) -> CtOption<Self> {
        UnreducedIbqf::new(a, b, discriminant).map(|form| form.reduce())
    }
}

impl<const HALF: usize, const LIMBS: usize> Ibqf<LIMBS>
where
    Uint<HALF>: Concat<Output = Uint<LIMBS>>,
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding + Split<Output = Uint<HALF>>,
{
    /// Construct a new form `(a, b, c)`, given `(a, b)` and discriminant `∆`.
    ///
    /// Assumes the result will be reduced; returns `None` otherwise.
    ///
    /// Upon success, this form has the following properties:
    /// - it has a negative discriminant,
    /// - it is primitive,
    /// - it is reduced.
    pub fn new_is_reduced(
        a: NonZeroUint<HALF>,
        b: Int<HALF>,
        discriminant: &Discriminant<LIMBS>,
    ) -> CtOption<Self> {
        UnreducedIbqf::new_compact(a, b, discriminant).and_then(|form| form.try_into_reduced())
    }
}

impl<const LIMBS: usize> Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    /// Read-only access to this form's `a`.
    pub fn a(&self) -> &NonZero<Int<LIMBS>> {
        &self.a
    }

    /// Read-only access to this form's `b`.
    pub fn b(&self) -> &Int<LIMBS> {
        &self.b
    }

    /// Read-only access to this form's `c`.
    pub fn c(&self) -> &NonZero<Int<LIMBS>> {
        &self.c
    }

    /// The discriminant of this form, computed as `∆(f) = b² − 4ac`.
    ///
    /// Assumes this form to be reduced; may return `None` otherwise.
    pub fn discriminant(&self) -> CtOption<Int<LIMBS>> {
        let b_sqr =
            CtOption::from(self.b.checked_square()).and_then(|b_sqr| b_sqr.try_into_int().into());

        let ac4 = self
            .a
            .checked_mul(self.c.as_ref())
            .and_then(|ac| ac.checked_mul(&I64::from(4i32)));

        ac4.and_then(|ac4| b_sqr.and_then(|b_sqr| b_sqr.checked_sub(&ac4)))
    }

    /// Whether this form is principal.
    ///
    /// A form `(a, b, c)` is principal when it is reduced and `a = 1`.
    pub(crate) fn is_principal(&self) -> Choice {
        self.a.get().ct_eq(&Int::ONE)
    }

    /// Variable time equivalent of [Ibqf::is_principal].
    pub(crate) fn is_principal_vartime(&self) -> bool {
        self.a.get() == Int::ONE
    }

    /// Maps `self` to `self`$^{-1}$, without reducing the result.
    fn invert_without_reducing(self) -> CtOption<Self> {
        CtOption::from(self.b.checked_neg()).map(|b| Self {
            a: self.a,
            b,
            c: self.c,
            discriminant_bits: self.discriminant_bits,
        })
    }

    /// Constructs `self⁻¹`
    pub fn inverse(&self) -> Self {
        self.inverse_if(Choice::from(1u8))
    }

    /// Returns `self⁻¹` if `choice` is truthy. Otherwise, returns `self`.
    pub fn inverse_if(&self, choice: Choice) -> Self {
        // Since we assume `self` to be reduced, it follows that `self.inverse` is reduced unless
        // `self.a = self.b`. In that case, it equals `(a, -a, *)`, which is not normal.
        // Normalizing it will again yield `self` and thus a reduced value. For all other values of
        // `self.inverse()` normalizing does nothing, hence, this operation is safe.
        UnreducedIbqf::from(self)
            .inverse_if(choice)
            .expect("safe to invert; -self.b is guaranteed to fit in `Int` since self is reduced")
            .normalize()
            .unwrap()
            .try_into_reduced()
            .expect("is reduced by construction")
    }

    /// Unit element for the discriminant of this form.
    ///
    /// The result of [Ibqf::nucomp]ing this element with `self` is `self`.
    pub(crate) fn unit(&self) -> Self {
        self.discriminant()
            .and_then(|d| Self::unit_for_discriminant(&d))
            .expect("this valid form has a unit")
    }

    /// Unit element for the discriminant of this form.
    ///
    /// The result of [Ibqf::nucomp]ing this element with `self` is `self`.
    ///
    /// Executes in variable time w.r.t. `discriminant`.
    pub(crate) fn unit_for_discriminant(discriminant: &Int<LIMBS>) -> CtOption<Self> {
        // A unit form for discriminant ∆ is constructed as `(1, p, (p - ∆)/4)`
        // where p = ∆ mod 2.

        let abs_discriminant = discriminant.abs();
        let parity = *abs_discriminant.bitand(Uint::ONE).as_int();

        let four = U64::from(4u32).to_nz().expect("is non-zero");
        let c = parity
            .checked_sub(discriminant)
            .and_then(|parity_sub_discriminant| {
                let (c, remainder) = parity_sub_discriminant.div_rem_uint(&four);
                CtOption::new(c, remainder.is_zero())
            })
            .and_then(|c| c.to_nz().into());

        c.map(|c| Self {
            a: NonZero::ONE,
            b: parity,
            c,
            discriminant_bits: abs_discriminant.bits_vartime(),
        })
    }

    /// Compute the partial reduction lower bound for this class.
    ///
    /// This reduction bound is used by [Ibqf::nudupl] to pre-emptively reduce the form.
    ///
    /// The bound is computed as the bit size of `|∆|^1/4`, which is equal to `||∆|| / 4`.
    fn partial_reduction_lower_bound(&self) -> u32 {
        // log2[ |∆|^1/4 ] = log2[|∆|] / 4
        self.discriminant_bits.div_ceil(4)
    }

    /// Compute the partial reduction lower bound for this class.
    ///
    /// This reduction bound is used by [Ibqf::nudupl] and [Ibqf::nucomp] to pre-emptively reduce
    /// the form.
    ///
    /// The bound is computed as the bit size of `|∆|^1/4`, which is equal to `||∆|| / 4`.
    fn nucomp_partial_reduction_threshold<const L: usize>(
        &self,
        lhs_a: &Uint<L>,
        rhs_a: &Uint<L>,
    ) -> u32 {
        let lhs_bits = lhs_a.bits();
        let rhs_bits = rhs_a.bits();
        let bit_gap = u32::ct_abs_diff(&lhs_bits, &rhs_bits);
        self.partial_reduction_lower_bound() + bit_gap.div_ceil(2)
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub(crate) mod test_helpers {
    use crate::ibqf::Ibqf;
    use crate::SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS;
    use crypto_bigint::subtle::CtOption;
    use crypto_bigint::{Concat, Encoding, Int, Split, Uint, I1024, U1024, U128, U64};

    pub(crate) fn get_deterministic_secp256k1_form(
    ) -> Ibqf<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        get_deterministic_secp256k1_forms().0
    }

    pub(crate) fn get_deterministic_secp256k1_forms() -> (
        Ibqf<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        Ibqf<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        Ibqf<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) {
        let d = Int::from_be_hex(concat![
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF2D44E0C3A2360AE0C",
            "7C8A9162FB9BB8B255D571CF917270922C2F8D26C847A7CE6D5A27C8209481B8",
            "708D45DA94DBC15852918B309D3274658AC97D067D8C0F4D8850A0F819F83DCB",
            "AB0ABC6DC7063BFB548785683E475F4B4E5419AF943EACFD9B3E6EEFF5F196D2",
            "F4D4A8F137B2FBDA33613916691E86619D25D3C5A3F12D03632EA35FBEB7187D",
            "7186635FFEB09C8532E3B8B241A0DCEA27FA4CA9EC16F2B101459F57BC00A7B1",
            "CE307AEE6408D644D4ECEDC13CE364890AB7BCF1DFDCE1CA89B0F084BC2D67F0",
            "422B8321EFF19C1A8851B61CF9F5B01BCF69ECBF1769893A77E8D1A68172DEE1"
        ])
        .to_nz()
        .unwrap()
        .try_into()
        .unwrap();

        let f = Ibqf::new_is_reduced(
            U1024::from_be_hex(concat![
                "0000000000000000000000008DD9CF7C0EE35D25EAC6A3B35341F51865E1C9A9",
                "F0DBDDF82FB32AC6BD69D96FB3F6A24D51D8A3693D8CF5D15911F39FD3BF4840",
                "F4E082CFAEEC6AC5798206CDA2EBCE4D5ED518A0CD374248CF390AE72B3D8DC2",
                "4180AC8EE88EE9A52FF23B790587E9C64DF5C16E852529A81E29F67A0B2791EC"
            ])
            .resize()
            .to_nz()
            .unwrap(),
            I1024::from_be_hex(concat![
                "FFFFFFFFFFFFFFFFFFFFFFFFC182683A0E05FFFEBB94FC98A3397FC4A6FF004E",
                "6E8C8A1D738DCCA84E6FF92587244408B093313AD9663DD1FB17C2CF5B9E2E50",
                "4007223CB7668CD8AE6D2E91FEC8EE6888D4726D5FE50FAC4D0A73A7612429CF",
                "8BFE72AC662A070098453019A0BA79EEC99CBC3BDC6273913FD0396521E95C9F"
            ])
            .resize(),
            &d,
        )
        .unwrap();
        let f2 = Ibqf::new_is_reduced(
            U1024::from_be_hex(concat![
                "0000000000000000000000010EE5C52B88259F12CD076271C155DFA6A86D84CE",
                "92D2BCDC4BC66C2CF592A8086BE80987FFF4006908559E7F7204A29A28340A92",
                "9B4F8909BDB1E49E493C37B7F1115671AEF6B2D2058C2B72FAE628539EAFFD41",
                "510C9890E7291BB2309F56850A4AF5A64CFEB8CD347F5D0B90D316EF159750C6"
            ])
            .resize()
            .to_nz()
            .unwrap(),
            I1024::from_be_hex(concat![
                "FFFFFFFFFFFFFFFFFFFFFFFF3BEA594CA76E6CCF73B69D462F9B414A5D70B6CF",
                "05F5C84D1F29639FC466F68028CD1034B43994696F2540FAB80AFE0871FEA0EC",
                "BDE085D8709C3829C07D1DBF05B846D07C5E01B852955AD2237694901C23C509",
                "3402C5130B1DC6D25E8654EC593DDB5B39E79637C99CCA66AF29918296EEEE9D"
            ])
            .resize(),
            &d,
        )
        .unwrap();
        let f3 = Ibqf::new_is_reduced(
            U1024::from_be_hex(concat![
                "0000000000000000000000014B556BDB7744E95861C2539305C74179D7D85403",
                "B8FD7DE9DCC966B85F4611201134A555361215409C5D13147C31F534885DD551",
                "9047049C7A1C13565F0788F74E37C552198A7ADBB36FF027634F30C4227A2320",
                "AF40C211ED13DF7488F810A842134636A7F3DA0DC76A2FEF147D95428DAEF5BB"
            ])
            .resize()
            .to_nz()
            .unwrap(),
            I1024::from_be_hex(concat![
                "000000000000000000000000865B3B279FB4D52DC6E72C424C63E48CAA329CCA",
                "43D7EF6A8884DEC8B12FB69EF1A36251CE7FB4A2FA401DA409969BB400797491",
                "CFEB41CA0323E4F9F13198BFA5762B42D61F521C6802B02C9138868B9B9CACD6",
                "DFC6FE8E679EE0BCE51F96191014E7DDB0BAABB4FD420EE5D4698AAAE09EA0B1"
            ])
            .resize(),
            &d,
        )
        .unwrap();

        (f, f2, f3)
    }

    impl<const LIMBS: usize, const DOUBLE: usize> Ibqf<LIMBS>
    where
        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        /// Construct an [`Ibqf`] from three `u64/i64` coefficients.
        pub(crate) const fn from_64(a: u64, b: i64, c: i64) -> Self {
            assert!(a < (1 << 63));
            let a = a as i64;
            let discriminant_bits =
                U64::from_u64((b * b - 4 * a * c).unsigned_abs()).bits_vartime();
            let a = Int::from_i64(a).to_nz().expect("ok");
            let b = Int::from_i64(b);
            let c = Int::from_i64(c).to_nz().expect("ok");

            Self {
                a,
                b,
                c,
                discriminant_bits,
            }
        }

        /// Variation to [`Ibqf::new`] that accepts `u64/i64`s
        pub(crate) fn new_reduced_64(a: u64, b: i64, discriminant: i64) -> CtOption<Self> {
            let a = Uint::from(a).to_nz().unwrap();
            let b = Int::from(b);
            let discriminant = Int::from_i64(discriminant)
                .to_nz()
                .unwrap()
                .try_into()
                .unwrap();
            Self::new(a, b, &discriminant)
        }
    }

    impl<const HALF: usize, const LIMBS: usize, const DOUBLE: usize> Ibqf<LIMBS>
    where
        Uint<HALF>: Concat<Output = Uint<LIMBS>>,
        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        /// Variation to [`Ibqf::new_is_reduced`] that accepts `u64/i64`s
        pub(crate) fn new_is_reduced_64(a: u64, b: i64, discriminant: i64) -> CtOption<Self> {
            let a = Uint::from(a).to_nz().unwrap();
            let b = Int::from(b);
            let discriminant = Int::from_i64(discriminant)
                .to_nz()
                .unwrap()
                .try_into()
                .unwrap();
            Self::new_is_reduced(a, b, &discriminant)
        }
    }

    pub(crate) type Ibqf64 = Ibqf<{ U64::LIMBS }>;
    pub(crate) type Ibqf128 = Ibqf<{ U128::LIMBS }>;
}

#[cfg(test)]
mod tests {
    use crypto_bigint::I128;

    use crate::ibqf::test_helpers::{get_deterministic_secp256k1_form, Ibqf128, Ibqf64};
    use crate::ibqf::Ibqf;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;

    #[test]
    fn test_secp256k1_form() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let secp256k1_form = get_deterministic_secp256k1_form();
        assert_eq!(
            secp256k1_form.discriminant().unwrap(),
            setup_parameters.h.discriminant().get()
        );
        assert_eq!(secp256k1_form, *setup_parameters.h.representative());
    }

    #[test]
    fn test_new_normalizes() {
        let form = Ibqf128::new_reduced_64(6, 7, -215).unwrap();
        let target = Ibqf::from_64(6, -5, 10);
        assert_eq!(form, target);
    }

    #[test]
    fn test_new_reduces() {
        let form = Ibqf128::new_reduced_64(8, 9, -15).unwrap();
        let target = Ibqf::from_64(2, 1, 2);
        assert_eq!(form, target);
    }

    #[test]
    fn test_new_is_reduced() {
        let not_reduced = Ibqf128::new_is_reduced_64(8, 9, -15);
        assert!(bool::from(not_reduced.is_none()));

        let reduced = Ibqf128::new_is_reduced_64(2, 1, -15);
        assert!(bool::from(reduced.is_some()));
    }

    #[test]
    fn test_new_c_exceeding_limb_size() {
        // The `c` for this form would have to be 59113636363636464486958711564593, which does not
        // fit in an I64.
        let form = Ibqf64::new_reduced_64(11, 51000000000000043, -51426183308840243i64);
        assert!(bool::from(form.is_none()));
    }

    #[test]
    fn test_new_requires_primitive() {
        let discriminant = 5 * 5 * -19;
        let primitive = Ibqf128::new_reduced_64(7, 13, discriminant);
        assert!(bool::from(primitive.is_some()));

        let not_primitive = Ibqf128::new_reduced_64(5 * 5, 5 * 9, discriminant);
        assert!(bool::from(not_primitive.is_none()));
    }

    #[test]
    fn test_new_reduced_requires_primitive() {
        let discriminant = -7 * 7 * 23;
        let primitive = Ibqf128::new_reduced_64(13, 15, discriminant);
        assert!(bool::from(primitive.is_some()));

        let not_primitive = Ibqf128::new_reduced_64(7 * 4, 4 * 3, discriminant);
        assert!(bool::from(not_primitive.is_none()));
    }

    #[test]
    fn test_discriminant_neg() {
        let form = Ibqf128::from_64(4, 8, 9);
        assert_eq!(form.discriminant().unwrap(), I128::from(-80))
    }

    #[test]
    fn test_discriminant_pos() {
        let form = Ibqf128::from_64(4, 8, -9);
        assert_eq!(form.discriminant().unwrap(), I128::from(208))
    }

    #[test]
    fn test_inverse_is_valid() {
        let f = Ibqf128::new_reduced_64(23, 9, -2219).unwrap();
        let target = Ibqf128::new_reduced_64(23, -9, -2219).unwrap();
        let inv_f = f.inverse();
        assert_eq!(inv_f, target);

        let unit = f.nucomp(inv_f);
        let target = Ibqf128::new_reduced_64(1, 1, -2219).unwrap();
        assert_eq!(unit, target);

        // test with unit element
        let unit_inv = unit.inverse();
        assert_eq!(unit_inv, unit);
    }

    #[test]
    fn test_unit() {
        let f = Ibqf128::new_reduced_64(11, 15, -2899).unwrap();
        let unit = f.unit();
        assert_eq!(unit.nucomp(f), f);
        assert_eq!(unit.nudupl(), unit);
    }

    #[test]
    fn test_unit_for_discriminant() {
        let unit = Ibqf128::unit_for_discriminant(&I128::from_i32(-3i32));
        assert!(bool::from(unit.is_some()));

        let unit = Ibqf128::unit_for_discriminant(&I128::from_i32(-5i32));
        assert!(bool::from(unit.is_none()));
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{BatchSize, BenchmarkGroup, Criterion};
    use crypto_bigint::{
        Concat, ConstantTimeSelect, Encoding, Int, Integer, Random, Split, Uint, U256,
    };

    use group::OsCsRng;

    use crate::ibqf::nucomp::benches::benchmark_nucomp;
    use crate::ibqf::nudupl::benches::benchmark_nudupl;
    use crate::ibqf::nupow::benches::benchmark_nupow;
    use crate::ibqf::unreduced::benches::benchmark_reduce;
    use crate::ibqf::{math, Ibqf};
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::EquivalenceClass;

    fn benchmark_select<const HALF: usize, const LIMBS: usize, const DOUBLE_LIMBS: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        form: EquivalenceClass<LIMBS>,
    ) where
        Int<LIMBS>: Encoding,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>> + Split<Output = Uint<HALF>>,
        Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        let form = *form.representative();
        let other = form.nudupl_vartime();

        g.bench_function("ct_select", |b| {
            b.iter_batched(
                || U256::random(&mut OsCsRng).is_odd(),
                |x| Ibqf::ct_select(&form, &other, x),
                BatchSize::SmallInput,
            )
        });
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        {
            let mut group = _c.benchmark_group("ibqf/secp256k1");
            group.warm_up_time(Duration::from_secs(5));
            group.measurement_time(Duration::from_secs(10));
            group.sample_size(10);

            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let ec = setup_parameters.h;
            let form = *ec.representative();

            let unreduced_form = form
                .nucomp_unreduced_vartime(form.nudupl_vartime())
                .unwrap();
            benchmark_reduce(&mut group, unreduced_form);
            benchmark_nucomp(&mut group, ec);
            benchmark_nudupl(&mut group, ec);
            benchmark_nupow(&mut group, ec);
            benchmark_select(&mut group, ec);
        }

        math::benches::benchmark(_c);
    }
}
