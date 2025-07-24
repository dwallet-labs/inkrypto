// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::cmp::min;
use std::mem;
use std::ops::{BitAnd, BitOr, Deref, Div};

use crypto_bigint::subtle::{
    Choice, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess, CtOption,
};
use crypto_bigint::{
    CheckedAdd, CheckedMul, CheckedSub, Concat, ConstantTimeSelect, Encoding, Gcd, Int,
    Integer as _, InvMod, NonZero, Split, Uint, Word, U64,
};
use serde::{Deserialize, Serialize};

use crate::discriminant::Discriminant;
use crate::ibqf::math::bounded_div_rem_vartime;
pub(crate) use crate::ibqf::math::PARTIAL_XGCD_VARTIME_OUTPUT_BITSIZE_SPREAD;
use crate::Error;

pub(crate) mod accelerator;
pub(crate) mod compact;
mod math;
mod nucomp;
mod nudupl;
mod traits;

/// Primitive Integral Binary Quadratic Form
/// Represents $f(x) = aX² + bXY + cY²$
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ibqf<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
{
    a: NonZero<Int<LIMBS>>,
    b: Int<LIMBS>,
    c: NonZero<Int<LIMBS>>,
    discriminant_bits: u32,
}

impl<const LIMBS: usize, const DOUBLE_LIMBS: usize> Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>>,
    Int<DOUBLE_LIMBS>: Encoding,
    Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    /// Construct a new form `(a, b, c)`, given `(a, b)` and discriminant `∆`.
    /// Upon success, this form has the following properties:
    /// - It has a negative discriminant,
    /// - It is primitive
    ///
    /// Note: to construct a new _reduced_ form, use [Ibqf::new_reduced].
    ///
    /// TODO(#100): remove into_option from constant time algorithms
    pub fn new(
        a: NonZero<Int<LIMBS>>,
        b: Int<LIMBS>,
        discriminant: &Discriminant<LIMBS>,
    ) -> Result<Self, Error> {
        // Given `a`, `b` and `∆`, one can compute `c` coefficient as follows:
        //       ∆ =  b² − 4ac
        // <=> 4ac =  b² − ∆
        // <=>   c = [b² − ∆]/4a
        // Note: this yields a valid form if and only if the division is exact.

        // safe to cast; a square of a k-bit int can be represented using at most 2k-1 bits.
        let b_sqr = b.widening_square().as_int();

        // safe to unwrap; scale up of non-zero value.
        let b_sqr_min_d = b_sqr
            .checked_sub(
                &discriminant
                    .deref()
                    .resize::<DOUBLE_LIMBS>()
                    .to_nz()
                    .unwrap(),
            )
            .into_option()
            .ok_or(Error::InvalidFormParameters)?;

        // safe to unwrap; `a` is non-zero
        // safe to vartime; shl_vartime is vartime only in the shift, which is static here.
        let four_a = a
            .resize::<DOUBLE_LIMBS>()
            .wrapping_shl_vartime(2)
            .to_nz()
            .unwrap();
        let (c, remainder) = b_sqr_min_d.checked_div_rem(&four_a);
        if remainder != Int::ZERO {
            return Err(Error::InvalidFormParameters);
        }

        // safe to unwrap;
        // - division was safe: 4*a is neither 0 nor -1 since a is nonzero.
        // - dividing a non-zero value and yielding a zero-remainder implies a non-zero quotient.
        // safe to resize; c < |∆| by construction.
        let c = c.unwrap().resize::<LIMBS>().to_nz().unwrap();
        Ok(Self {
            a,
            b,
            c,
            discriminant_bits: discriminant.bits_vartime(),
        })
    }

    /// Construct a new _reduced_ form `(a, b, c)`, given `(a, b)` and discriminant `∆`.
    /// Upon success, this form has the following properties:
    /// - It has a negative discriminant,
    /// - It is primitive
    pub fn new_reduced(
        a: NonZero<Int<LIMBS>>,
        b: Int<LIMBS>,
        discriminant: &Discriminant<LIMBS>,
    ) -> Result<Self, Error> {
        Self::new(a, b, discriminant)?.reduce()
    }

    /// Reduce this form.
    ///
    /// Ref: Section 5.2.1 in
    /// <https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf>
    pub fn reduce(self) -> Result<Self, Error> {
        self.reduce_core(self.discriminant_bits / 2)
    }

    /// Variation to [Ibqf::reduce] which assumes that `self` is the unreduced composition of two
    /// forms. In particular, this means that the bit lengths of their `a` and `c` attributes are
    /// nearly identical. This assumption implies that significantly fewer iterations are required
    /// to reduce the output form.
    ///
    /// More precisely, the bit size of the output of the composition of two random forms
    /// satisfies that `||a|| < ||Δ||/2 + 64` with probability `1-2^{-64}`. As every reduction
    /// step decreases `|a|` by at least one bit, we are guaranteed that performing 64 iterations
    /// will output a reduced form.
    pub fn reduce_randomized(self) -> Result<Self, Error> {
        self.reduce_core(64)
    }

    /// Apply the `rho` function `iterations` times to reduce this form.
    ///
    /// Ref: Section 5.2.1 in
    /// <https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf>
    fn reduce_core(self, iterations: u32) -> Result<Self, Error> {
        let mut res = self.normalize()?;
        for _ in 0..iterations {
            res = res.rho()?;
        }

        Ok(Ibqf::ct_select(
            &res.mirror_unreduced()?,
            &res,
            res.is_reduced(),
        ))
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

    /// The discriminant of this form.
    /// Computed as ∆(f) = b² − 4ac.
    ///
    /// Assumes this form to be reduced.
    pub fn discriminant(&self) -> Result<Int<LIMBS>, Error> {
        // Because this form is assumed reduced, we have:
        // |b²| = |b|² ≤ |a|² ≤ |√(∆)/3|² = |∆|/9 < |∆|/4
        // hence, safe to square-and-unwrap
        // moreover, the top bit is not set, so safe to cast as_int()
        let b_sqr = self.b.checked_square().unwrap().as_int();

        // Because this form is assumed reduced, we have:
        // |ac| = |b² − ∆| / 4 ≤ |2∆| / 4 = |∆|/2
        // safe to unwrap; the result of this multiplication fits.
        let ac = self.a.checked_mul(self.c.as_ref()).unwrap();
        let ac4 = ac
            .checked_mul(&Int::<LIMBS>::from(4i32))
            .into_option()
            .ok_or(Error::InternalError)?;
        b_sqr
            .checked_sub(&ac4)
            .into_option()
            .ok_or(Error::InternalError)
    }

    /// Whether this form is principal.
    /// A form `(a, b, c)` is principal when it is reduced and `a = 1`.
    pub(crate) fn is_principal(&self) -> Choice {
        self.is_reduced().bitand(self.a.get().ct_eq(&Int::ONE))
    }

    /// Variable time equivalent of [Ibqf::is_principal].
    pub(crate) fn is_principal_vartime(&self) -> bool {
        self.is_reduced_vartime() && self.a.get() == Int::ONE
    }

    /// Normalize this form, i.e.,
    /// map `(a, b, c)` to `(a, r, c - q(b+r)/2)`, where `(q, r) := ⌈b/a⌉`.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://gite.lirmm.fr/crypto/bicycl/-/blob/master/src/bicycl/arith/qfi.inl?ref_type=heads#L479),
    /// This is a variation on Algorithm 5.4.2, as found in "A Course in Computational Algebraic
    /// Number Theory" (978-3-662-02945-9).
    pub fn normalize(mut self) -> Result<Self, Error> {
        let (mut q, mut r) = self.b.div_rem_uint(&self.a.as_uint().to_nz().unwrap());

        // Rearrange such that b = (2*a)*q + r and -a < r <= a
        let r_gt_zero = r.ct_gt(&Int::ZERO);
        r = Int::ct_select(&r, &r.wrapping_sub(&self.a), r_gt_zero);
        q = Int::ct_select(&q, &q.wrapping_add(&Int::ONE), r_gt_zero);
        r = Int::ct_select(&r, &r.wrapping_add(&self.a), q.is_odd().into());
        // skip subtracting 1 from q, as it will be shifted off.

        // = q/2. Safe to shift; q is guaranteed even at this point.
        // safe to vartime, since we are shifting by a constant.
        q = q.shr_vartime(1);

        mem::swap(&mut self.b, &mut r);
        self.c = r
            .checked_add(&self.b)
            .map(|b_plus_r| b_plus_r.shr_vartime(1))
            .and_then(|b_plus_r_on_two| b_plus_r_on_two.checked_mul(&q))
            .and_then(|qb_plus_qr_on_two| self.c.wrapping_sub(&qb_plus_qr_on_two).to_nz().into())
            .into_option()
            .ok_or(Error::InternalError)?;

        Ok(self)
    }

    /// Variable time equivalent of [Self::normalize]
    pub fn normalize_vartime(self) -> Result<Self, Error> {
        let a_nz = self.a.as_uint().to_nz().unwrap();
        let b_bits = self.b.abs().bits_vartime();
        let a_bits = a_nz.bits_vartime();

        // Account for large `q`
        if b_bits.saturating_sub(a_bits) < 32 {
            // At this point, q is guaranteed to be smaller than 32 bits.
            // So we can approximate the result using bounded division.
            let (q, r) = bounded_div_rem_vartime(&self.b, a_nz.deref());
            self.normalize_vartime_core(q, r)
        } else {
            let (q, r) = self.b.div_rem_uint_vartime(&a_nz);
            self.normalize_vartime_core(q, r)
        }
    }

    /// Core of [Self::normalize_vartime] that is generic of the size of `q`.
    #[inline]
    fn normalize_vartime_core<const Q_LIMBS: usize>(
        mut self,
        mut q: Int<Q_LIMBS>,
        mut r: Int<LIMBS>,
    ) -> Result<Self, Error> {
        // Shift the quotient and remainder around such that b = (2*a)*q + r and -a < r <= a
        let q_is_odd: bool = q.is_odd().into();
        if r > Int::ZERO {
            if q_is_odd {
                r = r.wrapping_sub(&self.a);
            }
            q = q.wrapping_add(&Int::ONE);
        } else if q_is_odd {
            r = r.wrapping_add(&self.a);
        }
        // = q/2. Safe to shift; q is guaranteed even at this point.
        // safe to vartime, since we are shifting by a constant.
        q = q.shr_vartime(1);

        mem::swap(&mut self.b, &mut r);
        self.c = r
            .checked_add(&self.b)
            .map(|b_plus_r| b_plus_r.shr_vartime(1))
            .and_then(|b_plus_r_on_two| b_plus_r_on_two.checked_mul_vartime(&q))
            .and_then(|qb_plus_qr_on_two| self.c.wrapping_sub(&qb_plus_qr_on_two).to_nz().into())
            .into_option()
            .ok_or(Error::InternalError)?;

        Ok(self)
    }

    /// Compute a normalized copy of this form.
    /// See [Ibqf::normalize] for more details.
    pub fn normalized(&self) -> Result<Self, Error> {
        self.normalize()
    }

    /// Whether this form is normal.
    /// A form is normal when -a < b ≤ a.
    pub fn is_normal(&self) -> Choice {
        // safe to wrap; a is positive by construction, the negation of which always fits.
        self.a
            .wrapping_neg()
            .ct_lt(&self.b)
            .bitand(!self.a.ct_lt(&self.b))
    }

    /// Variable time equivalent of [Ibqf::is_normal].
    pub fn is_normal_vartime(&self) -> bool {
        // safe to wrap; a is positive by construction, the negation of which always fits.
        self.a.wrapping_neg() < self.b && self.b <= self.a.get()
    }

    /// Map `(a, b, c)` to `(c, -b, a)`.
    /// Warning: the mirror image of a reduced form is (almost always) NOT reduced.
    fn mirror_unreduced(mut self) -> Result<Self, Error> {
        mem::swap(&mut self.a, &mut self.c);
        self.invert_without_reducing()
    }

    /// Map `(a, b, c)` to `(c, -b + 2sc, cs² - br + a)`, where `s := ⌊(b+c)/2c⌋`.
    pub(crate) fn rho(self) -> Result<Self, Error> {
        self.mirror_unreduced().and_then(|form| form.normalize())
    }

    /// Variable time equivalent of [Self::rho]
    pub(crate) fn rho_vartime(self) -> Result<Self, Error> {
        self.mirror_unreduced()
            .and_then(|form| form.normalize_vartime())
    }

    /// Reduce this form.
    ///
    /// Operation is performed in variable time.
    ///
    /// Ref: Section 5.2.1 in
    /// <https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf>
    pub fn reduce_vartime(self) -> Result<Self, Error> {
        let mut res = self.normalize_vartime()?;
        while !res.normal_form_is_reduced_vartime() {
            res = res.rho_vartime()?;
        }
        Ok(res)
    }

    /// Whether this normal form is reduced.
    /// Note: assumes it is normalized.
    /// See [Ibqf::is_reduced_vartime] for more details.
    #[inline]
    fn normal_form_is_reduced_vartime(&self) -> bool {
        self.a < self.c || (self.a == self.c && !bool::from(self.b.is_negative()))
    }

    /// Whether this normal form is reduced.
    /// Note: assumes it is normalized.
    /// See [Ibqf::is_reduced_vartime] for more details.
    #[inline]
    fn normal_form_is_reduced(&self) -> Choice {
        self.a.ct_lt(&self.c).bitor(
            self.a
                .ct_eq(&self.c)
                .bitand(!Choice::from(self.b.is_negative())),
        )
    }

    /// Whether this form is reduced.
    /// A form `(a, b, c)` is reduced when
    /// 1. It [Ibqf::is_normal_vartime],
    /// 2. And
    ///     - a < c, or
    ///     - a = c and b >= 0.
    pub fn is_reduced_vartime(&self) -> bool {
        self.is_normal_vartime() && self.normal_form_is_reduced_vartime()
    }

    /// Whether this form is reduced.
    /// A form `(a, b, c)` is reduced when
    /// 1. It [Ibqf::is_normal],
    /// 2. And
    ///     - a < c, or
    ///     - a = c and b >= 0.
    pub fn is_reduced(&self) -> Choice {
        self.is_normal().bitand(self.normal_form_is_reduced())
    }

    /// Returns an inverted copy of `self`.
    /// See [Ibqf::invert] for more details.
    pub fn inverse(&self) -> Self {
        self.invert()
    }

    /// Maps `self` to `self`$^{-1}$, without reducing the result.
    ///
    /// TODO(#100): remove into_option from constant time algorithms
    fn invert_without_reducing(self) -> Result<Self, Error> {
        CtOption::from(self.b.checked_neg())
            .map(|b| Self {
                a: self.a,
                b,
                c: self.c,
                discriminant_bits: self.discriminant_bits,
            })
            .into_option()
            .ok_or(Error::InternalError)
    }

    /// Maps `self` to `self`$^{-1}$.
    ///
    /// Assumes `self` is reduced.
    pub fn invert(self) -> Self {
        // safe to unwrap; -self.b is guaranteed to fit in `Int` since self is reduced.
        let inverted = self.invert_without_reducing().unwrap();

        // Since we assume `self` to be reduced, it follows that `inverted` is reduced unless
        // `self.a = self.b`. In that case, `inverted` equals `(a, -a, *)`, which is not normal.
        // Normalizing it will again yield `self` and thus a reduced value. For all other values of
        // `inverted` normalizing does nothing, hence, this operation is safe.
        inverted.normalize().unwrap()
    }

    /// Maps `self` to `self`$^{-1}$ if `choice` is truthy.
    ///
    /// Assumes `self` to be reduced.
    ///
    /// Note: output may not be reduced.
    pub fn wrapping_invert_if(self, choice: Choice) -> Self {
        // safe to unwrap; -self.b is guaranteed to fit in `Int` since self is reduced.
        let b = Int::ct_select(&self.b, &self.b.wrapping_neg(), choice);
        Self {
            a: self.a,
            b,
            c: self.c,
            discriminant_bits: self.discriminant_bits,
        }
    }

    /// Unit element for the discriminant of this form.
    /// The result of [Ibqf::nucomp]ing this element with `self` is `self`.
    pub(crate) fn unit(&self) -> Result<Self, Error> {
        Self::unit_for_discriminant(&self.discriminant()?)
    }

    /// Unit element for the discriminant of this form.
    /// The result of [Ibqf::nucomp]ing this element with `self` is `self`.
    pub(crate) fn unit_for_discriminant(discriminant: &Int<LIMBS>) -> Result<Self, Error> {
        // A unit form for discriminant ∆ is constructed as `(1, p, (p - ∆)/4)`
        // where p = ∆ mod 2.

        // safe cast; parity is either zero or one.
        let parity = Uint::from(discriminant.abs().is_odd().unwrap_u8()).as_int();

        // safe to unwrap; 4 is a constant non-zero.
        let four = U64::from(4u32).to_nz().unwrap();
        let (c, remainder) = parity
            .checked_sub(discriminant)
            .into_option()
            .ok_or(Error::InternalError)?
            .div_rem_uint(&four);
        if remainder != Int::ZERO {
            return Err(Error::InvalidFormParameters);
        }

        // safe to unwrap;
        // Note that p - ∆ = p + |∆| > 0 since ∆ is negative.
        // Moreover, the division had a zero remainder, so `c` is non-zero.
        let c = c.to_nz().unwrap();

        Ok(Self {
            a: NonZero::ONE,
            b: parity,
            c,
            discriminant_bits: discriminant.abs().bits_vartime(),
        })
    }

    /// Resize the members in this form.
    /// Warning: this operation may lead to loss of information.
    pub(crate) fn resize<const TARGET_LIMBS: usize>(&self) -> Result<Ibqf<TARGET_LIMBS>, Error>
    where
        Int<TARGET_LIMBS>: Encoding,
    {
        Ok(Ibqf {
            a: CtOption::from(self.a.resize::<TARGET_LIMBS>().to_nz())
                .into_option()
                .ok_or(Error::InternalError)?,
            b: self.b.resize::<TARGET_LIMBS>(),
            c: CtOption::from(self.c.resize::<TARGET_LIMBS>().to_nz())
                .into_option()
                .ok_or(Error::InternalError)?,
            discriminant_bits: self.discriminant_bits,
        })
    }

    /// Compute the optimal partial reduction bound for this class.
    ///
    /// This reduction bound is used by `nudupl` and `nucomp` to pre-emptively reduce the form.
    ///
    /// The bound is computed as the bit size of `|∆|^1/4`, which is equal to `||∆|| / 4`.
    fn partial_reduction_bound(&self) -> u32 {
        // log2[ |∆|^1/4 ] = log2[|∆|] / 4
        self.discriminant_bits.div_ceil(4)
    }
}

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
    /// Map `self` to `self^exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    ///
    /// TODO(#34): deprecate in favor of default `AdditivelyHomomorphicEncryptionKey` implementation.
    pub(crate) fn nupow<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<{ EXPONENT_LIMBS }>,
    ) -> Result<Self, Error> {
        let base = self.unit()?;
        self.nupow_with_base(base, exponent)
    }

    /// Maps `(self, base)` to `base^{2^b} * self^{exponent}`, with
    /// `b = Uint::<EXPONENT_LIMBS>::BITS`.
    pub(crate) fn nupow_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<{ EXPONENT_LIMBS }>,
    ) -> Result<Self, Error> {
        let mut res = base;
        for limb in exponent.to_words().into_iter().rev() {
            res = self.pow_and_mul(res, limb, Word::BITS)?;
        }
        Ok(res)
    }

    /// Raise `self` to the `exponent`.
    ///
    /// Executes in variable time w.r.t. both `self` and `exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    ///
    /// TODO(#34): deprecate in favor of default `AdditivelyHomomorphicEncryptionKey` implementation.
    pub(crate) fn nupow_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Result<Self, Error> {
        let base = self.unit()?;
        self.nupow_with_base_vartime(base, exponent)
    }

    /// Maps `(self, base)` to `base^{2^b} * self^{exponent}`, with
    /// `b = Uint::<EXPONENT_LIMBS>::BITS`.
    ///
    /// Executes in variable time w.r.t. `self`, `base` and `exponent`.
    pub(crate) fn nupow_with_base_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Result<Self, Error> {
        let exponent_bits = exponent.bits_vartime();

        let full_limb_count =
            usize::try_from(exponent_bits / Word::BITS).map_err(|_| Error::InternalError)?;
        let leading_bit_count = exponent_bits % Word::BITS;
        let scalar_words = exponent.to_words();

        // leading bits from most significant limb.
        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul_vartime(res, leading_word, leading_bit_count)?;
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul_vartime(res, *limb, Word::BITS)?;
        }

        Ok(res)
    }

    /// Raise `self` to `2^k`.
    ///
    /// This operation is performed in time variable in `self` and `k`.
    ///
    /// See [Ibqf::nupow] for more details.
    pub(crate) fn nupow2k_vartime(&self, k: u32) -> Result<Self, Error> {
        let mut res = *self;
        for _ in 0..k {
            res = res.nudupl_vartime()?;
        }
        Ok(res)
    }

    /// Compute `self^e`, with `e` the integer represented by the
    /// `min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS)` least significant bits of `exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    ///
    /// TODO(#34): deprecate in favor of default `AdditivelyHomomorphicEncryptionKey` implementation.
    pub(crate) fn nupow_bounded<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Result<Self, Error> {
        let base = self.unit()?;
        self.nupow_bounded_with_base(base, exponent, exponent_bits)
    }

    /// Maps `(self, base)` to `base^{2^b} * self^e`, with `e` the integer represented by the
    /// `b = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS)` least significant bits of `exponent`.
    ///
    /// Computed as [Ibqf::nudupl]-and-[Ibqf::nucomp] (analogous to square-and-multiply).
    pub(crate) fn nupow_bounded_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
        mut exponent_bits: u32,
    ) -> Result<Self, Error> {
        exponent_bits = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS);

        let full_limb_count =
            usize::try_from(exponent_bits / Word::BITS).map_err(|_| Error::InternalError)?;
        let leading_bit_count = exponent_bits % Word::BITS;
        let scalar_words = exponent.to_words();

        // leading bits from most significant limb.
        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul(res, leading_word, leading_bit_count)?;
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul(res, *limb, Word::BITS)?;
        }

        Ok(res)
    }

    /// Variation to [Ibqf::nupow_bounded_with_base] that assumes `self` and `base` to be random
    /// forms. In particular, this means that
    /// - the bit lengths of their `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - significantly fewer iterations are required to reduce the output form.
    pub(crate) fn nupow_randomized_bounded_with_base<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
        mut exponent_bits: u32,
    ) -> Result<Self, Error> {
        exponent_bits = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS);

        let full_limb_count =
            usize::try_from(exponent_bits / Word::BITS).map_err(|_| Error::InternalError)?;
        let leading_bit_count = exponent_bits % Word::BITS;
        let scalar_words = exponent.to_words();

        // leading bits from most significant limb.
        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul_randomized(res, leading_word, leading_bit_count)?;
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul_randomized(res, *limb, Word::BITS)?;
        }

        Ok(res)
    }

    /// Compute `self^e`, with `e` the integer represented by the `exponent_bits` least significant
    /// bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. all input variables.
    pub(crate) fn nupow_bounded_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Result<Self, Error> {
        let mask =
            Uint::MAX.shr_vartime(Uint::<EXPONENT_LIMBS>::BITS.saturating_sub(exponent_bits));
        let exponent = exponent.bitand(&mask);
        let exponent_bits = exponent.bits_vartime();

        let base = self.unit()?;
        self.nupow_bounded_with_base_vartime(base, &exponent, exponent_bits)
    }

    /// Maps `(self, base)` to `base^{2^b} * self^e`, with `e` the integer represented by the
    /// `b = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS)` least significant bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. all parameters.
    pub(crate) fn nupow_bounded_with_base_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        base: Self,
        exponent: &Uint<EXPONENT_LIMBS>,
        mut exponent_bits: u32,
    ) -> Result<Self, Error> {
        exponent_bits = min(exponent_bits, Uint::<EXPONENT_LIMBS>::BITS);

        let full_limb_count =
            usize::try_from(exponent_bits / Word::BITS).map_err(|_| Error::InternalError)?;
        let leading_bit_count = exponent_bits % Word::BITS;
        let scalar_words = exponent.to_words();

        // leading bits from most significant limb.
        let mut res = base;
        if leading_bit_count > 0 {
            let leading_word = scalar_words[full_limb_count];
            res = self.pow_and_mul_vartime(res, leading_word, leading_bit_count)?;
        }

        // full limbs
        for limb in scalar_words[0..full_limb_count].iter().rev() {
            res = self.pow_and_mul_vartime(res, *limb, Word::BITS)?;
        }

        Ok(res)
    }

    /// Maps `(self, base)` to `base^{2^b} * self^e`, with `e` the value represented by the
    /// `b = min(exponent_bits, Word::BITS)` least significant bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. all parameters.
    ///
    /// TODO(#34): deprecate in favor of default `AdditivelyHomomorphicEncryptionKey` implementation.
    #[inline]
    fn pow_and_mul_vartime(
        &self,
        mut base: Self,
        mut exponent: Word,
        mut exponent_bits: u32,
    ) -> Result<Self, Error> {
        exponent_bits = min(exponent_bits, Word::BITS);
        exponent = exponent.reverse_bits() >> (Word::BITS - exponent_bits);

        for _ in 0..exponent_bits {
            base = base.nudupl_vartime()?;
            if exponent & 1 == 1 {
                base = base.nucomp_vartime(self)?;
            }
            exponent >>= 1;
        }
        Ok(base)
    }

    /// Maps `(self, base)` to `base^{2^b} * self^e`, with `e` the value represented by the
    /// `b = min(exponent_bits, Word::BITS)` least significant bits of `exponent`.
    ///
    /// TODO(#34): deprecate in favor of default `AdditivelyHomomorphicEncryptionKey` implementation.
    #[inline]
    fn pow_and_mul(
        &self,
        mut base: Self,
        mut exponent: Word,
        mut exponent_bits: u32,
    ) -> Result<Self, Error> {
        exponent_bits = min(exponent_bits, Word::BITS);
        exponent = exponent.reverse_bits() >> (Word::BITS - exponent_bits);

        for _ in 0..exponent_bits {
            let exponent_bit = Choice::from((exponent & 1) as u8);

            base = base.nudupl()?;
            base = Ibqf::ct_select(&base, &base.nucomp(self)?, exponent_bit);

            exponent >>= 1;
        }
        Ok(base)
    }

    /// Variation to [Ibqf::pow_and_mul] that assumes `self` and `base` to be random forms.
    /// In particular, this means that
    /// - the bit lengths of their `a` and `c` attributes are nearly identical, and
    /// - we expect random behaviour during gcd computations.
    ///
    /// This assumption implies that
    /// - a faster `partial_xgcd` algorithm can be leveraged, and
    /// - significantly fewer iterations are required to reduce the output form.
    #[inline]
    fn pow_and_mul_randomized(
        &self,
        mut base: Self,
        mut exponent: Word,
        mut exponent_bits: u32,
    ) -> Result<Self, Error> {
        exponent_bits = min(exponent_bits, Word::BITS);
        exponent = exponent.reverse_bits() >> (Word::BITS - exponent_bits);

        for _ in 0..exponent_bits {
            let exponent_bit = Choice::from((exponent & 1) as u8);

            base = base.nudupl_randomized()?;
            base = Ibqf::ct_select(&base, &base.nucomp_randomized(self)?, exponent_bit);

            exponent >>= 1;
        }
        Ok(base)
    }
}

impl<const LIMBS: usize, const DOUBLE_LIMBS: usize> Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding + InvMod<Modulus = NonZero<Uint<LIMBS>>, Output = Uint<LIMBS>>,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>> + Gcd<Output = Uint<LIMBS>>,

    Int<DOUBLE_LIMBS>: Encoding,
    Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    /// Map this form
    /// - **from**: the set of invertible ideals of the non-maximal order [discriminant: `conductor^2 * discriminant`]
    /// - **to**: the set of invertible ideals of the maximal order [discriminant `discriminant`].
    ///
    /// Assumes `self` has discriminant equal to `conductor² * discriminant`.
    /// Assumes `conductor` is an odd prime power.
    /// Assumes `self` is reduced.
    /// Undefined behaviour otherwise.
    ///
    /// Note: result is not necessarily reduced.
    ///
    /// Ref: Algorithm 3 (GoToMaxOrder) of [HJPT1998](https://link.springer.com/content/pdf/10.1007/bfb0054134.pdf).
    ///
    /// TODO(#100): remove into_option from constant time algorithms
    pub fn to_maximal_order(
        self,
        conductor: &NonZero<Uint<LIMBS>>,
        discriminant: &Discriminant<LIMBS>,
    ) -> Result<Ibqf<LIMBS>, Error> {
        let form = self.as_form_prime_to(conductor)?;

        // Solve extended gcd: conductor * x + form.a * y = 1.
        // safe to unwrap; `form.a` is coprime with `c` by construction; this inverse exists.
        let y = form.a.inv_mod(conductor).unwrap();
        let ay = form
            .a
            .checked_mul(&y)
            .into_option()
            .ok_or(Error::InternalError)?;
        // safe to unwrap; the negation of a positive value always fits.
        let x = ay.wrapping_sub(&Int::ONE).wrapping_neg().div(conductor);

        // Compute b
        let b = form
            .b
            .checked_mul(&x)
            .and_then(|bx| bx.checked_add(&ay))
            .into_option()
            .ok_or(Error::InternalError)?;

        Self::new(form.a, b, discriminant)
    }

    /// Construct a form equivalent to `self` for which the first coefficient is coprime with `p`.
    ///
    /// Here, _equivalent_ means that when the newly constructed form and `self` are
    /// [Ibqf::reduce]d, both are mapped to the same form.
    /// Thus note that the output form is not necessarily reduced.
    ///
    /// Assumes `p` is a prime power and that `self` is reduced. Undefined behaviour otherwise.
    ///
    /// Ref: Algorithm 1 (FindIdealPrimeTo) of [HJPT1998](https://link.springer.com/content/pdf/10.1007/bfb0054134.pdf).
    ///
    /// TODO(#100): remove into_option from constant time algorithms
    pub(crate) fn as_form_prime_to(&self, p: &Uint<LIMBS>) -> Result<Self, Error> {
        let a_plus_b = self
            .a
            .checked_add(&self.b)
            .into_option()
            .ok_or(Error::InternalError)?;

        let form = Self {
            a: self.a,
            b: a_plus_b
                .checked_add(&self.a)
                .into_option()
                .ok_or(Error::InternalError)?,

            // safe to unwrap; 0 <= |b| <= a < c since self is assumed reduced. Hence, a+b+c > 0.
            c: a_plus_b
                .checked_add(&self.c)
                .into_option()
                .ok_or(Error::InternalError)?
                .to_nz()
                .unwrap(),
            discriminant_bits: self.discriminant_bits,
        };

        // safe to abs; c > 0 since self is assumed to be reduced
        let c_coprime_to_p = self.c.abs().gcd(p).ct_eq(&Uint::ONE);
        let form = Self::ct_select(&form, self, c_coprime_to_p).mirror_unreduced()?;

        // safe to abs; a > 0 since self is assumed to be reduced
        let a_coprime_to_p = self.a.abs().gcd(p).ct_eq(&Uint::ONE);
        Ok(Self::ct_select(&form, self, a_coprime_to_p))
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{
        CheckedMul, CheckedSub, Concat, Encoding, Gcd, Int, NonZero, Random, Split, Uint, I128,
        U128, U256, U64,
    };
    use rand_core::OsRng;

    use crate::discriminant::Discriminant;
    use crate::ibqf::Ibqf;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::Error;

    impl<const LIMBS: usize, const DOUBLE_LIMBS: usize> Ibqf<LIMBS>
    where
        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>> + Gcd<Output = Uint<LIMBS>>,
        Int<DOUBLE_LIMBS>: Encoding,
        Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        /// Construct a new form _without_ reducing it.
        fn new_from_elements(
            a: NonZero<Int<LIMBS>>,
            b: Int<LIMBS>,
            c: NonZero<Int<LIMBS>>,
        ) -> Result<Self, Error> {
            let discriminant_bits = a
                .checked_mul(c.as_ref())
                .unwrap()
                .shl(2)
                .as_uint()
                .checked_sub(&b.wrapping_square())
                .unwrap()
                .bits_vartime();
            let form = Self {
                a,
                b,
                c,
                discriminant_bits,
            };
            if form.is_primitive() {
                Ok(form)
            } else {
                Err(Error::FormNotPrimitive)
            }
        }

        /// Construct a new form and reduce it.
        pub(crate) fn new_reduced_from_elements(
            a: NonZero<Int<LIMBS>>,
            b: Int<LIMBS>,
            c: NonZero<Int<LIMBS>>,
        ) -> Result<Self, Error> {
            Self::new_from_elements(a, b, c)?.reduce()
        }

        /// Whether this form is primitive.
        /// A form `(a, b, c)` is primitive when `gcd(a, b, c) = 1`.
        ///
        /// Ref: Definition 5.2.3 in "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
        fn is_primitive(&self) -> bool {
            self.a.abs().gcd(&self.b.abs()).gcd(&self.c.abs()) == Uint::ONE
        }
    }

    const LIMBS: usize = 1;

    #[test]
    fn test_new_normalizes() {
        let form = Ibqf::new_reduced_from_elements(
            I128::from(6).to_nz().unwrap(),
            I128::from(7),
            I128::from(11).to_nz().unwrap(),
        )
        .unwrap();

        let target = Ibqf::new_from_elements(
            I128::from(6).to_nz().unwrap(),
            I128::from(-5),
            I128::from(10).to_nz().unwrap(),
        )
        .unwrap();
        assert_eq!(form, target);
        assert_eq!(form.discriminant().unwrap(), target.discriminant().unwrap());
        // sanity check
    }

    #[test]
    fn test_new_reduces() {
        let form = Ibqf::new_reduced_from_elements(
            I128::from(8).to_nz().unwrap(),
            I128::from(9),
            I128::from(3).to_nz().unwrap(),
        )
        .unwrap();
        let target = Ibqf::new_from_elements(
            I128::from(2).to_nz().unwrap(),
            I128::from(1),
            I128::from(2).to_nz().unwrap(),
        )
        .unwrap();
        assert_eq!(form, target);
        assert_eq!(form.discriminant().unwrap(), target.discriminant().unwrap());
        // sanity check
    }

    const FORM_4_8_9: Ibqf<{ I128::LIMBS }> = Ibqf {
        a: NonZero::<I128>::new_unwrap(I128::from_i32(4i32)),
        b: I128::from_i32(8i32),
        c: NonZero::<I128>::new_unwrap(I128::from_i32(9i32)),
        discriminant_bits: 7,
    };

    #[test]
    fn test_discriminant_neg() {
        assert_eq!(FORM_4_8_9.discriminant().unwrap(), I128::from(-80))
    }

    #[test]
    fn test_discriminant_pos() {
        let form = Ibqf::new_from_elements(
            NonZero::<I128>::new_unwrap(I128::from_i32(4i32)),
            I128::from_i32(8i32),
            NonZero::<I128>::new_unwrap(I128::from_i32(-9i32)),
        )
        .unwrap();
        assert_eq!(form.discriminant().unwrap(), I128::from(208))
    }

    #[test]
    fn test_normalized() {
        let target = Ibqf::new_from_elements(
            I128::from(4).to_nz().unwrap(),
            I128::ZERO,
            I128::from(5).to_nz().unwrap(),
        )
        .unwrap();
        assert_eq!(FORM_4_8_9.normalized().unwrap(), target);
    }

    const FORM_4_3_11: Ibqf<{ I128::LIMBS }> = Ibqf {
        a: NonZero::<I128>::new_unwrap(I128::from_i32(4)),
        b: I128::from_i32(3),
        c: NonZero::<I128>::new_unwrap(I128::from_i32(11)),
        discriminant_bits: 8,
    };

    #[test]
    fn test_normalized_does_not_modify_normal() {
        assert_eq!(FORM_4_3_11.normalized().unwrap(), FORM_4_3_11);
    }

    #[test]
    fn test_is_reduced_true() {
        assert!(FORM_4_3_11.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_is_reduced_false_a_greater_than_c() {
        let form = Ibqf::new_from_elements(
            I128::from(11).to_nz().unwrap(),
            I128::from(3),
            I128::from(4).to_nz().unwrap(),
        )
        .unwrap();
        assert!(!form.normal_form_is_reduced_vartime());
    }

    const FORM_11_MIN3_11: Ibqf<{ I128::LIMBS }> = Ibqf {
        a: NonZero::<I128>::new_unwrap(I128::from_i32(11)),
        b: I128::from_i32(-3),
        c: NonZero::<I128>::new_unwrap(I128::from_i32(11)),
        discriminant_bits: 9,
    };

    #[test]
    fn test_is_reduced_false_a_equals_c_and_b_neg() {
        assert!(!FORM_11_MIN3_11.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_is_reduced_false_not_normal() {
        let form = Ibqf::new_from_elements(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(3),
            I128::from_i32(-9).to_nz().unwrap(),
        )
        .unwrap();
        assert!(!form.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_reduce_already_reduced() {
        assert_eq!(FORM_4_3_11.reduce_vartime().unwrap(), FORM_4_3_11);
    }

    #[test]
    fn test_reduce_a_greater_than_c() {
        let form = Ibqf::new_from_elements(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(3),
            I128::from_i32(4).to_nz().unwrap(),
        )
        .unwrap();
        let target = Ibqf::new_from_elements(
            I128::from_i32(4).to_nz().unwrap(),
            I128::from_i32(-3),
            I128::from_i32(11).to_nz().unwrap(),
        )
        .unwrap();
        assert_eq!(form.reduce_vartime().unwrap(), target);
    }

    #[test]
    fn test_reduce_a_equals_c_and_b_neg() {
        let target = Ibqf::new_from_elements(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(3),
            I128::from_i32(11).to_nz().unwrap(),
        )
        .unwrap();
        assert_eq!(FORM_11_MIN3_11.reduce_vartime().unwrap(), target);
    }

    const FORM_1_1_61: Ibqf<{ I128::LIMBS }> = Ibqf {
        a: NonZero::<I128>::new_unwrap(I128::from_i32(1)),
        b: I128::from_i32(1),
        c: NonZero::<I128>::new_unwrap(I128::from_i32(61)),
        discriminant_bits: 8,
    };

    #[test]
    fn test_inverse_is_valid() {
        let f = Ibqf::new_reduced_from_elements(
            I128::from_i32(23).to_nz().unwrap(),
            I128::from_i32(9),
            I128::from_i32(25).to_nz().unwrap(),
        )
        .unwrap();
        let inv_f = f.inverse();
        assert!(inv_f.is_normal_vartime());
        assert!(inv_f.is_reduced_vartime());
        assert_ne!(f, inv_f);

        let unit = f.nucomp(&inv_f).unwrap();
        assert_eq!(f.nucomp(&unit).unwrap(), f);
        assert_eq!(unit.nucomp(&f).unwrap(), f);
        assert_eq!(inv_f.nucomp(&unit).unwrap(), inv_f);
        assert_eq!(unit.nucomp(&inv_f).unwrap(), inv_f);

        // test with unit element
        let g = FORM_1_1_61;
        let inv_g = g.inverse();
        assert!(inv_g.is_normal_vartime());
        assert!(inv_g.is_reduced_vartime());
        assert_eq!(inv_g, g);
    }

    #[test]
    fn test_invert_without_reducing() {
        // The inverse of the unit element should not be reduced
        let inv = FORM_1_1_61.invert_without_reducing().unwrap();
        assert!(!inv.is_reduced_vartime());
    }

    #[test]
    fn test_unit() {
        let f = Ibqf::new_reduced_from_elements(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(15),
            I128::from_i32(71).to_nz().unwrap(),
        )
        .unwrap();
        let unit = f.unit().unwrap();

        assert_eq!(unit.nucomp(&f).unwrap(), f);
        assert_eq!(unit.nudupl().unwrap(), unit);
    }

    #[test]
    fn test_unit_for_discriminant() {
        let unit = Ibqf::<{ I128::LIMBS }>::unit_for_discriminant(&I128::from_i32(-3i32));
        assert!(unit.is_ok());

        let unit = Ibqf::<{ I128::LIMBS }>::unit_for_discriminant(&I128::from_i32(-5i32));
        assert!(unit.is_err());
    }

    #[test]
    fn test_nupow_relative_to_nudupl_and_nucomp() {
        let f = Ibqf::new_reduced_from_elements(
            I128::from_i32(11).to_nz().unwrap(),
            I128::from_i32(16),
            I128::from_i32(71).to_nz().unwrap(),
        )
        .unwrap();

        assert_eq!(
            f.nudupl().unwrap(),
            f.nupow(&Uint::<1>::from(2u64)).unwrap()
        );
        assert_eq!(
            f.nudupl().unwrap().nudupl().unwrap(),
            f.nupow(&Uint::<1>::from(4u64)).unwrap()
        );
        assert_eq!(
            f.nudupl().unwrap().nudupl().unwrap().nudupl().unwrap(),
            f.nupow(&Uint::<1>::from(8u64)).unwrap()
        );
        assert_eq!(
            f.nudupl()
                .unwrap() // 2
                .nucomp(&f)
                .unwrap() // 3
                .nudupl()
                .unwrap() // 6
                .nudupl()
                .unwrap() // 12
                .nucomp(&f)
                .unwrap() // 13
                .nudupl()
                .unwrap() // 26
                .nucomp(&f)
                .unwrap(), // 27
            f.nupow(&Uint::<1>::from(27u64)).unwrap()
        );

        let two_exp_63 = Uint::<1>::ONE << 63; // = 2^{63}
        let f2 = f.nupow(&two_exp_63).unwrap().nudupl().unwrap(); // = f^{2^32}
        let two_exp_64 = Uint::<2>::ONE << 64; // = 2^64
        let f3 = f.nupow(&two_exp_64).unwrap();
        assert_eq!(f2, f3);

        let f2 = f
            .nupow(&two_exp_63)
            .unwrap()
            .nupow(&two_exp_63)
            .unwrap()
            .nupow(&two_exp_63)
            .unwrap();
        let f3 = f.nupow(&(Uint::<3>::ONE << 189)).unwrap();
        assert_eq!(f2, f3);
    }

    #[test]
    fn test_nupow_ct_vs_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = *setup_parameters.h.representative();
        let exp = U256::random(&mut OsRng);
        assert_eq!(form.nupow(&exp).unwrap(), form.nupow_vartime(&exp).unwrap());
    }

    #[test]
    fn test_nupow_bounded_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h.representative();

        let exp = U64::random(&mut OsRng);

        assert_eq!(
            form.nupow_bounded(&exp, 35).unwrap(),
            form.nupow_bounded_vartime(&exp, 35).unwrap()
        );
    }

    #[test]
    fn test_nupow_with_base() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h.representative();
        let base = form.nupow_vartime(&U64::from(5u64)).unwrap();

        let exp = U64::random(&mut OsRng);
        assert_eq!(
            form.nupow_with_base(base, &exp).unwrap(),
            form.nupow(&exp)
                .unwrap()
                .nucomp(&base.nupow(&U128::ONE.shl(64)).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_nupow_with_base_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h.representative();
        let base = form.nupow_vartime(&U64::from(5u64)).unwrap();

        let exp = U64::random(&mut OsRng);
        assert_eq!(
            form.nupow_with_base_vartime(base, &exp).unwrap(),
            form.nupow_vartime(&exp)
                .unwrap()
                .nucomp(&base.nupow_vartime(&U128::ONE.shl(exp.bits())).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_nupow_bounded_with_base() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h.representative();
        let base = form.nupow_vartime(&U64::from(5u64)).unwrap();

        // Small bound
        let exp = U64::random(&mut OsRng);
        let bound = 35;
        assert_eq!(
            form.nupow_bounded_with_base(base, &exp, bound).unwrap(),
            form.nupow_bounded(&exp, bound)
                .unwrap()
                .nucomp(&base.nupow(&U64::ONE.shl(bound)).unwrap())
                .unwrap()
        );

        // Excessively large bound; exponentation should cap at 64
        let exp = U64::random(&mut OsRng);
        let bound = 73;
        assert_eq!(
            form.nupow_bounded_with_base(base, &exp, bound).unwrap(),
            form.nupow_bounded(&exp, bound)
                .unwrap()
                .nucomp(&base.nupow(&U128::ONE.shl(U64::BITS)).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_nupow_bounded_with_base_vartime() {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h.representative();
        let base = form.nupow_vartime(&U64::from(5u64)).unwrap();

        // Small bound
        let exp = U64::random(&mut OsRng);
        let bound = 35;
        assert_eq!(
            form.nupow_bounded_with_base_vartime(base, &exp, bound)
                .unwrap(),
            form.nupow_bounded_vartime(&exp, bound)
                .unwrap()
                .nucomp(&base.nupow_vartime(&U64::ONE.shl(bound)).unwrap())
                .unwrap()
        );

        // Excessively large bound; exponentation should cap at 64
        let exp = U64::random(&mut OsRng);
        let bound = 73;
        assert_eq!(
            form.nupow_bounded_with_base_vartime(base, &exp, bound)
                .unwrap(),
            form.nupow_bounded_vartime(&exp, bound)
                .unwrap()
                .nucomp(&base.nupow_vartime(&U128::ONE.shl(U64::BITS)).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn test_prime_to() {
        let f = Ibqf::new_reduced_from_elements(
            I128::from(30i32).to_nz().unwrap(),
            I128::from(11i32),
            I128::from(42i32).to_nz().unwrap(),
        )
        .unwrap();

        // returns self when self.a is already coprime with p
        let p = Uint::from(13u32).to_nz().unwrap();
        assert_eq!(f.as_form_prime_to(&p).unwrap(), f);

        // returns `self.mirrored` when self.c is coprime with p
        let p = Uint::from(5u32).to_nz().unwrap();
        assert_eq!(
            f.as_form_prime_to(&p).unwrap(),
            f.mirror_unreduced().unwrap()
        );

        // returns composition when self.a and self.c are not prime relative to p
        let p = Uint::from(6u32).to_nz().unwrap();
        let target = Ibqf::new_from_elements(
            I128::from(83).to_nz().unwrap(),
            I128::from(-71),
            I128::from(30).to_nz().unwrap(),
        )
        .unwrap();
        let res = f.as_form_prime_to(&p).unwrap();
        assert_eq!(res, target);
    }

    #[test]
    fn test_to_maximal_order() {
        let conductor = U128::from(71u32);
        let conductor_ = conductor.to_int().unwrap();
        let discriminant_minimal_order = Discriminant::new(
            conductor
                .wrapping_mul(&conductor)
                .wrapping_mul(&conductor)
                .as_int()
                .checked_neg()
                .unwrap()
                .to_nz()
                .unwrap(),
        )
        .unwrap();

        let mut inv = U128::from(55u32)
            .inv_mod(&conductor)
            .unwrap()
            .to_int()
            .unwrap();
        if inv.rem_uint(&U128::from(2u32).to_nz().unwrap()) == I128::ZERO {
            inv = inv.checked_sub(&conductor_).unwrap();
        }

        let f = Ibqf::new_reduced(
            conductor_
                .checked_mul(&conductor_)
                .unwrap()
                .to_nz()
                .unwrap(),
            inv * conductor_,
            &discriminant_minimal_order,
        )
        .unwrap();

        let discriminant_maximal_order =
            Discriminant::new(conductor_.checked_neg().unwrap().to_nz().unwrap()).unwrap();
        assert_eq!(
            f.to_maximal_order(
                &conductor.resize().to_nz().unwrap(),
                &discriminant_maximal_order
            )
            .unwrap(),
            Ibqf::new_from_elements(
                I128::from(258).to_nz().unwrap(),
                I128::from(22673),
                I128::from(498125).to_nz().unwrap(),
            )
            .unwrap()
        );
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{BenchmarkGroup, Criterion};
    use crypto_bigint::{
        Concat, Encoding, Gcd, Int, InvMod, NonZero, Random, Split, Uint, U1024, U2048, U256, U512,
    };
    use rand_core::OsRng;

    use crate::ibqf::nucomp::benches::benchmark_nucomp;
    use crate::ibqf::nudupl::benches::benchmark_nudupl;
    use crate::ibqf::{math, Ibqf};
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::EquivalenceClass;

    fn benchmark_reduce<const LIMBS: usize, const DOUBLE_LIMBS: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        form: Ibqf<LIMBS>,
    ) where
        Int<LIMBS>: Encoding + InvMod<Modulus = NonZero<Uint<LIMBS>>, Output = Uint<LIMBS>>,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>> + Gcd<Output = Uint<LIMBS>>,

        Int<DOUBLE_LIMBS>: Encoding,
        Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        let form = form
            .mirror_unreduced()
            .unwrap()
            .invert_without_reducing()
            .unwrap();
        assert!(!form.is_reduced_vartime());
        g.bench_function("reduce vartime", |b| b.iter(|| form.reduce_vartime()));
        g.bench_function("reduce", |b| b.iter(|| form.reduce()));
        g.bench_function("reduce_randomized", |b| b.iter(|| form.reduce_randomized()));
    }

    fn benchmark_nupow<const HALF: usize, const LIMBS: usize, const DOUBLE_LIMBS: usize>(
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
        let mut form = *form.representative();

        let exp = U256::random(&mut OsRng);
        g.bench_function("nupow U256 (ct)", |b| {
            b.iter(|| {
                form = form.nupow(&exp).unwrap();
            })
        });
        g.bench_function("nupow U256 (vt)", |b| {
            b.iter(|| {
                form = form.nupow_vartime(&exp).unwrap();
            })
        });

        let exp = U512::random(&mut OsRng);
        g.bench_function("nupow U512 (ct)", |b| {
            b.iter(|| {
                form = form.nupow(&exp).unwrap();
            })
        });
        g.bench_function("nupow U512 (vt)", |b| {
            b.iter(|| {
                form = form.nupow_vartime(&exp).unwrap();
            })
        });

        let exp = U1024::random(&mut OsRng);
        g.bench_function("nupow U1024 (ct)", |b| {
            b.iter(|| {
                form = form.nupow(&exp).unwrap();
            })
        });
        g.bench_function("nupow U1024 (vt)", |b| {
            b.iter(|| {
                form = form.nupow_vartime(&exp).unwrap();
            })
        });

        let exp = U2048::random(&mut OsRng);
        g.bench_function("nupow U2048 (ct)", |b| {
            b.iter(|| {
                form = form.nupow(&exp).unwrap();
            })
        });
        g.bench_function("nupow U2048 (vt)", |b| {
            b.iter(|| {
                form = form.nupow_vartime(&exp).unwrap();
            })
        });
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        {
            let mut group = _c.benchmark_group("ibqf/secp256k1");
            group.warm_up_time(Duration::from_secs(5));
            group.measurement_time(Duration::from_secs(10));

            let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
            let ec = setup_parameters.h;
            let form = *ec.representative();

            let unreduced_form = form
                .nucomp_unreduced(&form.nudupl_vartime().unwrap())
                .unwrap();
            benchmark_reduce(&mut group, unreduced_form);
            benchmark_nucomp(&mut group, ec);
            benchmark_nudupl(&mut group, ec);
            benchmark_nupow(&mut group, ec);
        }

        math::benches::benchmark(_c);
    }
}
