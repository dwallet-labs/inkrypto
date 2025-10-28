// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::discriminant::Discriminant;
use crate::helpers::vartime_mul::CheckedMulVartime;
use crate::ibqf::math::bounded_div_rem_vartime;
use crate::ibqf::Ibqf;
use crate::Error;
use crypto_bigint::subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
    CtOption,
};
use crypto_bigint::{
    CheckedAdd, CheckedMul, CheckedSub, Concat, ConstantTimeSelect, Encoding, Gcd, Int, Limb,
    NonZeroInt, NonZeroUint, Split, Uint, Zero,
};
use serde::{Deserialize, Serialize};
use std::mem;
use std::ops::{BitAnd, BitOr, Deref, Not};

/// Unreduced Equivalent of [`Ibqf`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnreducedIbqf<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
{
    pub(super) a: NonZeroInt<LIMBS>,
    pub(super) b: Int<LIMBS>,
    pub(super) c: NonZeroInt<LIMBS>,
    pub(super) discriminant_bits: u32,
}

impl<const LIMBS: usize, const DOUBLE: usize> UnreducedIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>>,
    Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    /// Construct a new form `(a, b, c)`, given `(a, b)` and discriminant `∆`.
    /// Upon success, this form has the following properties:
    /// - It has a negative discriminant,
    /// - It is primitive
    ///
    /// Note: to construct a new _reduced_ form, use [Ibqf::new].
    pub fn new(
        a: NonZeroUint<LIMBS>,
        b: Int<LIMBS>,
        discriminant: &Discriminant<LIMBS>,
    ) -> CtOption<Self> {
        // Given `a`, `b` and `∆`, one can compute `c` coefficient as follows:
        //       ∆ =  b² − 4ac
        // <=> 4ac =  b² − ∆
        // <=>   c = [b² − ∆]/4a
        // Note: this yields a valid form if and only if the division is exact.

        let b_sqr = b.widening_square().try_into_int().expect(
            "safe to cast; a square of a k-bit int can be represented using at most 2k-1 bits",
        );

        let b_sqr_min_d = b_sqr
            .checked_sub(
                &discriminant
                    .deref()
                    .resize::<DOUBLE>()
                    .to_nz()
                    .expect("upscaled non-zero value is non-zero"),
            )
            .expect("b² - ∆ = b² + |∆| < 2^{2k-1} since both |b| and |∆| are ≤ 2^k");

        // safe to vartime; shl_vartime is vartime only in the shift, which is static here.
        let four_a = a
            .resize::<DOUBLE>()
            .wrapping_shl_vartime(2)
            .to_nz()
            .expect("4x a non-zero value is non-zero; no wrapping on shift due to upscale");
        let (c, remainder) = b_sqr_min_d.div_rem_uint(&four_a);

        let c = CtOption::new(c, remainder.is_zero())
            .and_then(|c| {
                let safe_to_resize = c.abs().bits().ct_lt(&Uint::<LIMBS>::BITS);
                CtOption::new(c.resize::<LIMBS>(), safe_to_resize)
            })
            .and_then(|c| c.to_nz().into());

        let form = CtOption::from(a.try_into_int())
            .and_then(|a| a.to_nz().into())
            .and_then(|a| {
                c.map(|c| Self {
                    a,
                    b,
                    c,
                    discriminant_bits: discriminant.bits_vartime(),
                })
            });

        form.and_then(|form| CtOption::new(form, form.is_primitive()))
    }
}

impl<const HALF: usize, const LIMBS: usize> UnreducedIbqf<LIMBS>
where
    Uint<HALF>: Concat<Output = Uint<LIMBS>>,
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding + Split<Output = Uint<HALF>>,
{
    /// Variation to [`Self::new`] which assumes `b² + |∆|` fits in [`Uint<LIMBS>`].
    ///
    /// Executes in variable time w.r.t. `discriminant`.
    pub fn new_compact_vartime_discriminant(
        a: NonZeroUint<HALF>,
        b: Int<HALF>,
        discriminant: &Discriminant<LIMBS>,
    ) -> CtOption<Self> {
        // b² − ∆
        let b_sqr_min_d = b.widening_square().checked_add(&discriminant.abs());

        // [b² − ∆]/4
        let b_sqr_min_d_div_4 = b_sqr_min_d.and_then(|b_sqr_min_d| {
            let is_zero_mod_4 = b_sqr_min_d.as_limbs()[0].bitand(Limb::from(3u32)).is_zero();

            // Safe to vartime; vartime only in shift, which is known.
            let b_sqr_min_d_div_4 = b_sqr_min_d.shr_vartime(2);

            CtOption::new(b_sqr_min_d_div_4, is_zero_mod_4)
        });

        // [b² − ∆]/4a
        let c = b_sqr_min_d_div_4
            .and_then(|b_sqr_min_d_div_4| {
                let (c, remainder) = b_sqr_min_d_div_4.div_rem(&a);
                CtOption::new(c, remainder.is_zero())
            })
            .and_then(|c| c.try_into_int().into())
            .and_then(|c| c.to_nz().into());

        let form = CtOption::from(a.try_into_int())
            .and_then(|a| a.to_nz().into())
            .and_then(|a| {
                c.map(|c| Self {
                    a: a.resize().to_nz().unwrap(),
                    b: b.resize(),
                    c,
                    discriminant_bits: discriminant.bits_vartime(),
                })
            });

        form.and_then(|form| {
            CtOption::new(
                form,
                form.compact_is_primitive_vartime_discriminant(discriminant),
            )
        })
    }

    /// Whether this form is primitive, i.e., whether `gcd(a, b, c) = 1`.
    ///
    /// Assumes `a` and `b` fit in [`Uint<HALF>`] and [`Int<HALF>`], respectively.
    ///
    /// Executes in variable time w.r.t. `discriminant`.
    fn compact_is_primitive_vartime_discriminant(
        &self,
        discriminant: &Discriminant<LIMBS>,
    ) -> Choice {
        // Since `self` is constructed from a `CompactIbqf`, `a` and `b` fit in HALF limbs.
        let a = self.a.resize::<HALF>();
        let b = self.b.resize::<HALF>();

        if 2 * discriminant.lower_bound_p_bits_vartime() >= discriminant.bits_vartime() {
            // At this point ||p|| > ||Δ||/2 and thus p > q.
            //
            // Recall that Δ = -pq^{2k+1}. Let g := gcd(a, b, c).
            // Let A := a/g, B := b/g and C := c/g. It now follows that
            // -pq^{2k+1} = Δ = b² - 4ac = g²B² - 4g²AC = g²(B²-4AC), implying that g² must
            // divide -pq^{2k+1}. With p and q both integral and p > q, it must be that g² must
            // divide q^2k.

            if discriminant.k() == 0 {
                // With k = 0, g² must divide q^2k = 1 and thus g = ±1.
                // We can therefore conclude that this form is primitive.
                return Choice::from(1u8);
            }

            // Because gcd(a, b, c) is either 1 or a multiple of q, it is sufficient to check
            // whether a, b, c are divisible by q. In fact, we only need to perform this check for
            // a and c:
            //
            // Let f = gcd(a, c), A' := a/f, and C' := c/f.
            // -pq^{2k+1} = Δ = b² - 4ac = b² - 4f²A'C'
            // and thus
            // -pq^{2k+1}/f² = b²/f² - 4A'C'
            //
            // Since k > 0, f² is a proper divisor of q^{2k+1}. It therefore follows that f² must
            // be also be a proper divisor of b² and f thus a proper divisor of b.

            let a_is_zero_mod_q = a.rem_uint(discriminant.q()).is_zero();
            let c_is_zero_mod_q = self.c.rem_uint(discriminant.q()).is_zero();

            return a_is_zero_mod_q.bitand(c_is_zero_mod_q).not();
        }

        // Note that gcd(a, b, c) = gcd(gcd(a, b), c) and gcd(x, y) = gcd(x, y mod x)
        let gcd_a_b = a
            .gcd(&b)
            .to_nz()
            .expect("gcd is non-zero since a is non-zero.");
        let c_mod_gcd = self.c.abs().rem(&gcd_a_b);
        gcd_a_b.gcd_uint(&c_mod_gcd).ct_eq(&NonZeroUint::ONE)
    }
}

impl<const LIMBS: usize> UnreducedIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    /// Whether this form is primitive.
    ///
    /// A form `(a, b, c)` is primitive when `gcd(a, b, c) = 1`.
    ///
    /// Ref: Definition 5.2.3 in "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    fn is_primitive(&self) -> Choice {
        (*self.a.as_ref().gcd(&self.b).gcd(&self.c)).ct_eq(&Uint::ONE)
    }

    /// Construct `self⁻¹`.
    pub fn inverse(self) -> CtOption<Self> {
        self.inverse_if(Choice::from(1u8))
    }

    /// Returns `self⁻¹` if `choice` is truthy. Otherwise, returns `self`.
    pub fn inverse_if(self, choice: Choice) -> CtOption<Self> {
        CtOption::from(self.b.checked_neg()).map(|neg_b| Self {
            a: self.a,
            b: Int::ct_select(&self.b, &neg_b, choice),
            c: self.c,
            discriminant_bits: self.discriminant_bits,
        })
    }

    /// Whether this form is normal.
    /// A form is normal when `-a < b ≤ a`.
    fn is_normal(&self) -> Choice {
        self.a
            .checked_neg()
            .expect("safe to wrap; a is positive by construction: its negation always fits.")
            .ct_lt(&self.b)
            .bitand(!self.a.ct_lt(&self.b))
    }

    /// Normalize this form, i.e.,
    /// map `(a, b, c)` to `(a, r, c - q(b+r)/2)`, where `(q, r) := ⌈b/a⌉`.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://gite.lirmm.fr/crypto/bicycl/-/blob/master/src/bicycl/arith/qfi.inl?ref_type=heads#L479).
    /// This is a variation on Algorithm 5.4.2, as found in "A Course in Computational Algebraic
    /// Number Theory" (978-3-662-02945-9).
    pub fn normalize(mut self) -> CtOption<Self> {
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
        let new_c = CtOption::from(r.checked_add(&self.b))
            .map(|b_plus_r| b_plus_r.shr_vartime(1))
            .and_then(|b_plus_r_on_two| b_plus_r_on_two.checked_mul(&q))
            .and_then(|qb_plus_qr_on_two| self.c.wrapping_sub(&qb_plus_qr_on_two).to_nz().into());

        new_c.map(|new_c| {
            self.c = new_c;
            self
        })
    }

    /// Variable time equivalent of [Ibqf::is_normal].
    fn is_normal_vartime(&self) -> bool {
        // safe to wrap; a is positive by construction, the negation of which always fits.
        self.a.wrapping_neg() < self.b && self.b <= self.a.get()
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
        self.c = CtOption::from(r.checked_add(&self.b))
            .map(|b_plus_r| b_plus_r.shr_vartime(1))
            .and_then(|b_plus_r_on_two| b_plus_r_on_two.checked_mul_vartime(&q))
            .and_then(|qb_plus_qr_on_two| self.c.wrapping_sub(&qb_plus_qr_on_two).to_nz().into())
            .into_option()
            .ok_or(Error::InternalError)?;

        Ok(self)
    }

    /// Whether this form is reduced.
    /// A form `(a, b, c)` is reduced when
    /// 1. It [Ibqf::is_normal],
    /// 2. And
    ///     - a < c, or
    ///     - a = c and b >= 0.
    fn is_reduced(&self) -> Choice {
        self.is_normal().bitand(self.normal_form_is_reduced())
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

    /// Reduce this form.
    ///
    /// For the faster, fallible conversion, use [`Self::try_into_reduced`].
    ///
    /// Given that the size of `|c|` is decreased by at least a factor `(1/4 + Δ/√(4c²))` in each
    /// `rho` iteration, the form should be fully reduced after at most `||Δ||/4 + 4` iterations.
    ///
    /// Ref: Section 5.2.1 in
    /// <https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf>
    pub fn reduce(self) -> Ibqf<LIMBS> {
        let res = self.reduce_core(self.discriminant_bits.div_ceil(4) + 3);

        // It could be that we need one more rho iteration to mirror the form
        let res = Self::ct_select(&res.rho().expect("rho succeeds"), &res, res.is_reduced());

        res.try_into_reduced().expect("is reduced")
    }

    /// Attempt to reduce this form in 36 iterations.
    ///
    /// Returns `None` whenever the result is not reduced.
    ///
    /// For the faster, fallible conversion, use [`Self::try_into_reduced`].
    ///
    /// ### Randomized.
    /// This variation to [Ibqf::reduce] assumes that `self` is the unreduced composition of two
    /// randomized forms. This assumption implies that significantly fewer iterations are required
    /// to reduce this composed form.
    ///
    /// More precisely, the bit size of the output of the composition of two random forms
    /// satisfies that `||c|| < ||Δ||/2 + 64` with probability `1-2^{-64}`. As every reduction
    /// step decreases `|c|` by at least one bit, we are guaranteed that performing 64 iterations
    /// will output a reduced form.
    ///
    /// Paired with the `1/4 + Δ/√(4c²)` reduction factor on the size of `c` per `rho` iteration,
    /// the form should be reduced after at most 36 iterations.
    pub fn reduce_randomized(self) -> CtOption<Ibqf<LIMBS>> {
        let res = self.reduce_core(35);

        // It could be that we need one more rho iteration to mirror the form
        let res = Self::ct_select(&res.rho().expect("rho succeeds"), &res, res.is_reduced());

        res.try_into_reduced()
    }

    /// Reduce the size of the representation of `self`.
    ///
    /// This is achieved by applying the `rho` function `iterations` times. Each iteration,
    /// the value of `c` is decreased by at least a factor `1/4 + Δ/√(4c²)`, until the minimal
    /// representation has been reached.
    ///
    /// Ref: Section 5.2.1 in
    /// <https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf>
    fn reduce_core(self, iterations: u32) -> Self {
        let mut res = self.normalize().expect("normalize succeeds");
        for _ in 0..iterations {
            res = res.rho().expect("rho succeeds");
        }
        res
    }

    /// Map `(a, b, c)` to `(c, -b + 2sc, cs² - br + a)`, where `s := ⌊(b+c)/2c⌋`.
    ///
    /// Observe that the result equals `(c, -b, a)` when `self` is reduced.
    ///
    /// ### Shrink factor
    /// For unreduced `self`, this operation shrinks the value of `self.c` by at least a factor
    /// ```text
    /// (1/4 + Δ/√(4c²))
    /// ```
    fn rho(self) -> CtOption<Self> {
        self.mirror_unreduced().and_then(|form| form.normalize())
    }

    /// Map `(a, b, c)` to `(c, -b, a)`.
    fn mirror_unreduced(mut self) -> CtOption<Self> {
        mem::swap(&mut self.a, &mut self.c);
        self.inverse()
    }

    /// Whether this form is reduced.
    /// A form `(a, b, c)` is reduced when
    /// 1. It [Ibqf::is_normal_vartime],
    /// 2. And
    ///     - a < c, or
    ///     - a = c and b >= 0.
    fn is_reduced_vartime(&self) -> bool {
        self.is_normal_vartime() && self.normal_form_is_reduced_vartime()
    }

    /// Whether this normal form is reduced.
    /// Note: assumes it is normalized.
    /// See [Ibqf::is_reduced_vartime] for more details.
    #[inline]
    fn normal_form_is_reduced_vartime(&self) -> bool {
        self.a < self.c || (self.a == self.c && !bool::from(self.b.is_negative()))
    }

    /// Reduce this form.
    ///
    /// Operation is performed in variable time.
    ///
    /// For the faster, fallible conversion, use [`Self::try_into_reduced`].
    ///
    /// Ref: Section 5.2.1 in
    /// <https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf>
    pub fn reduce_vartime(self) -> Result<Ibqf<LIMBS>, Error> {
        let mut res = self.normalize_vartime()?;
        while !res.normal_form_is_reduced_vartime() {
            res = res.rho_vartime()?;
        }
        Ibqf::try_from(res)
    }

    /// Variable time equivalent of [Ibqf::rho]
    fn rho_vartime(self) -> Result<Self, Error> {
        self.mirror_unreduced()
            .into_option()
            .ok_or(Error::InternalError)
            .and_then(|form| form.normalize_vartime())
    }
}

// Conversion
impl<const LIMBS: usize> UnreducedIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    /// Fallibly convert this form into the reduced [`Ibqf`].
    ///
    /// The output `is_some` if `self.is_reduced`; otherwise returns `None`.
    ///
    /// For non-fallible conversion, use one of the slower [`Self::reduce`],
    /// [`Self::reduce_randomized`] or [`Self::reduce_vartime`] functions instead.
    pub(crate) fn try_into_reduced(self) -> CtOption<Ibqf<LIMBS>> {
        let value = Ibqf {
            a: self.a,
            b: self.b,
            c: self.c,
            discriminant_bits: self.discriminant_bits,
        };
        CtOption::new(value, self.is_reduced())
    }
}

impl<const LIMBS: usize> From<&Ibqf<LIMBS>> for UnreducedIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn from(value: &Ibqf<LIMBS>) -> Self {
        Self {
            a: value.a,
            b: value.b,
            c: value.c,
            discriminant_bits: value.discriminant_bits,
        }
    }
}

impl<const LIMBS: usize> TryFrom<UnreducedIbqf<LIMBS>> for Ibqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Error = Error;

    fn try_from(value: UnreducedIbqf<LIMBS>) -> Result<Self, Self::Error> {
        value
            .try_into_reduced()
            .into_option()
            .ok_or(Error::Unreduced)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for UnreducedIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            a: NonZeroInt::conditional_select(&a.a, &b.a, choice),
            b: Int::conditional_select(&a.b, &b.b, choice),
            c: NonZeroInt::conditional_select(&a.c, &b.c, choice),
            discriminant_bits: u32::conditional_select(
                &a.discriminant_bits,
                &b.discriminant_bits,
                choice,
            ),
        }
    }
}

impl<const LIMBS: usize> Default for UnreducedIbqf<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self {
            a: Int::from(2i64).to_nz().unwrap(),
            b: Int::<LIMBS>::ONE,
            c: Int::from(2i64).to_nz().unwrap(),
            discriminant_bits: 2,
        }
    }
}

#[cfg(any(test, feature = "test_helpers"))]
mod test_helpers {
    use crate::discriminant::Discriminant;
    use crate::ibqf::unreduced::UnreducedIbqf;
    use crypto_bigint::subtle::CtOption;
    use crypto_bigint::{Concat, Encoding, Int, Split, Uint, U128, U64};

    impl<const LIMBS: usize, const DOUBLE: usize> UnreducedIbqf<LIMBS>
    where
        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        /// Construct an [`UnreducedIbqf`] from three `u64/i64` coefficients.
        pub(crate) const fn from_i64(a: u64, b: i64, c: i64) -> Self {
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

        /// Variation to [`UnreducedIbqf::new`] that accepts `u64/i64`s
        pub(crate) fn new_64(a: u64, b: i64, d: (u64, u32, u64)) -> CtOption<Self> {
            let a = Uint::from(a).to_nz().unwrap();
            let b = Int::from(b);

            let (q, k, p) = d;
            let d = Discriminant::new_u64(q, k, p).unwrap();
            Self::new(a, b, &d)
        }
    }

    impl<const HALF: usize, const LIMBS: usize, const DOUBLE: usize> UnreducedIbqf<LIMBS>
    where
        Int<LIMBS>: Encoding,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>,
        Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        /// Variation to [`UnreducedIbqf::new_compact_vartime_discriminant`] that accepts `u64/i64`s
        pub(crate) fn new_compact_64(a: u64, b: i64, d: (u64, u32, u64)) -> CtOption<Self> {
            let a = Uint::from(a).to_nz().unwrap();
            let b = Int::from(b);

            let (q, k, p) = d;
            let d = Discriminant::new_u64(q, k, p).unwrap();
            Self::new_compact_vartime_discriminant(a, b, &d)
        }
    }

    pub(crate) type UnreducedIbqf64 = UnreducedIbqf<{ U64::LIMBS }>;
    pub(crate) type UnreducedIbqf128 = UnreducedIbqf<{ U128::LIMBS }>;
}

#[cfg(test)]
mod tests {
    use crate::ibqf::test_helpers::{Ibqf128, Ibqf64};
    use crate::ibqf::unreduced::test_helpers::{UnreducedIbqf128, UnreducedIbqf64};
    use crate::ibqf::unreduced::UnreducedIbqf;
    use crypto_bigint::Int;

    #[test]
    fn test_new_compact() {
        let d = (9051846487106533807, 0, 6237328879402234877);
        let a = 710020825444479141;
        let b = -220583842534643419;
        let c = 19896599758943023575i128;

        let val = UnreducedIbqf128::new_compact_64(a, b, d);
        assert!(bool::from(val.is_some()));
        assert_eq!(val.unwrap().c, Int::from_i128(c).to_nz().unwrap());
    }

    #[test]
    fn test_is_primitive() {
        let discriminant = -17 * 17 * 67;
        let primitive = UnreducedIbqf128::from_i64(59, 15, discriminant);
        assert!(bool::from(primitive.is_primitive()));

        let not_primitive = UnreducedIbqf128::from_i64(323, 51, discriminant);
        assert!(!bool::from(not_primitive.is_primitive()));
    }

    #[test]
    fn test_normalize() {
        let form = UnreducedIbqf64::from_i64(4, 8, 9);
        let target = UnreducedIbqf::from_i64(4, 0, 5);
        assert_eq!(form.normalize().unwrap(), target);
    }

    #[test]
    fn test_normalize_does_not_modify_normal() {
        let form = UnreducedIbqf64::from_i64(4, 3, 11);
        assert_eq!(form.normalize().unwrap(), form);
    }

    #[test]
    fn test_is_reduced_true() {
        let form = UnreducedIbqf64::from_i64(4, 3, 11);
        assert!(form.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_is_reduced_false_a_greater_than_c() {
        let form = UnreducedIbqf64::from_i64(11, 3, 4);
        assert!(!form.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_is_reduced_false_a_equals_c_and_b_neg() {
        let form = UnreducedIbqf64::from_i64(11, -3, 11);
        assert!(!form.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_is_reduced_false_not_normal() {
        let form = UnreducedIbqf128::from_i64(11, 3, -9);
        assert!(!form.normal_form_is_reduced_vartime());
    }

    #[test]
    fn test_reduce_already_reduced() {
        let form = UnreducedIbqf64::from_i64(4, 3, 11);
        let target = Ibqf64::from_64(4, 3, 11);
        assert_eq!(form.reduce_vartime().unwrap(), target);
    }

    #[test]
    fn test_reduce_a_greater_than_c() {
        let form = UnreducedIbqf128::from_i64(11, 3, 4);
        let target = Ibqf128::from_64(4, -3, 11);
        assert_eq!(form.reduce_vartime().unwrap(), target);
    }

    #[test]
    fn test_reduce_a_equals_c_and_b_neg() {
        let form = UnreducedIbqf64::from_i64(11, -3, 11);
        let target = Ibqf64::from_64(11, 3, 11);
        assert_eq!(form.reduce_vartime().unwrap(), target);
    }

    #[test]
    fn test_invert_without_reducing() {
        // The inverse of the unit element should not be reduced
        let unit = UnreducedIbqf64::from_i64(1, 1, 61);
        let inv = unit.inverse().unwrap();
        assert!(!inv.is_reduced_vartime());
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use crate::ibqf::unreduced::UnreducedIbqf;

    use crate::discriminant::Discriminant;
    use criterion::measurement::WallTime;
    use criterion::{BatchSize, BenchmarkGroup};
    use crypto_bigint::{Concat, Encoding, Int, NonZeroUint, Random, Split, Uint};
    use group::OsCsRng;

    pub(crate) fn benchmark_new_compact<
        const HALF: usize,
        const LIMBS: usize,
        const DOUBLE: usize,
    >(
        g: &mut BenchmarkGroup<WallTime>,
        d: &Discriminant<LIMBS>,
    ) where
        Uint<HALF>: Concat<Output = Uint<LIMBS>>,
        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        g.bench_function("new_compact", |b| {
            b.iter_batched(
                || {
                    let a = NonZeroUint::<HALF>::random(&mut OsCsRng);
                    let b = Int::<HALF>::random(&mut OsCsRng);
                    (a, b)
                },
                |(a, b)| UnreducedIbqf::new_compact_vartime_discriminant(a, b, d),
                BatchSize::SmallInput,
            )
        });
    }

    pub(crate) fn benchmark_reduce<const LIMBS: usize, const DOUBLE: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        form: UnreducedIbqf<LIMBS>,
    ) where
        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE>>,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        let form = form.mirror_unreduced().unwrap().inverse().unwrap();
        assert!(!form.is_reduced_vartime());
        g.bench_function("reduce vartime", |b| b.iter(|| form.reduce_vartime()));
        g.bench_function("reduce", |b| b.iter(|| form.reduce()));
        g.bench_function("reduce_randomized", |b| b.iter(|| form.reduce_randomized()));
    }
}
