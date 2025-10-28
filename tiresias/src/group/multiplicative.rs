// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{
    modular::{MontyForm, MontyParams},
    Concat, Encoding, Int, NonZero, Odd, RandomMod, Split, Uint,
};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use group::linear_combination::linearly_combine_bounded_or_scale;
use group::{
    BoundedGroupElement, CsRng, GroupElement as _, LinearlyCombinable, Samplable, Scale,
    Transcribeable,
};

/// An element of the [Multiplicative group of integers modulo N](https://en.wikipedia.org/wiki/Multiplicative_group_of_integers_modulo_n)
/// where `N = PQ` $\mathbb{Z}_N^*$ for the randomness space of the Paillier cryptosystem
/// or $\mathbb{Z}_N^{2*}$ for the ciphertext space.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct GroupElement<const LIMBS: usize>(pub(crate) MontyForm<LIMBS>);

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Samplable for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> group::Result<Self> {
        // Montgomery form only works for odd modulus, and this is assured in `MontyForm`
        // instantiation; therefore, the modulus of an instance can never be zero and it is safe to
        // `unwrap()`.
        let modulus = NonZero::new(**public_parameters.params.modulus()).unwrap();

        // Classic rejection-sampling technique.
        loop {
            let value = Value::new(Uint::<LIMBS>::random_mod(rng, &modulus), public_parameters)?;

            match Self::new(value, public_parameters) {
                Err(group::Error::InvalidGroupElement) => {
                    continue;
                }
                Ok(sampled_element) => {
                    return Ok(sampled_element);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> group::Result<Self> {
        Self::sample(public_parameters, rng)
    }
}

/// The value of a group element of the multiplicative group of integers modulo `n` $\mathbb{Z}_n^*$
#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, Default, Serialize, Deserialize)]
pub struct Value<const LIMBS: usize>(Uint<LIMBS>)
where
    Uint<LIMBS>: Encoding;

impl<const LIMBS: usize> Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    pub fn new(
        value: Uint<LIMBS>,
        public_parameters: &PublicParameters<LIMBS>,
    ) -> group::Result<Self> {
        let element = MontyForm::<LIMBS>::new(&value, public_parameters.params);

        Ok(Self(*element.as_montgomery()))
    }
}

impl<const LIMBS: usize> ConstantTimeEq for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Uint::<LIMBS>::conditional_select(&a.0, &b.0, choice))
    }
}

impl<const LIMBS: usize> ConstantTimeEq for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for GroupElement<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<MontyForm<LIMBS> as ConditionallySelectable>::conditional_select(&a.0, &b.0, choice))
    }
}

/// The public parameters of the multiplicative group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PublicParameters<const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub(crate) params: MontyParams<LIMBS>,
}

impl<const LIMBS: usize> Serialize for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.params.modulus().serialize(serializer)
    }
}

impl<'de, const LIMBS: usize, const WIDE_LIMBS: usize> Deserialize<'de> for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let modulus = Uint::<LIMBS>::deserialize(deserializer)?;

        PublicParameters::new(modulus).map_err(Error::custom)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Transcribeable for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type CanonicalRepresentation = Self;
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> PublicParameters<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    pub fn new(modulus: Uint<LIMBS>) -> group::Result<Self> {
        #[allow(deprecated)]
        let modulus = Odd::new(modulus);
        if modulus.is_none().into() {
            return Err(group::Error::UnsupportedPublicParameters);
        }
        let params = MontyParams::<LIMBS>::new(modulus.unwrap());

        Ok(Self { params })
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> LinearlyCombinable for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> group::Result<Self> {
        linearly_combine_bounded_or_scale(bases_and_multiplicands, exponent_bits, true)
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> group::Result<Self> {
        linearly_combine_bounded_or_scale(bases_and_multiplicands, exponent_bits, false)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> group::GroupElement for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Value = Value<LIMBS>;
    type PublicParameters = PublicParameters<LIMBS>;

    fn value(&self) -> Self::Value {
        self.0.into()
    }

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        let element = MontyForm::<LIMBS>::from_montgomery(value.0, public_parameters.params);

        // `element` is valid if and only if it has an inverse if and only if it is not co-primed to
        // the modulus $N$ or $N^2$. In the Paillier randomness and ciphertext groups, every square
        // number except for zero that is not co-primed to $N^2$ yields factorization of
        // $N$. Therefore checking that a square number is not zero sufficiently assures
        // they belong to the quadratic-residue group, which is required for the ciphertext group,
        // and that it is a valid group element, which is required for both groups.
        //
        // Note that if we'd have perform this check prior to squaring, it wouldn't have suffice;
        // take e.g. g = N != 0 -> g^2 = N^2 mod N^2 = 0 (accepting this value would have allowed
        // bypassing of the proof).

        if element.square() == MontyForm::<LIMBS>::zero(public_parameters.params) {
            Err(group::Error::InvalidGroupElement)
        } else {
            Ok(Self(element))
        }
    }

    fn neutral(&self) -> Self {
        GroupElement(MontyForm::<LIMBS>::one(*self.0.params()))
    }

    fn scale<const RHS_LIMBS: usize>(&self, scalar: &Uint<RHS_LIMBS>) -> Self {
        // This is inefficient, but in a hidden-order group, we can't do better than this as we
        // can't take the scalar modulus the order.
        Self(self.0.pow(scalar))
    }

    fn scale_bounded<const SCALAR_LIMBS: usize>(
        &self,
        scalar: &Uint<SCALAR_LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        // This is inefficient, but in a hidden-order group, we can't do better than this as we
        // can't take the scalar modulus the order.
        Self(self.0.pow_bounded_exp(scalar, scalar_bits))
    }

    fn double(&self) -> Self {
        Self(self.0.square())
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(GroupElement(MontyForm::<LIMBS>::one(
            public_parameters.params,
        )))
    }

    fn scale_bounded_vartime<const SCALAR_LIMBS: usize>(
        &self,
        scalar: &Uint<SCALAR_LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits)
    }

    fn add_vartime(self, other: &Self) -> Self {
        self + other
    }

    fn double_vartime(&self) -> Self {
        self.double()
    }

    fn add_randomized(self, other: &Self) -> Self {
        self + other
    }

    fn sub_randomized(self, other: &Self) -> Self {
        self - other
    }

    fn sub_vartime(self, other: &Self) -> Self {
        self - other
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for PublicParameters<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        PublicParameters {
            params: *value.0.params(),
        }
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Neg for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        // In a group, every element has its inverse;
        // because `self` is an element within the group,
        // `invert()` is guaranteed to succeed and we
        // skip the check.
        Self(self.0.invert().unwrap())
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Neg for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn neg(self) -> Self::Output {
        GroupElement::<LIMBS>(self.0.invert().unwrap())
    }
}

impl<const LIMBS: usize> Add<Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        // We are trying to adapt a multiplicative group to
        // the `GroupElement` trait which is in an additive notation -
        // so the abstract group operation "add" is mapped to the group operation (x \mod N) of the
        // multiplicative group of integers modulo N.
        Self(self.0 * rhs.0)
    }
}

impl<'r, const LIMBS: usize> Add<&'r Self> for GroupElement<LIMBS> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Sub<Self> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        // Subtraction is actually division in the multiplicative group,
        // which is defined as multiplication by the inverse of `rhs` - which we get from `neg()`
        Self(self.0 * rhs.neg().0)
    }
}

impl<'r, const LIMBS: usize, const WIDE_LIMBS: usize> Sub<&'r Self> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0 * rhs.neg().0)
    }
}

impl<const LIMBS: usize> AddAssign<Self> for GroupElement<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl<'r, const LIMBS: usize> AddAssign<&'r Self> for GroupElement<LIMBS> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add_assign(&mut self, rhs: &'r Self) {
        *self = *self + rhs
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> SubAssign<Self> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs
    }
}

impl<'r, const LIMBS: usize, const WIDE_LIMBS: usize> SubAssign<&'r Self> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub_assign(&mut self, rhs: &'r Self) {
        *self = *self - rhs
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const RHS_LIMBS: usize> Mul<Uint<RHS_LIMBS>>
    for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Uint<RHS_LIMBS>) -> Self::Output {
        self.scale(&rhs)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const RHS_LIMBS: usize> Mul<&Uint<RHS_LIMBS>>
    for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        self.scale(rhs)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const RHS_LIMBS: usize> Mul<Uint<RHS_LIMBS>>
    for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: Uint<RHS_LIMBS>) -> Self::Output {
        self.scale(&rhs)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const RHS_LIMBS: usize> Mul<&Uint<RHS_LIMBS>>
    for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &Uint<RHS_LIMBS>) -> Self::Output {
        self.scale(rhs)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Mul<GroupElement<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: GroupElement<LIMBS>) -> Self::Output {
        self.scale(&Uint::<LIMBS>::from(&rhs))
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Mul<&GroupElement<LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &GroupElement<LIMBS>) -> Self::Output {
        self.scale(&Uint::<LIMBS>::from(rhs))
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Mul<GroupElement<LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: GroupElement<LIMBS>) -> Self::Output {
        self.scale(&Uint::<LIMBS>::from(&rhs))
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Mul<&GroupElement<LIMBS>> for &GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    type Output = GroupElement<LIMBS>;

    fn mul(self, rhs: &GroupElement<LIMBS>) -> Self::Output {
        self.scale(&Uint::<LIMBS>::from(rhs))
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for Uint<LIMBS> {
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> From<GroupElement<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.value()
    }
}

impl<'r, const LIMBS: usize, const WIDE_LIMBS: usize> From<&'r GroupElement<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.value()
    }
}

impl<const LIMBS: usize> From<GroupElement<LIMBS>> for MontyForm<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: GroupElement<LIMBS>) -> Self {
        value.0
    }
}

impl<'r, const LIMBS: usize> From<&'r GroupElement<LIMBS>> for MontyForm<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &'r GroupElement<LIMBS>) -> Self {
        value.0
    }
}

impl<const LIMBS: usize> From<MontyForm<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: MontyForm<LIMBS>) -> Self {
        Value(*value.as_montgomery())
    }
}

impl<'r, const LIMBS: usize> From<&'r MontyForm<LIMBS>> for Value<LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &'r MontyForm<LIMBS>) -> Self {
        Value(*value.as_montgomery())
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> BoundedGroupElement<LIMBS> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
        (**public_parameters.params.modulus()) / NonZero::new(Uint::<LIMBS>::from(2u8)).unwrap()
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const SCALAR_LIMBS: usize>
    Scale<Uint<SCALAR_LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn scale_randomized_accelerated(
        &self,
        scalar: &Uint<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale(scalar)
    }

    fn scale_vartime_accelerated(
        &self,
        scalar: &Uint<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_vartime(scalar)
    }

    fn scale_randomized_bounded_accelerated(
        &self,
        scalar: &Uint<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
        scalar_bits: u32,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits)
    }

    fn scale_bounded_vartime_accelerated(
        &self,
        scalar: &Uint<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
        scalar_bits: u32,
    ) -> Self {
        self.scale_bounded_vartime(scalar, scalar_bits)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize, const SCALAR_LIMBS: usize>
    Scale<Int<SCALAR_LIMBS>> for GroupElement<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<WIDE_LIMBS>> + Encoding,
    Uint<WIDE_LIMBS>: Split<Output = Uint<LIMBS>>,
{
    fn scale_randomized_accelerated(
        &self,
        scalar: &Int<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer(scalar)
    }

    fn scale_vartime_accelerated(
        &self,
        scalar: &Int<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_vartime(scalar)
    }

    fn scale_randomized_bounded_accelerated(
        &self,
        scalar: &Int<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
        scalar_bits: u32,
    ) -> Self {
        self.scale_integer_bounded(scalar, scalar_bits)
    }

    fn scale_bounded_vartime_accelerated(
        &self,
        scalar: &Int<SCALAR_LIMBS>,
        _public_parameters: &Self::PublicParameters,
        scalar_bits: u32,
    ) -> Self {
        self.scale_integer_bounded_vartime(scalar, scalar_bits)
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::{BatchSize, Criterion};
    use crypto_bigint::{Integer, MultiExponentiate, Random};

    use group::{LinearlyCombinable, OsCsRng};

    use crate::PaillierModulusSizedNumber;

    use super::*;

    pub(crate) fn benchmark(c: &mut Criterion) {
        let mut g = c.benchmark_group("Linear Combination in multiplicative");

        let modulus = PaillierModulusSizedNumber::random(&mut OsCsRng);
        let modulus = if modulus.is_even().into() {
            modulus.wrapping_add(&PaillierModulusSizedNumber::ONE)
        } else {
            modulus
        };
        let public_parameters = PublicParameters::new(modulus).unwrap();

        let base = GroupElement::sample(&public_parameters, &mut OsCsRng).unwrap();

        let multiplicand = GroupElement::sample(&public_parameters, &mut OsCsRng).unwrap();

        g.bench_function("single exponentiation", |bench| {
            bench.iter(|| multiplicand * base);
        });

        for batch_size in [1, 2, 4, 8, 16, 32, 64, 128] {
            let bases =
                GroupElement::sample_batch(&public_parameters, batch_size, &mut OsCsRng).unwrap();
            let multiplicands: Vec<_> =
                GroupElement::sample_batch(&public_parameters, batch_size, &mut OsCsRng)
                    .unwrap()
                    .into_iter()
                    .map(PaillierModulusSizedNumber::from)
                    .collect();

            let bases_and_multiplicands: Vec<_> = bases
                .clone()
                .into_iter()
                .zip(multiplicands.clone())
                .collect();
            let bases_and_exponents: Vec<_> = bases
                .into_iter()
                .map(|x| x.0)
                .zip(multiplicands.clone())
                .collect();

            g.bench_function(
                format!("{batch_size} elements via `linearly_combine()`"),
                |bench| {
                    bench.iter_batched(
                        || bases_and_multiplicands.clone(),
                        |bases_and_multiplicands| {
                            GroupElement::linearly_combine(bases_and_multiplicands).unwrap()
                        },
                        BatchSize::PerIteration,
                    );
                },
            );

            g.bench_function(
                format!("{batch_size} elements via `multi_exponentiate()`"),
                |bench| {
                    bench.iter(|| MontyForm::multi_exponentiate(bases_and_exponents.as_slice()));
                },
            );
        }

        g.finish();
    }
}
