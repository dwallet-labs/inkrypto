// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;
use std::{
    array,
    ops::{Add, AddAssign, BitAnd, Mul, Neg, Sub, SubAssign},
};

use crypto_bigint::{rand_core::CryptoRngCore, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::{
    helpers::FlatMapResults, scalar, scalar::Scalar, BoundedGroupElement, GroupElement as _,
    KnownOrderGroupElement, KnownOrderScalar, LinearlyCombinable, Samplable, Scale,
};

/// An element of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct GroupElement<const N: usize, G>([G; N]);

impl<const N: usize, G: crate::GroupElement> Samplable for GroupElement<N, G>
where
    G: Samplable,
{
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> crate::Result<Self> {
        let public_parameters = &public_parameters.public_parameters;

        if N == 0 {
            return Err(crate::Error::InvalidPublicParameters);
        }

        Ok(Self(
            array::from_fn(|_| G::sample(public_parameters, rng)).flat_map_results()?,
        ))
    }
}

/// The public parameters of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const N: usize, PP> {
    pub public_parameters: PP,
    pub size: usize,
}

impl<const N: usize, PP> PublicParameters<N, PP> {
    pub fn new(public_parameters: PP) -> Self {
        Self {
            public_parameters,
            size: N,
        }
    }
}

/// The value of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Debug, Hash, Serialize, Deserialize, Copy)]
pub struct Value<const N: usize, GroupElementValue: Serialize + for<'a> Deserialize<'a>>(
    #[serde(with = "crate::helpers::const_generic_array_serialization")] [GroupElementValue; N],
);

impl<
        const N: usize,
        GroupElementValue: Serialize + for<'a> Deserialize<'a> + ConditionallySelectable,
    > ConditionallySelectable for Value<N, GroupElementValue>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[GroupElementValue; N]>::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<const N: usize, GroupElementValue: Serialize + for<'a> Deserialize<'a> + Default + Copy>
    Default for Value<N, GroupElementValue>
{
    fn default() -> Self {
        Self([GroupElementValue::default(); N])
    }
}
impl<const N: usize, GroupElementValue: Serialize + for<'a> Deserialize<'a> + ConstantTimeEq>
    ConstantTimeEq for Value<N, GroupElementValue>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        // The arrays are of the same size, so it's safe to `zip` them.
        // Following that, we get an array of the pairs, and we ensure they are all equal to each
        // other using `ct_eq` between the pairs and `bitand` between the results.
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(Choice::from(1u8), |choice, (x, y)| {
                choice.bitand(x.ct_eq(y))
            })
    }
}

impl<const N: usize, G: ConditionallySelectable> ConditionallySelectable for GroupElement<N, G> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[G; N]>::conditional_select(&a.0, &b.0, choice))
    }
}

impl<const N: usize, G: ConstantTimeEq> ConstantTimeEq for GroupElement<N, G> {
    fn ct_eq(&self, other: &Self) -> Choice {
        // The arrays are of the same size, so it's safe to `zip` them.
        // Following that, we get an array of the pairs, and we ensure they are all equal to each
        // other using `ct_eq` between the pairs and `bitand` between the results.
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(Choice::from(1u8), |choice, (x, y)| {
                choice.bitand(x.ct_eq(y))
            })
    }
}
impl<const N: usize, G: crate::GroupElement> LinearlyCombinable for GroupElement<N, G> {
    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self> {
        let bases_and_multiplicands: Vec<_> = bases_and_multiplicands
            .into_iter()
            .map(|(base, multiplicand)| base.0.map(|base| (base, multiplicand)))
            .collect();

        array::from_fn(|i| {
            G::linearly_combine_bounded(
                bases_and_multiplicands
                    .clone()
                    .into_iter()
                    .map(|bases_and_multiplicands| bases_and_multiplicands[i])
                    .collect(),
                exponent_bits,
            )
        })
        .flat_map_results()
        .map(Self)
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self> {
        let bases_and_multiplicands: Vec<_> = bases_and_multiplicands
            .into_iter()
            .map(|(base, multiplicand)| base.0.map(|base| (base, multiplicand)))
            .collect();

        array::from_fn(|i| {
            G::linearly_combine_bounded_vartime(
                bases_and_multiplicands
                    .clone()
                    .into_iter()
                    .map(|bases_and_multiplicands| bases_and_multiplicands[i])
                    .collect(),
                exponent_bits,
            )
        })
        .flat_map_results()
        .map(Self)
    }
}

impl<const N: usize, G: crate::GroupElement> crate::GroupElement for GroupElement<N, G> {
    type Value = Value<N, G::Value>;

    type PublicParameters = PublicParameters<N, G::PublicParameters>;

    fn public_parameters(&self) -> Self::PublicParameters {
        // in [`Self::new()`] we used the same public parameters for all elements, so we just pick
        // the first calling `unwrap()` is safe here because we assure to get at least two
        // values, i.e., this struct cannot be instantiated for `N == 0`.
        PublicParameters::new(self.0.first().unwrap().public_parameters())
    }

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        let public_parameters = &public_parameters.public_parameters;

        if N == 0 {
            return Err(crate::Error::InvalidPublicParameters);
        }

        Ok(Self(
            value
                .0
                .map(|value| G::new(value, public_parameters))
                .flat_map_results()?,
        ))
    }

    fn neutral(&self) -> Self {
        Self(self.0.map(|element| element.neutral()))
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        G::neutral_from_public_parameters(&public_parameters.public_parameters)
            .map(|neutral| Self(array::from_fn(|_| neutral)))
    }

    fn scale<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        Self(self.0.map(|element| element.scale(scalar)))
    }

    fn scale_bounded<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>, scalar_bits: u32) -> Self {
        Self(
            self.0
                .map(|element| element.scale_bounded(scalar, scalar_bits)),
        )
    }

    fn double(&self) -> Self {
        Self(self.0.map(|element| element.double()))
    }
}

impl<const N: usize, G: crate::GroupElement> From<GroupElement<N, G>> for Value<N, G::Value> {
    fn from(value: GroupElement<N, G>) -> Self {
        Self(value.0.map(|element| element.into()))
    }
}

impl<const N: usize, GroupElementValue: Serialize + for<'a> Deserialize<'a>>
    From<Value<N, GroupElementValue>> for [GroupElementValue; N]
{
    fn from(value: Value<N, GroupElementValue>) -> Self {
        value.0
    }
}

impl<
        const N: usize,
        GroupElementValue: Serialize + for<'a> Deserialize<'a> + From<OtherElementValue>,
        OtherElementValue: Serialize + for<'a> Deserialize<'a>,
    > From<[OtherElementValue; N]> for Value<N, GroupElementValue>
{
    fn from(value: [OtherElementValue; N]) -> Self {
        Value(value.map(GroupElementValue::from))
    }
}

impl<const N: usize, G: crate::GroupElement> From<GroupElement<N, G>>
    for PublicParameters<N, G::PublicParameters>
{
    fn from(value: GroupElement<N, G>) -> Self {
        value.public_parameters()
    }
}

impl<const N: usize, G: crate::GroupElement> Neg for GroupElement<N, G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.map(|element| element.neg()))
    }
}

impl<const N: usize, G: crate::GroupElement> Add<Self> for GroupElement<N, G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result: [G; N] = self.0;

        for (i, element) in result.iter_mut().enumerate() {
            *element += &rhs.0[i];
        }

        Self(result)
    }
}

impl<'r, const N: usize, G: crate::GroupElement> Add<&'r Self> for GroupElement<N, G> {
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        self + *rhs
    }
}

impl<const N: usize, G: crate::GroupElement> Sub<Self> for GroupElement<N, G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result: [G; N] = self.0;

        for (i, element) in result.iter_mut().enumerate() {
            *element -= &rhs.0[i];
        }

        Self(result)
    }
}

impl<'r, const N: usize, G: crate::GroupElement> Sub<&'r Self> for GroupElement<N, G> {
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        self - *rhs
    }
}

impl<const N: usize, G: crate::GroupElement> AddAssign<Self> for GroupElement<N, G> {
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs
    }
}

impl<'r, const N: usize, G: crate::GroupElement> AddAssign<&'r Self> for GroupElement<N, G> {
    fn add_assign(&mut self, rhs: &'r Self) {
        for i in 0..N {
            self.0[i] += &rhs.0[i];
        }
    }
}

impl<const N: usize, G: crate::GroupElement> SubAssign<Self> for GroupElement<N, G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs
    }
}

impl<'r, const N: usize, G: crate::GroupElement> SubAssign<&'r Self> for GroupElement<N, G> {
    fn sub_assign(&mut self, rhs: &'r Self) {
        for i in 0..N {
            self.0[i] -= &rhs.0[i];
        }
    }
}

impl<const N: usize, G: crate::GroupElement> From<GroupElement<N, G>> for [G; N] {
    fn from(value: GroupElement<N, G>) -> Self {
        value.0
    }
}

impl<'r, const N: usize, G: crate::GroupElement> From<&'r GroupElement<N, G>> for &'r [G; N] {
    fn from(value: &'r GroupElement<N, G>) -> Self {
        &value.0
    }
}

impl<const N: usize, G: crate::GroupElement> From<[G; N]> for GroupElement<N, G> {
    fn from(value: [G; N]) -> Self {
        GroupElement::<N, G>(value)
    }
}

impl<const N: usize, const SCALAR_LIMBS: usize, G: BoundedGroupElement<SCALAR_LIMBS>>
    BoundedGroupElement<SCALAR_LIMBS> for GroupElement<N, G>
{
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<SCALAR_LIMBS> {
        G::lower_bound(&public_parameters.public_parameters)
    }
}

impl<
        const N: usize,
        const SCALAR_LIMBS: usize,
        S: KnownOrderScalar<SCALAR_LIMBS> + Mul<G, Output = G>,
        G: KnownOrderGroupElement<SCALAR_LIMBS, Scalar = S>,
    > Mul<GroupElement<N, G>> for Scalar<SCALAR_LIMBS, crate::Scalar<SCALAR_LIMBS, G>>
{
    type Output = GroupElement<N, G>;

    fn mul(self, rhs: GroupElement<N, G>) -> Self::Output {
        GroupElement::<N, G>(rhs.0.map(|element| self.0 * element))
    }
}

impl<'r, const N: usize, const SCALAR_LIMBS: usize, G: KnownOrderGroupElement<SCALAR_LIMBS>>
    Mul<&'r GroupElement<N, G>> for Scalar<SCALAR_LIMBS, G::Scalar>
{
    type Output = GroupElement<N, G>;

    fn mul(self, rhs: &'r GroupElement<N, G>) -> Self::Output {
        self * *rhs
    }
}

impl<
        const N: usize,
        const SCALAR_LIMBS: usize,
        S: KnownOrderScalar<SCALAR_LIMBS> + Mul<G, Output = G>,
        G: KnownOrderGroupElement<SCALAR_LIMBS, Scalar = S>,
    > Scale<Scalar<SCALAR_LIMBS, S>> for GroupElement<N, G>
where
    S::Value: From<Uint<SCALAR_LIMBS>>
        + Into<Uint<SCALAR_LIMBS>>
        + Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + ConstantTimeEq
        + ConditionallySelectable
        + Copy,
    S: Default + ConditionallySelectable,
{
    fn scale_generic(&self, scalar: &Scalar<SCALAR_LIMBS, S>) -> Self {
        *scalar * self
    }

    fn scale_bounded_generic(&self, scalar: &Scalar<SCALAR_LIMBS, S>, scalar_bits: u32) -> Self {
        self.scale_bounded(&scalar.value().into(), scalar_bits)
    }

    fn scale_bounded_vartime_generic(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        scalar_bits: u32,
    ) -> Self {
        self.scale_bounded_vartime(&scalar.value().into(), scalar_bits)
    }
}

impl<const N: usize, V, G: crate::GroupElement> Scale<scalar::Value<V>> for GroupElement<N, G>
where
    V: Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + ConstantTimeEq
        + ConditionallySelectable
        + Copy,
    G: Scale<V>,
{
    fn scale_generic(&self, scalar: &scalar::Value<V>) -> Self {
        Self(self.0.map(|element| element.scale_generic(&scalar.0)))
    }

    fn scale_bounded_generic(&self, scalar: &scalar::Value<V>, scalar_bits: u32) -> Self {
        Self(
            self.0
                .map(|element| element.scale_bounded_generic(&scalar.0, scalar_bits)),
        )
    }

    fn scale_bounded_vartime_generic(&self, scalar: &scalar::Value<V>, scalar_bits: u32) -> Self {
        Self(
            self.0
                .map(|element| element.scale_bounded_vartime_generic(&scalar.0, scalar_bits)),
        )
    }
}

impl<
        const N: usize,
        const SCALAR_LIMBS: usize,
        S: KnownOrderScalar<SCALAR_LIMBS> + Mul<G, Output = G>,
        G: KnownOrderGroupElement<SCALAR_LIMBS, Scalar = S>,
    > KnownOrderGroupElement<SCALAR_LIMBS> for GroupElement<N, G>
where
    S::Value: From<Uint<SCALAR_LIMBS>>
        + Into<Uint<SCALAR_LIMBS>>
        + Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + ConstantTimeEq
        + ConditionallySelectable
        + Copy,
    S: Default + ConditionallySelectable,
{
    type Scalar = Scalar<SCALAR_LIMBS, S>;

    fn order_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        G::order_from_public_parameters(&public_parameters.public_parameters)
    }
}
