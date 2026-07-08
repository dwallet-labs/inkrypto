// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;
use std::{
    array,
    ops::{Add, AddAssign, BitAnd, Mul, Neg, Sub, SubAssign},
};

use crypto_bigint::{Int, Uint};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::{
    helpers::FlatMapResults, scalar, scalar::Scalar, BoundedGroupElement, CsRng,
    KnownOrderGroupElement, KnownOrderScalar, Samplable, Scale, Transcribeable,
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
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        let public_parameters = &public_parameters.0;

        if N == 0 {
            return Err(crate::Error::from(
                crate::ErrorKind::InvalidPublicParameters,
            ));
        }

        Ok(Self(
            array::from_fn(|_| G::sample(public_parameters, rng)).flat_map_results()?,
        ))
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        let public_parameters = &public_parameters.0;

        if N == 0 {
            return Err(crate::Error::from(
                crate::ErrorKind::InvalidPublicParameters,
            ));
        }

        Ok(Self(
            array::from_fn(|_| G::sample_randomizer(public_parameters, rng)).flat_map_results()?,
        ))
    }
}

/// The public parameters of the Self Product of the Group `G` by Itself.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicParameters<const N: usize, PP>(pub PP);

/// The canonical representation of the public parameters of the Self Product of the Group `G` by Itself.
#[derive(Serialize)]
pub struct CanonicalPublicParameters<const N: usize, PP: Transcribeable> {
    pub canonical_public_parameters: PP::CanonicalRepresentation,
    pub size: u64,
}

impl<const N: usize, PP: Transcribeable> From<PublicParameters<N, PP>>
    for CanonicalPublicParameters<N, PP>
{
    fn from(value: PublicParameters<N, PP>) -> Self {
        Self {
            canonical_public_parameters: value.0.into(),
            size: N.try_into().unwrap(),
        }
    }
}

impl<const N: usize, PP: Transcribeable> Transcribeable for PublicParameters<N, PP> {
    type CanonicalRepresentation = CanonicalPublicParameters<N, PP>;
}

impl<const N: usize, PP> PublicParameters<N, PP> {
    pub fn new(public_parameters: PP) -> Self {
        Self(public_parameters)
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

impl<const N: usize, GroupElementValue: Serialize + for<'a> Deserialize<'a> + Default> Default
    for Value<N, GroupElementValue>
{
    fn default() -> Self {
        Self(array::from_fn(|_| GroupElementValue::default()))
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
impl<const N: usize, G: crate::GroupElement> crate::GroupElement for GroupElement<N, G> {
    type Value = Value<N, G::Value>;

    type PublicParameters = PublicParameters<N, G::PublicParameters>;

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        let public_parameters = &public_parameters.0;

        if N == 0 {
            return Err(crate::Error::from(
                crate::ErrorKind::InvalidPublicParameters,
            ));
        }

        Ok(Self(
            value
                .0
                .map(|value| G::new(value, public_parameters))
                .flat_map_results()?,
        ))
    }

    fn neutral(&self) -> Self {
        Self(self.0.clone().map(|element| element.neutral()))
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        G::neutral_from_public_parameters(&public_parameters.0)
            .map(|neutral| Self(array::from_fn(|_| neutral.clone())))
    }

    fn add_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(array::from_fn(|i| {
            self.0[i].add_constant_time(&other.0[i], &public_parameters.0)
        }))
    }

    fn sub_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(array::from_fn(|i| {
            self.0[i].sub_constant_time(&other.0[i], &public_parameters.0)
        }))
    }

    fn neg_constant_time(&self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.neg_constant_time(&public_parameters.0)),
        )
    }

    fn scale<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale(scalar, &public_parameters.0)),
        )
    }

    fn scale_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_bounded(scalar, scalar_bits, &public_parameters.0)),
        )
    }

    fn scale_bounded_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_bounded_vartime(scalar, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_integer_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_integer_bounded(integer, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_integer<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_integer(integer, &public_parameters.0)),
        )
    }

    fn scale_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_vartime(scalar, &public_parameters.0)),
        )
    }

    fn scale_integer_vartime<const LIMBS: usize>(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_integer_vartime(scalar, &public_parameters.0)),
        )
    }

    fn scale_integer_bounded_vartime<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_integer_bounded_vartime(integer, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_vartime_scalar(scalar, &public_parameters.0)),
        )
    }

    fn scale_integer_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_integer_vartime_scalar(integer, &public_parameters.0)),
        )
    }

    fn scale_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_public_base(scalar, &public_parameters.0)),
        )
    }

    fn scale_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_public_base_bounded(scalar, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_integer_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_integer_public_base(integer, &public_parameters.0)),
        )
    }

    fn scale_integer_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_integer_public_base_bounded(integer, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_randomized<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_randomized(scalar, &public_parameters.0)),
        )
    }

    fn scale_randomized_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_bounded(scalar, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_randomized_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_randomized_public_base(scalar, &public_parameters.0)),
        )
    }

    fn scale_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_public_base_bounded(scalar, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_integer_randomized<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_integer_randomized(integer, &public_parameters.0)),
        )
    }

    fn scale_integer_randomized_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_integer_randomized_bounded(integer, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_integer_randomized_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_integer_randomized_public_base(integer, &public_parameters.0)
        }))
    }

    fn scale_integer_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_integer_randomized_public_base_bounded(
                integer,
                scalar_bits,
                &public_parameters.0,
            )
        }))
    }

    fn scale_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.clone().map(|element| {
                element.scale_randomized_vartime_scalar(scalar, &public_parameters.0)
            }),
        )
    }

    fn scale_integer_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_integer_randomized_vartime_scalar(integer, &public_parameters.0)
        }))
    }

    fn add_randomized(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(array::from_fn(|i| {
            self.0[i]
                .clone()
                .add_randomized(&other.0[i], &public_parameters.0)
        }))
    }

    fn add_vartime(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(array::from_fn(|i| {
            self.0[i]
                .clone()
                .add_vartime(&other.0[i], &public_parameters.0)
        }))
    }

    fn sub_randomized(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(array::from_fn(|i| {
            self.0[i]
                .clone()
                .sub_randomized(&other.0[i], &public_parameters.0)
        }))
    }

    fn sub_vartime(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self {
        Self(array::from_fn(|i| {
            self.0[i]
                .clone()
                .sub_vartime(&other.0[i], &public_parameters.0)
        }))
    }

    fn double(&self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.double(&public_parameters.0)),
        )
    }

    fn double_vartime(&self, public_parameters: &Self::PublicParameters) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.double_vartime(&public_parameters.0)),
        )
    }

    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
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
                    .map(|bm| {
                        let (ref base, multiplicand) = bm[i];
                        (base.clone(), multiplicand)
                    })
                    .collect(),
                exponent_bits,
                &public_parameters.0,
            )
        })
        .flat_map_results()
        .map(Self)
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
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
                    .map(|bm| {
                        let (ref base, multiplicand) = bm[i];
                        (base.clone(), multiplicand)
                    })
                    .collect(),
                exponent_bits,
                &public_parameters.0,
            )
        })
        .flat_map_results()
        .map(Self)
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

impl<const N: usize, G: crate::GroupElement + Neg<Output = G>> Neg for GroupElement<N, G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.clone().map(|element| element.neg()))
    }
}

impl<const N: usize, G: crate::GroupElement + for<'a> AddAssign<&'a G>> Add<Self>
    for GroupElement<N, G>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result: [G; N] = self.0;

        for (i, element) in result.iter_mut().enumerate() {
            *element += &rhs.0[i];
        }

        Self(result)
    }
}

impl<'r, const N: usize, G: crate::GroupElement + for<'a> AddAssign<&'a G>> Add<&'r Self>
    for GroupElement<N, G>
{
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        self + rhs.clone()
    }
}

impl<const N: usize, G: crate::GroupElement + for<'a> SubAssign<&'a G>> Sub<Self>
    for GroupElement<N, G>
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result: [G; N] = self.0;

        for (i, element) in result.iter_mut().enumerate() {
            *element -= &rhs.0[i];
        }

        Self(result)
    }
}

impl<'r, const N: usize, G: crate::GroupElement + for<'a> SubAssign<&'a G>> Sub<&'r Self>
    for GroupElement<N, G>
{
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        self - rhs.clone()
    }
}

impl<const N: usize, G: crate::GroupElement + for<'a> AddAssign<&'a G>> AddAssign<Self>
    for GroupElement<N, G>
{
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs
    }
}

impl<'r, const N: usize, G: crate::GroupElement + for<'a> AddAssign<&'a G>> AddAssign<&'r Self>
    for GroupElement<N, G>
{
    fn add_assign(&mut self, rhs: &'r Self) {
        for i in 0..N {
            self.0[i] += &rhs.0[i];
        }
    }
}

impl<const N: usize, G: crate::GroupElement + for<'a> SubAssign<&'a G>> SubAssign<Self>
    for GroupElement<N, G>
{
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs
    }
}

impl<'r, const N: usize, G: crate::GroupElement + for<'a> SubAssign<&'a G>> SubAssign<&'r Self>
    for GroupElement<N, G>
{
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
        G::lower_bound(&public_parameters.0)
    }
}

impl<
        const N: usize,
        const SCALAR_LIMBS: usize,
        S: KnownOrderScalar<SCALAR_LIMBS>,
        G: KnownOrderGroupElement<SCALAR_LIMBS, Scalar = S> + Scale<S>,
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
    fn scale_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_vartime_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_vartime_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_bounded_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.clone().map(|element| {
                element.scale_bounded_by(&scalar.0, scalar_bits, &public_parameters.0)
            }),
        )
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_bounded_vartime_by(&scalar.0, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_vartime_scalar_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_public_base_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_public_base_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_public_base_bounded_by(&scalar.0, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_randomized_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_randomized_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_bounded_by(&scalar.0, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_vartime_scalar_by(&scalar.0, &public_parameters.0)
        }))
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_public_base_by(&scalar.0, &public_parameters.0)
        }))
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &Scalar<SCALAR_LIMBS, S>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_public_base_bounded_by(
                &scalar.0,
                scalar_bits,
                &public_parameters.0,
            )
        }))
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
    fn scale_by(
        &self,
        scalar: &scalar::Value<V>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_vartime_by(
        &self,
        scalar: &scalar::Value<V>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_vartime_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_bounded_by(
        &self,
        scalar: &scalar::Value<V>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0.clone().map(|element| {
                element.scale_bounded_by(&scalar.0, scalar_bits, &public_parameters.0)
            }),
        )
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &scalar::Value<V>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_bounded_vartime_by(&scalar.0, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &scalar::Value<V>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_vartime_scalar_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_public_base_by(
        &self,
        scalar: &scalar::Value<V>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_public_base_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &scalar::Value<V>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_public_base_bounded_by(&scalar.0, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_randomized_by(
        &self,
        scalar: &scalar::Value<V>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(
            self.0
                .clone()
                .map(|element| element.scale_randomized_by(&scalar.0, &public_parameters.0)),
        )
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &scalar::Value<V>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_bounded_by(&scalar.0, scalar_bits, &public_parameters.0)
        }))
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &scalar::Value<V>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_vartime_scalar_by(&scalar.0, &public_parameters.0)
        }))
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &scalar::Value<V>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_public_base_by(&scalar.0, &public_parameters.0)
        }))
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &scalar::Value<V>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        Self(self.0.clone().map(|element| {
            element.scale_randomized_public_base_bounded_by(
                &scalar.0,
                scalar_bits,
                &public_parameters.0,
            )
        }))
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

impl<
        'r,
        const N: usize,
        const SCALAR_LIMBS: usize,
        S: KnownOrderScalar<SCALAR_LIMBS> + Mul<G, Output = G>,
        G: KnownOrderGroupElement<SCALAR_LIMBS, Scalar = S>,
    > Mul<&'r GroupElement<N, G>> for Scalar<SCALAR_LIMBS, crate::Scalar<SCALAR_LIMBS, G>>
{
    type Output = GroupElement<N, G>;

    fn mul(self, rhs: &'r GroupElement<N, G>) -> Self::Output {
        self * rhs.clone()
    }
}

impl<
        const N: usize,
        const SCALAR_LIMBS: usize,
        S: KnownOrderScalar<SCALAR_LIMBS>,
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
    S: Default + ConditionallySelectable + Mul<G, Output = G> + for<'r> Mul<&'r G, Output = G>,
{
    type Scalar = Scalar<SCALAR_LIMBS, S>;

    fn order_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS> {
        G::order_from_public_parameters(&public_parameters.0)
    }
}
