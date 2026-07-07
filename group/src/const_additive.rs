// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::modular::{ConstMontyForm, ConstMontyParams};
use crypto_bigint::{Encoding, Int, NonZero, Odd, Random, Uint};
use serde::{Deserialize, Serialize};
use subtle::ConditionallySelectable;
use subtle::{Choice, ConstantTimeEq, CtOption};

use crate::linear_combination::linearly_combine_bounded;
use crate::{
    BoundedGroupElement, CsRng, CyclicGroupElement, GroupElement as _, Invert,
    KnownOrderGroupElement, KnownOrderScalar, MulByGenerator, PrimeGroupElement, Reduce, Samplable,
    Scale, Transcribeable,
};

/// An element of the additive group of integers for an odd modulo `n = modulus`
/// $\mathbb{Z}_n^+$.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub struct GroupElement<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>(
    ConstMontyForm<MOD, LIMBS>,
);

/// A marker trait used to mark a modulus as prime.
pub trait PrimeConstMontyParams<const LIMBS: usize>: ConstMontyParams<LIMBS> {}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Samplable for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn sample(
        _public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        Ok(Self(ConstMontyForm::<MOD, LIMBS>::random(rng)))
    }

    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> crate::Result<Self> {
        Self::sample(public_parameters, rng)
    }
}

/// The public parameters of the additive group of integers modulo `n = modulus`
/// $\mathbb{Z}_n^+$.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct PublicParameters<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
where
    Uint<LIMBS>: Encoding,
{
    pub modulus: Odd<Uint<LIMBS>>,
    _mod_choice: PhantomData<MOD>,
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Transcribeable
    for PublicParameters<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type CanonicalRepresentation = Self;
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Default for PublicParameters<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self {
            modulus: ConstMontyForm::<MOD, LIMBS>::MODULUS,
            _mod_choice: PhantomData,
        }
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Default for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self(ConstMontyForm::<MOD, LIMBS>::ZERO)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> crate::GroupElement
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Value = Uint<LIMBS>;

    fn value(&self) -> Self::Value {
        self.0.retrieve()
    }

    type PublicParameters = PublicParameters<MOD, LIMBS>;

    fn new(value: Self::Value, _public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        Ok(Self(ConstMontyForm::<MOD, LIMBS>::new(&value)))
    }

    fn neutral(&self) -> Self {
        Self(ConstMontyForm::<MOD, LIMBS>::ZERO)
    }

    fn neutral_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Ok(Self(ConstMontyForm::<MOD, LIMBS>::ZERO))
    }

    fn scale<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar = ConstMontyForm::<MOD, LIMBS>::new(
            // Safe to `unwrap` here as `ConstMontyForm::<MOD, LIMBS>::MODULUS` is guaranteed to be odd and therefore non-zero.
            &scalar.reduce(&NonZero::new(ConstMontyForm::<MOD, LIMBS>::MODULUS.get()).unwrap()),
        );

        Self(self.0 * scalar)
    }

    fn scale_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_bounded(self, scalar, scalar_bits, true, public_parameters)
    }

    fn scale_bounded_vartime<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_bounded(self, scalar, scalar_bits, false, public_parameters)
    }

    fn scale_integer_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_integer<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded(integer, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_vartime<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded_vartime(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn scale_integer_vartime<const RHS_LIMBS: usize>(
        &self,
        scalar: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded_vartime(scalar, scalar.abs().bits_vartime(), public_parameters)
    }

    fn scale_vartime_scalar<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn scale_public_base<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_integer_public_base<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_public_base_bounded(integer, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_public_base_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_randomized<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_randomized_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_randomized_public_base<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_randomized_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_integer_randomized<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_bounded(integer, Uint::<RHS_LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_randomized_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_randomized_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_integer_randomized_public_base<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_public_base_bounded(
            integer,
            Uint::<RHS_LIMBS>::BITS,
            public_parameters,
        )
    }

    fn scale_integer_randomized_public_base_bounded<const RHS_LIMBS: usize>(
        &self,
        integer: &Int<RHS_LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        crate::scale_integer_randomized_public_base_bounded(
            self,
            integer,
            scalar_bits,
            public_parameters,
        )
    }

    fn scale_randomized_vartime_scalar<const RHS_LIMBS: usize>(
        &self,
        scalar: &Uint<RHS_LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn add_randomized(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self + other
    }

    fn add_vartime(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self + other
    }

    fn sub_randomized(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self - other
    }

    fn sub_vartime(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self - other
    }

    fn double(&self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0 + self.0)
    }

    fn double_vartime(&self, _public_parameters: &Self::PublicParameters) -> Self {
        self.double(_public_parameters)
    }

    fn add_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0.add(&other.0))
    }

    fn sub_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0.sub(&other.0))
    }

    fn neg_constant_time(&self, _public_parameters: &Self::PublicParameters) -> Self {
        Self(self.0.neg())
    }

    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        linearly_combine_bounded(
            bases_and_multiplicands,
            exponent_bits,
            true,
            public_parameters,
        )
    }

    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        linearly_combine_bounded(
            bases_and_multiplicands,
            exponent_bits,
            false,
            public_parameters,
        )
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> ConstantTimeEq for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> ConditionallySelectable
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(
            <ConstMontyForm<MOD, LIMBS> as ConditionallySelectable>::conditional_select(
                &a.0, &b.0, choice,
            ),
        )
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> From<GroupElement<MOD, LIMBS>>
    for PublicParameters<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(_value: GroupElement<MOD, LIMBS>) -> Self {
        Self::default()
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Neg for GroupElement<MOD, LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Add<Self> for GroupElement<MOD, LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Add<&'r Self>
    for GroupElement<MOD, LIMBS>
{
    type Output = Self;

    fn add(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Sub<Self> for GroupElement<MOD, LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Sub<&'r Self>
    for GroupElement<MOD, LIMBS>
{
    type Output = Self;

    fn sub(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> AddAssign<Self>
    for GroupElement<MOD, LIMBS>
{
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> AddAssign<&'r Self>
    for GroupElement<MOD, LIMBS>
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.0.add_assign(rhs.0)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> SubAssign<Self>
    for GroupElement<MOD, LIMBS>
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> SubAssign<&'r Self>
    for GroupElement<MOD, LIMBS>
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.0.sub_assign(rhs.0)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> MulByGenerator<Uint<LIMBS>>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Uint<LIMBS>) -> Self {
        self.mul_by_generator(&scalar)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> MulByGenerator<&Uint<LIMBS>>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: &Uint<LIMBS>) -> Self {
        // In the additive group, the generator is 1 and multiplication by it is simply returning
        // the same number modulu the order (which is taken care of in `ConstMontyForm`).
        Self(ConstMontyForm::new(scalar))
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> MulByGenerator<Self>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: Self) -> Self {
        self.mul_by_generator(&scalar)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> MulByGenerator<&Self>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn mul_by_generator(&self, scalar: &Self) -> Self {
        // In the additive group, the generator is 1 and multiplication by it is simply returning
        // the same number modulu the order (which is taken care of in `ConstMontyForm`).
        *scalar
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> BoundedGroupElement<LIMBS>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
        public_parameters.modulus.get()
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> CyclicGroupElement
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn generator(&self) -> Self {
        Self(ConstMontyForm::<MOD, LIMBS>::ONE)
    }

    fn generator_value_from_public_parameters(
        _public_parameters: &Self::PublicParameters,
    ) -> Self::Value {
        Uint::<LIMBS>::ONE
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<Self> for GroupElement<MOD, LIMBS> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<&'r Self>
    for GroupElement<MOD, LIMBS>
{
    type Output = Self;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<Self> for &GroupElement<MOD, LIMBS> {
    type Output = GroupElement<MOD, LIMBS>;

    fn mul(self, rhs: Self) -> Self::Output {
        GroupElement(self.0.mul(&rhs.0))
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<&'r Self>
    for &'r GroupElement<MOD, LIMBS>
{
    type Output = GroupElement<MOD, LIMBS>;

    fn mul(self, rhs: &'r Self) -> Self::Output {
        GroupElement(self.0.mul(&rhs.0))
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<Uint<LIMBS>> for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scale(&rhs, &Default::default())
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<&'r Uint<LIMBS>>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = Self;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scale(rhs, &Default::default())
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<Uint<LIMBS>>
    for &GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<MOD, LIMBS>;

    fn mul(self, rhs: Uint<LIMBS>) -> Self::Output {
        self.scale(&rhs, &Default::default())
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Mul<&'r Uint<LIMBS>>
    for &'r GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Output = GroupElement<MOD, LIMBS>;

    fn mul(self, rhs: &'r Uint<LIMBS>) -> Self::Output {
        self.scale(rhs, &Default::default())
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> From<GroupElement<MOD, LIMBS>>
    for Uint<LIMBS>
{
    fn from(value: GroupElement<MOD, LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<'r, MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> From<&'r GroupElement<MOD, LIMBS>>
    for Uint<LIMBS>
{
    fn from(value: &'r GroupElement<MOD, LIMBS>) -> Self {
        value.0.retrieve()
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Invert for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn invert(&self) -> CtOption<Self> {
        let inv = <ConstMontyForm<MOD, LIMBS> as crypto_bigint::Invert>::invert(&self.0);
        let default = self.neutral().0;

        CtOption::new(Self(inv.unwrap_or(default)), inv.is_some())
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> Scale<Self> for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn scale_by(&self, scalar: &Self, public_parameters: &Self::PublicParameters) -> Self {
        self.scale(&scalar.value(), public_parameters)
    }

    fn scale_vartime_by(&self, scalar: &Self, public_parameters: &Self::PublicParameters) -> Self {
        self.scale_vartime(&scalar.value(), public_parameters)
    }

    fn scale_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(&scalar.value(), scalar_bits, public_parameters)
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded_vartime(&scalar.value(), scalar_bits, public_parameters)
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_vartime_scalar(&scalar.value(), public_parameters)
    }

    fn scale_public_base_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_public_base(&scalar.value(), public_parameters)
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_public_base_bounded(&scalar.value(), scalar_bits, public_parameters)
    }

    fn scale_randomized_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized(&scalar.value(), public_parameters)
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_bounded(&scalar.value(), scalar_bits, public_parameters)
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_vartime_scalar(&scalar.value(), public_parameters)
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &Self,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_public_base(&scalar.value(), public_parameters)
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &Self,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_public_base_bounded(&scalar.value(), scalar_bits, public_parameters)
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> KnownOrderScalar<LIMBS>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize> KnownOrderGroupElement<LIMBS>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    type Scalar = Self;

    fn order_from_public_parameters(public_parameters: &Self::PublicParameters) -> Uint<LIMBS> {
        public_parameters.modulus.get()
    }
}

impl<MOD: PrimeConstMontyParams<LIMBS>, const LIMBS: usize> PrimeGroupElement<LIMBS>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize, const RHS_LIMBS: usize> From<Uint<RHS_LIMBS>>
    for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: Uint<RHS_LIMBS>) -> Self {
        let value = value.reduce(&NonZero::new(*ConstMontyForm::<MOD, LIMBS>::MODULUS).unwrap());
        Self(ConstMontyForm::<MOD, LIMBS>::new(&value))
    }
}

impl<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize, const RHS_LIMBS: usize>
    From<&Uint<RHS_LIMBS>> for GroupElement<MOD, LIMBS>
where
    Uint<LIMBS>: Encoding,
{
    fn from(value: &Uint<RHS_LIMBS>) -> Self {
        Self::from(*value)
    }
}
