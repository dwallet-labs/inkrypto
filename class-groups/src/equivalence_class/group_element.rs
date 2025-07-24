// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{Concat, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};

use group::linear_combination::linearly_combine_bounded_or_scale;
use group::{
    bounded_integers_group, bounded_natural_numbers_group, Error, GroupElement, LinearlyCombinable,
};

use crate::equivalence_class::{public_parameters::PublicParameters, EquivalenceClass};
use crate::ibqf::{compact::CompactIbqf, Ibqf};

impl<const DISCRIMINANT_LIMBS: usize> Neg for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            representative: self.representative.invert(),
            discriminant: self.discriminant,
            accelerator: None,
        }
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > Add<Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(&rhs)
    }
}

impl<
        'r,
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > Add<&'r Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    // TODO(#35): get rid of unwrap
    fn add(self, rhs: &'r Self) -> Self::Output {
        // TODO(#46): make const-time.
        self.mul_vartime(rhs).unwrap()
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > Sub<Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<
        'r,
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > Sub<&'r Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    // TODO(#35): get rid of unwrap
    fn sub(self, rhs: &'r Self) -> Self::Output {
        self.mul(&rhs.neg()).unwrap()
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > AddAssign<Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn add_assign(&mut self, rhs: Self) {
        self.representative = self.add(&rhs).representative;
    }
}

impl<
        'r,
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > AddAssign<&'r Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.representative = self.add(rhs).representative;
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > SubAssign<Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.representative = self.sub(rhs).representative;
    }
}

impl<
        'r,
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > SubAssign<&'r Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.representative = self.sub(rhs).representative;
    }
}

impl<const DISCRIMINANT_LIMBS: usize> From<EquivalenceClass<DISCRIMINANT_LIMBS>>
    for CompactIbqf<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    fn from(value: EquivalenceClass<DISCRIMINANT_LIMBS>) -> Self {
        // safe to unwrap; equivalence_class always contains a reduced representative.
        value.representative.try_into().unwrap()
    }
}

impl<const DISCRIMINANT_LIMBS: usize> From<EquivalenceClass<DISCRIMINANT_LIMBS>>
    for PublicParameters<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
{
    fn from(value: EquivalenceClass<DISCRIMINANT_LIMBS>) -> Self {
        PublicParameters::new(value.discriminant)
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > GroupElement for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Value = CompactIbqf<DISCRIMINANT_LIMBS>;
    type PublicParameters = PublicParameters<DISCRIMINANT_LIMBS>;

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        let discriminant = public_parameters.discriminant();

        let form = Ibqf::try_from((value, discriminant)).map_err(|_| Error::InvalidGroupElement)?;

        Ok(Self {
            representative: form,
            discriminant,
            accelerator: None,
        })
    }

    fn neutral(&self) -> Self {
        self.unit()
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        EquivalenceClass::unit_for_class(&public_parameters.discriminant())
            .map_err(|_| Error::InvalidPublicParameters)
    }

    fn scale<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        // TODO(#46): make const-time.
        self.scale_vartime(scalar)
    }

    fn scale_vartime<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        self.pow_vartime(scalar)
    }

    fn scale_bounded<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>, scalar_bits: u32) -> Self {
        // TODO(#46): make const-time.
        self.scale_bounded_vartime(scalar, scalar_bits)
    }

    fn scale_bounded_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        self.pow_bounded_vartime(scalar, scalar_bits)
    }

    fn add_vartime(self, other: &Self) -> Self {
        // TODO(#35): get rid of unwrap
        self.mul_vartime(other).unwrap()
    }

    fn double(&self) -> Self {
        // TODO(#46): make const-time.
        self.double_vartime()
    }

    fn double_vartime(&self) -> Self {
        self.square_vartime()
    }
}

impl<
        'r,
        const ELEMENT_SCALAR_LIMBS: usize,
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > Mul<&'r EquivalenceClass<DISCRIMINANT_LIMBS>>
    for bounded_natural_numbers_group::GroupElement<ELEMENT_SCALAR_LIMBS>
where
    Uint<ELEMENT_SCALAR_LIMBS>: Encoding,

    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = EquivalenceClass<DISCRIMINANT_LIMBS>;

    fn mul(self, rhs: &'r EquivalenceClass<DISCRIMINANT_LIMBS>) -> Self::Output {
        rhs.scale_bounded(&self.value(), self.upper_bound_bits)
    }
}

impl<
        'r,
        const ELEMENT_SCALAR_LIMBS: usize,
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > Mul<&'r EquivalenceClass<DISCRIMINANT_LIMBS>>
    for bounded_integers_group::GroupElement<ELEMENT_SCALAR_LIMBS>
where
    Uint<ELEMENT_SCALAR_LIMBS>: Encoding,
    Int<ELEMENT_SCALAR_LIMBS>: Encoding,

    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = EquivalenceClass<DISCRIMINANT_LIMBS>;

    fn mul(self, rhs: &'r EquivalenceClass<DISCRIMINANT_LIMBS>) -> Self::Output {
        rhs.scale_integer_bounded(&self.value(), self.upper_bound_bits)
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
        const SCALAR_LIMBS: usize,
    > Mul<Uint<SCALAR_LIMBS>> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Uint<SCALAR_LIMBS>: Encoding,

    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = EquivalenceClass<DISCRIMINANT_LIMBS>;

    fn mul(self, rhs: Uint<SCALAR_LIMBS>) -> Self::Output {
        self.scale(&rhs)
    }
}

impl<
        'r,
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
        const SCALAR_LIMBS: usize,
    > Mul<&'r Uint<SCALAR_LIMBS>> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Uint<SCALAR_LIMBS>: Encoding,

    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = EquivalenceClass<DISCRIMINANT_LIMBS>;

    fn mul(self, rhs: &'r Uint<SCALAR_LIMBS>) -> Self::Output {
        self.scale(rhs)
    }
}

impl<
        const HALF_DISCRIMINANT_LIMBS: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE_DISCRIMINANT_LIMBS: usize,
    > LinearlyCombinable for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<HALF_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_DISCRIMINANT_LIMBS>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_DISCRIMINANT_LIMBS>>
        + InvMod<Modulus = Uint<HALF_DISCRIMINANT_LIMBS>, Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Concat<Output = Uint<DOUBLE_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_DISCRIMINANT_LIMBS>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
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
