// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crypto_bigint::{Concat, Encoding, Int, Split, Uint};

use group::linear_combination::linearly_combine_bounded_or_scale;
use group::{Error, ErrorKind, GroupElement};

use crate::equivalence_class::{
    public_parameters::PublicParameters, EquivalenceClass, EquivalenceClassOps,
};
use crate::ibqf::{compact::CompactIbqf, Ibqf};

impl<const DISCRIMINANT_LIMBS: usize> Neg for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            representative: self.representative.inverse(),
            discriminant: self.discriminant,
        }
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize> Add<Self>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'r, const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize> Add<&'r Self>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    // TODO(#35): get rid of unwrap
    fn add(self, rhs: &'r Self) -> Self::Output {
        EquivalenceClass::mul(&self, rhs).unwrap()
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize> Sub<Self>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<'r, const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize> Sub<&'r Self>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = Self;

    // TODO(#35): get rid of unwrap
    fn sub(self, rhs: &'r Self) -> Self::Output {
        self.div(rhs).unwrap()
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize> AddAssign<Self>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn add_assign(&mut self, rhs: Self) {
        self.representative = self.add(&rhs).representative;
    }
}

impl<'r, const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize>
    AddAssign<&'r Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn add_assign(&mut self, rhs: &'r Self) {
        self.representative = self.add(rhs).representative;
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize> SubAssign<Self>
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.representative = self.sub(rhs).representative;
    }
}

impl<'r, const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize>
    SubAssign<&'r Self> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    fn sub_assign(&mut self, rhs: &'r Self) {
        self.representative = self.sub(rhs).representative;
    }
}

impl<const DISCRIMINANT_LIMBS: usize> From<EquivalenceClass<DISCRIMINANT_LIMBS>>
    for CompactIbqf<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<DISCRIMINANT_LIMBS>: Encoding,
{
    fn from(value: EquivalenceClass<DISCRIMINANT_LIMBS>) -> Self {
        // safe to unwrap; equivalence_class always contains a reduced representative.
        value.representative.try_into().unwrap()
    }
}

impl<const HALF: usize, const DISCRIMINANT_LIMBS: usize, const DOUBLE: usize> GroupElement
    for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Value = CompactIbqf<DISCRIMINANT_LIMBS>;
    type PublicParameters = PublicParameters<DISCRIMINANT_LIMBS>;

    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> group::Result<Self> {
        let discriminant = *public_parameters.discriminant();

        Ibqf::try_from((value, discriminant))
            .map(|form| Self {
                representative: form,
                discriminant,
            })
            .map_err(|_| Error::from(ErrorKind::InvalidGroupElement))
    }

    fn neutral(&self) -> Self {
        self.unit()
    }

    fn neutral_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        Ok(EquivalenceClass::unit_for_class(
            public_parameters.discriminant(),
        ))
    }

    fn add_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self + other
    }

    fn sub_constant_time(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        *self - other
    }

    fn neg_constant_time(&self, _public_parameters: &Self::PublicParameters) -> Self {
        (*self).neg()
    }

    fn scale<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.pow(scalar)
    }

    fn scale_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_bits = scalar.bits_vartime();
        match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
            Some(accelerator) => Self::pow_multifold_accelerated_vartime(accelerator, scalar),
            None => self.pow_vartime(scalar),
        }
    }

    fn scale_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.pow_bounded(scalar, scalar_bits)
    }

    fn scale_bounded_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
            Some(accelerator) => {
                Self::pow_bounded_multifold_accelerated_vartime(accelerator, scalar, scalar_bits)
            }
            None => self.pow_bounded_vartime(scalar, scalar_bits),
        }
    }

    fn scale_integer_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        group::scale_integer_bounded(self, integer, scalar_bits, public_parameters)
    }

    fn scale_integer<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded(integer, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_vartime<const LIMBS: usize>(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let (abs_scalar, scalar_is_negative) = scalar.abs_sign();
        let scalar_bits = abs_scalar.bits_vartime();
        let scaled_by_absolute_value_scalar =
            match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
                Some(accelerator) => Self::pow_bounded_multifold_accelerated_vartime(
                    accelerator,
                    &abs_scalar,
                    scalar_bits,
                ),
                None => self.scale_bounded_vartime(&abs_scalar, scalar_bits, public_parameters),
            };

        if bool::from(scalar_is_negative) {
            scaled_by_absolute_value_scalar.neg_constant_time(public_parameters)
        } else {
            scaled_by_absolute_value_scalar
        }
    }

    fn scale_integer_bounded_vartime<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let (abs_scalar, scalar_is_negative) = integer.abs_sign();
        let scaled_by_absolute_value_scalar =
            match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
                Some(accelerator) => Self::pow_bounded_multifold_accelerated_vartime(
                    accelerator,
                    &abs_scalar,
                    scalar_bits,
                ),
                None => self.scale_bounded_vartime(&abs_scalar, scalar_bits, public_parameters),
            };

        if bool::from(scalar_is_negative) {
            scaled_by_absolute_value_scalar.neg_constant_time(public_parameters)
        } else {
            scaled_by_absolute_value_scalar
        }
    }

    fn scale_randomized_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_bits = Uint::<LIMBS>::BITS;
        match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
            Some(accelerator) => {
                Self::pow_bounded_multifold_accelerated_randomized(accelerator, scalar, scalar_bits)
            }
            None => self.pow_public_base_randomized(scalar),
        }
    }

    fn scale_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
            Some(accelerator) => {
                Self::pow_bounded_multifold_accelerated_randomized(accelerator, scalar, scalar_bits)
            }
            None => self.pow_public_base_bounded_randomized(scalar, scalar_bits),
        }
    }

    fn scale_integer_randomized_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let scalar_bits = Uint::<LIMBS>::BITS;
        match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
            Some(accelerator) => {
                let (abs_scalar, scalar_is_negative) = integer.abs_sign();
                Self::pow_bounded_multifold_accelerated_randomized(
                    accelerator,
                    &abs_scalar,
                    scalar_bits,
                )
                .wrapping_negate_if(scalar_is_negative.into())
            }
            None => self.pow_public_base_integer_randomized(integer),
        }
    }

    fn scale_integer_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
            Some(accelerator) => {
                let (abs_scalar, scalar_is_negative) = integer.abs_sign();
                Self::pow_bounded_multifold_accelerated_randomized(
                    accelerator,
                    &abs_scalar,
                    scalar_bits,
                )
                .wrapping_negate_if(scalar_is_negative.into())
            }
            None => self.pow_public_base_integer_bounded_randomized(integer, scalar_bits),
        }
    }

    fn scale_randomized<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.pow_randomized(scalar)
    }

    fn scale_randomized_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.pow_bounded_randomized(scalar, scalar_bits)
    }

    fn scale_integer_randomized<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_bounded(integer, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_randomized_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        let (abs_scalar, scalar_is_negative) = integer.abs_sign();
        self.pow_bounded_randomized(&abs_scalar, scalar_bits)
            .wrapping_negate_if(scalar_is_negative.into())
    }

    fn scale_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_public_base_bounded(scalar, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        match public_parameters.get_accelerator_for(&self.representative, scalar_bits) {
            Some(accelerator) => {
                Self::pow_bounded_multifold_accelerated(accelerator, scalar, scalar_bits)
            }
            None => self.pow_public_base_bounded(scalar, scalar_bits),
        }
    }

    fn scale_integer_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_public_base_bounded(integer, Uint::<LIMBS>::BITS, public_parameters)
    }

    fn scale_integer_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let (abs_scalar, scalar_is_negative) = integer.abs_sign();
        self.scale_public_base_bounded(&abs_scalar, scalar_bits, public_parameters)
            .wrapping_negate_if(scalar_is_negative.into())
    }

    fn scale_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar.bits_vartime(), public_parameters)
    }

    fn scale_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.pow_bounded_randomized(scalar, scalar.bits_vartime())
    }

    fn scale_integer_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        _public_parameters: &Self::PublicParameters,
    ) -> Self {
        let (abs_scalar, scalar_is_negative) = integer.abs_sign();
        let scaled_by_absolute_value_scalar =
            self.pow_bounded_randomized(&abs_scalar, abs_scalar.bits_vartime());

        if bool::from(scalar_is_negative) {
            scaled_by_absolute_value_scalar.neg_constant_time(_public_parameters)
        } else {
            scaled_by_absolute_value_scalar
        }
    }

    fn add_randomized(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        // TODO(#35): get rid of unwrap
        self.mul_randomized(other).unwrap()
    }

    fn add_vartime(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        // TODO(#35): get rid of unwrap
        self.mul_vartime(other).unwrap()
    }

    fn sub_randomized(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        // TODO(#35): get rid of unwrap
        self.div(other).unwrap()
    }

    fn sub_vartime(&self, other: &Self, _public_parameters: &Self::PublicParameters) -> Self {
        // TODO(#35): get rid of unwrap
        self.div_vartime(other).unwrap()
    }

    fn double(&self, _public_parameters: &Self::PublicParameters) -> Self {
        self.square()
    }

    fn double_vartime(&self, _public_parameters: &Self::PublicParameters) -> Self {
        self.square_vartime()
    }

    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> group::Result<Self> {
        linearly_combine_bounded_or_scale(
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
    ) -> group::Result<Self> {
        linearly_combine_bounded_or_scale(
            bases_and_multiplicands,
            exponent_bits,
            false,
            public_parameters,
        )
    }
}

impl<
        const HALF: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE: usize,
        const SCALAR_LIMBS: usize,
    > Mul<Uint<SCALAR_LIMBS>> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Uint<SCALAR_LIMBS>: Encoding,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = EquivalenceClass<DISCRIMINANT_LIMBS>;

    fn mul(self, rhs: Uint<SCALAR_LIMBS>) -> Self::Output {
        let public_parameters = PublicParameters::new_unaccelerated(*self.discriminant());
        self.scale(&rhs, &public_parameters)
    }
}

impl<
        'r,
        const HALF: usize,
        const DISCRIMINANT_LIMBS: usize,
        const DOUBLE: usize,
        const SCALAR_LIMBS: usize,
    > Mul<&'r Uint<SCALAR_LIMBS>> for EquivalenceClass<DISCRIMINANT_LIMBS>
where
    Uint<SCALAR_LIMBS>: Encoding,

    Int<DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<DISCRIMINANT_LIMBS>>,
    Uint<DISCRIMINANT_LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<DISCRIMINANT_LIMBS>>,
{
    type Output = EquivalenceClass<DISCRIMINANT_LIMBS>;

    fn mul(self, rhs: &'r Uint<SCALAR_LIMBS>) -> Self::Output {
        let public_parameters = PublicParameters::new_unaccelerated(*self.discriminant());
        self.scale(rhs, &public_parameters)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::U128;

    use group::GroupElement;

    use crate::discriminant::Discriminant;
    use crate::equivalence_class::PublicParameters;
    use crate::ibqf::Ibqf;
    use crate::{CompactIbqf, EquivalenceClass};

    #[test]
    fn test_ec_new() {
        let disc = Discriminant::<{ U128::LIMBS }>::new_u64(3372547, 0, 1).unwrap();
        let public_parameters = PublicParameters::new_unaccelerated(disc);

        // This CompactIbqf is malicious since it points to an unreduced form.
        let malicious_compact =
            CompactIbqf::new_unchecked(U128::from_be_hex("FFFFFFFFFFFFFFFC0000000000006337"));
        let ec = EquivalenceClass::new(malicious_compact, &public_parameters);
        assert!(ec.is_err());

        // This CompactIbqf is valid since it points to a reduced form.
        let valid_compact =
            CompactIbqf::new_unchecked(U128::from_be_hex("00000000000000050000000000000031"));
        let ec = EquivalenceClass::new(valid_compact, &public_parameters);
        assert!(ec.is_ok());

        let representative = *ec.unwrap().representative();
        let target = Ibqf::from_64(49, 5, 17207);
        assert_eq!(representative, target);
    }
}
