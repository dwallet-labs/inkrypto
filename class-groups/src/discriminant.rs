// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::ops::{BitAnd, BitOr, Deref};

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crypto_bigint::{Encoding, Int, NonZero, Uint, Zero, U64};
use serde::{Deserialize, Serialize};

use crate::{ibqf::Ibqf, Error};

/// A discriminant.
/// Must be negative and 0 or 1 mod 4.
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discriminant<const LIMBS: usize>(NonZero<Int<LIMBS>>)
where
    Int<LIMBS>: Encoding;

impl<const LIMBS: usize> Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    /// Attempt to create a new discriminant.
    pub fn new(value: NonZero<Int<LIMBS>>) -> CtOption<Self> {
        let is_negative = Choice::from(value.is_negative());

        // For a negative value to be 0 or 1 mod 4, its absolute value should be 0 or 3 mod 4.
        // Note: value is negative.
        let three = Uint::from(3u64);
        let abs_value_mod_4 = value.abs().bitand(three);
        let is_zero_or_one_mod_4: Choice = abs_value_mod_4
            .is_zero()
            .bitor(abs_value_mod_4.ct_eq(&three));

        CtOption::new(Self(value), is_negative.bitand(is_zero_or_one_mod_4))
    }

    /// Upper bound on the size of the class group identified by this discriminant `∆`.
    /// Computed as: `√(|∆|) * ln(|∆|) / π`
    ///
    /// Ref: Section 5.4.3 (pg. 245) and Exercise 27 (pg. 296) in
    /// "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    pub fn class_number_upper_bound(&self) -> Uint<LIMBS> {
        let one_hundred_thousand = U64::from(100_000u64).to_nz().expect("is non-zero");

        let abs = self.0.abs();
        let log2 = abs.saturating_sub(&Uint::ONE).bits();

        // Upper bound √(|∆|) with 2^(⌈log2(|∆|)/2⌉)
        let sqrt_upper_bound = Uint::ONE.shl_vartime(log2.div_ceil(2));

        // ln(x) = log2(x) * ln(2), with ln(2) = 0.69315...
        let ln = U64::from((log2 as u64 * 69_315u64) / 100_000u64);

        // note: 1/π = 0.31831...
        sqrt_upper_bound * ln * U64::from(31_831u64) / one_hundred_thousand
    }

    pub(crate) fn resize<const TARGET_LIMBS: usize>(&self) -> Discriminant<TARGET_LIMBS>
    where
        Int<TARGET_LIMBS>: Encoding,
    {
        Discriminant(self.0.resize::<TARGET_LIMBS>().to_nz().unwrap())
    }

    /// Compute the bit size of this discriminant.
    ///
    /// Executes in variable time w.r.t. `self`.
    pub(crate) fn bits_vartime(&self) -> u32 {
        self.0.abs().bits_vartime()
    }
}

impl<const LIMBS: usize> Deref for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Target = NonZero<Int<LIMBS>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LIMBS: usize> TryFrom<NonZero<Int<LIMBS>>> for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Error = Error;

    fn try_from(value: NonZero<Int<LIMBS>>) -> Result<Self, Self::Error> {
        Self::new(value)
            .into_option()
            .ok_or(Error::InvalidDiscriminantParameters)
    }
}

impl<const LIMBS: usize> TryFrom<Ibqf<LIMBS>> for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Error = Error;

    fn try_from(form: Ibqf<LIMBS>) -> Result<Self, Self::Error> {
        form.discriminant()
            .and_then(|d| d.to_nz().into())
            .into_option()
            .ok_or(Error::InternalError)
            .and_then(Self::try_from)
    }
}

impl<const LIMBS: usize> ConditionallySelectable for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(NonZero::conditional_select(&a.0, &b.0, choice))
    }
}

impl<const LIMBS: usize> Default for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    fn default() -> Self {
        let minus_15 = Int::from(-15i64).to_nz().expect("-15 is non-zero");
        Self::new(minus_15).expect("-15 is negative and 1 mod 4")
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{NonZero, I128, I4096, I64, U1280, U2048, U4096};

    use crate::discriminant::Discriminant;
    use crate::ibqf::Ibqf;

    #[test]
    fn test_new_value() {
        let val =
            NonZero::<I128>::new_unwrap(I128::from(-7i64 * 13i64.pow(2u32) * 71i64.pow(4u32)));
        let d = Discriminant::new(val).unwrap();
        assert_eq!(
            d.0,
            NonZero::<I128>::new_unwrap(I128::from(-30062018623i64))
        );
    }

    #[test]
    fn test_new_rejects_positive_values() {
        let val = NonZero::<I128>::new_unwrap(I128::from(7i64 * 13i64.pow(4u32) * 71i64.pow(4u32)));
        let d = Discriminant::new(val);
        assert!(bool::from(d.is_none()));
    }

    #[test]
    fn test_new_rejects_2mod4_or_3mod4_values() {
        assert!(bool::from(
            Discriminant::new(NonZero::<I128>::new_unwrap(I128::from(-2i32))).is_none()
        ));
        assert!(bool::from(
            Discriminant::new(NonZero::<I128>::new_unwrap(I128::MINUS_ONE)).is_none()
        ));
        // note: -1 = 3 mod 4
    }

    #[test]
    fn test_try_from_non_zero_int() {
        let val = I128::from(55i32).to_nz().unwrap();
        assert!(Discriminant::try_from(val).is_err());

        let val = I128::from(-55i32).to_nz().unwrap();
        assert!(Discriminant::try_from(val).is_ok());
    }

    #[test]
    fn test_try_from_ibqf() {
        let d = Discriminant::new(NonZero::<I128>::new_unwrap(I128::from(-775i32))).unwrap();
        let form = Ibqf::new(NonZero::ONE, I128::ONE, &d).unwrap();
        let d_ = Discriminant::try_from(form).unwrap();
        assert_eq!(d, d_);
    }

    #[test]
    /// regression test
    fn test_class_number_upper_bound() {
        let d = U2048::from_be_hex(concat![
            "DC1D46A19581975D3B3353146163AB9E510E7FE126682F3C16464A1D8CB81036",
            "8F503588001263D731D839D462BF25A35A33631A11EF5C6B37FF39DC7F1FDA8C",
            "0D04606A6DD1A04E65828EC237B408771C94E3195B8FEF06534013AEE1F68E6B",
            "B2EC14F971F57613D4C4454C2B5FFB705F8F1FB1C0653809D2AA95F7AFC38CF9",
            "82E44437CF2A122092F5A5B75A92565B91D91C1F828A0D1C32B4641ABCEBDE03",
            "5E391FCEE42E95770C379AAD0051918CDBB276AC07694E2C28994D801296E590",
            "3417C29248DCA9EA16D959148FB7779ACA0489666BE9D66240779456F20AF9C0",
            "6B2424B90868A46E0DCB4DE4C01870CCC90B1D0EE0AC3B93C5FDBC4A49343C93"
        ])
        .resize::<{ U4096::LIMBS }>();
        let d = Discriminant::new(NonZero::<I4096>::new_unwrap(
            d.as_int().checked_neg().unwrap(),
        ))
        .unwrap();

        let bound = U1280::from_be_hex(concat![
            "00000000000000000000000000000000000000000000000000000000000001C3",
            "AE9057D1782D38476F2A5A469D7342EDBB59DDC1E7967CAEA747D805E5F30E7F",
            "F583A53B8E4B87BDCF0307F23CC8DE2AC322291FB3FA6DEFC7A398201CD5F99C",
            "38B04AB606B7AA25D8D79D0A67620EE8D10F51AC9AFE1DA7B0B39192641B328B",
            "6D86EC17EBAF102363B256FFC115DF6555C52E72DA122FAD6CB5350092CCF6BE"
        ])
        .resize::<{ U4096::LIMBS }>();

        assert_eq!(d.class_number_upper_bound(), bound);
    }

    #[test]
    fn test_bits_vartime() {
        let d = Discriminant::new(I64::from(-7).to_nz().unwrap()).unwrap();
        assert_eq!(d.bits_vartime(), 3);

        let d = Discriminant::new(I64::from(-644687).to_nz().unwrap()).unwrap();
        assert_eq!(d.bits_vartime(), 20);

        let d = U2048::from_be_hex(concat![
            "DC1D46A19581975D3B3353146163AB9E510E7FE126682F3C16464A1D8CB81036",
            "8F503588001263D731D839D462BF25A35A33631A11EF5C6B37FF39DC7F1FDA8C",
            "0D04606A6DD1A04E65828EC237B408771C94E3195B8FEF06534013AEE1F68E6B",
            "B2EC14F971F57613D4C4454C2B5FFB705F8F1FB1C0653809D2AA95F7AFC38CF9",
            "82E44437CF2A122092F5A5B75A92565B91D91C1F828A0D1C32B4641ABCEBDE03",
            "5E391FCEE42E95770C379AAD0051918CDBB276AC07694E2C28994D801296E590",
            "3417C29248DCA9EA16D959148FB7779ACA0489666BE9D66240779456F20AF9C0",
            "6B2424B90868A46E0DCB4DE4C01870CCC90B1D0EE0AC3B93C5FDBC4A49343C93"
        ])
        .resize::<{ U4096::LIMBS }>();
        let d = Discriminant::new(NonZero::<I4096>::new_unwrap(
            d.as_int().checked_neg().unwrap(),
        ))
        .unwrap();
        assert_eq!(d.bits_vartime(), 2048)
    }
}
