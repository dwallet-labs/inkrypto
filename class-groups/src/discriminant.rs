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
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discriminant<const LIMBS: usize>(NonZero<Int<LIMBS>>)
where
    Int<LIMBS>: Encoding;

impl<const LIMBS: usize> Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    /// Attempt to create a new discriminant.
    pub fn new(value: NonZero<Int<LIMBS>>) -> Result<Self, Error> {
        let is_negative = Choice::from(value.is_negative());

        // Safe to `unwrap` as this hard-coded number is non-zero
        let four = U64::from(4u32).to_nz().unwrap();
        let three = U64::from(3u32);

        // For a negative value to be 0 or 1 mod 4, its absolute value should be 0 or 3 mod 4.
        // Note: value is negative.
        let abs_value_mod_4 = value.abs().rem(&four);
        let is_zero_or_one_mod_4: Choice = abs_value_mod_4
            .is_zero()
            .bitor(abs_value_mod_4.ct_eq(&three));

        CtOption::new(Self(value), is_negative.bitand(is_zero_or_one_mod_4))
            .into_option()
            .ok_or(Error::InvalidDiscriminantParameters)
    }

    /// Upper bound on the size of the class group identified by this discriminant `∆`.
    /// Computed as: `sqrt(|∆|) * ln(|∆|) / π`
    ///
    /// Ref: Section 5.4.3 (pg. 245) and Exercise 27 (pg. 296) in
    /// "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    pub fn class_number_upper_bound(&self) -> Uint<LIMBS> {
        // Safe to `unwrap` as this hard-coded number is non-zero
        let one_hundred_thousand = U64::from(100_000u64).to_nz().unwrap();

        let abs = self.0.abs();
        let sqrt_of_d = abs.sqrt();
        let log2_of_d = Uint::from(abs.bits());

        // ln(x) = log2(x) * ln(2), with ln(2) = 0.69315...
        let ln_of_d = log2_of_d * U64::from(69_315u64) / one_hundred_thousand;

        // note: 1/π = 0.31831...
        ln_of_d * sqrt_of_d * U64::from(31_831u64) / one_hundred_thousand
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
    }
}

impl<const LIMBS: usize> TryFrom<Ibqf<LIMBS>> for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    type Error = Error;

    fn try_from(form: Ibqf<LIMBS>) -> Result<Self, Self::Error> {
        let d = form.discriminant().map_err(|_| Error::InternalError)?;
        let d = NonZero::new(d).into_option().ok_or(Error::InternalError)?;
        Self::try_from(d)
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
        assert!(d.is_err());
    }

    #[test]
    fn test_new_rejects_2mod4_or_3mod4_values() {
        assert!(Discriminant::new(NonZero::<I128>::new_unwrap(I128::from(-2i32))).is_err());
        assert!(Discriminant::new(NonZero::<I128>::new_unwrap(I128::MINUS_ONE)).is_err());
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
        let form = Ibqf::new_reduced(NonZero::ONE, I128::ONE, &d).unwrap();
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
            "00000000000000000000000000000000000000000000000000000000000001A2",
            "D4420BC55D827F80DE9660685B05481823FF27D91483181980D4BBC245E7516C",
            "57751168E396F79BE85B87C3F4358C3C89DB2E4BD0B21E974400F56AD5108262",
            "F6ABFCDE31EB7EE9CD342260D4A9497D9E290051C6984588C30B1D77AC626EE0",
            "CBF440564EA3E5B9DA870863B89CD05917E2EDCEDA3D768EEBA88C4E9C6BCAD2"
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
