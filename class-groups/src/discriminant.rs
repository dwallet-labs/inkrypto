// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::ops::{BitAnd, BitOr, Deref};

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crypto_bigint::{Encoding, Int, NonZero, NonZeroInt, NonZeroUint, Uint, Zero, U64};
use serde::{Deserialize, Serialize};

/// A discriminant with `value = -p·q^{2k+1}`
/// Must be negative and 0 or 1 mod 4.
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discriminant<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    q: NonZeroUint<LIMBS>,
    k: u32,
    value: NonZeroInt<LIMBS>,
}

impl<const LIMBS: usize> Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    /// Attempt to create a new discriminant `= -p · q^{2k+1}`.
    pub fn new<const Q_LIMBS: usize, const P_LIMBS: usize>(
        q: NonZeroUint<Q_LIMBS>,
        k: u32,
        p: NonZeroUint<P_LIMBS>,
    ) -> CtOption<Self> {
        assert!(Q_LIMBS <= LIMBS);
        assert!(P_LIMBS <= LIMBS);

        // = p · q^{2k+1}
        let mut abs_value = CtOption::new(Uint::ONE, Choice::from(1));
        for _ in 0..2 * k + 1 {
            abs_value = abs_value.and_then(|value| CtOption::from(value.checked_mul(q.as_ref())));
        }
        abs_value = abs_value.and_then(|value| CtOption::from(value.checked_mul(p.as_ref())));

        // = -p · q^{2k+1}
        let value = abs_value
            .and_then(|value| value.try_into_int().into())
            .and_then(|value| value.checked_neg().into())
            .and_then(|value| value.to_nz().into());

        value.and_then(|value| {
            // Note: value is negative by construction.
            // For a negative value to be 0 or 1 mod 4, its absolute value should be 0 or 3 mod 4.
            let three = Uint::from(3u64);
            let abs_value_mod_4 = value.abs().bitand(three);
            let abs_is_zero_mod_4 = abs_value_mod_4.is_zero();
            let abs_is_three_mod_4 = abs_value_mod_4.ct_eq(&three);
            let is_zero_or_one_mod_4: Choice = abs_is_zero_mod_4.bitor(abs_is_three_mod_4);

            let obj = Self {
                q: q.resize::<LIMBS>()
                    .to_nz()
                    .expect("upscaling a non-zero value"),
                k,
                value,
            };

            CtOption::new(obj, is_zero_or_one_mod_4)
        })
    }

    /// Read-only access to `q`
    pub fn q(&self) -> &NonZeroUint<LIMBS> {
        &self.q
    }

    /// Read-only access to `k`
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Lower bound on `p.bits()`.
    ///
    /// Executes in variable time w.r.t. `self`.
    pub fn lower_bound_p_bits_vartime(&self) -> u32 {
        self.value
            .abs()
            .bits()
            .saturating_sub(self.q.bits().saturating_mul(2 * self.k + 1))
    }

    /// Return a copy of `self` with `k := self.k + 1`.
    ///
    /// Returns `None` if the resulting discriminant does not fit in [`Int<LIMBS>`].
    pub(crate) fn with_incremented_k(&self) -> CtOption<Self> {
        CtOption::from(self.value.checked_mul_uint(&self.q))
            .and_then(|val_mul_q| val_mul_q.checked_mul_uint(&self.q).into())
            .and_then(|val_mul_q_sqr| val_mul_q_sqr.to_nz().into())
            .map(|val_mul_q_sqr| Self {
                q: self.q,
                k: self.k + 1,
                value: val_mul_q_sqr,
            })
    }

    /// Upper bound on the size of the class group identified by this discriminant `∆`.
    /// Computed as: `√(|∆|) * ln(|∆|) / π`
    ///
    /// Ref: Section 5.4.3 (pg. 245) and Exercise 27 (pg. 296) in
    /// "A Course in Computational Algebraic Number Theory" (978-3-662-02945-9).
    pub fn class_number_upper_bound(&self) -> Uint<LIMBS> {
        let one_hundred_thousand = U64::from(100_000u64).to_nz().expect("is non-zero");

        let abs = self.value.abs();
        let log2 = abs.saturating_sub(&Uint::ONE).bits();

        // Upper bound √(|∆|) with 2^(⌈log2(|∆|)/2⌉)
        let sqrt_upper_bound = Uint::ONE.shl_vartime(log2.div_ceil(2));

        // ln(x) = log2(x) * ln(2), with ln(2) = 0.69315...
        let ln = U64::from((log2 as u64 * 69_315u64) / 100_000u64);

        // note: 1/π = 0.31831...
        sqrt_upper_bound * ln * U64::from(31_831u64) / one_hundred_thousand
    }

    /// Compute the bit size of this discriminant.
    ///
    /// Executes in variable time w.r.t. `self`.
    pub(crate) fn bits_vartime(&self) -> u32 {
        self.value.abs().bits_vartime()
    }

    /// Scale `self` up to fit in `TARGET_LIMBS`.
    ///
    /// Panics if `TARGET_LIMBS ≤ LIMBS`.
    pub(crate) fn upscale<const TARGET_LIMBS: usize>(&self) -> Discriminant<TARGET_LIMBS>
    where
        Int<TARGET_LIMBS>: Encoding,
        Uint<TARGET_LIMBS>: Encoding,
    {
        assert!(LIMBS <= TARGET_LIMBS);
        Discriminant {
            q: self.q.resize::<TARGET_LIMBS>().to_nz().unwrap(),
            k: self.k,
            value: self.value.resize::<TARGET_LIMBS>().to_nz().unwrap(),
        }
    }
}

impl<const LIMBS: usize> Deref for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    type Target = NonZero<Int<LIMBS>>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<const LIMBS: usize> ConditionallySelectable for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            q: NonZero::conditional_select(&a.q, &b.q, choice),
            k: u32::conditional_select(&a.k, &b.k, choice),
            value: NonZero::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl<const LIMBS: usize> Default for Discriminant<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    fn default() -> Self {
        Self::new(
            U64::from_u64(3).to_nz().unwrap(),
            0,
            U64::from_u64(5).to_nz().unwrap(),
        )
        .expect("-15 is negative and 1 mod 4")
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub(crate) mod test_helpers {
    use crate::discriminant::Discriminant;
    use crate::{
        RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };
    use crypto_bigint::subtle::CtOption;
    use crypto_bigint::{Encoding, Int, Uint, U1280, U64};

    impl<const LIMBS: usize> Discriminant<LIMBS>
    where
        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Encoding,
    {
        pub(crate) fn new_u64(q: u64, k: u32, p: u64) -> CtOption<Self> {
            Self::new(
                U64::from_u64(q).to_nz().unwrap(),
                k,
                U64::from_u64(p).to_nz().unwrap(),
            )
        }
    }

    pub(crate) fn get_secp256k1_discriminant(
    ) -> Discriminant<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let q = group::secp256k1::ORDER.to_nz().unwrap();
        let k = 1;
        let p = U1280::from_be_hex(concat![
            "00000000000000000000000000000000000000000000000D2BB1F3C5DC9F51F3",
            "83756E9D0464477FE01B325DA603A754B2037B5303A9A0082494478C471C6975",
            "804CC0E754918F43A265EFF1AB83AF22BC037AEF7FCC34C558E38F9230CB58EC",
            "29D42226C7466BAD7490746DB9C6492CCE819F4CAD8A0D07D84C9BC42EAC0AF0",
            "F6EFB6866F87C6D56B262215C3DEF83DA9E3CA0BB069F4CE9F7C80F523264CDF"
        ])
        .to_nz()
        .unwrap();
        Discriminant::new(q, k, p).unwrap()
    }

    pub(crate) fn get_ristretto_discriminant(
    ) -> Discriminant<RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let q = group::ristretto::ORDER.to_nz().unwrap();
        let k = 1;
        let p = U1280::from_be_hex(concat![
            "00000000000000000000000000000000000000000000004AF663EEABD09DFD50",
            "6A9953372B3425C4DFBCD5166C42795FEAF08717409B37C2E21CC02D79D15C18",
            "1159239A9B9032353155272A35D0B5621CD541709F9915269C1B7A1FDC599628",
            "018B88A7D721108901A7BDA787D82B9ED82CFFF1F55496B7FCD3FBBB31EDDB27",
            "39032A260FF6F65A92E13595F26AA171F6AB11640A0C612244977F2B647758E7"
        ])
        .to_nz()
        .unwrap();
        Discriminant::new(q, k, p).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{I128, I2048, U1024, U128, U2048, U256, U64};

    use crate::discriminant::test_helpers::{
        get_ristretto_discriminant, get_secp256k1_discriminant,
    };
    use crate::discriminant::Discriminant;
    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };

    #[test]
    fn test_get_secp256k1_discriminant() {
        let cg_params =
            get_setup_parameters_secp256k1_112_bits_deterministic().class_group_parameters;
        let d = get_secp256k1_discriminant();
        assert_eq!(d, cg_params.delta_qk);
    }

    #[test]
    fn test_get_ristretto_discriminant() {
        let cg_params =
            get_setup_parameters_ristretto_112_bits_deterministic().class_group_parameters;
        let d = get_ristretto_discriminant();
        assert_eq!(d, cg_params.delta_qk);
    }

    #[test]
    fn test_new() {
        let (q, k, p) = (71, 1, 83993);
        let d = Discriminant::new_u64(q, k, p).unwrap();
        assert_eq!(d.q, U128::from(q).to_nz().unwrap());
        assert_eq!(d.k, k);
        assert_eq!(d.value, I128::from(-30062018623i64).to_nz().unwrap());

        // larger input values
        let d = get_ristretto_discriminant();
        let target = I2048::from_be_hex(concat![
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB5099C11542F620",
            "2AF9566ACC8D4CBD915C644639A6A924366D65883950DAFF6198AA31893D707C",
            "2B63D38E3B1827F1FF5EB54AB89BE2BF28B33534E5FA2E22046D34DDB9AF08A5",
            "FFBBE608A152AACB7B05992FD82076AD6E3F95206821791C63778DE6DD372088",
            "08433C88E8F195B7533476756279D12211487C40D7A16F27D301FD74DA54CF81",
            "AEAC00D86F1CED27AAB6D8770315594F7571819B33C66C5E71848346AECDE54A",
            "8520A365BA0ADB8D5AFADE0F2279B00D616B7FDFBC80891655A9EA762503F175",
            "8CC2B5D60B52DC3D8875A36CDEBDB6CFFBCE8FE3CA7E0297F8EF46AF44D3712D"
        ])
        .to_nz()
        .unwrap();
        assert_eq!(d.q, group::ristretto::ORDER.resize().to_nz().unwrap());
        assert_eq!(d.value, target);
    }

    #[test]
    fn test_new_rejects_2mod4_or_3mod4_values() {
        // note: -2 = 2 mod 4
        let d = Discriminant::<{ U64::LIMBS }>::new_u64(2, 0, 1);
        assert!(bool::from(d.is_none()));

        // note: -1 = 3 mod 4
        let d = Discriminant::<{ U64::LIMBS }>::new_u64(1, 0, 1);
        assert!(bool::from(d.is_none()));
    }

    #[test]
    /// regression test
    fn test_class_number_upper_bound() {
        let d = get_ristretto_discriminant();

        let bound = U1024::from_be_hex(concat![
            "00000000000000000000006619121AB4B72C5197A24894C447C30D306A2B1704",
            "FF43419E30014F8B588E368F08461F9F01B866E43AA79BBADC0980B242070B8C",
            "FBFC6540CC78E9F6A93F290ABB44E50C5EB313BE22E5DE15CA6CA03C4B09E98D",
            "CDB37C99AE924F227D028A1DFB9389B52007DD441355475A31A4BDBA0A526959"
        ])
        .resize::<{ U2048::LIMBS }>();

        assert_eq!(d.class_number_upper_bound(), bound);
    }

    #[test]
    fn test_bits_vartime() {
        let d = Discriminant::<{ U64::LIMBS }>::new_u64(7, 0, 1).unwrap();
        assert_eq!(d.bits_vartime(), 3);

        let d = Discriminant::<{ U64::LIMBS }>::new_u64(644687, 0, 1).unwrap();
        assert_eq!(d.bits_vartime(), 20);

        let d = get_ristretto_discriminant();
        assert_eq!(d.bits_vartime(), 1851)
    }
    #[test]
    fn test_lower_bound_p_bits() {
        // p ≠ 1
        let d = get_ristretto_discriminant();
        let actual_p_bit_size = 1095;
        assert!(d.lower_bound_p_bits_vartime() <= actual_p_bit_size);

        // p = 1
        let d = Discriminant::<{ U64::LIMBS }>::new_u64(7, 6, 1).unwrap();
        let actual_p_bit_size = 1;
        assert!(d.lower_bound_p_bits_vartime() <= actual_p_bit_size);
    }

    #[test]
    fn test_with_incremented_k() {
        let d = Discriminant::<{ U128::LIMBS }>::new_u64(5, 3, 7).unwrap();
        let target = Discriminant::new_u64(5, 4, 7).unwrap();
        assert_eq!(d.with_incremented_k().unwrap(), target);
    }

    #[test]
    fn test_upscale() {
        let d = Discriminant::<{ U128::LIMBS }>::new_u64(5, 3, 7).unwrap();
        let target = Discriminant::<{ U256::LIMBS }>::new_u64(5, 3, 7).unwrap();
        assert_eq!(d.upscale(), target);
    }
}
