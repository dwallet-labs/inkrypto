// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::cmp::{max, min};

use crypto_bigint::subtle::{Choice, ConstantTimeEq, ConstantTimeGreater};
use crypto_bigint::{Concat, ConstantTimeSelect, Encoding, Gcd, Int, InvMod, NonZero, Split, Uint};
use serde::{Deserialize, Serialize};

use crate::helpers::lookup::ConstantTimeLookup;
use crate::ibqf::accelerator::jsf::JointSparseForm;
use crate::ibqf::Ibqf;
use crate::randomizer::ScalingBase;
use crate::Error;

pub mod jsf;

/// Tool used to accelerate computing [Ibqf::nupow].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NupowAccelerator<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
{
    form: Ibqf<LIMBS>,
    quarter_target_bits: u32,
    half_target_bits: u32,
    form_exp_2_exp_quarter: Ibqf<LIMBS>,
    form_exp_2_exp_half: Ibqf<LIMBS>,
    form_exp_2_exp_three_quarter: Ibqf<LIMBS>,
}

type LookupTable<const LIMBS: usize> = [Ibqf<LIMBS>; 41];

type LookupIndices = Vec<(u32, Choice)>;

type EncodedExponent<const LIMBS: usize> = (LookupTable<LIMBS>, LookupIndices);

impl<const HALF: usize, const LIMBS: usize, const DOUBLE: usize> NupowAccelerator<LIMBS>
where
    Int<HALF>: InvMod<Modulus = NonZero<Uint<HALF>>, Output = Uint<HALF>>,
    Uint<HALF>: Concat<Output = Uint<LIMBS>>
        + Gcd<Output = Uint<HALF>>
        + InvMod<Modulus = Uint<HALF>, Output = Uint<HALF>>,

    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,

    Int<DOUBLE>: Encoding,
    Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    /// Construct nupow-accelerator for `form`.
    ///
    /// Optimizes for operating on exponents with bit size close to `exponent_bits_target`.
    ///
    /// Executes in variable time w.r.t. both `form` and `exponent_bits_target`.
    pub(crate) fn new_vartime(form: Ibqf<LIMBS>, exponent_bits_target: u32) -> Result<Self, Error> {
        let quarter = exponent_bits_target.div_ceil(4);
        let half = 2 * quarter;

        // = form^(2^quarter)
        let two_exp_quarter = form.nupow2k_vartime(quarter)?;
        // = form^(2^half)
        let two_exp_half = two_exp_quarter.nupow2k_vartime(quarter)?;
        // = form^(2^(3 * quarter))
        let two_exp_three_quarter = two_exp_half.nupow2k_vartime(quarter)?;

        Ok(Self {
            form,
            quarter_target_bits: quarter,
            half_target_bits: half,
            form_exp_2_exp_quarter: two_exp_quarter,
            form_exp_2_exp_half: two_exp_half,
            form_exp_2_exp_three_quarter: two_exp_three_quarter,
        })
    }

    /// Raise `self.form` to the power `exponent`.
    ///
    /// Executes in variable time w.r.t. `self.form` only.
    pub(crate) fn pow_vartime_form<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Result<Ibqf<LIMBS>, Error> {
        self.pow_bounded_vartime_form(exponent, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Raise `self.form` to the power `exponent`.
    ///
    /// Executes in variable time w.r.t. both `self` and `exponent`.
    pub(crate) fn pow_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> Result<Ibqf<LIMBS>, Error> {
        self.pow_bounded_vartime(exponent, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Compute `self.form^e`, with `e` the integer represented by the `exponent_bits` least
    /// significant bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. `self.form` and `exponent_bits`, but, importantly, not to
    /// `exponent`.
    pub(crate) fn pow_bounded_vartime_form<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Result<Ibqf<LIMBS>, Error> {
        let exponent = bound_exponent(exponent, exponent_bits);

        let (lookup_table, indices) =
            self.construct_exponentation_sequence_vartime(&exponent, exponent_bits)?;

        let mut res = self.form.unit()?;
        for (idx, negate) in indices.into_iter() {
            res = res.nudupl()?;
            let mut form = lookup_table
                .ct_lookup(idx as usize)
                .into_option()
                .ok_or(Error::InternalError)?;
            form = form.wrapping_invert_if(negate);
            res = res.nucomp(&form)?;
        }
        Ok(res)
    }

    /// Compute `self.form^e`, with `e` the integer represented by the `exponent_bits` least
    /// significant bits of `exponent`.
    ///
    /// Assumes that `self.form` is a random form, enabling the use of the faster
    /// `nucomp/nudupl_randomized` operations.
    ///
    /// Executes in variable time w.r.t. `self.form` and `exponent_bits`, but, importantly,
    /// not to `exponent`.
    pub(crate) fn pow_bounded_randomized_vartime_form<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
        start: ScalingBase<LIMBS>,
    ) -> Result<Ibqf<LIMBS>, Error> {
        let (lookup_table, indices) =
            self.construct_exponentation_sequence_vartime(exponent, exponent_bits)?;

        let ScalingBase {
            m1,
            m2,
            scalar_bits_bound,
        } = start;
        if scalar_bits_bound as usize != indices.len() {
            return Err(Error::InvalidScalingBase);
        }

        self.pow_encoded_bounded_randomized_with_start(
            *m1.representative(),
            (lookup_table, indices),
        )?
        .nucompinv(m2.representative())
    }

    /// Map `(self, start)` to `start^{2^b} * self^exponent` with `b` the length of `exponent`'s
    /// encoding.
    #[inline]
    fn pow_encoded_bounded_randomized_with_start(
        &self,
        start: Ibqf<LIMBS>,
        exponent: EncodedExponent<LIMBS>,
    ) -> Result<Ibqf<LIMBS>, Error> {
        let (lookup_table, indices) = exponent;

        let mut res = start;
        for (idx, negate) in indices.into_iter() {
            res = res.nudupl_randomized()?;
            let mut form = lookup_table
                .ct_lookup(idx as usize)
                .into_option()
                .ok_or(Error::InternalError)?;
            form = form.wrapping_invert_if(negate);
            let composed = res.nucomp_randomized(&form)?;

            // Bypass the composition of `res` with lookup_table[0], which is the unit element.
            // The unit element is not random and thus the composition cannot be reduced fast.
            res = Ibqf::ct_select(&composed, &res, idx.ct_eq(&0u32));
        }
        Ok(res)
    }

    /// Compute `self^e`, where `e` is the integer represented by the `exponent_bits` least
    /// significant bits of `exponent`.
    ///
    /// Executes in variable time w.r.t. both `self` and `exponent`.
    pub(crate) fn pow_bounded_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Result<Ibqf<LIMBS>, Error> {
        let (exponent, exponent_bits) = bound_exponent_vartime(exponent, exponent_bits);

        if exponent_bits < self.quarter_target_bits {
            return self.form.nupow_vartime(&exponent);
        }

        let (lookup_table, indices) =
            self.construct_exponentation_sequence_vartime(&exponent, exponent_bits)?;

        let mut res = self.form.unit()?;
        for (idx, negate) in indices.into_iter() {
            res = res.nudupl_vartime()?;

            if idx == 0 {
                continue;
            }

            let mut form = lookup_table[idx as usize];
            form = form.wrapping_invert_if(negate);
            res = res.nucomp_vartime(&form)?;
        }
        Ok(res)
    }

    /// Compute the size of the encoding of an exponent bounded by `exponent_bits`.
    pub(crate) fn get_bounded_exponent_encoding_size(&self, exponent_bits: u32) -> u32 {
        if exponent_bits <= self.quarter_target_bits {
            exponent_bits + 1
        } else {
            let jsf_size = max(
                exponent_bits.saturating_sub(self.half_target_bits),
                self.half_target_bits,
            ) + 1;
            max(
                jsf_size.saturating_sub(self.quarter_target_bits),
                self.quarter_target_bits + 1,
            )
        }
    }

    /// Encode an exponent in Joint Sparse Form.
    ///
    /// Executes in variable time w.r.t. `exponent_bits` only.
    fn encode_bounded_exponent<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> JointSparseForm {
        let exponent = bound_exponent(exponent, exponent_bits);

        if exponent_bits <= self.half_target_bits {
            return JointSparseForm::new(&exponent, &Uint::ZERO, exponent_bits + 1);
        }

        let lo = bound_exponent(&exponent, self.half_target_bits);
        let hi = exponent.wrapping_shr_vartime(self.half_target_bits);
        let bit_size = max(
            exponent_bits.saturating_sub(self.half_target_bits),
            self.half_target_bits,
        ) + 1;
        JointSparseForm::new(&lo, &hi, bit_size)
    }

    /// Construct a look-up table s.t.
    /// `tab[i] = form^e0 * two_exp_d^e1 * two_exp_e^e2 * two_exp_de^e3` where
    /// `[ e0, e1, e2, e3 ]` is `i` written in basis 3 with digits in `(-1, 0, 1)`.
    ///
    /// Example:
    /// `tab[21] = form^0 * two_exp_d^1 * two_exp_e^-1 * two_exp_de^1`,
    /// because `21 = 0*3^0 + 1*3^1 + -1*3^2 + 1*3^3`
    fn exponent_table_vartime(&self) -> Result<LookupTable<LIMBS>, Error> {
        // Set starting values
        let unit = self.form.unit()?;
        let mut tab: LookupTable<LIMBS> = core::array::from_fn(|_| unit);
        tab[1] = self.form;
        tab[3] = self.form_exp_2_exp_half;
        tab[9] = self.form_exp_2_exp_quarter;
        tab[27] = self.form_exp_2_exp_three_quarter;

        // Fill table
        let (mut b, mut pow3) = (1, 3);
        for _ in 0..3 {
            for k in 0..b {
                tab[pow3 + k + 1] = tab[pow3].nucomp_vartime(&tab[k + 1])?;
                tab[pow3 - k - 1] = tab[pow3].nucompinv_vartime(&tab[k + 1])?;
            }
            b += pow3;
            pow3 *= 3;
        }

        Ok(tab)
    }

    #[inline]
    /// Map a 4-bit JSF-entry to the set `{-1, 0, 1}`.
    ///
    /// Applied mapping:
    /// `0bxx11` -> `-1`,
    /// `0bxx10` -> `-1`,
    /// `0bxx01` -> ` 1`,
    /// `0bxx00` -> ` 0`
    fn decode(encoding: u8) -> i32 {
        let offset = i32::ct_select(&0, &1, (encoding & 0x3).ct_gt(&0));
        i32::ct_select(&offset, &-offset, (encoding & 0x2).ct_gt(&0))
    }

    /// Recode JSF to lookup-table indices.
    fn recode_jsf(&self, jsf: &JointSparseForm) -> Vec<(u32, Choice)> {
        let recoding_size = if jsf.size() <= self.quarter_target_bits as usize {
            jsf.size()
        } else {
            max(
                jsf.size().saturating_sub(self.quarter_target_bits as usize),
                self.quarter_target_bits as usize + 1,
            )
        };

        let mut recoding = vec![0; recoding_size];
        for (j, val) in recoding.iter_mut().enumerate() {
            let digh = jsf.get(j + self.quarter_target_bits as usize);
            *val += 9 * Self::decode(digh) + 27 * Self::decode(digh >> 4);
        }

        let upper_bound = min(recoding_size, self.quarter_target_bits as usize);
        for (j, val) in recoding[0..upper_bound].iter_mut().enumerate() {
            let digl = jsf.get(j);
            *val += Self::decode(digl) + 3 * Self::decode(digl >> 4);
        }

        recoding
            .into_iter()
            .map(|idx| {
                let abs = idx.unsigned_abs();
                let negate = idx.ct_ne(&(abs as i32));
                (abs, negate)
            })
            .rev()
            .collect()
    }

    /// Constructs a sequence of forms that should be added onto `self.form` in between doublings
    /// to construct the form `self.form^e`, with `e` the integer represented by the `exponent_bits`
    /// least significant bits of `exponent`.
    ///
    /// Exposes this set of forms as tuple containing
    /// - a look-up table, and
    /// - tuples containing the
    ///     - index in the look-up table to add, and
    ///     - a `Choice` indicating whether the form should be inverted before addition.
    ///
    /// Executes in time variable in `self` and `exponent_bits`, but not in `exponent`.
    fn construct_exponentation_sequence_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Result<EncodedExponent<LIMBS>, Error> {
        let tab = self.exponent_table_vartime()?;
        let jsf = self.encode_bounded_exponent(exponent, exponent_bits);
        let indices = self.recode_jsf(&jsf);

        Ok((tab, indices))
    }
}

impl<const LIMBS: usize> NupowAccelerator<LIMBS>
where
    Int<LIMBS>: Encoding,
{
    pub fn form(&self) -> &Ibqf<LIMBS> {
        &self.form
    }
}

/// Restrict `exponent` to its `exponent_bits` least significant bits; all other bits are set to
/// zero.
#[inline]
fn bound_exponent<const LIMBS: usize>(exponent: &Uint<LIMBS>, exponent_bits: u32) -> Uint<LIMBS> {
    let shift = Uint::<LIMBS>::BITS.saturating_sub(exponent_bits);
    let mask = Uint::<LIMBS>::MAX.shr_vartime(shift);
    exponent.bitand(&mask)
}

/// Restrict `exponent` to its `exponent_bits` least significant bits; all other bits are set to
/// zero. Additionally, the bit size of this bounded exponent is returned. This bit size is computed
/// in variable time.
#[inline]
fn bound_exponent_vartime<const LIMBS: usize>(
    exponent: &Uint<LIMBS>,
    exponent_bits: u32,
) -> (Uint<LIMBS>, u32) {
    let exponent = bound_exponent(exponent, exponent_bits);
    let exponent_bits = exponent.bits_vartime();
    (exponent, exponent_bits)
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{
        Concat, ConstantTimeSelect, Encoding, Gcd, Int, InvMod, NonZero, Random, Split, Uint,
        I2048, I4096, I64, U1024, U128, U2048, U256, U512, U768,
    };
    use rand_core::OsRng;

    use crate::ibqf::accelerator::NupowAccelerator;
    use crate::randomizer::ScalingBase;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::EquivalenceClass;

    /// Shared setup for this test suite
    fn setup_secp256k1(target_bits: u32) -> NupowAccelerator<{ I2048::LIMBS }> {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        NupowAccelerator::new_vartime(*setup_parameters.h.representative(), target_bits).unwrap()
    }

    /// Express `i` in base 3, i.e., as `a + 3b + 9c + 27d`, with `a, b, c, d` in `{-1, 0, 1}`.
    fn base_3_repr(i: i32) -> (i32, i32, i32, i32) {
        let mut a = i % 3;
        let mut b = i / 3 % 3;
        let mut c = i / 9 % 3;
        let mut d = i / 27 % 3;

        if a > 1 {
            a -= 3;
            b += 1;
        }
        if b > 1 {
            b -= 3;
            c += 1;
        }
        if c > 1 {
            c -= 3;
            d += 1;
        }

        (a, b, c, d)
    }

    #[test]
    fn test_lookup_table() {
        let acc = setup_secp256k1(768);

        let tab = acc.exponent_table_vartime().unwrap();

        // Test that the table is correct.
        for i in 0..41i32 {
            // express `indexed_value` in base 3, i.e., as a + 3b + 9c + 27d, with a, b, c, d in {-1, 0, 1}
            let (a, b, c, d) = base_3_repr(i);

            // construct entry
            let a = if a == 1 {
                acc.form
            } else if a == -1 {
                acc.form.invert()
            } else {
                acc.form.unit().unwrap()
            };

            let b = if b == 1 {
                acc.form_exp_2_exp_half
            } else if b == -1 {
                acc.form_exp_2_exp_half.invert()
            } else {
                acc.form.unit().unwrap()
            };

            let c = if c == 1 {
                acc.form_exp_2_exp_quarter
            } else if c == -1 {
                acc.form_exp_2_exp_quarter.invert()
            } else {
                acc.form.unit().unwrap()
            };

            let d = if d == 1 {
                acc.form_exp_2_exp_three_quarter
            } else if d == -1 {
                acc.form_exp_2_exp_three_quarter.invert()
            } else {
                acc.form.unit().unwrap()
            };

            assert_eq!(
                tab[i as usize],
                a.nucomp(&b)
                    .unwrap()
                    .nucomp(&c)
                    .unwrap()
                    .nucomp(&d)
                    .unwrap()
            )
        }
    }

    fn encode_exponent_test<
        const HALF: usize,
        const LIMBS: usize,
        const DOUBLE: usize,
        const EXPONENT_LIMBS: usize,
        const DOUBLE_EXPONENT_LIMBS: usize,
    >(
        acc: NupowAccelerator<LIMBS>,
        exp: Uint<EXPONENT_LIMBS>,
    ) where
        Int<HALF>: InvMod<Modulus = NonZero<Uint<HALF>>, Output = Uint<HALF>>,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>
            + Gcd<Output = Uint<HALF>>
            + InvMod<Modulus = Uint<HALF>, Output = Uint<HALF>>,

        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,

        Int<DOUBLE>: Encoding,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,

        Uint<EXPONENT_LIMBS>: Concat<Output = Uint<DOUBLE_EXPONENT_LIMBS>>,
    {
        // Construct JSF for the exponent
        let jsf = acc.encode_bounded_exponent(&exp, exp.bits_vartime());

        let two_exp_quarter = Int::ONE.shl_vartime(acc.quarter_target_bits);
        let two_exp_half = two_exp_quarter.shl_vartime(acc.quarter_target_bits);
        let two_exp_three_quarter = two_exp_half.shl_vartime(acc.quarter_target_bits);

        // Reconstruct the exponent from the JSF
        let mut rebuilt_exponent = Int::<DOUBLE_EXPONENT_LIMBS>::ZERO;
        for j in (acc.half_target_bits as usize..jsf.size()).rev() {
            let hi = jsf.get(j);
            let q = NupowAccelerator::<{ U2048::LIMBS }>::decode(hi);
            let three_q = NupowAccelerator::<{ U2048::LIMBS }>::decode(hi >> 4);

            let component =
                two_exp_quarter * I64::from(q) + two_exp_three_quarter * I64::from(three_q);

            rebuilt_exponent = rebuilt_exponent.shl_vartime(1);
            rebuilt_exponent += component;
        }
        for j in (0..acc.quarter_target_bits as usize).rev() {
            let lo = jsf.get(j);
            let f = NupowAccelerator::<{ U2048::LIMBS }>::decode(lo);
            let h = NupowAccelerator::<{ U2048::LIMBS }>::decode(lo >> 4);

            let hi = jsf.get(j + acc.quarter_target_bits as usize);
            let q = NupowAccelerator::<{ U2048::LIMBS }>::decode(hi);
            let three_q = NupowAccelerator::<{ U2048::LIMBS }>::decode(hi >> 4);

            let exponent_component = Int::from(f)
                + two_exp_quarter * I64::from(q)
                + two_exp_half * I64::from(h)
                + two_exp_three_quarter * I64::from(three_q);

            rebuilt_exponent = rebuilt_exponent.shl_vartime(1);
            rebuilt_exponent += exponent_component;
        }

        assert_eq!(rebuilt_exponent.as_uint().resize::<EXPONENT_LIMBS>(), exp);
    }

    #[test]
    fn test_encode_exponent() {
        let acc = setup_secp256k1(768);
        let exp = U2048::random(&mut OsRng);
        encode_exponent_test(acc, exp);

        // Regression tests
        let exp = U2048::from_be_hex(concat![
            "E8D8504873DF67C35B1D3CE8DCB475D78FC2D7C42BDB33F4CDA947F9F178797E",
            "E66755DD1672997CA0273BC7CAF751F8ADA7AB25501898589991CB4FBA727130",
            "EB12990B4E5BCFDD56F76A8370872D876990A03DBAA9E79D7DCDF102B560FF7A",
            "5C6A390D9B5BE05351A81058C2808F96F5639926D1D4F7916CF9A25B378ECA8A",
            "3AEFFC670FA6328F779B83D06BA3D82272194922B9355D3D030D7AF22D83E5DC",
            "6719B061F28AED492C05CDD3A6D60F57970202E6DBBEB09C8B2F71061BA1D5F3",
            "9C1CD12BDE1444026A120AA129CC60FA6B985AECBF7776D1735CC8454FB71675",
            "9D4786AABB6853536EBE48409A5E7AD663818CF25879A0E32898FC96F48FBC7F"
        ]);
        encode_exponent_test(acc, exp);
        let exp = U2048::from_be_hex(concat![
            "FE485B48A18B809CE649000B7434919A118232367B7CD5BEBEB88C33AE1EECF1",
            "0C6919C8C4A7A5AF551597CC43F27AE8BB92FFBCA2370E86BB120BA10676FF70",
            "F55D0ACDA1C319FBD8DE8A7A10FDD052AA140464649193AE522DFA4553C0AAD1",
            "04B3E5482F84503427E55132906D0BA3EB736F62ADB9C03EB25FC4C7160BC8A3",
            "8DF979FD4B914FA0898AB5FAF59D13024B8DBE7615DF6F1FEDC831455584E7B9",
            "DE4DACA121AF05F25B2107F4AF2B43B43407C757BBB2C16F23479BF6DC6A947D",
            "1172AEE2A8C993938BA8FD16BE0C27B86CC62858FF7362ABE3E950FF7BBC3E0B",
            "1CC4CD161F31F238F60199943B42CF9243B499FBDCB77951882B3063E833E5F9"
        ]);
        encode_exponent_test(acc, exp);
    }

    #[test]
    fn test_exponentation_sequence() {
        let acc = setup_secp256k1(768);

        // Sample random exponent
        let exp = U2048::random(&mut OsRng);

        // construct exponentation sequence
        let (_, seq) = acc
            .construct_exponentation_sequence_vartime(&exp, exp.bits_vartime())
            .unwrap();

        let two_exp_e = I4096::ONE.shl_vartime(acc.quarter_target_bits);
        let two_exp_d = I4096::ONE.shl_vartime(acc.half_target_bits);
        let two_exp_de = I4096::ONE.shl_vartime(acc.half_target_bits + acc.quarter_target_bits);

        // reconstruct exponent from seq
        let mut rebuilt_exponent = I4096::ZERO;
        for (index, invert_element) in seq {
            let (f, d, e, de) = base_3_repr(index as i32);

            let component = Int::from(f)
                + two_exp_d * I64::from(d)
                + two_exp_e * I64::from(e)
                + two_exp_de * I64::from(de);

            rebuilt_exponent = rebuilt_exponent.shl_vartime(1);
            rebuilt_exponent = Int::ct_select(
                &(rebuilt_exponent + component),
                &(rebuilt_exponent - component),
                invert_element,
            );
        }

        assert_eq!(rebuilt_exponent.as_uint().resize::<{ U2048::LIMBS }>(), exp);
    }

    fn test_acc_vs_nupow<
        const HALF: usize,
        const LIMBS: usize,
        const DOUBLE: usize,
        const EXPONENT_LIMBS: usize,
    >(
        acc: NupowAccelerator<LIMBS>,
        exp: Uint<EXPONENT_LIMBS>,
    ) where
        Int<HALF>: InvMod<Modulus = NonZero<Uint<HALF>>, Output = Uint<HALF>>,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>
            + Gcd<Output = Uint<HALF>>
            + InvMod<Modulus = Uint<HALF>, Output = Uint<HALF>>,

        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,

        Int<DOUBLE>: Encoding,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        let nupow_vt = acc.form.nupow_vartime(&exp).unwrap();
        let acc_vt = acc.pow_vartime(&exp).unwrap();

        // TODO: compare nupow_vt vs acc_vt vs nupow_ct vs acc_ct
        assert_eq!(nupow_vt, acc_vt);
    }

    #[test]
    fn test_nupow_exponent_smaller_than_quarter() {
        let acc = setup_secp256k1(768);
        let exp = U128::random(&mut OsRng);
        test_acc_vs_nupow(acc, exp);
    }

    #[test]
    fn test_nupow_exponent_between_quarter_and_half() {
        let acc = setup_secp256k1(768);
        let exp = U256::random(&mut OsRng);
        test_acc_vs_nupow(acc, exp);
    }

    #[test]
    fn test_nupow_exponent_between_half_and_full() {
        let acc = setup_secp256k1(768);
        let exp = U512::random(&mut OsRng);
        test_acc_vs_nupow(acc, exp);
    }

    #[test]
    fn test_nupow_full_size_exponent() {
        let acc = setup_secp256k1(768);
        let exp = U768::random(&mut OsRng);
        test_acc_vs_nupow(acc, exp);
    }

    #[test]
    fn test_nupow_exponent_exceeding_target_bits() {
        let acc = setup_secp256k1(768);
        let exp = U2048::random(&mut OsRng);
        test_acc_vs_nupow(acc, exp);

        let exp = U2048::from_be_hex(concat![
            "E8D8504873DF67C35B1D3CE8DCB475D78FC2D7C42BDB33F4CDA947F9F178797E",
            "E66755DD1672997CA0273BC7CAF751F8ADA7AB25501898589991CB4FBA727130",
            "EB12990B4E5BCFDD56F76A8370872D876990A03DBAA9E79D7DCDF102B560FF7A",
            "5C6A390D9B5BE05351A81058C2808F96F5639926D1D4F7916CF9A25B378ECA8A",
            "3AEFFC670FA6328F779B83D06BA3D82272194922B9355D3D030D7AF22D83E5DC",
            "6719B061F28AED492C05CDD3A6D60F57970202E6DBBEB09C8B2F71061BA1D5F3",
            "9C1CD12BDE1444026A120AA129CC60FA6B985AECBF7776D1735CC8454FB71675",
            "9D4786AABB6853536EBE48409A5E7AD663818CF25879A0E32898FC96F48FBC7F"
        ]);
        test_acc_vs_nupow(acc, exp);
        let exp = U2048::from_be_hex(concat![
            "FE485B48A18B809CE649000B7434919A118232367B7CD5BEBEB88C33AE1EECF1",
            "0C6919C8C4A7A5AF551597CC43F27AE8BB92FFBCA2370E86BB120BA10676FF70",
            "F55D0ACDA1C319FBD8DE8A7A10FDD052AA140464649193AE522DFA4553C0AAD1",
            "04B3E5482F84503427E55132906D0BA3EB736F62ADB9C03EB25FC4C7160BC8A3",
            "8DF979FD4B914FA0898AB5FAF59D13024B8DBE7615DF6F1FEDC831455584E7B9",
            "DE4DACA121AF05F25B2107F4AF2B43B43407C757BBB2C16F23479BF6DC6A947D",
            "1172AEE2A8C993938BA8FD16BE0C27B86CC62858FF7362ABE3E950FF7BBC3E0B",
            "1CC4CD161F31F238F60199943B42CF9243B499FBDCB77951882B3063E833E5F9"
        ]);
        test_acc_vs_nupow(acc, exp);
    }

    #[test]
    fn test_nupow_bounded_vartime() {
        let acc = setup_secp256k1(768);
        let exp = U2048::random(&mut OsRng);
        let exp_bits = 1235;

        let mask = U2048::MAX.shr_vartime(U2048::BITS - exp_bits);
        let truncated_exp = exp.bitand(&mask);

        assert_eq!(
            acc.form
                .nupow_bounded_vartime(&truncated_exp, exp_bits)
                .unwrap(),
            acc.pow_bounded_vartime(&exp, exp_bits).unwrap()
        );
    }

    #[test]
    fn test_pow_bounded_randomized_vartime() {
        let acc = setup_secp256k1(768);
        let ec = EquivalenceClass::try_from(acc.form).unwrap();

        // Basic case
        let exp = U768::random(&mut OsRng);
        let exp_bits = 755;
        let start = ScalingBase::new_vartime(ec, 193).unwrap();
        assert_eq!(
            acc.form.nupow_bounded_vartime(&exp, exp_bits).unwrap(),
            acc.pow_bounded_randomized_vartime_form(&exp, exp_bits, start)
                .unwrap()
        );

        // Exponent that is smaller than quarter
        let exp = U128::random(&mut OsRng);
        let exp_bits = 126;
        let start = ScalingBase::new_vartime(ec, 127).unwrap();
        assert_eq!(
            acc.form.nupow_bounded_vartime(&exp, exp_bits).unwrap(),
            acc.pow_bounded_randomized_vartime_form(&exp, exp_bits, start)
                .unwrap()
        );

        // Exponent that sits between quarter and half
        let exp = U256::random(&mut OsRng);
        let exp_bits = 200;
        let start = ScalingBase::new_vartime(ec, 193).unwrap();
        assert_eq!(
            acc.form.nupow_bounded_vartime(&exp, exp_bits).unwrap(),
            acc.pow_bounded_randomized_vartime_form(&exp, exp_bits, start)
                .unwrap()
        );

        // Exponent that sits between half and 3*quarter
        let exp = U512::random(&mut OsRng);
        let exp_bits = 500;
        let start = ScalingBase::new_vartime(ec, 193).unwrap();
        assert_eq!(
            acc.form.nupow_bounded_vartime(&exp, exp_bits).unwrap(),
            acc.pow_bounded_randomized_vartime_form(&exp, exp_bits, start)
                .unwrap()
        );

        // Exponent that sits between 3*quarter and full
        let exp = U768::random(&mut OsRng);
        let exp_bits = 715;
        let start = ScalingBase::new_vartime(ec, 193).unwrap();
        assert_eq!(
            acc.form.nupow_bounded_vartime(&exp, exp_bits).unwrap(),
            acc.pow_bounded_randomized_vartime_form(&exp, exp_bits, start)
                .unwrap()
        );

        // Exponent that is greater than full
        let exp = U1024::random(&mut OsRng);
        let exp_bits = 1000;
        let start = ScalingBase::new_vartime(ec, 425).unwrap();
        assert_eq!(
            acc.form.nupow_bounded_vartime(&exp, exp_bits).unwrap(),
            acc.pow_bounded_randomized_vartime_form(&exp, exp_bits, start)
                .unwrap()
        );
    }

    #[test]
    fn test_get_bounded_exponent_encoding_size() {
        let acc = setup_secp256k1(768);

        // Basic case
        assert_eq!(acc.get_bounded_exponent_encoding_size(755), 193);

        // Exponent that is smaller than quarter
        assert_eq!(acc.get_bounded_exponent_encoding_size(126), 127);

        // Exponent that sits between quarter and half
        assert_eq!(acc.get_bounded_exponent_encoding_size(200), 193);

        // Exponent that sits between half and 3*quarter
        assert_eq!(acc.get_bounded_exponent_encoding_size(500), 193);

        // Exponent that sits between 3*quarter and full
        assert_eq!(acc.get_bounded_exponent_encoding_size(715), 193);

        // Exponent that is greater than full
        assert_eq!(acc.get_bounded_exponent_encoding_size(1000), 425);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{black_box, BenchmarkGroup, Criterion};
    use crypto_bigint::{
        Concat, Encoding, Gcd, Int, InvMod, NonZero, Random, Split, Uint, U1024, U2048, U256, U512,
    };
    use rand_core::OsRng;

    use crate::ibqf::accelerator::NupowAccelerator;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::EquivalenceClass;

    fn benchmark_encode<const HALF: usize, const LIMBS: usize, const DOUBLE: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        form: &EquivalenceClass<LIMBS>,
    ) where
        Int<HALF>: InvMod<Modulus = NonZero<Uint<HALF>>, Output = Uint<HALF>>,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>
            + Gcd<Output = Uint<HALF>>
            + InvMod<Modulus = Uint<HALF>, Output = Uint<HALF>>,

        Int<LIMBS>: Encoding,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,

        Int<DOUBLE>: Encoding,
        Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
    {
        let acc = NupowAccelerator::new_vartime(*form.representative(), 256).unwrap();
        let exp = U256::random(&mut OsRng);
        g.bench_function("encode (U256)", |b| {
            b.iter(|| acc.construct_exponentation_sequence_vartime(&exp, 256))
        });

        let acc = NupowAccelerator::new_vartime(*form.representative(), 512).unwrap();
        let exp = U512::random(&mut OsRng);
        g.bench_function("encode (U512)", |b| {
            b.iter(|| acc.construct_exponentation_sequence_vartime(&exp, 512))
        });

        let acc = NupowAccelerator::new_vartime(*form.representative(), 1024).unwrap();
        let exp = U1024::random(&mut OsRng);
        g.bench_function("encode (U1024)", |b| {
            b.iter(|| acc.construct_exponentation_sequence_vartime(&exp, 1024))
        });

        let acc = NupowAccelerator::new_vartime(*form.representative(), 2048).unwrap();
        let exp = U2048::random(&mut OsRng);
        g.bench_function("encode (U2048)", |b| {
            b.iter(|| acc.construct_exponentation_sequence_vartime(&exp, 1024))
        });
    }

    fn benchmark_nupow<const HALF: usize, const LIMBS: usize, const DOUBLE_LIMBS: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        mut form: EquivalenceClass<LIMBS>,
    ) where
        Int<HALF>: InvMod<Modulus = NonZero<Uint<HALF>>, Output = Uint<HALF>>,
        Uint<HALF>: Concat<Output = Uint<LIMBS>>
            + Gcd<Output = Uint<HALF>>
            + InvMod<Modulus = Uint<HALF>, Output = Uint<HALF>>,

        Int<LIMBS>: Encoding + InvMod<Modulus = NonZero<Uint<LIMBS>>, Output = Uint<LIMBS>>,
        Uint<LIMBS>: Concat<Output = Uint<DOUBLE_LIMBS>>
            + Gcd<Output = Uint<LIMBS>>
            + Split<Output = Uint<HALF>>,

        Int<DOUBLE_LIMBS>: Encoding,
        Uint<DOUBLE_LIMBS>: Split<Output = Uint<LIMBS>>,
    {
        form.accelerate_vartime(256).unwrap();
        let exp = U256::random(&mut OsRng);
        g.bench_function("nupow U256 (ct)", |b| b.iter(|| black_box(form.pow(&exp))));
        g.bench_function("nupow U256 (vt)", |b| {
            b.iter(|| black_box(form.pow_vartime(&exp)))
        });

        form.accelerate_vartime(512).unwrap();
        let exp = U512::random(&mut OsRng);
        g.bench_function("nupow U512 (vt)", |b| {
            b.iter(|| black_box(form.pow_vartime(&exp)))
        });

        form.accelerate_vartime(1024).unwrap();
        let exp = U1024::random(&mut OsRng);
        g.bench_function("nupow U1024 (vt)", |b| {
            b.iter(|| black_box(form.pow_vartime(&exp)))
        });

        form.accelerate_vartime(2048).unwrap();
        let exp = U2048::random(&mut OsRng);
        g.bench_function("nupow U2048 (vt)", |b| {
            b.iter(|| black_box(form.pow_vartime(&exp)))
        });
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let mut group = _c.benchmark_group("accelerator/secp256k1");
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let ec = setup_parameters.h;

        benchmark_encode(&mut group, &ec);
        benchmark_nupow(&mut group, ec);
    }
}
