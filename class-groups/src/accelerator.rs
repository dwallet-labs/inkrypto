// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::ops::Shr;

use crate::helpers::lookup::ConstantTimeLookup;
use crate::helpers::CtMinMax;
use crate::ibqf::Ibqf;
use crate::{EquivalenceClass, Error};
use crypto_bigint::subtle::ConstantTimeEq;
use crypto_bigint::{Concat, ConstantTimeSelect, Encoding, Int, Limb, Split, Uint};
use serde::{Deserialize, Serialize};

/// Struct capable of accelerating the [Ibqf::nupow] operation.
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultiFoldNupowAccelerator<const LIMBS: usize>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    form: EquivalenceClass<LIMBS>,
    table: Vec<Ibqf<LIMBS>>,
    pub(crate) target_bits: u32,
    pub(crate) nr_lanes: u32,
    lane_length: u32,
}

type BoundedUint<const LIMBS: usize> = (Uint<LIMBS>, u32);

impl<const HALF: usize, const LIMBS: usize, const DOUBLE: usize> MultiFoldNupowAccelerator<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<HALF>: Concat<Output = Uint<LIMBS>>,
    Uint<LIMBS>: Encoding + Concat<Output = Uint<DOUBLE>> + Split<Output = Uint<HALF>>,
    Uint<DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    /// Construct a new [MultiFoldNupowAccelerator] for `form` that targets exponents of
    /// `max_exponent_bit_size`. This accelerator "folds" such an exponent into `folding_degree`
    /// lanes of size `lane_length := ⌈max_exponent_bit_size / nr_lanes⌉`.
    ///
    /// Executes in variable time w.r.t. all input parameters.
    pub(crate) fn new_vartime(
        form: EquivalenceClass<LIMBS>,
        folding_degree: u32,
        max_exponent_bit_size: u32,
    ) -> Result<Self, Error> {
        if folding_degree == 0 {
            return Err(Error::InvalidParameters);
        }

        let nr_lanes = folding_degree;
        let lane_length = max_exponent_bit_size.div_ceil(nr_lanes);
        let target_bits = lane_length
            .checked_mul(nr_lanes)
            .ok_or(Error::InternalError)?;

        let table_size = 1usize.checked_shl(nr_lanes).ok_or(Error::InternalError)?;
        let mut table = Vec::with_capacity(table_size);
        table.resize(table_size, *form.representative());

        table[0] = *form.unit().representative();
        let (mut b, mut pow2) = (1, 2);
        for _ in 0..nr_lanes - 1 {
            table[pow2] = table[pow2 / 2].nupow2k_vartime(lane_length);
            for k in 0..b {
                table[pow2 + k + 1] = table[pow2].nucomp_vartime(table[k + 1]);
            }
            b += pow2;
            pow2 *= 2;
        }

        Ok(Self {
            form,
            table,
            target_bits,
            nr_lanes,
            lane_length,
        })
    }

    /// Return the form being accelerated.
    pub(crate) fn form(&self) -> &EquivalenceClass<LIMBS> {
        &self.form
    }

    /// Encode `exponent` such that it can be used by this accelerator to exponentiate.
    pub(crate) fn encode_exponent<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> MultiFoldEncodedExponent<EXPONENT_LIMBS> {
        self.encode_bounded_exponent(exponent, Uint::<EXPONENT_LIMBS>::BITS)
    }

    /// Encode `exponent` such that it can be used by this accelerator to exponentiate.
    ///
    /// Executes in variable time w.r.t. `exponent`.
    pub(crate) fn encode_exponent_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
    ) -> MultiFoldEncodedExponent<EXPONENT_LIMBS> {
        self.encode_bounded_exponent(exponent, exponent.bits_vartime())
    }

    /// Encode the `exponent_bits` least significant bits of `exponent` such that it can be used
    /// by this accelerator to exponentiate.
    pub(crate) fn encode_bounded_exponent<const EXPONENT_LIMBS: usize>(
        &self,
        exponent: &Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> MultiFoldEncodedExponent<EXPONENT_LIMBS> {
        let bounded_exponent = bound(exponent, exponent_bits);

        let ((exponent, exponent_bits), overflow) = self.split_off_overflow(bounded_exponent);

        let lanes = self.exponent_to_lanes(exponent, exponent_bits);
        let nr_active_lanes = lanes.len();

        let lookup_indices = self.lanes_to_indices(lanes);

        MultiFoldEncodedExponent::<EXPONENT_LIMBS> {
            indices: lookup_indices,
            nr_active_lanes,
            overflow,
        }
    }

    /// Truncate `bounded_exponent` to `self.target_bits`, splitting off any excess as overflow.
    fn split_off_overflow<const EXPONENT_LIMBS: usize>(
        &self,
        bounded_exponent: BoundedUint<EXPONENT_LIMBS>,
    ) -> (BoundedUint<EXPONENT_LIMBS>, BoundedUint<EXPONENT_LIMBS>) {
        let (exponent, exponent_bits) = bounded_exponent;

        let overflow_size = exponent_bits.saturating_sub(self.target_bits);
        let overflow = exponent.wrapping_shr(exponent_bits.saturating_sub(overflow_size));

        let exponent_bits = u32::ct_min(&exponent_bits, &self.target_bits);
        let exponent = bound(&exponent, exponent_bits);

        (exponent, (overflow, overflow_size))
    }

    /// Convert an exponent of size `exponent_bits` into "lanes"; sections of size `self.lane_length`.
    fn exponent_to_lanes<const EXPONENT_LIMBS: usize>(
        &self,
        mut exponent: Uint<EXPONENT_LIMBS>,
        exponent_bits: u32,
    ) -> Vec<Uint<EXPONENT_LIMBS>> {
        exponent = mask(exponent, exponent_bits);
        let nr_active_lanes = exponent_bits.div_ceil(self.lane_length);

        let lane_mask = construct_mask::<EXPONENT_LIMBS>(self.lane_length);
        let mut lanes = Vec::new();
        for _ in 0..nr_active_lanes {
            lanes.push(exponent.bitand(&lane_mask));
            exponent = exponent.wrapping_shr_vartime(self.lane_length);
        }

        lanes
    }

    /// Convert "lanes" to the lookup indices in `self.table`.
    fn lanes_to_indices<const EXPONENT_LIMBS: usize>(
        &self,
        mut lanes: Vec<Uint<EXPONENT_LIMBS>>,
    ) -> Vec<usize> {
        let mut encoding_indices = Vec::new();
        for _ in 0..self.lane_length {
            let lookup_index = lanes
                .iter_mut()
                .rev()
                .map(|lane| {
                    let lsb = lane.as_limbs()[0].bitand(Limb::ONE).ct_eq(&Limb::ONE);

                    // safe to vartime; is vartime w.r.t. the shift only, which is constant
                    *lane = lane.shr_vartime(1);

                    lsb
                })
                .fold(0u64, |mut acc, elt| {
                    acc <<= 1;
                    u64::ct_select(&acc, &(acc | 1), elt)
                });

            encoding_indices.push(lookup_index as usize);
        }

        encoding_indices
    }

    /// Compute `self.form^exp` with `exp` the exponent represented by `encoded_exponent`.
    pub(crate) fn pow<const EXPONENT_LIMBS: usize>(
        &self,
        encoded_exponent: &MultiFoldEncodedExponent<EXPONENT_LIMBS>,
    ) -> Ibqf<LIMBS> {
        let MultiFoldEncodedExponent::<EXPONENT_LIMBS> {
            indices,
            nr_active_lanes,
            overflow,
        } = encoded_exponent;

        let (overflow, overflow_bits) = overflow;
        let mut res = self
            .overflow_pow_starter()
            .nupow_bounded(overflow, *overflow_bits);

        let max_index = usize::MAX.shr((usize::BITS as usize) - nr_active_lanes);
        for idx in indices.iter().rev() {
            res = res.nudupl();
            let elt = self
                .table
                .ct_bounded_lookup(*idx, max_index)
                .expect("valid index");
            res = res.nucomp(elt);
        }

        res
    }

    /// Compute `self.form^exp` with `exp` the exponent represented by `encoded_exponent`.
    ///
    /// ### Randomized
    /// Assumes `self.form` to be a random form, thus permitting the use of `*_randomized` functions
    /// during exponentiation.
    pub(crate) fn pow_randomized<const EXPONENT_LIMBS: usize>(
        &self,
        encoded_exponent: &MultiFoldEncodedExponent<EXPONENT_LIMBS>,
    ) -> Ibqf<LIMBS> {
        let MultiFoldEncodedExponent::<EXPONENT_LIMBS> {
            indices,
            nr_active_lanes,
            overflow,
        } = encoded_exponent;

        let (overflow, overflow_bits) = overflow;
        let mut res = self
            .overflow_pow_starter()
            .nupow_bounded_randomized(overflow, *overflow_bits);

        let max_index = usize::MAX.shr((usize::BITS as usize) - nr_active_lanes);
        for idx in indices.iter().rev() {
            res = res.nudupl_randomized();
            let elt = self
                .table
                .ct_bounded_lookup(*idx, max_index)
                .expect("valid index");

            // Bypass the case that idx = 0; this index points at the unit element, which can cause
            // trouble in the reduction phase.
            // First, we choose `elt` to be non-unit (we arbitrarily chose `self.form` here),
            // Then, we select the (randomized) composition of `res` and `elt` unless `idx` is zero,
            // in which case we simply select `res` as composition with unit returns the original value.
            let elt = Ibqf::ct_select(&elt, self.form.representative(), idx.ct_eq(&0));
            res = Ibqf::ct_select(&res.nucomp_randomized_pair(elt), &res, idx.ct_eq(&0))
        }

        res
    }

    /// Compute `self.form^exp` with `exp` the exponent represented by `encoded_exponent`.
    ///
    /// Executes in variable time w.r.t. `encoded_exponent`.
    pub(crate) fn pow_vartime<const EXPONENT_LIMBS: usize>(
        &self,
        encoded_exponent: &MultiFoldEncodedExponent<EXPONENT_LIMBS>,
    ) -> Ibqf<LIMBS> {
        let MultiFoldEncodedExponent {
            indices, overflow, ..
        } = encoded_exponent;

        let (overflow, overflow_bits) = overflow;
        let mut res = self
            .overflow_pow_starter()
            .nupow_bounded_vartime(overflow, *overflow_bits);

        for idx in indices.iter().rev() {
            res = res.nudupl_vartime();
            if *idx != 0 {
                let elt = self.table.get(*idx).expect("valid index");
                res = res.nucomp_vartime(*elt);
            }
        }
        res
    }

    /// The 'starter' element for exponentiating the overflow ahead of the encoded part of the
    /// exponent.
    ///
    /// ### The math
    /// Suppose we wish to compute `form^exp`, where the bit size of `exp` exceeds `target_bits`.
    /// This accelerator decomposes `exp` as `2^target_bits · overflow + tail`, of which we can only
    /// accelerate the computation of `form^tail`.
    ///
    /// However, we can pass in a `base` during the computation of `form^tail` and instead compute
    /// `base^{2^lane_length} · form^tail`. Since `target_bits = lane_length · nr_lanes`, this
    /// evaluates to `form^exp` when `base = starter^overflow` with
    /// `starter = form^{2^{target_bits-lane_length}}`.
    ///
    /// This `starter` element is located at index `self.table.len()/2` in the lookup table.
    fn overflow_pow_starter(&self) -> Ibqf<LIMBS> {
        self.table[self.table.len() / 2]
    }
}

/// Return a copy of `val` masked to its `bits` least significant bits.
fn bound<const LIMBS: usize>(val: &Uint<LIMBS>, length: u32) -> BoundedUint<LIMBS> {
    let effective_length = u32::ct_min(&Uint::<LIMBS>::BITS, &length);
    let bounded = val.bitand(&construct_mask(effective_length));
    (bounded, effective_length)
}

/// Return a copy of `val` masked to its `bits` least significant bits.
fn mask<const LIMBS: usize>(val: Uint<LIMBS>, length: u32) -> Uint<LIMBS> {
    val.bitand(&construct_mask(length))
}

/// Construct a [Uint] for which the `min(length, Uint::<LIMBS>::BITS` least significant bits are
/// set to `1`, while all other bits are zero.
fn construct_mask<const LIMBS: usize>(length: u32) -> Uint<LIMBS> {
    Uint::<LIMBS>::MAX.wrapping_shr_vartime(Uint::<LIMBS>::BITS.saturating_sub(length))
}

/// Encoding of an exponent that can be used by the [MultiFoldNupowAccelerator].
pub(crate) struct MultiFoldEncodedExponent<const EXPONENT_LIMBS: usize> {
    pub(crate) indices: Vec<usize>,
    pub(crate) nr_active_lanes: usize,
    pub(crate) overflow: BoundedUint<EXPONENT_LIMBS>,
}

impl<const LIMBS: usize> From<&MultiFoldNupowAccelerator<LIMBS>> for EquivalenceClass<LIMBS>
where
    Int<LIMBS>: Encoding,
    Uint<LIMBS>: Encoding,
{
    fn from(value: &MultiFoldNupowAccelerator<LIMBS>) -> Self {
        value.form
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{Encoding, Int, U1024, U128, U2048, U512, U64};

    use crate::accelerator::{construct_mask, MultiFoldNupowAccelerator};
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::{EquivalenceClass, Error, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS};

    #[test]
    fn test_construct_mask() {
        assert_eq!(construct_mask::<{ U64::LIMBS }>(0), U64::ZERO);
        assert_eq!(construct_mask::<{ U64::LIMBS }>(1), U64::ONE);
        assert_eq!(construct_mask::<{ U64::LIMBS }>(17), U64::from(131071u64));
        assert_eq!(construct_mask::<{ U64::LIMBS }>(64), U64::MAX);
    }

    fn get_form() -> EquivalenceClass<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        get_setup_parameters_secp256k1_112_bits_deterministic().h
    }

    const EXPONENT: U1024 = U1024::from_be_hex(concat![
        "E17583BAD53857D66AA430D7C8C8BCA81FF432ACF8ACF8A01663DA6E3D4B2E18",
        "CEE6A92CDD9AE25E087093F4AC018A05F369F7F5F569888CA6A5215169F30123",
        "2A08FDB5FA322F66742ECF3996726857E08FE4F1C2B25C122DB419F3C85F9629",
        "8EFE4B9FC896F3E5271B2B628553CA287CA0E611A88B8C0604E6AD0D230B0CE0"
    ]);

    type Secp256k1Accelerator =
        MultiFoldNupowAccelerator<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;

    fn eight_lane_accelerator(target_bit_size: u32) -> Result<Secp256k1Accelerator, Error> {
        MultiFoldNupowAccelerator::new_vartime(get_form(), 8, target_bit_size)
    }

    fn nine_lane_accelerator(target_bit_size: u32) -> Result<Secp256k1Accelerator, Error> {
        MultiFoldNupowAccelerator::new_vartime(get_form(), 9, target_bit_size)
    }

    #[test]
    fn test_new_simple() {
        let target_bit_size = 1024;

        let acc = eight_lane_accelerator(target_bit_size);
        assert!(acc.is_ok());
        let acc = acc.unwrap();

        assert_eq!(acc.target_bits, target_bit_size);
        assert_eq!(acc.nr_lanes, 8);
        assert_eq!(acc.lane_length, target_bit_size / 8);
    }

    #[test]
    fn test_new_with_non_power_of_two_nr_lanes() {
        let target_bit_size = 1024;

        let acc = nine_lane_accelerator(target_bit_size);
        assert!(acc.is_ok());
        let acc = acc.unwrap();

        assert_eq!(acc.target_bits, 1026);
        assert_eq!(acc.nr_lanes, 9);
        assert_eq!(acc.lane_length, 114);
    }

    #[test]
    fn test_new_target_bit_overflow() {
        let target_bit_size = 4294967295u32;
        let acc = nine_lane_accelerator(target_bit_size);
        assert!(acc.is_err());
    }

    fn test_table(acc: Secp256k1Accelerator)
    where
        Int<{ U128::LIMBS }>: Encoding,
    {
        let table_size = 1 << acc.nr_lanes;
        assert_eq!(acc.table.len(), table_size);

        for idx in 0..table_size {
            let elt = acc.table[idx];
            let mut exponent = U2048::ZERO;
            let mut bit_string = idx;
            for i in 0..acc.nr_lanes {
                let bit = bit_string & 1;
                exponent ^= U2048::from(bit as u64).shl_vartime(i * acc.lane_length);
                bit_string >>= 1;
            }

            assert_eq!(
                *get_form().pow_vartime(&exponent).representative(),
                elt,
                "{idx}"
            );
        }
    }

    #[test]
    fn test_new_constructs_proper_table() {
        let target_bit_size = 1024u32;
        let acc = eight_lane_accelerator(target_bit_size).unwrap();
        test_table(acc);
    }

    #[test]
    fn test_new_constructs_proper_table_with_non_power_of_two_nr_lanes() {
        let target_bit_size = 81u32;
        let acc = nine_lane_accelerator(target_bit_size).unwrap();
        test_table(acc);
    }

    #[test]
    fn test_encode_exponent_basic() {
        let acc = eight_lane_accelerator(1024).unwrap();

        let target_indices = Vec::from([
            60, 24, 40, 198, 72, 151, 9, 129, 16, 102, 197, 235, 132, 200, 10, 166, 119, 95, 4,
            197, 30, 24, 222, 144, 83, 9, 106, 244, 72, 113, 148, 174, 157, 198, 225, 73, 188, 110,
            246, 164, 63, 106, 9, 79, 228, 147, 72, 105, 82, 75, 157, 10, 38, 253, 97, 149, 6, 210,
            95, 164, 72, 158, 136, 16, 2, 173, 187, 48, 164, 74, 170, 210, 138, 170, 141, 93, 198,
            106, 230, 115, 17, 47, 66, 241, 174, 220, 16, 103, 176, 12, 176, 107, 248, 89, 254,
            255, 31, 130, 122, 226, 159, 252, 20, 222, 186, 211, 29, 42, 88, 125, 31, 189, 148, 38,
            230, 30, 194, 243, 242, 103, 208, 122, 99, 107, 81, 157, 181, 182,
        ]);

        let encoding = acc.encode_exponent(&EXPONENT);
        assert_eq!(encoding.nr_active_lanes, 8);
        assert_eq!(encoding.indices, target_indices);
    }

    #[test]
    fn test_encode_exponent_with_non_power_of_two_nr_lanes() {
        let acc = nine_lane_accelerator(1024).unwrap();

        let target_indices = Vec::from([
            116, 24, 16, 510, 132, 183, 257, 389, 234, 122, 79, 387, 18, 180, 396, 332, 397, 447,
            388, 151, 280, 116, 372, 478, 217, 43, 88, 172, 446, 347, 162, 22, 49, 76, 371, 113,
            50, 372, 54, 472, 111, 392, 41, 381, 108, 423, 492, 231, 236, 401, 357, 114, 418, 185,
            355, 463, 280, 498, 261, 46, 356, 148, 426, 234, 156, 199, 39, 364, 428, 480, 106, 134,
            310, 216, 329, 195, 272, 88, 478, 505, 23, 293, 72, 351, 398, 314, 182, 455, 472, 396,
            130, 139, 154, 207, 208, 331, 311, 96, 258, 32, 329, 498, 268, 204, 316, 131, 117, 40,
            234, 439, 483, 507, 78, 214,
        ]);

        let encoding = acc.encode_exponent(&EXPONENT);
        assert_eq!(encoding.nr_active_lanes, 9);
        assert_eq!(encoding.indices, target_indices);
    }

    #[test]
    fn test_encode_bounded_exponent_basic() {
        let acc = eight_lane_accelerator(1024).unwrap();

        let target_indices = Vec::from([
            28, 24, 8, 6, 8, 23, 9, 1, 16, 6, 5, 11, 4, 8, 10, 6, 23, 31, 4, 5, 30, 24, 30, 16, 19,
            9, 10, 20, 8, 17, 20, 14, 29, 6, 1, 9, 28, 14, 22, 4, 31, 10, 9, 15, 4, 19, 8, 9, 18,
            11, 29, 10, 6, 29, 1, 21, 6, 18, 31, 4, 8, 30, 8, 16, 2, 13, 11, 0, 4, 10, 10, 2, 10,
            10, 13, 13, 6, 10, 6, 3, 1, 15, 2, 1, 14, 12, 0, 7, 0, 12, 0, 11, 8, 9, 14, 15, 15, 2,
            10, 2, 15, 12, 4, 14, 10, 3, 13, 10, 8, 13, 15, 13, 4, 6, 6, 14, 2, 3, 2, 7, 0, 10, 3,
            11, 1, 13, 5, 6,
        ]);

        let encoding = acc.encode_bounded_exponent(&EXPONENT, 576);
        assert_eq!(encoding.nr_active_lanes, 5);
        assert_eq!(encoding.indices, target_indices);
        let max_index = (1 << encoding.nr_active_lanes) as usize;
        assert!(target_indices.iter().all(|e| *e < max_index));
    }

    #[test]
    fn test_encode_bounded_exponent_zero_length() {
        let acc = eight_lane_accelerator(1024).unwrap();

        let encoding = acc.encode_bounded_exponent(&EXPONENT, 0);
        assert_eq!(encoding.nr_active_lanes, 0);
        assert_eq!(encoding.indices, Vec::from([0; 128]));
    }

    #[test]
    fn test_encode_bounded_exponent_with_non_power_of_two_nr_lanes() {
        let acc = nine_lane_accelerator(1024).unwrap();

        let target_indices = Vec::from([
            4, 8, 0, 14, 4, 7, 1, 5, 10, 10, 15, 3, 2, 4, 12, 12, 13, 15, 4, 7, 8, 4, 4, 14, 9, 11,
            8, 12, 14, 11, 2, 6, 1, 12, 3, 1, 2, 4, 6, 8, 15, 8, 9, 13, 12, 7, 12, 7, 12, 1, 5, 2,
            2, 9, 3, 15, 8, 2, 5, 14, 4, 4, 10, 10, 12, 7, 7, 12, 12, 0, 10, 6, 6, 8, 9, 3, 0, 8,
            14, 9, 7, 5, 8, 15, 14, 10, 6, 7, 8, 12, 2, 11, 10, 15, 0, 11, 7, 0, 2, 0, 9, 2, 12,
            12, 12, 3, 5, 8, 10, 7, 3, 3, 6, 6,
        ]);

        let encoding = acc.encode_bounded_exponent(&EXPONENT, 453);
        assert_eq!(encoding.nr_active_lanes, 4);
        assert_eq!(encoding.indices, target_indices);
        let max_index = (1 << encoding.nr_active_lanes) as usize;
        assert!(target_indices.iter().all(|e| *e < max_index));
    }

    #[test]
    fn test_encode_exponent_vartime_basic() {
        let acc = eight_lane_accelerator(1024).unwrap();
        let exp = EXPONENT.bitand(&U1024::MAX.shr_vartime(555));

        let target_indices = Vec::from([
            12, 8, 8, 6, 8, 7, 9, 1, 0, 6, 5, 11, 4, 8, 10, 6, 7, 15, 4, 5, 14, 8, 14, 0, 3, 9, 10,
            4, 8, 1, 4, 14, 13, 6, 1, 9, 12, 14, 6, 4, 15, 10, 9, 15, 4, 3, 8, 9, 2, 11, 13, 10, 6,
            13, 1, 5, 6, 2, 15, 4, 8, 14, 8, 0, 2, 13, 11, 0, 4, 10, 10, 2, 10, 10, 13, 13, 6, 10,
            6, 3, 1, 15, 2, 1, 14, 4, 0, 7, 0, 4, 0, 3, 0, 1, 6, 7, 7, 2, 2, 2, 7, 4, 4, 6, 2, 3,
            5, 2, 0, 5, 7, 5, 4, 6, 6, 6, 2, 3, 2, 7, 0, 2, 3, 3, 1, 5, 5, 6,
        ]);

        let encoding = acc.encode_exponent_vartime(&exp);
        assert_eq!(encoding.nr_active_lanes, 4);
        assert_eq!(encoding.indices, target_indices);
    }

    #[test]
    fn test_encode_exponent_vartime_with_uint_smaller_than_lane_length() {
        let acc = eight_lane_accelerator(1024).unwrap();
        let exp = U64::from_be_hex("abcdef0123456789");

        let target_indices = Vec::from([
            1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0,
            1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1,
            0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);

        let encoding = acc.encode_exponent_vartime(&exp);
        assert_eq!(encoding.nr_active_lanes, 1);
        assert_eq!(encoding.indices, target_indices);
    }

    #[test]
    fn test_encode_exponent_vartime_with_non_power_of_two_nr_lanes() {
        let acc = nine_lane_accelerator(1024).unwrap();
        let exp = EXPONENT.bitand(&U1024::MAX.shr_vartime(555));

        let target_indices = Vec::from([
            20, 24, 16, 30, 4, 23, 1, 5, 10, 26, 15, 3, 18, 4, 12, 12, 13, 15, 4, 7, 8, 4, 4, 14,
            9, 11, 8, 12, 14, 11, 2, 6, 1, 12, 3, 1, 2, 4, 6, 8, 15, 8, 9, 13, 12, 7, 12, 7, 12, 1,
            5, 2, 2, 9, 3, 15, 8, 2, 5, 14, 4, 4, 10, 10, 12, 7, 7, 12, 12, 0, 10, 6, 6, 8, 9, 3,
            0, 8, 14, 9, 7, 5, 8, 15, 14, 10, 6, 7, 8, 12, 2, 11, 10, 15, 0, 11, 7, 0, 2, 0, 9, 2,
            12, 12, 12, 3, 5, 8, 10, 7, 3, 11, 14, 6,
        ]);

        let encoding = acc.encode_exponent_vartime(&exp);
        assert_eq!(encoding.nr_active_lanes, 5);
        assert_eq!(encoding.indices, target_indices);
    }

    #[test]
    fn test_encode_exponent_exceeding_target_bits() {
        let acc = eight_lane_accelerator(512).unwrap();
        let encoding = acc.encode_exponent(&EXPONENT);

        let target_indices = Vec::from([
            88, 226, 202, 20, 96, 157, 201, 9, 136, 156, 179, 231, 56, 200, 108, 30, 23, 255, 24,
            19, 252, 224, 84, 42, 5, 225, 68, 154, 192, 131, 184, 254, 251, 28, 137, 73, 250, 244,
            52, 184, 221, 78, 227, 221, 144, 167, 234, 227, 36, 109, 121, 236, 28, 91, 9, 59, 20,
            140, 95, 154, 66, 246, 98, 40,
        ]);
        let target_leading_exponent = U512::from_be_hex(concat![
            "E17583BAD53857D66AA430D7C8C8BCA81FF432ACF8ACF8A01663DA6E3D4B2E18",
            "CEE6A92CDD9AE25E087093F4AC018A05F369F7F5F569888CA6A5215169F30123",
        ])
        .resize::<{ U1024::LIMBS }>();

        assert_eq!(encoding.nr_active_lanes, 8);
        assert_eq!(encoding.indices, target_indices);
        assert_eq!(encoding.overflow, (target_leading_exponent, 512));
    }

    fn test_pow(acc: Secp256k1Accelerator) {
        let encoding = acc.encode_exponent(&EXPONENT);
        let target = *get_form().pow_vartime(&EXPONENT).representative();
        assert_eq!(acc.pow(&encoding), target);
        assert_eq!(acc.pow_randomized(&encoding), target);
        assert_eq!(acc.pow_vartime(&encoding), target);
    }

    #[test]
    fn test_pow_basic() {
        let acc = eight_lane_accelerator(1024);
        test_pow(acc.unwrap());
    }

    #[test]
    fn test_pow_with_non_power_of_two_nr_lanes() {
        let acc = nine_lane_accelerator(1024);
        test_pow(acc.unwrap());
    }

    #[test]
    fn test_pow_not_all_lanes_used() {
        let acc = eight_lane_accelerator(1792);
        test_pow(acc.unwrap());
    }

    #[test]
    fn test_pow_with_non_power_of_two_nr_lanes_not_all_lanes_used() {
        let acc = nine_lane_accelerator(1792);

        test_pow(acc.unwrap());
    }

    #[test]
    fn test_pow_exponent_exceeding_target() {
        let acc = eight_lane_accelerator(748);
        test_pow(acc.unwrap());
    }

    #[test]
    fn test_pow_with_non_power_of_two_nr_lanes_exponent_exceeding_target() {
        let acc = nine_lane_accelerator(748);
        test_pow(acc.unwrap());
    }

    #[test]
    fn test_exponent_to_lanes() {
        let acc = eight_lane_accelerator(748).unwrap();

        // basic case
        let exponent_bits = 573u32;
        let target_lanes = Vec::from([
            U128::from_be_hex("00000000288B8C0604E6AD0D230B0CE0").resize(),
            U128::from_be_hex("000000001C6CAD8A154F28A1F2839846").resize(),
            U128::from_be_hex("0000000005F96298EFE4B9FC896F3E52").resize(),
            U128::from_be_hex("0000000023F93C70AC97048B6D067CF2").resize(),
            U128::from_be_hex("00000000322F66742ECF3996726857E0").resize(),
            U128::from_be_hex("00000000148545A7CC048CA823F6D7E8").resize(),
            U128::from_be_hex("0000000000000000000000000000006A").resize(),
        ]);

        let lanes: Vec<_> = acc.exponent_to_lanes(EXPONENT, exponent_bits);
        assert_eq!(
            lanes.len(),
            exponent_bits.div_ceil(acc.lane_length) as usize
        );
        assert_eq!(lanes, target_lanes);

        // exponent_bits == lane_width
        let exponent_bits = acc.lane_length;
        let target_lanes =
            Vec::from([U128::from_be_hex("00000000288B8C0604E6AD0D230B0CE0").resize()]);

        let lanes: Vec<_> = acc.exponent_to_lanes(EXPONENT, exponent_bits);
        assert_eq!(
            lanes.len(),
            exponent_bits.div_ceil(acc.lane_length) as usize
        );
        assert_eq!(lanes, target_lanes);

        // exponent_bits == lane_width * k
        let k = 3;
        let exponent_bits = acc.lane_length * k;
        let target_lanes = Vec::from([
            U128::from_be_hex("00000000288B8C0604E6AD0D230B0CE0").resize(),
            U128::from_be_hex("000000001C6CAD8A154F28A1F2839846").resize(),
            U128::from_be_hex("0000000005F96298EFE4B9FC896F3E52").resize(),
        ]);

        let lanes: Vec<_> = acc.exponent_to_lanes(EXPONENT, exponent_bits);
        assert_eq!(
            lanes.len(),
            exponent_bits.div_ceil(acc.lane_length) as usize
        );
        assert_eq!(lanes, target_lanes);

        // exponent_bits == acc.target_bits
        let exponent_bits = acc.target_bits;
        let target_lanes = Vec::from([
            U128::from_be_hex("00000000288B8C0604E6AD0D230B0CE0").resize(),
            U128::from_be_hex("000000001C6CAD8A154F28A1F2839846").resize(),
            U128::from_be_hex("0000000005F96298EFE4B9FC896F3E52").resize(),
            U128::from_be_hex("0000000023F93C70AC97048B6D067CF2").resize(),
            U128::from_be_hex("00000000322F66742ECF3996726857E0").resize(),
            U128::from_be_hex("00000000148545A7CC048CA823F6D7E8").resize(),
            U128::from_be_hex("0000000018A05F369F7F5F569888CA6A").resize(),
            U128::from_be_hex("000000002A4B3766B897821C24FD2B00").resize(),
        ]);

        let lanes: Vec<_> = acc.exponent_to_lanes(EXPONENT, exponent_bits);
        assert_eq!(
            lanes.len(),
            exponent_bits.div_ceil(acc.lane_length) as usize
        );
        assert_eq!(lanes, target_lanes);
    }

    #[test]
    fn test_overflow_pow_starter() {
        let acc = eight_lane_accelerator(748).unwrap();
        assert_eq!(
            acc.overflow_pow_starter(),
            *get_form()
                .pow_2k_vartime(acc.target_bits - acc.lane_length)
                .representative()
        );

        let acc = nine_lane_accelerator(748).unwrap();
        assert_eq!(
            acc.overflow_pow_starter(),
            *get_form()
                .pow_2k_vartime(acc.target_bits - acc.lane_length)
                .representative()
        );
    }

    #[test]
    fn test_pow_randomized_with_zero_idx() {
        let acc = eight_lane_accelerator(748).unwrap();
        let exp = U1024::from_be_hex(concat![
            "2000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001"
        ]);

        let encoding = acc.encode_exponent(&exp);
        let target = *get_form().pow_vartime(&exp).representative();
        assert_eq!(acc.pow_randomized(&encoding), target);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::hint::black_box;
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{BatchSize, BenchmarkGroup, BenchmarkId, Criterion};
    use crypto_bigint::{Random, Uint, U1024, U1280, U2048, U256, U448, U512, U704, U832};

    use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
    use group::OsCsRng;

    use crate::accelerator::MultiFoldNupowAccelerator;
    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::EquivalenceClass;

    fn bench<const EXPONENT_LIMBS: usize>(
        g: &mut BenchmarkGroup<WallTime>,
        form: EquivalenceClass<{ U2048::LIMBS }>,
        folding_degree: u32,
        target_bits: u32,
        exp_bits: u32,
        bench_new: bool,
    ) {
        if bench_new {
            g.bench_function(
                BenchmarkId::new(format!("new_vartime({folding_degree})"), target_bits),
                |b| {
                    b.iter(|| {
                        let acc = MultiFoldNupowAccelerator::<{ U2048::LIMBS }>::new_vartime(
                            form,
                            folding_degree,
                            target_bits,
                        )
                        .unwrap();

                        black_box(acc)
                    })
                },
            );
        }

        let acc = MultiFoldNupowAccelerator::<{ U2048::LIMBS }>::new_vartime(
            form,
            folding_degree,
            target_bits,
        )
        .unwrap();

        let mask = (Uint::<EXPONENT_LIMBS>::ONE.wrapping_shl(exp_bits))
            .wrapping_sub(&Uint::<EXPONENT_LIMBS>::ONE);

        g.bench_function(
            format!("pow({folding_degree}) ct/{target_bits}/{exp_bits}"),
            |b| {
                b.iter_batched(
                    || {
                        let exp = Uint::<EXPONENT_LIMBS>::random(&mut OsCsRng) & mask;
                        acc.encode_bounded_exponent(&exp, exp_bits)
                    },
                    |enc| {
                        let x = acc.pow(&enc);

                        black_box(x)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
        g.bench_function(
            format!("pow({folding_degree}) rt/{target_bits}/{exp_bits}"),
            |b| {
                b.iter_batched(
                    || {
                        let exp = Uint::<EXPONENT_LIMBS>::random(&mut OsCsRng) & mask;
                        acc.encode_bounded_exponent(&exp, exp_bits)
                    },
                    |enc| {
                        let x = acc.pow_randomized(&enc);

                        black_box(x)
                    },
                    BatchSize::SmallInput,
                )
            },
        );

        g.bench_function(
            format!("pow({folding_degree}) vt/{target_bits}/{exp_bits}"),
            |b| {
                b.iter_batched(
                    || {
                        let exp = Uint::<EXPONENT_LIMBS>::random(&mut OsCsRng) & mask;
                        acc.encode_bounded_exponent(&exp, exp_bits)
                    },
                    |enc| {
                        let x = acc.pow_vartime(&enc);

                        black_box(x)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let mut group = _c.benchmark_group("acc/k1");
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));
        group.sample_size(10);

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let form = setup_parameters.h;

        for folding_degree in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] {
            // Because of zk-proofs using larger randomizer over the integers, the target bits is `MAURER_RANDOMIZER_DIFF_BITS` bigger even when calculating the statement.
            // TODO: we can get rid of that bound too at least for the runtime not pre-accelerated ones below
            bench::<{ U256::LIMBS }>(&mut group, form, folding_degree, 256, 256, true);
            bench::<{ U448::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                256 + MAURER_RANDOMIZER_DIFF_BITS,
                256,
                true,
            );
            bench::<{ U448::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                256 + MAURER_RANDOMIZER_DIFF_BITS,
                256 + MAURER_RANDOMIZER_DIFF_BITS,
                false,
            );

            bench::<{ U512::LIMBS }>(&mut group, form, folding_degree, 512, 512, true);
            bench::<{ U704::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                512 + MAURER_RANDOMIZER_DIFF_BITS,
                512,
                true,
            );
            bench::<{ U704::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                512 + MAURER_RANDOMIZER_DIFF_BITS,
                512 + MAURER_RANDOMIZER_DIFF_BITS,
                false,
            );

            // pre-accelerated
            bench::<{ U832::LIMBS }>(&mut group, form, folding_degree, 829, 829, true);
            bench::<{ U1024::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                829 + MAURER_RANDOMIZER_DIFF_BITS,
                829,
                true,
            );
            bench::<{ U1024::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                829 + MAURER_RANDOMIZER_DIFF_BITS,
                829 + MAURER_RANDOMIZER_DIFF_BITS,
                false,
            );

            bench::<{ U1280::LIMBS }>(&mut group, form, folding_degree, 1086, 1086, true);
            bench::<{ U1280::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                1086 + MAURER_RANDOMIZER_DIFF_BITS,
                1086,
                true,
            );
            bench::<{ U1280::LIMBS }>(
                &mut group,
                form,
                folding_degree,
                1086 + MAURER_RANDOMIZER_DIFF_BITS,
                1086 + MAURER_RANDOMIZER_DIFF_BITS,
                false,
            );
        }

        group.finish()
    }
}
