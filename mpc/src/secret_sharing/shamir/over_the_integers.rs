// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(clippy::too_many_arguments)]

use std::collections::{HashMap, HashSet};
use std::iter;

use crypto_bigint::subtle::{Choice, CtOption};
use crypto_bigint::{Encoding, Int, Limb, NonZero, Uint, I64, U4096, U64};
use gcd::Gcd;
#[cfg(feature = "parallel")]
use rayon::iter::IntoParallelIterator;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use group::helpers::{FlatMapResults, TryCollectHashMap};
use group::{
    bounded_integers_group, bounded_natural_numbers_group, CsRng, GroupElement, KnownOrderScalar,
    LinearlyCombinable, PartyID, Samplable, Scale, StatisticalSecuritySizedNumber,
};

use crate::secret_sharing::shamir::Polynomial;
use crate::{Error, Result};

const NUM_CRYPTO_BIGINT_SIZES: usize = 29;
pub const CRYPTO_BIGINT_SIZES: [usize; NUM_CRYPTO_BIGINT_SIZES] = [
    64, 128, 192, 256, 320, 384, 448, 512, 576, 640, 704, 768, 832, 896, 960, 1024, 1280, 1536,
    1792, 2048, 3072, 3584, 4096, 4224, 4352, 6144, 8192, 16384, 32768,
];

pub const fn find_closest_crypto_bigint_size(bits: usize) -> usize {
    debug_assert!(bits <= CRYPTO_BIGINT_SIZES[NUM_CRYPTO_BIGINT_SIZES - 1]);

    let mut i = 0;
    let mut size = 0;

    while i < NUM_CRYPTO_BIGINT_SIZES {
        size = CRYPTO_BIGINT_SIZES[i];

        if bits <= size {
            break;
        }

        i += 1;
    }

    size
}

pub const fn const_log(n: u32) -> u32 {
    let mut power = 1;
    let mut counter = 0;

    while power < n {
        power *= 2;
        counter += 1;
    }

    counter
}

/// Computes the Stirling Numbers of the First Kind https://en.wikipedia.org/wiki/Stirling_numbers_of_the_first_kind,
/// using the following recursion formula:
/// $\left[{t \atop k}\right]=(t-1)\cdot \left[{t-1 \atop k}\right]+\left[{t-1 \atop k-1}\right]$
/// with the boundary condition
/// \left[{0 \atop 0}\right]=1,\left[{t \atop 0}\right]=\left[{0 \atop k}\right]=0.
///
/// This function computes the value using dynamic programming for efficiency reasons.
fn stirling<const LIMBS: usize>(t: u32, k: u32) -> Uint<LIMBS> {
    assert!(t >= k);

    let t = usize::try_from(t).unwrap();
    let k = usize::try_from(k).unwrap();
    let mut hint: Vec<_> = iter::repeat_n(vec![Uint::ZERO; t + 1], t + 1).collect();
    hint[0][0] = Uint::ONE;

    for i in 1..=t {
        for j in 1..=i {
            // Safe to convert back to `u32`, as the parameters were `u32` and `i`, `j` are smaller than them.
            hint[i][j] = Uint::from((i - 1) as u16) * hint[i - 1][j] + hint[i - 1][j - 1];
        }
    }

    hint[t][k]
}

/// The `k`th coefficient is sampled from $[0,2^\sigma B \frac{n!}{t!}\left[{t+1 \atop k+1}\right]]$.
pub fn secret_sharing_polynomial_coefficient_size_upper_bound(
    number_of_parties: u32,
    threshold: u32,
    coefficient_index: u32,
    secret_key_bits: u32,
) -> u32 {
    StatisticalSecuritySizedNumber::BITS
        + secret_key_bits
        + stirling::<FACTORIAL_LIMBS>(threshold + 1, coefficient_index + 1).bits_vartime()
        + (factorial_upper_bound(number_of_parties) - factorial_upper_bound(threshold))
}

/// Sampling the `k`th coefficient from $[0,\frac{n!}{t!}2^\sigma B \left[{t+1 \atop k+1}\right]]$
/// is secure and the shares are bounded by $2^\sigma B \binom{n+t}{t}\cdot n!$.
/// This is absolutely tight for the current setting, proof approach and set of indices.
pub const fn secret_key_share_size_upper_bound(
    number_of_parties: u32,
    threshold: u32,
    secret_key_bits: u32,
) -> u32 {
    let secret_key_share_size_upper_bound = StatisticalSecuritySizedNumber::BITS
        + secret_key_bits
        + (factorial_upper_bound(number_of_parties + threshold) - factorial_upper_bound(threshold));

    // Not part of the bound on a single share;
    // accounts for summing up `threshold` shamir shares in various protocols,
    // and a growing of log(n) bits for n reconfigurations which we bound n for 2^64 as it will never be exceeded.
    // An additional statistical security accounts for masking decryption key share in some reconfiguration protocols.
    secret_key_share_size_upper_bound
        + const_log(threshold)
        + U64::BITS
        + StatisticalSecuritySizedNumber::BITS
}

/// A bound on the intermediate values used for computation during an interpolation on the secret key shares.
pub const fn computation_decryption_key_shares_interpolation_upper_bound(
    number_of_parties: u32,
    threshold: u32,
    secret_key_bits: u32,
) -> u32 {
    secret_key_share_size_upper_bound(number_of_parties, threshold, secret_key_bits)
        + (2 * factorial_upper_bound(number_of_parties))
}

/// This bound is exact, i.e. can only be used for accurate `number_of_parties` and `threshold` (not for bounds on these.)
pub const fn adjusted_lagrange_coefficient_sized_number_upper_bound(
    number_of_parties: u32,
    threshold: u32,
) -> u32 {
    // An upper bound for:
    //  $ 2{\binom{n}{j}}\prod_{j\in [n] \setminus S} |j'-j| $ - (1) $\binom{n}{j}\leq 2^{n}$, (2) $\prod_{j\in [n] \setminus S} |j'-j| \leq n^{n-t+1}$
    // (1) See https://www.johndcook.com/blog/2008/11/10/bounds-on-binomial-coefficients/
    // (2) Trivial, can be improved to $(n+1)log_{2}(n+1)-tlog_{2}(t)-n+t+2$ - https://cs.stackexchange.com/questions/156973/what-is-the-lower-bound-of-n-factorial
    (number_of_parties - threshold + 1) * const_log(number_of_parties) + number_of_parties + 1
}

pub const MAX_PLAYERS: u32 = 128;
pub const MAX_THRESHOLD: u32 = 86;

const FACTORIAL_BITS: [u32; (MAX_PLAYERS + MAX_THRESHOLD) as usize] = [
    1, 2, 3, 5, 7, 10, 13, 16, 19, 22, 26, 29, 33, 37, 41, 45, 49, 53, 57, 62, 66, 70, 75, 80, 84,
    89, 94, 98, 103, 108, 113, 118, 123, 128, 133, 139, 144, 149, 154, 160, 165, 170, 176, 181,
    187, 192, 198, 203, 209, 215, 220, 226, 232, 238, 243, 249, 255, 261, 267, 273, 279, 285, 290,
    296, 303, 309, 315, 321, 327, 333, 339, 345, 351, 358, 364, 370, 376, 383, 389, 395, 402, 408,
    414, 421, 427, 434, 440, 447, 453, 459, 466, 473, 479, 486, 492, 499, 505, 512, 519, 525, 532,
    539, 545, 552, 559, 565, 572, 579, 586, 592, 599, 606, 613, 620, 627, 633, 640, 647, 654, 661,
    668, 675, 682, 689, 696, 703, 710, 717, 724, 731, 738, 745, 752, 759, 766, 773, 780, 787, 794,
    802, 809, 816, 823, 830, 837, 845, 852, 859, 866, 873, 881, 888, 895, 902, 910, 917, 924, 932,
    939, 946, 953, 961, 968, 976, 983, 990, 998, 1005, 1012, 1020, 1027, 1035, 1042, 1050, 1057,
    1065, 1072, 1079, 1087, 1094, 1102, 1109, 1117, 1124, 1132, 1140, 1147, 1155, 1162, 1170, 1177,
    1185, 1193, 1200, 1208, 1215, 1223, 1231, 1238, 1246, 1254, 1261, 1269, 1277, 1284, 1292, 1300,
    1307, 1315, 1323, 1330, 1338, 1346, 1354,
];

pub const fn factorial_upper_bound(number_of_parties: u32) -> u32 {
    // Try to get exact pre-computed value, otherwise return the non-optimal upper bound.
    if number_of_parties <= (MAX_PLAYERS + MAX_THRESHOLD) {
        FACTORIAL_BITS[(number_of_parties - 1) as usize]
    } else {
        // See https://math.stackexchange.com/questions/55709/how-to-prove-this-approximation-of-logarithm-of-factorial
        // This expands to $(n+1)log_{2}(n+1) - n$ when further bounding $\log2{e}$ to $1.4$.
        (number_of_parties + 1) * const_log(number_of_parties + 1) - ((number_of_parties * 7) / 5)
    }
}

pub const SECRET_KEY_SHARE_SIZE_UPPER_BOUND: u32 =
    secret_key_share_size_upper_bound(MAX_PLAYERS, MAX_THRESHOLD, U4096::BITS);
pub const ADJUSTED_LAGRANGE_COEFFICIENT_SIZE_UPPER_BOUND: u32 = {
    // This is a threshold-independent bound. Cannot use
    factorial_upper_bound(MAX_PLAYERS) + MAX_PLAYERS + 1
};

pub const SECRET_KEY_SHARE_LIMBS: usize =
    find_closest_crypto_bigint_size(SECRET_KEY_SHARE_SIZE_UPPER_BOUND as usize)
        / Limb::BITS as usize;

pub const COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_UPPER_BOUND: u32 =
    computation_decryption_key_shares_interpolation_upper_bound(
        MAX_PLAYERS,
        MAX_THRESHOLD,
        U4096::BITS,
    );
pub const COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_LIMBS: usize =
    find_closest_crypto_bigint_size(
        COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_UPPER_BOUND as usize,
    ) / Limb::BITS as usize;

pub const FACTORIAL_LIMBS: usize =
    find_closest_crypto_bigint_size(factorial_upper_bound(MAX_PLAYERS) as usize)
        / Limb::BITS as usize;

pub type SecretKeyShareSizedNumber = Uint<SECRET_KEY_SHARE_LIMBS>;
pub type SecretKeyShareSizedInteger = Int<SECRET_KEY_SHARE_LIMBS>;

pub type FactorialSizedNumber = Uint<FACTORIAL_LIMBS>;

pub type BinomialCoefficientSizedNumber =
    Uint<{ find_closest_crypto_bigint_size(MAX_PLAYERS as usize) / Limb::BITS as usize }>;

pub type AdjustedLagrangeCoefficientSizedNumber = Uint<
    {
        find_closest_crypto_bigint_size(ADJUSTED_LAGRANGE_COEFFICIENT_SIZE_UPPER_BOUND as usize)
            / Limb::BITS as usize
    },
>;

/// This struct holds precomputed values that are computationally expensive to compute,
/// used for operations of Shamir secret sharing over the integers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecomputedValues<ScalarValue> {
    // A precomputed mapping of the party-id $j$ to the binomial coefficient ${n\choose j}$.
    pub binomial_coefficients: HashMap<PartyID, BinomialCoefficientSizedNumber>,
    // The precomputed value $(n!^3)^{-1} mod(N)$ where $N$ is the order of the group.
    pub n_factorial_cubed_inverse: ScalarValue,
    // The precomputed value $n!^{-4} mod(q)$ where $q$ is the order of the group.
    pub n_factorial_quad_inverse: ScalarValue,
    // The precomputed value $n!$.
    pub n_factorial: FactorialSizedNumber,
}

impl<ScalarValue> PrecomputedValues<ScalarValue> {
    pub fn new<const SCALAR_LIMBS: usize, Scalar>(
        number_of_parties: PartyID,
        scalar_group_public_parameters: &Scalar::PublicParameters,
    ) -> crate::Result<Self>
    where
        Scalar: KnownOrderScalar<SCALAR_LIMBS, ValueExt = ScalarValue>,
        ScalarValue: From<Uint<SCALAR_LIMBS>>,
    {
        if u32::from(number_of_parties) > MAX_PLAYERS {
            return Err(crate::Error::InvalidParameters);
        }

        let binomial_coefficients = compute_binomial_coefficients(number_of_parties);

        let party_ids = (2..=number_of_parties)
            .map(|i| {
                Scalar::new(
                    Scalar::Value::from(Uint::<SCALAR_LIMBS>::from(i)),
                    scalar_group_public_parameters,
                )
            })
            .collect::<group::Result<Vec<_>>>()?;

        let multiplicative_neutral = Scalar::new(
            Scalar::Value::from(Uint::<SCALAR_LIMBS>::ONE),
            scalar_group_public_parameters,
        )?;

        let n_factorial = party_ids
            .into_iter()
            .fold(multiplicative_neutral, |acc, i| acc * i);

        let n_factorial_inverse = n_factorial
            .invert()
            .into_option()
            .ok_or(Error::InternalError)?;

        let n_factorial_cubed_inverse =
            (n_factorial_inverse * n_factorial_inverse * n_factorial_inverse).value();

        let n_factorial_quad_inverse =
            (n_factorial_inverse * n_factorial_inverse * n_factorial_inverse * n_factorial_inverse)
                .value();

        let n_factorial = factorial(number_of_parties);

        Ok(Self {
            binomial_coefficients,
            n_factorial_cubed_inverse,
            n_factorial_quad_inverse,
            n_factorial,
        })
    }
}

/// Compute $\delta = n! $
pub fn factorial(number_of_parties: PartyID) -> FactorialSizedNumber {
    // Can't overflow
    // The default case only happens if `number_of_parties == 1` or `number_of_parties == 0` in both cases result is 1.
    (2..=number_of_parties)
        .map(FactorialSizedNumber::from)
        .reduce(|a, b| a * b)
        .unwrap_or(Uint::ONE)
}

/// Compute the binomial coefficients by reducing the fractions ${n\choose j} = \frac{{n - j +
/// 1}\cdots n}{1\cdots j}$. This could be done once and for all for a given number of
/// participants `n`.
///
/// The binomial coefficient formula is symmetric, i.e. ${n\choose j} = {n\choose {n - j}}$.
/// This allows us the following optimization: instead of computing the coeffecients for all
/// parties, compute it only for the smallest half $1 <= j <= n/2$
pub fn compute_binomial_coefficients(
    number_of_parties: PartyID,
) -> HashMap<PartyID, BinomialCoefficientSizedNumber> {
    let mut binomial_coefficients: HashMap<PartyID, BinomialCoefficientSizedNumber> = (1
        ..=(number_of_parties / 2))
        .flat_map(|j| {
            let coefficient = compute_binomial_coefficient(j, number_of_parties);

            // Account for the coefficient's symmetric nature for the above-mentioned
            // optimization.
            if j == (number_of_parties - j) {
                vec![(j, coefficient)]
            } else {
                vec![(j, coefficient), (number_of_parties - j, coefficient)]
            }
        })
        .collect();

    binomial_coefficients.insert(number_of_parties, Uint::ONE);

    binomial_coefficients
}

// Compute the binomial coefficients by reducing the fractions ${n\choose j} = \frac{{n - j +
// 1}\cdots n}{1\cdots j}$.
fn compute_binomial_coefficient(j: PartyID, n: PartyID) -> BinomialCoefficientSizedNumber {
    let mut denominators: Vec<PartyID> = (2..=j).collect();

    let mut reduced_numerators: Vec<PartyID> = vec![];
    for numerator in (n - j + 1)..=n {
        if denominators.is_empty() {
            reduced_numerators.push(numerator);
        } else if numerator != 1 {
            let mut reduced_denominators: Vec<PartyID> = vec![];
            let mut reduced_numerator = numerator;

            for mut denominator in denominators {
                let gcd = reduced_numerator.gcd(denominator);

                if gcd != 1 {
                    reduced_numerator /= gcd;
                    denominator /= gcd;
                }

                if gcd != 1 || denominator != 1 {
                    reduced_denominators.push(denominator);
                }
            }

            if reduced_numerator != 1 {
                reduced_numerators.push(reduced_numerator);
            }

            denominators = reduced_denominators;
        }
    }

    // Can't overflow
    reduced_numerators
        .iter()
        .map(|x| Uint::from(*x))
        .reduce(|a, b| a * b)
        .unwrap_or(Uint::ONE)
}

/// This function optimizes the computation of the decryption share base by expecting a subset $\bar{S}$ for which it is likely the interpolation subset $S$ will be a subset of (i.e. $S\subset \bar{S}$.
pub fn generate_expected_decryption_share_base<GroupElement: group::GroupElement + Send + Sync>(
    decryption_share_base: &GroupElement,
    expected_decrypters: HashSet<PartyID>,
    party_id: PartyID,
    number_of_parties: PartyID,
) -> GroupElement {
    let mut parties: HashSet<PartyID> = (1..=number_of_parties).collect();
    parties.remove(&party_id);

    // $\Pi_{j\in [n]\setminus \{\bar{S}\cup \{i\}\}}|j-i|$.
    let expected_decryptors_factor = parties
        .difference(&expected_decrypters)
        .map(|&expected_non_decrypter_party_id| party_id.abs_diff(expected_non_decrypter_party_id))
        .fold(FactorialSizedNumber::ONE, |a, b| a * U64::from(b));

    decryption_share_base.scale_vartime(&expected_decryptors_factor)
}

/// A helper function for threshold decryption schemes that work over hidden-order groups and thus use Shamir's secret sharing over the integers.
/// Computes the decryption share and its base for every ciphertext: $(c^{n!}, c^{n!d_i})$
pub fn generate_decryption_shares<
    const SECRET_KEY_SHARE_LIMBS: usize,
    GroupElement: group::GroupElement + Send + Sync + Scale<Int<SECRET_KEY_SHARE_LIMBS>>,
>(
    decryption_key_share: Int<SECRET_KEY_SHARE_LIMBS>,
    decryption_share_bases: Vec<GroupElement>,
    threshold: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    binomial_coefficient: BinomialCoefficientSizedNumber,
    group_public_parameters: &GroupElement::PublicParameters,
    secret_key_bits: u32,
) -> (Vec<GroupElement>, Vec<GroupElement>) {
    #[cfg(not(feature = "parallel"))]
    let iter = decryption_share_bases.iter();
    #[cfg(feature = "parallel")]
    let iter = decryption_share_bases.par_iter();

    iter.map(|decryption_share_base| {
        generate_decryption_share(
            decryption_key_share,
            decryption_share_base,
            number_of_parties,
            threshold,
            n_factorial,
            binomial_coefficient,
            group_public_parameters,
            secret_key_bits,
        )
    })
    .unzip()
}

/// A helper function for threshold decryption schemes that work over hidden-order groups and thus use Shamir's secret sharing over the integers.
/// Computes the decryption share and its base for every ciphertext: $(c^{n!}, c^{n!d_i})$
pub fn generate_decryption_share<
    const SECRET_KEY_SHARE_LIMBS: usize,
    GroupElement: group::GroupElement + Send + Sync + Scale<Int<SECRET_KEY_SHARE_LIMBS>>,
>(
    decryption_key_share: Int<SECRET_KEY_SHARE_LIMBS>,
    decryption_share_base: &GroupElement,
    threshold: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    binomial_coefficient: BinomialCoefficientSizedNumber,
    group_public_parameters: &GroupElement::PublicParameters,
    secret_key_bits: u32,
) -> (GroupElement, GroupElement) {
    let decryption_share_base = decryption_share_base
        .scale_vartime(&n_factorial)
        .scale_vartime(&binomial_coefficient);

    // $ c_i = c^{n! \cdot {{n}\choose{j}} \cdot d_i} $
    let decryption_share = decryption_share_base.scale_randomized_bounded_accelerated(
        &decryption_key_share,
        group_public_parameters,
        secret_key_share_size_upper_bound(
            u32::from(number_of_parties),
            u32::from(threshold),
            secret_key_bits,
        ),
    );

    (decryption_share_base, decryption_share)
}

/// A helper function for threshold decryption schemes that work over hidden-order groups and thus use Shamir's secret sharing over the integers.
/// Computes the decryption share and its base for every ciphertext: $(c^{n!}, c^{n!d_i})$
/// Depending on the scheme there may be other constants in this exponentiation.
/// The generation of the decryption share is separated to the generation of the decryption share basis which consists of operations on the ciphertexts which do not involve the secret key and operations which do depend on it.
/// Security Note: While it seems that the order of these functions could have been reversed there is a non-trivial interaction between the simulation and vartime computations.
/// Thus always do the public operations first in vartime and then the operation using the key in constant time.
pub fn generate_decryption_share_semi_honest<
    const SECRET_KEY_SHARE_LIMBS: usize,
    GroupElement: group::GroupElement + Send + Sync + Scale<Int<SECRET_KEY_SHARE_LIMBS>>,
    DecryptionShare: Default + From<GroupElement>,
>(
    decryption_key_share: Int<SECRET_KEY_SHARE_LIMBS>,
    decryption_share_base: &GroupElement,
    expected_decrypters: HashSet<PartyID>,
    party_id: PartyID,
    threshold: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    binomial_coefficients: &HashMap<PartyID, BinomialCoefficientSizedNumber>,
    group_public_parameters: &GroupElement::PublicParameters,
    secret_key_bits: u32,
) -> CtOption<DecryptionShare> {
    if !binomial_coefficients.contains_key(&party_id) {
        // This is a public check, so no need for constant time logic here; just return a None.
        return CtOption::new(
            DecryptionShare::from(*decryption_share_base),
            Choice::from(0u8),
        );
    }

    // Safe to unwrap due to sanity check.
    let binomial_coefficient = *binomial_coefficients.get(&party_id).unwrap();

    let decryption_share_base = generate_expected_decryption_share_base(
        decryption_share_base,
        expected_decrypters,
        party_id,
        number_of_parties,
    );

    let (_, decryption_share) = generate_decryption_share(
        decryption_key_share,
        &decryption_share_base,
        threshold,
        number_of_parties,
        n_factorial,
        binomial_coefficient,
        group_public_parameters,
        secret_key_bits,
    );

    CtOption::new(DecryptionShare::from(decryption_share), Choice::from(1u8))
}

/// This function takes a subset of t decryption shares
/// and interpolates the plaintext (for interpolation point `i = 0`, otherwise it interpolates the `i`th decryption share).
pub fn interpolate_decryption_shares<GroupElement: group::GroupElement + Send + Sync>(
    decryption_shares: HashMap<PartyID, Vec<GroupElement>>,
    expected_decrypters: HashSet<PartyID>,
    interpolation_point: PartyID,
    threshold: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    batch_size: usize,
) -> Result<(bool, Vec<GroupElement>)> {
    // Filter out invalid decryption shares.
    let decryption_shares: HashMap<_, _> = decryption_shares
        .into_iter()
        .filter(|(_, decryption_shares)| decryption_shares.len() == batch_size)
        .collect();

    if decryption_shares.len() < usize::from(threshold) {
        return Err(Error::InvalidParameters);
    };

    let decrypters: HashSet<_> = decryption_shares.keys().copied().collect();
    let available_expected_decrypters: HashSet<_> = decrypters
        .intersection(&expected_decrypters)
        .copied()
        .collect();

    // Check if there exists a subset $S$ of parties that have sent decryption shares and are part of the expected subset $\bar{S}$. If True continues in the "happy path".
    let have_enough_expected_decrypters =
        available_expected_decrypters.len() >= usize::from(threshold);
    let mut decrypters: Vec<_> = if have_enough_expected_decrypters {
        available_expected_decrypters
    } else {
        decrypters
    }
    .into_iter()
    .collect();

    decrypters.sort();
    let interpolation_subset: HashSet<PartyID> = decrypters
        .into_iter()
        .take(usize::from(threshold))
        .collect();

    let decryption_shares: HashMap<PartyID, Vec<_>> = decryption_shares
        .into_iter()
        .filter(|(party_id, _)| interpolation_subset.contains(party_id))
        .collect();

    let lagrange_coefficients = interpolation_subset
        .clone()
        .into_iter()
        .map(|j| {
            let coefficient = if have_enough_expected_decrypters {
                compute_expected_adjusted_lagrange_coefficient(
                    j,
                    interpolation_subset.clone(),
                    expected_decrypters.clone(),
                )
            } else {
                compute_unexpected_adjusted_lagrange_coefficient(
                    j,
                    interpolation_subset.clone(),
                    expected_decrypters.clone(),
                    n_factorial,
                )
            };

            (j, coefficient)
        })
        .collect();

    interpolate_in_the_exponent(
        decryption_shares,
        lagrange_coefficients,
        interpolation_point,
        number_of_parties,
        n_factorial,
        Some(expected_decrypters),
        true,
    )
    .map(|combined_decryption_shares| (have_enough_expected_decrypters, combined_decryption_shares))
}

/// In case that the happy flow ('semi-honest' like threshold decryption without zk-proofs) failed we need to identify which party has caused the failure.
/// As no proofs were generated we need to use the decryption shares generated in the sad flow to interpolate the expected decryption share that should have been sent in the happy flow.
/// This is done via interpolation in the exponent.
/// First you compute the expected decryption share (without any adaptations for the expected group) as $\textsf{ds}_{\textsf{expected}}=\Pi_{\j\in S_{\textsf{identification}}}\tilde{\textsf{ds}}_{j}^{\lambada_{j^*,j}^{S_{\textsf{identification}}}}$.
/// The actual decryption share that was sent by $j^*$ is denoted by $\bar{\textsf{ds}}_{j^*}$ and if $$\bar{\textsf{ds}}_{j^*}^{\Delta}\neq \textsf{ds}_{\textsf{expected}}^{\binom{n}{j^*}\Pi_{j\in [n]/\bar{S}}|j-j^*|}$ identify $j^*$ as malicious.
pub fn identify_malicious_semi_honest_decrypters<
    GroupElement: group::GroupElement + Send + Sync,
>(
    invalid_semi_honest_decryption_shares: HashMap<PartyID, Vec<GroupElement>>,
    valid_maliciously_secure_decryption_shares: HashMap<PartyID, Vec<GroupElement>>,
    expected_decrypters: HashSet<PartyID>,
    threshold: PartyID,
    number_of_parties: PartyID,
    binomial_coefficients: HashMap<PartyID, BinomialCoefficientSizedNumber>,
    n_factorial: FactorialSizedNumber,
    batch_size: usize,
) -> Result<Vec<PartyID>> {
    let malicious_decrypters = invalid_semi_honest_decryption_shares
        .into_iter()
        .map(|(virtual_party_id, possibly_invalid_decryption_shares)| {
            let (_, interpolated_decryption_shares) = interpolate_decryption_shares(
                valid_maliciously_secure_decryption_shares.clone(),
                // Using the expected decryptors as all parties reverts to the original fully asynchronous case even when interpolating at a non-zero point.
                HashSet::<PartyID>::from_iter(1..=number_of_parties),
                virtual_party_id,
                threshold,
                number_of_parties,
                n_factorial,
                batch_size,
            )?;

            Ok::<_, Error>((
                virtual_party_id,
                (
                    possibly_invalid_decryption_shares,
                    interpolated_decryption_shares,
                ),
            ))
        })
        .try_collect_hash_map()?
        .into_iter()
        .filter(
            |(
                virtual_party_id,
                (possibly_invalid_decryption_shares, interpolated_decryption_shares),
            )| {
                // Check if $\bar{\textsf{ds}}_{j^*}^{\Delta}\neq \textsf{ds}_{\textsf{expected}}^{\binom{n}{j^*}\Pi_{j\in [n]/\bar{S}}|j-j^*|}$
                if let Some(&binomial_coefficient) = binomial_coefficients.get(virtual_party_id) {
                    let possibly_invalid_decryption_shares: Vec<_> =
                        possibly_invalid_decryption_shares
                            .iter()
                            .map(|possibly_invalid_decryption_share| {
                                possibly_invalid_decryption_share.scale_vartime(&n_factorial)
                            })
                            .collect();

                    let expected_decryption_shares: Vec<_> = interpolated_decryption_shares
                        .iter()
                        .map(|interpolated_decryption_share| {
                            generate_expected_decryption_share_base(
                                interpolated_decryption_share,
                                expected_decrypters.clone(),
                                *virtual_party_id,
                                number_of_parties,
                            )
                            .scale_vartime(&binomial_coefficient)
                        })
                        .collect();

                    possibly_invalid_decryption_shares != expected_decryption_shares
                } else {
                    true
                }
            },
        )
        .map(|(virtual_party_id, _)| virtual_party_id)
        .collect();

    Ok(malicious_decrypters)
}

/// A helper function for threshold decryption schemes that work over hidden-order groups and thus use Shamir's secret sharing over the integers.
/// Combines shares over the hidden group to help recover another specified share,
/// E.g. a plaintext in threshold decryption, in which case the shares are decryption shares and $v = 0$:
/// $\left[\prod_{j\in S} \ct_j^{\Delta_n\lambda_{v,j}^S}]$
/// At the moment this function is also used during the reconfiguration protocol to compute verification keys, and interpolate secret shares.
/// We can't calculate the lagrange coefficients using the standard equations involving
/// division, and division in the exponent in a ring requires knowing its order,
/// which we don't for hidden order groups like Class Groups and Paillier.
/// Instead, we are not calculating the lagrange coefficients
/// directly but the lagrange coefficients multiplied by $\delta = n!$, which is guaranteed to be an
/// integer:
///\[
///    n! \lambda^{S}_{v,j'} = \frac{n!}{\prod\limits_{j \in S \setminus \{j'\}} (j' - j)} \cdot \prod\limits_{j \in S \setminus \{j'\}} (v - j)
///\]
///\[
///    = \frac{n!}{\prod\limits_{j \in [1,n] \setminus \{j'\}} (j' - j)} \cdot \prod\limits_{j \in [1,n] \setminus S} (j' - j) \cdot \prod\limits_{j \in S \setminus \{j'\}} (v - j)
///\]
///\[
///    = \frac{n!}{(j'-1)(j'-2)\cdots 1 \cdot (-1)(-2)\cdots -(n-j')} \cdot \prod\limits_{j \in [1,n] \setminus S} (j' - j) \cdot \prod\limits_{j \in S \setminus \{j'\}} (v - j)
///\]
///\[
///    = (-1)^{n-j'} \binom{n}{j'} \cdot j' \cdot \prod\limits_{j \in [1,n] \setminus S} (j' - j) \cdot \prod\limits_{j \in S \setminus \{j'\}} (v - j)
///\]
///\[
///    = (-1)^{n-j'} \binom{n}{j'} \cdot \frac{1}{v - j'} \prod\limits_{j \in [n] \setminus S} (j' - j) \cdot \prod\limits_{j \in S} (v - j)
///\]
///
/// Note: for threshold decryption, this does not decrypt the ciphertext,
/// as there is an extra scheme-dependent step of handling the combined decryption shares,
/// which should be handled by the caller.
fn interpolate_internal<GroupElement: group::GroupElement + Send + Sync + LinearlyCombinable>(
    shares: HashMap<PartyID, Vec<GroupElement>>,
    adjusted_lagrange_coefficients: HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber>,
    interpolated_point: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    expected_decrypters: Option<HashSet<PartyID>>, // $\bar{S}$
    is_expected_decryption_share: bool,
    is_vartime: bool,
) -> Result<Vec<GroupElement>> {
    let batch_size = shares
        .iter()
        .next()
        .ok_or(Error::InvalidParameters)?
        .1
        .len();

    // The set $S$ of parties participating in the interpolation
    let interpolation_subset: HashSet<_> = adjusted_lagrange_coefficients.keys().copied().collect();

    if batch_size == 0
        || shares.iter().any(|(_, shares)| shares.len() != batch_size)
        || shares.keys().copied().collect::<HashSet<_>>() != interpolation_subset
    {
        return Err(Error::InvalidParameters);
    }

    let neutral = shares
        .iter()
        .next()
        .ok_or(Error::InvalidParameters)?
        .1
        .first()
        .ok_or(Error::InternalError)?
        .neutral();

    if interpolation_subset.contains(&interpolated_point) {
        return shares
            .get(&interpolated_point)
            .cloned()
            .ok_or(Error::InternalError)
            .and_then(|shares| {
                // This function interpolates shares over the integers.
                // Since it is supports interpolation in the exponent, we must interpolate the share times $n!$:
                // $n! \cdot s_v$ with `v` being the `interpolated_point`.
                // In this case, we already have the share given to use as input in `shares`
                // and only need to compensate the $n!$ term to be consistent with the interpolation formula.
                shares
                    .into_iter()
                    .map(|share| {
                        if is_expected_decryption_share {
                            // The `i`th decryption share given as input is computed as
                            // $\binom{n}{j} \cdot \Pi_{j \in [n] \setminus \bar{S}}|j - i| \cdot s_i$.
                            // Since $ n! = \binom{n}{j} \cdot \Pi_{j \in [n] \setminus \{i\}}|j - i| $,
                            // we can simply compensate by multiplying the `v`th share
                            // by $ \Pi_{j \in \bar{S} \setminus \{v\}}|j - v| $:
                            let mut expected_decrypters_with_zero: HashSet<PartyID> =
                                expected_decrypters
                                    .clone()
                                    .ok_or(Error::InvalidParameters)?;
                            expected_decrypters_with_zero.insert(0);
                            let factor = expected_decrypters_with_zero
                                .difference(&HashSet::from([interpolated_point]))
                                .fold(FactorialSizedNumber::ONE, |acc, &j| {
                                    acc * FactorialSizedNumber::from(j.abs_diff(interpolated_point))
                                });

                            if is_vartime {
                                Ok(share.scale_vartime(&factor))
                            } else {
                                Ok(share.scale_bounded(&factor, factor.bits_vartime()))
                            }
                        } else {
                            // The share `s_i` given as input wasn't multiplied by any additional factor, so we simply multiply by `n!`.
                            if is_vartime {
                                Ok(share.scale_vartime(&n_factorial))
                            } else {
                                Ok(share.scale_bounded(&n_factorial, n_factorial.bits_vartime()))
                            }
                        }
                    })
                    .collect::<Result<Vec<_>>>()
            });
    }

    #[cfg(not(feature = "parallel"))]
    let iter = 0..batch_size;
    #[cfg(feature = "parallel")]
    let iter = (0..batch_size).into_par_iter();

    let interpolation_parties_requiring_inversion: Vec<PartyID> = interpolation_subset
        .clone()
        .into_iter()
        .filter(|&interpolation_party_id| {
            // We raise to the power of the absolute value,
            // and use an inverted base if the exponent should have been negative.

            // In $\binom{n}{j'}$ we have that all terms bigger than $j'$ gives a minus sign.
            // Overall we get $-1^{n-j'}$, which is negative if $(n - j')$ is odd.
            let binomial_inversion_factor = ((number_of_parties - interpolation_party_id) % 2) == 1;

            // We have the multiplication $\Pi_{j \in [n] \setminus S}(j' - j)$
            let multiplication_of_diffrences_inversion_factor = (1..=number_of_parties)
                .filter(|j| !interpolation_subset.contains(j))
                .fold(false, |acc, j| {
                    if j > interpolation_party_id {
                        !acc
                    } else {
                        acc
                    }
                });

            // Lastly, we divide by the interpolated point minus the interpolation party $(v - j')$.
            let interpolated_point_inversion_factor = interpolation_party_id > interpolated_point;

            // We invert if the factors combine (mod 2) to 1, so that we have an odd number of `true` factors.
            // This is combined using XORs.
            binomial_inversion_factor
                ^ multiplication_of_diffrences_inversion_factor
                ^ interpolated_point_inversion_factor
        })
        .collect();

    // Compute $c_j' = c_{j}^{n!\lambda_{0,j}^{S}}=c_{j}^{\pm 1\cdot {n\choose j}\Pi_{j\in [n]
    // \setminus S} |j'-j|\Pi_{j \in S}j}$.
    let combined_shares = iter
        .map(|i| {
            let shares_and_lagrange_coefficients: Vec<(
                PartyID,
                GroupElement,
                AdjustedLagrangeCoefficientSizedNumber,
            )> = shares
                .clone()
                .into_iter()
                .map(|(party_id, shares)| {
                    adjusted_lagrange_coefficients
                        .get(&party_id)
                        .map(|coefficient| {
                            // The absolute lagrange coefficients were computed without regarding the interpolated point, and we need to now regard that by dividing it by the absolute
                            // difference between the interpolated and interpolation points. This is because when we computed the coefficient, we multiplied by that factor when we shouldn't have
                            // (but couldn't foresee in advance to avoid that.)
                            // First, we know that the interpolated point is never the interpolation point, because of the check above that if it is we return the share without interpolation.
                            let interpolated_point_abs_diff_interpolation_point =
                                NonZero::new(U64::from(
                                    u64::from(interpolated_point).abs_diff(u64::from(party_id)),
                                ))
                                .unwrap();

                            // Second, because we multiplied by that factor (again, the above check guarantees that the interpolated point is not part of the interpolation subset,
                            // so we must have multiplied by this difference when computing the coefficient) we know that the absolute difference factor must divide the coefficient.
                            let (coefficient, remainder) = coefficient
                                .div_rem(&interpolated_point_abs_diff_interpolation_point);

                            if remainder == Uint::ZERO {
                                Ok(coefficient)
                            } else {
                                // This must never happen, if it does there's a bug.
                                Err(Error::InternalError)
                            }
                        })
                        .map(|coefficient| {
                            coefficient.map(|coefficient| (party_id, shares[i], coefficient))
                        })
                        .unwrap_or(Err(Error::InvalidParameters))
                })
                .collect::<Result<_>>()?;

            // To reduce the number of inversion we divide the interpolation shares into these that need inverting and these that do not and compute multi-exponantation serertaley.
            let shares_needing_inversion_and_adjusted_lagrange_coefficients: Vec<(
                GroupElement,
                AdjustedLagrangeCoefficientSizedNumber,
            )> = shares_and_lagrange_coefficients
                .clone()
                .into_iter()
                .filter(|(party_id, ..)| {
                    interpolation_parties_requiring_inversion.contains(party_id)
                })
                .map(|(_, share, absolute_adjusted_lagrange_coefficient)| {
                    (share, absolute_adjusted_lagrange_coefficient)
                })
                .collect();

            let shares_not_needing_inversion_and_adjusted_lagrange_coefficients: Vec<(
                GroupElement,
                AdjustedLagrangeCoefficientSizedNumber,
            )> = shares_and_lagrange_coefficients
                .into_iter()
                .filter(|(party_id, ..)| {
                    !interpolation_parties_requiring_inversion.contains(party_id)
                })
                .map(|(_, share, absolute_adjusted_lagrange_coefficient)| {
                    (share, absolute_adjusted_lagrange_coefficient)
                })
                .collect();

            Ok((
                shares_needing_inversion_and_adjusted_lagrange_coefficients,
                shares_not_needing_inversion_and_adjusted_lagrange_coefficients,
            ))
        })
        .map(|res| {
            res.and_then(
                |(
                    shares_needing_inversion_and_adjusted_lagrange_coefficients,
                    shares_not_needing_inversion_and_adjusted_lagrange_coefficients,
                )| {
                    #[allow(clippy::tuple_array_conversions)]
                    let [c_prime_part_needing_inversion, c_prime_part_not_needing_inversion] = [
                        shares_needing_inversion_and_adjusted_lagrange_coefficients,
                        shares_not_needing_inversion_and_adjusted_lagrange_coefficients,
                    ]
                    .map(|bases_and_exponents| {
                        if bases_and_exponents.is_empty() {
                            Ok(neutral)
                        } else {
                            // Safe to `unwrap`, checked it is non-empty.
                            let exponent_bits = bases_and_exponents
                                .iter()
                                .map(|(_, exp)| exp.bits_vartime())
                                .max()
                                .unwrap();

                            if is_vartime {
                                GroupElement::linearly_combine_bounded_vartime(
                                    bases_and_exponents,
                                    exponent_bits,
                                )
                            } else {
                                GroupElement::linearly_combine_bounded(
                                    bases_and_exponents,
                                    exponent_bits,
                                )
                            }
                        }
                    })
                    .flat_map_results()
                    .map_err(Error::from)?;

                    let c_prime = if is_vartime {
                        // TODO: sub vartime
                        c_prime_part_not_needing_inversion
                            .add_vartime(&c_prime_part_needing_inversion.neg())
                    } else {
                        c_prime_part_not_needing_inversion - c_prime_part_needing_inversion
                    };

                    // $^{\Pi_{j \in S}(v - j)}$
                    // This computation is independent of `j'` so it could be done outside the loop
                    let shared_factor = interpolation_subset
                        .iter()
                        .fold(SecretKeyShareSizedInteger::ONE, |acc, &j| {
                            acc * I64::from(i64::from(interpolated_point) - i64::from(j))
                        });

                    if is_vartime {
                        Ok(c_prime.scale_integer_bounded_vartime(
                            &shared_factor,
                            shared_factor.abs().bits_vartime(),
                        ))
                    } else {
                        Ok(c_prime.scale_integer_bounded_vartime_scalar(
                            &shared_factor,
                            shared_factor.abs().bits_vartime(),
                        ))
                    }
                },
            )
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(combined_shares)
}

/// Interpolate `shares` in `interpolated_point` in the exponent.
/// This is a variable-time function that must only be used with public `shares` (e.g. commitments),
/// thus the interpolation happens in the exponent.
pub fn interpolate_in_the_exponent<
    GroupElement: group::GroupElement + Send + Sync + LinearlyCombinable,
>(
    shares: HashMap<PartyID, Vec<GroupElement>>,
    adjusted_lagrange_coefficients: HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber>,
    interpolated_point: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    expected_decrypters: Option<HashSet<PartyID>>, // $\bar{S}$
    is_expected_decryption_share: bool,
) -> Result<Vec<GroupElement>> {
    interpolate_internal(
        shares,
        adjusted_lagrange_coefficients,
        interpolated_point,
        number_of_parties,
        n_factorial,
        expected_decrypters,
        is_expected_decryption_share,
        true,
    )
}

/// Interpolate the secret `shares` in `interpolated_point`.
/// This is a constant time function that must only be used with secret `shares` (e.g. Shamir secret shares).
pub fn interpolate_secret_shares<
    GroupElement: group::GroupElement + Send + Sync + LinearlyCombinable,
>(
    shares: HashMap<PartyID, Vec<GroupElement>>,
    adjusted_lagrange_coefficients: HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber>,
    interpolated_point: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
) -> Result<Vec<GroupElement>> {
    interpolate_internal(
        shares,
        adjusted_lagrange_coefficients,
        interpolated_point,
        number_of_parties,
        n_factorial,
        None,
        false,
        false,
    )
}

/// A wrapper around `interpolate_in_the_exponent()` that takes a map of shares dealt to a set of parties,
/// takes those that belong to a specific `party_id`, and interpolates it.
pub fn interpolate_shares_of_party_in_the_exponent<
    GroupElement: group::GroupElement + Send + Sync + LinearlyCombinable,
>(
    party_id: PartyID,
    shares: HashMap<PartyID, HashMap<PartyID, GroupElement>>,
    adjusted_lagrange_coefficients: HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber>,
    interpolated_point: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    expected_decrypters: Option<HashSet<PartyID>>, // $\bar{S}$
    is_expected_decryption_share: bool,
) -> Result<GroupElement> {
    let shares: HashMap<_, _> = shares
        .into_iter()
        .flat_map(|(dealer_party_id, shares)| {
            shares
                .get(&party_id)
                .map(|commitment| (dealer_party_id, vec![*commitment]))
        })
        .collect();

    let interpolated_shares = interpolate_in_the_exponent(
        shares,
        adjusted_lagrange_coefficients,
        interpolated_point,
        number_of_parties,
        n_factorial,
        expected_decrypters,
        is_expected_decryption_share,
    )?;

    // We passed a single share per party to interpolation, so should get a single interpolated share.
    interpolated_shares
        .into_iter()
        .next()
        .ok_or(Error::InternalError)
}

/// Compute the adjusted lagrange coefficient: $\Pi_{j\in \bar{S} \setminus S} |j'-j| $
/// The original formula is given by:
///\[
///  2. The last part $ \Pi_{j \in S}v-j} $ is independent of $ j' $,
///     so as an optimization, we are raising the result of the multi-exponentiation by it
///     once, instead of every time.```
/// Compute the adjusted lagrange coefficient: $ {n\choose j}\Pi_{j\in [n] \setminus S} |j'-j| $
/// The original formula is given by:
///\[
///    = (-1)^{n-j'} \binom{n}{j'} \cdot \frac{1}{v - j'} \prod\limits_{j \in [n] \setminus S} (j' - j) \cdot \prod\limits_{j \in S} (v - j)
///\]
/// Here, we are only computing a part of that for two reasons:
///  1. Supporting legacy code which assume we cannot hold negative numbers in crypto-bigint, so we are computing the absolute
///     value.
///  2. The last part $ \Pi_{j \in S}v-j} $ is independent of $ j $,
///     so as an optimization, we are raising the result of the multi-exponentiation by it
///     once, instead of every time.
pub fn compute_adjusted_lagrange_coefficient_internal(
    party_id: PartyID,
    interpolation_subset: HashSet<PartyID>, // $S$
    expected_decrypters: HashSet<PartyID>,  // $\bar{S}$
    initial_value: AdjustedLagrangeCoefficientSizedNumber,
) -> AdjustedLagrangeCoefficientSizedNumber {
    let mut expected_decrypters_with_zero: HashSet<PartyID> = expected_decrypters.clone();
    expected_decrypters_with_zero.insert(0);

    // Multiply the binomial coefficient by ${\Pi_{j\in [n] \setminus S} |j'-j|}$
    expected_decrypters_with_zero
        .difference(&interpolation_subset)
        .fold(initial_value, |acc, &j_prime| {
            acc * AdjustedLagrangeCoefficientSizedNumber::from(party_id.abs_diff(j_prime))
        })
}

/// This function computes the Adjusted Lagrange coefficient without the expected decryptors optimization.
pub fn compute_adjusted_lagrange_coefficient(
    party_id: PartyID,
    number_of_parties: PartyID,
    interpolation_subset: HashSet<PartyID>, // $S$
    initial_value: AdjustedLagrangeCoefficientSizedNumber,
) -> AdjustedLagrangeCoefficientSizedNumber {
    compute_adjusted_lagrange_coefficient_internal(
        party_id,
        interpolation_subset,
        HashSet::<PartyID>::from_iter(1..=number_of_parties),
        initial_value,
    )
}

/// This functions computes the Adjusted Lagrange coefficients in the case that the interpolation subset is a subset of the expected decryptors.
pub fn compute_expected_adjusted_lagrange_coefficient(
    party_id: PartyID,
    interpolation_subset: HashSet<PartyID>, // $S$
    expected_decrypters: HashSet<PartyID>,
) -> AdjustedLagrangeCoefficientSizedNumber {
    compute_adjusted_lagrange_coefficient_internal(
        party_id,
        interpolation_subset,
        expected_decrypters,
        Uint::ONE,
    )
}

/// This functions computes the Adjusted Lagrange coefficients in the case that the interpolation subset is not a subset of the expected decryptors.
/// This is done by computing the *unexpected factor* which is equal to $\frac{\Delta}{\Pi_{j'\in S/\bar{S}}|j'-j|}$ which is guaranteed to be a natural number and allows us to divide in the exponent.
/// This "unexpected factor" is then used as an initial value for the computation of the Adjusted Lagrange coefficients.
pub fn compute_unexpected_adjusted_lagrange_coefficient(
    party_id: PartyID,
    interpolation_subset: HashSet<PartyID>, // $S$
    expected_decrypters: HashSet<PartyID>,
    n_factorial: FactorialSizedNumber,
) -> AdjustedLagrangeCoefficientSizedNumber {
    let mut unexpected_decrypters: HashSet<PartyID> = interpolation_subset
        .difference(&expected_decrypters)
        .copied()
        .collect();
    unexpected_decrypters.remove(&party_id);

    let unexpected_factor =
        n_factorial
            / NonZero::new(unexpected_decrypters.into_iter().fold(
                Uint::<SECRET_KEY_SHARE_LIMBS>::ONE,
                |acc, j_prime| {
                    acc * Uint::<SECRET_KEY_SHARE_LIMBS>::from(j_prime.abs_diff(party_id))
                },
            ))
            .unwrap();

    compute_adjusted_lagrange_coefficient_internal(
        party_id,
        interpolation_subset,
        expected_decrypters,
        unexpected_factor.resize(),
    )
}

pub fn deal_shares<
    const SECRET_KEY_SHARE_LIMBS: usize,
    GroupElement: group::GroupElement + Send + Sync + Scale<Int<SECRET_KEY_SHARE_LIMBS>>,
>(
    threshold: PartyID,
    number_of_parties: PartyID,
    n_factorial: FactorialSizedNumber,
    secret: Int<SECRET_KEY_SHARE_LIMBS>,
    commitment_base: GroupElement,
    group_public_parameters: &GroupElement::PublicParameters,
    secret_key_bits: u32,
    rng: &mut impl CsRng,
) -> Result<(
    Vec<GroupElement>,
    HashMap<PartyID, Uint<SECRET_KEY_SHARE_LIMBS>>,
)>
where
    Uint<SECRET_KEY_SHARE_LIMBS>: Encoding,
    Int<SECRET_KEY_SHARE_LIMBS>: Encoding,
{
    // Threshold of 1 means shares can be negative,
    // this is a special case that we see no practical usefulness for at the moment, wherein the shares are all equal to the secret
    // so we rather just not support it until needed.
    if threshold == 1 {
        return Err(Error::InvalidParameters);
    }

    let upper_bound = secret_key_share_size_upper_bound(
        u32::from(number_of_parties),
        u32::from(threshold),
        secret_key_bits,
    );

    let coefficients_sample_bits: Vec<_> = (0..usize::from(threshold))
        .map(|k| {
            if k == 0 {
                secret_key_bits
            } else {
                secret_sharing_polynomial_coefficient_size_upper_bound(
                    u32::from(number_of_parties),
                    u32::from(threshold),
                    k as u32,
                    secret_key_bits,
                )
            }
        })
        .collect();

    let biggest_coefficient_sample_bits = *coefficients_sample_bits
        .iter()
        .max()
        .ok_or(Error::InternalError)?;
    let integer_public_parameters = bounded_integers_group::PublicParameters::new(
        biggest_coefficient_sample_bits,
        upper_bound,
    )?;

    let mut coefficients: Vec<_> = coefficients_sample_bits
        .iter()
        .enumerate()
        .map(|(k, &sample_bits)| {
            let value = if k == 0 {
                // Compute the coefficient commitments such that the first commitment is a commitment on the secret.
                Ok(secret)
            } else {
                let natural_numbers_public_parameters =
                    bounded_natural_numbers_group::PublicParameters::new(sample_bits, upper_bound)?;

                // Sample natural numbers.
                if let Some(value) = bounded_natural_numbers_group::GroupElement::sample(
                    &natural_numbers_public_parameters,
                    rng,
                )?
                .value()
                .try_into_int()
                .into()
                {
                    Ok(value)
                } else {
                    Err(group::Error::InvalidPublicParameters)
                }
            }?;

            bounded_integers_group::GroupElement::new(value, &integer_public_parameters)
        })
        .collect::<group::Result<_>>()?;

    #[cfg(feature = "parallel")]
    let coefficients_iter = coefficients.clone().into_par_iter();
    #[cfg(not(feature = "parallel"))]
    let coefficients_iter = coefficients.clone().into_iter();

    // $C_{\mainIndex}=\bar{g}_{q'}^{a_{\mainIndex}}$
    let coefficients_commitments: Vec<GroupElement> = coefficients_iter
        .enumerate()
        .map(|(k, coefficient)| {
            let sample_bits = *coefficients_sample_bits
                .get(k)
                .ok_or(Error::InternalError)?;
            Ok(commitment_base.scale_randomized_bounded_accelerated(
                &coefficient.value(),
                group_public_parameters,
                sample_bits,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    // For dealing the shares, set the first coefficient as the secret multiplied by `delta`.
    coefficients[0] = coefficients[0].scale_bounded(&n_factorial, n_factorial.bits_vartime());

    let polynomial = Polynomial::try_from(coefficients)?;

    #[cfg(feature = "parallel")]
    let parties_iter = (1..=number_of_parties).into_par_iter();
    #[cfg(not(feature = "parallel"))]
    let parties_iter = (1..=number_of_parties).into_iter();

    let shares: HashMap<PartyID, _> = parties_iter
        .map(|j| {
            let degree = bounded_integers_group::GroupElement::new(
                Int::<SECRET_KEY_SHARE_LIMBS>::from(i32::from(j)),
                &integer_public_parameters,
            )?;

            // $[s]_{i}=f(i)$
            // Safe to convert to `uint`, as the result are guaranteed to be positive,
            // as we sample the coefficients to be positive, and they are significantly bigger than the secret (statistically hiding it).
            let share = polynomial.evaluate(&degree).value().abs();

            Ok((j, share))
        })
        .collect::<group::Result<_>>()?;

    Ok((coefficients_commitments, shares))
}

pub fn commit_shares<
    const SECRET_KEY_SHARE_LIMBS: usize,
    GroupElement: group::GroupElement + Send + Sync,
>(
    threshold: PartyID,
    number_of_parties: PartyID,
    commitment_base: GroupElement,
    secret_key_bits: u32,
    shares: HashMap<PartyID, Uint<SECRET_KEY_SHARE_LIMBS>>,
) -> Result<HashMap<PartyID, GroupElement>> {
    #[cfg(feature = "parallel")]
    let shares_iter = shares.clone().into_par_iter();
    #[cfg(not(feature = "parallel"))]
    let shares_iter = shares.clone().into_iter();

    // $\bar{C}_{i}=\bar{g}_{q'}^{f(i)}$
    let shares_commitments: HashMap<PartyID, GroupElement> = shares_iter
        .map(|(j, share)| {
            (
                j,
                commitment_base.scale_bounded(
                    &share,
                    secret_key_share_size_upper_bound(
                        u32::from(number_of_parties),
                        u32::from(threshold),
                        secret_key_bits,
                    ),
                ),
            )
        })
        .collect();

    Ok(shares_commitments)
}

#[cfg(test)]
mod tests {
    use std::cmp::min;

    use crypto_bigint::{ConstChoice, Random, U2048, U256};
    use rand::seq::IteratorRandom;
    use rstest::rstest;

    use group::{secp256k1, OsCsRng};

    use super::*;

    fn factorial(num: PartyID) -> u64 {
        (1u64..=u64::from(num)).product()
    }

    #[rstest]
    #[case::args((3, HashMap::from([
    (1, BinomialCoefficientSizedNumber::from(3u16)),
    (2, BinomialCoefficientSizedNumber::from(3u16)),
    (3, BinomialCoefficientSizedNumber::from(1u16))
    ])))]
    #[case::args((5, HashMap::from([
    (1, BinomialCoefficientSizedNumber::from(5u16)),
    (2, BinomialCoefficientSizedNumber::from(2u16 * 5)),
    (3, BinomialCoefficientSizedNumber::from(2u16 * 5)),
    (4, BinomialCoefficientSizedNumber::from(5u16)),
    (5, BinomialCoefficientSizedNumber::from(1u16))
    ])))]
    #[case::args((6, HashMap::from([
    (1, BinomialCoefficientSizedNumber::from(6u16)),
    (2, BinomialCoefficientSizedNumber::from(5u16 * 3)),
    (3, BinomialCoefficientSizedNumber::from(2u16 * 5 * 2)),
    (4, BinomialCoefficientSizedNumber::from(5u16 * 3)),
    (5, BinomialCoefficientSizedNumber::from(6u16)),
    (6, BinomialCoefficientSizedNumber::from(1u16))
    ])))]
    fn constructs(#[case] args: (PartyID, HashMap<PartyID, BinomialCoefficientSizedNumber>)) {
        let (n, coefficients) = args;

        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let precomputed_values = PrecomputedValues::<secp256k1::Scalar>::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
        >(n, &scalar_public_parameters)
        .unwrap();

        assert_eq!(precomputed_values.binomial_coefficients, coefficients);

        let n_factorial_mod_q = secp256k1::Scalar::from(U256::from(factorial(n)));
        let n_factorial_cubed_inverse = precomputed_values.n_factorial_cubed_inverse;

        assert_eq!(
            U256::from(
                n_factorial_mod_q
                    * n_factorial_mod_q
                    * n_factorial_mod_q
                    * n_factorial_cubed_inverse
            ),
            U256::ONE
        );
    }

    #[test]
    fn interpolates() {
        for number_of_parties in [2, 3, 4, 6, 10, 64, 119, MAX_PLAYERS as u16] {
            let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

            let precomputed_values = PrecomputedValues::<secp256k1::Scalar>::new::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
            >(number_of_parties, &scalar_public_parameters)
            .unwrap();

            let n_factorial = precomputed_values.n_factorial;

            for threshold in (2..=min(number_of_parties, MAX_THRESHOLD as u16))
                .choose_multiple(&mut OsCsRng, 4)
                .into_iter()
            {
                let interpolation_subset: HashSet<_> = (1..=number_of_parties)
                    .choose_multiple(&mut OsCsRng, usize::from(threshold))
                    .into_iter()
                    .collect();

                let adjusted_lagrange_coefficients: HashMap<_, _> = interpolation_subset
                    .iter()
                    .map(|&dealer_virtual_party_id| {
                        let binomial_coefficient = precomputed_values
                            .binomial_coefficients
                            .get(&dealer_virtual_party_id)
                            .unwrap()
                            .resize();

                        // dealer_virtual_party_id is $j \in S_{B_{T}} for a valid subset$
                        let adjusted_lagrange_coefficient = compute_adjusted_lagrange_coefficient(
                            dealer_virtual_party_id,
                            number_of_parties,
                            interpolation_subset.clone(),
                            binomial_coefficient,
                        );

                        (dealer_virtual_party_id, adjusted_lagrange_coefficient)
                    })
                    .collect();

                // This is useless for this test, use anything
                let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
                let neutral =
                    secp256k1::Scalar::neutral_from_public_parameters(&scalar_public_parameters)
                        .unwrap();

                let public_parameters = bounded_integers_group::PublicParameters::<
                    COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_LIMBS,
                >::new(
                    secret_key_share_size_upper_bound(
                        u32::from(number_of_parties),
                        u32::from(threshold),
                        U2048::BITS,
                    ),
                    computation_decryption_key_shares_interpolation_upper_bound(
                        u32::from(number_of_parties),
                        u32::from(threshold),
                        U2048::BITS,
                    ),
                )
                .unwrap();

                // First try a positive secret
                let secret = Int::new_from_abs_sign(
                    SecretKeyShareSizedNumber::from(&U2048::random(&mut OsCsRng)),
                    ConstChoice::FALSE,
                )
                .unwrap();

                let (_, shares) = deal_shares::<{ SecretKeyShareSizedNumber::LIMBS }, _>(
                    threshold,
                    number_of_parties,
                    n_factorial,
                    secret,
                    neutral,
                    &scalar_public_parameters,
                    U2048::BITS,
                    &mut OsCsRng,
                )
                .unwrap();

                let shares_for_interpolation: HashMap<_, _> = shares
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| interpolation_subset.contains(party_id))
                    .map(|(party_id, share)| {
                        let share = Int::new_from_abs_sign(share, ConstChoice::FALSE).unwrap();

                        (
                            party_id,
                            vec![bounded_integers_group::GroupElement::new(
                                Int::from(&share),
                                &public_parameters,
                            )
                            .unwrap()],
                        )
                    })
                    .collect();

                let interpolated_secret = interpolate_secret_shares(
                    shares_for_interpolation.clone(),
                    adjusted_lagrange_coefficients.clone(),
                    0,
                    number_of_parties,
                    n_factorial,
                )
                .unwrap()[0]
                    .value();

                assert_eq!(
                        (Int::from(&secret) * n_factorial) * n_factorial,
                        interpolated_secret,
                        "{threshold}-out-of-{number_of_parties} interpolation of secret should equal the secret by n!^2"
                    );

                (1..=number_of_parties).choose_multiple(&mut OsCsRng, 4).into_iter().for_each(|party_id| {
                        let interpolated_share = interpolate_secret_shares(
                            shares_for_interpolation.clone(),
                            adjusted_lagrange_coefficients.clone(),
                            party_id,
                            number_of_parties,
                            n_factorial,
                        )
                            .unwrap()[0]
                            .value();

                        let share_by_delta =
                            Int::from(&Int::new_from_abs_sign(*shares.get(&party_id).unwrap(), ConstChoice::FALSE)
                                .unwrap())
                                * n_factorial;

                        assert_eq!(
                            share_by_delta, interpolated_share,
                            "{threshold}-out-of-{number_of_parties} interpolation of the share of {party_id} should equal the share by n!"
                        );
                    });

                // Now try a negative one
                let secret = secret.checked_neg().unwrap();

                let (_, shares) = deal_shares::<{ SecretKeyShareSizedNumber::LIMBS }, _>(
                    threshold,
                    number_of_parties,
                    n_factorial,
                    secret,
                    neutral,
                    &scalar_public_parameters,
                    U2048::BITS,
                    &mut OsCsRng,
                )
                .unwrap();

                let shares_for_interpolation: HashMap<_, _> = shares
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| interpolation_subset.contains(party_id))
                    .map(|(party_id, share)| {
                        let share = Int::new_from_abs_sign(share, ConstChoice::FALSE).unwrap();

                        (
                            party_id,
                            vec![bounded_integers_group::GroupElement::new(
                                Int::from(&share),
                                &public_parameters,
                            )
                            .unwrap()],
                        )
                    })
                    .collect();

                let interpolated_secret = interpolate_secret_shares(
                    shares_for_interpolation.clone(),
                    adjusted_lagrange_coefficients.clone(),
                    0,
                    number_of_parties,
                    n_factorial,
                )
                .unwrap()[0]
                    .value();

                assert_eq!(
                        (Int::from(&secret) * n_factorial) * n_factorial,
                        interpolated_secret,
                        "{threshold}-out-of-{number_of_parties} interpolation of a negative secret should equal the secret by n!^2"
                    );

                (1..=number_of_parties).choose_multiple(&mut OsCsRng, 4).into_iter().for_each(|party_id| {
                        let interpolated_share = interpolate_secret_shares(
                            shares_for_interpolation.clone(),
                            adjusted_lagrange_coefficients.clone(),
                            party_id,
                            number_of_parties,
                            n_factorial,
                        )
                            .unwrap()[0]
                            .value();

                        let share_by_delta =
                            Int::from(&Int::new_from_abs_sign(*shares.get(&party_id).unwrap(), ConstChoice::FALSE)
                                .unwrap())
                                * n_factorial;

                        assert_eq!(
                            share_by_delta, interpolated_share,
                            "{threshold}-out-of-{number_of_parties} interpolation of the share of {party_id} of a negative secret should equal the share by n!"
                        );
                    });
            }
        }
    }

    #[test]
    fn factorial_bits_computed_correctly() {
        let mut n_factorial = SecretKeyShareSizedNumber::ONE;
        (1..=(MAX_PLAYERS + MAX_THRESHOLD)).for_each(|n| {
            n_factorial *= U64::from(u64::from(n));

            assert_eq!(
                factorial_upper_bound(n),
                n_factorial.bits_vartime(),
                "factorial bits for {n} computed incorrectly"
            );
        })
    }

    #[test]
    fn computes_stirling() {
        assert_eq!(stirling(0, 0), FactorialSizedNumber::ONE);
        assert_eq!(stirling(1, 0), FactorialSizedNumber::ZERO);
        assert_eq!(stirling(1, 1), FactorialSizedNumber::ONE);
        assert_eq!(stirling(2, 1), FactorialSizedNumber::ONE);
        assert_eq!(stirling(2, 2), FactorialSizedNumber::ONE);
        assert_eq!(stirling(3, 1), FactorialSizedNumber::from(2u64));
        assert_eq!(stirling(3, 2), FactorialSizedNumber::from(3u64));
        assert_eq!(stirling(3, 3), FactorialSizedNumber::from(1u64));
        assert_eq!(stirling(9, 3), FactorialSizedNumber::from(118124u64));
        assert_eq!(stirling(10, 5), FactorialSizedNumber::from(269325u64));
        println!("{}", FactorialSizedNumber::BITS);
        assert_eq!(stirling(50, 40), FactorialSizedNumber::from_be_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000078B281D3DDFCD97DAD18"));
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use group::OsCsRng;

    use super::*;

    /// Do a "trusted dealer" setup, in real life we'd have the secret shares as an output of the
    /// DKG.
    pub fn deal_trusted_shares<
        const SECRET_KEY_SHARE_LIMBS: usize,
        GroupElement: group::GroupElement + Send + Sync + Scale<Int<SECRET_KEY_SHARE_LIMBS>>,
    >(
        threshold: PartyID,
        number_of_parties: PartyID,
        secret_key: Int<SECRET_KEY_SHARE_LIMBS>,
        public_verification_key_base: GroupElement,
        group_public_parameters: &GroupElement::PublicParameters,
        secret_key_bits: u32,
    ) -> (
        GroupElement,
        HashMap<PartyID, GroupElement>,
        HashMap<PartyID, Uint<SECRET_KEY_SHARE_LIMBS>>,
    )
    where
        Uint<SECRET_KEY_SHARE_LIMBS>: Encoding,
        Int<SECRET_KEY_SHARE_LIMBS>: Encoding,
    {
        let n_factorial = (2..=number_of_parties)
            .map(FactorialSizedNumber::from)
            .reduce(|a, b| a.wrapping_mul(&b))
            .unwrap();

        let (_, decryption_key_shares) = deal_shares(
            threshold,
            number_of_parties,
            n_factorial,
            secret_key,
            public_verification_key_base,
            group_public_parameters,
            secret_key_bits,
            &mut OsCsRng,
        )
        .unwrap();

        let public_verification_keys = commit_shares(
            threshold,
            number_of_parties,
            public_verification_key_base,
            secret_key_bits,
            decryption_key_shares.clone(),
        )
        .unwrap();

        (
            public_verification_key_base,
            public_verification_keys,
            decryption_key_shares,
        )
    }
}
