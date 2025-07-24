// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{Limb, Uint, Word};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use crate::Error;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

const WINDOW: u32 = 4;
const WINDOW_MASK: Word = (1 << WINDOW) - 1;

/// Performs constant-time "modular multi-exponentiation" (i.e. linear combination) using Montgomery's ladder.
pub trait LinearlyCombinable: Sized {
    /// Performs constant-time "modular multi-exponentiation" (i.e. linear combination) using Montgomery's ladder.
    ///
    /// See: Straus, E. G. Problems and solutions: Addition chains of vectors. American Mathematical
    /// Monthly 71 (1964), 806–808.
    ///
    /// This gives roughly a 4x improvement for 4096-bits multiplicative groups
    fn linearly_combine<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
    ) -> crate::Result<Self> {
        Self::linearly_combine_bounded(bases_and_multiplicands, Uint::<RHS_LIMBS>::BITS)
    }

    /// Performs constant-time "modular multi-exponentiation" (i.e. linear combination) using Montgomery's ladder.
    /// `exponent_bits` represents the number of bits to take into account for the exponent.
    ///
    /// See: Straus, E. G. Problems and solutions: Addition chains of vectors. American Mathematical
    /// Monthly 71 (1964), 806–808.
    ///
    /// This gives roughly a 4x improvement for 4096-bits multiplicative groups
    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self>;

    /// Performs variable-time "modular multi-exponentiation" (i.e. linear combination) using Montgomery's ladder.
    ///
    /// See: Straus, E. G. Problems and solutions: Addition chains of vectors. American Mathematical
    /// Monthly 71 (1964), 806–808.
    fn linearly_combine_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
    ) -> crate::Result<Self> {
        Self::linearly_combine_bounded_vartime(bases_and_multiplicands, Uint::<RHS_LIMBS>::BITS)
    }

    /// Performs variable-time "modular multi-exponentiation" (i.e. linear combination) using Montgomery's ladder.
    /// `exponent_bits` represents the number of bits to take into account for the exponent.
    ///
    /// See: Straus, E. G. Problems and solutions: Addition chains of vectors. American Mathematical
    /// Monthly 71 (1964), 806–808.
    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
    ) -> crate::Result<Self>;
}

pub fn linearly_combine_bounded<
    const RHS_LIMBS: usize,
    GroupElement: crate::GroupElement + ConditionallySelectable,
>(
    bases_and_multiplicands: Vec<(GroupElement, Uint<RHS_LIMBS>)>,
    exponent_bits: u32,
    constant_time: bool,
) -> crate::Result<GroupElement> {
    if bases_and_multiplicands.is_empty() || exponent_bits > Uint::<RHS_LIMBS>::BITS {
        return Err(Error::InvalidParameters);
    }

    // Checked that it's non-empty, so safe to `unwrap`
    let neutral = bases_and_multiplicands.first().unwrap().0.neutral();

    if exponent_bits == 0 {
        return Ok(neutral);
    }

    let starting_limb = (exponent_bits - 1) / Limb::BITS;
    let starting_bit_in_limb = (exponent_bits - 1) % Limb::BITS;
    let starting_window = starting_bit_in_limb / WINDOW;
    let starting_window_mask = (1 << (starting_bit_in_limb % WINDOW + 1)) - 1;

    #[cfg(not(feature = "parallel"))]
    let iter = bases_and_multiplicands.into_iter();
    #[cfg(feature = "parallel")]
    let iter = bases_and_multiplicands.into_par_iter();

    let products_and_multiplicands: Vec<([_; 1 << WINDOW], Uint<RHS_LIMBS>)> = iter
        .map(|(base, exponent)| {
            // products[i] contains i*base
            let mut products = [neutral; 1 << WINDOW];
            products[1] = base;

            let mut i = 2;
            while i < products.len() {
                if constant_time {
                    products[i] = base + products[i - 1];
                } else {
                    products[i] = base.add_vartime(&products[i - 1])
                }
                i += 1;
            }
            (products, exponent)
        })
        .collect();

    let mut z = neutral;

    let mut limb_num = starting_limb + 1;
    while limb_num > 0 {
        limb_num -= 1;

        let mut window_num = if limb_num == starting_limb {
            starting_window + 1
        } else {
            Limb::BITS / WINDOW
        };
        while window_num > 0 {
            window_num -= 1;

            if limb_num != starting_limb || window_num != starting_window {
                let mut i = 0;
                while i < WINDOW {
                    i += 1;

                    if constant_time {
                        z = z.double();
                    } else {
                        z = z.double_vartime()
                    }
                }
            }

            #[cfg(not(feature = "parallel"))]
            let iter = (0..products_and_multiplicands.len()).into_iter();
            #[cfg(feature = "parallel")]
            let iter = (0..products_and_multiplicands.len()).into_par_iter();

            let powers = iter.map(|i| {
                let (powers, exponent) = products_and_multiplicands[i];
                let w = exponent.as_limbs()[limb_num as usize].0;
                let mut idx = (w >> (window_num * WINDOW)) & WINDOW_MASK;

                if limb_num == starting_limb && window_num == starting_window {
                    idx &= starting_window_mask;
                }

                if constant_time {
                    // Constant-time lookup in the array of powers
                    let mut power = powers[0];
                    let mut j = 1;
                    while j < 1 << WINDOW {
                        let choice = <Limb as ConstantTimeEq>::ct_eq(&Limb(j as Word), &Limb(idx));

                        power = <GroupElement as ConditionallySelectable>::conditional_select(
                            &power, &powers[j], choice,
                        );
                        j += 1;
                    }

                    power
                } else {
                    // Variable time dereferencing
                    powers[idx as usize]
                }
            });

            #[cfg(not(feature = "parallel"))]
            {
                z = powers.fold(z, |a, b| {
                    if constant_time {
                        a + b
                    } else {
                        a.add_vartime(&b)
                    }
                });
            }
            #[cfg(feature = "parallel")]
            {
                z += powers.reduce(
                    || neutral,
                    |a, b| {
                        if constant_time {
                            a + b
                        } else {
                            a.add_vartime(&b)
                        }
                    },
                );
            }
        }
    }

    Ok(z)
}

/// Linearly combine `bases_and_multiplicands` with `exponent_bits` as a bound on the bits of each multiplicand.
/// Default to use the (hopefully faster) `scale_bounded` in case there is only one base and multiplicand.
pub fn linearly_combine_bounded_or_scale<
    const RHS_LIMBS: usize,
    GroupElement: crate::GroupElement + ConditionallySelectable,
>(
    bases_and_multiplicands: Vec<(GroupElement, Uint<RHS_LIMBS>)>,
    exponent_bits: u32,
    constant_time: bool,
) -> crate::Result<GroupElement> {
    if let &[(base, multiplicand)] = &bases_and_multiplicands[..] {
        if constant_time {
            Ok(base.scale_bounded(&multiplicand, exponent_bits))
        } else {
            Ok(base.scale_bounded_vartime(&multiplicand, exponent_bits))
        }
    } else {
        linearly_combine_bounded(bases_and_multiplicands, exponent_bits, constant_time)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::rand_core::OsRng;
    use crypto_bigint::U256;

    use crate::Samplable;
    use crate::{secp256k1, CyclicGroupElement};

    use super::*;

    #[test]
    fn linearly_combines() {
        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let group_public_parameters = secp256k1::group_element::PublicParameters::default();

        let generators =
            secp256k1::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();
        let scalars =
            secp256k1::Scalar::sample_batch(&scalar_public_parameters, 3, &mut OsRng).unwrap();
        let bases: Vec<_> =
            secp256k1::Scalar::sample_batch(&scalar_public_parameters, 3, &mut OsRng)
                .unwrap()
                .into_iter()
                .map(|scalar| scalar * generators)
                .collect();

        let vartime_result = linearly_combine_bounded_or_scale(
            bases
                .clone()
                .into_iter()
                .zip(scalars.clone())
                .map(|(base, scalar)| (base, U256::from(scalar)))
                .collect(),
            U256::BITS,
            false,
        )
        .unwrap();

        let result = linearly_combine_bounded_or_scale(
            bases
                .clone()
                .into_iter()
                .zip(scalars.clone())
                .map(|(base, scalar)| (base, U256::from(scalar)))
                .collect(),
            U256::BITS,
            true,
        )
        .unwrap();

        let expected = bases
            .into_iter()
            .zip(scalars)
            .map(|(base, scalar)| scalar * base)
            .reduce(|a, b| a + b)
            .unwrap();

        assert_eq!(expected, result,);
        assert_eq!(expected, vartime_result,);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;
    use crypto_bigint::U256;
    use rand_core::OsRng;

    use crate::linear_combination::LinearlyCombinable;
    use crate::{ristretto, secp256k1, CyclicGroupElement, Samplable};

    pub(crate) fn benchmark(c: &mut Criterion) {
        let mut g = c.benchmark_group("Linear Combination in secp256k1");

        let scalar_public_parameters = secp256k1::scalar::PublicParameters::default();
        let group_public_parameters = secp256k1::group_element::PublicParameters::default();

        let generator =
            secp256k1::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let exponent = secp256k1::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        g.bench_function("single exponentiation", |bench| {
            bench.iter(|| exponent * generator);
        });

        for batch_size in [1, 2, 4, 8, 16, 32, 64, 128] {
            let multiplicands: Vec<_> =
                secp256k1::Scalar::sample_batch(&scalar_public_parameters, batch_size, &mut OsRng)
                    .unwrap()
                    .into_iter()
                    .map(U256::from)
                    .collect();

            let scalars =
                secp256k1::Scalar::sample_batch(&scalar_public_parameters, batch_size, &mut OsRng)
                    .unwrap();
            let bases: Vec<_> = scalars.into_iter().map(|s| s * generator).collect();

            let bases_and_multiplicands: Vec<_> = bases
                .clone()
                .into_iter()
                .zip(multiplicands.clone())
                .collect();

            g.bench_function(format!("{batch_size} elements"), |bench| {
                bench.iter(|| {
                    secp256k1::GroupElement::linearly_combine(bases_and_multiplicands.clone())
                        .unwrap()
                });
            });
        }

        g.finish();

        let mut g = c.benchmark_group("Linear Combination in ristretto");

        let scalar_public_parameters = ristretto::scalar::PublicParameters::default();
        let group_public_parameters = ristretto::group_element::PublicParameters::default();

        let generator =
            ristretto::GroupElement::generator_from_public_parameters(&group_public_parameters)
                .unwrap();

        let exponent = ristretto::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        g.bench_function("single exponentiation", |bench| {
            bench.iter(|| exponent * generator);
        });

        for batch_size in [1, 2, 4, 8, 16, 32, 64, 128] {
            let multiplicands: Vec<_> =
                ristretto::Scalar::sample_batch(&scalar_public_parameters, batch_size, &mut OsRng)
                    .unwrap()
                    .into_iter()
                    .map(U256::from)
                    .collect();

            let scalars =
                ristretto::Scalar::sample_batch(&scalar_public_parameters, batch_size, &mut OsRng)
                    .unwrap();
            let bases: Vec<_> = scalars.into_iter().map(|s| s * generator).collect();

            let bases_and_multiplicands: Vec<_> = bases
                .clone()
                .into_iter()
                .zip(multiplicands.clone())
                .collect();

            g.bench_function(format!("{batch_size} elements"), |bench| {
                bench.iter(|| {
                    ristretto::GroupElement::linearly_combine(bases_and_multiplicands.clone())
                        .unwrap()
                });
            });
        }

        g.finish();
    }
}
