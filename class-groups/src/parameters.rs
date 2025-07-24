// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(dead_code)]

use std::ops::Deref;

use crypto_bigint::subtle::CtOption;
use crypto_bigint::{CheckedMul, Concat, Encoding, Int, NonZero, NonZeroUint, Split, Uint, Word};
use crypto_primes::{is_prime, Flavor};
use serde::{Deserialize, Serialize};

use group::{CsRng, Transcribeable};

use crate::discriminant::Discriminant;
use crate::equivalence_class::EquivalenceClass;
use crate::helpers::math;
use crate::helpers::math::FIRST_100_PRIMES;
use crate::Error;

/// The bit-length of the prime being targeted during the construction of `h`.
const H_PRIME_BIT_LENGTH_TARGET: u32 = 128;

/// The maximum number of primes sampled during the construction of `h` before aborting.
const H_PRIME_MAX_SAMPLE_ATTEMPTS: u32 = 128;

/// Set of parameters used in ClassGroup cryptography.
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Parameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const DELTA_K_LIMBS: usize,
    const DELTA_QK_LIMBS: usize,
> where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Int<DELTA_K_LIMBS>: Encoding,
    Uint<DELTA_K_LIMBS>: Encoding,
    Int<DELTA_QK_LIMBS>: Encoding,
    Uint<DELTA_QK_LIMBS>: Encoding,
{
    // The discriminants of the two class groups on which this scheme operates.
    pub delta_k: Discriminant<DELTA_K_LIMBS>,
    pub delta_qk: Discriminant<DELTA_QK_LIMBS>,

    // Decomposition of ∆_k = -pq, the class group identifying discriminant.
    // q: Plaintext Space order
    pub q: NonZero<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
    pub p: NonZero<Uint<DELTA_K_LIMBS>>,

    // Parameters relating to the order.
    // BICYCL (https://eprint.iacr.org/2022/1466) uses `q` as the conductor.
    pub k: u8,
    pub q_exp_2k: NonZero<Uint<DELTA_QK_LIMBS>>,

    // Parameters related to the security of the scheme
    pub computational_security_parameter: u32,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const DELTA_K_LIMBS: usize,
        const HALF_DELTA_QK_LIMBS: usize,
        const DELTA_QK_LIMBS: usize,
        const DOUBLE_DELTA_QK_LIMBS: usize,
    > Parameters<PLAINTEXT_SPACE_SCALAR_LIMBS, DELTA_K_LIMBS, DELTA_QK_LIMBS>
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<DELTA_K_LIMBS>: Encoding,
    Uint<DELTA_K_LIMBS>: Encoding,

    Int<DELTA_QK_LIMBS>: Encoding,
    Uint<HALF_DELTA_QK_LIMBS>: Concat<Output = Uint<DELTA_QK_LIMBS>>,
    Uint<DELTA_QK_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_DELTA_QK_LIMBS>>
        + Split<Output = Uint<HALF_DELTA_QK_LIMBS>>,
    Uint<DOUBLE_DELTA_QK_LIMBS>: Split<Output = Uint<DELTA_QK_LIMBS>>,
{
    pub(crate) fn new(
        q: NonZero<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        k: u8,
        p: NonZero<Uint<DELTA_K_LIMBS>>,
        computational_security_parameter: u32,
    ) -> Result<Self, Error> {
        Self::validate_parameters(&q, k, &p, computational_security_parameter)?;

        let q_upsized = q.resize::<DELTA_QK_LIMBS>();
        let q_ = CtOption::from(q_upsized.try_into_int())
            .into_option()
            .ok_or(Error::InternalError)?;
        let p_ = CtOption::from((*p).try_into_int())
            .into_option()
            .ok_or(Error::InternalError)?;

        // Compute ∆_k := -p * q
        let delta_k = p_
            .checked_mul(&q_)
            .and_then(|pq| pq.checked_neg().into())
            .into_option()
            .ok_or(Error::InvalidDiscriminantParameters)?;

        // Compute ∆_{q^k} := ∆_k * q^2k = - p * q^{2k+1}
        // safe to unwrap; q is non-zero
        let q_exp_k = math::pow_vartime(&q_upsized, k as u32)?.to_nz().unwrap();
        // safe to unwrap; q is non-zero
        let q_exp_2k = q_exp_k
            .checked_mul(&q_exp_k)
            .and_then(|q_exp_2k| q_exp_2k.to_nz().into())
            .into_option()
            .ok_or(Error::InvalidDiscriminantParameters)?;
        // safe to resize; scaling up
        let delta_qk = delta_k
            .resize::<DELTA_QK_LIMBS>()
            .checked_mul(q_exp_2k.deref())
            .into_option()
            .ok_or(Error::InvalidDiscriminantParameters)?;

        // safe to unwrap; q is non-zero
        let delta_k_nz = delta_k.to_nz().unwrap();
        let delta_qk_nz = delta_qk.to_nz().unwrap();

        Ok(Self {
            delta_k: Discriminant::new(delta_k_nz)
                .into_option()
                .ok_or(Error::InvalidDiscriminantParameters)?,
            delta_qk: Discriminant::new(delta_qk_nz)
                .into_option()
                .ok_or(Error::InvalidDiscriminantParameters)?,
            q,
            p,
            k,
            q_exp_2k,
            computational_security_parameter,
        })
    }

    /// Validate the set of provided parameters.
    fn validate_parameters(
        q: &NonZero<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        k: u8,
        p: &NonZero<Uint<DELTA_K_LIMBS>>,
        computational_security_parameter: u32,
    ) -> Result<(), Error> {
        // Verify that the resulting discriminant will fit inside DISCRIMINANT_LIMBS.
        // `∆_{q^k}` will be computed as `- q^{2k+1} * p`
        let delta_qk_bits = q.bits() * (2 * u32::from(k) + 1) + p.bits();
        if delta_qk_bits > Uint::<DELTA_QK_LIMBS>::BITS {
            return Err(Error::InvalidPublicParameters);
        }

        // Verify that the resulting discriminant has the desired bit size
        let delta_k_bits = q.bits() + p.bits();
        if delta_k_bits < minimum_discriminant_bits(computational_security_parameter)? {
            return Err(Error::InvalidPublicParameters);
        }

        // Verify that p*q ≡ 3 mod 4
        //
        // Note that:
        // x mod 2^k
        //   = the $k$ least significant bits of x
        //   = x & (2^k - 1)
        let three = Word::from(3u32);
        let q_mod_4 = q.as_limbs()[0].0 & three;
        let p_mod_4 = p.as_limbs()[0].0 & three;
        if (q_mod_4 * p_mod_4) & three != three {
            return Err(Error::InvalidPublicParameters);
        }

        // Verify q is valid
        Self::validate_q(q)?;

        // Verify k is valid
        Self::validate_k(k)?;

        // Verify that p is prime, or one.
        if !(p.get() == Uint::ONE || is_prime(Flavor::Any, p.deref())) {
            return Err(Error::InvalidPublicParameters);
        }

        // If p ≠ 1, check that (q/p) = -1
        let q_ = CtOption::from((*q).resize::<DELTA_QK_LIMBS>().try_into_int())
            .into_option()
            .ok_or(Error::InternalError)?;
        let p_ = p
            .resize::<DELTA_QK_LIMBS>()
            .to_nz()
            .expect("upscaled non-zero value should be non-zero");
        if !(p.get() == Uint::ONE
            || math::legendre_symbol(&q_, &p_).map_err(|_| Error::InvalidPublicParameters)? == -1)
        {
            return Err(Error::InvalidPublicParameters);
        }

        Ok(())
    }

    /// Validate `q`.
    fn validate_q(q: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>) -> Result<(), Error> {
        // Only requirement: `q` must be prime.
        if !is_prime(Flavor::Any, q) {
            return Err(Error::InvalidPublicParameters);
        }
        Ok(())
    }

    /// Validate `k`.
    fn validate_k(k: u8) -> Result<(), Error> {
        // Currently, only `k=1` is supported.
        // TODO(#17): support k > 1
        if k != 1 {
            return Err(Error::InvalidPublicParameters);
        }
        Ok(())
    }

    /// Construct `h`.
    /// The encryption scheme composes this with the randomness.
    ///
    /// Uses `rng` to sample a random prime form.
    ///
    /// TODO: use hash-to-group instead (#225)
    pub(crate) fn h(
        &self,
        rng: &mut impl CsRng,
    ) -> Result<EquivalenceClass<DELTA_QK_LIMBS>, Error> {
        let kronecker_prime: NonZero<Uint<HALF_DELTA_QK_LIMBS>> = math::random_kronecker_prime(
            self.delta_qk.deref(),
            rng,
            H_PRIME_BIT_LENGTH_TARGET,
            H_PRIME_MAX_SAMPLE_ATTEMPTS,
        )
        .ok_or(Error::InvalidPublicParameters)?
        .to_nz()
        .expect("is non-zero; kronecker_prime is a prime");

        // Construct t, a prime form for CL(∆_{q^k})²
        let t = EquivalenceClass::prime_form(&self.delta_qk, kronecker_prime)?.square_vartime();

        // Construct h as t^{q^k}
        // TODO(#17): use t.pow(q_exp_k) instead.
        Ok(t.pow_vartime(&self.q))
    }

    /// Construct new class group parameters, using a randomly sampled `p`.
    pub(crate) fn new_random_vartime(
        q: NonZero<Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        k: u8,
        computational_security_parameter: u32,
        rng: &mut impl CsRng,
    ) -> Result<Self, Error> {
        Self::validate_q(&q)?;
        Self::validate_k(k)?;

        let large_discriminant_bits = Uint::<DELTA_QK_LIMBS>::BITS;
        let small_discriminant_bits = Uint::<DELTA_K_LIMBS>::BITS;

        // DELTA_K_LIMBS must at least be able to contain the small discriminant
        let min_small_discriminant_bits =
            minimum_discriminant_bits(computational_security_parameter)?;
        if small_discriminant_bits < min_small_discriminant_bits {
            return Err(Error::InvalidPublicParameters);
        }

        // DELTA_QK_LIMBS must at least be able to contain the large discriminant
        let min_large_discriminant_bits = min_small_discriminant_bits + 2 * u32::from(k) * q.bits();
        if large_discriminant_bits < min_large_discriminant_bits {
            return Err(Error::InvalidPublicParameters);
        }

        let min_p_bits = min_small_discriminant_bits.saturating_sub(q.bits());
        let max_p_bits = large_discriminant_bits.saturating_sub((2 * u32::from(k) + 1) * q.bits());
        if max_p_bits < min_p_bits {
            return Err(Error::InvalidPublicParameters);
        }

        // Test if `p=1` can be selected
        if min_p_bits <= 1 {
            let params = Self::new(q, k, NonZero::ONE, computational_security_parameter);
            if params.is_ok() {
                return params;
            };
        }
        // `p=1` is invalid; we have to choose something larger.
        if max_p_bits <= 1 {
            return Err(Error::InvalidPublicParameters);
        }

        // Test if some small p can be selected
        if max_p_bits <= 9 {
            return FIRST_100_PRIMES
                .iter()
                .find_map(|candidate| {
                    // safe to unwrap; candidate is a non-zero prime.
                    let p = NonZero::new(Uint::<DELTA_K_LIMBS>::from(*candidate)).unwrap();
                    Self::new(q, k, p, computational_security_parameter).ok()
                })
                .ok_or(Error::InvalidPublicParameters);
        }

        // Attempt to sample a prime for the given bit-length
        const SAMPLE_ITERATIONS: u32 = 1000;
        for _ in 0..SAMPLE_ITERATIONS {
            let candidate = NonZero::<Uint<DELTA_K_LIMBS>>::new(crypto_primes::random_prime(
                rng,
                Flavor::Any,
                min_p_bits,
            ))
            .unwrap();
            let params = Self::new(q, k, candidate, computational_security_parameter);
            if params.is_ok() {
                return params;
            }
        }

        // Was not able to find a valid set of parameters
        Err(Error::InvalidPublicParameters)
    }
}

/// Obtain the minimum size of the discriminant for a given security level.
/// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
/// Table 2
pub(crate) const fn minimum_discriminant_bits(
    computational_security_bits: u32,
) -> Result<u32, Error> {
    if computational_security_bits <= 112 {
        Ok(1348)
    } else if computational_security_bits <= 128 {
        Ok(1827)
    } else {
        Err(Error::ComputationalSecurityTooHigh)
    }
}

#[derive(Serialize)]
pub struct CanonicalParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const DELTA_K_LIMBS: usize,
> where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<DELTA_K_LIMBS>: Encoding,
{
    q: NonZeroUint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    k: u8,
    p: NonZeroUint<DELTA_K_LIMBS>,
    computational_security_parameter: u32,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const DELTA_K_LIMBS: usize,
        const DELTA_QK_LIMBS: usize,
    > From<Parameters<PLAINTEXT_SPACE_SCALAR_LIMBS, DELTA_K_LIMBS, DELTA_QK_LIMBS>>
    for CanonicalParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, DELTA_K_LIMBS>
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Int<DELTA_K_LIMBS>: Encoding,
    Uint<DELTA_K_LIMBS>: Encoding,
    Int<DELTA_QK_LIMBS>: Encoding,
    Uint<DELTA_QK_LIMBS>: Encoding,
{
    fn from(
        value: Parameters<PLAINTEXT_SPACE_SCALAR_LIMBS, DELTA_K_LIMBS, DELTA_QK_LIMBS>,
    ) -> Self {
        Self {
            q: value.q,
            k: value.k,
            p: value.p,
            computational_security_parameter: value.computational_security_parameter,
        }
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const DELTA_K_LIMBS: usize,
        const DELTA_QK_LIMBS: usize,
    > Transcribeable for Parameters<PLAINTEXT_SPACE_SCALAR_LIMBS, DELTA_K_LIMBS, DELTA_QK_LIMBS>
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Int<DELTA_K_LIMBS>: Encoding,
    Uint<DELTA_K_LIMBS>: Encoding,
    Int<DELTA_QK_LIMBS>: Encoding,
    Uint<DELTA_QK_LIMBS>: Encoding,
{
    type CanonicalRepresentation = CanonicalParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, DELTA_K_LIMBS>;
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{NonZero, U1280, U1536, U2048, U256, U4096, U768};

    use group::{secp256k1, OsCsRng};

    use crate::parameters::Parameters;
    use crate::Error;

    // Some consts, making it easier to spot the difference in the tests.
    // Valid (q, k, p) triple, using SECP256K1;
    const Q: NonZero<U256> = NonZero::<U256>::new_unwrap(secp256k1::ORDER);
    const CSP: u32 = 112;
    const K: u8 = 1;
    const P: NonZero<U1536> = NonZero::<U1536>::new_unwrap(
        U1280::from_be_hex(concat![
            "00000000000000000000000000000000000000000000001EDEDF5FAD2F9DE421",
            "30493425D52F86F227E3A23D68DB7244AEA088426A8CE445DF899BA564471DF9",
            "52ADB8BB89F241752894B0114B8A42634FE831D89D50BDF4EF84E03E18E8EEA2",
            "091B876DDA7381AC2179394A890D661A4F681F064CAAAAC933A90F15846E6273",
            "E08AB871BB4447D7EFF23E2CCF5CED167B7F1E4836C09FA90799441217FF7CF3"
        ])
        .resize::<{ U1536::LIMBS }>(),
    );

    // Plaintext limbs
    const PTL: usize = U256::LIMBS;
    // Small discriminant limbs
    const SDL: usize = U1536::LIMBS;
    // Large discriminant limbs
    const LDL: usize = U2048::LIMBS;

    // ========================//
    // Test new_random_vartime //
    // ========================//

    #[test]
    fn test_new_random_vartime_success() {
        assert!(Parameters::<PTL, SDL, LDL>::new_random_vartime(Q, K, 112, &mut OsCsRng).is_ok());
    }

    #[test]
    fn test_new_random_vartime_lmv() {
        let large_q = NonZero::<U1536>::new_unwrap(U1536::from_be_hex(concat![
            "0000000000000000000000000000000000000000000366A3AA22C61AD3B92F64",
            "16274050E61DA17FD9B990D7E648363D282823380987B898A3003434D4955AEB",
            "957E58DF4762474AFD698EEB1E496D54F312171DFDD97098929E676450E9DB7C",
            "B52FFB54CB3D9325ADC994022984756C8DB36570D1525F2F8F17A9004F8C39C1",
            "811EBBFCAC4105B7BE66C884B3733BE21C3232EC910E8AF605D1E4C8BBF08425",
            "0BB7506EE7D25F5388B351084F4F2A436D6E2FDF376193B69B318ACB6C01758F"
        ]));
        let res =
            Parameters::<{ U1536::LIMBS }, { U1536::LIMBS }, { U4096::LIMBS }>::new_random_vartime(
                large_q,
                K,
                CSP,
                &mut OsCsRng,
            );
        assert!(res.is_ok());
        assert_eq!(res.unwrap().p, NonZero::ONE);
    }

    #[test]
    fn test_new_random_vartime_non_prime_q_errors() {
        let res =
            Parameters::<PTL, SDL, LDL>::new_random_vartime(NonZero::ONE, K, CSP, &mut OsCsRng);
        assert!(res.is_err());
        matches!(res.unwrap_err(), Error::InvalidPublicParameters);
    }

    #[test]
    fn test_new_random_vartime_non_unit_k_is_error() {
        let res = Parameters::<PTL, SDL, LDL>::new_random_vartime(Q, 0, CSP, &mut OsCsRng);
        assert!(res.is_err());
        matches!(res.unwrap_err(), Error::InvalidPublicParameters);
    }

    #[test]
    fn test_new_random_vartime_fundamental_discriminant_limbs_errors() {
        let res =
            Parameters::<PTL, SDL, { U1536::LIMBS }>::new_random_vartime(Q, K, CSP, &mut OsCsRng);
        assert!(res.is_err());
        matches!(res.unwrap_err(), Error::InvalidPublicParameters);
    }

    #[test]
    fn test_new_random_vartime_csp_too_high_errors() {
        let res = Parameters::<PTL, SDL, LDL>::new_random_vartime(Q, K, 128, &mut OsCsRng);
        assert!(res.is_err());
        matches!(res.unwrap_err(), Error::ComputationalSecurityTooHigh);
    }

    #[test]
    fn test_new_random_vartime_sdl_too_small_fails() {
        assert!(Parameters::<PTL, { U768::LIMBS }, LDL>::new_random_vartime(
            Q,
            K,
            112,
            &mut OsCsRng
        )
        .is_err());
    }

    #[test]
    fn test_new_random_vartime_ldl_too_small_fails() {
        assert!(
            Parameters::<PTL, SDL, { U1536::LIMBS }>::new_random_vartime(Q, K, 112, &mut OsCsRng)
                .is_err()
        );
    }

    // ==============//
    // Test validate //
    // ==============//

    #[test]
    fn test_validate_success() {
        let res = Parameters::<PTL, SDL, LDL>::validate_parameters(&Q, K, &P, 112);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_ldl_too_small_errors() {
        let res = Parameters::<PTL, SDL, { U1536::LIMBS }>::validate_parameters(&Q, K, &P, 112);
        assert!(res.is_err());
    }

    #[test]
    fn test_validate_p_too_small_errors() {
        assert!(
            Parameters::<PTL, SDL, SDL>::validate_parameters(&Q, K, &NonZero::ONE, 112).is_err()
        );
    }

    #[test]
    fn test_validate_k_is_zero_errors() {
        assert!(Parameters::<PTL, SDL, LDL>::validate_parameters(&Q, 0, &P, 112).is_err());
    }

    #[test]
    fn test_validate_csp_too_high_fails() {
        assert!(Parameters::<PTL, SDL, LDL>::validate_parameters(&Q, K, &P, 128).is_err());
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::measurement::WallTime;
    use criterion::{BenchmarkGroup, Criterion};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;

    use group::CsRng;

    use crate::parameters::Parameters;
    use crate::{
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_SCALAR_LIMBS,
    };

    /// Benchmark the time it takes to execute `Parameters::h` for the `SECP256K1` message space.
    pub fn benchmark_secp256k1_h(g: &mut BenchmarkGroup<WallTime>, rng: &mut impl CsRng) {
        let q = group::secp256k1::ORDER.to_nz().unwrap();
        let class_group_parameters = Parameters::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::new_random_vartime(q, 1, 112, rng)
        .unwrap();

        g.bench_function("h", |b| b.iter(|| class_group_parameters.h(rng)));
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let mut rng = ChaChaRng::seed_from_u64(123456789u64);
        benchmark_secp256k1_h(&mut _c.benchmark_group("parameters/secp256k1"), &mut rng);
    }
}
