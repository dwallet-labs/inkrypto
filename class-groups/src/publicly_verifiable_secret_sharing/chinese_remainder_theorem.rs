// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::array;
use std::collections::HashMap;
use std::marker::PhantomData;

use crypto_bigint::subtle::{ConditionallySelectable, ConstantTimeLess};
use crypto_bigint::{CheckedSub, ConstChoice, Int, Limb, NonZero, Uint};
#[cfg(feature = "parallel")]
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub use consts::*;
use group::bounded_natural_numbers_group::MAURER_PROOFS_DIFF_UPPER_BOUND_BITS;
use group::helpers::{DeduplicateAndSort, FlatMapResults};
use group::{bounded_natural_numbers_group, CsRng, GroupElement, PartyID};
use maurer::{fischlin, knowledge_of_discrete_log, UC_PROOFS_REPETITIONS};
use mpc::secret_sharing::shamir::over_the_integers::find_closest_crypto_bigint_size;
use mpc::{HandleInvalidMessages, SeedableCollection};
use proof::GroupsPublicParametersAccessors;

use crate::decryption_key_share::PartialDecryptionProof;
use crate::setup::DeriveFromPlaintextPublicParameters;
use crate::setup::SetupParameters;
use crate::{
    decryption_key_share, encryption_key, equivalence_class, CompactIbqf, DecryptionKey,
    DecryptionKeyShare, EncryptionKey, EquivalenceClass, Error, Result,
};

mod consts;

pub const NUM_SECRET_SHARE_PRIMES: usize = MAX_PRIMES;
pub const SECRET_SHARE_CRT_PRIMES_PRODUCT: CRTReconstructionSizedNumber = CRT_PRIMES_PRODUCT;
pub const SECRET_SHARE_CRT_COEFFICIENTS: [CRTCoefficientSizedNumber; NUM_SECRET_SHARE_PRIMES] =
    CRT_COEFFICIENTS;

pub const CRT_COEFFICIENT_BITS: u32 = CRTPrimeSizedNumber::BITS * MAX_PRIMES as u32;
pub const CRT_COEFFICIENT_LIMBS: usize =
    find_closest_crypto_bigint_size(CRT_COEFFICIENT_BITS as usize) / Limb::BITS as usize;
pub const CRT_RECONSTRUCTION_BITS: u32 =
    (CRTPrimeSizedNumber::BITS + CRT_COEFFICIENT_BITS) + MAX_PRIMES.ilog2() + 1;
pub const CRT_RECONSTRUCTION_LIMBS: usize =
    find_closest_crypto_bigint_size(CRT_RECONSTRUCTION_BITS as usize) / Limb::BITS as usize;

pub const CRT_DECRYPTION_KEY_WITNESS_LIMBS: usize = find_closest_crypto_bigint_size(
    ({ Uint::<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>::BITS } + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS)
        as usize,
) / Limb::BITS as usize;

pub type SecretKeyShareCRTPrimeGroupElement = group::additive::PrimeGroupElement<CRT_PRIME_LIMBS>;

pub type SecretKeyShareCRTPrimePublicParameters =
    group::additive::PrimePublicParameters<CRT_PRIME_LIMBS>;

pub type SecretKeyShareCRTPrimeSetupParameters = SetupParameters<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimePublicParameters,
>;

pub type SecretKeyShareCRTPrimeEncryptionSchemePublicParameters = encryption_key::PublicParameters<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimePublicParameters,
>;

pub type SecretKeyShareCRTPrimeEncryptionKey = EncryptionKey<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimeGroupElement,
>;

pub type SecretKeyShareCRTPrimeDecryptionKey = DecryptionKey<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimeGroupElement,
>;

pub type SecretKeyShareCRTPrimeDecryptionKeyShare = DecryptionKeyShare<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimeGroupElement,
>;

pub type SecretKeyShareCRTPrimeDecryptionKeySharePublicParameters =
    decryption_key_share::PublicParameters<
        CRT_PRIME_LIMBS,
        CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SecretKeyShareCRTPrimePublicParameters,
    >;

pub type SecretKeyShareCRTPrimePartialDecryptionProof =
    PartialDecryptionProof<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;

pub type SecretKeyShareCRTPrimeDecryptionShare =
    CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;

/// The knowledge of discrete log UC-secure Fischlin proof used to prove valid encryption keys.
pub type KnowledgeOfDiscreteLogUCProof = maurer::fischlin::Proof<
    UC_PROOFS_REPETITIONS,
    knowledge_of_discrete_log::FischlinLanguage<
        UC_PROOFS_REPETITIONS,
        bounded_natural_numbers_group::GroupElement<CRT_DECRYPTION_KEY_WITNESS_LIMBS>,
        EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    PhantomData<()>,
>;

/// The public parameters of the knowledge of discrete log UC-secure Fischlin proof used to prove valid encryption keys.
pub type KnowledgeOfDiscreteLogUCPublicParameters = knowledge_of_discrete_log::PublicParameters<
    bounded_natural_numbers_group::PublicParameters<CRT_DECRYPTION_KEY_WITNESS_LIMBS>,
    equivalence_class::PublicParameters<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
>;

pub type CRTPrimeSizedNumber = Uint<CRT_PRIME_LIMBS>;
pub type CRTCoefficientSizedNumber = Uint<CRT_COEFFICIENT_LIMBS>;
pub type CRTReconstructionSizedNumber = Uint<CRT_RECONSTRUCTION_LIMBS>;

/// Perform Chinese Remainder Theorem (CRT) reconstruction.
pub fn reconstruct<const NUM_PRIMES: usize>(
    crt_coefficients: [CRTCoefficientSizedNumber; NUM_PRIMES],
    crt_primes_product: CRTReconstructionSizedNumber,
    secret_modulo_crt_primes: [CRTPrimeSizedNumber; NUM_PRIMES],
) -> CRTReconstructionSizedNumber {
    debug_assert!(NUM_PRIMES != 0 && NUM_PRIMES <= MAX_PRIMES);

    // Safe to dereference & unwrap, as the arrays are the same, non-empty size (`NUM_PRIMES`).
    let share: CRTReconstructionSizedNumber = secret_modulo_crt_primes
        .into_iter()
        .enumerate()
        .map(|(i, share_modulo_crt_prime)| {
            CRTReconstructionSizedNumber::from(&share_modulo_crt_prime)
                .wrapping_mul(&crt_coefficients[i])
        })
        .reduce(|a, b| a.wrapping_add(&b))
        .unwrap();

    share % NonZero::new(crt_primes_product).unwrap()
}

pub fn reconstruct_integer<const NUM_PRIMES: usize, const SECRET_LIMBS: usize>(
    crt_coefficients: [CRTCoefficientSizedNumber; NUM_PRIMES],
    crt_primes_product: CRTReconstructionSizedNumber,
    secret_modulo_crt_primes: [CRTPrimeSizedNumber; NUM_PRIMES],
) -> Result<Int<SECRET_LIMBS>> {
    let secret_positive = reconstruct(
        crt_coefficients,
        crt_primes_product,
        secret_modulo_crt_primes,
    );

    let secret = Int::new_from_abs_sign(secret_positive, ConstChoice::FALSE).unwrap();
    let crt_primes_product =
        Int::new_from_abs_sign(crt_primes_product, ConstChoice::FALSE).unwrap();

    // Should never overflow by choice of parameters
    let secret_negative = secret
        .checked_sub(&crt_primes_product)
        .into_option()
        .ok_or(Error::InternalError)?;

    let secret = <Int<CRT_RECONSTRUCTION_LIMBS> as ConditionallySelectable>::conditional_select(
        &secret,
        &secret_negative,
        secret_negative.abs().ct_lt(&secret_positive),
    );

    // Safe to resize now, since we picked the smaller one, which is guaranteed to be of the requested size.
    Ok(Int::<SECRET_LIMBS>::from(&secret))
}

pub fn construct_setup_parameters_per_crt_prime(
    computational_security_parameter: u32,
) -> Result<[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES]> {
    CRT_PRIMES
        .map(|prime| {
            let plaintext_space_parameters = SecretKeyShareCRTPrimePublicParameters::new(prime)?;

            SecretKeyShareCRTPrimeSetupParameters::derive_from_plaintext_parameters::<
                SecretKeyShareCRTPrimeGroupElement,
            >(plaintext_space_parameters, computational_security_parameter)
        })
        .flat_map_results()
}

pub fn generate_keypairs_per_crt_prime(
    setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    rng: &mut impl CsRng,
) -> Result<[Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]> {
    setup_parameters_per_crt_prime
        .map(|setup_parameters| {
            SecretKeyShareCRTPrimeDecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                rng,
            )
            .map(|(_, decryption_key)| decryption_key.decryption_key)
        })
        .flat_map_results()
}

pub fn construct_knowledge_of_decryption_key_public_parameters(
    base: CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    discrete_log_sample_bits: u32,
    equivalence_class_public_parameters: group::PublicParameters<
        EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
) -> crate::Result<KnowledgeOfDiscreteLogUCPublicParameters> {
    if fischlin::target_bits::<UC_PROOFS_REPETITIONS>() > 10 {
        // For security we need to have small challenges. Refer to paper: https://eprint.iacr.org/2024/717.pdf
        return Err(Error::InternalError);
    }

    let witness_group_public_parameters = bounded_natural_numbers_group::PublicParameters::<
        CRT_DECRYPTION_KEY_WITNESS_LIMBS,
    >::new_with_randomizer_upper_bound(
        discrete_log_sample_bits
    )?;

    let discrete_log_sample_bits = Some(witness_group_public_parameters.sample_bits);
    let language_public_parameters = knowledge_of_discrete_log::PublicParameters::new::<
        bounded_natural_numbers_group::GroupElement<CRT_DECRYPTION_KEY_WITNESS_LIMBS>,
        EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >(
        witness_group_public_parameters,
        equivalence_class_public_parameters,
        base,
        discrete_log_sample_bits,
    );

    Ok(language_public_parameters)
}

pub fn construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
    setup_parameters_per_crt_prime: [&SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
) -> crate::Result<[KnowledgeOfDiscreteLogUCPublicParameters; MAX_PRIMES]> {
    setup_parameters_per_crt_prime
        .map(|setup_parameters| {
            construct_knowledge_of_decryption_key_public_parameters(
                setup_parameters.h.value(),
                setup_parameters.decryption_key_bits(),
                setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
            )
        })
        .flat_map_results()
}

/// Implements Protocol F.1 Step 4.
pub fn generate_knowledge_of_decryption_key_proofs_per_crt_prime(
    language_public_parameters_per_crt_prime: [KnowledgeOfDiscreteLogUCPublicParameters;
        MAX_PRIMES],
    decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    rng: &mut impl CsRng,
) -> Result<
    [(
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        KnowledgeOfDiscreteLogUCProof,
    ); MAX_PRIMES],
> {
    let seeded_indices = (0..MAX_PRIMES).seed(rng);
    #[cfg(not(feature = "parallel"))]
    let iter = seeded_indices.into_iter();
    #[cfg(feature = "parallel")]
    let iter = seeded_indices.into_par_iter();

    let encryption_keys_and_proofs = iter
        .map(|(i, mut unique_rng)| {
            let language_public_parameters = &language_public_parameters_per_crt_prime[i];
            let decryption_key = bounded_natural_numbers_group::GroupElement::new(
                Uint::from(&decryption_key_per_crt_prime[i]),
                language_public_parameters.witness_space_public_parameters(),
            )?;

            let (proof, encryption_key) = KnowledgeOfDiscreteLogUCProof::prove(
                // Don't need a protocol context for this specific proof.
                &PhantomData,
                language_public_parameters,
                decryption_key,
                &mut unique_rng,
            )?;

            Ok::<_, Error>((encryption_key.value(), proof))
        })
        .collect::<Result<Vec<_>>>()?;

    encryption_keys_and_proofs
        .try_into()
        .map_err(|_| Error::InternalError)
}

pub(super) fn instantiate_encryption_keys_per_crt_prime(
    setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    encryption_key_values_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
) -> Result<(
    Vec<PartyID>,
    HashMap<
        PartyID,
        [(
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
)> {
    Ok(encryption_key_values_and_proofs_per_crt_prime
        .into_iter()
        .map(|(party_id, encryption_key_values_and_proofs)| {
            let encryption_keys_and_proofs = array::from_fn(|i| {
                // Safe to derefernce as these are same-sized arrays.
                let (encryption_key_value, proof) = encryption_key_values_and_proofs[i].clone();

                <EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> as group::GroupElement>::new(
                    encryption_key_value,
                    setup_parameters_per_crt_prime[i].equivalence_class_public_parameters(),
                )
                    .map(|encryption_key| (encryption_key, proof))
            })
                .flat_map_results();

            (party_id, encryption_keys_and_proofs)
        })
        .handle_invalid_messages_async())
}

pub fn verify_knowledge_of_decryption_key_proofs(
    language_public_parameters_per_crt_prime: [KnowledgeOfDiscreteLogUCPublicParameters;
        MAX_PRIMES],
    parties_without_valid_encryption_keys: Vec<PartyID>,
    encryption_keys_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
) -> Result<(
    Vec<PartyID>,
    HashMap<PartyID, [EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
)> {
    #[cfg(not(feature = "parallel"))]
    let iter = encryption_keys_and_proofs_per_crt_prime.iter();
    #[cfg(feature = "parallel")]
    let iter = encryption_keys_and_proofs_per_crt_prime.par_iter();

    let parties_sending_invalid_proofs: Vec<PartyID> = iter
        .filter(|(_, encryption_keys_and_proofs)| {
            encryption_keys_and_proofs
                .iter()
                .zip(language_public_parameters_per_crt_prime.iter())
                .any(|((encryption_key, proof), language_public_parameters)| {
                    proof
                        .verify(&PhantomData, language_public_parameters, *encryption_key)
                        .is_err()
                })
        })
        .map(|(party_id, _)| *party_id)
        .collect();

    // Add both the parties that sent invalid statements and malicious proof to the malicious parties list, and filter out their messages.
    let malicious_parties: Vec<PartyID> = parties_without_valid_encryption_keys
        .into_iter()
        .chain(parties_sending_invalid_proofs)
        .deduplicate_and_sort();

    let encryption_keys_and_proofs_per_crt_prime: HashMap<_, _> =
        encryption_keys_and_proofs_per_crt_prime
            .into_iter()
            .filter(|(party_id, _)| !malicious_parties.contains(party_id))
            .collect();

    let crt_primes_encryption_keys = encryption_keys_and_proofs_per_crt_prime
        .into_iter()
        .map(|(party_id, encryption_keys_and_proofs)| {
            (
                party_id,
                encryption_keys_and_proofs.map(|(encryption_key, _)| encryption_key),
            )
        })
        .collect();

    Ok((malicious_parties, crt_primes_encryption_keys))
}

#[cfg(test)]
mod tests {
    use crypto_bigint::RandomMod;

    use group::{OsCsRng, Reduce};
    use mpc::secret_sharing::shamir::over_the_integers::{
        secret_key_share_size_upper_bound, MAX_PLAYERS,
    };

    use crate::{SecretKeyShareSizedNumber, DECRYPTION_KEY_BITS_112BIT_SECURITY, MAX_THRESHOLD};

    use super::*;

    #[test]
    fn crt_reconstructs() {
        let crt_primes_product = CRT_PRIMES
            .iter()
            .map(CRTReconstructionSizedNumber::from)
            .reduce(|a, b| a.checked_mul(&b).unwrap())
            .unwrap();

        assert_eq!(
            crt_primes_product,
            CRTReconstructionSizedNumber::from(&CRT_PRIMES_PRODUCT),
            "CRT Primes product computed incorrectly"
        );

        let crt_primes_product = CRT_PRIMES
            .iter()
            .take(NUM_SECRET_SHARE_PRIMES)
            .map(CRTReconstructionSizedNumber::from)
            .reduce(|a, b| a.checked_mul(&b).unwrap())
            .unwrap();

        assert_eq!(
            crt_primes_product,
            CRTReconstructionSizedNumber::from(&SECRET_SHARE_CRT_PRIMES_PRODUCT),
            "CRT Primes product computed incorrectly"
        );

        let secret = SecretKeyShareSizedNumber::random_mod(
            &mut OsCsRng,
            &NonZero::new(SecretKeyShareSizedNumber::ONE.shl_vartime(
                secret_key_share_size_upper_bound(
                    MAX_PLAYERS,
                    MAX_THRESHOLD,
                    DECRYPTION_KEY_BITS_112BIT_SECURITY,
                ),
            ))
            .unwrap(),
        );

        let secret_modulo_crt_primes =
            array::from_fn(|i| secret.reduce(&NonZero::new(CRT_PRIMES[i]).unwrap()));

        let reconstructed_secret = SecretKeyShareSizedNumber::from(&reconstruct(
            SECRET_SHARE_CRT_COEFFICIENTS,
            SECRET_SHARE_CRT_PRIMES_PRODUCT,
            secret_modulo_crt_primes,
        ));

        assert_eq!(
            secret, reconstructed_secret,
            "CRT reconstruction should yield the original secret"
        );
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::hint::black_box;
    use std::time::Duration;

    use criterion::{BatchSize, Criterion};
    use crypto_bigint::Random;

    use group::{OsCsRng, Samplable};
    use homomorphic_encryption::GroupsPublicParametersAccessors;

    use crate::equivalence_class::EquivalenceClassOps;
    use crate::{RandomnessSpaceGroupElement, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER};

    use super::*;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let mut group = _c.benchmark_group("crt");
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));
        group.sample_size(10);

        let group = &mut group;

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();
        let setup_parameters = setup_parameters_per_crt_prime[0].clone();
        let (pp, decryption_key) =
            SecretKeyShareCRTPrimeDecryptionKey::generate_with_setup_parameters(
                setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();
        let encryption_key = decryption_key.encryption_key;

        group.bench_function("equivalence class mul (ct)", |b| {
            b.iter_batched(
                || {
                    let randomness = RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value();

                    let a = setup_parameters.h.pow_vartime(&randomness);
                    let b = setup_parameters.h.pow_vartime(&randomness);

                    (a, b)
                },
                |(a, b)| {
                    let res = a.mul(&b).unwrap();
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class mul (rt)", |b| {
            b.iter_batched(
                || {
                    let randomness = RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value();

                    let a = setup_parameters.h.pow_vartime(&randomness);
                    let b = setup_parameters.h.pow_vartime(&randomness);

                    (a, b)
                },
                |(a, b)| {
                    let res = a.mul_randomized(&b).unwrap();
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class mul (vt)", |b| {
            b.iter_batched(
                || {
                    let randomness = RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value();

                    let a = setup_parameters.h.pow_vartime(&randomness);
                    let b = setup_parameters.h.pow_vartime(&randomness);

                    (a, b)
                },
                |(a, b)| {
                    let res = a.mul_vartime(&b).unwrap();
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class pow (ct)", |b| {
            b.iter_batched(
                || {
                    RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value()
                },
                |randomness| {
                    let res = setup_parameters.h.pow_bounded(
                        &randomness,
                        pp.randomness_space_public_parameters().sample_bits,
                    );
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class pow (rt)", |b| {
            b.iter_batched(
                || {
                    RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value()
                },
                |randomness| {
                    let res = setup_parameters.h.pow_bounded_randomized(
                        &randomness,
                        pp.randomness_space_public_parameters().sample_bits,
                    );
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class pow (vt)", |b| {
            b.iter_batched(
                || {
                    RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value()
                },
                |randomness| {
                    let res = setup_parameters.h.pow_vartime(&randomness);
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        let m = NonZero::random(&mut OsCsRng);
        group.bench_function("power_of_f", |b| {
            b.iter(|| {
                black_box(SecretKeyShareCRTPrimeEncryptionKey::power_of_f(
                    &m,
                    &pp.setup_parameters.class_group_parameters,
                ))
            })
        });

        SecretKeyShareCRTPrimeEncryptionKey::benchmark_pow_h(group, &pp);
        SecretKeyShareCRTPrimeEncryptionKey::benchmark_pow_pk(group, &pp);

        SecretKeyShareCRTPrimeEncryptionKey::benchmark_encrypt(group, &encryption_key, &pp);
    }
}
