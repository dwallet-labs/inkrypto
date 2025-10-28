// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#[cfg(any(test, feature = "test_helpers"))]
mod test_helpers {
    use std::iter;

    use crypto_bigint::{Uint, U256};

    use class_groups::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use class_groups::{
        Secp256k1DecryptionKey, Secp256k1EncryptionKey, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_MESSAGE_LIMBS,
    };
    use group::{bounded_natural_numbers_group, secp256k1, GroupElement, OsCsRng, Samplable};
    use homomorphic_encryption::{
        AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors,
    };
    use maurer::language;
    use maurer::SOUND_PROOFS_REPETITIONS;

    use maurer::extended_encryption_of_tuple::{Language, PublicParameters};

    pub(crate) type ClassGroupsLang = Language<
        2,
        { U256::LIMBS },
        { U256::LIMBS },
        SECP256K1_MESSAGE_LIMBS,
        secp256k1::GroupElement,
        Secp256k1EncryptionKey,
    >;

    pub(crate) fn generate_witnesses_class_groups(
        language_public_parameters: &language::PublicParameters<
            SOUND_PROOFS_REPETITIONS,
            ClassGroupsLang,
        >,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>> {
        iter::repeat_with(|| {
            let multiplicand = secp256k1::Scalar::sample(
                &language_public_parameters.scalar_group_public_parameters,
                &mut OsCsRng,
            )
            .unwrap();

            let multiplicand = bounded_natural_numbers_group::GroupElement::new(
                Uint::<SECP256K1_MESSAGE_LIMBS>::from(&U256::from(&multiplicand.value())),
                language_public_parameters.message_group_public_parameters(),
            )
            .unwrap();

            let randomness = class_groups::RandomnessSpaceGroupElement::<
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsCsRng,
            )
            .unwrap();

            let first_second_randomness = class_groups::RandomnessSpaceGroupElement::<
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsCsRng,
            )
            .unwrap();

            let second_second_randomness = class_groups::RandomnessSpaceGroupElement::<
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsCsRng,
            )
            .unwrap();

            (
                multiplicand,
                randomness,
                [first_second_randomness, second_second_randomness].into(),
            )
                .into()
        })
        .take(batch_size)
        .collect()
    }

    pub(crate) fn class_groups_language_public_parameters(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, ClassGroupsLang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (encryption_scheme_public_parameters, _) =
            Secp256k1DecryptionKey::generate_with_setup_parameters(setup_parameters, &mut OsCsRng)
                .unwrap();

        let encryption_key = <Secp256k1EncryptionKey as AdditivelyHomomorphicEncryptionKey<
            { secp256k1::SCALAR_LIMBS },
        >>::new(&encryption_scheme_public_parameters)
        .unwrap();
        let (_, first_ciphertext) = encryption_key
            .encrypt(
                &secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsCsRng)
                    .unwrap(),
                &encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();
        let (_, second_ciphertext) = encryption_key
            .encrypt(
                &secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsCsRng)
                    .unwrap(),
                &encryption_scheme_public_parameters,
                true,
                &mut OsCsRng,
            )
            .unwrap();
        let upper_bound = secp256k1::ORDER;

        PublicParameters::<
            2,
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            SECP256K1_MESSAGE_LIMBS,
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, Secp256k1EncryptionKey>(
            secp256k1_scalar_public_parameters,
            encryption_scheme_public_parameters,
            [first_ciphertext.value(), second_ciphertext.value()],
            Uint::from(&upper_bound),
        )
        .unwrap()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::marker::PhantomData;

    use rstest::rstest;

    use group::OsCsRng;

    use crate::extended_encryption_of_tuple::test_helpers::*;

    use maurer::SOUND_PROOFS_REPETITIONS;

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn valid_proof_verifies_class_groups(#[case] batch_size: usize) {
        let language_public_parameters = class_groups_language_public_parameters();

        let witnesses = generate_witnesses_class_groups(&language_public_parameters, batch_size);

        let (proof, statements) =
            maurer::Proof::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang, PhantomData<()>>::prove(
                &PhantomData,
                &language_public_parameters,
                witnesses,
                &mut OsCsRng,
            )
            .unwrap();

        assert!(
            proof
                .verify(&PhantomData, &language_public_parameters, statements)
                .is_ok(),
            "valid proofs should verify"
        );
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;
    use crypto_bigint::{Random, U256};

    use group::{GroupElement, LinearlyCombinable, OsCsRng};
    use maurer::language::StatementSpaceGroupElement;
    use maurer::{Language, SOUND_PROOFS_REPETITIONS};

    use crate::extended_encryption_of_tuple::test_helpers::*;

    pub(crate) fn benchmark(c: &mut Criterion) {
        let language_public_parameters = class_groups_language_public_parameters();

        let witness = generate_witnesses_class_groups(&language_public_parameters, 1)[0];

        let statement =
            ClassGroupsLang::homomorphose(&witness, &language_public_parameters, false, false)
                .unwrap();
        let challenge = U256::random(&mut OsCsRng);
        let mut g = c.benchmark_group("Linear Combination in statement space of encdh");

        g.bench_function("single exponentiation", |bench| {
            bench.iter(|| statement.scale(&challenge));
        });

        for batch_size in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            let bases_and_multiplicands = vec![(statement, challenge); batch_size];

            g.bench_function(
                format!("{batch_size} elements"),
                |bench| {
                    bench.iter(|| {
                        StatementSpaceGroupElement::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>::linearly_combine(
                            bases_and_multiplicands.clone()
                        ).unwrap()
                    });
                },
            );
        }

        g.finish();

        maurer::test_helpers::benchmark_proof_internal::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>(
            &language_public_parameters,
            None,
            false,
            None,
            witness,
        );
    }
}
