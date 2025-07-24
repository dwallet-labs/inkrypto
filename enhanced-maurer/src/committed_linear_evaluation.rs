// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(clippy::type_complexity)]

use std::array;

use crypto_bigint::Uint;

use group::{
    bounded_natural_numbers_group, direct_product, helpers::FlatMapResults, self_product,
    GroupElement, KnownOrderGroupElement,
};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use maurer::committed_linear_evaluation::*;
use maurer::SOUND_PROOFS_REPETITIONS;

use crate::{language::DecomposableWitness, EnhanceableLanguage};

impl<
        const NUM_RANGE_CLAIMS: usize,
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
    >
    EnhanceableLanguage<
        SOUND_PROOFS_REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            tiresias::RandomnessSpaceGroupElement,
        >,
    >
    for Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        tiresias::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        unbounded_witness: direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            tiresias::RandomnessSpaceGroupElement,
        >,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<Self::WitnessSpaceGroupElement> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        if NUM_RANGE_CLAIMS != RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        let mut decomposed_witness = decomposed_witness.into_iter();

        let coefficients: [[_; RANGE_CLAIMS_PER_SCALAR]; DIMENSION] = array::from_fn(|_| {
            array::from_fn(|_| {
                decomposed_witness
                    .next()
                    .ok_or(maurer::Error::InvalidPublicParameters)
            })
            .flat_map_results()
        })
        .flat_map_results()?;

        let coefficients = coefficients
            .map(|coefficient| {
                let coefficient = <tiresias::PlaintextSpaceGroupElement as DecomposableWitness<
                    RANGE_CLAIMS_PER_SCALAR,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
                >>::compose(
                    &coefficient,
                    language_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                    range_claim_bits,
                );

                coefficient.and_then(|coefficient| {
                    Ok(bounded_natural_numbers_group::GroupElement::new(
                        coefficient.value(),
                        language_public_parameters.message_group_public_parameters(),
                    )?)
                })
            })
            .flat_map_results()?
            .into();

        let mask: [_; RANGE_CLAIMS_PER_MASK] = array::from_fn(|_| {
            decomposed_witness
                .next()
                .ok_or(maurer::Error::InvalidParameters)
        })
        .flat_map_results()?;

        let mask = <tiresias::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_MASK,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            &mask,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        let (commitment_randomness, encryption_randomness) = unbounded_witness.into();

        Ok((
            coefficients,
            commitment_randomness,
            mask,
            encryption_randomness,
        )
            .into())
    }

    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; NUM_RANGE_CLAIMS],
        direct_product::GroupElement<
            self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
            tiresias::RandomnessSpaceGroupElement,
        >,
    )> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, GroupElement::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        if NUM_RANGE_CLAIMS != (RANGE_CLAIMS_PER_SCALAR * DIMENSION + RANGE_CLAIMS_PER_MASK) {
            return Err(maurer::Error::InvalidPublicParameters);
        }

        let (coefficients, commitment_randomness, mask, encryption_randomness) = witness.into();

        let coefficients: [_; DIMENSION] = coefficients.into();

        let range_proof_commitment_message = coefficients
            .map(|coefficient| {
                Ok(tiresias::PlaintextSpaceGroupElement::new(
                    coefficient.value(),
                    language_public_parameters
                        .encryption_scheme_public_parameters
                        .plaintext_space_public_parameters(),
                )?)
            })
            .map(|coefficient| {
                coefficient.and_then(|coefficient| coefficient.decompose(range_claim_bits))
            })
            .flat_map_results()?
            .into_iter()
            .flat_map(<[_; RANGE_CLAIMS_PER_SCALAR]>::from);

        let decomposed_mask: [_; RANGE_CLAIMS_PER_MASK] = mask.decompose(range_claim_bits)?;

        let range_proof_commitment_message: Vec<_> = range_proof_commitment_message
            .chain(decomposed_mask)
            .collect();

        let range_proof_commitment_message: [_; NUM_RANGE_CLAIMS] =
            range_proof_commitment_message.try_into().ok().unwrap();

        Ok((
            range_proof_commitment_message,
            (commitment_randomness, encryption_randomness).into(),
        ))
    }
}

pub type Proof<
    const NUM_RANGE_CLAIMS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    ProtocolContext,
> = crate::Proof<
    SOUND_PROOFS_REPETITIONS,
    NUM_RANGE_CLAIMS,
    MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

#[cfg(test)]
pub(crate) mod tests {
    use core::iter;
    use std::collections::HashMap;

    use class_groups::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use class_groups::{
        Secp256k1DecryptionKey, Secp256k1EncryptionKey, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };
    use commitment::pedersen;
    use crypto_bigint::{Random, U256, U64};
    use group::{
        secp256k1, ComputationalSecuritySizedNumber, PartyID, Samplable,
        StatisticalSecuritySizedNumber,
    };
    use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
    use maurer::language;
    use mpc::Weight;
    use proof::range::{bulletproofs, bulletproofs::RANGE_CLAIM_BITS};
    use rand_core::OsRng;
    use rstest::rstest;
    use std::marker::PhantomData;
    use tiresias::test_helpers::N;

    use crate::{
        aggregation::tests::setup_aggregation,
        language::tests::{generate_scalar_plaintext, RANGE_CLAIMS_PER_SCALAR},
    };

    use super::*;

    pub(crate) const MASK_LIMBS: usize =
        secp256k1::SCALAR_LIMBS + StatisticalSecuritySizedNumber::LIMBS + U64::LIMBS;

    pub(crate) const DIMENSION: usize = 2;

    pub(crate) const RANGE_CLAIMS_PER_MASK: usize =
        Uint::<MASK_LIMBS>::BITS as usize / bulletproofs::RANGE_CLAIM_BITS;

    pub(crate) const NUM_RANGE_CLAIMS: usize =
        DIMENSION * RANGE_CLAIMS_PER_SCALAR + RANGE_CLAIMS_PER_MASK;

    pub type Lang = Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { secp256k1::SCALAR_LIMBS },
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { RANGE_CLAIMS_PER_SCALAR },
        { RANGE_CLAIMS_PER_MASK },
        { DIMENSION },
        secp256k1::GroupElement,
        tiresias::EncryptionKey,
    >;

    const MESSAGE_LIMBS: usize = {
        U256::LIMBS
            + ComputationalSecuritySizedNumber::LIMBS
            + StatisticalSecuritySizedNumber::LIMBS
            + ComputationalSecuritySizedNumber::LIMBS
            + U64::LIMBS
            + U64::LIMBS
    };

    pub type ClassGroupsLang = Language<
        { U256::LIMBS },
        { U256::LIMBS },
        MESSAGE_LIMBS,
        { RANGE_CLAIMS_PER_SCALAR },
        { RANGE_CLAIMS_PER_MASK },
        { DIMENSION },
        secp256k1::GroupElement,
        Secp256k1EncryptionKey,
    >;

    pub(crate) fn public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
    {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let paillier_encryption_key =
            tiresias::EncryptionKey::new(&paillier_public_parameters).unwrap();

        let upper_bound = Uint::<{ tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS }>::from(
            u64::try_from(RANGE_CLAIMS_PER_SCALAR * RANGE_CLAIM_BITS).unwrap(),
        );

        let ciphertexts_and_encoded_messages_upper_bounds =
            array::from_fn(|_| (&U256::random(&mut OsRng)).into())
                .map(|plaintext| {
                    tiresias::PlaintextSpaceGroupElement::new(
                        plaintext,
                        paillier_public_parameters.plaintext_space_public_parameters(),
                    )
                    .unwrap()
                })
                .map(|plaintext| {
                    let ciphertext = paillier_encryption_key
                        .encrypt(&plaintext, &paillier_public_parameters, &mut OsRng)
                        .unwrap()
                        .1
                        .value();

                    (ciphertext, upper_bound)
                });

        let pedersen_public_parameters = pedersen::PublicParameters::derive::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
        )
        .unwrap()
        .into();

        PublicParameters::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { DIMENSION },
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
        >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, tiresias::EncryptionKey>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            paillier_public_parameters,
            pedersen_public_parameters,
            ciphertexts_and_encoded_messages_upper_bounds,
            Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS,
        )
        .unwrap()
    }

    pub(crate) fn class_groups_language_public_parameters(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, ClassGroupsLang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (encryption_scheme_public_parameters, _) =
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

        let encryption_key = <Secp256k1EncryptionKey as AdditivelyHomomorphicEncryptionKey<
            { secp256k1::SCALAR_LIMBS },
        >>::new(&encryption_scheme_public_parameters)
        .unwrap();

        let first_message_to_encrypt =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();
        let (_, first_ciphertext) = encryption_key
            .encrypt(
                &first_message_to_encrypt,
                &encryption_scheme_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        let second_message_to_encrypt =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();
        let (_, second_ciphertext) = encryption_key
            .encrypt(
                &second_message_to_encrypt,
                &encryption_scheme_public_parameters,
                &mut OsRng,
            )
            .unwrap();

        let upper_bound = secp256k1::ORDER;

        let pedersen_public_parameters = pedersen::PublicParameters::derive::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters.clone(),
        )
        .unwrap()
        .into();

        PublicParameters::<
            { secp256k1::SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            MESSAGE_LIMBS,
            { DIMENSION },
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >::new::<{ secp256k1::SCALAR_LIMBS }, secp256k1::GroupElement, Secp256k1EncryptionKey>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            encryption_scheme_public_parameters,
            pedersen_public_parameters,
            [
                (first_ciphertext.value(), Uint::from(&upper_bound)),
                (second_ciphertext.value(), Uint::from(&upper_bound)),
            ],
            Uint::<{ secp256k1::SCALAR_LIMBS }>::BITS,
        )
        .unwrap()
    }

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let coefficients = array::from_fn(|_| {
                bounded_natural_numbers_group::GroupElement::new(
                    generate_scalar_plaintext().value(),
                    language_public_parameters.message_group_public_parameters(),
                )
                .unwrap()
            })
            .into();

            let first_commitment_randomness = secp256k1::Scalar::sample(
                language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let second_commitment_randomness = secp256k1::Scalar::sample(
                language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let mask = Uint::<MASK_LIMBS>::random(&mut OsRng);
            let mask = tiresias::PlaintextSpaceGroupElement::new(
                (&mask).into(),
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            )
            .unwrap();

            let encryption_randomness = tiresias::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (
                coefficients,
                [first_commitment_randomness, second_commitment_randomness].into(),
                mask,
                encryption_randomness,
            )
                .into()
        })
        .take(batch_size)
        .collect()
    }

    fn generate_witnesses_class_groups(
        language_public_parameters: &language::PublicParameters<
            SOUND_PROOFS_REPETITIONS,
            ClassGroupsLang,
        >,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>> {
        iter::repeat_with(|| {
            let coefficients = array::from_fn(|_| {
                let coefficient = secp256k1::Scalar::sample(
                    language_public_parameters.scalar_group_public_parameters(),
                    &mut OsRng,
                )
                .unwrap();

                bounded_natural_numbers_group::GroupElement::new(
                    Uint::<MESSAGE_LIMBS>::from(&U256::from(&coefficient.value())),
                    language_public_parameters.message_group_public_parameters(),
                )
                .unwrap()
            })
            .into();

            let first_commitment_randomness = secp256k1::Scalar::sample(
                language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let second_commitment_randomness = secp256k1::Scalar::sample(
                language_public_parameters.scalar_group_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            let mask = first_commitment_randomness.neutral();

            let encryption_randomness = class_groups::RandomnessSpaceGroupElement::<
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsRng,
            )
            .unwrap();

            (
                coefficients,
                [first_commitment_randomness, second_commitment_randomness].into(),
                mask,
                encryption_randomness,
            )
                .into()
        })
        .take(batch_size)
        .collect()
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(11)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        crate::proof::tests::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

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
                &mut OsRng,
            )
            .unwrap();

        assert!(
            proof
                .verify(&PhantomData, &language_public_parameters, statements)
                .is_ok(),
            "valid proofs should verify"
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_out_of_range_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn proof_with_valid_range_proof_over_wrong_witness_fails(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_valid_range_proof_over_wrong_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        )
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        crate::aggregation::tests::aggregates::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), 1)]
    #[case(2, HashMap::from([(1, 1), (2, 1)]), 2)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), 1)]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]), 2)]
    fn statement_aggregates_asynchronously(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(party_to_weight.len())
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        crate::proof::tests::statement_aggregates_asynchronously::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
            threshold,
            party_to_weight,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 3)]
    #[should_panic(
        expected = "called `Result::unwrap()` on an `Err` value: MismatchingRangeProofMaurerCommitments([2])"
    )]
    fn party_mismatching_maurer_range_proof_statements_aborts_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        crate::aggregation::tests::party_mismatching_maurer_range_proof_statements_aborts_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
            witnesses,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn wrong_decommitment_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::wrong_decommitment_aborts_session_identifiably(
            commitment_round_parties,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn failed_proof_share_verification_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters.clone(),
            witnesses,
        );

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let wrong_commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::failed_proof_share_verification_aborts_session_identifiably(
            commitment_round_parties, wrong_commitment_round_parties,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(3, 1)]
    #[case(3, 3)]
    fn unresponsive_parties_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = public_parameters();

        let witnesses =
            iter::repeat_with(|| generate_witnesses(&language_public_parameters, batch_size))
                .take(number_of_parties)
                .collect();

        let unbounded_witness_public_parameters = direct_product::PublicParameters(
            self_product::PublicParameters::new(
                language_public_parameters
                    .scalar_group_public_parameters()
                    .clone(),
            ),
            language_public_parameters
                .encryption_scheme_public_parameters
                .randomness_space_public_parameters()
                .clone(),
        );

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            NUM_RANGE_CLAIMS,
            direct_product::GroupElement<
                self_product::GroupElement<DIMENSION, secp256k1::Scalar>,
                tiresias::RandomnessSpaceGroupElement,
            >,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        proof::aggregation::test_helpers::unresponsive_parties_aborts_session_identifiably(
            commitment_round_parties,
        );
    }
}
