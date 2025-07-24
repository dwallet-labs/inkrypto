// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use crypto_bigint::Uint;

use group::{KnownOrderGroupElement, Scale};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use maurer::encryption_of_discrete_log::*;
use maurer::SOUND_PROOFS_REPETITIONS;
use tiresias::LargeBiPrimeSizedNumber;

use crate::{language::DecomposableWitness, EnhanceableLanguage};

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS> + Scale<LargeBiPrimeSizedNumber>,
    >
    EnhanceableLanguage<
        SOUND_PROOFS_REPETITIONS,
        RANGE_CLAIMS_PER_SCALAR,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        tiresias::RandomnessSpaceGroupElement,
    >
    for Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        SCALAR_LIMBS,
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        tiresias::PlaintextSpaceGroupElement,
        GroupElement,
        tiresias::EncryptionKey,
    >
{
    fn compose_witness(
        decomposed_witness: [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>;
            RANGE_CLAIMS_PER_SCALAR],
        randomness: tiresias::RandomnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<Self::WitnessSpaceGroupElement> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            tiresias::RandomnessSpaceGroupElement,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        let discrete_log = <tiresias::PlaintextSpaceGroupElement as DecomposableWitness<
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        >>::compose(
            &decomposed_witness,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
            range_claim_bits,
        )?;

        Ok((discrete_log, randomness).into())
    }

    fn decompose_witness(
        witness: Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        range_claim_bits: u32,
    ) -> maurer::Result<(
        [Uint<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>; RANGE_CLAIMS_PER_SCALAR],
        tiresias::RandomnessSpaceGroupElement,
    )> {
        <Self as EnhanceableLanguage<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            tiresias::RandomnessSpaceGroupElement,
        >>::valid_group_order::<RANGE_CLAIMS_PER_SCALAR, SCALAR_LIMBS, GroupElement>(
            range_claim_bits,
            language_public_parameters.group_public_parameters(),
        )?;

        Ok((
            witness.discrete_log().decompose(range_claim_bits)?,
            *witness.randomness(),
        ))
    }
}

pub type Proof<
    const NUM_RANGE_CLAIMS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
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
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        homomorphic_encryption::PlaintextSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

#[cfg(test)]
pub(crate) mod tests {
    use core::iter;
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::U256;
    use rstest::rstest;

    use class_groups::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use class_groups::{
        Secp256k1DecryptionKey, Secp256k1EncryptionKey, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };
    use group::{secp256k1, OsCsRng, PartyID, Samplable};
    use maurer::language;
    use mpc::Weight;
    use tiresias::test_helpers::N;

    use crate::{
        aggregation::tests::setup_aggregation,
        language::tests::{generate_scalar_plaintext, RANGE_CLAIMS_PER_SCALAR},
    };

    use super::*;

    pub type Lang = Language<
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        { U256::LIMBS },
        { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
        tiresias::PlaintextSpaceGroupElement,
        secp256k1::GroupElement,
        tiresias::EncryptionKey,
    >;

    pub type ClassGroupsLang = Language<
        { U256::LIMBS },
        { U256::LIMBS },
        { U256::LIMBS },
        secp256k1::Scalar,
        secp256k1::GroupElement,
        Secp256k1EncryptionKey,
    >;

    pub(crate) fn public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
    {
        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let paillier_public_parameters =
            tiresias::encryption_key::PublicParameters::new(N).unwrap();

        let generator = secp256k1_group_public_parameters.generator;

        PublicParameters::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            tiresias::PlaintextSpaceGroupElement,
            secp256k1::GroupElement,
            tiresias::EncryptionKey,
        >::new::<
            { tiresias::PLAINTEXT_SPACE_SCALAR_LIMBS },
            { secp256k1::SCALAR_LIMBS },
            tiresias::EncryptionKey,
        >(
            paillier_public_parameters
                .plaintext_space_public_parameters()
                .clone(),
            secp256k1_group_public_parameters,
            paillier_public_parameters,
            generator,
            None,
        )
    }

    pub(crate) fn class_groups_language_public_parameters(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, ClassGroupsLang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1_group_public_parameters.generator;

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (encryption_scheme_public_parameters, _) =
            Secp256k1DecryptionKey::generate(setup_parameters, &mut OsCsRng).unwrap();

        PublicParameters::<
            { U256::LIMBS },
            { U256::LIMBS },
            { U256::LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
            Secp256k1EncryptionKey,
        >::new::<{ U256::LIMBS }, { secp256k1::SCALAR_LIMBS }, Secp256k1EncryptionKey>(
            secp256k1_scalar_public_parameters.clone(),
            secp256k1_group_public_parameters,
            encryption_scheme_public_parameters,
            generator,
            None,
        )
    }

    fn generate_witnesses(
        language_public_parameters: &language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>,
        batch_size: usize,
    ) -> Vec<language::WitnessSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>> {
        iter::repeat_with(|| {
            let discrete_log = generate_scalar_plaintext();

            let randomness = tiresias::RandomnessSpaceGroupElement::sample(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .randomness_space_public_parameters(),
                &mut OsCsRng,
            )
            .unwrap();

            (discrete_log, randomness).into()
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
            let discrete_log = secp256k1::Scalar::sample(
                language_public_parameters.discrete_log_public_parameters(),
                &mut OsCsRng,
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

            (discrete_log, randomness).into()
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::proof::tests::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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
    #[case(11)]
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

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(5)]
    #[case(10)]
    #[case(50)]
    fn proof_with_out_of_range_randomness_response_fails_verification_class_groups(
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = class_groups_language_public_parameters();

        let witnesses = generate_witnesses_class_groups(&language_public_parameters, 1);

        let (proof, statements) =
            maurer::Proof::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang, PhantomData<()>>::prove(
                &PhantomData,
                &language_public_parameters,
                witnesses,
                &mut OsCsRng,
            )
            .unwrap();

        let mut proofs: Vec<_> = std::iter::repeat_n(proof.clone(), batch_size).collect();
        let mut malicious_proof = proof.clone();

        let (discrete_log_response, _) = malicious_proof.responses[0].into();
        malicious_proof.responses[0] = (discrete_log_response, Uint::MAX).into();
        proofs[0] = malicious_proof.clone();

        let res = malicious_proof.verify(
            &PhantomData,
            &language_public_parameters,
            statements.clone(),
        );

        assert!(
            matches!(
                res.err().unwrap(),
                maurer::Error::Group(group::Error::InvalidGroupElement),
            ),
            "proof with out-of-range randomness response should fail verification"
        );

        let res = maurer::Proof::verify_batch(
            proofs,
            vec![PhantomData; batch_size],
            &language_public_parameters,
            std::iter::repeat_n(statements, batch_size).collect(),
            &mut OsCsRng,
        );

        assert!(
            matches!(
                res.err().unwrap(),
                maurer::Error::Group(group::Error::InvalidGroupElement),
            ),
            "batch verify of proof with out-of-range randomness response should fail verification"
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(5)]
    #[case(10)]
    #[case(50)]
    fn valid_proofs_verifies_batch_class_groups(#[case] batch_size: usize) {
        let language_public_parameters = class_groups_language_public_parameters();

        let witnesses = generate_witnesses_class_groups(&language_public_parameters, 1);

        let (proof, statements) =
            maurer::Proof::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang, PhantomData<()>>::prove(
                &PhantomData,
                &language_public_parameters,
                witnesses,
                &mut OsCsRng,
            )
            .unwrap();

        let measurement = WallTime;
        let now = measurement.start();
        let res = proof.verify(
            &PhantomData,
            &language_public_parameters,
            statements.clone(),
        );
        let time = measurement.end(now);
        println!("single proof verify took {:?}ms", time.as_millis());
        assert!(res.is_ok(), "valid proofs should verify");

        let now = measurement.start();
        let res = maurer::Proof::verify_batch(
            std::iter::repeat_n(proof, batch_size).collect(),
            vec![PhantomData; batch_size],
            &language_public_parameters,
            std::iter::repeat_n(statements, batch_size).collect(),
            &mut OsCsRng,
        );
        let time = measurement.end(now);
        println!(
            "batch_verify of batch size {batch_size} took {:?}ms",
            time.as_millis()
        );

        assert!(res.is_ok(), "valid proofs should verify");
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    fn proof_with_out_of_range_witness_fails(#[case] batch_size: usize) {
        let language_public_parameters = public_parameters();

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_out_of_range_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let witnesses = generate_witnesses(&language_public_parameters, batch_size);

        crate::proof::tests::proof_with_valid_range_proof_over_wrong_witness_fails::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::aggregation::tests::aggregates::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::proof::tests::statement_aggregates_asynchronously::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        crate::aggregation::tests::party_mismatching_maurer_range_proof_statements_aborts_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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

        let unbounded_witness_public_parameters = language_public_parameters
            .randomness_space_public_parameters()
            .clone();

        let commitment_round_parties = setup_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            RANGE_CLAIMS_PER_SCALAR,
            tiresias::RandomnessSpaceGroupElement,
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
