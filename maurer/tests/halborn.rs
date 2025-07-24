// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod maurer_tests {
    use group::{secp256k1, CyclicGroupElement, GroupElement, PartyID};
    use maurer::language::StatementSpaceGroupElement;
    use maurer::Language;
    use maurer::{commitment_of_discrete_log, knowledge_of_discrete_log, SOUND_PROOFS_REPETITIONS};
    use maurer::{test_helpers, Proof};
    use rand_core::OsRng;
    use std::iter;
    use std::marker::PhantomData;

    #[test]
    fn test_valid_discrete_log_proof_verifies() {
        // @instructions: add pub mod tests to maurer/src/knowledge_of_discrete_log.rs and change pub(crate) to pub mod tests
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();

        // Test with different batch sizes
        for batch_size in [1, 2, 3] {
            test_helpers::valid_proof_verifies::<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_discrete_log::test_helpers::Lang,
            >(&language_public_parameters, batch_size, &mut OsRng);
        }
    }

    #[test]
    #[should_panic]
    fn test_zero_target_bits() {
        // @audit-issue underflow attempt with 0 repetitions
        maurer::fischlin::target_bits::<0>();
    }

    #[test]
    fn test_large_repetitions_with_fischlin_lang() {
        use maurer::knowledge_of_discrete_log::test_helpers::FischlinLang;
        use std::marker::PhantomData;

        const LARGE_REPETITIONS: usize = 1500;

        // Get language public parameters for the Fischlin variant
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<LARGE_REPETITIONS>(
            );

        // Use the FischlinLang type which supports arbitrary repetitions
        let result = maurer::Proof::<
            LARGE_REPETITIONS,
            FischlinLang<LARGE_REPETITIONS>,
            PhantomData<()>,
        >::sample_randomizers_and_statement_masks(
            &language_public_parameters, &mut OsRng
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_correctness() {
        // Test knowledge of discrete log proofs
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();

        // Verify with different batch sizes
        for batch_size in [1, 2, 3] {
            test_helpers::valid_proof_verifies::<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_discrete_log::test_helpers::Lang,
            >(&language_public_parameters, batch_size, &mut OsRng);
        }

        // Also test commitment of discrete log proofs
        let cod_language_public_parameters =
            commitment_of_discrete_log::test_helpers::language_public_parameters();

        for batch_size in [1, 2, 3] {
            test_helpers::valid_proof_verifies::<
                SOUND_PROOFS_REPETITIONS,
                commitment_of_discrete_log::test_helpers::Lang,
            >(&cod_language_public_parameters, batch_size, &mut OsRng);
        }
    }

    #[test]
    fn test_proof_soundness_against_wrong_statements() {
        // For knowledge of discrete log
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();

        let witnesses = test_helpers::sample_witnesses::<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_discrete_log::test_helpers::Lang,
        >(&language_public_parameters, 1, &mut OsRng);

        let (maurer_proof, mut statements) =
            test_helpers::generate_valid_proof::<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_discrete_log::test_helpers::Lang,
            >(&language_public_parameters, witnesses, &mut OsRng);

        // Generate a witness that would create a different statement
        let wrong_witness = test_helpers::sample_witness::<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_discrete_log::test_helpers::Lang,
        >(&language_public_parameters, &mut OsRng);

        let wrong_statement = knowledge_of_discrete_log::test_helpers::Lang::homomorphose(
            &wrong_witness,
            &language_public_parameters,
        )
        .unwrap();

        // Replace the statement with a wrong one
        statements[0] = wrong_statement;

        // Verify that the maurer_proof fails against the wrong statement
        let result = maurer_proof.verify(&PhantomData, &language_public_parameters, statements);
        assert!(result.is_err());

        if result.is_ok() {
            panic!("Expected ProofVerification error, got: {:?}", result);
        }
    }

    #[test]
    fn test_public_parameter_mismatch() {
        let verifier_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        // Modify the base point to create a mismatch
        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        prover_public_parameters.base = secp256k1::GroupElement::new(
            prover_public_parameters.base,
            &secp256k1_group_public_parameters,
        )
        .unwrap()
        .generator()
        .neutral()
        .value();

        // Test with different batch sizes
        for batch_size in [1, 2, 3] {
            test_helpers::proof_over_invalid_public_parameters_fails_verification::<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_discrete_log::test_helpers::Lang,
            >(
                &prover_public_parameters,
                &verifier_public_parameters,
                batch_size,
                &mut OsRng,
            );
        }
    }

    #[test]
    fn test_transcript_completeness() {
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();

        // Test with different batch sizes
        for batch_size in [1, 2, 3] {
            test_helpers::proof_with_incomplete_transcript_fails::<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_discrete_log::test_helpers::Lang,
            >(&language_public_parameters, batch_size, &mut OsRng);
        }
    }

    #[test]
    fn test_batch_verification_integrity() {
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();

        // Create multiple valid proofs
        let number_of_proofs = 3;
        let batch_size = 2;

        let (proofs, statements): (
            Vec<
                maurer::Proof<
                    SOUND_PROOFS_REPETITIONS,
                    knowledge_of_discrete_log::test_helpers::Lang,
                    PhantomData<()>,
                >,
            >,
            Vec<
                Vec<
                    StatementSpaceGroupElement<
                        SOUND_PROOFS_REPETITIONS,
                        knowledge_of_discrete_log::test_helpers::Lang,
                    >,
                >,
            >,
        ) = iter::repeat_with(|| {
            let witnesses = test_helpers::sample_witnesses::<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_discrete_log::test_helpers::Lang,
            >(&language_public_parameters, batch_size, &mut OsRng);

            test_helpers::generate_valid_proof(&language_public_parameters, witnesses, &mut OsRng)
        })
        .take(number_of_proofs)
        .unzip();

        // Batch verification should succeed with all valid proofs
        let result = maurer::Proof::verify_batch(
            proofs.clone(),
            vec![PhantomData; number_of_proofs],
            &language_public_parameters,
            statements.clone(),
            &mut OsRng,
        );
        assert!(result.is_ok());

        // Create a batch with one invalid maurer::proof
        let mut invalid_proofs = proofs.clone();
        invalid_proofs[0].responses =
            [<knowledge_of_discrete_log::test_helpers::Lang as maurer::Language<
                SOUND_PROOFS_REPETITIONS,
            >>::WitnessSpaceGroupElement::neutral_from_public_parameters(
                &language_public_parameters
                    .groups_public_parameters
                    .witness_space_public_parameters,
            )
            .unwrap()
            .value(); SOUND_PROOFS_REPETITIONS];

        // Batch verification should fail with one invalid maurer::proof
        let result = maurer::Proof::verify_batch(
            invalid_proofs,
            vec![PhantomData; number_of_proofs],
            &language_public_parameters,
            statements.clone(),
            &mut OsRng,
        );
        assert!(result.is_err());

        // Create a batch with one invalid statement
        let mut invalid_statements = statements.clone();
        invalid_statements[0][0] =
            <knowledge_of_discrete_log::test_helpers::Lang as maurer::Language<
                SOUND_PROOFS_REPETITIONS,
            >>::StatementSpaceGroupElement::neutral_from_public_parameters(
                &language_public_parameters
                    .groups_public_parameters
                    .statement_space_public_parameters,
            )
            .unwrap();

        // Batch verification should fail with one invalid statement
        let result = maurer::Proof::verify_batch(
            proofs.clone(),
            vec![PhantomData; number_of_proofs],
            &language_public_parameters,
            invalid_statements,
            &mut OsRng,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregation_protocol_malicious_party() {
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();

        // Test that wrong decommitment from a malicious party causes abort
        let number_of_parties = 3;
        let batch_size = 2;

        test_helpers::wrong_decommitment_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_discrete_log::test_helpers::Lang,
        >(&language_public_parameters, number_of_parties, batch_size);

        // Test that failed maurer::proof share verification from a malicious party causes abort
        test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_discrete_log::test_helpers::Lang,
        >(&language_public_parameters, number_of_parties, batch_size);
    }

    #[test]
    fn test_resilience_to_unresponsive_parties() {
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                SOUND_PROOFS_REPETITIONS,
            >();

        // Test various party counts and batch sizes
        for (number_of_parties, batch_size) in [(2, 1), (3, 1), (5, 2)] {
            test_helpers::unresponsive_parties_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                knowledge_of_discrete_log::test_helpers::Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }
    }

    #[test]
    fn test_fischlin_transform_hash_collision_resistance() {
        use maurer::fischlin;
        use maurer::knowledge_of_discrete_log::test_helpers::FischlinLang;

        // Test different repetition values for Fischlin transform
        const FISCHLIN_REPETITIONS_16: usize = 16;
        const FISCHLIN_REPETITIONS_32: usize = 32;

        // Ensure target bits calculation is correct
        assert_eq!(fischlin::target_bits::<FISCHLIN_REPETITIONS_16>(), 8);
        assert_eq!(fischlin::target_bits::<FISCHLIN_REPETITIONS_32>(), 4);

        // Test Fischlin proofs with 16 repetitions
        let language_public_parameters_16 =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                FISCHLIN_REPETITIONS_16,
            >();
        test_helpers::valid_fischlin_proof_verifies::<
            FISCHLIN_REPETITIONS_16,
            FischlinLang<FISCHLIN_REPETITIONS_16>,
        >(&language_public_parameters_16, &mut OsRng);

        // Invalid Fischlin proofs should fail verification
        test_helpers::invalid_fischlin_proof_fails_verification::<
            FISCHLIN_REPETITIONS_16,
            FischlinLang<FISCHLIN_REPETITIONS_16>,
        >(&language_public_parameters_16, &mut OsRng);

        // Test with 32 repetitions as well
        let language_public_parameters_32 =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                FISCHLIN_REPETITIONS_32,
            >();
        test_helpers::valid_fischlin_proof_verifies::<
            FISCHLIN_REPETITIONS_32,
            FischlinLang<FISCHLIN_REPETITIONS_32>,
        >(&language_public_parameters_32, &mut OsRng);

        test_helpers::invalid_fischlin_proof_fails_verification::<
            FISCHLIN_REPETITIONS_32,
            FischlinLang<FISCHLIN_REPETITIONS_32>,
        >(&language_public_parameters_32, &mut OsRng);
    }

    #[test]
    fn test_fischlin_with_max_repetitions() {
        use maurer::knowledge_of_discrete_log::test_helpers::FischlinLang;

        // Test with 100 repetitions
        const FISCHLIN_REPETITIONS_100: usize = 100;
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                FISCHLIN_REPETITIONS_100,
            >();

        // Test maurer::proof generation and verification
        let witnesses = test_helpers::sample_witnesses::<
            FISCHLIN_REPETITIONS_100,
            FischlinLang<FISCHLIN_REPETITIONS_100>,
        >(&language_public_parameters, 1, &mut OsRng);

        let (maurer_proof, statements) =
            test_helpers::generate_valid_proof::<
                FISCHLIN_REPETITIONS_100,
                FischlinLang<FISCHLIN_REPETITIONS_100>,
            >(&language_public_parameters, witnesses, &mut OsRng);

        assert!(maurer_proof
            .verify(&PhantomData, &language_public_parameters, statements)
            .is_ok());
    }

    #[test]
    fn test_fischlin_with_large_repetitions() {
        use maurer::knowledge_of_discrete_log::test_helpers::FischlinLang;

        // Test with 1000 repetitions
        const FISCHLIN_REPETITIONS_1000: usize = 1000;
        let language_public_parameters =
            knowledge_of_discrete_log::test_helpers::language_public_parameters::<
                FISCHLIN_REPETITIONS_1000,
            >();

        // Test maurer::proof generation and verification
        let witnesses = test_helpers::sample_witnesses::<
            FISCHLIN_REPETITIONS_1000,
            FischlinLang<FISCHLIN_REPETITIONS_1000>,
        >(&language_public_parameters, 1, &mut OsRng);

        assert!(matches!(
            Proof::<
                FISCHLIN_REPETITIONS_1000,
                FischlinLang<FISCHLIN_REPETITIONS_1000>,
                PhantomData<()>,
            >::prove(
                &PhantomData,
                &language_public_parameters,
                witnesses,
                &mut OsRng
            )
            .err()
            .unwrap(),
            maurer::Error::UnsupportedRepetitions
        ));
    }

    #[test]
    fn test_proof_share_round_with_large_validators() {
        use group::ComputationalSecuritySizedNumber;
        use maurer::aggregation::{commitment_round, decommitment_round, proof_share_round};
        use maurer::knowledge_of_discrete_log::test_helpers::language_public_parameters;
        use maurer::knowledge_of_discrete_log::test_helpers::Lang;
        use maurer::Error;
        use proof::aggregation::CommitmentRoundParty;
        use proof::aggregation::DecommitmentRoundParty;
        use proof::aggregation::ProofShareRoundParty;
        use std::collections::{HashMap, HashSet};
        use std::marker::PhantomData;

        // Set up a large number of validators
        const NUM_VALIDATORS: usize = 100;
        const BATCH_SIZE: usize = 2;

        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

        // Create a set of party IDs
        let provers: HashSet<PartyID> = (1..=NUM_VALIDATORS as PartyID).collect();

        // Sample witnesses for each party
        let protocol_context = PhantomData::<()>;
        let party_witnesses: HashMap<PartyID, Vec<_>> = provers
            .iter()
            .map(|&party_id| {
                let witnesses = test_helpers::sample_witnesses::<SOUND_PROOFS_REPETITIONS, Lang>(
                    &language_public_parameters,
                    BATCH_SIZE,
                    &mut OsRng,
                );
                (party_id, witnesses)
            })
            .collect();

        // Create commitment round parties
        let mut commitment_round_parties: HashMap<
            PartyID,
            commitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();
        for &party_id in &provers {
            let party = commitment_round::Party::new_session(
                party_id,
                provers.clone(),
                language_public_parameters.clone(),
                protocol_context,
                party_witnesses[&party_id].clone(),
                &mut OsRng,
            )
            .unwrap();
            commitment_round_parties.insert(party_id, party);
        }

        // Generate commitments
        let mut commitments = HashMap::new();
        let mut decommitment_round_parties: HashMap<
            PartyID,
            decommitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();

        for (party_id, party) in commitment_round_parties.drain() {
            let (commitment, decommitment_party) = party
                .commit_statements_and_statement_mask(&mut OsRng)
                .unwrap();
            commitments.insert(party_id, commitment);
            decommitment_round_parties.insert(party_id, decommitment_party);
        }

        // Generate decommitments
        let mut decommitments = HashMap::new();
        let mut proof_share_round_parties: HashMap<
            PartyID,
            proof_share_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();

        for (party_id, party) in decommitment_round_parties.drain() {
            let (decommitment, proof_share_party) = party
                .decommit_statements_and_statement_mask(commitments.clone(), &mut OsRng)
                .unwrap();
            decommitments.insert(party_id, decommitment);
            proof_share_round_parties.insert(party_id, proof_share_party);
        }

        // Test 1: Verify that all parties can generate valid proof shares
        let mut proof_share_results = HashMap::new();
        for (party_id, party) in proof_share_round_parties.drain() {
            let result = party.generate_proof_share(decommitments.clone(), &mut OsRng);
            assert!(
                result.is_ok(),
                "Party {} failed to generate proof share: {:?}",
                party_id,
                result.err()
            );

            // Store results for later tests if needed
            proof_share_results.insert(party_id, result.unwrap());
        }

        // For the rest of the tests, we need to create new instances since we've consumed the original ones
        // Re-create parties for testing corrupted decommitments

        // First recreate the commitment parties
        let mut commitment_round_parties: HashMap<
            PartyID,
            commitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();
        for &party_id in &provers {
            let party = commitment_round::Party::new_session(
                party_id,
                provers.clone(),
                language_public_parameters.clone(),
                protocol_context,
                party_witnesses[&party_id].clone(),
                &mut OsRng,
            )
            .unwrap();
            commitment_round_parties.insert(party_id, party);
        }

        // Regenerate commitments
        let mut commitments = HashMap::new();
        let mut decommitment_round_parties: HashMap<
            PartyID,
            decommitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();

        for (party_id, party) in commitment_round_parties.drain() {
            let (commitment, decommitment_party) = party
                .commit_statements_and_statement_mask(&mut OsRng)
                .unwrap();
            commitments.insert(party_id, commitment);
            decommitment_round_parties.insert(party_id, decommitment_party);
        }

        // Regenerate decommitments
        let mut decommitments = HashMap::new();
        let mut proof_share_round_parties: HashMap<
            PartyID,
            proof_share_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();

        for (party_id, party) in decommitment_round_parties.drain() {
            let (decommitment, proof_share_party) = party
                .decommit_statements_and_statement_mask(commitments.clone(), &mut OsRng)
                .unwrap();
            decommitments.insert(party_id, decommitment);
            proof_share_round_parties.insert(party_id, proof_share_party);
        }

        // Test 2: Test with one party submitting an invalid decommitment (corrupted commitment randomness)
        if let Some(first_party_id) = provers.iter().next().copied() {
            // Create a modified decommitment with corrupted randomness
            let mut corrupted_decommitments = decommitments.clone();
            if let Some(decommit) = corrupted_decommitments.get_mut(&first_party_id) {
                // Modify the commitment randomness to make it invalid
                decommit.set_commitment_randomness(ComputationalSecuritySizedNumber::from(42u64));
            }

            // Pick a different party to process the corrupted decommitment
            let verifier_id = provers
                .iter()
                .find(|&&id| id != first_party_id)
                .copied()
                .unwrap_or(1);

            // Take ownership by removing from the HashMap
            let verifier_party = proof_share_round_parties.remove(&verifier_id).unwrap();

            // Verify that the error properly identifies the miscommitting party
            let result = verifier_party.generate_proof_share(corrupted_decommitments, &mut OsRng);

            assert!(
                result.is_err(),
                "Expected an error with corrupted decommitment"
            );

            match result {
                Err(Error::Aggregation(proof::aggregation::Error::WrongDecommitment(parties))) => {
                    assert!(
                        parties.contains(&first_party_id),
                        "Error should identify the corrupting party: expected {}, got {:?}",
                        first_party_id,
                        parties
                    );
                }
                Err(e) => panic!("Expected WrongDecommitment error, got: {:?}", e),
                Ok(_) => panic!("Expected error but got success"),
            }
        }

        // Test 3: Test with multiple parties submitting invalid decommitments
        if provers.len() >= 3 {
            // For Test 3, we need to recreate all parties again since we've consumed some
            // Recreate commitment round parties
            let mut commitment_round_parties: HashMap<
                PartyID,
                commitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
            > = HashMap::new();
            for &party_id in &provers {
                let party = commitment_round::Party::new_session(
                    party_id,
                    provers.clone(),
                    language_public_parameters.clone(),
                    protocol_context,
                    party_witnesses[&party_id].clone(),
                    &mut OsRng,
                )
                .unwrap();
                commitment_round_parties.insert(party_id, party);
            }

            // Regenerate commitments
            let mut commitments = HashMap::new();
            let mut decommitment_round_parties: HashMap<
                PartyID,
                decommitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
            > = HashMap::new();

            for (party_id, party) in commitment_round_parties.drain() {
                let (commitment, decommitment_party) = party
                    .commit_statements_and_statement_mask(&mut OsRng)
                    .unwrap();
                commitments.insert(party_id, commitment);
                decommitment_round_parties.insert(party_id, decommitment_party);
            }

            // Regenerate decommitments
            let mut decommitments = HashMap::new();
            let mut proof_share_round_parties: HashMap<
                PartyID,
                proof_share_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
            > = HashMap::new();

            for (party_id, party) in decommitment_round_parties.drain() {
                let (decommitment, proof_share_party) = party
                    .decommit_statements_and_statement_mask(commitments.clone(), &mut OsRng)
                    .unwrap();
                decommitments.insert(party_id, decommitment);
                proof_share_round_parties.insert(party_id, proof_share_party);
            }

            let mut corrupted_parties: Vec<PartyID> = provers.iter().take(3).copied().collect();
            let mut corrupted_decommitments = decommitments.clone();

            for &party_id in &corrupted_parties {
                if let Some(decommit) = corrupted_decommitments.get_mut(&party_id) {
                    // Use different bad values for each party
                    decommit.set_commitment_randomness(ComputationalSecuritySizedNumber::from(
                        (party_id as u64) * 100,
                    ));
                }
            }

            // Pick a party that's not in the corrupted set
            let verifier_id = provers
                .iter()
                .find(|&&id| !corrupted_parties.contains(&id))
                .copied()
                .unwrap_or(corrupted_parties[0]);

            // Take ownership by removing from the HashMap
            let verifier_party = proof_share_round_parties.remove(&verifier_id).unwrap();

            // Verify that the error properly identifies all miscommitting parties
            let result = verifier_party.generate_proof_share(corrupted_decommitments, &mut OsRng);

            assert!(
                result.is_err(),
                "Expected an error with corrupted decommitments"
            );

            match result {
                Err(Error::Aggregation(proof::aggregation::Error::WrongDecommitment(parties))) => {
                    // Sort the expected parties for comparison
                    corrupted_parties.sort();

                    assert_eq!(
                        parties, corrupted_parties,
                        "Error should identify all corrupting parties: expected {:?}, got {:?}",
                        corrupted_parties, parties
                    );
                }
                Err(e) => panic!("Expected WrongDecommitment error, got: {:?}", e),
                Ok(_) => panic!("Expected error but got success"),
            }
        }
    }

    #[test]
    fn test_proof_share_round_with_very_large_validators() {
        use maurer::aggregation::{commitment_round, decommitment_round, proof_share_round};
        use maurer::knowledge_of_discrete_log::test_helpers::language_public_parameters;
        use maurer::knowledge_of_discrete_log::test_helpers::Lang;
        use proof::aggregation::CommitmentRoundParty;
        use proof::aggregation::DecommitmentRoundParty;
        use proof::aggregation::ProofShareRoundParty;
        use std::collections::{HashMap, HashSet};
        use std::marker::PhantomData;

        // Set up a much larger number of validators
        const NUM_VALIDATORS: usize = 1500;
        const BATCH_SIZE: usize = 2;

        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

        // Create a set of party IDs
        let provers: HashSet<PartyID> = (1..=NUM_VALIDATORS as PartyID).collect();

        // Sample witnesses for each party
        let protocol_context = PhantomData::<()>;
        let party_witnesses: HashMap<PartyID, Vec<_>> = provers
            .iter()
            .map(|&party_id| {
                let witnesses = test_helpers::sample_witnesses::<SOUND_PROOFS_REPETITIONS, Lang>(
                    &language_public_parameters,
                    BATCH_SIZE,
                    &mut OsRng,
                );
                (party_id, witnesses)
            })
            .collect();

        // Create commitment round parties
        let mut commitment_round_parties: HashMap<
            PartyID,
            commitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();
        for &party_id in &provers {
            let party = commitment_round::Party::new_session(
                party_id,
                provers.clone(),
                language_public_parameters.clone(),
                protocol_context,
                party_witnesses[&party_id].clone(),
                &mut OsRng,
            )
            .unwrap();
            commitment_round_parties.insert(party_id, party);
        }

        // Generate commitments
        let mut commitments = HashMap::new();
        let mut decommitment_round_parties: HashMap<
            PartyID,
            decommitment_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();

        for (party_id, party) in commitment_round_parties.drain() {
            let (commitment, decommitment_party) = party
                .commit_statements_and_statement_mask(&mut OsRng)
                .unwrap();
            commitments.insert(party_id, commitment);
            decommitment_round_parties.insert(party_id, decommitment_party);
        }

        // Generate decommitments
        let mut decommitments = HashMap::new();
        let mut proof_share_round_parties: HashMap<
            PartyID,
            proof_share_round::Party<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>,
        > = HashMap::new();

        for (party_id, party) in decommitment_round_parties.drain() {
            let (decommitment, proof_share_party) = party
                .decommit_statements_and_statement_mask(commitments.clone(), &mut OsRng)
                .unwrap();
            decommitments.insert(party_id, decommitment);
            proof_share_round_parties.insert(party_id, proof_share_party);
        }

        // Test: Verify that all parties can generate valid proof shares
        let mut proof_shares = HashMap::new();
        let mut next_party_idx = 1;

        // Process proof shares in smaller batches to avoid excessive memory usage
        while !proof_share_round_parties.is_empty() {
            // Take a batch of parties to process
            let batch_size = 100;
            let party_ids: Vec<PartyID> = proof_share_round_parties
                .keys()
                .take(batch_size)
                .copied()
                .collect();

            for party_id in party_ids {
                if let Some(party) = proof_share_round_parties.remove(&party_id) {
                    let result = party.generate_proof_share(decommitments.clone(), &mut OsRng);
                    assert!(
                        result.is_ok(),
                        "Party {} failed to generate proof share: {:?}",
                        party_id,
                        result.err()
                    );

                    // Store the proof share
                    proof_shares.insert(party_id, result.unwrap());

                    // Print progress every 100 parties
                    if next_party_idx % 100 == 0 {
                        println!("Processed {} of {} parties", next_party_idx, NUM_VALIDATORS);
                    }
                    next_party_idx += 1;
                }
            }
        }

        assert_eq!(
            proof_shares.len(),
            NUM_VALIDATORS,
            "All validators should successfully generate proof shares"
        );
        println!(
            "Successfully processed all {} validators without issues",
            NUM_VALIDATORS
        );
    }
}
