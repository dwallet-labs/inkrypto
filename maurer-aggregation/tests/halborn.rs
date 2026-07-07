// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Halborn security audit tests for aggregation protocol

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use group::{ComputationalSecuritySizedNumber, OsCsRng, PartyID};
use maurer::knowledge_of_discrete_log;
use maurer::SOUND_PROOFS_REPETITIONS;
use maurer_aggregation::{
    commitment_round, decommitment_round, proof_share_round, Error, ErrorKind,
};
use proof_aggregation::synchronous::{
    CommitmentRoundParty, DecommitmentRoundParty, ProofShareRoundParty,
};

use maurer_aggregation::test_helpers as aggregation_test_helpers;

#[test]
fn test_aggregation_protocol_malicious_party() {
    let language_public_parameters =
        knowledge_of_discrete_log::test_helpers::language_public_parameters::<
            SOUND_PROOFS_REPETITIONS,
        >();

    // Test that wrong decommitment from a malicious party causes abort
    let number_of_parties = 3;
    let batch_size = 2;

    aggregation_test_helpers::wrong_decommitment_aborts_session_identifiably::<
        SOUND_PROOFS_REPETITIONS,
        knowledge_of_discrete_log::test_helpers::Lang,
    >(&language_public_parameters, number_of_parties, batch_size);

    // Test that failed proof share verification from a malicious party causes abort
    aggregation_test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
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
        aggregation_test_helpers::unresponsive_parties_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            knowledge_of_discrete_log::test_helpers::Lang,
        >(&language_public_parameters, number_of_parties, batch_size);
    }
}

#[test]
fn test_proof_share_round_with_large_validators() {
    use knowledge_of_discrete_log::test_helpers::language_public_parameters;
    use knowledge_of_discrete_log::test_helpers::Lang;
    use maurer::test_helpers;

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
                &mut OsCsRng,
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
            &mut OsCsRng,
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
            .commit_statements_and_statement_mask(&mut OsCsRng)
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
            .decommit_statements_and_statement_mask(commitments.clone(), &mut OsCsRng)
            .unwrap();
        decommitments.insert(party_id, decommitment);
        proof_share_round_parties.insert(party_id, proof_share_party);
    }

    // Test 1: Verify that all parties can generate valid proof shares
    let mut proof_share_results = HashMap::new();
    for (party_id, party) in proof_share_round_parties.drain() {
        let result = party.generate_proof_share(decommitments.clone(), &mut OsCsRng);
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
            &mut OsCsRng,
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
            .commit_statements_and_statement_mask(&mut OsCsRng)
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
            .decommit_statements_and_statement_mask(commitments.clone(), &mut OsCsRng)
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
        let result = verifier_party.generate_proof_share(corrupted_decommitments, &mut OsCsRng);

        assert!(
            result.is_err(),
            "Expected an error with corrupted decommitment"
        );

        match result {
            Err(Error {
                kind:
                    ErrorKind::Aggregation(proof_aggregation::synchronous::Error {
                        kind: proof_aggregation::synchronous::ErrorKind::WrongDecommitment(parties),
                        ..
                    }),
                ..
            }) => {
                assert!(
                    parties.contains(&first_party_id),
                    "Error should identify the corrupting party: expected {first_party_id}, got {parties:?}"
                );
            }
            Err(e) => panic!("Expected WrongDecommitment error, got: {e:?}"),
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
                &mut OsCsRng,
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
                .commit_statements_and_statement_mask(&mut OsCsRng)
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
                .decommit_statements_and_statement_mask(commitments.clone(), &mut OsCsRng)
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
        let result = verifier_party.generate_proof_share(corrupted_decommitments, &mut OsCsRng);

        assert!(
            result.is_err(),
            "Expected an error with corrupted decommitments"
        );

        match result {
            Err(Error {
                kind:
                    ErrorKind::Aggregation(proof_aggregation::synchronous::Error {
                        kind: proof_aggregation::synchronous::ErrorKind::WrongDecommitment(parties),
                        ..
                    }),
                ..
            }) => {
                // Sort the expected parties for comparison
                corrupted_parties.sort();

                assert_eq!(
                    parties, corrupted_parties,
                    "Error should identify all corrupting parties: expected {corrupted_parties:?}, got {parties:?}"
                );
            }
            Err(e) => panic!("Expected WrongDecommitment error, got: {e:?}"),
            Ok(_) => panic!("Expected error but got success"),
        }
    }
}

#[test]
fn test_proof_share_round_with_very_large_validators() {
    use knowledge_of_discrete_log::test_helpers::language_public_parameters;
    use knowledge_of_discrete_log::test_helpers::Lang;
    use maurer::test_helpers;

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
                &mut OsCsRng,
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
            &mut OsCsRng,
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
            .commit_statements_and_statement_mask(&mut OsCsRng)
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
            .decommit_statements_and_statement_mask(commitments.clone(), &mut OsCsRng)
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
                let result = party.generate_proof_share(decommitments.clone(), &mut OsCsRng);
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
                    println!("Processed {next_party_idx} of {NUM_VALIDATORS} parties");
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
    println!("Successfully processed all {NUM_VALIDATORS} validators without issues");
}
