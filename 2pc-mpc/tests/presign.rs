// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashMap;

use common::run_dkg_protocol;
use common::ProtocolContext;
use group::PartyID;
use mpc::AsynchronousRoundResult;

mod common;

#[cfg(test)]
mod tests {
    use group::OsCsRng;

    use crate::common::{advance_presign_party, run_presign_protocol, PresignMessage};

    use super::*;

    /// This test demonstrates the complete workflow:
    /// 1. First, the DKG protocol is executed to establish key shares
    /// 2. Then, the Presign protocol is executed among the same parties
    ///
    /// The test uses a 2-out-of-3 threshold scheme.
    #[test]
    fn test_dkg_and_presign() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;
        let skip_parties = None;

        println!("Starting DKG protocol...");

        // Create protocol context for DKG
        let mut protocol_context = ProtocolContext::new(1234, num_parties, threshold);

        // Execute the DKG protocol
        let dkg_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, skip_parties.clone())
            .expect("DKG protocol should complete successfully");

        println!("DKG protocol completed. Proceeding to Presign protocol...");

        // Determine participating parties (same as in DKG)
        if let Some(skip_ids) = &skip_parties {
            // Filter out skipped parties
            protocol_context
                .decentralized_parties
                .retain(|party| !skip_ids.contains(&party.id));
        }

        // Execute the Presign protocol
        let presign_results = run_presign_protocol(&mut rng, &mut protocol_context, &dkg_outputs)
            .expect("Presign protocol should complete successfully");

        // Get participating party IDs from protocol context
        let participating_party_ids: Vec<PartyID> = protocol_context
            .decentralized_parties
            .iter()
            .map(|party| party.id)
            .collect();

        // Check that presign outputs are generated for all participating parties
        assert_eq!(
            presign_results.len(),
            participating_party_ids.len(),
            "All participating parties should have presign outputs"
        );

        // Verify that each participating party has a presign output
        for party_id in &participating_party_ids {
            assert!(
                presign_results.contains_key(party_id),
                "Party {party_id} should have a presign output"
            );
        }

        println!("Presign protocol completed successfully");
    }

    /// This test verifies that:
    /// 1. A malicious party attempting to use a wrong session ID during presign phase 1 is detected
    /// 2. The protocol correctly identifies the malicious party
    /// 3. Other honest parties can detect this malicious behavior
    #[test]
    fn test_presign_phase1_malicious_session_id() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;

        // First run DKG protocol normally to get the required outputs
        let mut protocol_context = ProtocolContext::new(1234, num_parties, threshold);
        let dkg_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, None)
            .expect("DKG protocol should complete successfully");

        // Create a malicious protocol context with different session ID
        let malicious_protocol_context = ProtocolContext::new(5678, num_parties, threshold);

        // Initialize message storage
        let mut messages: Vec<HashMap<PartyID, PresignMessage>> = vec![];

        // Execute Round 1 for honest parties
        let mut round1_messages = HashMap::new();
        for party_context in &protocol_context.decentralized_parties[1..] {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs)
                .expect("Honest parties should complete round 1");

            match result {
                AsynchronousRoundResult::Advance {
                    message,
                    malicious_parties,
                } => {
                    assert!(
                        malicious_parties.is_empty(),
                        "No malicious parties should be detected in round 1"
                    );
                    round1_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in round 1"),
            }
        }

        // Execute Round 1 for malicious party
        let malicious_party = &malicious_protocol_context.decentralized_parties[0];
        let malicious_result =
            advance_presign_party(&mut rng, malicious_party, &messages, &dkg_outputs)
                .expect("Malicious party should complete round 1");

        match malicious_result {
            AsynchronousRoundResult::Advance {
                message,
                malicious_parties,
            } => {
                assert!(
                    malicious_parties.is_empty(),
                    "No malicious parties should be detected in round 1"
                );
                round1_messages.insert(malicious_party.id, message);
            }
            _ => panic!("Expected Advance result for malicious party in round 1"),
        }

        messages.push(round1_messages);

        // Execute Round 2 for all parties
        let mut detected_malicious_party = false;
        for party_context in &protocol_context.decentralized_parties {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs)
                .expect("Round 2 should complete");

            match result {
                AsynchronousRoundResult::Advance {
                    malicious_parties, ..
                } => {
                    if !malicious_parties.is_empty() {
                        assert!(
                            malicious_parties.contains(&malicious_party.id),
                            "Malicious party should be detected"
                        );
                        detected_malicious_party = true;
                    }
                }
                _ => panic!("Expected Advance result in round 2"),
            }
        }

        assert!(
            detected_malicious_party,
            "Protocol should have detected the malicious party"
        );
        println!("Successfully detected malicious behavior in presign phase 1");
    }

    /// This test verifies that:
    /// 1. A malicious party attempting to use an incorrect proof during presign phase 1 is detected
    /// 2. The protocol correctly identifies the malicious party
    /// 3. Other honest parties can detect this malicious behavior
    #[test]
    fn test_presign_malicious_proof_manipulation() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;

        // First run DKG protocol normally to get the required outputs
        let mut protocol_context = ProtocolContext::new(1234, num_parties, threshold);
        let dkg_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, None)
            .expect("DKG protocol should complete successfully");

        // Initialize message storage
        let mut messages: Vec<HashMap<PartyID, PresignMessage>> = vec![];

        // Execute Round 1 for honest parties (parties 1 and 2)
        let mut round1_messages = HashMap::new();
        for party_context in &protocol_context.decentralized_parties[1..] {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs)
                .expect("Honest parties should complete round 1");

            match result {
                AsynchronousRoundResult::Advance {
                    message,
                    malicious_parties,
                } => {
                    assert!(
                        malicious_parties.is_empty(),
                        "No malicious parties should be detected in round 1"
                    );
                    round1_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in round 1"),
            }
        }

        // Create a second protocol context to generate a different proof
        let mut second_protocol_context = ProtocolContext::new(5678, num_parties, threshold);
        let second_dkg_outputs = run_dkg_protocol(&mut rng, &mut second_protocol_context, None)
            .expect("Second DKG protocol should complete successfully");

        // Generate a malicious message for party 0 using the second protocol context
        let malicious_party = &second_protocol_context.decentralized_parties[0];
        let malicious_result =
            advance_presign_party(&mut rng, malicious_party, &messages, &second_dkg_outputs)
                .expect("Malicious party should complete round 1");

        // Insert the malicious message into round 1 messages
        match malicious_result {
            AsynchronousRoundResult::Advance {
                message,
                malicious_parties,
            } => {
                assert!(
                    malicious_parties.is_empty(),
                    "No malicious parties should be detected in round 1"
                );
                // Use the party ID from the original context
                round1_messages.insert(protocol_context.decentralized_parties[0].id, message);
            }
            _ => panic!("Expected Advance result for malicious party in round 1"),
        }

        messages.push(round1_messages);

        // Execute Round 2 for all parties and check if malicious party is detected
        let mut detected_malicious_party = false;
        for party_context in &protocol_context.decentralized_parties {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs);

            // The protocol should either detect malicious behavior or fail with an error
            match result {
                Ok(AsynchronousRoundResult::Advance {
                    malicious_parties, ..
                }) => {
                    if !malicious_parties.is_empty() {
                        assert!(
                            malicious_parties
                                .contains(&protocol_context.decentralized_parties[0].id),
                            "Malicious party should be detected"
                        );
                        detected_malicious_party = true;
                    }
                }
                Err(e) => {
                    println!("Protocol failed with error: {e:?}");
                    detected_malicious_party = true;
                }
                _ => {}
            }
        }

        assert!(
            detected_malicious_party,
            "Protocol should have detected the malicious party"
        );
        println!("Successfully detected malicious behavior in presign protocol");
    }

    /// This test verifies that:
    /// 1. A malicious party attempting to use an incorrect proof during presign phase 2 is detected
    /// 2. The protocol correctly identifies the malicious party
    /// 3. Other honest parties can detect this malicious behavior
    #[test]
    fn test_presign_phase2_malicious_proof() {
        let mut rng = OsCsRng;
        let num_parties = 3;
        let threshold = 2;

        // First run DKG protocol normally to get the required outputs
        let mut protocol_context = ProtocolContext::new(1234, num_parties, threshold);
        let dkg_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, None)
            .expect("DKG protocol should complete successfully");

        // Get participating party IDs from the protocol context
        let _participating_party_ids: Vec<PartyID> = protocol_context
            .decentralized_parties
            .iter()
            .map(|party| party.id)
            .collect();

        // Initialize message storage
        let mut messages: Vec<HashMap<PartyID, PresignMessage>> = vec![];

        println!("Running Phase 1 (Rounds 1-2) normally for all parties");

        // Execute Round 1 normally for all parties
        let mut round1_messages = HashMap::new();
        for party_context in &protocol_context.decentralized_parties {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs)
                .expect("All parties should complete round 1");

            match result {
                AsynchronousRoundResult::Advance {
                    message,
                    malicious_parties,
                } => {
                    assert!(
                        malicious_parties.is_empty(),
                        "No malicious parties should be detected in round 1"
                    );
                    round1_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in round 1"),
            }
        }
        messages.push(round1_messages);

        // Execute Round 2 normally for all parties
        let mut round2_messages = HashMap::new();
        for party_context in &protocol_context.decentralized_parties {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs)
                .expect("All parties should complete round 2");

            match result {
                AsynchronousRoundResult::Advance {
                    message,
                    malicious_parties,
                } => {
                    assert!(
                        malicious_parties.is_empty(),
                        "No malicious parties should be detected in round 2"
                    );
                    round2_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in round 2"),
            }
        }
        messages.push(round2_messages);

        println!("Phase 1 completed successfully. Starting Phase 2 with malicious behavior");

        // Create a second protocol context to generate different proofs for Phase 2
        let mut second_protocol_context = ProtocolContext::new(5678, num_parties, threshold);
        let second_dkg_outputs = run_dkg_protocol(&mut rng, &mut second_protocol_context, None)
            .expect("Second DKG protocol should complete successfully");

        // Run Phase 1 for the second protocol context to get it to the same state
        let mut second_messages: Vec<HashMap<PartyID, PresignMessage>> = vec![];

        // Round 1 for second context
        let mut second_round1_messages = HashMap::new();
        for party_context in &second_protocol_context.decentralized_parties {
            let result = advance_presign_party(
                &mut rng,
                party_context,
                &second_messages,
                &second_dkg_outputs,
            )
            .expect("Second context parties should complete round 1");

            match result {
                AsynchronousRoundResult::Advance { message, .. } => {
                    second_round1_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in second context round 1"),
            }
        }
        second_messages.push(second_round1_messages);

        // Round 2 for second context
        let mut second_round2_messages = HashMap::new();
        for party_context in &second_protocol_context.decentralized_parties {
            let result = advance_presign_party(
                &mut rng,
                party_context,
                &second_messages,
                &second_dkg_outputs,
            )
            .expect("Second context parties should complete round 2");

            match result {
                AsynchronousRoundResult::Advance { message, .. } => {
                    second_round2_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in second context round 2"),
            }
        }
        second_messages.push(second_round2_messages);

        // Now execute Round 3 (Phase 2) with honest parties
        let mut round3_messages = HashMap::new();
        for party_context in &protocol_context.decentralized_parties[1..] {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs)
                .expect("Honest parties should complete round 3");

            match result {
                AsynchronousRoundResult::Advance {
                    message,
                    malicious_parties,
                } => {
                    assert!(
                        malicious_parties.is_empty(),
                        "No malicious parties should be detected for honest parties in round 3"
                    );
                    round3_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in round 3 for honest parties"),
            }
        }

        // Generate a malicious message for party 0 using the second protocol context
        let malicious_party_id = protocol_context.decentralized_parties[0].id;
        let malicious_party = &second_protocol_context
            .decentralized_parties
            .iter()
            .find(|p| p.id == malicious_party_id)
            .expect("Malicious party should exist in second context");

        let malicious_result = advance_presign_party(
            &mut rng,
            malicious_party,
            &second_messages,
            &second_dkg_outputs,
        )
        .expect("Malicious party should complete round 3");

        // Insert the malicious message into round 3 messages
        match malicious_result {
            AsynchronousRoundResult::Advance { message, .. } => {
                round3_messages.insert(malicious_party_id, message);
            }
            _ => panic!("Expected Advance result for malicious party in round 3"),
        }

        messages.push(round3_messages);

        println!("Finalizing with malicious message in Phase 2");

        // Try to finalize with the malicious message and check if it's detected
        let mut detected_malicious_party = false;

        for party_context in &protocol_context.decentralized_parties {
            let result = advance_presign_party(&mut rng, party_context, &messages, &dkg_outputs);

            // The protocol should either detect malicious behavior or fail with an error
            match result {
                Ok(AsynchronousRoundResult::Finalize {
                    malicious_parties, ..
                }) => {
                    if !malicious_parties.is_empty() {
                        assert!(
                            malicious_parties.contains(&malicious_party_id),
                            "Malicious party should be detected"
                        );
                        detected_malicious_party = true;
                        println!(
                            "Party {} detected malicious behavior from party {}",
                            party_context.id, malicious_party_id
                        );
                    }
                }
                Err(e) => {
                    println!("Party {} failed with error: {:?}", party_context.id, e);
                    detected_malicious_party = true;
                }
                _ => panic!("Expected Finalize result in finalization"),
            }
        }

        assert!(
            detected_malicious_party,
            "Protocol should have detected the malicious party"
        );
        println!("✓ Successfully detected malicious behavior in presign phase 2");
    }
}
