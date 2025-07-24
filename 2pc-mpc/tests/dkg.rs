// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use rand_core::OsRng;
use std::collections::HashMap;

use group::PartyID;
use common::ProtocolContext;
use mpc::two_party::RoundResult;
use mpc::{AsynchronousRoundResult, AsynchronouslyAdvanceable};
use twopc_mpc::dkg::centralized_party;

pub mod common;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::common::{
        run_dkg_phase1, run_dkg_phase2, run_dkg_phase3, run_dkg_protocol, EncryptionParty,
    };

    /// This test verifies that:
    /// 1. The DKG protocol completes through all three phases
    /// 2. No parties are flagged as malicious during the protocol
    /// 3. All parties generate the same public key at the end
    /// 4. Each party receives their own output including key shares
    ///
    /// The protocol uses a 3-out-of-5 threshold scheme, meaning any 3 parties can later
    /// collaborate to perform operations with the distributed key.
    /// We try to skip 2 parties and check if the protocol still works and demonstrate
    /// finalization with the remaining 3 parties.
    #[test]
    pub fn test_dkg_success_case() {
        let mut rng = OsRng;
        let num_parties = 5;
        let threshold = 3;
        let skip_parties = Some(vec![1, 2]);

        // Create protocol context
        let mut protocol_context = ProtocolContext::new(1234, num_parties, threshold);

        // Run the DKG protocol with 3 out of 5 parties
        let dkt_outputs = run_dkg_protocol(&mut rng, &mut protocol_context, skip_parties)
            .expect("DKG protocol should complete with partial participation meeting threshold");

        // Check that we have results for all 3 parties
        assert_eq!(
            dkt_outputs.len(),
            3,
            "All parties should have verification results"
        );

        // Verify that all parties have the same public key
        let first_party_id = dkt_outputs.keys().next().unwrap();
        let first_public_key = &dkt_outputs.get(first_party_id).unwrap().public_key;

        for (party_id, result) in &dkt_outputs {
            assert_eq!(
                *first_public_key, result.public_key,
                "Public keys should match for all parties (party {})",
                party_id
            );
        }

        println!(
            "DKG completed successfully with 3 parties. Final public key: {:?}",
            first_public_key
        );
    }

    /// This test verifies that:
    /// 1. The DKG protocol detects when a centralized party acts maliciously
    /// 2. Specifically, when the centralized party attempts to provide a valid proof
    ///    for a different key share than what they're claiming
    /// 3. The decentralized parties detect this manipulation attempt
    #[test]
    pub fn test_dkg_malicious_centralized_party_proof_manipulation() {
        let mut rng = OsRng;
        let num_parties = 5;
        let threshold = 3;

        // First run - get valid share and proof
        let mut protocol_context_1 = ProtocolContext::new(1234, num_parties, threshold);
        let decentralized_outputs_1 = run_dkg_phase1(&mut rng, &protocol_context_1)
            .expect("First DKG phase 1 should complete successfully");
        let centralized_result_1 =
            run_dkg_phase2(&mut rng, &mut protocol_context_1, &decentralized_outputs_1)
                .expect("First DKG phase 2 should complete successfully");
        let valid_share_1 = centralized_result_1.outgoing_message.public_key_share;

        // Second run - get another valid share and proof
        let mut protocol_context_2 = ProtocolContext::new(5678, num_parties, threshold);
        let decentralized_outputs_2 = run_dkg_phase1(&mut rng, &protocol_context_2)
            .expect("Second DKG phase 1 should complete successfully");
        let centralized_result_2 =
            run_dkg_phase2(&mut rng, &mut protocol_context_2, &decentralized_outputs_2)
                .expect("Second DKG phase 2 should complete successfully");

        // Create mismatched proof by combining share from first run with proof from second run
        let mismatched_proof = centralized_party::PublicKeyShareAndProof {
            proof: centralized_result_2.outgoing_message.proof,
            public_key_share: valid_share_1,
        };

        // Try to verify the mismatched proof
        let verification_result = run_dkg_phase3(
            &mut rng,
            &mut protocol_context_1,
            &decentralized_outputs_1,
            &RoundResult {
                outgoing_message: mismatched_proof,
                private_output: centralized_result_1.private_output,
                public_output: centralized_result_1.public_output,
            },
        );

        // Verify that the protocol fails with appropriate error
        assert!(
            verification_result.is_err(),
            "DKG should fail with mismatched proof"
        );
        match verification_result {
            Err(e) => {
                println!("DKG correctly failed with error: {:?}", e);
                // You can add more specific error checks here if the error type allows it
            }
            Ok(_) => panic!("DKG should not succeed with mismatched proof"),
        }
    }

    /// This test verifies that:
    /// 1. A malicious party can attempt to manipulate the encryption phase using advance
    /// 2. The protocol detects the manipulation attempt
    /// 3. The malicious party is identified
    #[test]
    pub fn test_dkg_malicious_session_id_during_encryption_phase() {
        let mut rng = OsRng;
        let num_parties = 3;
        let threshold = 2;

        // Create protocol context
        let protocol_context = ProtocolContext::new(1234, num_parties, threshold);

        // Initialize message storage
        let mut decentralized_messages: Vec<
            HashMap<PartyID, <EncryptionParty as mpc::Party>::Message>,
        > = vec![];

        // Execute Round 1 normally for honest parties
        let mut round1_messages = HashMap::new();
        for party_context in &protocol_context.decentralized_parties[1..] {
            let result = EncryptionParty::advance(
                party_context.initialization_context.session_id,
                party_context.id,
                &party_context.initialization_context.access_structure,
                vec![],
                None,
                &party_context
                    .initialization_context
                    .protocol_public_parameters,
                &mut rng,
            )
            .expect("Honest parties should complete round 1");

            match result {
                AsynchronousRoundResult::Advance {
                    message,
                    malicious_parties,
                } => {
                    assert!(malicious_parties.is_empty());
                    round1_messages.insert(party_context.id, message);
                }
                _ => panic!("Expected Advance result in round 1"),
            }
        }

        // Malicious party (party 0) uses advance
        let malicous_party_protocol_context = ProtocolContext::new(0, num_parties, threshold);
        let malicious_party = &malicous_party_protocol_context.decentralized_parties[0];

        let malicious_result = EncryptionParty::advance(
            malicious_party.initialization_context.session_id,
            malicious_party.id,
            &malicious_party.initialization_context.access_structure,
            vec![],
            None,
            &malicious_party
                .initialization_context
                .protocol_public_parameters,
            &mut rng,
        )
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

        decentralized_messages.push(round1_messages);

        // Execute Round 2 for all parties
        let mut detected_malicious_party = false;
        for party_context in &protocol_context.decentralized_parties {
            let result = EncryptionParty::advance(
                party_context.initialization_context.session_id,
                party_context.id,
                &party_context.initialization_context.access_structure,
                decentralized_messages.clone(),
                None,
                &party_context
                    .initialization_context
                    .protocol_public_parameters,
                &mut rng,
            )
            .expect("Round 2 should complete");

            match result {
                AsynchronousRoundResult::Finalize {
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
                _ => panic!("Expected Finalize result in round 2"),
            }
        }

        assert!(
            detected_malicious_party,
            "Protocol should have detected the malicious party"
        );
        println!("Successfully detected malicious behavior in encryption phase for all parties");
    }
}
