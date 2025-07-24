// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub use decommitment_round::Decommitment;
pub use proof_share_round::ProofShare;

use crate::{language, Proof};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_aggregation_round;
pub mod proof_share_round;

pub type Output<const REPETITIONS: usize, Language, ProtocolContext> = (
    Proof<REPETITIONS, Language, ProtocolContext>,
    Vec<language::StatementSpaceGroupElement<REPETITIONS, Language>>,
);

#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub(super) mod test_helpers {
    use std::{
        collections::{HashMap, HashSet},
        iter,
        marker::PhantomData,
        time::Duration,
    };

    use criterion::measurement::{Measurement, WallTime};
    use rand_core::OsRng;

    use group::PartyID;

    use crate::{test_helpers::sample_witnesses, Language};

    use super::*;

    /// Sample witnesses for aggregation tests.
    pub fn sample_witnesses_for_aggregation<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) -> Vec<Vec<Lang::WitnessSpaceGroupElement>> {
        iter::repeat_with(|| {
            sample_witnesses::<REPETITIONS, Lang>(
                language_public_parameters,
                batch_size,
                &mut OsRng,
            )
        })
        .take(number_of_parties)
        .collect()
    }

    /// Setup aggregation tests.
    fn setup<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) -> (
        Duration,
        HashMap<PartyID, commitment_round::Party<REPETITIONS, Lang, PhantomData<()>>>,
    ) {
        let measurement = WallTime;

        let witnesses = sample_witnesses_for_aggregation::<REPETITIONS, Lang>(
            language_public_parameters,
            number_of_parties,
            batch_size,
        );
        let number_of_parties = witnesses.len().try_into().unwrap();
        let provers = HashSet::from_iter(1..=number_of_parties);

        let mut instantiation_time = Duration::default();

        let parties = witnesses
            .into_iter()
            .enumerate()
            .map(|(party_id, witnesses)| {
                let party_id: u16 = (party_id + 1).try_into().unwrap();

                let now = measurement.start();
                let party = commitment_round::Party::new_session(
                    party_id,
                    provers.clone(),
                    language_public_parameters.clone(),
                    PhantomData,
                    witnesses,
                    &mut OsRng,
                )
                .unwrap();
                instantiation_time = measurement.end(now);
                (party_id, party)
            })
            .collect();
        (instantiation_time, parties)
    }

    /// Test that the Maurer aggregation protocol for `Lang` succeeds.
    pub fn aggregates<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        let (.., (proof, statements)) =
            proof::aggregation::test_helpers::aggregates(commitment_round_parties);

        assert!(
            proof
                .verify(&PhantomData, language_public_parameters, statements)
                .is_ok(),
            "valid aggregated proofs should verify"
        );
    }

    /// Test that the Maurer aggregation protocol for `Lang` aborts identifiably in the presence of
    /// unresponsive parties.
    pub fn unresponsive_parties_aborts_session_identifiably<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        proof::aggregation::test_helpers::unresponsive_parties_aborts_session_identifiably(
            commitment_round_parties,
        );
    }

    pub fn wrong_decommitment_aborts_session_identifiably<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        proof::aggregation::test_helpers::wrong_decommitment_aborts_session_identifiably(
            commitment_round_parties,
        );
    }

    /// Test that the Maurer aggregation protocol for `Lang` aborts identifiably in the presence of
    /// malicious parties in proof share round.
    pub fn failed_proof_share_verification_aborts_session_identifiably<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);
        let (_, wrong_commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        proof::aggregation::test_helpers::failed_proof_share_verification_aborts_session_identifiably(commitment_round_parties, wrong_commitment_round_parties);
    }

    /// Benchmark aggregation.
    pub fn benchmark_aggregation<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        extra_description: Option<String>,
        as_millis: bool,
        batch_sizes: Option<Vec<usize>>,
    ) {
        let timestamp = if as_millis { "ms" } else { "µs" };
        println!(
            "\nLanguage Name, Repetitions, Extra Description, Number of Parties, Batch Size, Instantiation Time ({timestamp}), Commitment Round Time ({timestamp}), Decommitment Round Time ({timestamp}), Proof Share Round Time ({timestamp}), Proof Aggregation Round Time ({timestamp}), Protocol Time ({timestamp})",
        );

        for number_of_parties in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
            for batch_size in batch_sizes
                .clone()
                .unwrap_or(vec![1, 2, 4, 8, 16, 32, 64, 128])
                .into_iter()
            {
                let (instantiation_time, commitment_round_parties) = setup::<REPETITIONS, Lang>(
                    language_public_parameters,
                    number_of_parties,
                    batch_size,
                );

                let (
                    commitment_round_time,
                    decommitment_round_time,
                    proof_share_round_time,
                    proof_aggregation_round_time,
                    total_time,
                    _,
                ) = proof::aggregation::test_helpers::aggregates(commitment_round_parties);

                let measurement = WallTime;
                let total_time = measurement.add(&total_time, &instantiation_time);

                println!(
                    "{}, {}, {}, {number_of_parties}, {batch_size}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
                    Lang::NAME,
                    REPETITIONS,
                    extra_description.clone().unwrap_or("".to_string()),
                    if as_millis { instantiation_time.as_millis() } else { instantiation_time.as_micros() },
                    if as_millis { commitment_round_time.as_millis() } else { commitment_round_time.as_micros() },
                    if as_millis { decommitment_round_time.as_millis() } else { decommitment_round_time.as_micros() },
                    if as_millis { proof_share_round_time.as_millis() } else { proof_share_round_time.as_micros() },
                    if as_millis { proof_aggregation_round_time.as_millis() } else { proof_aggregation_round_time.as_micros() },
                    if as_millis { total_time.as_millis() } else { total_time.as_micros() },
                );
            }
        }
    }
}
