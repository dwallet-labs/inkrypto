// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

/// Maurer-aggregation error wrapper that carries a backtrace captured at construction.
#[derive(thiserror::Error, Clone, Debug)]
#[error("{kind}\n{backtrace}")]
pub struct Error {
    pub kind: ErrorKind,
    pub backtrace: std::sync::Arc<std::backtrace::Backtrace>,
}

impl<E> From<E> for Error
where
    ErrorKind: From<E>,
{
    fn from(value: E) -> Self {
        Self {
            kind: ErrorKind::from(value),
            backtrace: std::sync::Arc::new(std::backtrace::Backtrace::capture()),
        }
    }
}

/// Maurer-aggregation error kind.
#[derive(thiserror::Error, Debug, Clone)]
pub enum ErrorKind {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("commitment error")]
    Commitment(#[from] commitment::Error),
    #[error("mpc error")]
    MPC(#[from] ::mpc::Error),
    #[error("maurer error")]
    Maurer(#[from] maurer::Error),
    #[error("aggregation error")]
    Aggregation(#[from] proof_aggregation::synchronous::Error),
    #[error("unsupported repetitions")]
    UnsupportedRepetitions,
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("serialization/deserialization error: {0:?}")]
    Serialization(String),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::from(ErrorKind::Serialization(e.to_string()))
    }
}

/// Maurer result.
pub type Result<T> = std::result::Result<T, Error>;

impl TryInto<::proof::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<::proof::Error, Self::Error> {
        match self.kind {
            ErrorKind::Proof(e) => Ok(e),
            kind => Err(Error {
                kind,
                backtrace: self.backtrace,
            }),
        }
    }
}

impl TryInto<proof_aggregation::synchronous::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<proof_aggregation::synchronous::Error, Self::Error> {
        match self.kind {
            ErrorKind::Aggregation(e) => Ok(e),
            kind => Err(Error {
                kind,
                backtrace: self.backtrace,
            }),
        }
    }
}

impl From<Error> for ::mpc::Error {
    fn from(value: Error) -> Self {
        match value.kind {
            ErrorKind::MPC(e) => e,
            ErrorKind::Aggregation(e) => e.into(),
            ErrorKind::Group(e) => mpc::Error::from(mpc::ErrorKind::Group(e)),
            ErrorKind::InternalError => mpc::Error::from(mpc::ErrorKind::InternalError),
            ErrorKind::InvalidParameters => mpc::Error::from(mpc::ErrorKind::InvalidParameters),
            ErrorKind::InvalidPublicParameters => {
                mpc::Error::from(mpc::ErrorKind::InvalidParameters)
            }
            kind => mpc::Error::from(mpc::ErrorKind::Consumer(format!("maurer error {kind:?}"))),
        }
    }
}

pub use decommitment_round::Decommitment;
pub use proof_share_round::ProofShare;

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_aggregation_round;
pub mod proof_share_round;

pub type Output<const REPETITIONS: usize, Language, ProtocolContext> = (
    maurer::Proof<REPETITIONS, Language, ProtocolContext>,
    Vec<maurer::language::StatementSpaceGroupElement<REPETITIONS, Language>>,
);

#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub mod test_helpers {
    use std::{
        collections::{HashMap, HashSet},
        iter,
        marker::PhantomData,
        time::Duration,
    };

    use commitment::CommitmentSizedNumber;
    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::Random;
    use group::{CsRng, OsCsRng, PartyID};
    use maurer::test_helpers::sample_witnesses;
    use mpc::{Weight, WeightedThresholdAccessStructure};

    use super::*;

    /// Test that the MPC Session for the Maurer statement aggregation asynchronous protocol for `Lang` succeeds.
    pub fn statement_aggregates_asynchronously<
        const REPETITIONS: usize,
        Lang: maurer::Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
        batch_size: usize,
        rng: &mut impl CsRng,
    ) {
        let session_id = CommitmentSizedNumber::random(rng);
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        let (private_inputs, public_inputs): (HashMap<_, _>, HashMap<_, _>) = (1
            ..=access_structure.number_of_tangible_parties())
            .map(|party_id| {
                let witnesses = sample_witnesses::<REPETITIONS, Lang>(
                    language_public_parameters,
                    batch_size,
                    rng,
                );

                let public_input = proof_aggregation::asynchronous::PublicInput {
                    protocol_context: session_id,
                    public_parameters: language_public_parameters.clone(),
                    batch_size,
                };

                ((party_id, witnesses), (party_id, public_input))
            })
            .unzip();

        mpc::test_helpers::asynchronous_session_terminates_successfully::<
            proof_aggregation::asynchronous::Party<
                maurer::Proof<REPETITIONS, Lang, CommitmentSizedNumber>,
            >,
        >(
            session_id,
            &access_structure,
            private_inputs,
            public_inputs,
            2,
        );
    }

    /// Sample witnesses for aggregation tests.
    pub fn sample_witnesses_for_aggregation<
        const REPETITIONS: usize,
        Lang: maurer::Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) -> Vec<Vec<Lang::WitnessSpaceGroupElement>> {
        iter::repeat_with(|| {
            sample_witnesses::<REPETITIONS, Lang>(
                language_public_parameters,
                batch_size,
                &mut OsCsRng,
            )
        })
        .take(number_of_parties)
        .collect()
    }

    /// Setup aggregation tests.
    fn setup<const REPETITIONS: usize, Lang: maurer::Language<REPETITIONS>>(
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
                    &mut OsCsRng,
                )
                .unwrap();
                instantiation_time = measurement.end(now);
                (party_id, party)
            })
            .collect();
        (instantiation_time, parties)
    }

    /// Test that the Maurer aggregation protocol for `Lang` succeeds.
    pub fn aggregates<const REPETITIONS: usize, Lang: maurer::Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        let (.., (proof, statements)) =
            proof_aggregation::test_helpers::aggregates(commitment_round_parties);

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
        Lang: maurer::Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        proof_aggregation::test_helpers::unresponsive_parties_aborts_session_identifiably(
            commitment_round_parties,
        );
    }

    pub fn wrong_decommitment_aborts_session_identifiably<
        const REPETITIONS: usize,
        Lang: maurer::Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        proof_aggregation::test_helpers::wrong_decommitment_aborts_session_identifiably(
            commitment_round_parties,
        );
    }

    /// Test that the Maurer aggregation protocol for `Lang` aborts identifiably in the presence of
    /// malicious parties in proof share round.
    pub fn failed_proof_share_verification_aborts_session_identifiably<
        const REPETITIONS: usize,
        Lang: maurer::Language<REPETITIONS>,
    >(
        language_public_parameters: &Lang::PublicParameters,
        number_of_parties: usize,
        batch_size: usize,
    ) {
        let (_, commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);
        let (_, wrong_commitment_round_parties) =
            setup::<REPETITIONS, Lang>(language_public_parameters, number_of_parties, batch_size);

        proof_aggregation::test_helpers::failed_proof_share_verification_aborts_session_identifiably(commitment_round_parties, wrong_commitment_round_parties);
    }

    /// Benchmark aggregation.
    pub fn benchmark_aggregation<const REPETITIONS: usize, Lang: maurer::Language<REPETITIONS>>(
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
                .unwrap_or_else(|| vec![1, 2, 4, 8, 16, 32, 64, 128])
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
                ) = proof_aggregation::test_helpers::aggregates(commitment_round_parties);

                let measurement = WallTime;
                let total_time = measurement.add(&total_time, &instantiation_time);

                println!(
                    "{}, {}, {}, {number_of_parties}, {batch_size}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
                    Lang::NAME,
                    REPETITIONS,
                    extra_description.clone().unwrap_or_default(),
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

/// Language module aggregation tests.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use group::{OsCsRng, PartyID};
    use maurer::SOUND_PROOFS_REPETITIONS;
    use mpc::Weight;
    use rstest::rstest;

    use crate::test_helpers as aggregation_test_helpers;

    // ============================================
    // knowledge_of_discrete_log aggregation tests
    // ============================================
    mod knowledge_of_discrete_log_tests {
        use super::*;
        use maurer::knowledge_of_discrete_log::test_helpers::{language_public_parameters, Lang};

        #[rstest]
        #[case(1, 1)]
        #[case(1, 2)]
        #[case(2, 1)]
        #[case(2, 3)]
        #[case(5, 2)]
        fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

            aggregation_test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(
                &language_public_parameters,
                number_of_parties,
                batch_size,
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
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

            aggregation_test_helpers::statement_aggregates_asynchronously::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(
                &language_public_parameters,
                threshold,
                party_to_weight,
                batch_size,
                &mut OsCsRng,
            );
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn unresponsive_parties_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

            aggregation_test_helpers::unresponsive_parties_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn wrong_decommitment_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

            aggregation_test_helpers::wrong_decommitment_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn failed_proof_share_verification_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

            aggregation_test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }
    }

    // ============================================
    // commitment_of_discrete_log aggregation tests
    // ============================================
    mod commitment_of_discrete_log_tests {
        use super::*;
        use maurer::commitment_of_discrete_log::test_helpers::{language_public_parameters, Lang};

        #[rstest]
        #[case(1, 1)]
        #[case(1, 2)]
        #[case(2, 1)]
        #[case(2, 3)]
        #[case(5, 2)]
        fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(
                &language_public_parameters,
                number_of_parties,
                batch_size,
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
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::statement_aggregates_asynchronously::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(
                &language_public_parameters,
                threshold,
                party_to_weight,
                batch_size,
                &mut OsCsRng,
            );
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn unresponsive_parties_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::unresponsive_parties_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn wrong_decommitment_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::wrong_decommitment_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn failed_proof_share_verification_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }
    }

    // ============================================
    // knowledge_of_decommitment aggregation tests
    // ============================================
    mod knowledge_of_decommitment_tests {
        use super::*;
        use maurer::knowledge_of_decommitment::test_helpers::language_public_parameters;
        use maurer::knowledge_of_decommitment::test_helpers::Lang;

        #[rstest]
        #[case(1, 1)]
        #[case(1, 2)]
        #[case(2, 1)]
        #[case(2, 3)]
        #[case(5, 2)]
        fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

            aggregation_test_helpers::aggregates::<
                SOUND_PROOFS_REPETITIONS,
                Lang<SOUND_PROOFS_REPETITIONS, 1>,
            >(&language_public_parameters, number_of_parties, batch_size);
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
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

            aggregation_test_helpers::statement_aggregates_asynchronously::<
                SOUND_PROOFS_REPETITIONS,
                Lang<SOUND_PROOFS_REPETITIONS, 1>,
            >(
                &language_public_parameters,
                threshold,
                party_to_weight,
                batch_size,
                &mut OsCsRng,
            );
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn unresponsive_parties_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

            aggregation_test_helpers::unresponsive_parties_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang<SOUND_PROOFS_REPETITIONS, 1>,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn wrong_decommitment_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

            aggregation_test_helpers::wrong_decommitment_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang<SOUND_PROOFS_REPETITIONS, 1>,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn failed_proof_share_verification_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters =
                language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

            aggregation_test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang<SOUND_PROOFS_REPETITIONS, 1>,
            >(&language_public_parameters, number_of_parties, batch_size);
        }
    }

    // ==================================================
    // discrete_log_ratio_of_committed_values aggregation tests
    // ==================================================
    mod discrete_log_ratio_tests {
        use super::*;
        use maurer::discrete_log_ratio_of_committed_values::test_helpers::{
            language_public_parameters, Lang,
        };

        #[rstest]
        #[case(1, 1)]
        #[case(1, 2)]
        #[case(2, 1)]
        #[case(2, 3)]
        #[case(5, 2)]
        fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(
                &language_public_parameters,
                number_of_parties,
                batch_size,
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
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::statement_aggregates_asynchronously::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(
                &language_public_parameters,
                threshold,
                party_to_weight,
                batch_size,
                &mut OsCsRng,
            );
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn unresponsive_parties_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::unresponsive_parties_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn wrong_decommitment_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::wrong_decommitment_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn failed_proof_share_verification_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }
    }

    // ==================================================
    // equality_of_discrete_logs aggregation tests (using TiresiasLang)
    // ==================================================
    mod equality_of_discrete_logs_tests {
        use super::*;
        use crypto_bigint::U2048;
        use group::{bounded_natural_numbers_group, GroupElement as _, Samplable};
        use homomorphic_encryption::GroupsPublicParametersAccessors;
        use maurer::{equality_of_discrete_logs, language};
        use tiresias::test_helpers::N;

        pub type TiresiasLang = equality_of_discrete_logs::Language<
            2,
            bounded_natural_numbers_group::GroupElement<
                { tiresias::PaillierModulusSizedNumber::LIMBS },
            >,
            tiresias::CiphertextSpaceGroupElement,
        >;

        pub fn tiresias_language_public_parameters(
        ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, TiresiasLang> {
            let paillier_public_parameters =
                tiresias::encryption_key::PublicParameters::new(N).unwrap();

            let scalar_public_parameters =
                bounded_natural_numbers_group::PublicParameters::new_with_randomizer_upper_bound(
                    U2048::BITS,
                )
                .unwrap();

            let ciphertext_space_public_parameters = paillier_public_parameters
                .ciphertext_space_public_parameters()
                .clone();

            let first_base = tiresias::CiphertextSpaceGroupElement::sample(
                &ciphertext_space_public_parameters,
                &mut OsCsRng,
            )
            .unwrap();

            let second_base = tiresias::CiphertextSpaceGroupElement::sample(
                &ciphertext_space_public_parameters,
                &mut OsCsRng,
            )
            .unwrap();

            let discrete_log_sample_bits = Some(scalar_public_parameters.upper_bound_bits);
            equality_of_discrete_logs::PublicParameters::new::<
                bounded_natural_numbers_group::GroupElement<
                    { tiresias::PaillierModulusSizedNumber::LIMBS },
                >,
                tiresias::CiphertextSpaceGroupElement,
            >(
                scalar_public_parameters,
                ciphertext_space_public_parameters,
                [first_base.value(), second_base.value()],
                discrete_log_sample_bits,
            )
        }

        #[rstest]
        #[case(1, 1)]
        #[case(1, 2)]
        #[case(2, 1)]
        #[case(2, 3)]
        #[case(5, 2)]
        fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
            let language_public_parameters = tiresias_language_public_parameters();

            aggregation_test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, TiresiasLang>(
                &language_public_parameters,
                number_of_parties,
                batch_size,
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
            let language_public_parameters = tiresias_language_public_parameters();

            aggregation_test_helpers::statement_aggregates_asynchronously::<
                SOUND_PROOFS_REPETITIONS,
                TiresiasLang,
            >(
                &language_public_parameters,
                threshold,
                party_to_weight,
                batch_size,
                &mut OsCsRng,
            );
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn unresponsive_parties_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = tiresias_language_public_parameters();

            aggregation_test_helpers::unresponsive_parties_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                TiresiasLang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn wrong_decommitment_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = tiresias_language_public_parameters();

            aggregation_test_helpers::wrong_decommitment_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                TiresiasLang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn failed_proof_share_verification_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = tiresias_language_public_parameters();

            aggregation_test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                TiresiasLang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }
    }

    // ==================================================
    // vector_commitment_of_discrete_log aggregation tests
    // ==================================================
    mod vector_commitment_tests {
        use super::*;
        use maurer::vector_commitment_of_discrete_log::test_helpers::{
            language_public_parameters, Lang,
        };

        #[rstest]
        #[case(1, 1)]
        #[case(1, 2)]
        #[case(2, 1)]
        #[case(2, 3)]
        #[case(5, 2)]
        fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(
                &language_public_parameters,
                number_of_parties,
                batch_size,
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
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::statement_aggregates_asynchronously::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(
                &language_public_parameters,
                threshold,
                party_to_weight,
                batch_size,
                &mut OsCsRng,
            );
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn unresponsive_parties_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::unresponsive_parties_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn wrong_decommitment_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::wrong_decommitment_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }

        #[rstest]
        #[case(2, 1)]
        #[case(3, 1)]
        #[case(5, 2)]
        fn failed_proof_share_verification_aborts_session_identifiably(
            #[case] number_of_parties: usize,
            #[case] batch_size: usize,
        ) {
            let language_public_parameters = language_public_parameters();

            aggregation_test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
                SOUND_PROOFS_REPETITIONS,
                Lang,
            >(&language_public_parameters, number_of_parties, batch_size);
        }
    }
}
