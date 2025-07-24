// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::fmt::Debug;

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::Concat;
use merlin::Transcript;
use serde::Serialize;

use group::{ComputationalSecuritySizedNumber, GroupElement};
use proof::TranscriptProtocol;

use crate::language::{WitnessSpaceValue, MAX_REPETITIONS};
use crate::{language, Error, Result};

/// The amount of repetitions used in Fischlin UC proofs.
/// This affects the number of group elements sent in the proof, and also performance.
pub const UC_PROOFS_REPETITIONS: usize = 16;

/// Compute the number of zero bits in the target $b$ such that $b \cdot \rho >= \kappa$.
/// This determines the number of trailling (b) zeros in H_b(common_h, i, e_i, z_i), to ensure a given computational security parameter, given the number of parallel repetitions.
pub const fn target_bits<const REPETITIONS: usize>() -> usize {
    assert!(REPETITIONS != 0, "Zero-repetition proofs are not supported");
    assert!(
        REPETITIONS < MAX_REPETITIONS,
        "Proofs with too many repetitions are not supported"
    );

    (ComputationalSecuritySizedNumber::BITS as usize + (REPETITIONS - 1)) / REPETITIONS
}

/// A Universally Composable (UC) Maurer Zero-Knowledge Proof via Fischlin's transform.
/// Implements [Chen and Lindell (2024)](https://eprint.iacr.org/2024/526.pdf).
pub type Proof<
    // Number of parallel repetitions $\rho$ required to get a negligible knowledge error.
    const REPETITIONS: usize,
    // The language we are proving
    Language,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext,
> = private::Proof<REPETITIONS, super::Proof<REPETITIONS, Language, ProtocolContext>>;

mod private {
    use serde::{Deserialize, Serialize};

    use group::ComputationalSecuritySizedNumber;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Proof<const REPETITIONS: usize, MaurerProof> {
        pub maurer_proof: MaurerProof,

        #[serde(with = "group::helpers::const_generic_array_serialization")]
        pub challenges: [ComputationalSecuritySizedNumber; REPETITIONS],
    }
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > Proof<REPETITIONS, Language, ProtocolContext>
{
    /// Prove a Universally Composable (UC) Extractable zero-knowledge (ZK) Maurer statement via Fischlin's transform.
    /// Implements [Chen and Lindell (2024)](https://eprint.iacr.org/2024/526.pdf), sections 2.2, 2.3.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witness: Language::WitnessSpaceGroupElement, // $w$
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Language::StatementSpaceGroupElement)> {
        if REPETITIONS == 0 || REPETITIONS > MAX_REPETITIONS {
            return Err(Error::UnsupportedRepetitions);
        }

        let statement = Language::homomorphose(&witness, language_public_parameters)?; // $x$

        let (randomizers, statement_masks) = // $(\vec{\sigma}, \vec{m_i})
            super::Proof::<REPETITIONS, Language, ProtocolContext>::sample_randomizers_and_statement_masks(language_public_parameters, rng)?;

        let statement_masks_values =
            Language::StatementSpaceGroupElement::batch_normalize_const_generic(statement_masks);

        // $common-h$
        let common_hash = Self::compute_common_hash(
            protocol_context,
            language_public_parameters,
            &statement,
            &statement_masks_values,
        )?;

        let challenges_and_responses: [Result<(
            ComputationalSecuritySizedNumber,
            WitnessSpaceValue<REPETITIONS, Language>,
        )>; REPETITIONS] = array::from_fn(|i| {
            let randomizer = randomizers[i];

            let mut challenge = ComputationalSecuritySizedNumber::ZERO; // $e_i$
            let mut response = randomizer; // $z_i$

            loop {
                if Self::hash_hits_target(common_hash, i, challenge, &response.value())? {
                    break;
                }

                // Advance the challenge. Safe to wrap as it requires computational security work to overflow.
                challenge = challenge.wrapping_add(&ComputationalSecuritySizedNumber::ONE);

                // Advance the response. Due to the nature of the loop,
                // every iteration increases the challenge by `1` and the response by `witness`.
                // This ensures that the response equals the randomizer plus the witness times the challenge:
                // $z_i = \sigma_i + e_i \cdot w$ without requiring $t$ multiplications (only additions, which is cheaper).
                response += &witness;
            }

            Ok((challenge, response.value()))
        });

        if challenges_and_responses.iter().any(|res| res.is_err()) {
            return Err(Error::InternalError);
        }
        let challenges_and_responses = challenges_and_responses.map(|res| res.unwrap());

        let challenges = challenges_and_responses.map(|(challenge, _)| challenge);

        let responses = challenges_and_responses.map(|(_, response)| response);

        let maurer_proof = super::Proof::new(statement_masks_values, responses);

        let uc_proof = Self {
            maurer_proof,
            challenges,
        };

        Ok((uc_proof, statement))
    }

    /// Verify a Universally Composable (UC) Extractable Maurer zero-knowledge claim via Fischlin's transform.
    /// Implements [Chen and Lindell (2024)](https://eprint.iacr.org/2024/526.pdf), sections 2.2, 2.3.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statement: Language::StatementSpaceGroupElement,
    ) -> Result<()> {
        if REPETITIONS == 0 || REPETITIONS > MAX_REPETITIONS {
            return Err(Error::UnsupportedRepetitions);
        }

        // $common-h$
        let common_hash = Self::compute_common_hash(
            protocol_context,
            language_public_parameters,
            &statement,
            &self.maurer_proof.statement_masks,
        )?;

        let hash_checks: Vec<_> = self
            .challenges
            .into_iter()
            .zip(self.maurer_proof.responses)
            .enumerate()
            .map(|(i, (challenge, response))| {
                Self::hash_hits_target(common_hash, i, challenge, &response)
            })
            .collect();

        if hash_checks.iter().any(|res| res.is_err()) {
            return Err(Error::InternalError);
        } else if hash_checks
            .into_iter()
            .map(|res| res.unwrap())
            .any(|is_target| !is_target)
        {
            return Err(proof::Error::ProofVerification)?;
        }

        self.maurer_proof.verify_inner(
            self.challenges.map(|challenge| vec![challenge]),
            language_public_parameters,
            vec![statement],
        )
    }

    /// Compute $common-h$ as a full hash with output length $2\cdot\kappa_c$.
    fn compute_common_hash(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statement: &Language::StatementSpaceGroupElement,
        statement_masks_values: &[group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
    ) -> Result<<ComputationalSecuritySizedNumber as Concat>::Output> {
        let mut transcript =
            super::Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
                protocol_context,
                language_public_parameters,
                vec![statement.value()],
                statement_masks_values,
            )?;

        Ok(transcript.challenge(b"common hash"))
    }

    /// Performs the Fischlin transformation check that $h_i = H(common-h, i, e_i, z_i)$ hits the target,
    /// i.e. it starts with `target_bits` $b$ zeros.
    fn hash_hits_target(
        common_hash: <ComputationalSecuritySizedNumber as Concat>::Output,
        i: usize,
        challenge: ComputationalSecuritySizedNumber,
        response: &WitnessSpaceValue<REPETITIONS, Language>,
    ) -> Result<bool> {
        // Set up the transcript
        let mut transcript = Transcript::new(b"Fischlin hash check");
        // Add the common hash $common-h$
        transcript.append_uint(b"common hash", &common_hash);
        // Add the response index $i$.
        // Safe to use `as` here as `i` is an index to a `REPETITIONS` sized array, so it is smaller than the number of repetitions, which is smaller than the computational security bits.
        transcript.append_message(b"i", &(i as u64).to_be_bytes());
        // Add the challenge $e_i$
        transcript.append_uint(b"challenge", &challenge);
        // Add the response $z_i$
        transcript.serialize_to_transcript_as_json(b"response", &response)?;
        // Finalize the hash computation to get $h_i = H(common-h, i, e_i, z_i)$.
        let hash: ComputationalSecuritySizedNumber = transcript.challenge(b"hash");

        // Compute the number of zero bits in the target $b$ such that $b \cdot \rho >= \kappa$.
        // This determines the number of tralining zeros in H_b(common_h, i, e_i, z_i).
        let target_bits = target_bits::<REPETITIONS>();
        let target_mask = ComputationalSecuritySizedNumber::from(1u64 << target_bits)
            .wrapping_sub(&ComputationalSecuritySizedNumber::ONE);

        Ok(hash & target_mask == ComputationalSecuritySizedNumber::ZERO)
    }
}

// These tests helpers can be used for different `group` implementations,
// therefore they need to be exported.
// Since exporting rust `#[cfg(test)]` is impossible, they exist in a dedicated feature-gated module.
#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub(crate) mod test_helpers {
    use std::marker::PhantomData;
    use std::time::Duration;

    use criterion::measurement::{Measurement, WallTime};
    use rand_core::OsRng;

    use crate::test_helpers::sample_witness;

    use super::*;

    pub fn generate_valid_fischlin_proof<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> (
        Proof<REPETITIONS, Language, PhantomData<()>>,
        Language::StatementSpaceGroupElement,
    ) {
        let witness = sample_witness::<REPETITIONS, Language>(language_public_parameters, rng);

        Proof::prove(&PhantomData, language_public_parameters, witness, rng).unwrap()
    }

    pub fn valid_fischlin_proof_verifies<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) {
        let (proof, statement) =
            generate_valid_fischlin_proof::<REPETITIONS, Language>(language_public_parameters, rng);

        let res = proof.verify(&PhantomData, language_public_parameters, statement);
        assert!(
            res.is_ok(),
            "valid Fischlin proofs should verify, got error {:?}",
            res.err().unwrap()
        );
    }

    pub fn invalid_fischlin_proof_fails_verification<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) {
        let witness = sample_witness::<REPETITIONS, Language>(language_public_parameters, rng);

        let (maurer_proof, statements) = crate::proof::test_helpers::generate_valid_proof::<
            REPETITIONS,
            Language,
        >(language_public_parameters, vec![witness], rng);

        let statement = statements[0];

        let mut transcript =
            crate::proof::Proof::<REPETITIONS, Language, PhantomData<()>>::setup_transcript(
                &PhantomData,
                language_public_parameters,
                Language::StatementSpaceGroupElement::batch_normalize(statements.clone()),
                &maurer_proof.statement_masks,
            )
            .unwrap();

        let challenges: [_; REPETITIONS] =
            crate::Proof::<REPETITIONS, Language, PhantomData<()>>::compute_challenges(
                statements.len(),
                &mut transcript,
            );

        let fischlin_proof = Proof {
            maurer_proof,
            challenges: challenges.clone().map(|v| v[0]),
        };

        // A valid maurer proof shouldn't pass Fischlin verification, as the hash computation must fail.
        assert!(
            fischlin_proof
                .maurer_proof
                .verify_inner(challenges, language_public_parameters, statements)
                .is_ok(),
            "valid maurer proof should verify"
        );

        assert!(
            matches!(
                fischlin_proof
                    .verify(&PhantomData, language_public_parameters, statement)
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification),
            ),
            "proofs with incomplete transcripts (missing language name) should fail"
        );
    }

    pub fn benchmark_fischlin_proof<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
    ) {
        let measurement = WallTime;

        println!(
            "\nLanguage Name, Repetitions, Fischlin Hash Bits, Prove Time (Incl. Statement Computation) (ms), Verification Time (ms)",
        );

        let mut sum = 0;
        let mut verify_time = Duration::default();
        for i in 1..=10 {
            let now = measurement.start();
            let (proof, statement) = generate_valid_fischlin_proof::<REPETITIONS, Language>(
                language_public_parameters,
                &mut OsRng,
            );
            let prove_time = measurement.end(now);

            sum += prove_time.as_millis();

            if i == 10 {
                let now = measurement.start();
                proof
                    .verify(&PhantomData, language_public_parameters, statement)
                    .unwrap();
                verify_time = measurement.end(now);
            }
        }
        let prove_time = sum / 10;

        println!(
            "{}, {}, {}, {:?}, {:?}",
            Language::NAME,
            REPETITIONS,
            target_bits::<REPETITIONS>(),
            prove_time,
            verify_time.as_millis()
        );
    }
}
