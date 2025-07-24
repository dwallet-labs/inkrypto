// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use core::array;
use std::fmt::Debug;

use crypto_bigint::{NonZero, RandomMod, Uint};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use commitment::GroupsPublicParametersAccessors as _;
use group::{
    helpers::FlatMapResults, CsRng, GroupElement, Samplable, StatisticalSecuritySizedNumber,
};
use maurer::Language;
use proof::{
    range::{
        CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement,
        PublicParametersAccessors,
    },
    TranscriptProtocol,
};

use crate::{
    language::{
        EnhancedLanguageStatementAccessors, EnhancedLanguageWitnessAccessors,
        EnhancedPublicParameters, StatementSpaceGroupElement, WitnessSpaceGroupElement,
    },
    EnhanceableLanguage, EnhancedLanguage, Error, Result,
};

/// An Enhanced Batched Maurer Zero-Knowledge Proof.
/// Implements Section 4. Enhanced Batch Schnorr Protocols in the paper.
pub type Proof<
    // Number of times this proof should be repeated to achieve sufficient security.
    const REPETITIONS: usize,
    // The number of witnesses with range claims.
    const NUM_RANGE_CLAIMS: usize,
    // The range proof commitment scheme's message space scalar size in limbs.
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    // The corresponding range proof.
    RangeProof,
    // The unbounded witness group element.
    UnboundedWitnessSpaceGroupElement,
    // The enhanceable language we are proving.
    Language,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript.
    ProtocolContext,
> = private::Proof<
    maurer::Proof<
        REPETITIONS,
        EnhancedLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        ProtocolContext,
    >,
    RangeProof,
>;

mod private {
    use super::*;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Proof<MaurerProof, RangeProof> {
        pub(crate) maurer_proof: MaurerProof,
        pub(crate) range_proof: RangeProof,
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    >
    Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    /// Prove an enhanced batched Maurer zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        witnesses: Vec<
            WitnessSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(
        Self,
        Vec<
            StatementSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
    )> {
        let transcript = Self::setup_range_proof(
            protocol_context,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )?;

        let (commitment_messages, commitment_randomnesses): (Vec<_>, Vec<_>) = witnesses
            .clone()
            .into_iter()
            .map(|witness| {
                (
                    *witness.range_proof_commitment_message(),
                    *witness.range_proof_commitment_randomness(),
                )
            })
            .unzip();

        let (range_proof, _) = RangeProof::prove(
            &enhanced_language_public_parameters.range_proof_public_parameters,
            commitment_messages,
            commitment_randomnesses,
            transcript,
            rng,
        )?;

        let (randomizers, statement_masks) =
            Self::sample_randomizers_and_statement_masks(enhanced_language_public_parameters, rng)?;

        let (maurer_proof, statements) = maurer::Proof::<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
            ProtocolContext,
        >::prove_with_randomizers(
            protocol_context,
            enhanced_language_public_parameters,
            witnesses,
            randomizers,
            statement_masks,
        )?;

        Ok((
            Proof {
                maurer_proof,
                range_proof,
            },
            statements,
        ))
    }

    /// Verify an enhanced batched Maurer zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        statements: Vec<
            StatementSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<()> {
        self.verify_range_proof(
            protocol_context,
            enhanced_language_public_parameters,
            statements.clone(),
            rng,
        )
        .and(Ok(self.maurer_proof.verify(
            protocol_context,
            enhanced_language_public_parameters,
            statements,
        )?))
    }

    fn verify_range_proof(
        &self,
        protocol_context: &ProtocolContext,
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        statements: Vec<
            StatementSpaceGroupElement<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Language,
            >,
        >,
        rng: &mut impl CsRng,
    ) -> Result<()> {
        let transcript = Self::setup_range_proof(
            protocol_context,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )?;

        let commitments: Vec<_> = statements
            .clone()
            .into_iter()
            .map(|statement| *statement.range_proof_commitment())
            .collect();

        // Range check:
        // Z < delta \cdot PARTY_ID_MAX \cdot NUM_CONSTRAINED_WITNESS \cdot (2^(kappa+s+1)
        // Range check for enhanced Maurer. Protocol~7 suggests the formula below for non-batched
        // version: $$ Z < \Delta \cdot n_{max} \cdot d \cdot (\ell + \ell_\omega) \cdot
        // 2^{\kappa+s+1} $$ The range check for the batched protocol with batch size = m,
        // appears in Appendix~K. Seemingly, to get a 2^-s' statistical zk, one must use
        // $2^s = m2^s'$ throughout the protocol (sampling a greater mask, checking a
        // broader range, and requiring a greater lower bound for the range-proof commitment
        // space). Nevertheless, this is also the case when running m non-batched zk protocols in
        // parallel. So in general, setting s should take into consideration the number of signing
        // protocols expected in the whole system, regardless of whether proofs are batched
        // or not.

        let bound = crate::language::commitment_message_space_lower_bound::<
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        >(true, RangeProof::RANGE_CLAIM_BITS)?;

        if !self.maurer_proof.responses.into_iter().all(|response| {
            let (commitment_message, ..): (_, _) = response.into();
            let (commitment_message, _) = commitment_message.into();

            <[_; NUM_RANGE_CLAIMS]>::from(commitment_message)
                .into_iter()
                .all(|range_claim| range_claim.into() < bound)
        }) {
            return Err(Error::OutOfRange);
        }

        Ok(self.range_proof.verify(
            &enhanced_language_public_parameters.range_proof_public_parameters,
            commitments,
            transcript,
            rng,
        )?)
    }

    pub(crate) fn setup_range_proof(
        protocol_context: &ProtocolContext,
        range_proof_public_parameters: &proof::range::PublicParameters<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >,
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        transcript.append_message(
            b"range proof used for the enhanced Maurer proof",
            RangeProof::NAME.as_bytes(),
        );

        transcript.transcribe(
            b"range proof public parameters",
            range_proof_public_parameters.clone(),
        )?;

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        Ok(transcript)
    }

    pub(crate) fn sample_randomizers_and_statement_masks(
        enhanced_language_public_parameters: &EnhancedPublicParameters<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(
        [WitnessSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >; REPETITIONS],
        [StatementSpaceGroupElement<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >; REPETITIONS],
    )> {
        let challenge_bits = EnhancedLanguage::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Language,
        >::challenge_bits()?;

        // $ [0,\Delta \cdot d(\ell+1+\omegalen) \cdot 2^{\kappa+s}) $
        // Note: we do not add the log of the number of range claims
        // (i.e. the number of bits that holds the `NUM_RANGE_CLAIMS` value),
        // which means this reduces the statistical security by that amount.
        // This is fine for our settings in which `NUM_RANGE_CLAIMS` is very small,
        // and the decrease in statistical security is insignificant (no more than 4-7 bits.)
        // The reason we don't account for this is the inconsistencies with the non-enhanced Maurer randomizer size it would cause.
        // In effect it would have the (composed) enhanced Maurer randomizers the same as the Maurer ones, but statistical security will reduce by the log of the number of range claims. Equivalently, to reach the same statistical security, one should use a statistical security parameter that is larger by that amount.
        let sampling_bit_size: u32 = RangeProof::RANGE_CLAIM_BITS
            .checked_add(challenge_bits)
            .and_then(|bits| bits.checked_add(StatisticalSecuritySizedNumber::BITS))
            .ok_or(Error::InvalidPublicParameters)?;

        if Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::BITS <= sampling_bit_size {
            return Err(Error::InvalidPublicParameters);
        }

        let sampling_range_upper_bound = NonZero::new(
            Uint::<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>::ONE << sampling_bit_size,
        )
        .unwrap();

        let commitment_messages: [CommitmentSchemeMessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            NUM_RANGE_CLAIMS,
            RangeProof,
        >; REPETITIONS] = array::from_fn(|_| {
            array::from_fn(|_| {
                let value = Uint::<{ COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS }>::random_mod(
                    rng,
                    &sampling_range_upper_bound,
                )
                .into();

                RangeProof::RangeClaimGroupElement::new(
                    value,
                    &enhanced_language_public_parameters
                        .range_proof_public_parameters
                        .commitment_scheme_public_parameters()
                        .message_space_public_parameters()
                        .0,
                )
            })
            .flat_map_results()
            .map(|decomposed_witness| decomposed_witness.into())
        })
        .flat_map_results()?;

        let unbounded_witnesses: [_; REPETITIONS] = array::from_fn(|_| {
            UnboundedWitnessSpaceGroupElement::sample(
                enhanced_language_public_parameters.unbounded_witness_public_parameters(),
                rng,
            )
        })
        .flat_map_results()?;

        let commitment_randomnesses: [_; REPETITIONS] = array::from_fn(|_| {
            CommitmentSchemeRandomnessSpaceGroupElement::<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                RangeProof,
            >::sample(
                enhanced_language_public_parameters
                    .range_proof_public_parameters
                    .commitment_scheme_public_parameters()
                    .randomness_space_public_parameters(),
                rng,
            )
        })
        .flat_map_results()?;

        let randomizers: [_; REPETITIONS] = commitment_messages
            .into_iter()
            .zip(commitment_randomnesses.into_iter())
            .zip(unbounded_witnesses.into_iter())
            .map(
                |((commitment_message, commitment_randomness), unbounded_witness)| {
                    (commitment_message, commitment_randomness, unbounded_witness).into()
                },
            )
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        let is_randomizer = true;
        let is_verify = false;
        let statement_masks = randomizers
            .map(|randomizer| {
                EnhancedLanguage::<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Language,
                >::homomorphose(
                    &randomizer,
                    enhanced_language_public_parameters,
                    is_randomizer,
                    is_verify,
                )
            })
            .flat_map_results()?;

        Ok((randomizers, statement_masks))
    }
}

impl<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
        RangeProof: proof::RangeProof<COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS>,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Language: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            UnboundedWitnessSpaceGroupElement,
        >,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
    > proof::Proof
    for Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >
{
    type Error = Error;
    type ProtocolContext = ProtocolContext;
    type ProofWithAggregationProtocolContext = Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        proof::aggregation::ProtocolContext<ProtocolContext>,
    >;
    type PublicParameters = EnhancedPublicParameters<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >;

    type WitnessSpaceGroupElement = WitnessSpaceGroupElement<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >;
    type StatementSpaceGroupElement = StatementSpaceGroupElement<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
    >;
    type AggregationStatementSpaceValue = group::Value<Language::StatementSpaceGroupElement>;

    fn prove(
        protocol_context: &Self::ProtocolContext,
        enhanced_language_public_parameters: &Self::PublicParameters,
        witnesses: Vec<Self::WitnessSpaceGroupElement>,
        rng: &mut impl CsRng,
    ) -> std::result::Result<(Self, Vec<Self::StatementSpaceGroupElement>), Self::Error> {
        Proof::prove(
            protocol_context,
            enhanced_language_public_parameters,
            witnesses,
            rng,
        )
    }

    fn verify(
        &self,
        protocol_context: &Self::ProtocolContext,
        enhanced_language_public_parameters: &Self::PublicParameters,
        statements: Vec<Self::StatementSpaceGroupElement>,
        rng: &mut impl CsRng,
    ) -> std::result::Result<(), Self::Error> {
        self.verify(
            protocol_context,
            enhanced_language_public_parameters,
            statements,
            rng,
        )
    }

    fn statements_to_output_value(
        enhanced_statements: Vec<Self::StatementSpaceGroupElement>,
    ) -> Vec<Self::AggregationStatementSpaceValue> {
        let maurer_statements = enhanced_statements
            .into_iter()
            .map(|enhanced_statement| {
                let (_, statement) = enhanced_statement.into();
                statement
            })
            .collect();

        Language::StatementSpaceGroupElement::batch_normalize(maurer_statements)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::{iter, marker::PhantomData};

    use ::bulletproofs::{BulletproofGens, PedersenGens};
    use crypto_bigint::{Random, U256, U64};

    use commitment::CommitmentSizedNumber;
    use group::{OsCsRng, PartyID};
    use mpc::{Weight, WeightedThresholdAccessStructure};
    use proof::range::{
        bulletproofs,
        bulletproofs::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS},
    };

    use crate::language::tests::enhanced_language_public_parameters;

    use super::*;

    pub(crate) fn valid_proof_verifies<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let witnesses = EnhancedLanguage::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >::generate_witnesses(
            witnesses,
            &enhanced_language_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let (proof, statements) = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::prove(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses,
            &mut OsCsRng,
        )
        .unwrap();

        assert!(
            proof
                .verify(
                    &PhantomData,
                    &enhanced_language_public_parameters,
                    statements,
                    &mut OsCsRng,
                )
                .is_ok(),
            "valid enhanced proofs should verify",
        );
    }

    /// Test that the MPC Session for the Enhanced Maurer statement aggregation asynchronous
    /// protocol for `Lang` succeeds.
    pub(crate) fn statement_aggregates_asynchronously<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Vec<Lang::WitnessSpaceGroupElement>>,
        threshold: PartyID,
        party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let (private_inputs, public_inputs): (HashMap<_, _>, HashMap<_, _>) = witnesses
            .into_iter()
            .enumerate()
            .map(|(party_id, witnesses)| {
                let party_id: u16 = (party_id + 1).try_into().unwrap();

                let witnesses = EnhancedLanguage::<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
                    bulletproofs::RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Lang,
                >::generate_witnesses(
                    witnesses,
                    &enhanced_language_public_parameters,
                    &mut OsCsRng,
                )
                .unwrap();

                let public_input = proof::aggregation::asynchronous::PublicInput {
                    protocol_context: session_id,
                    public_parameters: enhanced_language_public_parameters.clone(),
                    batch_size: witnesses.len(),
                };

                ((party_id, witnesses), (party_id, public_input))
            })
            .unzip();

        mpc::test_helpers::asynchronous_session_terminates_successfully::<
            proof::aggregation::asynchronous::Party<
                Proof<
                    REPETITIONS,
                    NUM_RANGE_CLAIMS,
                    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                    bulletproofs::RangeProof,
                    UnboundedWitnessSpaceGroupElement,
                    Lang,
                    CommitmentSizedNumber,
                >,
            >,
        >(
            session_id,
            &access_structure,
            private_inputs,
            public_inputs,
            2,
        );
    }

    pub(crate) fn proof_with_out_of_range_witness_fails<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let mut witnesses = EnhancedLanguage::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >::generate_witnesses(
            witnesses,
            &enhanced_language_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let out_of_range_witness = witnesses.first().cloned().unwrap();
        let (range_proof_commitment_message, commitment_randomness, unbounded_element) =
            out_of_range_witness.into();
        let mut range_proof_commitment_message_array: [_; NUM_RANGE_CLAIMS] =
            range_proof_commitment_message.into();
        range_proof_commitment_message_array[0] = U256::from(1u64 << RANGE_CLAIM_BITS).into();
        let out_of_range_witness = (
            range_proof_commitment_message_array.into(),
            commitment_randomness,
            unbounded_element,
        )
            .into();
        witnesses[0] = out_of_range_witness;

        // First test that we can't even generate a proof with out of range witness.
        let res = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::prove(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses.clone(),
            &mut OsCsRng,
        );

        assert!(
            matches!(
                res.err().unwrap(),
                Error::Proof(proof::Error::InvalidParameters)
            ),
            "shouldn't be able to verify proofs on out of range witnesses"
        );

        // Then check that if a malicious prover generates such proof, it fails verification.
        let transcript = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::setup_range_proof(
            &PhantomData,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )
        .unwrap();

        let (randomizers, statement_masks) = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::sample_randomizers_and_statement_masks(
            &enhanced_language_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let (maurer_proof, statements) = maurer::Proof::<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                bulletproofs::RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Lang,
            >,
            PhantomData<()>,
        >::prove_with_randomizers(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses.clone(),
            randomizers,
            statement_masks,
        )
        .unwrap();

        let (witnesses, commitments_randomness): (Vec<_>, Vec<_>) = witnesses
            .into_iter()
            .map(|witness| {
                let (range_proof_commitment_message, commitment_randomness, _) = witness.into();

                (range_proof_commitment_message, commitment_randomness)
            })
            .unzip();

        let witnesses: Vec<_> = witnesses
            .into_iter()
            .flat_map(<[_; NUM_RANGE_CLAIMS]>::from)
            .map(U256::from)
            .map(|witness| U64::from(&witness).into())
            .collect();

        let commitments_randomness: Vec<_> = commitments_randomness
            .into_iter()
            .flat_map(<[_; NUM_RANGE_CLAIMS]>::from)
            .map(curve25519_dalek::scalar::Scalar::from)
            .collect();

        let padded_witnesses_length = witnesses.len().next_power_of_two();
        let mut iter = witnesses.into_iter();
        let witnesses: Vec<u64> = iter::repeat_with(|| iter.next().unwrap_or(0u64))
            .take(padded_witnesses_length)
            .collect();

        let mut iter = commitments_randomness.into_iter();
        let commitments_randomness: Vec<curve25519_dalek::scalar::Scalar> =
            iter::repeat_with(|| {
                iter.next()
                    .unwrap_or(curve25519_dalek::scalar::Scalar::ZERO)
            })
            .take(padded_witnesses_length)
            .collect();

        let bulletproofs_generators = BulletproofGens::new(64, witnesses.len());
        let commitment_generators = PedersenGens::default();

        let out_of_range_proof = bulletproofs::test_helpers::new_range_proof(
            ::bulletproofs::RangeProof::prove_multiple_with_rng(
                bulletproofs_generators,
                commitment_generators,
                transcript,
                witnesses.as_slice(),
                commitments_randomness.as_slice(),
                64,
                &mut OsCsRng,
            )
            .unwrap()
            .0,
        );

        let proof = Proof {
            maurer_proof,
            range_proof: out_of_range_proof,
        };

        assert!(
            matches!(
                proof
                    .verify(
                        &PhantomData,
                        &enhanced_language_public_parameters,
                        statements,
                        &mut OsCsRng,
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::OutOfRange)
            ),
            "enhanced proof with out of range range proof must fail verification",
        );
    }

    pub(crate) fn proof_with_valid_range_proof_over_wrong_witness_fails<
        const REPETITIONS: usize,
        const NUM_RANGE_CLAIMS: usize,
        UnboundedWitnessSpaceGroupElement: group::GroupElement + Samplable,
        Lang: EnhanceableLanguage<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            UnboundedWitnessSpaceGroupElement,
        >,
    >(
        unbounded_witness_public_parameters: UnboundedWitnessSpaceGroupElement::PublicParameters,
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let mut witnesses = EnhancedLanguage::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >::generate_witnesses(
            witnesses,
            &enhanced_language_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        // Then check that if a malicious prover generates such proof, it fails verification.
        let transcript = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::setup_range_proof(
            &PhantomData,
            &enhanced_language_public_parameters.range_proof_public_parameters,
        )
        .unwrap();

        let (randomizers, statement_masks) = Proof::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >::sample_randomizers_and_statement_masks(
            &enhanced_language_public_parameters,
            &mut OsCsRng,
        )
        .unwrap();

        let (maurer_proof, statements) = maurer::Proof::<
            REPETITIONS,
            EnhancedLanguage<
                REPETITIONS,
                NUM_RANGE_CLAIMS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                bulletproofs::RangeProof,
                UnboundedWitnessSpaceGroupElement,
                Lang,
            >,
            PhantomData<()>,
        >::prove_with_randomizers(
            &PhantomData,
            &enhanced_language_public_parameters,
            witnesses.clone(),
            randomizers,
            statement_masks,
        )
        .unwrap();

        let wrong_witness = witnesses.first().cloned().unwrap();
        let (range_proof_commitment_message, commitment_randomness, unbounded_element) =
            wrong_witness.into();
        let mut range_proof_commitment_message_array: [_; NUM_RANGE_CLAIMS] =
            range_proof_commitment_message.into();
        range_proof_commitment_message_array[0] = U256::from(1u64).into();
        let wrong_witness = (
            range_proof_commitment_message_array.into(),
            commitment_randomness,
            unbounded_element,
        )
            .into();
        witnesses[0] = wrong_witness;

        let (witnesses, commitments_randomness): (Vec<_>, Vec<_>) = witnesses
            .into_iter()
            .map(|witness| {
                let (range_proof_commitment_message, commitment_randomness, _) = witness.into();

                (range_proof_commitment_message, commitment_randomness)
            })
            .unzip();

        let witnesses: Vec<_> = witnesses
            .into_iter()
            .flat_map(<[_; NUM_RANGE_CLAIMS]>::from)
            .map(U256::from)
            .map(|witness| U64::from(&witness).into())
            .collect();

        let commitments_randomness: Vec<_> = commitments_randomness
            .into_iter()
            .flat_map(<[_; NUM_RANGE_CLAIMS]>::from)
            .map(curve25519_dalek::scalar::Scalar::from)
            .collect();

        let padded_witnesses_length = witnesses.len().next_power_of_two();
        let mut iter = witnesses.into_iter();
        let witnesses: Vec<u64> = iter::repeat_with(|| iter.next().unwrap_or(0u64))
            .take(padded_witnesses_length)
            .collect();

        let mut iter = commitments_randomness.into_iter();
        let commitments_randomness: Vec<curve25519_dalek::scalar::Scalar> =
            iter::repeat_with(|| {
                iter.next()
                    .unwrap_or(curve25519_dalek::scalar::Scalar::ZERO)
            })
            .take(padded_witnesses_length)
            .collect();

        let bulletproofs_generators = BulletproofGens::new(RANGE_CLAIM_BITS, witnesses.len());
        let commitment_generators = PedersenGens::default();

        let out_of_range_proof = bulletproofs::test_helpers::new_range_proof(
            ::bulletproofs::RangeProof::prove_multiple_with_rng(
                bulletproofs_generators,
                commitment_generators,
                transcript,
                witnesses.as_slice(),
                commitments_randomness.as_slice(),
                RANGE_CLAIM_BITS,
                &mut OsCsRng,
            )
            .unwrap()
            .0,
        );

        let proof = Proof {
            maurer_proof,
            range_proof: out_of_range_proof,
        };

        assert!(
            matches!(
                proof
                    .verify(
                        &PhantomData,
                        &enhanced_language_public_parameters,
                        statements,
                        &mut OsCsRng,
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::OutOfRange)
            ),
            "enhanced proof with out of range range proof must fail verification",
        );
    }
}
