// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashSet;
use std::fmt::Debug;

use crypto_bigint::Random;

use serde::Serialize;

use commitment::Commitment;
use group::{ComputationalSecuritySizedNumber, CsRng, GroupElement, PartyID};
use proof::aggregation;
use proof::aggregation::CommitmentRoundParty;

use crate::aggregation::decommitment_round;
use crate::aggregation::decommitment_round::Decommitment;
use crate::{language, Proof};
use crate::{Error, Result};

#[cfg_attr(any(test, feature = "test_helpers"), derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security.
    const REPETITIONS: usize,
    // The language we are proving
    Language: language::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript.
    ProtocolContext: Clone,
> {
    pub party_id: PartyID,
    // The set of parties ${P_i}$ participating in the proof aggregation protocol.
    pub provers: HashSet<PartyID>,
    pub language_public_parameters: Language::PublicParameters,
    pub protocol_context: ProtocolContext,
    pub witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > CommitmentRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type Commitment = Commitment;

    type DecommitmentRoundParty = decommitment_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CsRng,
    ) -> Result<(Self::Commitment, Self::DecommitmentRoundParty)> {
        if !self.provers.contains(&self.party_id) {
            return Err(Error::Aggregation(
                aggregation::Error::NonParticipatingParty,
            ));
        }

        let is_randomizer = false;
        let is_verify = false;
        let statements: Result<Vec<Language::StatementSpaceGroupElement>> = self
            .witnesses
            .iter()
            .map(|witness| {
                Language::homomorphose(
                    witness,
                    &self.language_public_parameters,
                    is_randomizer,
                    is_verify,
                )
            })
            .collect();
        let statements = statements?;

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        let statement_masks_values =
            Language::StatementSpaceGroupElement::batch_normalize_const_generic(
                self.statement_masks,
            );

        let statements_values =
            Language::StatementSpaceGroupElement::batch_normalize(statements.clone());

        let mut transcript = Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
            &self.protocol_context,
            &self.language_public_parameters,
            statements_values.clone(),
            &statement_masks_values,
        )?;

        let commitment = Commitment::commit_transcript(
            self.party_id,
            COMMITMENT_LABEL.to_string(),
            &mut transcript,
            &commitment_randomness,
        );

        let decommitment = Decommitment::<REPETITIONS, Language> {
            statements: statements_values,
            statement_masks: statement_masks_values,
            commitment_randomness,
        };

        let decommitment_round_party =
            decommitment_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                provers: self.provers,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                witnesses: self.witnesses,
                statements,
                randomizers: self.randomizers,
                statement_masks: self.statement_masks,
                decommitment,
            };

        Ok((commitment, decommitment_round_party))
    }
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync + Send + Sync,
    > Party<REPETITIONS, Language, ProtocolContext>
{
    pub fn new_session(
        party_id: PartyID,
        provers: HashSet<PartyID>,
        language_public_parameters: Language::PublicParameters,
        protocol_context: ProtocolContext,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CsRng,
    ) -> Result<Self> {
        let (randomizers, statement_masks) = Proof::<
            REPETITIONS,
            Language,
            ProtocolContext,
        >::sample_randomizers_and_statement_masks(
            &language_public_parameters, rng,
        )?;

        Ok(Self {
            party_id,
            provers,
            language_public_parameters,
            protocol_context,
            witnesses,
            randomizers,
            statement_masks,
        })
    }
}

pub(super) const COMMITMENT_LABEL: &str = "maurer proof aggregation - commitment round commitment";
