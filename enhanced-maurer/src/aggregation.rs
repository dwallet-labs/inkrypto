// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use crate::{language::StatementSpaceGroupElement, Proof};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_aggregation_round;
pub mod proof_share_round;

pub type Output<
    const REPETITIONS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    RangeProof,
    UnboundedWitnessSpaceGroupElement,
    Language,
    ProtocolContext,
> = (
    Proof<
        REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedWitnessSpaceGroupElement,
        Language,
        ProtocolContext,
    >,
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
);

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        collections::{HashMap, HashSet},
        marker::PhantomData,
    };

    use crypto_bigint::U256;

    use group::{OsCsRng, PartyID, Samplable};
    use proof::range::{bulletproofs, bulletproofs::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS};

    use crate::{
        aggregation::commitment_round, language::tests::enhanced_language_public_parameters,
        EnhanceableLanguage, EnhancedLanguage,
    };

    pub(crate) fn setup_aggregation<
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
    ) -> HashMap<
        PartyID,
        commitment_round::Party<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            { COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS },
            bulletproofs::RangeProof,
            UnboundedWitnessSpaceGroupElement,
            Lang,
            PhantomData<()>,
        >,
    > {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters,
            language_public_parameters,
        );

        let witnesses: Vec<_> = witnesses
            .into_iter()
            .map(|witnesses| {
                EnhancedLanguage::<
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
                .unwrap()
            })
            .collect();

        let number_of_parties: u16 = witnesses.len().try_into().unwrap();

        let mut provers = HashSet::new();
        (1..=number_of_parties).for_each(|i| {
            provers.insert(i);
        });

        witnesses
            .clone()
            .into_iter()
            .enumerate()
            .map(|(party_id, witnesses)| {
                let party_id: u16 = (party_id + 1).try_into().unwrap();

                (
                    party_id,
                    commitment_round::Party::new_session(
                        party_id,
                        provers.clone(),
                        enhanced_language_public_parameters.clone(),
                        PhantomData,
                        witnesses,
                        &mut OsCsRng,
                    )
                    .unwrap(),
                )
            })
            .collect()
    }

    pub(crate) fn aggregates<
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
    ) {
        let enhanced_language_public_parameters = enhanced_language_public_parameters::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters.clone(),
        );

        let commitment_round_parties = setup_aggregation::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        let (.., (proof, statements)) =
            proof::aggregation::test_helpers::aggregates(commitment_round_parties);

        assert!(
            proof
                .verify(
                    &PhantomData,
                    &enhanced_language_public_parameters,
                    statements,
                    &mut OsCsRng,
                )
                .is_ok(),
            "valid aggregated enhanced proofs should verify"
        );
    }

    pub(crate) fn party_mismatching_maurer_range_proof_statements_aborts_identifiably<
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
    ) {
        let mut commitment_round_parties = setup_aggregation::<
            REPETITIONS,
            NUM_RANGE_CLAIMS,
            UnboundedWitnessSpaceGroupElement,
            Lang,
        >(
            unbounded_witness_public_parameters.clone(),
            language_public_parameters,
            witnesses,
        );

        let malicious_party_id = 2;
        let mut malicious_commitment_round_party = commitment_round_parties
            .get(&malicious_party_id)
            .unwrap()
            .clone();

        let mut witnesses = malicious_commitment_round_party
            .range_proof_commitment_round_party
            .witnesses;
        let wrong_witness = witnesses.first().cloned().unwrap();
        let mut wrong_witness_array: [_; NUM_RANGE_CLAIMS] = wrong_witness.into();
        wrong_witness_array[0] = U256::from(1u64).into();
        witnesses[0] = wrong_witness_array.into();
        malicious_commitment_round_party
            .range_proof_commitment_round_party
            .witnesses = witnesses;
        commitment_round_parties.insert(malicious_party_id, malicious_commitment_round_party);

        proof::aggregation::test_helpers::aggregates(commitment_round_parties);
    }
}
