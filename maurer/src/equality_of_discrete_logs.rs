// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::ops::Mul;

use serde::Serialize;

use crate::{Result, SOUND_PROOFS_REPETITIONS};
use group::helpers::{const_generic_array_serialization, FlatMapResults};
use group::{self_product, Samplable};
use proof::GroupsPublicParameters;

/// Equality of Discrete Logs Maurer Language.
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However, knowledge-soundness proofs are group-dependent, and thus we can only assure security
/// for groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
pub type Language<const BATCH_SIZE: usize, Scalar, GroupElement> =
    private::Language<BATCH_SIZE, SOUND_PROOFS_REPETITIONS, Scalar, GroupElement>;

impl<
        const BATCH_SIZE: usize,
        const REPETITIONS: usize,
        Scalar: group::GroupElement + Samplable + Mul<GroupElement, Output = GroupElement> + Copy,
        GroupElement: group::GroupElement,
    > crate::Language<REPETITIONS> for Language<BATCH_SIZE, Scalar, GroupElement>
{
    type WitnessSpaceGroupElement = Scalar;
    type StatementSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, GroupElement>;

    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        group::Value<GroupElement>,
    >;

    const NAME: &'static str = "Equality of Discrete Logs";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let bases = language_public_parameters
            .bases
            .map(|base| {
                GroupElement::new(
                    base,
                    &language_public_parameters
                        .groups_public_parameters
                        .statement_space_public_parameters
                        .public_parameters,
                )
            })
            .flat_map_results()?;

        let bases_by_discrete_log = bases.map(|base| *witness * base);

        Ok(bases_by_discrete_log.into())
    }
}

/// The Public Parameters of Equality of Discrete Logs Maurer Language.
#[derive(Clone, Debug, PartialEq, Serialize, Eq)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    ScalarPublicParameters,
    GroupPublicParameters,
    GroupElementValue,
> where
    GroupElementValue: Serialize,
{
    pub groups_public_parameters: GroupsPublicParameters<
        ScalarPublicParameters,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    >,
    #[serde(with = "const_generic_array_serialization")]
    pub bases: [GroupElementValue; BATCH_SIZE],
}

impl<const BATCH_SIZE: usize, ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    PublicParameters<BATCH_SIZE, ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
where
    GroupElementValue: Serialize,
{
    pub fn new<Scalar, GroupElement>(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        bases: [GroupElementValue; BATCH_SIZE],
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + group::GroupElement
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: scalar_group_public_parameters,
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<BATCH_SIZE, GroupElement>,
                >::new(group_public_parameters),
            },
            bases,
        }
    }
}

impl<const BATCH_SIZE: usize, ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    AsRef<
        GroupsPublicParameters<
            ScalarPublicParameters,
            self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
        >,
    >
    for PublicParameters<
        BATCH_SIZE,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
    >
where
    GroupElementValue: Serialize,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        ScalarPublicParameters,
        self_product::PublicParameters<BATCH_SIZE, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

pub type Proof<const BATCH_SIZE: usize, Scalar, GroupElement, ProtocolContext> = crate::Proof<
    SOUND_PROOFS_REPETITIONS,
    Language<BATCH_SIZE, Scalar, GroupElement>,
    ProtocolContext,
>;

pub(super) mod private {
    use std::marker::PhantomData;

    use serde::{Deserialize, Serialize};

    #[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
    pub struct Language<const BATCH_SIZE: usize, const REPETITIONS: usize, Scalar, GroupElement> {
        _scalar_choice: PhantomData<Scalar>,
        _group_element_choice: PhantomData<GroupElement>,
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use crypto_bigint::U2048;
    use rand_core::OsRng;

    use group::{bounded_natural_numbers_group, GroupElement};
    use homomorphic_encryption::GroupsPublicParametersAccessors;
    use tiresias::test_helpers::N;

    use crate::language;

    use super::*;

    pub type TiresiasLang = Language<
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
            &mut OsRng,
        )
        .unwrap();

        let second_base = tiresias::CiphertextSpaceGroupElement::sample(
            &ciphertext_space_public_parameters,
            &mut OsRng,
        )
        .unwrap();

        PublicParameters::new::<
            bounded_natural_numbers_group::GroupElement<
                { tiresias::PaillierModulusSizedNumber::LIMBS },
            >,
            tiresias::CiphertextSpaceGroupElement,
        >(
            scalar_public_parameters,
            ciphertext_space_public_parameters,
            [first_base.value(), second_base.value()],
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::iter;

    use crypto_bigint::{Concat, Uint, U2048, U256};
    use rand_core::OsRng;
    use rstest::rstest;

    use class_groups::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use class_groups::EquivalenceClass;
    use group::GroupElement;
    use group::{bounded_natural_numbers_group, PartyID};
    use group::{secp256k1, CyclicGroupElement};
    use mpc::secret_sharing::shamir::over_the_integers::SecretKeyShareSizedNumber;
    use mpc::Weight;

    use crate::equality_of_discrete_logs::test_helpers::tiresias_language_public_parameters;
    use crate::equality_of_discrete_logs::test_helpers::TiresiasLang;
    use crate::language::StatementSpaceGroupElement;
    use crate::test_helpers::{batch_verifies, generate_valid_proof, sample_witnesses};
    use crate::{language, test_helpers};

    use super::*;

    pub type Lang = Language<2, secp256k1::Scalar, secp256k1::GroupElement>;

    pub fn language_public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang>
    {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let second_base =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap()
                * secp256k1::GroupElement::generator_from_public_parameters(
                    &secp256k1_group_public_parameters,
                )
                .unwrap();

        PublicParameters::new::<secp256k1::Scalar, secp256k1::GroupElement>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters.clone(),
            [
                secp256k1_group_public_parameters.generator,
                second_base.value(),
            ],
        )
    }

    const DISCRIMINANT_LIMBS: usize = U2048::LIMBS;
    pub(crate) type ClassGroupsLang = Language<
        2,
        bounded_natural_numbers_group::GroupElement<{ SecretKeyShareSizedNumber::LIMBS }>,
        EquivalenceClass<DISCRIMINANT_LIMBS>,
    >;

    pub(crate) fn class_groups_language_public_parameters(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, ClassGroupsLang> {
        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();

        let scalar_public_parameters = bounded_natural_numbers_group::PublicParameters::new(
            Uint::<DISCRIMINANT_LIMBS>::BITS,
            <Uint<DISCRIMINANT_LIMBS> as Concat>::Output::BITS,
        )
        .unwrap();

        let group_public_parameters = setup_parameters
            .equivalence_class_public_parameters()
            .clone();

        let first_base = setup_parameters.h;
        let second_base = first_base + first_base + first_base;

        PublicParameters::new::<
            bounded_natural_numbers_group::GroupElement<{ SecretKeyShareSizedNumber::LIMBS }>,
            EquivalenceClass<DISCRIMINANT_LIMBS>,
        >(
            scalar_public_parameters,
            group_public_parameters,
            [first_base.value(), second_base.value()],
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        );

        let language_public_parameters = tiresias_language_public_parameters();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, TiresiasLang>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        );

        let language_public_parameters = class_groups_language_public_parameters();
        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(1, 1)]
    #[case(2, 2)]
    #[case(3, 1)]
    fn valid_proofs_verifies_batch(#[case] number_of_proofs: usize, #[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        let (proofs, statements): (
            Vec<crate::Proof<SOUND_PROOFS_REPETITIONS, Lang, _>>,
            Vec<Vec<StatementSpaceGroupElement<SOUND_PROOFS_REPETITIONS, Lang>>>,
        ) = iter::repeat_with(|| {
            let witnesses = sample_witnesses::<SOUND_PROOFS_REPETITIONS, Lang>(
                &language_public_parameters,
                batch_size,
                &mut OsRng,
            );

            generate_valid_proof(&language_public_parameters, witnesses, &mut OsRng)
        })
        .take(number_of_proofs)
        .unzip();

        batch_verifies(proofs, statements, &language_public_parameters, &mut OsRng);
    }

    #[rstest]
    #[case(1, 1)]
    #[case(2, 2)]
    #[case(3, 1)]
    fn valid_proofs_verifies_batch_tiresias(
        #[case] number_of_proofs: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = tiresias_language_public_parameters();

        let (proofs, statements): (
            Vec<crate::Proof<SOUND_PROOFS_REPETITIONS, TiresiasLang, _>>,
            Vec<Vec<StatementSpaceGroupElement<SOUND_PROOFS_REPETITIONS, TiresiasLang>>>,
        ) = iter::repeat_with(|| {
            let witnesses = sample_witnesses::<SOUND_PROOFS_REPETITIONS, TiresiasLang>(
                &language_public_parameters,
                batch_size,
                &mut OsRng,
            );

            generate_valid_proof(&language_public_parameters, witnesses, &mut OsRng)
        })
        .take(number_of_proofs)
        .unzip();

        batch_verifies(proofs, statements, &language_public_parameters, &mut OsRng);
    }

    #[rstest]
    #[case(1, 1)]
    #[case(2, 2)]
    #[case(3, 1)]
    fn valid_proofs_verifies_batch_class_groups(
        #[case] number_of_proofs: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters = class_groups_language_public_parameters();

        let (proofs, statements): (
            Vec<crate::Proof<SOUND_PROOFS_REPETITIONS, ClassGroupsLang, _>>,
            Vec<Vec<StatementSpaceGroupElement<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>>>,
        ) = iter::repeat_with(|| {
            let witnesses = sample_witnesses::<SOUND_PROOFS_REPETITIONS, ClassGroupsLang>(
                &language_public_parameters,
                batch_size,
                &mut OsRng,
            );

            generate_valid_proof(&language_public_parameters, witnesses, &mut OsRng)
        })
        .take(number_of_proofs)
        .unzip();

        batch_verifies(proofs, statements, &language_public_parameters, &mut OsRng);
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
            None,
            None,
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_over_invalid_public_parameters_fails_verification(#[case] batch_size: usize) {
        let verifier_public_parameters = language_public_parameters();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        prover_public_parameters.bases[0] = secp256k1::GroupElement::new(
            prover_public_parameters.bases[0],
            &secp256k1_group_public_parameters,
        )
        .unwrap()
        .generator()
        .neutral()
        .value();

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );

        let mut prover_public_parameters = verifier_public_parameters.clone();
        prover_public_parameters
            .groups_public_parameters
            .statement_space_public_parameters
            .public_parameters
            .curve_equation_a = U256::from(42u8);

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_with_incomplete_transcript_fails(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::proof_with_incomplete_transcript_fails::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(
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

        test_helpers::statement_aggregates_asynchronously::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            threshold,
            party_to_weight,
            batch_size,
            &mut OsRng,
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

        test_helpers::unresponsive_parties_aborts_session_identifiably::<
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

        test_helpers::wrong_decommitment_aborts_session_identifiably::<
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

        test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(&language_public_parameters, number_of_parties, batch_size);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;

    use crate::equality_of_discrete_logs::test_helpers::{
        tiresias_language_public_parameters, TiresiasLang,
    };
    use crate::{test_helpers, SOUND_PROOFS_REPETITIONS};

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let maurer_language_public_parameters = tiresias_language_public_parameters();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, TiresiasLang>(
            &maurer_language_public_parameters,
            None,
            false,
            None,
        );

        test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, TiresiasLang>(
            &maurer_language_public_parameters,
            None,
            false,
            None,
        );
    }
}
