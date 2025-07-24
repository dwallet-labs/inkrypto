// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::ops::Mul;

use serde::Serialize;

use crate::{Result, SOUND_PROOFS_REPETITIONS};
use group::Samplable;
use proof::GroupsPublicParameters;

/// Schnorr's Knowledge of Discrete Log Maurer Language.
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
pub type Language<Scalar, GroupElement> =
    private::Language<SOUND_PROOFS_REPETITIONS, Scalar, GroupElement>;

/// Knowledge of Discrete Log Maurer Language.
/// This is a generalized version that can be used for Fischlin proofs.
pub type FischlinLanguage<const REPETITIONS: usize, Scalar, GroupElement> =
    private::Language<REPETITIONS, Scalar, GroupElement>;

impl<
        const REPETITIONS: usize,
        Scalar: group::GroupElement
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: group::GroupElement,
    > crate::Language<REPETITIONS> for private::Language<REPETITIONS, Scalar, GroupElement>
{
    type WitnessSpaceGroupElement = Scalar;
    type StatementSpaceGroupElement = GroupElement;

    type PublicParameters = PublicParameters<
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        group::Value<GroupElement>,
    >;

    const NAME: &'static str = "Schnorr's Knowledge of the Discrete Log";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let generator = GroupElement::new(
            language_public_parameters.base,
            &language_public_parameters
                .groups_public_parameters
                .statement_space_public_parameters,
        )?;

        Ok(*witness * generator)
    }
}

/// The Public Parameters of Schnorr's Knowledge of Discrete Log Maurer Language.
#[derive(Clone, Debug, PartialEq, Serialize, Eq)]
pub struct PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue> {
    pub groups_public_parameters:
        GroupsPublicParameters<ScalarPublicParameters, GroupPublicParameters>,
    pub base: GroupElementValue,
}

impl<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
{
    pub fn new<Scalar, GroupElement>(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        base: GroupElementValue,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + group::GroupElement
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: scalar_group_public_parameters,
                statement_space_public_parameters: group_public_parameters,
            },
            base,
        }
    }
}

impl<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    AsRef<GroupsPublicParameters<ScalarPublicParameters, GroupPublicParameters>>
    for PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
{
    fn as_ref(&self) -> &GroupsPublicParameters<ScalarPublicParameters, GroupPublicParameters> {
        &self.groups_public_parameters
    }
}

pub type Proof<Scalar, GroupElement, ProtocolContext> =
    crate::Proof<SOUND_PROOFS_REPETITIONS, Language<Scalar, GroupElement>, ProtocolContext>;

pub(super) mod private {
    use std::marker::PhantomData;

    use serde::{Deserialize, Serialize};

    #[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
    pub struct Language<const REPETITIONS: usize, Scalar, GroupElement> {
        _scalar_choice: PhantomData<Scalar>,
        _group_element_choice: PhantomData<GroupElement>,
    }
}

#[cfg(any(test, feature = "test_helpers"))]
#[allow(clippy::type_complexity)]
pub mod test_helpers {
    use crate::language;
    use group::secp256k1;

    use super::*;

    pub type Lang = Language<secp256k1::Scalar, secp256k1::GroupElement>;
    pub type FischlinLang<const REPETITIONS: usize> =
        FischlinLanguage<REPETITIONS, secp256k1::Scalar, secp256k1::GroupElement>;

    pub fn language_public_parameters<const REPETITIONS: usize>(
    ) -> language::PublicParameters<REPETITIONS, FischlinLang<REPETITIONS>> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        PublicParameters::new::<secp256k1::Scalar, secp256k1::GroupElement>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters.clone(),
            secp256k1_group_public_parameters.generator,
        )
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use std::collections::HashMap;
    use std::iter;
    use std::marker::PhantomData;

    use crypto_bigint::U256;
    use rand_core::OsRng;
    use rstest::rstest;

    use group::{secp256k1, GroupElement, PartyID};
    use mpc::Weight;

    use crate::language::StatementSpaceGroupElement;
    use crate::test_helpers;
    use crate::test_helpers::{batch_verifies, generate_valid_proof, sample_witnesses};
    use group::CyclicGroupElement;

    use super::test_helpers::*;
    use super::*;

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1, 1)]
    #[case(2, 2)]
    #[case(3, 1)]
    fn valid_proofs_verifies_batch(#[case] number_of_proofs: usize, #[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

        let (proofs, statements): (
            Vec<crate::Proof<SOUND_PROOFS_REPETITIONS, Lang, PhantomData<()>>>,
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

    #[test]
    fn valid_fischlin_proof_verifies() {
        let language_public_parameters32 = language_public_parameters::<32>();
        test_helpers::valid_fischlin_proof_verifies::<32, FischlinLang<32>>(
            &language_public_parameters32,
            &mut OsRng,
        );

        let language_public_parameters16 = language_public_parameters::<16>();
        test_helpers::valid_fischlin_proof_verifies::<16, FischlinLang<16>>(
            &language_public_parameters16,
            &mut OsRng,
        );
    }

    #[test]
    fn invalid_fischlin_proof_fails_verification() {
        let language_public_parameters16 = language_public_parameters::<16>();

        test_helpers::invalid_fischlin_proof_fails_verification::<16, FischlinLang<16>>(
            &language_public_parameters16,
            &mut OsRng,
        );

        let language_public_parameters22 = language_public_parameters::<22>();
        test_helpers::invalid_fischlin_proof_fails_verification::<22, FischlinLang<22>>(
            &language_public_parameters22,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

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
        let verifier_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        prover_public_parameters.base = secp256k1::GroupElement::new(
            prover_public_parameters.base,
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
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

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
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

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
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

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
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

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
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

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
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

        test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(&language_public_parameters, number_of_parties, batch_size);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;

    use crate::knowledge_of_discrete_log::test_helpers::FischlinLang;
    use crate::{
        knowledge_of_discrete_log::test_helpers::{language_public_parameters, Lang},
        test_helpers, SOUND_PROOFS_REPETITIONS,
    };

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let maurer_language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS>();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, Lang>(
            &maurer_language_public_parameters,
            None,
            false,
            None,
        );

        let fischlin_language_public_parameters32 = language_public_parameters::<32>();
        test_helpers::benchmark_fischlin_proof::<32, FischlinLang<32>>(
            &fischlin_language_public_parameters32,
        );

        let fischlin_language_public_parameters16 = language_public_parameters::<16>();
        test_helpers::benchmark_fischlin_proof::<16, FischlinLang<16>>(
            &fischlin_language_public_parameters16,
        );

        test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, Lang>(
            &maurer_language_public_parameters,
            None,
            false,
            None,
        );
    }
}
