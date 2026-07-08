// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::WeightedThresholdAccessStructure;
use crate::{Error, ErrorKind, Result};
use crypto_bigint::I64;
use group::{GroupElement, PartyID};
use itertools::Itertools;
use std::collections::HashMap;

/// Deterministically expand a set of per-party contributions into multiple blended aggregates each of them guaranteed to be uniformly random.
/// Specifically we use a Vandermonde based blending matrix. Index the contributing parties in a canonical order and associate each party with a small
/// signed integer $r_{j}\in \{0, \pm 1, \pm 2, \ldots\}$. The `i`-th blended output is the sum
/// $Z_{i} = \sum_{j} r_{j}^{i| · X_{j}$, where per-party
/// inputs that are missing/invalid are excluded by not being present in `contributions`.
pub trait ContributionBlending: GroupElement {
    /// Deterministically expand a set of per-party contributions into multiple blended aggregates each of them guaranteed to be uniformly random.
    fn blend_contributions(
        access_structure: &WeightedThresholdAccessStructure,
        contributions: HashMap<PartyID, Self>,
        public_parameters: &Self::PublicParameters,
    ) -> Result<Vec<Self>>;
}

impl<G: GroupElement> ContributionBlending for G {
    fn blend_contributions(
        access_structure: &WeightedThresholdAccessStructure,
        contributions: HashMap<PartyID, Self>,
        public_parameters: &Self::PublicParameters,
    ) -> Result<Vec<Self>> {
        if contributions.is_empty() {
            return Err(Error::from(ErrorKind::InvalidParameters));
        }

        access_structure.is_authorized_subset(&contributions.keys().copied().collect())?;

        // We want an upper bound on the tangible number of parties the adversary controls,
        // and we are given an upper bound on the virtual parties it controls.
        // We take the pessimistic case where the adversary controls all the contributing parties with smallest weight, which is the worst case.
        let mut adversary_controlled_parties = 0;
        let mut adversary_controlled_weight = 0;

        let verified_contributions_weights_increasing = contributions
            .keys()
            .flat_map(|party_id| access_structure.party_to_weight.get(party_id))
            .sorted();
        for weight in verified_contributions_weights_increasing {
            if adversary_controlled_weight + weight >= access_structure.threshold {
                break;
            }

            adversary_controlled_weight += weight;
            adversary_controlled_parties += 1;
        }

        // $ N_p $
        let number_of_contributing_parties = contributions.len();
        let number_of_blended_contributions =
            number_of_contributing_parties - adversary_controlled_parties;

        let contributions: Vec<_> = contributions
            .into_iter()
            .sorted_by(|(party_id, _), (other_party_id, _)| party_id.cmp(other_party_id))
            .map(|(_, contribution)| contribution)
            .collect();

        // First, we associate with each of the presign share X_i where a point
        // $  i = r_{i} = -\floor{N_p/2},...+\floor{(N_p-1)/2} $.
        // Any choice of distinct points works but for efficiency
        // we take the smallest ones in absolute value: 0,-1,1,-2,2,-3,3 ...
        let blending_factors: Vec<I64> = (0..number_of_contributing_parties as u32)
            .map(|i| {
                let factor = i.div_ceil(2) as i32;
                if i.is_multiple_of(2) {
                    I64::from_i32(factor)
                } else {
                    I64::from_i32(-factor)
                }
            })
            .collect();

        // Safe to dereference, checked non-empty.
        let neutral_contribution = contributions[0].neutral();

        let mut blended_contributions = vec![];

        // A special case: the first "blended" contribution isn't blended at all, it is the typical aggregated contribution.
        let blended_contribution = contributions
            .iter()
            .fold(neutral_contribution.clone(), |a, b| {
                a.add_vartime(b, public_parameters)
            });

        blended_contributions.push(blended_contribution);

        let mut contributions_by_factor_to_the_ith_power = contributions;
        // The first factor is zero, so the first contribution by the factor will always be neutral.
        contributions_by_factor_to_the_ith_power[0] = neutral_contribution.clone();

        for _ in 1..number_of_blended_contributions {
            for k in 1..number_of_contributing_parties {
                // Multiply by the blending factor.
                // We started with the kth contribution * 1,
                // so this will always give us the kth contribution by the ith power of the factor.
                contributions_by_factor_to_the_ith_power[k] =
                    contributions_by_factor_to_the_ith_power[k]
                        .scale_integer_vartime(&blending_factors[k], public_parameters);
            }

            let blended_contribution = contributions_by_factor_to_the_ith_power
                .iter()
                .fold(neutral_contribution.clone(), |a, b| {
                    a.add_vartime(b, public_parameters)
                });

            blended_contributions.push(blended_contribution);
        }

        Ok(blended_contributions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{U256, U64};
    use group::{KnownOrderGroupElement, OsCsRng, Samplable};

    #[test]
    fn expands_contributions_correctly() {
        let scalar_group_public_parameters = group::secp256k1::scalar::PublicParameters::default();

        let party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 4)]);
        let threshold = 3;
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        let scalar_0 = group::secp256k1::Scalar::from(U64::from_u32(0));
        let scalar_42 = group::secp256k1::Scalar::from(U64::from_u32(42));
        let scalar_112 = group::secp256k1::Scalar::from(U64::from_u32(112));
        let scalar_151 = group::secp256k1::Scalar::from(U64::from_u32(151));
        let scalar_154 = group::secp256k1::Scalar::from(U64::from_u32(154));
        let scalar_order_minus_3 = group::secp256k1::Scalar::from(
            group::secp256k1::Scalar::order_from_public_parameters(&scalar_group_public_parameters)
                - U256::from_u32(3),
        );

        let contributions = HashMap::from([(1, scalar_42), (2, scalar_112)]);

        let blended_contributions = group::secp256k1::Scalar::blend_contributions(
            &access_structure,
            contributions,
            &scalar_group_public_parameters,
        )
        .unwrap();

        assert_eq!(blended_contributions, vec![scalar_154]);

        let contributions =
            HashMap::from([(1, scalar_42), (2, scalar_112), (3, scalar_order_minus_3)]);

        let blended_contributions = group::secp256k1::Scalar::blend_contributions(
            &access_structure,
            contributions,
            &scalar_group_public_parameters,
        )
        .unwrap();

        assert_eq!(scalar_42 + scalar_112 + scalar_order_minus_3, scalar_151); // Just an extra check: see that we overflow correctly

        assert_eq!(
            blended_contributions,
            vec![
                scalar_42 + scalar_112 + scalar_order_minus_3,
                scalar_order_minus_3 - scalar_112
            ]
        );

        let threshold = 67;
        let access_structure =
            WeightedThresholdAccessStructure::uniform(threshold, 100, 100, &mut OsCsRng).unwrap();

        let subset = access_structure
            .random_authorized_subset(&mut OsCsRng)
            .unwrap();
        let contributions: HashMap<_, _> = subset
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    group::secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng)
                        .unwrap(),
                )
            })
            .collect();

        let blended_contributions = group::secp256k1::Scalar::blend_contributions(
            &access_structure,
            contributions.clone(),
            &scalar_group_public_parameters,
        )
        .unwrap();

        let aggregated_contribution = contributions.values().fold(scalar_0, |a, b| a + b);

        assert_eq!(blended_contributions, vec![aggregated_contribution]);

        let subset = access_structure
            .random_subset_with_target_weight(68, &mut OsCsRng)
            .unwrap();
        let contributions: HashMap<_, _> = subset
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    group::secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng)
                        .unwrap(),
                )
            })
            .collect();

        let blended_contributions = group::secp256k1::Scalar::blend_contributions(
            &access_structure,
            contributions.clone(),
            &scalar_group_public_parameters,
        )
        .unwrap();

        let contributions: Vec<_> = contributions
            .into_iter()
            .sorted_by(|(party_id, _), (other_party_id, _)| party_id.cmp(other_party_id))
            .map(|(_, contribution)| contribution)
            .collect();

        let aggregated_contribution = contributions.iter().fold(scalar_0, |a, b| a + b);
        let expanded_second_contribution = contributions
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let scalar_half_i =
                    group::secp256k1::Scalar::from(U64::from_u32((i as u32).div_ceil(2)));
                if i.is_multiple_of(2) {
                    scalar_half_i * s
                } else {
                    (scalar_0 - scalar_half_i) * s
                }
            })
            .fold(scalar_0, |a, b| a + b);

        assert_eq!(
            blended_contributions,
            vec![aggregated_contribution, expanded_second_contribution]
        );

        let subset = access_structure
            .random_subset_with_target_weight(99, &mut OsCsRng)
            .unwrap();
        let contributions: HashMap<_, _> = subset
            .into_iter()
            .map(|party_id| {
                (
                    party_id,
                    group::secp256k1::Scalar::sample(&scalar_group_public_parameters, &mut OsCsRng)
                        .unwrap(),
                )
            })
            .collect();

        let blended_contributions = group::secp256k1::Scalar::blend_contributions(
            &access_structure,
            contributions.clone(),
            &scalar_group_public_parameters,
        )
        .unwrap();

        let contributions: Vec<_> = contributions
            .into_iter()
            .sorted_by(|(party_id, _), (other_party_id, _)| party_id.cmp(other_party_id))
            .map(|(_, contribution)| contribution)
            .collect();

        let aggregated_contribution = contributions.iter().fold(scalar_0, |a, b| a + b);

        let mut expected_blended_contributions = vec![aggregated_contribution];
        for j in 1..(99 + 1 - threshold) {
            let contribution = contributions
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let scalar_half_i =
                        group::secp256k1::Scalar::from(U64::from_u32(i.div_ceil(2) as u32));
                    let mut factor = scalar_half_i;
                    for _ in 0..(j - 1) {
                        factor = factor * scalar_half_i;
                    }
                    if i.is_multiple_of(2) || j.is_multiple_of(2) {
                        factor * s
                    } else {
                        (scalar_0 - factor) * s
                    }
                })
                .fold(scalar_0, |a, b| a + b);

            expected_blended_contributions.push(contribution);
        }

        assert_eq!(blended_contributions, expected_blended_contributions);
    }
}
