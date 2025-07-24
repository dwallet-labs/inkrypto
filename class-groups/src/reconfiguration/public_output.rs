// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::compute_public_verification_keys_for_participating_party;
use crate::encryption_key::public_parameters::Instantiate;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    construct_setup_parameters_per_crt_prime, CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES, NUM_SECRET_SHARE_PRIMES,
    SECRET_SHARE_CRT_COEFFICIENTS, SECRET_SHARE_CRT_PRIMES_PRODUCT,
};
use crate::publicly_verifiable_secret_sharing::DealtSecretShare;
use crate::reconfiguration::RANDOMIZER_LIMBS;
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use crate::{
    decryption_key_share, encryption_key, equivalence_class, publicly_verifiable_secret_sharing,
    CiphertextSpaceGroupElement, CiphertextSpaceValue, CompactIbqf, EquivalenceClass, Result,
    SecretKeyShareSizedInteger, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, SECRET_KEY_SHARE_LIMBS,
    SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use crypto_bigint::{Encoding, Int, Uint};
use group::helpers::{FlatMapResults, NormalizeConstGenericValues, TryCollectHashMap};
use group::{GroupElement, PartyID, PrimeGroupElement};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::secret_sharing::shamir::over_the_integers::FactorialSizedNumber;
use mpc::WeightedThresholdAccessStructure;
use serde::{Deserialize, Serialize};
use std::array;
use std::collections::{HashMap, HashSet};

/// The serializable public output of the Reconfiguration protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicOutput<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> where
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    masked_decryption_key_by_n_factorial: SecretKeyShareSizedInteger,
    public_verification_keys: HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    encryptions_of_randomizer_shares_per_crt_prime: HashMap<
        PartyID,
        [CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; NUM_SECRET_SHARE_PRIMES],
    >,
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    >
    PublicOutput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn new<GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>>(
        access_structure: &WeightedThresholdAccessStructure,
        parties_that_were_dealt_shares: HashSet<PartyID>,
        masked_decryption_key: Int<RANDOMIZER_LIMBS>,
        reconstructed_commitments_to_randomizer_sharing: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
        encryptions_of_randomizer_contribution_shares_and_proofs: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShare<
                            NUM_SECRET_SHARE_PRIMES,
                            SECRET_KEY_SHARE_WITNESS_LIMBS,
                            PLAINTEXT_SPACE_SCALAR_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                        >,
                    >,
                >,
            >,
        >,
        encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        public_verification_key_base: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        n_factorial: FactorialSizedNumber,
    ) -> Result<Self>
    where
        GroupElement::Scalar: Default,
    {
        let reconstructed_commitments_to_randomizer_sharing: HashMap<_, _> =
            reconstructed_commitments_to_randomizer_sharing
                .into_iter()
                .flat_map(|(dealer_tangible_party_id, commitments)| {
                    commitments
                        .get(&None)
                        .cloned()
                        .map(|commitments| (dealer_tangible_party_id, commitments))
                })
                .collect();

        // SecretKeyShareSizedInteger is of randomizer size as $r$ statistically hides $s$ therefore $r+s$ is statistically indsitinguishable from $rR and as such the size is large enough
        // excpet with statsitcally neglible probablity.
        // We compute $n_{new}!\cdot (r+s)$ (the bound accounts for this multiplication as well)
        let masked_decryption_key_by_n_factorial =
            SecretKeyShareSizedInteger::from(&masked_decryption_key) * n_factorial;

        // The final verification key of the virtual upcoming party $j_{R}$ is computed as $h_{q}^{n_{new}!(r+s)}\cdot \bar{C}_{j_{R}}^{-1}$.    fn compute_public_verification_keys<
        let public_verification_keys = Self::compute_public_verification_keys::<GroupElement>(
            access_structure,
            masked_decryption_key_by_n_factorial,
            reconstructed_commitments_to_randomizer_sharing,
            public_verification_key_base,
        );

        let virtual_parties_that_were_dealt_shares =
            access_structure.virtual_subset(parties_that_were_dealt_shares)?;

        let encryptions_of_randomizer_shares_per_crt_prime =
            publicly_verifiable_secret_sharing::Party::<
                NUM_SECRET_SHARE_PRIMES,
                SECRET_KEY_SHARE_LIMBS,
                SECRET_KEY_SHARE_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >::sum_encryptions_of_additively_shared_secrets(
                virtual_parties_that_were_dealt_shares,
                access_structure,
                encryptions_of_randomizer_contribution_shares_and_proofs,
            )?
            .normalize_const_generic_values();

        Ok(Self {
            encryption_key,
            masked_decryption_key_by_n_factorial,
            public_verification_keys,
            encryptions_of_randomizer_shares_per_crt_prime,
        })
    }

    // The parties threshold decrypt to get $r+s$ in plaintext as a integer which is then multiplied by $n_{new}!$.
    // In addition, the parties compute commitment each party’s share on the randomizer first by using Homer’s method to compute commitment the each parties randomizer contribution share.
    // multiplying commitments to contribution share from each party in the authorized subset. This commitment will be denoted by $\bar{C}_{j}$.
    // The final verification key of the virtual upcoming party $j_{R}$ is computed as $h_{q}^{n_{new}!(r+s)}\cdot \bar{C}_{j_{R}}^{-1}$.    fn compute_public_verification_keys<
    fn compute_public_verification_keys<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        access_structure: &WeightedThresholdAccessStructure,
        masked_decryption_key_by_n_factorial: SecretKeyShareSizedInteger,
        reconstructed_commitments_to_randomizer_sharing: HashMap<
            PartyID,
            HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
        public_verification_key_base: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ) -> HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
    where
        GroupElement::Scalar: Default,
    {
        let masked_decryption_key_commitment_by_n_factorial = public_verification_key_base
            .scale_integer_vartime(&masked_decryption_key_by_n_factorial);

        let commitments_to_randomizer_share: HashMap<_, _> = access_structure
            .party_to_virtual_parties()
            .keys()
            .flat_map(|participating_tangible_party_id| {
                compute_public_verification_keys_for_participating_party(
                    access_structure,
                    reconstructed_commitments_to_randomizer_sharing.clone(),
                    participating_tangible_party_id,
                )
                .ok()
            })
            .flatten()
            .collect();

        commitments_to_randomizer_share
            .into_iter()
            .map(
                |(dealer_virtual_party_id, reconstruct_commitment_to_randomizer_share)| {
                    let public_verification_key = (masked_decryption_key_commitment_by_n_factorial
                        - reconstruct_commitment_to_randomizer_share)
                        .value();

                    (dealer_virtual_party_id, public_verification_key)
                },
            )
            .collect()
    }

    pub fn default_decryption_key_share_public_parameters<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
        access_structure: &WeightedThresholdAccessStructure,
    ) -> Result<
        decryption_key_share::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    >
    where
        SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: DeriveFromPlaintextPublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: Instantiate<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        GroupElement::Scalar: Default,
        group::PublicParameters<GroupElement::Scalar>: Default,
    {
        let plaintext_space_public_parameters =
            group::PublicParameters::<GroupElement::Scalar>::default();

        self.compute_decryption_key_share_public_parameters::<GroupElement>(
            plaintext_space_public_parameters,
            access_structure,
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
    }

    pub fn compute_encryption_scheme_public_parameters<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
        plaintext_space_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        computational_security_parameter: u32,
    ) -> Result<
        encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    >
    where
        SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: DeriveFromPlaintextPublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: Instantiate<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        GroupElement::Scalar: Default,
    {
        let setup_parameters = SetupParameters::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            _,
        >::derive_from_plaintext_parameters::<GroupElement::Scalar>(
            plaintext_space_public_parameters.clone(),
            computational_security_parameter,
        )?;

        let encryption_key = EquivalenceClass::new(
            self.encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        )?;
        let encryption_scheme_public_parameters =
            encryption_key::PublicParameters::new_maximally_accelerated(
                setup_parameters.clone(),
                encryption_key,
            )?;

        Ok(encryption_scheme_public_parameters)
    }

    pub fn compute_decryption_key_share_public_parameters<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
        plaintext_space_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        access_structure: &WeightedThresholdAccessStructure,
        computational_security_parameter: u32,
    ) -> Result<
        decryption_key_share::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    >
    where
        SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: DeriveFromPlaintextPublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        encryption_key::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >: Instantiate<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        GroupElement::Scalar: Default,
    {
        let encryption_scheme_public_parameters = self
            .compute_encryption_scheme_public_parameters::<GroupElement>(
                plaintext_space_public_parameters,
                computational_security_parameter,
            )?;

        let decryption_key_share_public_parameters =
            decryption_key_share::PublicParameters::new::<GroupElement>(
                access_structure.threshold,
                access_structure.number_of_virtual_parties(),
                encryption_scheme_public_parameters
                    .setup_parameters
                    .h
                    .value(),
                self.public_verification_keys.clone(),
                encryption_scheme_public_parameters,
            )?;

        Ok(decryption_key_share_public_parameters)
    }

    // The final share is computed as $n_{new}!\cdot (r+s)-[r]_{i_{R}}$.
    pub fn decrypt_decryption_key_shares<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    ) -> Result<HashMap<PartyID, SecretKeyShareSizedInteger>>
    where
        GroupElement::Scalar: Default,
    {
        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)?;

        // Upcoming quorum output round:
        let virtual_subset = access_structure.virtual_subset(HashSet::from([tangible_party_id]))?;

        let encryptions_of_randomizer_shares_per_crt_prime = self
            .encryptions_of_randomizer_shares_per_crt_prime
            .clone()
            .into_iter()
            .filter(|(virtual_party_id, _)| virtual_subset.contains(virtual_party_id))
            .map(|(virtual_party_id, encryption_of_share_per_crt_prime)| {
                let encryption_of_share_per_crt_prime = array::from_fn(|i| {
                    CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                        encryption_of_share_per_crt_prime[i],
                        setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters(),
                    )
                })
                .flat_map_results()?;

                Ok::<_, group::Error>((virtual_party_id, encryption_of_share_per_crt_prime))
            })
            .try_collect_hash_map()?;

        let randomizer_shares = publicly_verifiable_secret_sharing::Party::<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::decrypt_secrets(
            setup_parameters_per_crt_prime.clone(),
            SECRET_SHARE_CRT_COEFFICIENTS,
            SECRET_SHARE_CRT_PRIMES_PRODUCT,
            encryptions_of_randomizer_shares_per_crt_prime,
            decryption_key_per_crt_prime,
        )?;

        let decryption_key_shares = randomizer_shares
            .into_iter()
            .map(|(dealer_virtual_party_id, randomizer_share)| {
                (
                    dealer_virtual_party_id,
                    self.masked_decryption_key_by_n_factorial - randomizer_share,
                )
            })
            .collect();

        Ok(decryption_key_shares)
    }
}
