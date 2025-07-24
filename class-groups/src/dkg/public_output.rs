// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::dkg::{
    compute_public_verification_keys_for_participating_party, ProveEqualityOfDiscreteLog,
};
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeEncryptionSchemePublicParameters, SecretKeyShareCRTPrimeSetupParameters,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
    NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES, NUM_SECRET_SHARE_PRIMES,
    SECRET_SHARE_CRT_COEFFICIENTS, SECRET_SHARE_CRT_PRIMES_PRODUCT,
};
use crate::publicly_verifiable_secret_sharing::DealtSecretShare;
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use crate::{
    decryption_key_share, encryption_key, equivalence_class, publicly_verifiable_secret_sharing,
    CiphertextSpaceGroupElement, CiphertextSpaceValue, CompactIbqf, EquivalenceClass, Error,
    Result, SecretKeyShareSizedInteger, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
    SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{Encoding, Int, Invert, NonZero, Uint};
use group::helpers::{
    FlatMapResults, NormalizeConstGenericValues, NormalizeValues, TryCollectHashMap,
};
use group::{GroupElement, PartyID, PrimeGroupElement, Reduce};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use mpc::secret_sharing::shamir::over_the_integers::{
    interpolate_in_the_exponent, AdjustedLagrangeCoefficientSizedNumber, FactorialSizedNumber,
};
use mpc::WeightedThresholdAccessStructure;
use serde::{Deserialize, Serialize};
use std::array;
use std::collections::{HashMap, HashSet};

/// The serializable public output of the Distributed Key Generation (DKG) protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicOutput<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    pub(crate) setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    pub(crate) encryption_key: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(crate) threshold_encryption_key_per_crt_prime:
        [CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
    pub(crate) public_verification_keys:
        HashMap<PartyID, CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    pub(crate) encryptions_of_shares_per_crt_prime: HashMap<
        PartyID,
        [CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; NUM_SECRET_SHARE_PRIMES],
    >,
    pub(crate) threshold_encryption_of_decryption_key_per_crt_prime:
        [CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
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
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn new<GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>>(
        access_structure: &WeightedThresholdAccessStructure,
        setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        malicious_decryption_key_contribution_dealers: Vec<PartyID>,
        interpolation_subset: HashSet<PartyID>,
        adjusted_lagrange_coefficients: HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber>,
        parties_that_were_dealt_shares: HashSet<PartyID>,
        threshold_encryption_key_per_crt_prime: [EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
        public_verification_keys: HashMap<
            PartyID,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        coefficients_contribution_commitments: HashMap<
            PartyID,
            HashMap<Option<PartyID>, Vec<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        >,
        encryptions_of_shares_and_proofs: HashMap<
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
        encryptions_of_decryption_key_shares_and_proofs: HashMap<
            PartyID,
            HashMap<
                PartyID,
                DealtSecretShare<
                    NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                    SECRET_KEY_SHARE_WITNESS_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        >,
        n_factorial: FactorialSizedNumber,
    ) -> Result<Self> {
        let encryptions_of_shares_per_crt_prime = Self::sum_encryptions_of_shares::<GroupElement>(
            access_structure,
            malicious_decryption_key_contribution_dealers.clone(),
            parties_that_were_dealt_shares,
            encryptions_of_shares_and_proofs,
        )?
        .normalize_const_generic_values();

        // The elliptic curve Class-Group encryption key $\textsf{pk}_{q}$
        let encryption_key = coefficients_contribution_commitments
            .into_iter()
            .filter(|(dealer_party_id, _)| {
                !malicious_decryption_key_contribution_dealers.contains(dealer_party_id)
            })
            .map(|(_, deal_decryption_key_contribution_message)| {
                // Safe to unwrap by construction.
                let coefficients_contribution_commitments =
                    deal_decryption_key_contribution_message.get(&None).unwrap();

                // Safe to unwrap - we validated this vector is of size `t`, which is non-zero.
                *coefficients_contribution_commitments.first().unwrap()
            })
            .reduce(|a, b| a + b)
            .ok_or(Error::InvalidParameters)?
            .value();

        // Prepare for interpolation: keep just encryptions, only from the parties in the interpolation subset.
        let encryptions_of_decryption_key_shares: HashMap<_, _> =
            encryptions_of_decryption_key_shares_and_proofs
                .into_iter()
                .flat_map(|(_, encryptions_of_decryption_key_shares_and_proofs)| {
                    encryptions_of_decryption_key_shares_and_proofs
                        .into_iter()
                        .filter(|(dealer_virtual_party_id, _)| {
                            interpolation_subset.contains(dealer_virtual_party_id)
                        })
                        .map(|(dealer_virtual_party_id, dealt_secret_share_message)| {
                            (
                                dealer_virtual_party_id,
                                dealt_secret_share_message.map(|(_, ciphertext)| ciphertext),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

        // Interpolation of Encryption of Secret Shares:
        // At this point we have collected $S'_{B}$ encryptions $\textsf{ct}_{\textsf{share},Q'_{m'}}^{i}$
        // of the secret key share $[\textsf{sk}_{i}]$ per CRT prime.
        //
        // We now use interpolation above the integers to get $\textsf{ct}_{\Delta^{2}\cdot s,Q'_{m'}}$.
        let encryption_of_decryption_key_per_crt_prime = array::from_fn(|i| {
            // Safe to `unwrap` as this prime is non-zero.
            let crt_prime = NonZero::new(
                *setup_parameters_per_crt_prime[i]
                    .plaintext_space_public_parameters()
                    .modulus,
            )
            .unwrap();
            // Compute $n!^{-2} mod Q'_{m'}$
            let n_factorial_mod_crt_prime = n_factorial.reduce(&crt_prime);
            let params = MontyParams::new(
                setup_parameters_per_crt_prime[i]
                    .plaintext_space_public_parameters()
                    .modulus,
            );

            // Inversion must succeed as $n < Q'_{m'}$,
            // therefore, all the prime factors of `n!` are smaller than $Q'_{m'}$,
            // and since $Q'_{m'}$ is prime it does not divide $n!$,
            // and an inverse if and only if the gcd of the numbers is $1$.
            let n_factorial_square_inverse_mod_crt_prime =
                MontyForm::new(&n_factorial_mod_crt_prime, params)
                    .invert()
                    .unwrap()
                    .square()
                    .retrieve();

            let encryptions_of_decryption_key_shares = encryptions_of_decryption_key_shares
                .iter()
                .map(|(&dealer_virtual_party_id, dealt_secret_share_message)| {
                    (dealer_virtual_party_id, vec![dealt_secret_share_message[i]])
                })
                .collect();

            interpolate_in_the_exponent(
                encryptions_of_decryption_key_shares,
                adjusted_lagrange_coefficients.clone(),
                0,
                access_structure.number_of_virtual_parties(),
                n_factorial,
                None,
                false,
            )
            .map_err(Error::from)
            .and_then(|encryption_of_decryption_key_share| {
                encryption_of_decryption_key_share
                    .first()
                    .ok_or(Error::InternalError)
                    .map(|encryption_of_decryption_key_share| {
                        // This effectively divides the message by $n^-2$,
                        // reaching an encryption of the decryption key modulo $Q'_{m'}$.
                        encryption_of_decryption_key_share
                            .scale_vartime(&n_factorial_square_inverse_mod_crt_prime)
                            .value()
                    })
            })
        })
        .flat_map_results()?;

        let public_verification_keys = public_verification_keys.normalize_values();

        Ok(Self {
            setup_parameters_per_crt_prime,
            encryption_key,
            threshold_encryption_key_per_crt_prime: EquivalenceClass::<
                CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >::batch_normalize_const_generic(
                threshold_encryption_key_per_crt_prime
            ),
            public_verification_keys,
            encryptions_of_shares_per_crt_prime,
            threshold_encryption_of_decryption_key_per_crt_prime:
                encryption_of_decryption_key_per_crt_prime,
        })
    }

    /// This function filters out the malicious parties
    /// and sums the encryption of decryption key contribution shares
    /// yielding the encryption of decryption key share for each party.
    #[allow(clippy::type_complexity)]
    pub(crate) fn sum_encryptions_of_shares<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        access_structure: &WeightedThresholdAccessStructure,
        malicious_decryption_key_contribution_dealers: Vec<PartyID>,
        parties_that_were_dealt_shares: HashSet<PartyID>,
        encryptions_of_shares_and_proofs: HashMap<
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
    ) -> Result<
        HashMap<
            PartyID,
            [CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
                NUM_SECRET_SHARE_PRIMES],
        >,
    > {
        let encryptions_of_shares_and_proofs: HashMap<_, _> = encryptions_of_shares_and_proofs
            .into_iter()
            .filter(|(dealer_party_id, _)| {
                !malicious_decryption_key_contribution_dealers.contains(dealer_party_id)
            })
            .collect();

        let virtual_parties_that_were_dealt_shares =
            access_structure.virtual_subset(parties_that_were_dealt_shares)?;

        let encryptions_of_shares_per_crt_prime = publicly_verifiable_secret_sharing::Party::<
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
            encryptions_of_shares_and_proofs,
        )?;

        Ok(encryptions_of_shares_per_crt_prime)
    }

    pub(crate) fn compute_threshold_encryption_keys(
        malicious_decryption_key_contribution_dealers: Vec<PartyID>,
        threshold_encryption_key_shares_and_proofs: HashMap<
            PartyID,
            ProveEqualityOfDiscreteLog<
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    ) -> Result<
        [EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
    > {
        array::from_fn(|i| {
            threshold_encryption_key_shares_and_proofs
                .iter()
                .filter(|(dealer_party_id, _)| {
                    !malicious_decryption_key_contribution_dealers.contains(dealer_party_id)
                })
                .map(|(_, share_threshold_encryption_key)| {
                    let (_, threshold_encryption_key_share_per_crt_prime) =
                        &share_threshold_encryption_key[i];

                    *threshold_encryption_key_share_per_crt_prime
                })
                .reduce(|a, b| a + b)
                .ok_or(Error::InternalError)
        })
        .flat_map_results()
    }

    pub fn default_encryption_scheme_public_parameters<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
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
        GroupElement::Scalar: Default,
        group::PublicParameters<GroupElement::Scalar>: Default,
    {
        let plaintext_space_public_parameters =
            group::PublicParameters::<GroupElement::Scalar>::default();

        self.compute_encryption_scheme_public_parameters::<GroupElement>(
            plaintext_space_public_parameters,
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
            encryption_key::PublicParameters::new(setup_parameters.clone(), encryption_key)?;

        Ok(encryption_scheme_public_parameters)
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

        let public_verification_key_base = setup_parameters.h;

        let encryption_scheme_public_parameters = self
            .compute_encryption_scheme_public_parameters::<GroupElement>(
                plaintext_space_public_parameters,
                computational_security_parameter,
            )?;

        let decryption_key_share_public_parameters =
            decryption_key_share::PublicParameters::new::<GroupElement>(
                access_structure.threshold,
                access_structure.number_of_virtual_parties(),
                public_verification_key_base.value(),
                self.public_verification_keys.clone(),
                encryption_scheme_public_parameters,
            )?;

        Ok(decryption_key_share_public_parameters)
    }

    pub fn default_decryption_key_shares<
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        &self,
        tangible_party_id: PartyID,
        access_structure: &WeightedThresholdAccessStructure,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    ) -> Result<HashMap<PartyID, SecretKeyShareSizedInteger>>
    where
        GroupElement::Scalar: Default,
        group::PublicParameters<GroupElement::Scalar>: Default,
    {
        self.decrypt_decryption_key_shares::<GroupElement>(
            tangible_party_id,
            access_structure,
            decryption_key_per_crt_prime,
        )
    }

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
        let virtual_subset = access_structure.virtual_subset(HashSet::from([tangible_party_id]))?;

        let encryptions_of_shares_per_crt_prime = self
            .encryptions_of_shares_per_crt_prime
            .clone()
            .into_iter()
            .filter(|(virtual_party_id, _)| virtual_subset.contains(virtual_party_id))
            .map(|(virtual_party_id, encryption_of_share_per_crt_prime)| {
                let encryption_of_share_per_crt_prime = array::from_fn(|i| {
                    CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                        encryption_of_share_per_crt_prime[i],
                        self.setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters(),
                    )
                })
                .flat_map_results()?;

                Ok::<_, group::Error>((virtual_party_id, encryption_of_share_per_crt_prime))
            })
            .try_collect_hash_map()?;

        publicly_verifiable_secret_sharing::Party::<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >::decrypt_secrets(
            self.setup_parameters_per_crt_prime.clone(),
            SECRET_SHARE_CRT_COEFFICIENTS,
            SECRET_SHARE_CRT_PRIMES_PRODUCT,
            encryptions_of_shares_per_crt_prime,
            decryption_key_per_crt_prime,
        )
    }

    /// Sum the commitments to each receiving virtual party to get its public verification key.
    /// Note:
    /// * `reconstructed_commitments_to_sharing` is keyed by *virtual* participant party id.
    pub(crate) fn compute_public_verification_keys(
        access_structure: &WeightedThresholdAccessStructure,
        malicious_decryption_key_contribution_dealers: Vec<PartyID>,
        reconstructed_commitments_to_sharing: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
            >,
        >,
    ) -> HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>> {
        // Filter malicious parties out.
        let reconstructed_commitments_to_sharing: HashMap<_, _> =
            reconstructed_commitments_to_sharing
                .into_iter()
                .filter(|(dealer_party_id, _)| {
                    !malicious_decryption_key_contribution_dealers.contains(dealer_party_id)
                })
                .map(|(dealer_party_id, reconstructed_commitments_to_sharing)| {
                    // Safe to unwrap by construction.
                    let reconstructed_commitments_to_sharing =
                        reconstructed_commitments_to_sharing.get(&None).unwrap();

                    (
                        dealer_party_id,
                        reconstructed_commitments_to_sharing.clone(),
                    )
                })
                .collect();

        access_structure
            .party_to_virtual_parties()
            .keys()
            .flat_map(|participating_tangible_party_id| {
                compute_public_verification_keys_for_participating_party(
                    access_structure,
                    reconstructed_commitments_to_sharing.clone(),
                    participating_tangible_party_id,
                )
                .ok()
            })
            .flatten()
            .collect()
    }

    pub fn threshold_encryption_of_decryption_key_per_crt_prime(
        &self,
    ) -> Result<
        [CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
    > {
        array::from_fn(|i| {
            CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                self.threshold_encryption_of_decryption_key_per_crt_prime[i],
                self.setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters(),
            )
        })
        .flat_map_results()
        .map_err(Error::from)
    }

    pub fn threshold_encryption_scheme_public_parameters_per_crt_prime(
        &self,
    ) -> Result<
        [SecretKeyShareCRTPrimeEncryptionSchemePublicParameters;
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
    > {
        array::from_fn(|i| {
            let encryption_key = EquivalenceClass::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                self.threshold_encryption_key_per_crt_prime[i],
                self.setup_parameters_per_crt_prime[i].equivalence_class_public_parameters(),
            )?;

            encryption_key::PublicParameters::new(
                self.setup_parameters_per_crt_prime[i].clone(),
                encryption_key,
            )
        })
        .flat_map_results()
    }
}
