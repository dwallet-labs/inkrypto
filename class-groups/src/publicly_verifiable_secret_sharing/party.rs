// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use crypto_bigint::{Encoding, Int, Uint, U64};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use commitment::CommitmentSizedNumber;
use group::helpers::{DeduplicateAndSort, FlatMapResults, TryCollectHashMap};
use group::{bounded_integers_group, self_product, CsRng, GroupElement, PrimeGroupElement};
use homomorphic_encryption::AdditivelyHomomorphicDecryptionKey;
use mpc::secret_sharing::shamir::over_the_integers::{
    factorial, FactorialSizedNumber, MAX_PLAYERS, MAX_THRESHOLD,
};
use mpc::PartyID;
use mpc::WeightedThresholdAccessStructure;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::prove_encryption_of_discrete_log_per_crt_prime;
use crate::encryption_key::public_parameters::Instantiate;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::*;
use crate::publicly_verifiable_secret_sharing::{
    chinese_remainder_theorem, BaseProtocolContext, DealtSecretShare, EncryptionOfDiscreteLogProof,
    ProtocolContext,
};
use crate::setup::SetupParameters;
use crate::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement, CiphertextSpaceValue,
    CompactIbqf, EquivalenceClass, Error, Result,
};

/// The Publicly Verifiable Secret Sharing (PVSS) party,
/// used to asynchronously and verifiably distribute a sharing over an additive secret.
pub struct Party<
    const NUM_PRIMES: usize,
    const SECRET_SHARE_LIMBS: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
> where
    Int<SECRET_SHARE_LIMBS>: Encoding,
    Uint<SECRET_SHARE_LIMBS>: Encoding,
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

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
    pub(in crate::publicly_verifiable_secret_sharing) session_id: CommitmentSizedNumber,
    pub(in crate::publicly_verifiable_secret_sharing) dealer_tangible_party_id: PartyID,
    pub(in crate::publicly_verifiable_secret_sharing) participating_tangible_party_id:
        Option<PartyID>,
    pub(in crate::publicly_verifiable_secret_sharing) dealer_access_structure:
        WeightedThresholdAccessStructure,
    pub(in crate::publicly_verifiable_secret_sharing) participating_parties_access_structure:
        WeightedThresholdAccessStructure,
    pub(in crate::publicly_verifiable_secret_sharing) participating_parties_n_factorial:
        FactorialSizedNumber,
    pub(in crate::publicly_verifiable_secret_sharing) public_verification_key_base:
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    pub(in crate::publicly_verifiable_secret_sharing) discrete_log_witness_group_public_parameters:
        bounded_integers_group::PublicParameters<DISCRETE_LOG_WITNESS_LIMBS>,
    pub(in crate::publicly_verifiable_secret_sharing) setup_parameters_per_crt_prime:
        [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    pub(in crate::publicly_verifiable_secret_sharing) equivalence_class_public_parameters:
        group::PublicParameters<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    pub(in crate::publicly_verifiable_secret_sharing) encryption_keys_per_crt_prime:
        HashMap<PartyID, [EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
    pub(in crate::publicly_verifiable_secret_sharing) encryption_keys_and_proofs_per_crt_prime:
        HashMap<
            PartyID,
            [(
                EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
    pub(in crate::publicly_verifiable_secret_sharing) base_protocol_context: BaseProtocolContext,
    pub(in crate::publicly_verifiable_secret_sharing) secret_bits: u32,
    pub(in crate::publicly_verifiable_secret_sharing) parties_without_valid_encryption_keys:
        Vec<PartyID>,
    pub(in crate::publicly_verifiable_secret_sharing) participating_and_dealers_match: bool,
    _group_choice: PhantomData<GroupElement>,
    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<
        const NUM_PRIMES: usize,
        const SECRET_SHARE_LIMBS: usize,
        const DISCRETE_LOG_WITNESS_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    Party<
        NUM_PRIMES,
        SECRET_SHARE_LIMBS,
        DISCRETE_LOG_WITNESS_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<SECRET_SHARE_LIMBS>: Encoding,
    Uint<SECRET_SHARE_LIMBS>: Encoding,
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

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
    pub fn new(
        session_id: CommitmentSizedNumber,
        dealer_tangible_party_id: PartyID,
        participating_tangible_party_id: Option<PartyID>,
        dealer_access_structure: WeightedThresholdAccessStructure,
        participating_parties_access_structure: WeightedThresholdAccessStructure,
        setup_parameters: SetupParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
        base_protocol_context: BaseProtocolContext,
        public_verification_key_base: CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        secret_bits: u32,
        discrete_log_sampling_bits: u32,
        participating_and_dealers_match: bool,
    ) -> Result<Self> {
        if u32::from(dealer_access_structure.threshold) > MAX_THRESHOLD
            || u32::from(participating_parties_access_structure.threshold) > MAX_THRESHOLD
            || u32::from(dealer_access_structure.number_of_virtual_parties()) > MAX_PLAYERS
            || u32::from(participating_parties_access_structure.number_of_virtual_parties())
                > MAX_PLAYERS
        {
            return Err(Error::InvalidParameters);
        }

        let participating_parties_n_factorial =
            factorial(participating_parties_access_structure.number_of_virtual_parties());

        let equivalence_class_public_parameters = setup_parameters
            .equivalence_class_public_parameters()
            .clone();

        let discrete_log_witness_group_public_parameters = bounded_integers_group::PublicParameters::<
            DISCRETE_LOG_WITNESS_LIMBS,
        >::new_with_randomizer_upper_bound(
            discrete_log_sampling_bits
        )?;

        let public_verification_key_base = EquivalenceClass::new(
            public_verification_key_base,
            &equivalence_class_public_parameters,
        )?;

        let participating_tangible_parties: HashSet<_> = participating_parties_access_structure
            .party_to_weight
            .keys()
            .copied()
            .collect();
        let parties_with_encryption_keys: HashSet<_> =
            encryption_key_values_and_proofs_per_crt_prime
                .keys()
                .copied()
                .collect();
        if !participating_tangible_parties.is_superset(&parties_with_encryption_keys) {
            return Err(Error::InvalidParameters);
        }
        let parties_without_encryption_keys: HashSet<_> = participating_tangible_parties
            .difference(&parties_with_encryption_keys)
            .copied()
            .collect();

        let (parties_sending_invalid_encryption_keys, encryption_keys_and_proofs_per_crt_prime) =
            instantiate_encryption_keys_per_crt_prime(
                &setup_parameters_per_crt_prime,
                encryption_key_values_and_proofs_per_crt_prime,
            )?;

        let parties_without_valid_encryption_keys = parties_without_encryption_keys
            .into_iter()
            .chain(parties_sending_invalid_encryption_keys)
            .deduplicate_and_sort();

        let encryption_keys_per_crt_prime: HashMap<_, _> = encryption_keys_and_proofs_per_crt_prime
            .clone()
            .into_iter()
            .map(|(party_id, encryption_keys_and_proofs)| {
                (
                    party_id,
                    encryption_keys_and_proofs.map(|(encryption_key, _)| encryption_key),
                )
            })
            .collect();

        let party = Self {
            session_id,
            dealer_tangible_party_id,
            participating_tangible_party_id,
            dealer_access_structure,
            participating_parties_access_structure,
            participating_parties_n_factorial,
            public_verification_key_base,
            discrete_log_witness_group_public_parameters,
            setup_parameters_per_crt_prime,
            equivalence_class_public_parameters,
            encryption_keys_and_proofs_per_crt_prime,
            encryption_keys_per_crt_prime,
            base_protocol_context,
            secret_bits,
            parties_without_valid_encryption_keys,
            participating_and_dealers_match,
            _group_choice: PhantomData,
            _protocol_context_choice: PhantomData,
        };

        Ok(party)
    }

    /// Generate a proof $\pi_{\textsf{share},i}\gets \Pi_{\textsf{zk}}^{L_{\textsf{EncDL}}[\AHEpk_{i},(\mathbb{G}_{q},\bar{g}_{q'},\mathbb{Z})]}(\textsf{ct}_{i},\bar{C}_{i};[s]_{i},\eta_{i})$.
    /// $(\pi_{\textsf{share}, (\textsf{ct}_{i}, \bar{C}_{i}))$
    #[allow(unused_variables)]
    pub fn prove_encryption_of_discrete_log_per_crt_prime(
        &self,
        dealer_virtual_party_id: Option<PartyID>,
        participating_tangible_party_id: PartyID,
        participating_virtual_party_id: PartyID,
        discrete_log: bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
        rng: &mut impl CsRng,
    ) -> Result<
        [(
            EncryptionOfDiscreteLogProof<
                DISCRETE_LOG_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
            CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ); NUM_PRIMES],
    > {
        let encryption_key_per_crt_prime = self
            .encryption_keys_per_crt_prime
            .get(&participating_tangible_party_id)
            .ok_or(Error::InvalidParameters)?
            .iter()
            .take(NUM_PRIMES)
            .copied()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        prove_encryption_of_discrete_log_per_crt_prime::<
            NUM_PRIMES,
            DISCRETE_LOG_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >(
            self.dealer_tangible_party_id,
            dealer_virtual_party_id,
            Some(participating_tangible_party_id),
            Some(participating_virtual_party_id),
            self.session_id,
            discrete_log,
            self.equivalence_class_public_parameters.clone(),
            self.public_verification_key_base,
            &encryption_key_per_crt_prime,
            &self.setup_parameters_per_crt_prime,
            self.base_protocol_context.clone(),
            self.discrete_log_witness_group_public_parameters
                .sample_bits,
            rng,
        )
    }

    /// Calculate $\bar{C}_{i}=\Pi_{\ell\in[t]}C_{\ell}^{j^{\ell}}$ via Horner's method.
    /// Assumes the vector is of size `t`, and implicitly that it is non-empty.
    pub fn reconstruct_commitment_to_share_in_the_exponent(
        participating_parties_n_factorial: FactorialSizedNumber,
        participating_party_id: PartyID, // $j$
        coefficients_contribution_commitments: Vec<
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let participating_party_id = U64::from(participating_party_id);

        // The free coefficient of the polynomial is $\Delta\cdot{s_i}$ while the commitment is for $s_i$.
        // So we have to multiply the commitment by $\Delta$.
        // Safe to dereference as it is non-empty.
        let mut coefficients_contribution_commitments =
            coefficients_contribution_commitments.clone();

        coefficients_contribution_commitments[0] = coefficients_contribution_commitments[0]
            .scale_vartime(&participating_parties_n_factorial);

        // Now reverse the coefficient commitment vector and reconstruct via Horner's method.
        let mut reversed_coefficient_commitments =
            coefficients_contribution_commitments.into_iter().rev();

        // Safe to `unwrap` as it is non-empty.
        let last_coefficient_commitment = reversed_coefficient_commitments.next().unwrap();

        reversed_coefficient_commitments.fold(
            last_coefficient_commitment,
            |partially_evaluated_polynomial, coefficient| {
                (partially_evaluated_polynomial.scale_vartime(&participating_party_id))
                    .add_vartime(&coefficient)
            },
        )
    }

    pub fn reconstruct_commitment_to_sharing(
        &self,
        coefficients_contribution_commitments: HashMap<
            PartyID,
            HashMap<Option<PartyID>, Vec<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>,
        >,
        virtual_subset: HashSet<PartyID>,
    ) -> HashMap<
        PartyID,
        HashMap<
            Option<PartyID>,
            HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    > {
        #[cfg(not(feature = "parallel"))]
        let iter = coefficients_contribution_commitments.into_iter();
        #[cfg(feature = "parallel")]
        let iter = coefficients_contribution_commitments.into_par_iter();

        iter.map(
            |(dealer_tangible_party_id, coefficients_contribution_commitments)| {
                let reconstructed_commitments_to_sharing = coefficients_contribution_commitments
                    .into_iter()
                    .map(
                        |(dealer_virtual_party_id, coefficients_contribution_commitments)| {
                            // A mapping from *virtual* participant party id to the reconstructed commitment of its share.
                            let reconstructed_commitments_to_sharing: HashMap<_, _> =
                                virtual_subset
                                    .iter()
                                    .map(|participating_virtual_party_id| {
                                        let commitment_to_share =
                                            Self::reconstruct_commitment_to_share_in_the_exponent(
                                                self.participating_parties_n_factorial,
                                                *participating_virtual_party_id,
                                                coefficients_contribution_commitments.clone(),
                                            );

                                        (*participating_virtual_party_id, commitment_to_share)
                                    })
                                    .collect();

                            (
                                dealer_virtual_party_id,
                                reconstructed_commitments_to_sharing,
                            )
                        },
                    )
                    .collect();

                (
                    dealer_tangible_party_id,
                    reconstructed_commitments_to_sharing,
                )
            },
        )
        .collect()
    }

    /// This function sums an additively shared secret and (per CRT-prime) returns a single encryption of the secret, per virtual party in `virtual_subset`.
    /// It does so per virtual party in the virtual subset of `participating_tangible_party_id`.
    /// It does so by first summing the shares from each dealer,
    /// and then decrypting the encryption of the secret per CRT prime, and performing CRT reconstruction.
    /// This is done for each virtual party in the virtual subset of `participating_tangible_party_id` separately.
    #[allow(clippy::type_complexity)]
    pub fn sum_encryptions_of_additively_shared_secrets(
        virtual_subset: HashSet<PartyID>,
        participating_parties_access_structure: &WeightedThresholdAccessStructure,
        encryptions_of_secrets_and_proofs: HashMap<
            PartyID,
            HashMap<
                Option<PartyID>,
                HashMap<
                    PartyID,
                    HashMap<
                        PartyID,
                        DealtSecretShare<
                            NUM_PRIMES,
                            DISCRETE_LOG_WITNESS_LIMBS,
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
            [CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; NUM_PRIMES],
        >,
    > {
        let encryptions_of_secrets_per_crt_prime = virtual_subset
            .into_iter()
            .map(|participating_virtual_party_id| {
                let participating_tangible_party_id = participating_parties_access_structure
                    .to_tangible_party_id(participating_virtual_party_id)
                    .ok_or(Error::InternalError)?;

                encryptions_of_secrets_and_proofs
                    .values()
                    .map(|encryptions_of_shares_and_proofs| {
                        // Safe to unwrap by construction.
                        encryptions_of_shares_and_proofs.get(&None).unwrap()
                    })
                    .map(|encryptions_of_shares_and_proofs| {
                        encryptions_of_shares_and_proofs
                            .get(&participating_tangible_party_id)
                            .and_then(|encryptions_of_secrets_per_crt_prime| {
                                encryptions_of_secrets_per_crt_prime
                                    .get(&participating_virtual_party_id)
                                    .map(|dealt_secret_share| {
                                        dealt_secret_share
                                            .each_ref()
                                            .map(|(_, encryption)| *encryption)
                                    })
                                    .map(self_product::GroupElement::from)
                            })
                            .ok_or(Error::InvalidParameters)
                    })
                    .reduce(|a, b| a.and_then(|a| b.map(|b| a.add_vartime(&b))))
                    .ok_or(Error::InternalError)?
                    .map(<[_; NUM_PRIMES]>::from)
                    .map(|encryption| (participating_virtual_party_id, encryption))
            })
            .try_collect_hash_map()?;

        Ok(encryptions_of_secrets_per_crt_prime)
    }

    /// This function decrypts an encryption of secret per-CRT prime for every virtual party,
    /// and performs CRT reconstruction to get a mapping between a virtual party and its secret.
    /// This function implements the command $\textsf{PVSS}.\textsf{DecShare}$ from (link to 2pc-mpc eprint).
    ///
    /// Note: `encryptions_of_secrets_per_crt_prime` must be pre-filtered to hold secrets dealt to our party, so they would be decryptable using `decryption_key_per_crt_prime`.
    pub fn decrypt_secrets(
        setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        crt_coefficients: [CRTCoefficientSizedNumber; NUM_PRIMES],
        crt_primes_product: CRTReconstructionSizedNumber,
        encryptions_of_secrets_per_crt_prime: HashMap<
            PartyID,
            [CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; NUM_PRIMES],
        >,
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    ) -> Result<HashMap<PartyID, Int<SECRET_SHARE_LIMBS>>>
    where
        Int<SECRET_SHARE_LIMBS>: Encoding,
    {
        #[cfg(not(feature = "parallel"))]
        let iter = encryptions_of_secrets_per_crt_prime.into_iter();
        #[cfg(feature = "parallel")]
        let iter = encryptions_of_secrets_per_crt_prime.into_par_iter();

        let shares = iter
            .map(
                |(participating_virtual_party_id, encryption_of_share_per_crt_prime)| {
                    // This cannot fail since we validated zk-proofs
                    let share = Self::decrypt_and_crt_reconstruct(
                        crt_coefficients,
                        crt_primes_product,
                        &setup_parameters_per_crt_prime,
                        decryption_key_per_crt_prime,
                        encryption_of_share_per_crt_prime.each_ref(),
                    )?;

                    Ok((participating_virtual_party_id, share))
                },
            )
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .collect();

        Ok(shares)
    }

    /// Decrypt the encryptions of the share modulo each CRT prime, and perform CRT reconstruction to get the share.
    /// The amount of shares needed for decryption needs to be atmost crt_primes_product.
    pub fn decrypt_and_crt_reconstruct(
        crt_coefficients: [CRTCoefficientSizedNumber; NUM_PRIMES],
        crt_primes_product: CRTReconstructionSizedNumber,
        setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
        encryption_of_share_per_crt_prime: [&CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_PRIMES],
    ) -> Result<Int<SECRET_SHARE_LIMBS>> {
        let encryption_scheme_public_parameters_per_crt_prime = array::from_fn(|i| {
            encryption_key::PublicParameters::new_from_secret_key(
                setup_parameters_per_crt_prime[i].clone(),
                decryption_key_per_crt_prime[i],
            )
        })
        .flat_map_results()?;

        let decryption_key_per_crt_prime = array::from_fn(|i| {
            SecretKeyShareCRTPrimeDecryptionKey::new(
                decryption_key_per_crt_prime[i],
                &encryption_scheme_public_parameters_per_crt_prime[i],
            )
        })
        .flat_map_results()?;

        Self::decrypt_and_crt_reconstruct_internal(
            crt_coefficients,
            crt_primes_product,
            encryption_scheme_public_parameters_per_crt_prime,
            decryption_key_per_crt_prime,
            encryption_of_share_per_crt_prime,
        )
    }

    /// Decrypt the encryptions of the share modulo each CRT prime, and perform CRT reconstruction to get the share.
    /// The amount of shares needed for decryption needs to be atmost crt_primes_product.
    pub fn decrypt_and_crt_reconstruct_internal(
        crt_coefficients: [CRTCoefficientSizedNumber; NUM_PRIMES],
        crt_primes_product: CRTReconstructionSizedNumber,
        encryption_scheme_public_parameters_per_crt_prime: [SecretKeyShareCRTPrimeEncryptionSchemePublicParameters;
            NUM_PRIMES],
        decryption_key_per_crt_prime: [SecretKeyShareCRTPrimeDecryptionKey; NUM_PRIMES],
        encryption_of_share_per_crt_prime: [&CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
            NUM_PRIMES],
    ) -> Result<Int<SECRET_SHARE_LIMBS>> {
        let share_modulo_crt_primes = array::from_fn(|i| {
            let encryption_scheme_public_parameters =
                &encryption_scheme_public_parameters_per_crt_prime[i];
            let decryption_key = decryption_key_per_crt_prime[i];

            // Safe to convert `into_option()`.
            // In Class-Groups the decryption operation that can fail independently of the secret key value.
            // In this case only the message can be revealed.
            // If the operation fails there is no message to speak of.
            // If it succeeds the operation is constant time and thus do not reveal information on it.
            decryption_key
                .decrypt(
                    encryption_of_share_per_crt_prime[i],
                    encryption_scheme_public_parameters,
                )
                .into_option()
                .map(|share_modulo_crt_prime| share_modulo_crt_prime.value())
                .ok_or(Error::Decryption)
        })
        .flat_map_results()?;

        chinese_remainder_theorem::reconstruct_integer(
            crt_coefficients,
            crt_primes_product,
            share_modulo_crt_primes,
        )
    }
}
