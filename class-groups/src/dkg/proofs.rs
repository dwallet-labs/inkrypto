// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(unused_variables)]

use crate::dkg::ProveEqualityOfDiscreteLog;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    SecretKeyShareCRTPrimeEncryptionSchemePublicParameters, SecretKeyShareCRTPrimeGroupElement,
    SecretKeyShareCRTPrimeSetupParameters, CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, CRT_PRIME_LIMBS, MAX_PRIMES,
    NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{
    BaseProtocolContext, DealtSecretShare, EncryptionOfDiscreteLogProof,
    EncryptionOfDiscreteLogPublicParameters, ProtocolContext,
};
use crate::setup::SetupParameters;
use crate::{
    encryption_key, equivalence_class, CiphertextSpaceValue, CompactIbqf, EncryptionKey,
    EquivalenceClass, Error, RandomnessSpaceGroupElement, Result,
};
use commitment::CommitmentSizedNumber;
use crypto_bigint::rand_core::CryptoRngCore;
#[cfg(feature = "parallel")]
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{Encoding, Int, Uint};
use group::helpers::FlatMapResults;
use group::{
    bounded_integers_group, direct_product, GroupElement, PartyID, PrimeGroupElement, Samplable,
};
use homomorphic_encryption::GroupsPublicParametersAccessors;
use maurer::knowledge_of_discrete_log;
use maurer::SOUND_PROOFS_REPETITIONS;
use mpc::WeightedThresholdAccessStructure;
use proof::Proof;
use std::array;
use std::collections::{HashMap, HashSet};

/// A proof of equality of descrete logs $(g_1,g_1^x), $g_2,g_2^x)$ under different hidden order groups $g_1\in G_1, g_2 \in G_2$.
/// In a hidden order we group, we can use a knowledge of discrete log proof to prove the equality of discrete logs of two bases:
/// Let $G_{1}$ and $G_{2}$ be groups of unknown order containing elements $g_{1},g_{2}$ respectively.
/// The prover shows it knows a number $s \in \mathbb{Z}$ such that $v_{1}=g_{1}^s,v_{2}=g_{2}^s$.
/// This is used to prove (per-crt-prime) the contribution to the threshold encryption key against the contribution for the encryption key.
pub type EqualityOfDiscreteLogsInHiddenOrderGroupProof<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    knowledge_of_discrete_log::Language<
        bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
        direct_product::GroupElement<
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    ProtocolContext,
>;

/// In a hidden order we group, we can use a knowledge of discrete log proof to prove the equality of discrete logs of two bases:
/// Let $G_{1}$ and $G_{2}$ be groups of unknown order containing elements $g_{1},g_{2}$ respectively.
/// The prover shows it knows a number $s \in \mathbb{Z}$ such that $v_{1}=g_{1}^s,v_{2}=g_{2}^s$.
pub type KnowledgeOfDiscreteLogPublicParameters<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = knowledge_of_discrete_log::PublicParameters<
    bounded_integers_group::PublicParameters<DISCRETE_LOG_WITNESS_LIMBS>,
    direct_product::PublicParameters<
        equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        equivalence_class::PublicParameters<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    direct_product::Value<
        CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
>;

/// This function constructs the public parameters for the equality of discrete log language.
/// This includes description of the group for each CRT prime.
/// Note: `crt_prime_index` must be `< MAX_PRIMES`
fn construct_equality_of_discrete_log_public_parameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    setup_parameters: &SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    discrete_log_group_public_parameters: bounded_integers_group::PublicParameters<
        DISCRETE_LOG_WITNESS_LIMBS,
    >,
    crt_prime_index: usize,
) -> KnowledgeOfDiscreteLogPublicParameters<
    DISCRETE_LOG_WITNESS_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    GroupElement::Scalar: Default,
{
    let base = (
        setup_parameters.h.value(),
        setup_parameters_per_crt_prime[crt_prime_index].h.value(),
    )
        .into();
    let group_public_parameters = (
        setup_parameters
            .equivalence_class_public_parameters()
            .clone(),
        setup_parameters_per_crt_prime[crt_prime_index]
            .equivalence_class_public_parameters()
            .clone(),
    )
        .into();

    KnowledgeOfDiscreteLogPublicParameters::new::<
        bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
        direct_product::GroupElement<
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >(
        discrete_log_group_public_parameters,
        group_public_parameters,
        base,
    )
}

/// Prove equality between the discrete log under different bases
/// via M' equalities of discrete log proofs $\pi_{\textsf{EncDL},Q'_{m'}}^{i}$ between $(h_{q},h_{Q'_{m'},\textsf{pk}_{q},\textsf{pk}_{Q'_{m'};s)$.
pub(crate) fn prove_equality_of_discrete_log<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    dealer_tangible_party_id: PartyID,
    dealer_virtual_party_id: Option<PartyID>,
    session_id: CommitmentSizedNumber,
    knowledge_of_discrete_log_base_protocol_context: BaseProtocolContext,
    discrete_log_group_public_parameters: bounded_integers_group::PublicParameters<
        DISCRETE_LOG_WITNESS_LIMBS,
    >,
    discrete_log: bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
    setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    setup_parameters: &SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    secret_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> crate::Result<
    [(
        EqualityOfDiscreteLogsInHiddenOrderGroupProof<
            DISCRETE_LOG_WITNESS_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ); NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    GroupElement::Scalar: Default,
{
    array::from_fn(|i| {
        let language_public_parameters = construct_equality_of_discrete_log_public_parameters::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            DISCRETE_LOG_WITNESS_LIMBS,
            GroupElement,
        >(
            setup_parameters_per_crt_prime,
            setup_parameters,
            discrete_log_group_public_parameters.clone(),
            i,
        );

        let protocol_context = ProtocolContext {
            dealer_tangible_party_id,
            dealer_virtual_party_id,
            participating_tangible_party_id: None,
            participating_virtual_party_id: None,
            session_id,
            crt_prime_index: i as u8,
            secret_bits,
            base_protocol_context: knowledge_of_discrete_log_base_protocol_context.clone(),
        };

        let (proof, statement) = EqualityOfDiscreteLogsInHiddenOrderGroupProof::prove(
            &protocol_context,
            &language_public_parameters,
            vec![discrete_log],
            rng,
        )?;

        let (_, threshold_encryption_key_per_crt_prime) =
            statement.first().ok_or(Error::InternalError)?.into();

        Ok::<_, Error>((proof, threshold_encryption_key_per_crt_prime.value()))
    })
    .flat_map_results()
}

/// Verify equality between the discrete log under different bases
/// via M' equalities of discrete log proofs $\pi_{\textsf{EncDL},Q'_{m'}}^{i}$ between $(h_{q},h_{Q'_{m'},\textsf{pk}_{q},\textsf{pk}_{Q'_{m'};s)$.
pub(crate) fn verify_equality_of_discrete_log_proofs<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    session_id: CommitmentSizedNumber,
    access_structure: &WeightedThresholdAccessStructure,
    knowledge_of_discrete_log_base_protocol_context: BaseProtocolContext,
    discrete_log_group_public_parameters: bounded_integers_group::PublicParameters<
        DISCRETE_LOG_WITNESS_LIMBS,
    >,
    setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    setup_parameters: &SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    commitments: HashMap<
        PartyID,
        HashMap<Option<PartyID>, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    >,
    encryption_key_shares_and_proofs: &HashMap<
        PartyID,
        HashMap<
            Option<PartyID>,
            ProveEqualityOfDiscreteLog<
                DISCRETE_LOG_WITNESS_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    >,
    secret_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> Result<HashSet<PartyID>>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    GroupElement::Scalar: Default,
{
    let parties_with_no_commitments: HashSet<_> = encryption_key_shares_and_proofs
        .iter()
        .filter(
            |(dealer_tangible_party_id, encryption_key_shares_and_proofs)| {
                // Verify that there exists commitment(s) for the dealer and potentially all of its virtual subset, if being used.
                if let Some(commitments) = commitments.get(dealer_tangible_party_id) {
                    encryption_key_shares_and_proofs
                        .keys()
                        .copied()
                        .collect::<HashSet<_>>()
                        != commitments.keys().copied().collect::<HashSet<_>>()
                } else {
                    true
                }
            },
        )
        .map(|(dealer_tangible_party_id, _)| dealer_tangible_party_id)
        .copied()
        .collect();

    let parties_sending_invalid_proofs: HashSet<_> = (0..NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES)
        .flat_map(|i| {
            let proofs_and_protocol_contexts_and_statements = encryption_key_shares_and_proofs
                .iter()
                .filter(|(dealer_tangible_party_id, _)| {
                    !parties_with_no_commitments.contains(dealer_tangible_party_id)
                })
                .map(
                    |(&dealer_tangible_party_id, encryption_key_shares_and_proofs)| {
                        let proofs_and_protocol_contexts_and_statements =
                            encryption_key_shares_and_proofs
                                .iter()
                                .map(
                                    |(&dealer_virtual_party_id, prove_equality_of_discrete_log)| {
                                        let protocol_context = ProtocolContext {
                                            dealer_tangible_party_id,
                                            dealer_virtual_party_id,
                                            participating_tangible_party_id: None,
                                            participating_virtual_party_id: None,
                                            session_id,
                                            crt_prime_index: i as u8,
                                            secret_bits,
                                            base_protocol_context:
                                                knowledge_of_discrete_log_base_protocol_context
                                                    .clone(),
                                        };

                                        // Safe to `unwrap` because we blamed and filtered any party that hasn't such commitment.
                                        // let prove_equality_of_discrete_log = commitments
                                        let commitment = *commitments
                                            .get(&dealer_tangible_party_id)
                                            .unwrap()
                                            .get(&dealer_virtual_party_id)
                                            .unwrap();

                                        let (proof, current_base_by_discrete_log) =
                                            prove_equality_of_discrete_log[i].clone();

                                        (
                                            proof,
                                            (
                                                protocol_context.clone(),
                                                vec![(commitment, current_base_by_discrete_log)
                                                    .into()],
                                            ),
                                        )
                                    },
                                )
                                .collect();

                        (
                            dealer_tangible_party_id,
                            proofs_and_protocol_contexts_and_statements,
                        )
                    },
                )
                .collect();

            let language_public_parameters = construct_equality_of_discrete_log_public_parameters::<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                DISCRETE_LOG_WITNESS_LIMBS,
                GroupElement,
            >(
                setup_parameters_per_crt_prime,
                setup_parameters,
                discrete_log_group_public_parameters.clone(),
                i,
            );

            let (parties_sending_invalid_proofs, _) = Proof::verify_batch_asynchronously(
                proofs_and_protocol_contexts_and_statements,
                &language_public_parameters,
                #[cfg(not(feature = "parallel"))]
                rng,
                #[cfg(feature = "parallel")]
                &mut OsRng,
            );

            parties_sending_invalid_proofs
        })
        .collect();

    let malicious_parties: HashSet<_> = parties_with_no_commitments
        .into_iter()
        .chain(parties_sending_invalid_proofs)
        .collect();

    let honest_parties = encryption_key_shares_and_proofs
        .keys()
        .copied()
        .filter(|party_id| !malicious_parties.contains(party_id))
        .collect();

    access_structure.is_authorized_subset(&honest_parties)?;

    Ok(malicious_parties)
}

/// Construct $L_{\textsf{EncDL}}$ language parameters.
pub fn construct_encryption_of_discrete_log_public_parameters<
    const NUM_PRIMES: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
>(
    discrete_log_witness_group_public_parameters: bounded_integers_group::PublicParameters<
        DISCRETE_LOG_WITNESS_LIMBS,
    >,
    equivalence_class_public_parameters: group::PublicParameters<
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    public_verification_key_base: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        CRT_PRIME_LIMBS,
        EncryptionKey<
            CRT_PRIME_LIMBS,
            CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SecretKeyShareCRTPrimeGroupElement,
        >,
    >,
) -> EncryptionOfDiscreteLogPublicParameters<
    DISCRETE_LOG_WITNESS_LIMBS,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
>
where
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let upper_bound_bits = discrete_log_witness_group_public_parameters.upper_bound_bits;

    EncryptionOfDiscreteLogPublicParameters::<
        DISCRETE_LOG_WITNESS_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >::new::<
        CRT_PRIME_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey<
            CRT_PRIME_LIMBS,
            CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SecretKeyShareCRTPrimeGroupElement,
        >,
    >(
        discrete_log_witness_group_public_parameters,
        equivalence_class_public_parameters,
        encryption_scheme_public_parameters,
        public_verification_key_base.value(),
        Some(upper_bound_bits),
    )
}

pub fn prove_encryption_of_discrete_log_per_crt_prime<
    const NUM_PRIMES: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
>(
    dealer_tangible_party_id: PartyID,
    dealer_virtual_party_id: Option<PartyID>,
    participating_tangible_party_id: Option<PartyID>,
    participating_virtual_party_id: Option<PartyID>,
    session_id: CommitmentSizedNumber,
    discrete_log: bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
    equivalence_class_public_parameters: group::PublicParameters<
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    public_verification_key_base: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    encryption_key_per_crt_prime: &[EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
         NUM_PRIMES],
    setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    base_protocol_context: BaseProtocolContext,
    discrete_log_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> Result<
    [(
        EncryptionOfDiscreteLogProof<
            DISCRETE_LOG_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ); NUM_PRIMES],
>
where
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let discrete_log_witness_group_public_parameters = bounded_integers_group::PublicParameters::<
        DISCRETE_LOG_WITNESS_LIMBS,
    >::new_with_randomizer_upper_bound(
        discrete_log_bits
    )?;

    array::from_fn(|i| {
        // Safe to dereference - same sized arrays of size >= NUM_PRIMES.
        let encryption_scheme_public_parameters = encryption_key::PublicParameters::new(
            setup_parameters_per_crt_prime[i].clone(),
            encryption_key_per_crt_prime[i],
        )?;

        let language_public_parameters = construct_encryption_of_discrete_log_public_parameters::<
            NUM_PRIMES,
            DISCRETE_LOG_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >(
            discrete_log_witness_group_public_parameters.clone(),
            equivalence_class_public_parameters.clone(),
            public_verification_key_base,
            encryption_scheme_public_parameters.clone(),
        );

        let crt_prime_index = (i + 1) as u8;
        let protocol_context = ProtocolContext {
            dealer_tangible_party_id,
            dealer_virtual_party_id,
            participating_tangible_party_id,
            participating_virtual_party_id,
            session_id,
            crt_prime_index,
            secret_bits: discrete_log_bits,
            base_protocol_context: base_protocol_context.clone(),
        };

        // Sample $\eta_{i}\gets \mathcal{D}_{q}$
        let encryption_randomness = RandomnessSpaceGroupElement::sample(
            encryption_scheme_public_parameters.randomness_space_public_parameters(),
            #[cfg(not(feature = "parallel"))]
            rng,
            #[cfg(feature = "parallel")]
            &mut OsRng,
        )?;

        let (proof, statement) = EncryptionOfDiscreteLogProof::<
            DISCRETE_LOG_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >::prove(
            &protocol_context,
            &language_public_parameters,
            vec![(discrete_log, encryption_randomness).into()],
            #[cfg(not(feature = "parallel"))]
            rng,
            #[cfg(feature = "parallel")]
            &mut OsRng,
        )?;

        let (encryption_of_discrete_log, _) =
            (*statement.first().ok_or(crate::Error::InternalError)?).into();

        Ok((proof, encryption_of_discrete_log.value()))
    })
    .flat_map_results()
}

pub fn verify_encryptions_of_secrets_per_crt_prime<
    const NUM_PRIMES: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
>(
    participating_tangible_party_id: Option<PartyID>,
    session_id: CommitmentSizedNumber,
    encryption_scheme_public_parameters_per_crt_prime: [SecretKeyShareCRTPrimeEncryptionSchemePublicParameters;
        NUM_PRIMES],
    commitments: HashMap<
        PartyID,
        HashMap<
            Option<PartyID>,
            HashMap<Option<PartyID>, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        >,
    >,
    encryptions_of_shares_and_proofs: HashMap<
        PartyID,
        HashMap<
            Option<PartyID>,
            HashMap<
                Option<PartyID>,
                DealtSecretShare<
                    NUM_PRIMES,
                    DISCRETE_LOG_WITNESS_LIMBS,
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                >,
            >,
        >,
    >,
    equivalence_class_public_parameters: group::PublicParameters<
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    public_verification_key_base: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    base_protocol_context: BaseProtocolContext,
    discrete_log_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> Result<HashSet<PartyID>>
where
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,

    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let discrete_log_witness_group_public_parameters = bounded_integers_group::PublicParameters::<
        DISCRETE_LOG_WITNESS_LIMBS,
    >::new_with_randomizer_upper_bound(
        discrete_log_bits
    )?;

    let proofs_and_protocol_contexts_and_statements: Vec<(PartyID, [_; NUM_PRIMES])> =
        encryptions_of_shares_and_proofs
            .into_iter()
            .map(
                |(dealer_tangible_party_id, encryptions_of_shares_and_proofs)| {
                    let proofs_and_protocol_contexts_and_statements: Vec<[_; NUM_PRIMES]> =
                        encryptions_of_shares_and_proofs
                            .into_iter()
                            .map(
                                |(
                                     dealer_virtual_party_id,
                                     encryptions_of_shares_and_proofs,
                                 )| {
                                    let proofs_and_protocol_contexts_and_statements: Vec<
                                        [_; NUM_PRIMES],
                                    > = encryptions_of_shares_and_proofs
                                        .into_iter()
                                        .map(
                                            |(
                                                 participating_virtual_party_id,
                                                 dealt_secret_share,
                                             )| {
                                                let commitment_to_share = commitments
                                                    .get(&dealer_tangible_party_id)
                                                    .ok_or(Error::InvalidParameters)?
                                                    .get(&dealer_virtual_party_id)
                                                    .ok_or(Error::InvalidParameters)?
                                                    .get(&participating_virtual_party_id)
                                                    .ok_or(Error::InvalidParameters)?;

                                                // Safe to dereference - same sized arrays.
                                                array::from_fn(|i| {
                                                    let crt_prime_index = (i + 1) as u8;
                                                    let protocol_context = ProtocolContext {
                                                        dealer_tangible_party_id,
                                                        dealer_virtual_party_id,
                                                        participating_tangible_party_id,
                                                        participating_virtual_party_id,
                                                        session_id,
                                                        crt_prime_index,
                                                        secret_bits: discrete_log_bits,
                                                        base_protocol_context: base_protocol_context
                                                            .clone(),
                                                    };

                                                    let (
                                                        proof,
                                                        encryption_of_share_modulo_crt_prime,
                                                    ) = dealt_secret_share[i].clone();

                                                    Ok((
                                                        proof,
                                                        (
                                                            protocol_context,
                                                            vec![(
                                                                encryption_of_share_modulo_crt_prime,
                                                                *commitment_to_share,
                                                            )
                                                                .into()],
                                                        ),
                                                    ))
                                                })
                                                    .flat_map_results()
                                            },
                                        )
                                        .collect::<Result<_>>()?;

                                    Ok(proofs_and_protocol_contexts_and_statements)
                                },
                            )
                            .collect::<Result<Vec<_>>>()?
                            .into_iter()
                            .flatten()
                            .collect();

                    let proofs_and_protocol_contexts_and_statements: [Vec<_>; NUM_PRIMES] =
                        array::from_fn(|i| {
                            proofs_and_protocol_contexts_and_statements
                                .iter()
                                .map(|x| x[i].clone())
                                .collect()
                        });

                    Ok((
                        dealer_tangible_party_id,
                        proofs_and_protocol_contexts_and_statements,
                    ))
                },
            )
            .collect::<Result<_>>()?;

    let proofs_and_protocol_contexts_and_statements: [HashMap<PartyID, Vec<_>>; NUM_PRIMES] =
        array::from_fn(|i| {
            proofs_and_protocol_contexts_and_statements
                .iter()
                .map(
                    |(dealer_party_id, proofs_and_protocol_contexts_and_statements)| {
                        (
                            *dealer_party_id,
                            proofs_and_protocol_contexts_and_statements[i].clone(),
                        )
                    },
                )
                .collect()
        });

    let parties_sending_invalid_proofs =
        (0..NUM_PRIMES)
            .flat_map(|i| {
                let language_public_parameters =
                    construct_encryption_of_discrete_log_public_parameters::<
                        NUM_PRIMES,
                        DISCRETE_LOG_WITNESS_LIMBS,
                        PLAINTEXT_SPACE_SCALAR_LIMBS,
                        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                    >(
                        discrete_log_witness_group_public_parameters.clone(),
                        equivalence_class_public_parameters.clone(),
                        public_verification_key_base,
                        encryption_scheme_public_parameters_per_crt_prime[i].clone(),
                    );

                let proofs_and_protocol_contexts_and_statements =
                    proofs_and_protocol_contexts_and_statements[i].clone();

                let (parties_sending_invalid_proofs, _) = Proof::verify_batch_asynchronously(
                    proofs_and_protocol_contexts_and_statements,
                    &language_public_parameters,
                    rng,
                );

                parties_sending_invalid_proofs
            })
            .collect();

    Ok(parties_sending_invalid_proofs)
}
