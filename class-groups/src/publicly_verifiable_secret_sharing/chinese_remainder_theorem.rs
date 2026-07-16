// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::array;
use std::collections::HashMap;
use std::marker::PhantomData;

use crypto_bigint::subtle::{ConditionallySelectable, ConstantTimeLess};
use crypto_bigint::{CheckedSub, ConstChoice, Int, Limb, NonZero, Uint};
#[cfg(all(feature = "parallel", not(feature = "unsafe_mock")))]
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use std::collections::HashSet;
use std::fmt::Debug;

use crypto_bigint::Encoding;
use serde::{Deserialize, Serialize};

use commitment::CommitmentSizedNumber;
use group::{bounded_integers_group, helpers::const_generic_array_serialization};
use maurer::encryption_of_discrete_log;
use maurer::SOUND_PROOFS_REPETITIONS;
use mpc::secret_sharing::shamir::over_the_integers::{
    compute_adjusted_lagrange_coefficient, AdjustedLagrangeCoefficientSizedNumber,
    BinomialCoefficientSizedNumber,
};
use mpc::WeightedThresholdAccessStructure;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::equivalence_class::EquivalenceClassOps;
use crate::{CiphertextSpaceGroupElement, CiphertextSpaceValue};

pub use consts::*;
use group::bounded_natural_numbers_group::MAURER_PROOFS_DIFF_UPPER_BOUND_BITS;
use group::helpers::{DeduplicateAndSort, FlatMapResults};
use group::SeedableCollection;
use group::{bounded_natural_numbers_group, CsRng, GroupElement, PartyID};
use maurer::{fischlin, knowledge_of_discrete_log, UC_PROOFS_REPETITIONS};
use mpc::secret_sharing::shamir::over_the_integers::find_closest_crypto_bigint_size;
use mpc::HandleInvalidMessages;
use proof::GroupsPublicParametersAccessors;

use crate::decryption_key_share::PartialDecryptionProof;
use crate::setup::DeriveFromPlaintextPublicParameters;
use crate::setup::SetupParameters;
use crate::{
    decryption_key_share, encryption_key, equivalence_class, CompactIbqf, DecryptionKey,
    DecryptionKeyShare, EncryptionKey, EquivalenceClass, Error, ErrorKind, Result,
};

use super::BaseProtocolContext;

pub use party::Party;

mod consts;
mod deal_shares;
mod party;
mod test_consts;
mod verify_shares;

pub const NUM_SECRET_SHARE_PRIMES: usize = MAX_PRIMES;
pub const SECRET_SHARE_CRT_PRIMES_PRODUCT: CRTReconstructionSizedNumber = CRT_PRIMES_PRODUCT;
pub const SECRET_SHARE_CRT_COEFFICIENTS: [CRTCoefficientSizedNumber; NUM_SECRET_SHARE_PRIMES] =
    CRT_COEFFICIENTS;

pub const CRT_COEFFICIENT_BITS: u32 = CRTPrimeSizedNumber::BITS * MAX_PRIMES as u32;
pub const CRT_COEFFICIENT_LIMBS: usize =
    find_closest_crypto_bigint_size(CRT_COEFFICIENT_BITS as usize) / Limb::BITS as usize;
pub const CRT_RECONSTRUCTION_BITS: u32 =
    (CRTPrimeSizedNumber::BITS + CRT_COEFFICIENT_BITS) + MAX_PRIMES.ilog2() + 1;
pub const CRT_RECONSTRUCTION_LIMBS: usize =
    find_closest_crypto_bigint_size(CRT_RECONSTRUCTION_BITS as usize) / Limb::BITS as usize;

pub const CRT_DECRYPTION_KEY_WITNESS_LIMBS: usize = find_closest_crypto_bigint_size(
    ({ Uint::<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>::BITS } + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS)
        as usize,
) / Limb::BITS as usize;

pub type SecretKeyShareCRTPrimeGroupElement = group::additive::PrimeGroupElement<CRT_PRIME_LIMBS>;

pub type SecretKeyShareCRTPrimePublicParameters =
    group::additive::PrimePublicParameters<CRT_PRIME_LIMBS>;

pub type SecretKeyShareCRTPrimeSetupParameters = SetupParameters<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimePublicParameters,
>;

pub type SecretKeyShareCRTPrimeEncryptionSchemePublicParameters = encryption_key::PublicParameters<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimePublicParameters,
>;

pub type SecretKeyShareCRTPrimeEncryptionKey = EncryptionKey<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimeGroupElement,
>;

pub type SecretKeyShareCRTPrimeDecryptionKey = DecryptionKey<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimeGroupElement,
>;

pub type SecretKeyShareCRTPrimeDecryptionKeyShare = DecryptionKeyShare<
    CRT_PRIME_LIMBS,
    CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SecretKeyShareCRTPrimeGroupElement,
>;

pub type SecretKeyShareCRTPrimeDecryptionKeySharePublicParameters =
    decryption_key_share::PublicParameters<
        CRT_PRIME_LIMBS,
        CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SecretKeyShareCRTPrimePublicParameters,
    >;

pub type SecretKeyShareCRTPrimePartialDecryptionProof =
    PartialDecryptionProof<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;

pub type SecretKeyShareCRTPrimeDecryptionShare =
    CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;

/// The knowledge of discrete log UC-secure Fischlin proof used to prove valid encryption keys.
pub type KnowledgeOfDiscreteLogUCProof = maurer::fischlin::Proof<
    UC_PROOFS_REPETITIONS,
    knowledge_of_discrete_log::FischlinLanguage<
        UC_PROOFS_REPETITIONS,
        bounded_natural_numbers_group::GroupElement<CRT_DECRYPTION_KEY_WITNESS_LIMBS>,
        EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    PhantomData<()>,
>;

/// The public parameters of the knowledge of discrete log UC-secure Fischlin proof used to prove valid encryption keys.
pub type KnowledgeOfDiscreteLogUCPublicParameters = knowledge_of_discrete_log::PublicParameters<
    bounded_natural_numbers_group::PublicParameters<CRT_DECRYPTION_KEY_WITNESS_LIMBS>,
    equivalence_class::PublicParameters<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
>;

pub type CRTPrimeSizedNumber = Uint<CRT_PRIME_LIMBS>;
pub type CRTCoefficientSizedNumber = Uint<CRT_COEFFICIENT_LIMBS>;
pub type CRTReconstructionSizedNumber = Uint<CRT_RECONSTRUCTION_LIMBS>;

/// Perform Chinese Remainder Theorem (CRT) reconstruction.
pub fn reconstruct<const NUM_PRIMES: usize>(
    crt_coefficients: [CRTCoefficientSizedNumber; NUM_PRIMES],
    crt_primes_product: CRTReconstructionSizedNumber,
    secret_modulo_crt_primes: [CRTPrimeSizedNumber; NUM_PRIMES],
) -> CRTReconstructionSizedNumber {
    debug_assert!(NUM_PRIMES != 0 && NUM_PRIMES <= MAX_PRIMES);

    // Safe to dereference & unwrap, as the arrays are the same, non-empty size (`NUM_PRIMES`).
    let share: CRTReconstructionSizedNumber = secret_modulo_crt_primes
        .into_iter()
        .enumerate()
        .map(|(i, share_modulo_crt_prime)| {
            CRTReconstructionSizedNumber::from(&share_modulo_crt_prime)
                .wrapping_mul(&crt_coefficients[i])
        })
        .reduce(|a, b| a.wrapping_add(&b))
        .unwrap();

    share % NonZero::new(crt_primes_product).unwrap()
}

pub fn reconstruct_integer<const NUM_PRIMES: usize, const SECRET_LIMBS: usize>(
    crt_coefficients: [CRTCoefficientSizedNumber; NUM_PRIMES],
    crt_primes_product: CRTReconstructionSizedNumber,
    secret_modulo_crt_primes: [CRTPrimeSizedNumber; NUM_PRIMES],
) -> Result<Int<SECRET_LIMBS>> {
    let secret_positive = reconstruct(
        crt_coefficients,
        crt_primes_product,
        secret_modulo_crt_primes,
    );

    let secret = Int::new_from_abs_sign(secret_positive, ConstChoice::FALSE).unwrap();
    let crt_primes_product =
        Int::new_from_abs_sign(crt_primes_product, ConstChoice::FALSE).unwrap();

    // Should never overflow by choice of parameters
    let secret_negative = secret
        .checked_sub(&crt_primes_product)
        .into_option()
        .ok_or_else(|| Error::from(ErrorKind::InternalError))?;

    let secret = <Int<CRT_RECONSTRUCTION_LIMBS> as ConditionallySelectable>::conditional_select(
        &secret,
        &secret_negative,
        secret_negative.abs().ct_lt(&secret_positive),
    );

    // Safe to resize now, since we picked the smaller one, which is guaranteed to be of the requested size.
    Ok(Int::<SECRET_LIMBS>::from(&secret))
}

pub fn construct_setup_parameters_per_crt_prime(
    computational_security_parameter: u32,
) -> Result<[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES]> {
    CRT_PRIMES
        .map(|prime| {
            let plaintext_space_parameters = SecretKeyShareCRTPrimePublicParameters::new(prime)?;

            SecretKeyShareCRTPrimeSetupParameters::derive_from_plaintext_parameters::<
                SecretKeyShareCRTPrimeGroupElement,
            >(plaintext_space_parameters, computational_security_parameter)
        })
        .flat_map_results()
}

pub fn generate_keypairs_per_crt_prime(
    setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    rng: &mut impl CsRng,
) -> Result<[Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]> {
    setup_parameters_per_crt_prime
        .map(|setup_parameters| {
            SecretKeyShareCRTPrimeDecryptionKey::generate_with_setup_parameters(
                setup_parameters,
                rng,
            )
            .map(|(_, decryption_key)| decryption_key.decryption_key)
        })
        .flat_map_results()
}

pub fn construct_knowledge_of_decryption_key_public_parameters(
    base: CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    discrete_log_sample_bits: u32,
    equivalence_class_public_parameters: group::PublicParameters<
        EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
) -> crate::Result<KnowledgeOfDiscreteLogUCPublicParameters> {
    if fischlin::target_bits::<UC_PROOFS_REPETITIONS>() > 10 {
        // For security we need to have small challenges. Refer to paper: https://eprint.iacr.org/2024/717.pdf
        return Err(Error::from(ErrorKind::InternalError));
    }

    let witness_group_public_parameters = bounded_natural_numbers_group::PublicParameters::<
        CRT_DECRYPTION_KEY_WITNESS_LIMBS,
    >::new_with_randomizer_upper_bound(
        discrete_log_sample_bits
    )?;

    let discrete_log_sample_bits = Some(witness_group_public_parameters.sample_bits);
    let language_public_parameters = knowledge_of_discrete_log::PublicParameters::new::<
        bounded_natural_numbers_group::GroupElement<CRT_DECRYPTION_KEY_WITNESS_LIMBS>,
        EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >(
        witness_group_public_parameters,
        equivalence_class_public_parameters,
        base,
        discrete_log_sample_bits,
    );

    Ok(language_public_parameters)
}

pub fn construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
    setup_parameters_per_crt_prime: [&SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
) -> crate::Result<[KnowledgeOfDiscreteLogUCPublicParameters; MAX_PRIMES]> {
    setup_parameters_per_crt_prime
        .map(|setup_parameters| {
            construct_knowledge_of_decryption_key_public_parameters(
                setup_parameters.h.value(),
                setup_parameters.decryption_key_bits(),
                setup_parameters
                    .equivalence_class_public_parameters()
                    .clone(),
            )
        })
        .flat_map_results()
}

/// Implements Protocol F.1 Step 4.
pub fn generate_knowledge_of_decryption_key_proofs_per_crt_prime(
    language_public_parameters_per_crt_prime: [KnowledgeOfDiscreteLogUCPublicParameters;
        MAX_PRIMES],
    decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    rng: &mut impl CsRng,
) -> Result<
    [(
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        KnowledgeOfDiscreteLogUCProof,
    ); MAX_PRIMES],
> {
    let seeded_indices = (0..MAX_PRIMES).seed(rng);
    #[cfg(not(feature = "parallel"))]
    let iter = seeded_indices.into_iter();
    #[cfg(feature = "parallel")]
    let iter = seeded_indices.into_par_iter();

    let encryption_keys_and_proofs = iter
        .map(|(i, mut unique_rng)| {
            let language_public_parameters = &language_public_parameters_per_crt_prime[i];
            let decryption_key = bounded_natural_numbers_group::GroupElement::new(
                Uint::from(&decryption_key_per_crt_prime[i]),
                language_public_parameters.witness_space_public_parameters(),
            )?;

            let (proof, encryption_key) = KnowledgeOfDiscreteLogUCProof::prove(
                // Don't need a protocol context for this specific proof.
                &PhantomData,
                language_public_parameters,
                decryption_key,
                &mut unique_rng,
            )?;

            Ok::<_, Error>((encryption_key.value(), proof))
        })
        .collect::<Result<Vec<_>>>()?;

    encryption_keys_and_proofs
        .try_into()
        .map_err(|_| Error::from(ErrorKind::InternalError))
}

/// Deterministically generate a class-groups CRT keypair from
/// `rng`: the per-CRT-prime decryption key and the matching per-prime encryption
/// keys with UC knowledge-of-decryption-key proofs. Bundles the full CRT keygen
/// orchestration (setup- and language-parameter derivation, keypair generation,
/// proof generation) behind one entry point so callers never touch the low-level
/// primitives.
#[cfg(not(feature = "unsafe_mock"))]
pub fn generate_class_groups_keypair(
    rng: &mut impl CsRng,
) -> Result<(
    [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    [(
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        KnowledgeOfDiscreteLogUCProof,
    ); MAX_PRIMES],
)> {
    let setup_parameters_per_crt_prime =
        construct_setup_parameters_per_crt_prime(crate::DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)?;
    let language_public_parameters_per_crt_prime =
        construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
            setup_parameters_per_crt_prime.each_ref(),
        )?;
    let decryption_key_per_crt_prime =
        generate_keypairs_per_crt_prime(setup_parameters_per_crt_prime, rng)?;
    let encryption_keys_and_proofs = generate_knowledge_of_decryption_key_proofs_per_crt_prime(
        language_public_parameters_per_crt_prime,
        decryption_key_per_crt_prime,
        rng,
    )?;

    Ok((decryption_key_per_crt_prime, encryption_keys_and_proofs))
}

/// INSECURE mock twin (feature `unsafe_mock`): returns a fixed decryption key and
/// neutral encryption keys with `new_default` proofs, seed-independent. The
/// encryption keys + proofs are decoded from an embedded fixture (see
/// [`crate::publicly_verifiable_secret_sharing::unsafe_mock_keygen_fixtures`]) so
/// there is no runtime setup-parameter derivation. The matching verification twins
/// accept the default proofs. The production definition above is left untouched.
#[cfg(feature = "unsafe_mock")]
pub fn generate_class_groups_keypair(
    _rng: &mut impl CsRng,
) -> Result<(
    [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
    [(
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        KnowledgeOfDiscreteLogUCProof,
    ); MAX_PRIMES],
)> {
    let encryption_keys_and_proofs =
        crate::publicly_verifiable_secret_sharing::unsafe_mock_keygen_fixtures::crt_encryption_keys_and_proofs()?;

    Ok((
        [Uint::from(crate::UNSAFE_MOCK_DECRYPTION_KEY); MAX_PRIMES],
        encryption_keys_and_proofs,
    ))
}

pub(super) fn instantiate_encryption_keys_per_crt_prime(
    setup_parameters_per_crt_prime: &[SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    encryption_key_values_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
) -> Result<(
    Vec<PartyID>,
    HashMap<
        PartyID,
        [(
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
)> {
    Ok(encryption_key_values_and_proofs_per_crt_prime
        .into_iter()
        .map(|(party_id, encryption_key_values_and_proofs)| {
            let encryption_keys_and_proofs = array::from_fn(|i| {
                // Safe to derefernce as these are same-sized arrays.
                let (encryption_key_value, proof) = encryption_key_values_and_proofs[i].clone();

                <EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> as group::GroupElement>::new(
                    encryption_key_value,
                    setup_parameters_per_crt_prime[i].equivalence_class_public_parameters(),
                )
                    .map(|encryption_key| (encryption_key, proof))
            })
                .flat_map_results();

            (party_id, encryption_keys_and_proofs)
        })
        .handle_invalid_messages_async())
}

/// INSECURE mock twin (feature `unsafe_mock`): skips CRT
/// knowledge-of-decryption-key proof verification. The mock produces default
/// proofs (see inkrypto `unsafe_mock`) that real verification would
/// flag as malicious, so no party is flagged for an invalid proof (only parties
/// that already lacked a valid encryption key remain malicious). The production
/// definition below is left untouched.
#[cfg(feature = "unsafe_mock")]
pub fn verify_knowledge_of_decryption_key_proofs(
    _language_public_parameters_per_crt_prime: [KnowledgeOfDiscreteLogUCPublicParameters;
        MAX_PRIMES],
    parties_without_valid_encryption_keys: Vec<PartyID>,
    encryption_keys_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
) -> Result<(
    Vec<PartyID>,
    HashMap<PartyID, [EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
)> {
    let malicious_parties: Vec<PartyID> =
        parties_without_valid_encryption_keys.deduplicate_and_sort();

    let crt_primes_encryption_keys = encryption_keys_and_proofs_per_crt_prime
        .into_iter()
        .filter(|(party_id, _)| !malicious_parties.contains(party_id))
        .map(|(party_id, encryption_keys_and_proofs)| {
            (
                party_id,
                encryption_keys_and_proofs.map(|(encryption_key, _)| encryption_key),
            )
        })
        .collect();

    Ok((malicious_parties, crt_primes_encryption_keys))
}

#[cfg(not(feature = "unsafe_mock"))]
pub fn verify_knowledge_of_decryption_key_proofs(
    language_public_parameters_per_crt_prime: [KnowledgeOfDiscreteLogUCPublicParameters;
        MAX_PRIMES],
    parties_without_valid_encryption_keys: Vec<PartyID>,
    encryption_keys_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
) -> Result<(
    Vec<PartyID>,
    HashMap<PartyID, [EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
)> {
    #[cfg(not(feature = "parallel"))]
    let iter = encryption_keys_and_proofs_per_crt_prime.iter();
    #[cfg(feature = "parallel")]
    let iter = encryption_keys_and_proofs_per_crt_prime.par_iter();

    let parties_sending_invalid_proofs: Vec<PartyID> = iter
        .filter(|(_, encryption_keys_and_proofs)| {
            encryption_keys_and_proofs
                .iter()
                .zip(language_public_parameters_per_crt_prime.iter())
                .any(|((encryption_key, proof), language_public_parameters)| {
                    proof
                        .verify(&PhantomData, language_public_parameters, *encryption_key)
                        .is_err()
                })
        })
        .map(|(party_id, _)| *party_id)
        .collect();

    // Add both the parties that sent invalid statements and malicious proof to the malicious parties list, and filter out their messages.
    let malicious_parties: Vec<PartyID> = parties_without_valid_encryption_keys
        .into_iter()
        .chain(parties_sending_invalid_proofs)
        .deduplicate_and_sort();

    let encryption_keys_and_proofs_per_crt_prime: HashMap<_, _> =
        encryption_keys_and_proofs_per_crt_prime
            .into_iter()
            .filter(|(party_id, _)| !malicious_parties.contains(party_id))
            .collect();

    let crt_primes_encryption_keys = encryption_keys_and_proofs_per_crt_prime
        .into_iter()
        .map(|(party_id, encryption_keys_and_proofs)| {
            (
                party_id,
                encryption_keys_and_proofs.map(|(encryption_key, _)| encryption_key),
            )
        })
        .collect();

    Ok((malicious_parties, crt_primes_encryption_keys))
}

/// The encryption of discrete log proof used for DKG.
pub type EncryptionOfDiscreteLogProof<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    encryption_of_discrete_log::Language<
        CRT_PRIME_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        DISCRETE_LOG_WITNESS_LIMBS,
        bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        EncryptionKey<
            CRT_PRIME_LIMBS,
            CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SecretKeyShareCRTPrimeGroupElement,
        >,
    >,
    ProtocolContext,
>;

pub type EncryptionOfDiscreteLogPublicParameters<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = encryption_of_discrete_log::PublicParameters<
    CRT_PRIME_LIMBS,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    DISCRETE_LOG_WITNESS_LIMBS,
    bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    EncryptionKey<
        CRT_PRIME_LIMBS,
        CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SecretKeyShareCRTPrimeGroupElement,
    >,
>;

/// The serializable message sent by a dealer to share a secret to a single participating parties:
/// * The encryption of the share dealt for this party, modulo each CRT prime.
/// * A proof that the encryption matches the commitment to the share.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DealtSecretShareMessage<
    const NUM_PRIMES: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
>(
    #[serde(with = "const_generic_array_serialization")]
    pub(crate)  [(
        EncryptionOfDiscreteLogProof<
            DISCRETE_LOG_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceValue<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ); NUM_PRIMES],
)
where
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
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
        >;

/// The instantiated message sent by a dealer to share a secret to a single participating party:
/// * The encryption of the share dealt for this party, modulo each CRT prime.
/// * A proof that the encryption matches the commitment to the share.
pub type DealtSecretShare<
    const NUM_PRIMES: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = [(
    EncryptionOfDiscreteLogProof<
        DISCRETE_LOG_WITNESS_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    CiphertextSpaceGroupElement<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
); NUM_PRIMES];

/// The serializable message sent by a dealer to share a secret to all participating parties:
/// * A vector of commitments to the coefficients of the polynomial used to share the decryption key contribution.
/// * Per-receiving party (tangible -> virtual):
///     * The encryption of the share dealt for each party, modulo each CRT prime.
///     * A proof that the encryption matches the commitment to the share.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DealSecretMessage<
    const NUM_PRIMES: usize,
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> where
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
    pub coefficients_contribution_commitments: Vec<CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    pub encryptions_of_secret_shares_and_proofs: HashMap<
        PartyID,
        HashMap<
            PartyID,
            DealtSecretShareMessage<
                NUM_PRIMES,
                DISCRETE_LOG_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    >,
}

/// The protocol context used to prove encryption of shares.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolContext {
    pub(crate) dealer_tangible_party_id: PartyID,
    pub(crate) dealer_virtual_party_id: Option<PartyID>,
    pub(crate) participating_tangible_party_id: Option<PartyID>,
    pub(crate) participating_virtual_party_id: Option<PartyID>,
    pub(crate) session_id: CommitmentSizedNumber,
    pub(crate) crt_prime_index: u8,
    pub(crate) secret_bits: u32,
    pub(crate) base_protocol_context: BaseProtocolContext,
}

pub(crate) fn compute_adjusted_lagrange_coefficients(
    access_structure: &WeightedThresholdAccessStructure,
    honest_dealers: HashSet<PartyID>,
    binomial_coefficients: &HashMap<PartyID, BinomialCoefficientSizedNumber>,
) -> Result<(
    HashSet<PartyID>,
    HashMap<PartyID, AdjustedLagrangeCoefficientSizedNumber>,
)> {
    // Take exactly $t$ virtual parties
    let mut honest_virtual_dealers: Vec<_> = access_structure
        .virtual_subset(honest_dealers)?
        .into_iter()
        .collect();
    honest_virtual_dealers.sort();

    let interpolation_subset: HashSet<_> = honest_virtual_dealers
        .into_iter()
        .take(access_structure.threshold.into())
        .collect();

    if interpolation_subset.len() != usize::from(access_structure.threshold) {
        return Err(Error::from(ErrorKind::InternalError));
    }

    let adjusted_lagrange_coefficients: HashMap<_, _> = interpolation_subset
        .clone()
        .into_iter()
        .map(|j| {
            binomial_coefficients
                .get(&j)
                .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))
                .map(|binomial_coefficient| {
                    let coefficient = compute_adjusted_lagrange_coefficient(
                        j,
                        access_structure.number_of_virtual_parties(),
                        interpolation_subset.clone(),
                        binomial_coefficient.resize(),
                    );

                    (j, coefficient)
                })
        })
        .collect::<Result<_>>()?;

    Ok((interpolation_subset, adjusted_lagrange_coefficients))
}

#[cfg(test)]
mod tests {
    use crypto_bigint::RandomMod;

    use group::{OsCsRng, Reduce};
    use mpc::secret_sharing::shamir::over_the_integers::{
        secret_key_share_size_upper_bound, MAX_PLAYERS,
    };

    use crate::{SecretKeyShareSizedNumber, DECRYPTION_KEY_BITS_112BIT_SECURITY, MAX_THRESHOLD};

    use super::*;
    use std::array;
    use std::collections::HashMap;
    use std::ops::Neg;

    use crypto_bigint::Random;

    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, GroupElement};
    use homomorphic_encryption::GroupsPublicParametersAccessors;

    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        construct_setup_parameters_per_crt_prime, SECRET_SHARE_CRT_COEFFICIENTS,
        SECRET_SHARE_CRT_PRIMES_PRODUCT,
    };
    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::setup::SetupParameters;
    use crate::test_helpers::deal_trusted_shares;
    use crate::{
        Secp256k1DecryptionKey, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_SCALAR_LIMBS, SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
    };

    #[test]
    fn decrypts_and_crt_reconstructs() {
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        let threshold = 4;
        let party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);

        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        let plaintext_space_public_parameters = secp256k1::scalar::PublicParameters::default();

        let setup_parameters = SetupParameters::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<secp256k1::Scalar>,
        >::derive_from_plaintext_parameters::<secp256k1::Scalar>(
            plaintext_space_public_parameters.clone(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
        .unwrap();

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let (decryption_keys_per_crt_prime, encryption_keys_per_crt_prime_and_proofs) =
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(&access_structure);

        let decryption_key_per_crt_prime = *decryption_keys_per_crt_prime.get(&1).unwrap();

        let secret_key_share_upper_bound_bits = secret_key_share_size_upper_bound(
            u32::from(access_structure.number_of_virtual_parties()),
            u32::from(access_structure.threshold),
            setup_parameters.decryption_key_bits(),
        );

        let discrete_log_group_public_parameters = bounded_integers_group::PublicParameters::<
            SECRET_KEY_SHARE_WITNESS_LIMBS,
        >::new_with_randomizer_upper_bound(
            secret_key_share_upper_bound_bits
        )
        .unwrap();

        let (encryption_scheme_public_parameters, decryption_key) =
            Secp256k1DecryptionKey::generate_with_setup_parameters(
                setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();

        let (_, decryption_key_shares) = deal_trusted_shares::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >(
            access_structure.threshold,
            access_structure.number_of_virtual_parties(),
            encryption_scheme_public_parameters.clone(),
            decryption_key.decryption_key,
            setup_parameters.h,
            setup_parameters.decryption_key_bits(),
        );

        let decryption_key_share = *decryption_key_shares.get(&1).unwrap();

        let decryption_key_share_group_element =
            bounded_integers_group::GroupElement::<SECRET_KEY_SHARE_WITNESS_LIMBS>::new(
                Int::from(&decryption_key_share),
                &discrete_log_group_public_parameters,
            )
            .unwrap();

        let base_protocol_context = BaseProtocolContext {
            protocol_name: "Test".to_string(),
            round: 0,
            proof_name: "Test".to_string(),
        };

        // In the DKG, dealers deal shares to themselves, i.e. the participating parties are the same as the dealers.
        let pvss_party = Party::<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >::new(
            session_id,
            1,
            Some(1),
            access_structure.clone(),
            access_structure.clone(),
            setup_parameters.clone(),
            setup_parameters_per_crt_prime.clone(),
            encryption_keys_per_crt_prime_and_proofs,
            base_protocol_context,
            setup_parameters.h.value(),
            setup_parameters.decryption_key_bits(),
            secret_key_share_upper_bound_bits,
            true,
            false,
        )
        .unwrap();

        let encryption_of_share_per_crt_prime = pvss_party
            .prove_encryption_of_discrete_log_per_crt_prime(
                Some(1),
                2,
                3,
                decryption_key_share_group_element,
                &mut OsCsRng,
            )
            .unwrap()
            .map(|(_, encryption)| encryption);

        let encryption_of_share_per_crt_prime = array::from_fn(|i| {
            CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                encryption_of_share_per_crt_prime[i],
                setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters(),
            )
            .unwrap()
        });

        let decrypted_share = Party::<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >::decrypt_and_crt_reconstruct(
            SECRET_SHARE_CRT_COEFFICIENTS,
            SECRET_SHARE_CRT_PRIMES_PRODUCT,
            &setup_parameters_per_crt_prime,
            decryption_key_per_crt_prime,
            encryption_of_share_per_crt_prime.each_ref(),
        )
        .unwrap();

        assert_eq!(
            decrypted_share, decryption_key_share,
            "CRT reconstruction of an encrypted natural number should succeed"
        );

        let encryption_of_share_per_crt_prime = pvss_party
            .prove_encryption_of_discrete_log_per_crt_prime(
                Some(1),
                2,
                3,
                decryption_key_share_group_element.neg(),
                &mut OsCsRng,
            )
            .unwrap()
            .map(|(_, encryption)| encryption);

        let encryption_of_share_per_crt_prime = array::from_fn(|i| {
            CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                encryption_of_share_per_crt_prime[i],
                setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters(),
            )
            .unwrap()
        });

        let decrypted_share = Party::<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >::decrypt_and_crt_reconstruct(
            SECRET_SHARE_CRT_COEFFICIENTS,
            SECRET_SHARE_CRT_PRIMES_PRODUCT,
            &setup_parameters_per_crt_prime,
            decryption_key_per_crt_prime,
            encryption_of_share_per_crt_prime.each_ref(),
        )
        .unwrap();

        assert_eq!(
            decrypted_share,
            decryption_key_share.checked_neg().unwrap(),
            "CRT reconstruction of an encrypted integer should succeed"
        );
    }

    #[test]
    fn crt_reconstructs() {
        let crt_primes_product = CRT_PRIMES
            .iter()
            .map(CRTReconstructionSizedNumber::from)
            .reduce(|a, b| a.checked_mul(&b).unwrap())
            .unwrap();

        assert_eq!(
            crt_primes_product,
            CRTReconstructionSizedNumber::from(&CRT_PRIMES_PRODUCT),
            "CRT Primes product computed incorrectly"
        );

        let crt_primes_product = CRT_PRIMES
            .iter()
            .take(NUM_SECRET_SHARE_PRIMES)
            .map(CRTReconstructionSizedNumber::from)
            .reduce(|a, b| a.checked_mul(&b).unwrap())
            .unwrap();

        assert_eq!(
            crt_primes_product,
            CRTReconstructionSizedNumber::from(&SECRET_SHARE_CRT_PRIMES_PRODUCT),
            "CRT Primes product computed incorrectly"
        );

        let secret = SecretKeyShareSizedNumber::random_mod(
            &mut OsCsRng,
            &NonZero::new(SecretKeyShareSizedNumber::ONE.shl_vartime(
                secret_key_share_size_upper_bound(
                    MAX_PLAYERS,
                    MAX_THRESHOLD,
                    DECRYPTION_KEY_BITS_112BIT_SECURITY,
                ),
            ))
            .unwrap(),
        );

        let secret_modulo_crt_primes =
            array::from_fn(|i| secret.reduce(&NonZero::new(CRT_PRIMES[i]).unwrap()));

        let reconstructed_secret = SecretKeyShareSizedNumber::from(&reconstruct(
            SECRET_SHARE_CRT_COEFFICIENTS,
            SECRET_SHARE_CRT_PRIMES_PRODUCT,
            secret_modulo_crt_primes,
        ));

        assert_eq!(
            secret, reconstructed_secret,
            "CRT reconstruction should yield the original secret"
        );
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::hint::black_box;
    use std::time::Duration;

    use criterion::{BatchSize, Criterion};
    use crypto_bigint::Random;

    use group::{OsCsRng, Samplable};
    use homomorphic_encryption::GroupsPublicParametersAccessors;

    use crate::equivalence_class::EquivalenceClassOps;
    use crate::{RandomnessSpaceGroupElement, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER};

    use super::*;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let mut group = _c.benchmark_group("crt");
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));
        group.sample_size(10);

        let group = &mut group;

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();
        let setup_parameters = setup_parameters_per_crt_prime[0].clone();
        let (pp, decryption_key) =
            SecretKeyShareCRTPrimeDecryptionKey::generate_with_setup_parameters(
                setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();
        let encryption_key = decryption_key.encryption_key;

        group.bench_function("equivalence class mul (ct)", |b| {
            b.iter_batched(
                || {
                    let randomness = RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value();

                    let a = setup_parameters.h.pow_vartime(&randomness);
                    let b = setup_parameters.h.pow_vartime(&randomness);

                    (a, b)
                },
                |(a, b)| {
                    let res = a.mul(&b).unwrap();
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class mul (rt)", |b| {
            b.iter_batched(
                || {
                    let randomness = RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value();

                    let a = setup_parameters.h.pow_vartime(&randomness);
                    let b = setup_parameters.h.pow_vartime(&randomness);

                    (a, b)
                },
                |(a, b)| {
                    let res = a.mul_randomized(&b).unwrap();
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class mul (vt)", |b| {
            b.iter_batched(
                || {
                    let randomness = RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value();

                    let a = setup_parameters.h.pow_vartime(&randomness);
                    let b = setup_parameters.h.pow_vartime(&randomness);

                    (a, b)
                },
                |(a, b)| {
                    let res = a.mul_vartime(&b).unwrap();
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class pow (ct)", |b| {
            b.iter_batched(
                || {
                    RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value()
                },
                |randomness| {
                    let res = setup_parameters.h.pow_bounded(
                        &randomness,
                        pp.randomness_space_public_parameters().sample_bits,
                    );
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class pow (rt)", |b| {
            b.iter_batched(
                || {
                    RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value()
                },
                |randomness| {
                    let res = setup_parameters.h.pow_bounded_randomized(
                        &randomness,
                        pp.randomness_space_public_parameters().sample_bits,
                    );
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        group.bench_function("equivalence class pow (vt)", |b| {
            b.iter_batched(
                || {
                    RandomnessSpaceGroupElement::sample(
                        pp.randomness_space_public_parameters(),
                        &mut OsCsRng,
                    )
                    .unwrap()
                    .value()
                },
                |randomness| {
                    let res = setup_parameters.h.pow_vartime(&randomness);
                    black_box(res)
                },
                BatchSize::SmallInput,
            )
        });

        let m = NonZero::random(&mut OsCsRng);
        group.bench_function("power_of_f", |b| {
            b.iter(|| {
                black_box(SecretKeyShareCRTPrimeEncryptionKey::power_of_f(
                    &m,
                    &pp.setup_parameters.class_group_parameters,
                ))
            })
        });

        SecretKeyShareCRTPrimeEncryptionKey::benchmark_pow_h(group, &pp);
        SecretKeyShareCRTPrimeEncryptionKey::benchmark_pow_pk(group, &pp);

        SecretKeyShareCRTPrimeEncryptionKey::benchmark_encrypt(group, &encryption_key, &pp);
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use std::collections::HashMap;

    use crypto_bigint::Uint;

    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        KnowledgeOfDiscreteLogUCProof, MAX_PRIMES,
    };
    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::test_consts::test_helpers::{
        DECRYPTION_KEY_PER_CRT_PRIME, ENCRYPTION_KEY_AND_PROOF_PER_CRT_PRIME,
    };
    use crate::CompactIbqf;

    use super::*;

    #[allow(clippy::type_complexity)]
    pub fn construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(
        access_structure: &WeightedThresholdAccessStructure,
    ) -> (
        HashMap<PartyID, [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
        HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
    ) {
        let decryption_key_per_crt_prime: [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES] =
            serde_json::from_str(DECRYPTION_KEY_PER_CRT_PRIME).unwrap();

        let encryption_key_and_proof_per_crt_prime: [(
            CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES] = serde_json::from_str(ENCRYPTION_KEY_AND_PROOF_PER_CRT_PRIME).unwrap();

        access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|&party_id| {
                (
                    (party_id, decryption_key_per_crt_prime),
                    (party_id, encryption_key_and_proof_per_crt_prime.clone()),
                )
            })
            .unzip()
    }
}
