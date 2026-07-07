// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! Round 1: Deal and encrypt shares (PVSS.Dist)
//!
//! This module implements the dealing phase of single-prime PVSS where the dealer:
//! 1. Samples polynomial $f(x) = s + a_1 x + \cdots + a_{t-1} x^{t-1}$
//! 2. Computes shares $s_i = f(i)$ for each party
//! 3. Computes commitments $C_j = \bar{g}^{a_j}$ to coefficients
//! 4. Encrypts each share: $E(\textsf{pk}_i, s_i)$
//! 5. Generates EncDL proof for each encrypted share

use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Uint};

use commitment;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use group::{CsRng, GroupElement as _, PartyID, PrimeGroupElement, Samplable, SeedableCollection};
use homomorphic_encryption::{
    AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicEncryptionKey,
    GroupsPublicParametersAccessors,
};
use mpc::secret_sharing::shamir::Polynomial;
use mpc::{HandleInvalidMessages, WeightedThresholdAccessStructure};

use super::{
    construct_encryption_of_discrete_log_public_parameters, DealSecretMessage,
    DealtSecretShareMessage, EncryptionOfDiscreteLogProof, ProtocolContext,
};
use crate::accelerator::MultiFoldNupowAccelerator;
use crate::encryption_key::public_parameters::Instantiate;
use crate::equivalence_class::{EquivalenceClass, EquivalenceClassOps};
use crate::publicly_verifiable_secret_sharing::small_prime::encryption::{
    verify_knowledge_of_decryption_key_uc_proof, KnowledgeOfDecryptionKeyUCProof,
};
use crate::{encryption_key, encryption_key::EncryptionKey, DecryptionKey, SetupParameters};
use crate::{
    equivalence_class, CiphertextSpaceGroupElement, CiphertextSpaceValue, CompactIbqf, Error,
    ErrorKind, Result,
};

/// Return type for [`deal_secret_shares`]: malicious parties, verified encryption keys, and the
/// dealing message.
pub struct DealSecretSharesOutput<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
> where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + crate::encryption_key::public_parameters::Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    pub malicious_parties: Vec<PartyID>,
    pub verified_encryption_keys:
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    pub dealing_message: DealSecretMessage<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
}

/// Round 1: Deal and encrypt shares to valid encryption key holders (PVSS.Dist).
///
/// The dealer:
/// 1. Samples polynomial $f(X) = s + a_1 X + \cdots + a_{t-1} X^{t-1}$
/// 2. Computes shares $s_i = f(i)$ for each party
/// 3. Computes commitments $C_j = \bar{g}^{a_j}$ to coefficients
/// 4. Encrypts each share: $E(\textsf{pk}_i, s_i)$
/// 5. Generates EncDL proof for each encrypted share
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `dealer_party_id` - The dealer's party ID
/// * `threshold` - Threshold for secret sharing
/// * `secret` - The secret to share
/// * `setup_parameters` - Cryptographic setup parameters
/// * `encryption_keys` - Map of party IDs to their encryption keys
/// * `base_protocol_context` - Protocol context for proofs
/// * `scalar_public_parameters` - Scalar public parameters for polynomial sampling
/// * `group_public_parameters` - Group public parameters for commitment base
/// * `rng` - Random number generator
///
/// # Returns
/// Tuple of (malicious_parties, verified_encryption_keys, dealing_message)
#[allow(clippy::too_many_arguments)]
pub fn deal_secret_shares<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DECRYPTION_KEY_WITNESS_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    dealer_party_id: PartyID,
    secret: GroupElement::Scalar,
    setup_parameters: &SetupParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    encryption_keys_and_proofs: &HashMap<
        PartyID,
        (
            CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDecryptionKeyUCProof<
                DECRYPTION_KEY_WITNESS_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        ),
    >,
    participating_and_dealers_match: bool,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    base_protocol_context: &crate::publicly_verifiable_secret_sharing::BaseProtocolContext,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<
    DealSecretSharesOutput<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<DECRYPTION_KEY_WITNESS_LIMBS>: Encoding,
    Uint<DECRYPTION_KEY_WITNESS_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let (malicious_participating_parties, verified_encryption_keys): (_, HashMap<_, _>) =
        encryption_keys_and_proofs
            .iter()
            .map(
                |(&party_id, (encryption_key, knowledge_of_decryption_key_uc_proof))| {
                    let encryption_key = EquivalenceClass::new(
                        *encryption_key,
                        setup_parameters.equivalence_class_public_parameters(),
                    )
                    .map_err(Error::from)
                    .and_then(|encryption_key| {
                        verify_knowledge_of_decryption_key_uc_proof::<
                            SCALAR_LIMBS,
                            FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                            DECRYPTION_KEY_WITNESS_LIMBS,
                            GroupElement,
                        >(
                            encryption_key,
                            knowledge_of_decryption_key_uc_proof,
                            setup_parameters,
                        )
                    });

                    (party_id, encryption_key)
                },
            )
            .handle_invalid_messages_async();

    // Check that the honest parties form an authorized subset, and combine their public contributions.
    // Note that `verify_knowledge_of_decryption_key_proofs()` already filters-out the malicious parties from `encryption_keys_per_crt_prime`.
    // If this fails, we have an irrecoverable error: we can't do PVSS.
    let participating_parties_with_valid_encryption_keys: HashSet<PartyID> =
        verified_encryption_keys.keys().copied().collect();
    participating_parties_access_structure
        .is_authorized_subset(&participating_parties_with_valid_encryption_keys)
        .map_err(Error::from)?;

    let deal_secret_message = deal_secret_shares_with_preverified_encryption_keys(
        session_id,
        dealer_party_id,
        secret,
        setup_parameters,
        verified_encryption_keys.clone(),
        participating_parties_access_structure,
        base_protocol_context,
        scalar_public_parameters,
        group_public_parameters,
        rng,
    )?;

    let malicious_parties: Vec<PartyID> = if participating_and_dealers_match {
        malicious_participating_parties
    } else {
        vec![]
    };

    Ok(DealSecretSharesOutput {
        malicious_parties,
        verified_encryption_keys,
        dealing_message: deal_secret_message,
    })
}

/// Round 1: Deal and encrypt shares to valid encryption key holders (PVSS.Dist).
/// This optimized variant accepts a pre-verified map of encryption keys.
///
/// The dealer:
/// 1. Samples polynomial $f(X) = s + a_1 X + \cdots + a_{t-1} X^{t-1}$
/// 2. Computes shares $s_i = f(i)$ for each party
/// 3. Computes commitments $C_j = \bar{g}^{a_j}$ to coefficients
/// 4. Encrypts each share: $E(\textsf{pk}_i, s_i)$
/// 5. Generates EncDL proof for each encrypted share
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `dealer_party_id` - The dealer's party ID
/// * `threshold` - Threshold for secret sharing
/// * `secret` - The secret to share
/// * `setup_parameters` - Cryptographic setup parameters
/// * `encryption_keys` - Map of party IDs to their encryption keys
/// * `base_protocol_context` - Protocol context for proofs
/// * `scalar_public_parameters` - Scalar public parameters for polynomial sampling
/// * `group_public_parameters` - Group public parameters for commitment base
/// * `rng` - Random number generator
///
/// # Returns
/// The dealing message
#[allow(clippy::too_many_arguments)]
pub fn deal_secret_shares_with_preverified_encryption_keys<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    dealer_party_id: PartyID,
    secret: GroupElement::Scalar,
    setup_parameters: &SetupParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    verified_encryption_keys: HashMap<
        PartyID,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    participating_parties_access_structure: &WeightedThresholdAccessStructure,
    base_protocol_context: &crate::publicly_verifiable_secret_sharing::BaseProtocolContext,
    scalar_public_parameters: &<GroupElement::Scalar as group::GroupElement>::PublicParameters,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<
    DealSecretMessage<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let threshold = participating_parties_access_structure.threshold;

    if threshold == 0 {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    // Validate no party id is 0 (polynomial evaluation at 0 reveals the secret)
    if verified_encryption_keys
        .keys()
        .any(|&party_id| party_id == 0)
    {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    if verified_encryption_keys.keys().any(|party_id| {
        !participating_parties_access_structure
            .party_to_virtual_parties()
            .contains_key(party_id)
    }) {
        return Err(Error::from(ErrorKind::InvalidParameters));
    }

    let degree = threshold - 1;

    let polynomial =
        Polynomial::sample_with_constant_term(degree, secret, scalar_public_parameters, rng)?;

    // Compute curve group commitments: C_j = g^{a_j}
    let generator = GroupElement::generator_from_public_parameters(group_public_parameters)?;
    let coefficients_contribution_commitments: Vec<group::Value<GroupElement>> = polynomial
        .coefficients()
        .iter()
        .map(|coeff| generator.scale_by(coeff, group_public_parameters).value())
        .collect();

    // Each participating party's secret-share encryption + EncDL proof is
    // independent of the others, so they can be produced in parallel. Because a
    // `CsRng` cannot cross threads, derive a per-share `ChaCha20Rng` from `rng`
    // up front (`seed`), then prove each share with its own rng — under the
    // `parallel` feature this fans out across rayon's pool, otherwise it runs
    // serially. (This is the same seed→parallelize idiom used in `proof`.)
    let seeded_shares = verified_encryption_keys.iter().seed(rng);

    #[cfg(not(feature = "parallel"))]
    let seeded_shares = seeded_shares.into_iter();
    #[cfg(feature = "parallel")]
    let seeded_shares = seeded_shares.into_par_iter();

    let encryptions_of_secret_shares_and_proofs = seeded_shares
        .map(
            |((&participating_party_id, encryption_key), mut share_rng)| -> Result<_> {
                let constant_time = true;
                let share_scalar = polynomial.evaluate_degree(
                    participating_party_id,
                    constant_time,
                    scalar_public_parameters,
                );

                let (proof, ciphertext) = prove_encryption_of_discrete_log(
                    session_id,
                    dealer_party_id,
                    participating_party_id,
                    share_scalar,
                    setup_parameters,
                    encryption_key,
                    base_protocol_context,
                    scalar_public_parameters,
                    group_public_parameters,
                    &mut share_rng,
                )?;

                Ok((
                    participating_party_id,
                    DealtSecretShareMessage {
                        encryption_of_secret_share_proof: proof,
                        encryption_of_secret_share: ciphertext,
                    },
                ))
            },
        )
        .collect::<Result<HashMap<_, _>>>()?;

    Ok(DealSecretMessage {
        coefficients_contribution_commitments,
        encryptions_of_secret_shares_and_proofs,
    })
}

/// Decrypts an encrypted share using a party's decryption key.
///
/// # Arguments
/// * `encryption_scheme_public_parameters` - Pre-instantiated encryption scheme parameters
/// * `decryption_key` - The party's decryption key
/// * `ciphertext` - The encrypted share
///
/// # Returns
/// The decrypted share as a scalar
pub fn decrypt_share<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    encryption_scheme_public_parameters: &encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    decryption_key: Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ciphertext: &CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
) -> Result<GroupElement::Scalar>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    DecryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicDecryptionKey<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
        SecretKey = Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let decryption_key_group = DecryptionKey::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >::new(decryption_key, encryption_scheme_public_parameters)
    .map_err(|_| Error::from(ErrorKind::InvalidParameters))?;

    let plaintext = decryption_key_group
        .decrypt(ciphertext, encryption_scheme_public_parameters)
        .into_option()
        .ok_or_else(|| Error::from(ErrorKind::InvalidParameters))?;

    Ok(plaintext)
}

// ================================================================================================
// Helper functions
// ================================================================================================

/// Proves encryption of a discrete log and returns proof + ciphertext.
#[allow(clippy::too_many_arguments)]
fn prove_encryption_of_discrete_log<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + Copy,
>(
    session_id: commitment::CommitmentSizedNumber,
    dealer_party_id: PartyID,
    participant_party_id: PartyID,
    share_scalar: GroupElement::Scalar,
    setup_parameters: &SetupParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >,
    encryption_key: &EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    base_protocol_context: &crate::publicly_verifiable_secret_sharing::BaseProtocolContext,
    scalar_public_parameters: &group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: &GroupElement::PublicParameters,
    rng: &mut impl CsRng,
) -> Result<(
    EncryptionOfDiscreteLogProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
)>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
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
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = crate::RandomnessSpaceGroupElement<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<GroupElement::Scalar>,
                crate::RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                crate::CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            >,
        > + Instantiate<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
{
    let encryption_scheme_public_parameters =
        encryption_key::PublicParameters::new(setup_parameters.clone(), *encryption_key)?;

    let language_public_parameters = construct_encryption_of_discrete_log_public_parameters(
        scalar_public_parameters.clone(),
        group_public_parameters.clone(),
        encryption_scheme_public_parameters.clone(),
    );

    let encryption_randomness =
        crate::RandomnessSpaceGroupElement::<FUNDAMENTAL_DISCRIMINANT_LIMBS>::sample(
            encryption_scheme_public_parameters.randomness_space_public_parameters(),
            rng,
        )?;

    let protocol_context = ProtocolContext {
        dealer_party_id,
        participating_party_id: participant_party_id,
        session_id,
        base_protocol_context: base_protocol_context.clone(),
    };

    let (proof, statement) = EncryptionOfDiscreteLogProof::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >::prove(
        &protocol_context,
        &language_public_parameters,
        vec![(share_scalar, encryption_randomness).into()],
        rng,
    )?;

    let (encryption_of_discrete_log, _) = (*statement
        .first()
        .ok_or_else(|| Error::from(ErrorKind::InternalError))?)
    .into();

    Ok((proof, encryption_of_discrete_log.value()))
}
