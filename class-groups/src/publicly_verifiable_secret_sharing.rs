// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use crypto_bigint::{Encoding, Int, Uint};
use serde::{Deserialize, Serialize};

use chinese_remainder_theorem::*;
use commitment::CommitmentSizedNumber;
use group::{bounded_integers_group, helpers::const_generic_array_serialization};
use maurer::encryption_of_discrete_log;
use maurer::SOUND_PROOFS_REPETITIONS;
use mpc::secret_sharing::shamir::over_the_integers::{
    compute_adjusted_lagrange_coefficient, AdjustedLagrangeCoefficientSizedNumber,
    BinomialCoefficientSizedNumber,
};
use mpc::PartyID;
use mpc::WeightedThresholdAccessStructure;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::equivalence_class::EquivalenceClassOps;
use crate::{
    equivalence_class, CiphertextSpaceGroupElement, CiphertextSpaceValue, CompactIbqf,
    EncryptionKey, EquivalenceClass, Error, Result,
};

pub use party::Party;

pub mod chinese_remainder_theorem;
mod deal_shares;
mod party;
mod test_consts;
mod verify_shares;

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

/// The base, protocol-dependent context used to prove encryption of shares.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BaseProtocolContext {
    pub protocol_name: String,
    pub round: u8,
    pub proof_name: String,
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
        return Err(Error::InternalError);
    }

    let adjusted_lagrange_coefficients: HashMap<_, _> = interpolation_subset
        .clone()
        .into_iter()
        .map(|j| {
            binomial_coefficients
                .get(&j)
                .ok_or(Error::InvalidParameters)
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
    use std::array;
    use std::collections::HashMap;
    use std::ops::Neg;

    use crypto_bigint::Random;

    use commitment::CommitmentSizedNumber;
    use group::{secp256k1, GroupElement, OsCsRng};
    use homomorphic_encryption::GroupsPublicParametersAccessors;
    use mpc::secret_sharing::shamir::over_the_integers::secret_key_share_size_upper_bound;

    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        construct_setup_parameters_per_crt_prime, SECRET_SHARE_CRT_COEFFICIENTS,
        SECRET_SHARE_CRT_PRIMES_PRODUCT,
    };
    use crate::publicly_verifiable_secret_sharing::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::setup::SetupParameters;
    use crate::test_helpers::deal_trusted_shares;
    use crate::{
        Secp256k1DecryptionKey, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_SCALAR_LIMBS, SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
    };

    use super::*;

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
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use std::collections::HashMap;

    use crypto_bigint::Uint;

    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        KnowledgeOfDiscreteLogUCProof, MAX_PRIMES,
    };
    use crate::publicly_verifiable_secret_sharing::test_consts::test_helpers::{
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
