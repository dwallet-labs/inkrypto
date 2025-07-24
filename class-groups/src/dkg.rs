// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    construct_setup_parameters_per_crt_prime, KnowledgeOfDiscreteLogUCProof,
    SecretKeyShareCRTPrimeSetupParameters, CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES, NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
    NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{DealSecretMessage, DealtSecretShareMessage};
use crate::{
    equivalence_class, CompactIbqf, EquivalenceClass, Error, Result,
    DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
};
use crate::{
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
    SECRET_KEY_SHARE_WITNESS_LIMBS,
};
use crypto_bigint::{Encoding, Int, Uint};
use group::helpers::{const_generic_array_serialization, TryCollectHashMap};
use group::{ristretto, secp256k1, PartyID, PrimeGroupElement};
use mpc::secret_sharing::shamir::over_the_integers::{
    compute_binomial_coefficients, factorial, BinomialCoefficientSizedNumber, FactorialSizedNumber,
    MAX_PLAYERS, MAX_THRESHOLD,
};
use mpc::WeightedThresholdAccessStructure;
pub use party::Party;
pub use proofs::*;
pub use public_output::PublicOutput;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

mod first_round;
mod fourth_round;
mod party;
mod proofs;
mod public_output;
mod second_round;
mod third_round;

pub type Secp256k1Party = Party<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;
pub type Secp256k1Message = mpc::Message<Secp256k1Party>;
pub type Secp256k1PublicInput = PublicInput<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::scalar::PublicParameters,
>;

pub type RistrettoParty = Party<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;
pub type RistrettoMessage = mpc::Message<RistrettoParty>;
pub type RistrettoPublicInput = PublicInput<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::scalar::PublicParameters,
>;

// TODO: @offir new name, generalize doc
/// The serializable message sent by a dealer to share the encryption keys used to encrypt secret modulo each CRT prime
/// * The encryption keys used to encrypt the secret modulo each CRT prime.
/// * Proofs that the encryption key contributions match the encryption key shares.
///
/// We generate an encryption key for threshold decryption per threshold CRT prime $Q'_{m'}$ for $m' \in [1,M']$.
/// This is done by computing a public key contribution $\{g_{Q'_{m'}}^{s_{i}}\}_{m' \in [1,M']}$ along with $g_{q}^{s_{i}}$.
/// Notice that the decryption key is the same for all encryptions, this is enforced via zk proofs of equality of discrete log.
/// This is done in pairs i.e. proving each public key contribution for each CRT prime has the same discrete log
/// as the public key contribution to the class-group used for the ECDSA sign.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProveEqualityOfDiscreteLogMessage<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
>(
    #[serde(with = "const_generic_array_serialization")]
    pub(crate)  [(
        EqualityOfDiscreteLogsInHiddenOrderGroupProof<
            DISCRETE_LOG_WITNESS_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    ); NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
)
where
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        group::GroupElement<Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>;

// TODO: @offir new name, generalize doc
/// The instantiated message sent by a dealer to share the threshold encryption key
/// * The encryption key of the encryption of secret modulo each CRT prime.
/// * A proof that the encryption key matches the encryption key share.
pub type ProveEqualityOfDiscreteLog<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = [(
    EqualityOfDiscreteLogsInHiddenOrderGroupProof<
        DISCRETE_LOG_WITNESS_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    EquivalenceClass<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
); NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES];

/// The Public Input of the Distributed Key Generation (DKG) party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInput<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters,
> where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    plaintext_space_public_parameters: ScalarPublicParameters,
    computational_security_parameter: u32,
    setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    encryption_key_values_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
    n_factorial: FactorialSizedNumber,
    // A precomputed mapping of the party-id $j$ to the binomial coefficient ${n\choose j}$.
    binomial_coefficients: HashMap<PartyID, BinomialCoefficientSizedNumber>,
}

/// The Message of the Distributed Key Generation (DKG) protocol.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Message<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        group::GroupElement<Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    DealDecryptionKeyContribution(
        DealSecretMessage<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        ProveEqualityOfDiscreteLogMessage<
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ),
    VerifiedDealers(HashSet<PartyID>),
    EncryptDecryptionKeyShares {
        malicious_decryption_key_contribution_dealers: HashSet<PartyID>,
        encryptions_of_decryption_key_shares_and_proofs: HashMap<
            PartyID,
            DealtSecretShareMessage<
                NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                SECRET_KEY_SHARE_WITNESS_LIMBS,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    },
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        ScalarPublicParameters: Clone,
    >
    PublicInput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
{
    pub fn new<GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>>(
        access_structure: &WeightedThresholdAccessStructure,
        plaintext_space_public_parameters: ScalarPublicParameters,
        computational_security_parameter: u32,
        encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
    ) -> Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
    {
        if computational_security_parameter != DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER {
            // Our sizes are optimized for 112-bits security, need to recompile to allow 128-bit security.
            return Err(Error::InvalidParameters);
        }

        if u32::from(access_structure.threshold) > MAX_THRESHOLD
            || u32::from(access_structure.number_of_virtual_parties()) > MAX_PLAYERS
        {
            return Err(Error::InvalidParameters);
        }

        if FUNDAMENTAL_DISCRIMINANT_LIMBS != CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS {
            return Err(Error::InvalidParameters);
        }

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(computational_security_parameter)?;

        let n_factorial = factorial(access_structure.number_of_virtual_parties());
        let binomial_coefficients =
            compute_binomial_coefficients(access_structure.number_of_virtual_parties());

        Ok(Self {
            plaintext_space_public_parameters,
            computational_security_parameter,
            setup_parameters_per_crt_prime,
            encryption_key_values_and_proofs_per_crt_prime,
            n_factorial,
            binomial_coefficients,
        })
    }
}

/// Sum the commitments to each receiving virtual party to get its public verification key.
/// Note:
/// * `reconstructed_commitments_to_sharing` is keyed by *virtual* participant party id.
///
/// $\textsf{vk}_{j}=\Pi_{j'\in S}C_{\textsf{Share}^{j',j|$
pub fn compute_public_verification_keys_for_participating_party<
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
>(
    access_structure: &WeightedThresholdAccessStructure,
    reconstructed_commitments_to_sharing: HashMap<
        PartyID,
        HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    >,
    participating_tangible_party_id: &PartyID,
) -> Result<HashMap<PartyID, EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>>
where
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
        Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        PublicParameters = equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
{
    let party_to_virtual_parties = access_structure.party_to_virtual_parties();
    let virtual_subset = party_to_virtual_parties
        .get(participating_tangible_party_id)
        .ok_or(Error::InvalidParameters)?;

    virtual_subset
        .iter()
        .map(|&participating_virtual_party_id| {
            reconstructed_commitments_to_sharing
                .clone()
                .into_values()
                .map(|commitments_to_shares| {
                    commitments_to_shares
                        .get(&participating_virtual_party_id)
                        .cloned()
                        .ok_or(Error::InvalidParameters)
                })
                .collect::<Result<Vec<_>>>()
                .and_then(|commitments_to_shares| {
                    commitments_to_shares
                        .into_iter()
                        .reduce(|public_verification_key_accumulator, commitment_to_share| {
                            public_verification_key_accumulator + commitment_to_share
                        })
                        .ok_or(Error::InvalidParameters)
                })
                .map(|public_verification_key| {
                    (participating_virtual_party_id, public_verification_key)
                })
        })
        .try_collect_hash_map()
}

#[cfg(any(test, feature = "test_helpers"))]
#[allow(dead_code)]
pub(crate) mod test_helpers {
    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::rand_core::OsRng;
    use crypto_bigint::{NonZero, Random};
    #[cfg(feature = "parallel")]
    use rayon::iter::IntoParallelIterator;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;
    use std::array;

    use commitment::CommitmentSizedNumber;
    use group::{bounded_integers_group, secp256k1};
    use group::{GroupElement, Reduce};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, AdditivelyHomomorphicDecryptionKeyShare,
        AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors,
    };
    use mpc::secret_sharing::shamir::over_the_integers::{
        compute_adjusted_lagrange_coefficient, interpolate_secret_shares,
        secret_key_share_size_upper_bound,
    };
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;

    use super::*;
    use crate::decryption_key::SecretKey;
    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
        construct_setup_parameters_per_crt_prime, generate_keypairs_per_crt_prime,
        generate_knowledge_of_decryption_key_proofs_per_crt_prime,
        SecretKeyShareCRTPrimeDecryptionKey, SecretKeyShareCRTPrimeEncryptionKey,
        SecretKeyShareCRTPrimeEncryptionSchemePublicParameters, SecretKeyShareCRTPrimeGroupElement,
        ENCRYPTION_OF_DECRYPTION_KEY_CRT_COEFFICIENTS,
        ENCRYPTION_OF_DECRYPTION_KEY_CRT_PRIMES_PRODUCT,
    };
    use crate::publicly_verifiable_secret_sharing::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use crate::{
        decryption_key_share, dkg, CiphertextSpaceGroupElement, RistrettoDecryptionKeyShare,
        Secp256k1DecryptionKeyShare, SecretKeyShareSizedInteger, SecretKeyShareSizedNumber,
        DECRYPTION_KEY_BITS_112BIT_SECURITY, SECRET_KEY_SHARE_LIMBS,
    };

    pub(crate) fn mock_dkg_output<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >(
        decryption_key: SecretKey<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        decryption_key_share_public_parameters: decryption_key_share::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
    ) -> PublicOutput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >
    where
        Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,

        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    {
        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let threshold_encryption_scheme_public_parameters_per_crt_prime = array::from_fn(|i| {
            SecretKeyShareCRTPrimeEncryptionSchemePublicParameters::new_from_secret_key(
                setup_parameters_per_crt_prime[i].clone(),
                decryption_key,
            )
            .unwrap()
        });

        let encryption_of_decryption_key_per_crt_prime = array::from_fn(|i| {
            let public_parameters = &threshold_encryption_scheme_public_parameters_per_crt_prime[i];
            let encryption_key =
                SecretKeyShareCRTPrimeEncryptionKey::new(public_parameters).unwrap();

            let modulus = NonZero::new(
                *public_parameters
                    .plaintext_space_public_parameters()
                    .modulus,
            )
            .unwrap();
            let decryption_key_mod_crt_prime = SecretKeyShareCRTPrimeGroupElement::new(
                decryption_key.reduce(&modulus),
                public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap();

            let (_, ct) = encryption_key
                .encrypt(&decryption_key_mod_crt_prime, public_parameters, &mut OsRng)
                .unwrap();

            ct.value()
        });
        let threshold_encryption_key_per_crt_prime =
            threshold_encryption_scheme_public_parameters_per_crt_prime
                .map(|pp| pp.encryption_key.value());

        dkg::PublicOutput {
            setup_parameters_per_crt_prime,
            encryption_key: decryption_key_share_public_parameters
                .encryption_scheme_public_parameters
                .encryption_key
                .value(),
            threshold_encryption_key_per_crt_prime,
            public_verification_keys: decryption_key_share_public_parameters
                .public_verification_keys
                .clone(),
            encryptions_of_shares_per_crt_prime: HashMap::new(),
            threshold_encryption_of_decryption_key_per_crt_prime:
                encryption_of_decryption_key_per_crt_prime,
        }
    }

    /// Setup parameters for secp256k1 including Class-Groups parameters
    pub fn setups_dkg_secp256k1(
        access_structure: &WeightedThresholdAccessStructure,
        use_same_keys: bool,
    ) -> (
        CommitmentSizedNumber,
        HashMap<PartyID, [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
        HashMap<PartyID, Secp256k1PublicInput>,
    ) {
        let session_id = CommitmentSizedNumber::random(&mut OsRng);
        let plaintext_space_public_parameters = secp256k1::scalar::PublicParameters::default();

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();
        let language_public_parameters_per_crt_prime =
            construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                setup_parameters_per_crt_prime.each_ref(),
            )
            .unwrap();

        let (decryption_key_per_crt_prime, encryption_keys_per_crt_prime_and_proofs): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = if use_same_keys {
            construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(access_structure)
        } else {
            #[cfg(not(feature = "parallel"))]
            let iter = access_structure.party_to_virtual_parties().into_iter();
            #[cfg(feature = "parallel")]
            let iter = access_structure.party_to_virtual_parties().into_par_iter();

            iter.map(|(party_id, _)| {
                let decryption_key_per_crt_prime = generate_keypairs_per_crt_prime(
                    setup_parameters_per_crt_prime.clone(),
                    &mut OsRng,
                )
                .unwrap();

                let encryption_keys_and_proofs =
                    generate_knowledge_of_decryption_key_proofs_per_crt_prime(
                        language_public_parameters_per_crt_prime.clone(),
                        decryption_key_per_crt_prime,
                        &mut OsRng,
                    )
                    .unwrap();

                (
                    (party_id, decryption_key_per_crt_prime),
                    (party_id, encryption_keys_and_proofs),
                )
            })
            .unzip()
        };

        let public_inputs: HashMap<_, _> = (1..=access_structure.number_of_tangible_parties())
            .map(|party_id| {
                (
                    party_id,
                    PublicInput::new::<secp256k1::GroupElement>(
                        access_structure,
                        plaintext_space_public_parameters.clone(),
                        DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                        encryption_keys_per_crt_prime_and_proofs.clone(),
                    )
                    .unwrap(),
                )
            })
            .collect();

        (session_id, decryption_key_per_crt_prime, public_inputs)
    }

    pub fn generates_distributed_key_secp256k1_internal(
        access_structure: &WeightedThresholdAccessStructure,
        bench: bool,
    ) -> (
        decryption_key_share::PublicParameters<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::scalar::PublicParameters,
        >,
        HashMap<PartyID, Secp256k1DecryptionKeyShare>,
    ) {
        let (session_id, decryption_keys, public_inputs) =
            setups_dkg_secp256k1(access_structure, !bench);

        let (total_time, rounds_times, public_output) =
            asynchronous_session_terminates_successfully_internal::<Secp256k1Party>(
                session_id,
                access_structure,
                decryption_keys.clone(),
                public_inputs.clone(),
                4,
                HashMap::from([(
                    2,
                    HashSet::from_iter(1..=(access_structure.number_of_tangible_parties() - 1)),
                )]),
                bench,
                bench,
            );

        let decryption_key_share_public_parameters = public_output
            .default_decryption_key_share_public_parameters::<secp256k1::GroupElement>(
                access_structure,
            )
            .unwrap();

        let measurement = WallTime;
        let now = measurement.start();
        let decryption_key_shares: HashMap<_, _> = public_inputs
            .keys()
            .flat_map(|&tangible_party_id| {
                let decryption_key_shares = public_output
                    .decrypt_decryption_key_shares::<secp256k1::GroupElement>(
                        tangible_party_id,
                        access_structure,
                        *decryption_keys.get(&tangible_party_id).unwrap(),
                    )
                    .unwrap();

                decryption_key_shares
            })
            .collect();
        let decryption_time = measurement.end(now);
        let total_time_with_decryption = measurement.add(&total_time, &decryption_time);

        let setup_parameters_per_crt_prime = public_inputs
            .values()
            .next()
            .unwrap()
            .setup_parameters_per_crt_prime
            .clone();
        let n_factorial = public_inputs.values().next().unwrap().n_factorial;
        let binomial_coefficients = &public_inputs.values().next().unwrap().binomial_coefficients;

        let decryption_key = Uint::from(&interpolate_decryption_key(
            access_structure.threshold,
            access_structure.number_of_virtual_parties(),
            decryption_key_shares.clone(),
            binomial_coefficients,
            n_factorial,
        ));

        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                let decryption_key_share = Secp256k1DecryptionKeyShare::new(
                    virtual_party_id,
                    decryption_key_share,
                    &decryption_key_share_public_parameters,
                )
                .unwrap();

                (virtual_party_id, decryption_key_share)
            })
            .collect();

        homomorphic_encryption::test_helpers::threshold_decrypts(
            access_structure.threshold,
            1,
            decryption_key_shares.clone(),
            &decryption_key_share_public_parameters,
            &mut OsRng,
        );

        let threshold_encryption_scheme_public_parameters_per_crt_prime = public_output
            .threshold_encryption_scheme_public_parameters_per_crt_prime()
            .unwrap();
        for i in 0..NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES {
            let expected_encryption_key =
                setup_parameters_per_crt_prime[i].power_of_h_vartime(&decryption_key);

            assert_eq!(
                expected_encryption_key,
                threshold_encryption_scheme_public_parameters_per_crt_prime[i].encryption_key,
                "threshold encryption key for prime {i} is wrong"
            );
        }

        let encryption_of_decryption_key_per_crt_prime = array::from_fn(|i| {
            CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                public_output.threshold_encryption_of_decryption_key_per_crt_prime[i],
                setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters(),
            )
            .unwrap()
        });

        let decryption_key_per_crt_primes = array::from_fn(|i| {
            SecretKeyShareCRTPrimeDecryptionKey::new(
                decryption_key,
                &threshold_encryption_scheme_public_parameters_per_crt_prime[i],
            )
            .unwrap()
        });

        let decrypted_encryption_of_decryption_key =
            crate::publicly_verifiable_secret_sharing::Party::<
                NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
                SECRET_KEY_SHARE_LIMBS,
                SECRET_KEY_SHARE_WITNESS_LIMBS,
                SECP256K1_SCALAR_LIMBS,
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                secp256k1::GroupElement,
            >::decrypt_and_crt_reconstruct_internal(
                ENCRYPTION_OF_DECRYPTION_KEY_CRT_COEFFICIENTS,
                ENCRYPTION_OF_DECRYPTION_KEY_CRT_PRIMES_PRODUCT,
                threshold_encryption_scheme_public_parameters_per_crt_prime,
                decryption_key_per_crt_primes,
                encryption_of_decryption_key_per_crt_prime.each_ref(),
            )
            .unwrap();

        let expected_decryption_key = SecretKeyShareSizedNumber::from(&decryption_key);

        assert_eq!(
            decrypted_encryption_of_decryption_key.abs(),
            expected_decryption_key,
            "decrypted decryption key from threshold encryption is wrong"
        );

        println!(
            "Secp256k1 Class-Groups DKG, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
            access_structure.number_of_tangible_parties(),
            access_structure.number_of_virtual_parties(),
            access_structure.threshold,
            total_time.as_millis(),
            total_time_with_decryption.as_millis(),
            rounds_times[0].as_millis(),
            rounds_times[1].as_millis(),
            rounds_times[2].as_millis(),
            decryption_time.as_millis(),
        );

        (
            decryption_key_share_public_parameters,
            decryption_key_shares,
        )
    }

    fn interpolate_decryption_key(
        threshold: PartyID,
        number_of_parties: PartyID,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        binomial_coefficients: &HashMap<PartyID, BinomialCoefficientSizedNumber>,
        n_factorial: FactorialSizedNumber,
    ) -> SecretKeyShareSizedNumber {
        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .take(usize::from(threshold))
            .collect();

        let interpolation_subset: HashSet<_> = decryption_key_shares.keys().copied().collect();

        let secret_key_share_upper_bound_bits = secret_key_share_size_upper_bound(
            number_of_parties.into(),
            threshold.into(),
            DECRYPTION_KEY_BITS_112BIT_SECURITY,
        );

        let discrete_log_group_public_parameters = bounded_integers_group::PublicParameters::<
            SECRET_KEY_SHARE_WITNESS_LIMBS,
        >::new_with_randomizer_upper_bound(
            secret_key_share_upper_bound_bits
        )
        .unwrap();

        let decryption_key_shares_for_interpolation: HashMap<_, _> = decryption_key_shares
            .clone()
            .into_iter()
            .map(|(party_id, x)| {
                (
                    party_id,
                    vec![bounded_integers_group::GroupElement::new(
                        Int::from(&x),
                        &discrete_log_group_public_parameters,
                    )
                    .unwrap()],
                )
            })
            .collect();

        let adjusted_lagrange_coefficients: HashMap<_, _> = interpolation_subset
            .iter()
            .map(|&dealer_virtual_party_id| {
                // dealer_virtual_party_id is $j_{T} \in {S_{B_{T}}}$
                let adjusted_lagrange_coefficient = compute_adjusted_lagrange_coefficient(
                    dealer_virtual_party_id,
                    number_of_parties,
                    interpolation_subset.clone(),
                    binomial_coefficients
                        .get(&dealer_virtual_party_id)
                        .unwrap()
                        .resize(),
                );

                (dealer_virtual_party_id, adjusted_lagrange_coefficient)
            })
            .collect();

        let interpolated_decryption_key = interpolate_secret_shares(
            decryption_key_shares_for_interpolation,
            adjusted_lagrange_coefficients,
            0,
            number_of_parties,
            n_factorial,
        )
        .unwrap()[0];
        Uint::from(&((interpolated_decryption_key.value().abs() / n_factorial) / n_factorial))
    }

    /// Setup parameters for ristretto including Class-Groups parameters
    pub fn setups_dkg_ristretto(
        access_structure: &WeightedThresholdAccessStructure,
    ) -> (
        CommitmentSizedNumber,
        HashMap<PartyID, [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
        HashMap<PartyID, RistrettoPublicInput>,
    ) {
        let session_id = CommitmentSizedNumber::random(&mut OsRng);

        let plaintext_space_public_parameters = ristretto::scalar::PublicParameters::default();

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();
        let language_public_parameters_per_crt_prime =
            construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                setup_parameters_per_crt_prime.each_ref(),
            )
            .unwrap();

        #[cfg(not(feature = "parallel"))]
        let iter = access_structure.party_to_virtual_parties().into_iter();
        #[cfg(feature = "parallel")]
        let iter = access_structure.party_to_virtual_parties().into_par_iter();

        let (decryption_key_per_crt_prime, encryption_keys_per_crt_prime_and_proofs): (
            HashMap<_, _>,
            HashMap<_, _>,
        ) = iter
            .map(|(party_id, _)| {
                let decryption_key_per_crt_prime = generate_keypairs_per_crt_prime(
                    setup_parameters_per_crt_prime.clone(),
                    &mut OsRng,
                )
                .unwrap();

                let encryption_keys_and_proofs =
                    generate_knowledge_of_decryption_key_proofs_per_crt_prime(
                        language_public_parameters_per_crt_prime.clone(),
                        decryption_key_per_crt_prime,
                        &mut OsRng,
                    )
                    .unwrap();

                (
                    (party_id, decryption_key_per_crt_prime),
                    (party_id, encryption_keys_and_proofs),
                )
            })
            .unzip();

        let public_inputs: HashMap<_, _> = (1..=access_structure.number_of_tangible_parties())
            .map(|party_id| {
                (
                    party_id,
                    PublicInput::new::<ristretto::GroupElement>(
                        access_structure,
                        plaintext_space_public_parameters.clone(),
                        DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
                        encryption_keys_per_crt_prime_and_proofs.clone(),
                    )
                    .unwrap(),
                )
            })
            .collect();

        (session_id, decryption_key_per_crt_prime, public_inputs)
    }

    pub fn generates_distributed_key_ristretto_internal(
        access_structure: &WeightedThresholdAccessStructure,
        bench: bool,
    ) -> (
        decryption_key_share::PublicParameters<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::scalar::PublicParameters,
        >,
        HashMap<PartyID, RistrettoDecryptionKeyShare>,
    ) {
        let (session_id, decryption_keys, public_inputs) = setups_dkg_ristretto(access_structure);

        let (total_time, rounds_times, public_output) =
            asynchronous_session_terminates_successfully_internal::<RistrettoParty>(
                session_id,
                access_structure,
                decryption_keys.clone(),
                public_inputs.clone(),
                4,
                HashMap::from([(
                    2,
                    HashSet::from_iter(1..=(access_structure.number_of_tangible_parties() - 1)),
                )]),
                bench,
                bench,
            );

        let decryption_key_share_public_parameters = public_output
            .default_decryption_key_share_public_parameters::<ristretto::GroupElement>(
                access_structure,
            )
            .unwrap();

        let measurement = WallTime;
        let now = measurement.start();
        let decryption_key_shares: HashMap<_, _> = public_inputs
            .keys()
            .flat_map(|&tangible_party_id| {
                let decryption_key_shares = public_output
                    .decrypt_decryption_key_shares::<ristretto::GroupElement>(
                        tangible_party_id,
                        access_structure,
                        *decryption_keys.get(&tangible_party_id).unwrap(),
                    )
                    .unwrap();

                decryption_key_shares
            })
            .collect();
        let decryption_time = measurement.end(now);
        let total_time_with_decryption = measurement.add(&total_time, &decryption_time);

        let decryption_key_shares: HashMap<_, _> = decryption_key_shares
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                let decryption_key_share = RistrettoDecryptionKeyShare::new(
                    virtual_party_id,
                    decryption_key_share,
                    &decryption_key_share_public_parameters,
                )
                .unwrap();

                (virtual_party_id, decryption_key_share)
            })
            .collect();

        homomorphic_encryption::test_helpers::threshold_decrypts(
            access_structure.threshold,
            1,
            decryption_key_shares.clone(),
            &decryption_key_share_public_parameters,
            &mut OsRng,
        );

        println!(
            "Ristretto Class-Groups DKG, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
            access_structure.number_of_tangible_parties(),
            access_structure.number_of_virtual_parties(),
            access_structure.threshold,
            total_time.as_millis(),
            total_time_with_decryption.as_millis(),
            rounds_times[0].as_millis(),
            rounds_times[1].as_millis(),
            rounds_times[2].as_millis(),
            decryption_time.as_millis(),
        );

        (
            decryption_key_share_public_parameters,
            decryption_key_shares,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::dkg::test_helpers::{
        generates_distributed_key_ristretto_internal, generates_distributed_key_secp256k1_internal,
        mock_dkg_output,
    };
    use crypto_bigint::Uint;
    use group::{secp256k1, GroupElement, PartyID};
    use homomorphic_encryption::{
        AdditivelyHomomorphicDecryptionKey, GroupsPublicParametersAccessors,
    };
    use mpc::{Weight, WeightedThresholdAccessStructure};
    use rand_core::OsRng;
    use rstest::rstest;
    use std::array;
    use std::collections::HashMap;

    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        SecretKeyShareCRTPrimeDecryptionKey, CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ENCRYPTION_OF_DECRYPTION_KEY_CRT_COEFFICIENTS,
        ENCRYPTION_OF_DECRYPTION_KEY_CRT_PRIMES_PRODUCT, NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
    };
    use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
    use crate::test_helpers::deal_trusted_shares;
    use crate::{
        publicly_verifiable_secret_sharing, CiphertextSpaceGroupElement, Secp256k1DecryptionKey,
        DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
        SECRET_KEY_SHARE_LIMBS, SECRET_KEY_SHARE_WITNESS_LIMBS,
    };

    #[test]
    fn test_mock_dkg_output() {
        let access_structure =
            WeightedThresholdAccessStructure::random(82, 50, 103, &mut OsRng).unwrap();
        let plaintext_space_public_parameters =
            group::secp256k1::scalar::PublicParameters::default();

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
        let (encryption_scheme_public_parameters, decryption_key) =
            Secp256k1DecryptionKey::generate(setup_parameters.clone(), &mut OsRng).unwrap();

        let (decryption_key_share_public_parameters, _) = deal_trusted_shares::<
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

        let dkg_output = mock_dkg_output::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >(
            decryption_key.decryption_key,
            decryption_key_share_public_parameters.clone(),
        );

        let encryption_of_decryption_key_per_crt_prime = array::from_fn(|i| {
            CiphertextSpaceGroupElement::<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
                dkg_output.threshold_encryption_of_decryption_key_per_crt_prime[i],
                dkg_output.setup_parameters_per_crt_prime[i].ciphertext_space_public_parameters(),
            )
            .unwrap()
        });

        let threshold_encryption_scheme_public_parameters_per_crt_prime = dkg_output
            .threshold_encryption_scheme_public_parameters_per_crt_prime()
            .unwrap();

        let decryption_key_per_crt_primes = array::from_fn(|i| {
            SecretKeyShareCRTPrimeDecryptionKey::new(
                decryption_key.decryption_key,
                &threshold_encryption_scheme_public_parameters_per_crt_prime[i],
            )
            .unwrap()
        });

        let decrypted_encryption_of_decryption_key = publicly_verifiable_secret_sharing::Party::<
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
            SECRET_KEY_SHARE_LIMBS,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >::decrypt_and_crt_reconstruct_internal(
            ENCRYPTION_OF_DECRYPTION_KEY_CRT_COEFFICIENTS,
            ENCRYPTION_OF_DECRYPTION_KEY_CRT_PRIMES_PRODUCT,
            threshold_encryption_scheme_public_parameters_per_crt_prime,
            decryption_key_per_crt_primes,
            encryption_of_decryption_key_per_crt_prime.each_ref(),
        )
        .unwrap();

        assert_eq!(
            Uint::from(&decrypted_encryption_of_decryption_key.abs()),
            decryption_key.decryption_key,
            "decrypted decryption key from threshold encryption is wrong"
        );
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn generates_distributed_key_secp256k1(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        generates_distributed_key_secp256k1_internal(&access_structure, false);
    }

    #[rstest]
    #[case(2, HashMap::from([(1, 1), (2, 1)]))]
    #[case(4, HashMap::from([(1, 2), (2, 1), (3, 3)]))]
    fn generates_distributed_key_ristretto(
        #[case] threshold: PartyID,
        #[case] party_to_weight: HashMap<PartyID, Weight>,
    ) {
        let access_structure =
            WeightedThresholdAccessStructure::new(threshold, party_to_weight).unwrap();

        generates_distributed_key_ristretto_internal(&access_structure, false);
    }
}

#[cfg(all(test, feature = "benchmarking"))]
mod benches {
    use rand_core::OsRng;

    use mpc::WeightedThresholdAccessStructure;

    #[test]
    #[ignore]
    fn benchmark() {
        println!("\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Total Time (ms), Total Time With Decryption (ms), First Round (ms), Second Round (ms), Third Round (ms), Decryption (ms)", );

        for (threshold, number_of_tangible_parties, total_weight) in
            [(77, 50, 115), (67, 100, 100), (77, 100, 115)]
        {
            let access_structure = WeightedThresholdAccessStructure::uniform(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsRng,
            )
            .unwrap();

            super::test_helpers::generates_distributed_key_secp256k1_internal(
                &access_structure,
                true,
            );

            super::test_helpers::generates_distributed_key_ristretto_internal(
                &access_structure,
                true,
            );
        }
    }
}
