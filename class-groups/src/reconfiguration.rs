// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::{HashMap, HashSet};

use crypto_bigint::{Encoding, Int, Limb, Uint};
use serde::{Deserialize, Serialize};

use group::bounded_natural_numbers_group::MAURER_PROOFS_DIFF_UPPER_BOUND_BITS;
use group::{ristretto, secp256k1, PartyID, PrimeGroupElement, StatisticalSecuritySizedNumber};
use mpc::secret_sharing::shamir::over_the_integers::{
    find_closest_crypto_bigint_size, MAX_PLAYERS, MAX_THRESHOLD,
};
use mpc::WeightedThresholdAccessStructure;
pub use party::{Party, RistrettoParty, Secp256k1Party};
pub use public_output::PublicOutput;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::dkg::ProveEqualityOfDiscreteLogMessage;
use crate::equivalence_class::EquivalenceClassOps;
use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
    construct_setup_parameters_per_crt_prime, KnowledgeOfDiscreteLogUCProof,
    SecretKeyShareCRTPrimeDecryptionShare, SecretKeyShareCRTPrimePartialDecryptionProof,
    SecretKeyShareCRTPrimeSetupParameters, CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES, NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
    NUM_SECRET_SHARE_PRIMES,
};
use crate::publicly_verifiable_secret_sharing::{DealSecretMessage, DealtSecretShareMessage};
use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
use crate::{
    decryption_key_share, dkg, equivalence_class, CompactIbqf, EquivalenceClass, Error, Result,
    DECRYPTION_KEY_BITS_112BIT_SECURITY, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
};
use crate::{
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_SCALAR_LIMBS, SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_SCALAR_LIMBS,
    SECRET_KEY_SHARE_WITNESS_LIMBS,
};

mod first_round;
mod fourth_round;
mod party;
mod public_output;
mod second_round;
mod third_round;

pub type Secp256k1Message = mpc::Message<Secp256k1Party>;
pub type Secp256k1PublicInput = PublicInput<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::scalar::PublicParameters,
>;
pub type Secp256k1PublicOutput = PublicOutput<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
>;

pub type RistrettoMessage = mpc::Message<RistrettoParty>;
pub type RistrettoPublicInput = PublicInput<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::scalar::PublicParameters,
>;
pub type RistrettoPublicOutput = PublicOutput<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
>;

pub const RANDOMIZER_UPPER_BOUND: u32 =
    DECRYPTION_KEY_BITS_112BIT_SECURITY + StatisticalSecuritySizedNumber::BITS;
pub const RANDOMIZER_LIMBS: usize =
    find_closest_crypto_bigint_size(RANDOMIZER_UPPER_BOUND as usize) / Limb::BITS as usize;
pub const RANDOMIZER_WITNESS_LIMBS: usize = find_closest_crypto_bigint_size(
    (RANDOMIZER_UPPER_BOUND + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS) as usize,
) / Limb::BITS as usize;

/// The Public Input of the Reconfiguration party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicInput<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    ScalarPublicParameters,
> where
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
    SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >: DeriveFromPlaintextPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >,
{
    pub upcoming_access_structure: WeightedThresholdAccessStructure,
    pub plaintext_space_public_parameters: ScalarPublicParameters,
    pub setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
    pub setup_parameters: SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >,
    pub computational_security_parameter: u32,
    pub current_encryption_key_values_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
    pub upcoming_encryption_key_values_and_proofs_per_crt_prime: HashMap<
        PartyID,
        [(
            CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            KnowledgeOfDiscreteLogUCProof,
        ); MAX_PRIMES],
    >,
    // The *current* (latest) decryption key share public parameters.
    pub decryption_key_share_public_parameters: decryption_key_share::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >,
    // If the party participates in the upcoming party set, then its value is `Some()`, otherwise its `None`
    pub current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
    pub dkg_output: dkg::PublicOutput<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
}

/// The Message of the Reconfiguration protocol.
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
    // First Round:
    // 1. Encryption of the randomizer contribution shares for each party under each CRT threshold encryption
    // 2. Commitment to the sharing polynomial over the Elliptic Curve Class-Group
    // 3. ZK proofs roofs of correct sharing.
    DealRandomizer {
        deal_randomizer_contribution_to_upcoming_parties_message: DealSecretMessage<
            NUM_SECRET_SHARE_PRIMES,
            SECRET_KEY_SHARE_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        threshold_encryption_of_randomizer_contribution_and_proof: DealtSecretShareMessage<
            NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES,
            RANDOMIZER_WITNESS_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    },

    // Second Round:
    // 1. If a party is not part of the upcoming set (in case it leaves the network), then it cannot verify anything for it and sends `None`.
    //    Otherwise, it verifies for itself and sends `Some()`.
    VerifiedRandomizerDealers(Option<HashSet<PartyID>>),

    // Third Round:
    // 1. The malicious dealers of the first round.
    // 2.
    //  2.1. Decryption Share of the ciphertext containing the masked key per CRT prime.
    //  2.2. Proof of correct decryption share generation using the verification keys generated in the same round.
    // 3.
    //  3.1. Verification Keys in the CRT Class-Groups
    //  3.2. Proof of consistency with the verificdation key in the Elliptic Curve Group.
    ThresholdDecryptShares {
        malicious_randomizer_dealers: HashSet<PartyID>,
        masked_decryption_key_decryption_shares_and_proofs: HashMap<
            PartyID,
            [(
                SecretKeyShareCRTPrimeDecryptionShare,
                SecretKeyShareCRTPrimePartialDecryptionProof,
            ); NUM_ENCRYPTION_OF_DECRYPTION_KEY_PRIMES],
        >,
        prove_public_verification_keys_messages: HashMap<
            PartyID,
            ProveEqualityOfDiscreteLogMessage<
                SECRET_KEY_SHARE_WITNESS_LIMBS,
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
    SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >: DeriveFromPlaintextPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        ScalarPublicParameters,
    >,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new<GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>>(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: WeightedThresholdAccessStructure,
        plaintext_space_public_parameters: ScalarPublicParameters,
        current_encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
        upcoming_encryption_key_values_and_proofs_per_crt_prime: HashMap<
            PartyID,
            [(
                CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
                KnowledgeOfDiscreteLogUCProof,
            ); MAX_PRIMES],
        >,
        decryption_key_share_public_parameters: decryption_key_share::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        computational_security_parameter: u32,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        dkg_output: dkg::PublicOutput<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
    {
        if computational_security_parameter != DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER {
            // Our sizes are optimized for 112-bits security, need to recompile to allow 128-bit security.
            return Err(Error::InvalidParameters);
        }

        if u32::from(current_access_structure.threshold) > MAX_THRESHOLD
            || u32::from(upcoming_access_structure.threshold) > MAX_THRESHOLD
            || u32::from(current_access_structure.number_of_virtual_parties()) > MAX_PLAYERS
            || u32::from(upcoming_access_structure.number_of_virtual_parties()) > MAX_PLAYERS
        {
            return Err(Error::InvalidParameters);
        }

        if FUNDAMENTAL_DISCRIMINANT_LIMBS != CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS {
            return Err(Error::InvalidParameters);
        }

        let current_tangible_parties: HashSet<_> = current_tangible_party_id_to_upcoming
            .keys()
            .copied()
            .collect();
        let upcoming_tangible_parties: HashSet<_> = upcoming_access_structure
            .party_to_weight
            .keys()
            .copied()
            .collect();

        if current_tangible_parties
            != current_access_structure
                .party_to_weight
                .keys()
                .copied()
                .collect()
        {
            return Err(Error::InvalidParameters);
        }

        let upcoming_party_ids_of_current_parties: HashSet<_> =
            current_tangible_party_id_to_upcoming
                .values()
                .copied()
                .flatten()
                .collect();

        if !upcoming_tangible_parties.is_superset(&upcoming_party_ids_of_current_parties) {
            return Err(Error::InvalidParameters);
        }

        let setup_parameters =
            SetupParameters::derive_from_plaintext_parameters::<GroupElement::Scalar>(
                plaintext_space_public_parameters.clone(),
                computational_security_parameter,
            )?;

        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(computational_security_parameter)?;

        Ok(Self {
            plaintext_space_public_parameters,
            computational_security_parameter,
            setup_parameters_per_crt_prime,
            setup_parameters,
            current_encryption_key_values_and_proofs_per_crt_prime,
            upcoming_encryption_key_values_and_proofs_per_crt_prime,
            current_tangible_party_id_to_upcoming,
            decryption_key_share_public_parameters,
            upcoming_access_structure,
            dkg_output,
        })
    }
}

#[cfg(any(test, feature = "test_helpers"))]
#[allow(dead_code)]
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
pub(crate) mod test_helpers {
    use criterion::measurement::{Measurement, WallTime};
    use crypto_bigint::Random;
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    use commitment::CommitmentSizedNumber;
    use group::{bounded_integers_group, secp256k1, GroupElement, OsCsRng};
    use homomorphic_encryption::AdditivelyHomomorphicDecryptionKeyShare;
    use mpc::secret_sharing::shamir::over_the_integers::{
        compute_adjusted_lagrange_coefficient, compute_binomial_coefficients, factorial,
        interpolate_in_the_exponent, interpolate_secret_shares, secret_key_share_size_upper_bound,
    };
    use mpc::test_helpers::asynchronous_session_terminates_successfully_internal;

    use crate::dkg::test_helpers::mock_dkg_output;
    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::{
        construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
        construct_setup_parameters_per_crt_prime, generate_keypairs_per_crt_prime,
        generate_knowledge_of_decryption_key_proofs_per_crt_prime,
    };
    use crate::publicly_verifiable_secret_sharing::test_helpers::construct_encryption_keys_and_proofs_per_crt_prime_secp256k1;
    use crate::setup::{DeriveFromPlaintextPublicParameters, SetupParameters};
    use crate::test_helpers::deal_trusted_shares;
    use crate::{
        decryption_key_share, EquivalenceClass, RistrettoDecryptionKey,
        RistrettoDecryptionKeyShare, RistrettoDecryptionKeySharePublicParameters,
        Secp256k1DecryptionKey, Secp256k1DecryptionKeyShare,
        Secp256k1DecryptionKeySharePublicParameters, Secp256k1EncryptionSchemePublicParameters,
        SecretKeyShareSizedInteger, COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_LIMBS,
        COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_UPPER_BOUND,
        DECRYPTION_KEY_BITS_112BIT_SECURITY, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };

    use super::*;

    fn interpolated_encryption_decryption_keys_checks_out(
        threshold: PartyID,
        number_of_parties: PartyID,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        decryption_key: Uint<SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        public_verification_keys: HashMap<
            PartyID,
            CompactIbqf<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
        encryption_key: EquivalenceClass<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        equivalence_class_public_parameters: &equivalence_class::PublicParameters<
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) {
        let n_factorial = factorial(number_of_parties);
        let binomial_coefficients = compute_binomial_coefficients(number_of_parties);

        let public_verification_keys_for_interpolation: HashMap<_, _> = public_verification_keys
            .clone()
            .into_iter()
            .map(|(party_id, vk)| {
                (
                    party_id,
                    vec![EquivalenceClass::new(vk, equivalence_class_public_parameters).unwrap()],
                )
            })
            .take(usize::from(threshold))
            .collect();

        let interpolation_subset: HashSet<_> = public_verification_keys_for_interpolation
            .keys()
            .copied()
            .collect();

        let secret_key_share_upper_bound_bits = secret_key_share_size_upper_bound(
            number_of_parties.into(),
            threshold.into(),
            DECRYPTION_KEY_BITS_112BIT_SECURITY,
        );

        let discrete_log_group_public_parameters = bounded_integers_group::PublicParameters::<
            COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_LIMBS,
        >::new(
            secret_key_share_upper_bound_bits,
            COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_UPPER_BOUND,
        )
        .unwrap();

        let decryption_key_shares_for_interpolation: HashMap<_, _> = decryption_key_shares
            .clone()
            .into_iter()
            .filter(|(party_id, _)| interpolation_subset.contains(party_id))
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

        let interpolated_encryption_key = interpolate_in_the_exponent(
            public_verification_keys_for_interpolation,
            adjusted_lagrange_coefficients.clone(),
            0,
            number_of_parties,
            n_factorial,
            None,
            false,
        )
        .unwrap()[0];

        let interpolated_decryption_key = interpolate_secret_shares(
            decryption_key_shares_for_interpolation,
            adjusted_lagrange_coefficients,
            0,
            number_of_parties,
            n_factorial,
        )
        .unwrap()[0];

        let expected_decryption_key =
            (Uint::<COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_LIMBS>::from(&decryption_key)
                * n_factorial)
                * n_factorial;

        assert_eq!(
            interpolated_decryption_key.value().abs(),
            expected_decryption_key,
            "interpolated decryption key is wrong"
        );

        let expected_encryption_key =
            (1..=2).fold(encryption_key, |acc, _| acc.scale_vartime(&n_factorial));

        assert_eq!(
            interpolated_encryption_key, expected_encryption_key,
            "interpolated encryption key is wrong"
        );
    }

    pub fn setup_reconfig_secp256k1(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        encryption_scheme_public_parameters: Secp256k1EncryptionSchemePublicParameters,
        decryption_key: Secp256k1DecryptionKey,
        decryption_key_share_public_parameters: Secp256k1DecryptionKeySharePublicParameters,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        dkg_output: dkg::PublicOutput<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        use_same_keys: bool,
    ) -> (
        CommitmentSizedNumber,
        HashMap<PartyID, HashMap<PartyID, SecretKeyShareSizedInteger>>,
        HashMap<PartyID, [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
        HashMap<PartyID, Secp256k1PublicInput>,
    ) {
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        let plaintext_space_public_parameters = secp256k1::scalar::PublicParameters::default();

        let (
            current_encryption_keys_per_crt_prime_and_proofs,
            upcoming_decryption_key_per_crt_prime,
            upcoming_encryption_keys_per_crt_prime_and_proofs,
        ) = if use_same_keys {
            let (_, current_encryption_keys_per_crt_prime_and_proofs) =
                construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(
                    current_access_structure,
                );

            let (
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            ) = construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(
                upcoming_access_structure,
            );

            (
                current_encryption_keys_per_crt_prime_and_proofs,
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            )
        } else {
            let language_public_parameters_per_crt_prime =
                construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                    setup_parameters_per_crt_prime.each_ref(),
                )
                .unwrap();

            #[cfg(not(feature = "parallel"))]
            let iter = current_access_structure
                .party_to_virtual_parties()
                .into_iter();
            #[cfg(feature = "parallel")]
            let iter = current_access_structure
                .party_to_virtual_parties()
                .into_par_iter();

            let current_encryption_keys_per_crt_prime_and_proofs: HashMap<_, _> = iter
                .map(|(party_id, _)| {
                    let decryption_key_per_crt_prime = generate_keypairs_per_crt_prime(
                        setup_parameters_per_crt_prime.clone(),
                        &mut OsCsRng,
                    )
                    .unwrap();

                    let encryption_keys_and_proofs =
                        generate_knowledge_of_decryption_key_proofs_per_crt_prime(
                            language_public_parameters_per_crt_prime.clone(),
                            decryption_key_per_crt_prime,
                            &mut OsCsRng,
                        )
                        .unwrap();

                    (party_id, encryption_keys_and_proofs)
                })
                .collect();

            #[cfg(not(feature = "parallel"))]
            let iter = upcoming_access_structure
                .party_to_virtual_parties()
                .into_iter();
            #[cfg(feature = "parallel")]
            let iter = upcoming_access_structure
                .party_to_virtual_parties()
                .into_par_iter();

            let (
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            ): (HashMap<_, _>, HashMap<_, _>) = iter
                .map(|(party_id, _)| {
                    let decryption_key_per_crt_prime = generate_keypairs_per_crt_prime(
                        setup_parameters_per_crt_prime.clone(),
                        &mut OsCsRng,
                    )
                    .unwrap();

                    let encryption_keys_and_proofs =
                        generate_knowledge_of_decryption_key_proofs_per_crt_prime(
                            language_public_parameters_per_crt_prime.clone(),
                            decryption_key_per_crt_prime,
                            &mut OsCsRng,
                        )
                        .unwrap();

                    (
                        (party_id, decryption_key_per_crt_prime),
                        (party_id, encryption_keys_and_proofs),
                    )
                })
                .unzip();

            (
                current_encryption_keys_per_crt_prime_and_proofs,
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            )
        };

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

        let private_inputs = current_access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|tangible_party_id| {
                let party_to_virtual_parties = current_access_structure.party_to_virtual_parties();

                let decryption_key_shares = party_to_virtual_parties
                    .get(tangible_party_id)
                    .unwrap()
                    .clone()
                    .into_iter()
                    .map(|virtual_party_id| {
                        (
                            virtual_party_id,
                            *decryption_key_shares.get(&virtual_party_id).unwrap(),
                        )
                    })
                    .collect();

                (*tangible_party_id, decryption_key_shares)
            })
            .collect();

        let public_input = PublicInput::new::<secp256k1::GroupElement>(
            current_access_structure,
            upcoming_access_structure.clone(),
            plaintext_space_public_parameters.clone(),
            current_encryption_keys_per_crt_prime_and_proofs.clone(),
            upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
            decryption_key_share_public_parameters.clone(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            current_tangible_party_id_to_upcoming.clone(),
            dkg_output.clone(),
        )
        .unwrap();

        let public_inputs: HashMap<_, _> = (1..=current_access_structure
            .number_of_tangible_parties())
            .map(|party_id| (party_id, public_input.clone()))
            .collect();

        interpolated_encryption_decryption_keys_checks_out(
            current_access_structure.threshold,
            current_access_structure.number_of_virtual_parties(),
            decryption_key_shares,
            decryption_key.decryption_key,
            decryption_key_share_public_parameters.public_verification_keys,
            encryption_scheme_public_parameters.encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        );

        (
            session_id,
            private_inputs,
            upcoming_decryption_key_per_crt_prime,
            public_inputs,
        )
    }

    pub fn reconfigures_secp256k1_internal(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        use_same_keys: bool,
        bench: bool,
    ) -> (
        Secp256k1DecryptionKey,
        dkg::PublicOutput<
            SECP256K1_SCALAR_LIMBS,
            CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        decryption_key_share::PublicParameters<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::scalar::PublicParameters,
        >,
        HashMap<PartyID, SecretKeyShareSizedInteger>,
    ) {
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
        let (encryption_scheme_public_parameters, decryption_key) =
            Secp256k1DecryptionKey::generate_with_setup_parameters(
                setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();

        let (decryption_key_share_public_parameters, decryption_key_shares) = deal_trusted_shares::<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::GroupElement,
        >(
            current_access_structure.threshold,
            current_access_structure.number_of_virtual_parties(),
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

        let (decryption_key, decryption_key_share_public_parameters, decryption_key_shares) =
            reconfigures_secp256k1_internal_internal(
                current_access_structure,
                upcoming_access_structure,
                current_tangible_party_id_to_upcoming,
                encryption_scheme_public_parameters,
                decryption_key,
                decryption_key_share_public_parameters,
                decryption_key_shares,
                dkg_output.clone(),
                use_same_keys,
                bench,
            );

        (
            decryption_key,
            dkg_output,
            decryption_key_share_public_parameters,
            decryption_key_shares,
        )
    }

    pub fn reconfigures_secp256k1_internal_internal(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        encryption_scheme_public_parameters: Secp256k1EncryptionSchemePublicParameters,
        decryption_key: Secp256k1DecryptionKey,
        decryption_key_share_public_parameters: Secp256k1DecryptionKeySharePublicParameters,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        dkg_output: dkg::PublicOutput<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        use_same_keys: bool,
        bench: bool,
    ) -> (
        Secp256k1DecryptionKey,
        decryption_key_share::PublicParameters<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::scalar::PublicParameters,
        >,
        HashMap<PartyID, SecretKeyShareSizedInteger>,
    ) {
        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let (session_id, private_inputs, upcoming_decryption_keys, public_inputs) =
            setup_reconfig_secp256k1(
                current_access_structure,
                upcoming_access_structure,
                current_tangible_party_id_to_upcoming,
                encryption_scheme_public_parameters,
                decryption_key,
                decryption_key_share_public_parameters,
                decryption_key_shares,
                dkg_output,
                setup_parameters_per_crt_prime.clone(),
                use_same_keys,
            );

        let (decryption_key_share_public_parameters, decryption_key_shares) =
            reconfigures_secp256k1_internal_internal_internal(
                session_id,
                current_access_structure,
                upcoming_access_structure,
                private_inputs,
                upcoming_decryption_keys,
                public_inputs,
                bench,
            );

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

        interpolated_encryption_decryption_keys_checks_out(
            upcoming_access_structure.threshold,
            upcoming_access_structure.number_of_virtual_parties(),
            decryption_key_shares.clone(),
            decryption_key.decryption_key,
            decryption_key_share_public_parameters
                .public_verification_keys
                .clone(),
            decryption_key_share_public_parameters
                .encryption_scheme_public_parameters
                .encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        );

        (
            decryption_key,
            decryption_key_share_public_parameters,
            decryption_key_shares,
        )
    }

    pub fn reconfigures_secp256k1_internal_internal_internal(
        session_id: CommitmentSizedNumber,
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        private_inputs: HashMap<PartyID, HashMap<PartyID, SecretKeyShareSizedInteger>>,
        upcoming_decryption_keys: HashMap<
            PartyID,
            [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES],
        >,
        public_inputs: HashMap<PartyID, Secp256k1PublicInput>,
        bench: bool,
    ) -> (
        decryption_key_share::PublicParameters<
            SECP256K1_SCALAR_LIMBS,
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            secp256k1::scalar::PublicParameters,
        >,
        HashMap<PartyID, SecretKeyShareSizedInteger>,
    ) {
        let (total_time, rounds_times, public_output) =
            asynchronous_session_terminates_successfully_internal::<Secp256k1Party>(
                session_id,
                current_access_structure,
                private_inputs,
                public_inputs,
                4,
                HashMap::from([(
                    2,
                    HashSet::from_iter(
                        1..=(current_access_structure.number_of_tangible_parties() - 1)
                            .max(current_access_structure.threshold),
                    ),
                )]),
                bench,
                true,
            );

        let decryption_key_share_public_parameters = public_output
            .default_decryption_key_share_public_parameters::<secp256k1::GroupElement>(
                upcoming_access_structure,
            )
            .unwrap();

        let measurement = WallTime;
        let now = measurement.start();
        let decryption_key_shares: HashMap<_, _> = upcoming_decryption_keys
            .into_iter()
            .flat_map(|(tangible_party_id, decryption_key_per_crt_prime)| {
                public_output
                    .decrypt_decryption_key_shares::<secp256k1::GroupElement>(
                        tangible_party_id,
                        upcoming_access_structure,
                        decryption_key_per_crt_prime,
                    )
                    .unwrap()
            })
            .collect();
        let decryption_time = measurement.end(now);
        let total_time_with_decryption = measurement.add(&total_time, &decryption_time);

        let decryption_key_shares_for_tdec: HashMap<_, _> = decryption_key_shares
            .clone()
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                let decryption_key_share = Secp256k1DecryptionKeyShare::new(
                    virtual_party_id,
                    decryption_key_share,
                    &decryption_key_share_public_parameters,
                    &mut OsCsRng,
                )
                .unwrap();

                (virtual_party_id, decryption_key_share)
            })
            .collect();

        homomorphic_encryption::test_helpers::threshold_decrypts(
            upcoming_access_structure.threshold,
            1,
            decryption_key_shares_for_tdec,
            &decryption_key_share_public_parameters,
            &mut OsCsRng,
        );

        println!(
            "Secp256k1 Class-Groups Reconfiguration, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
            current_access_structure.number_of_tangible_parties(),
            current_access_structure.number_of_virtual_parties(),
            current_access_structure.threshold,
            total_time.as_millis(),
            total_time_with_decryption.as_millis(),
            rounds_times[0].as_millis(),
            rounds_times[1].as_millis(),
            rounds_times[2].as_millis(),
            rounds_times[3].as_millis(),
            decryption_time.as_millis(),
        );

        (
            decryption_key_share_public_parameters,
            decryption_key_shares,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setup_reconfig_ristretto(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        decryption_key_share_public_parameters: RistrettoDecryptionKeySharePublicParameters,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        dkg_output: dkg::PublicOutput<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        setup_parameters_per_crt_prime: [SecretKeyShareCRTPrimeSetupParameters; MAX_PRIMES],
        use_same_keys: bool,
    ) -> (
        CommitmentSizedNumber,
        HashMap<PartyID, HashMap<PartyID, SecretKeyShareSizedInteger>>,
        HashMap<PartyID, [Uint<CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS>; MAX_PRIMES]>,
        HashMap<PartyID, RistrettoPublicInput>,
    ) {
        let session_id = CommitmentSizedNumber::random(&mut OsCsRng);

        let language_public_parameters_per_crt_prime =
            construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(
                setup_parameters_per_crt_prime.each_ref(),
            )
            .unwrap();

        let (
            current_encryption_keys_per_crt_prime_and_proofs,
            upcoming_decryption_key_per_crt_prime,
            upcoming_encryption_keys_per_crt_prime_and_proofs,
        ) = if use_same_keys {
            let (_, current_encryption_keys_per_crt_prime_and_proofs) =
                construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(
                    current_access_structure,
                );

            let (
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            ) = construct_encryption_keys_and_proofs_per_crt_prime_secp256k1(
                upcoming_access_structure,
            );

            (
                current_encryption_keys_per_crt_prime_and_proofs,
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            )
        } else {
            #[cfg(not(feature = "parallel"))]
            let iter = current_access_structure
                .party_to_virtual_parties()
                .into_iter();
            #[cfg(feature = "parallel")]
            let iter = current_access_structure
                .party_to_virtual_parties()
                .into_par_iter();

            let (
                current_decryption_key_per_crt_prime,
                current_encryption_keys_per_crt_prime_and_proofs,
            ): (HashMap<_, _>, HashMap<_, _>) = iter
                .map(|(party_id, _)| {
                    let decryption_key_per_crt_prime = generate_keypairs_per_crt_prime(
                        setup_parameters_per_crt_prime.clone(),
                        &mut OsCsRng,
                    )
                    .unwrap();

                    let encryption_keys_and_proofs =
                        generate_knowledge_of_decryption_key_proofs_per_crt_prime(
                            language_public_parameters_per_crt_prime.clone(),
                            decryption_key_per_crt_prime,
                            &mut OsCsRng,
                        )
                        .unwrap();

                    (
                        (party_id, decryption_key_per_crt_prime),
                        (party_id, encryption_keys_and_proofs),
                    )
                })
                .unzip();

            #[cfg(not(feature = "parallel"))]
            let iter = upcoming_access_structure
                .party_to_virtual_parties()
                .into_iter();
            #[cfg(feature = "parallel")]
            let iter = upcoming_access_structure
                .party_to_virtual_parties()
                .into_par_iter();

            let (
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            ): (HashMap<_, _>, HashMap<_, _>) = iter
                .map(|(party_id, _)| {
                    if let Some((current, _)) = current_tangible_party_id_to_upcoming
                        .iter()
                        .find(|(_, upcoming)| **upcoming == Some(party_id))
                    {
                        (
                            (
                                party_id,
                                *current_decryption_key_per_crt_prime.get(current).unwrap(),
                            ),
                            (
                                party_id,
                                current_encryption_keys_per_crt_prime_and_proofs
                                    .get(current)
                                    .unwrap()
                                    .clone(),
                            ),
                        )
                    } else {
                        let decryption_key_per_crt_prime = generate_keypairs_per_crt_prime(
                            setup_parameters_per_crt_prime.clone(),
                            &mut OsCsRng,
                        )
                        .unwrap();

                        let encryption_keys_and_proofs =
                            generate_knowledge_of_decryption_key_proofs_per_crt_prime(
                                language_public_parameters_per_crt_prime.clone(),
                                decryption_key_per_crt_prime,
                                &mut OsCsRng,
                            )
                            .unwrap();

                        (
                            (party_id, decryption_key_per_crt_prime),
                            (party_id, encryption_keys_and_proofs),
                        )
                    }
                })
                .unzip();

            (
                current_encryption_keys_per_crt_prime_and_proofs,
                upcoming_decryption_key_per_crt_prime,
                upcoming_encryption_keys_per_crt_prime_and_proofs,
            )
        };

        let plaintext_space_public_parameters = ristretto::scalar::PublicParameters::default();

        let private_inputs = current_access_structure
            .party_to_virtual_parties()
            .keys()
            .map(|tangible_party_id| {
                let party_to_virtual_parties = current_access_structure.party_to_virtual_parties();

                let decryption_key_shares = party_to_virtual_parties
                    .get(tangible_party_id)
                    .unwrap()
                    .clone()
                    .into_iter()
                    .map(|virtual_party_id| {
                        (
                            virtual_party_id,
                            *decryption_key_shares.get(&virtual_party_id).unwrap(),
                        )
                    })
                    .collect();

                (*tangible_party_id, decryption_key_shares)
            })
            .collect();

        let public_input = PublicInput::new::<ristretto::GroupElement>(
            current_access_structure,
            upcoming_access_structure.clone(),
            plaintext_space_public_parameters.clone(),
            current_encryption_keys_per_crt_prime_and_proofs.clone(),
            upcoming_encryption_keys_per_crt_prime_and_proofs.clone(),
            decryption_key_share_public_parameters.clone(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            current_tangible_party_id_to_upcoming.clone(),
            dkg_output.clone(),
        )
        .unwrap();

        let public_inputs: HashMap<_, _> = (1..=current_access_structure
            .number_of_tangible_parties())
            .map(|party_id| (party_id, public_input.clone()))
            .collect();

        (
            session_id,
            private_inputs,
            upcoming_decryption_key_per_crt_prime,
            public_inputs,
        )
    }

    pub fn reconfigures_ristretto_internal(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        use_same_keys: bool,
        bench: bool,
    ) -> (
        RistrettoDecryptionKey,
        dkg::PublicOutput<
            RISTRETTO_SCALAR_LIMBS,
            CRT_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        decryption_key_share::PublicParameters<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::scalar::PublicParameters,
        >,
        HashMap<PartyID, SecretKeyShareSizedInteger>,
    ) {
        let plaintext_space_public_parameters = ristretto::scalar::PublicParameters::default();

        let setup_parameters = SetupParameters::<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<ristretto::Scalar>,
        >::derive_from_plaintext_parameters::<ristretto::Scalar>(
            plaintext_space_public_parameters.clone(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
        .unwrap();

        let (encryption_scheme_public_parameters, decryption_key) =
            RistrettoDecryptionKey::generate_with_setup_parameters(
                setup_parameters.clone(),
                &mut OsCsRng,
            )
            .unwrap();

        let (decryption_key_share_public_parameters, decryption_key_shares) = deal_trusted_shares::<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::GroupElement,
        >(
            current_access_structure.threshold,
            current_access_structure.number_of_virtual_parties(),
            encryption_scheme_public_parameters.clone(),
            decryption_key.decryption_key,
            setup_parameters.h,
            setup_parameters.decryption_key_bits(),
        );

        let dkg_output = mock_dkg_output::<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::GroupElement,
        >(
            decryption_key.decryption_key,
            decryption_key_share_public_parameters.clone(),
        );

        let (decryption_key, decryption_key_share_public_parameters, decryption_key_shares) =
            reconfigures_ristretto_internal_internal(
                current_access_structure,
                upcoming_access_structure,
                current_tangible_party_id_to_upcoming,
                decryption_key,
                decryption_key_share_public_parameters,
                decryption_key_shares,
                dkg_output.clone(),
                use_same_keys,
                bench,
            );

        (
            decryption_key,
            dkg_output,
            decryption_key_share_public_parameters,
            decryption_key_shares,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reconfigures_ristretto_internal_internal(
        current_access_structure: &WeightedThresholdAccessStructure,
        upcoming_access_structure: &WeightedThresholdAccessStructure,
        current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>>,
        decryption_key: RistrettoDecryptionKey,
        decryption_key_share_public_parameters: RistrettoDecryptionKeySharePublicParameters,
        decryption_key_shares: HashMap<PartyID, SecretKeyShareSizedInteger>,
        dkg_output: dkg::PublicOutput<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
        use_same_keys: bool,
        bench: bool,
    ) -> (
        RistrettoDecryptionKey,
        decryption_key_share::PublicParameters<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ristretto::scalar::PublicParameters,
        >,
        HashMap<PartyID, SecretKeyShareSizedInteger>,
    ) {
        let setup_parameters_per_crt_prime =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();

        let (session_id, private_inputs, upcoming_decryption_keys, public_inputs) =
            setup_reconfig_ristretto(
                current_access_structure,
                upcoming_access_structure,
                current_tangible_party_id_to_upcoming,
                decryption_key_share_public_parameters,
                decryption_key_shares,
                dkg_output,
                setup_parameters_per_crt_prime.clone(),
                use_same_keys,
            );

        let (total_time, rounds_times, public_output) =
            asynchronous_session_terminates_successfully_internal::<RistrettoParty>(
                session_id,
                current_access_structure,
                private_inputs,
                public_inputs,
                4,
                HashMap::from([(
                    2,
                    HashSet::from_iter(
                        1..=(current_access_structure.number_of_tangible_parties() - 1)
                            .max(current_access_structure.threshold),
                    ),
                )]),
                bench,
                false,
            );

        let decryption_key_share_public_parameters = public_output
            .default_decryption_key_share_public_parameters::<ristretto::GroupElement>(
                upcoming_access_structure,
            )
            .unwrap();

        let measurement = WallTime;
        let now = measurement.start();
        let decryption_key_shares: HashMap<_, _> = upcoming_decryption_keys
            .clone()
            .into_iter()
            .flat_map(|(tangible_party_id, decryption_key_per_crt_prime)| {
                public_output
                    .decrypt_decryption_key_shares::<ristretto::GroupElement>(
                        tangible_party_id,
                        upcoming_access_structure,
                        decryption_key_per_crt_prime,
                    )
                    .unwrap()
            })
            .collect();
        let decryption_time = measurement.end(now);
        let total_time_with_decryption = measurement.add(&total_time, &decryption_time);

        let plaintext_space_public_parameters =
            group::ristretto::scalar::PublicParameters::default();
        let setup_parameters = SetupParameters::<
            RISTRETTO_SCALAR_LIMBS,
            RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<ristretto::Scalar>,
        >::derive_from_plaintext_parameters::<ristretto::Scalar>(
            plaintext_space_public_parameters.clone(),
            DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        )
        .unwrap();

        interpolated_encryption_decryption_keys_checks_out(
            upcoming_access_structure.threshold,
            upcoming_access_structure.number_of_virtual_parties(),
            decryption_key_shares.clone(),
            decryption_key.decryption_key,
            decryption_key_share_public_parameters
                .public_verification_keys
                .clone(),
            decryption_key_share_public_parameters
                .encryption_scheme_public_parameters
                .encryption_key,
            setup_parameters.equivalence_class_public_parameters(),
        );

        let decryption_key_shares_for_tdec: HashMap<_, _> = decryption_key_shares
            .clone()
            .into_iter()
            .map(|(virtual_party_id, decryption_key_share)| {
                let decryption_key_share = RistrettoDecryptionKeyShare::new(
                    virtual_party_id,
                    decryption_key_share,
                    &decryption_key_share_public_parameters,
                    &mut OsCsRng,
                )
                .unwrap();

                (virtual_party_id, decryption_key_share)
            })
            .collect();

        homomorphic_encryption::test_helpers::threshold_decrypts(
            upcoming_access_structure.threshold,
            1,
            decryption_key_shares_for_tdec,
            &decryption_key_share_public_parameters,
            &mut OsCsRng,
        );

        println!(
            "Ristretto Class-Groups Reconfiguration, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
            current_access_structure.number_of_tangible_parties(),
            current_access_structure.number_of_virtual_parties(),
            current_access_structure.threshold,
            total_time.as_millis(),
            total_time_with_decryption.as_millis(),
            rounds_times[0].as_millis(),
            rounds_times[1].as_millis(),
            rounds_times[2].as_millis(),
            rounds_times[3].as_millis(),
            decryption_time.as_millis(),
        );

        (
            decryption_key,
            decryption_key_share_public_parameters,
            decryption_key_shares,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mpc::WeightedThresholdAccessStructure;

    use super::test_helpers::*;

    #[test]
    fn reconfigures_secp256k1() {
        let threshold = 4;
        let current_party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);
        let upcoming_party_to_weight = HashMap::from([(1, 1), (2, 2), (3, 2)]);

        let current_access_structure =
            WeightedThresholdAccessStructure::new(threshold, current_party_to_weight).unwrap();

        let upcoming_access_structure =
            WeightedThresholdAccessStructure::new(threshold, upcoming_party_to_weight).unwrap();

        let current_tangible_party_id_to_upcoming =
            HashMap::from([(1, Some(2)), (2, None), (3, Some(3))]);

        reconfigures_secp256k1_internal(
            &current_access_structure,
            &upcoming_access_structure,
            current_tangible_party_id_to_upcoming,
            true,
            false,
        );
    }

    #[test]
    fn reconfigures_ristretto() {
        let current_party_to_weight = HashMap::from([(1, 2), (2, 2), (3, 2)]);
        let upcoming_party_to_weight = HashMap::from([(1, 2), (2, 3)]);

        let current_access_structure =
            WeightedThresholdAccessStructure::new(4, current_party_to_weight).unwrap();

        let upcoming_access_structure =
            WeightedThresholdAccessStructure::new(3, upcoming_party_to_weight).unwrap();

        let current_tangible_party_id_to_upcoming =
            HashMap::from([(1, None), (2, None), (3, Some(1))]);

        reconfigures_ristretto_internal(
            &current_access_structure,
            &upcoming_access_structure,
            current_tangible_party_id_to_upcoming,
            true,
            false,
        );
    }

    #[test]
    fn reconfigures_reconfigures_secp256k1() {
        let current_party_to_weight = HashMap::from([(1, 2), (2, 1), (3, 3)]);
        let upcoming_party_to_weight = HashMap::from([(1, 1), (2, 1), (3, 2), (4, 2), (5, 1)]);
        let upcoming2_party_to_weight = HashMap::from([(1, 1), (2, 2), (3, 1)]);

        let current_access_structure =
            WeightedThresholdAccessStructure::new(4, current_party_to_weight).unwrap();

        let upcoming_access_structure =
            WeightedThresholdAccessStructure::new(5, upcoming_party_to_weight).unwrap();

        let upcoming2_access_structure =
            WeightedThresholdAccessStructure::new(4, upcoming2_party_to_weight).unwrap();

        let current_tangible_party_id_to_upcoming =
            HashMap::from([(1, Some(2)), (2, None), (3, Some(3))]);

        let upcoming_tangible_party_id_to_upcoming2 =
            HashMap::from([(1, Some(1)), (2, None), (3, None), (4, Some(2)), (5, None)]);

        let (
            decryption_key,
            dkg_output,
            decryption_key_share_public_parameters,
            decryption_key_shares,
        ) = reconfigures_secp256k1_internal(
            &current_access_structure,
            &upcoming_access_structure,
            current_tangible_party_id_to_upcoming,
            false,
            false,
        );

        reconfigures_secp256k1_internal_internal(
            &upcoming_access_structure,
            &upcoming2_access_structure,
            upcoming_tangible_party_id_to_upcoming2,
            decryption_key_share_public_parameters
                .encryption_scheme_public_parameters
                .clone(),
            decryption_key,
            decryption_key_share_public_parameters,
            decryption_key_shares,
            dkg_output,
            false,
            false,
        );
    }

    #[test]
    fn reconfigures_reconfigures_ristretto() {
        let current_party_to_weight = HashMap::from([(1, 1), (2, 1), (3, 2)]);
        let upcoming_party_to_weight = HashMap::from([(1, 2), (2, 2), (3, 2), (4, 1)]);
        let upcoming2_party_to_weight = HashMap::from([(1, 2), (2, 1)]);

        let current_access_structure =
            WeightedThresholdAccessStructure::new(2, current_party_to_weight).unwrap();

        let upcoming_access_structure =
            WeightedThresholdAccessStructure::new(6, upcoming_party_to_weight).unwrap();

        let upcoming2_access_structure =
            WeightedThresholdAccessStructure::new(3, upcoming2_party_to_weight).unwrap();

        let current_tangible_party_id_to_upcoming =
            HashMap::from([(1, Some(2)), (2, None), (3, Some(3))]);

        let upcoming_tangible_party_id_to_upcoming2 =
            HashMap::from([(1, None), (2, None), (3, Some(1)), (4, None)]);

        let (
            decryption_key,
            dkg_output,
            decryption_key_share_public_parameters,
            decryption_key_shares,
        ) = reconfigures_ristretto_internal(
            &current_access_structure,
            &upcoming_access_structure,
            current_tangible_party_id_to_upcoming,
            true,
            false,
        );

        reconfigures_ristretto_internal_internal(
            &upcoming_access_structure,
            &upcoming2_access_structure,
            upcoming_tangible_party_id_to_upcoming2,
            decryption_key,
            decryption_key_share_public_parameters,
            decryption_key_shares,
            dkg_output,
            true,
            false,
        );
    }
}

#[cfg(all(test, feature = "benchmarking"))]
#[allow(clippy::single_element_loop)]
mod benches {
    use std::collections::HashMap;

    use group::{OsCsRng, PartyID};
    use mpc::WeightedThresholdAccessStructure;

    #[test]
    #[ignore]
    fn benchmark() {
        println!("\nProtocol, Number of Tangible Parties, Number of Virtual Parties, Threshold, Total Time (ms), Total Time With Decryption (ms), First Round (ms), Second Round (ms), Third Round (ms), Fourth Round (ms), Decryption (ms)");
        for (threshold, number_of_tangible_parties, total_weight) in [(67, 100, 100)] {
            let current_access_structure = WeightedThresholdAccessStructure::uniform(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            let upcoming_access_structure = WeightedThresholdAccessStructure::random(
                threshold,
                number_of_tangible_parties,
                total_weight,
                &mut OsCsRng,
            )
            .unwrap();

            let current_tangible_party_id_to_upcoming: HashMap<PartyID, Option<PartyID>> =
                current_access_structure
                    .party_to_weight
                    .keys()
                    .map(|&current_party_id| {
                        if current_party_id < number_of_tangible_parties {
                            (current_party_id, Some(current_party_id + 1))
                        } else {
                            (current_party_id, None)
                        }
                    })
                    .collect();

            super::test_helpers::reconfigures_secp256k1_internal(
                &current_access_structure,
                &upcoming_access_structure,
                current_tangible_party_id_to_upcoming.clone(),
                true,
                true,
            );
        }
    }
}
