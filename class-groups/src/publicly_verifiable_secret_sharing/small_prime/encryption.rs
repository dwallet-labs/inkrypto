// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! PVSS Encryption Key Generation
//!
//! Generates encryption/decryption keypairs with proofs for PVSS share encryption.
//! Unlike threshold decryption keys (which use CRT in reconfiguration), these are single-curve keys
//! used by each party to encrypt/decrypt their PVSS shares in the threshold encryption to sharing protocol.
//!
//! # Protocol Reference
//!
//! Based on Protocol C.6 from https://eprint.iacr.org/2025/297.pdf
//!
//! Each party $B_i$ generates:
//! - Decryption key: $\textsf{sk}_i \leftarrow \mathbb{Z}_q$
//! - Encryption key: $\textsf{pk}_i = \bar{g}^{\textsf{sk}_i}$ where $\bar{g}$ is the generator
//! - Proof $\pi_i$: UC-secure Fischlin proof of knowledge of $\textsf{sk}_i$
//!   $$\pi_i \leftarrow \Pi_{\textsf{zk-uc}}^{L_{\textsf{DL}}[\mathbb{G}/\mathbb{H}, \bar{g}, \mathbb{Z}]}(\textsf{pk}_i; \textsf{sk}_i)$$

use std::marker::PhantomData;

use crypto_bigint::{Encoding, Int, Uint};

use group::{bounded_natural_numbers_group, CsRng, GroupElement, PrimeGroupElement};
use maurer::{knowledge_of_discrete_log, UC_PROOFS_REPETITIONS};
use proof::GroupsPublicParametersAccessors;

use crate::accelerator::MultiFoldNupowAccelerator;
use crate::equivalence_class::EquivalenceClassOps;
use crate::setup::SetupParameters;
use crate::{equivalence_class, CompactIbqf, DecryptionKey, EquivalenceClass, Result};

/// Knowledge of discrete log UC-secure Fischlin proof for PVSS encryption keys.
///
/// Proves knowledge of the discrete logarithm: $\pi \leftarrow \Pi_{\textsf{zk-uc}}^{L_{\textsf{DL}}}(\textsf{pk}; \textsf{sk})$
/// where $\textsf{pk} = \bar{g}^{\textsf{sk}}$.
pub type KnowledgeOfDecryptionKeyUCProof<
    const DECRYPTION_KEY_WITNESS_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = maurer::fischlin::Proof<
    UC_PROOFS_REPETITIONS,
    knowledge_of_discrete_log::FischlinLanguage<
        UC_PROOFS_REPETITIONS,
        bounded_natural_numbers_group::GroupElement<DECRYPTION_KEY_WITNESS_LIMBS>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    PhantomData<()>,
>;

/// Public parameters for PVSS encryption key proof.
pub type KnowledgeOfDecryptionKeyUCProofPublicParameters<
    const DECRYPTION_KEY_WITNESS_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
> = knowledge_of_discrete_log::PublicParameters<
    bounded_natural_numbers_group::PublicParameters<DECRYPTION_KEY_WITNESS_LIMBS>,
    equivalence_class::PublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
>;

/// Generates a PVSS encryption/decryption keypair with proof for a single curve.
///
/// # Mathematical Description
///
/// Generates:
/// 1. Decryption key: $\textsf{sk} \sample \mathbb{Z}_{\Delta}$ where $\Delta$ is the discriminant
/// 2. Encryption key: $\textsf{pk} = \bar{g}^{\textsf{sk}}$
/// 3. Proof: $\pi \leftarrow \Pi_{\textsf{zk-uc}}^{L_{\textsf{DL}}}(\textsf{pk}; \textsf{sk})$
///
/// # Arguments
///
/// * `setup_parameters` - Setup parameters for the curve (contains $\bar{g}$, $\Delta$, etc.)
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
///
/// A tuple of:
/// - $\textsf{pk}$: Encryption key (public key value)
/// - $\pi$: Knowledge of discrete log proof
/// - $\textsf{sk}$: Decryption key (secret)
///
/// # Example
///
/// ```ignore
/// use class_groups::*;
/// use group::secp256k1;
///
/// let setup_parameters = Secp256k1SetupParameters::derive_from_plaintext_parameters(
///     secp256k1::scalar::PublicParameters::default(),
///     DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
/// )?;
///
/// let (pk, proof, sk) = generate_pvss_encryption_keypair::<
///     { secp256k1::SCALAR_LIMBS },
///     _,
///     _,
///     _,
///     secp256k1::GroupElement,
/// >(&setup_parameters, &mut rng)?;
/// ```
pub fn generate_and_prove_encryption_keypair<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DECRYPTION_KEY_WITNESS_LIMBS: usize,
    PlaintextSpaceGroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    setup_parameters: &SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<PlaintextSpaceGroupElement::Scalar>,
    >,
    rng: &mut impl CsRng,
) -> Result<(
    CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    KnowledgeOfDecryptionKeyUCProof<
        DECRYPTION_KEY_WITNESS_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
)>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + crypto_bigint::InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        crypto_bigint::Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + crypto_bigint::Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + crypto_bigint::Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        crypto_bigint::Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

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
{
    // Step 1: Generate decryption key sk ← Z_Δ
    let (encryption_scheme_public_parameters, decryption_key) =
        DecryptionKey::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            PlaintextSpaceGroupElement,
        >::generate_with_setup_parameters(setup_parameters.clone(), rng)?;

    let decryption_key = decryption_key.decryption_key;

    // Step 2: Construct proof public parameters
    let language_public_parameters = construct_knowledge_of_decryption_key_uc_public_parameters::<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        DECRYPTION_KEY_WITNESS_LIMBS,
        PlaintextSpaceGroupElement,
    >(setup_parameters)?;

    // Step 3: Prepare witness for proof: convert sk to group element
    let decryption_key_witness = bounded_natural_numbers_group::GroupElement::new(
        Uint::from(&decryption_key),
        language_public_parameters.witness_space_public_parameters(),
    )?;

    // Step 4: Generate proof π ← Π_zk-uc^L_DL(pk; sk)
    let (proof, _) = KnowledgeOfDecryptionKeyUCProof::<
        DECRYPTION_KEY_WITNESS_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >::prove(
        &PhantomData,
        &language_public_parameters,
        decryption_key_witness,
        rng,
    )?;

    Ok((
        encryption_scheme_public_parameters.encryption_key.value(),
        proof,
        decryption_key,
    ))
}

/// Constructs public parameters for PVSS encryption key proof.
///
/// Creates the language public parameters for $L_{\textsf{DL}}[\mathbb{G}/\mathbb{H}, \bar{g}, \mathbb{Z}]$
///
/// # Arguments
///
/// * `setup_parameters` - Setup parameters containing $\bar{g}$ and group structure
///
/// # Returns
///
/// Public parameters for the knowledge of discrete log proof
pub fn construct_knowledge_of_decryption_key_uc_public_parameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DECRYPTION_KEY_WITNESS_LIMBS: usize,
    PlaintextSpaceGroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    setup_parameters: &SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<PlaintextSpaceGroupElement::Scalar>,
    >,
) -> Result<
    KnowledgeOfDecryptionKeyUCProofPublicParameters<
        DECRYPTION_KEY_WITNESS_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + crypto_bigint::InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

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
{
    let decryption_key_bits = setup_parameters.decryption_key_bits();

    // Create witness space public parameters (for Z with appropriate bounds)
    let witness_group_public_parameters = bounded_natural_numbers_group::PublicParameters::<
        DECRYPTION_KEY_WITNESS_LIMBS,
    >::new_with_randomizer_upper_bound(
        decryption_key_bits
    )?;

    let discrete_log_sample_bits = Some(witness_group_public_parameters.sample_bits);

    // Create language public parameters for L_DL[G/H, ḡ, Z]
    let language_public_parameters = knowledge_of_discrete_log::PublicParameters::new::<
        bounded_natural_numbers_group::GroupElement<DECRYPTION_KEY_WITNESS_LIMBS>,
        EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >(
        witness_group_public_parameters,
        setup_parameters
            .equivalence_class_public_parameters()
            .clone(),
        setup_parameters.h.value(), // ḡ (generator)
        discrete_log_sample_bits,
    );

    Ok(language_public_parameters)
}

/// Verifies a PVSS encryption key proof.
///
/// Verifies that the proof $\pi$ demonstrates knowledge of $\textsf{sk}$ such that $\textsf{pk} = \bar{g}^{\textsf{sk}}$.
///
/// # Arguments
///
/// * `encryption_key` - The encryption key $\textsf{pk}$ to verify
/// * `proof` - The proof $\pi$ of knowledge of discrete log
/// * `setup_parameters` - Setup parameters (contains $\bar{g}$)
///
/// # Returns
///
/// `Ok(())` if the proof is valid, `Err` otherwise
/// INSECURE mock twin (feature `unsafe_mock`): accepts the (neutral) encryption
/// key without verifying its knowledge-of-decryption-key UC proof. The mock
/// produces default proofs (see cryptography-private `unsafe_mock`) that real
/// verification would reject. The production definition below is left untouched.
#[cfg(feature = "unsafe_mock")]
pub fn verify_knowledge_of_decryption_key_uc_proof<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DECRYPTION_KEY_WITNESS_LIMBS: usize,
    PlaintextSpaceGroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    proof: &KnowledgeOfDecryptionKeyUCProof<
        DECRYPTION_KEY_WITNESS_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    setup_parameters: &SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<PlaintextSpaceGroupElement::Scalar>,
    >,
) -> Result<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + crypto_bigint::InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

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
{
    let _ = (proof, setup_parameters);
    Ok(encryption_key)
}

#[cfg(not(feature = "unsafe_mock"))]
pub fn verify_knowledge_of_decryption_key_uc_proof<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const DECRYPTION_KEY_WITNESS_LIMBS: usize,
    PlaintextSpaceGroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    encryption_key: EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    proof: &KnowledgeOfDecryptionKeyUCProof<
        DECRYPTION_KEY_WITNESS_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
    setup_parameters: &SetupParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<PlaintextSpaceGroupElement::Scalar>,
    >,
) -> Result<EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + crypto_bigint::InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

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
{
    let language_public_parameters = construct_knowledge_of_decryption_key_uc_public_parameters::<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        DECRYPTION_KEY_WITNESS_LIMBS,
        PlaintextSpaceGroupElement,
    >(setup_parameters)?;

    proof.verify(&PhantomData, &language_public_parameters, encryption_key)?;

    Ok(encryption_key)
}

/// Type alias for encryption key and proof pair.
pub type EncryptionKeyAndProof<const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize> = (
    CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    KnowledgeOfDecryptionKeyUCProof<
        CRT_DECRYPTION_KEY_WITNESS_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
);

use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publicly_verifiable_secret_sharing::chinese_remainder_theorem::CRT_DECRYPTION_KEY_WITNESS_LIMBS;
    use crate::setup::DeriveFromPlaintextPublicParameters;
    use crate::{
        Secp256k1SetupParameters, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };
    use crypto_bigint::{U1024, U4096};
    use group::secp256k1;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_generate_and_verify_pvss_encryption_keypair_secp256k1() {
        let mut rng = ChaChaRng::seed_from_u64(123456789u64);

        let setup_parameters =
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        let (encryption_key_value, proof, _decryption_key) =
            generate_and_prove_encryption_keypair::<
                { secp256k1::SCALAR_LIMBS },
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                { U1024::LIMBS },
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                { U4096::LIMBS },
                CRT_DECRYPTION_KEY_WITNESS_LIMBS,
                secp256k1::GroupElement,
            >(&setup_parameters, &mut rng)
            .unwrap();

        // Construct EquivalenceClass from the CompactIbqf value
        let encryption_key = EquivalenceClass::new(
            encryption_key_value,
            setup_parameters.equivalence_class_public_parameters(),
        )
        .unwrap();

        // Verify the proof (doesn't need HALF/DOUBLE)
        verify_knowledge_of_decryption_key_uc_proof::<
            { secp256k1::SCALAR_LIMBS },
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            CRT_DECRYPTION_KEY_WITNESS_LIMBS,
            secp256k1::GroupElement,
        >(encryption_key, &proof, &setup_parameters)
        .unwrap();
    }

    #[test]
    fn test_invalid_proof_fails_verification_secp256k1() {
        let mut rng = ChaChaRng::seed_from_u64(123456789u64);

        let setup_parameters =
            Secp256k1SetupParameters::derive_from_plaintext_parameters::<secp256k1::Scalar>(
                secp256k1::scalar::PublicParameters::default(),
                DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
            )
            .unwrap();

        // Generate first keypair
        let (encryption_key_first_value, _proof_first, _decryption_key_first) =
            generate_and_prove_encryption_keypair::<
                { secp256k1::SCALAR_LIMBS },
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                { U1024::LIMBS },
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                { U4096::LIMBS },
                CRT_DECRYPTION_KEY_WITNESS_LIMBS,
                secp256k1::GroupElement,
            >(&setup_parameters, &mut rng)
            .unwrap();

        // Generate second keypair
        let (_encryption_key_second, proof_second, _decryption_key_second) =
            generate_and_prove_encryption_keypair::<
                { secp256k1::SCALAR_LIMBS },
                SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                { U1024::LIMBS },
                SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                { U4096::LIMBS },
                CRT_DECRYPTION_KEY_WITNESS_LIMBS,
                secp256k1::GroupElement,
            >(&setup_parameters, &mut rng)
            .unwrap();

        // Construct EquivalenceClass from the CompactIbqf value
        let encryption_key_first = EquivalenceClass::new(
            encryption_key_first_value,
            setup_parameters.equivalence_class_public_parameters(),
        )
        .unwrap();

        // Try to verify first key with second proof (should fail, doesn't need HALF/DOUBLE)
        let result = verify_knowledge_of_decryption_key_uc_proof::<
            { secp256k1::SCALAR_LIMBS },
            SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            CRT_DECRYPTION_KEY_WITNESS_LIMBS,
            secp256k1::GroupElement,
        >(encryption_key_first, &proof_second, &setup_parameters);

        assert!(result.is_err());
    }
}
