// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! INSECURE (feature `unsafe_mock`) embedded mock-keygen fixtures.
//!
//! The mock keygen returns neutral encryption keys + `new_default` proofs. Those
//! values are process-independent constants, but *deriving* them requires the
//! class-group setup parameters (a discriminant prime search + accelerator
//! tables) — several seconds. Downstream (ika) calls the mock keygen on a latency-
//! sensitive path (a mid-epoch joiner must publish its key material inside the
//! committee-freeze window), so instead of deriving on every call, the fixtures
//! are computed once and their BCS bytes embedded here; the mock keygen just
//! decodes them (microseconds), with no runtime derivation and no global cache.
//!
//! To regenerate after a serialization-format change, run the ignored test
//! `regenerate_fixtures` below (`cargo test -p class_groups --features
//! threshold,parallel,unsafe_mock unsafe_mock_keygen_fixtures -- --ignored`).

use super::chinese_remainder_theorem::{
    KnowledgeOfDiscreteLogUCProof, CRT_DECRYPTION_KEY_WITNESS_LIMBS,
    CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, MAX_PRIMES,
};
use super::small_prime::encryption::KnowledgeOfDecryptionKeyUCProof;
use crate::{
    CompactIbqf, Error, ErrorKind, Result, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};

/// Per-CRT-prime `(encryption_key, knowledge-of-decryption-key proof)`.
pub(crate) type CrtEncryptionKeysAndProofs = [(
    CompactIbqf<CRT_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    KnowledgeOfDiscreteLogUCProof,
); MAX_PRIMES];

/// A single curve's PVSS `(encryption_key, proof)` — the [`super::small_prime::
/// encryption::PvssKeypairAndProof`] without the (constant) decryption key.
pub(crate) type PvssEncryptionKeyAndProof<const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize> = (
    CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    KnowledgeOfDecryptionKeyUCProof<
        { CRT_DECRYPTION_KEY_WITNESS_LIMBS },
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    >,
);

/// The three per-curve PVSS encryption keys + proofs (secp256k1, secp256r1, ristretto).
pub(crate) type PvssEncryptionKeysAndProofs = (
    PvssEncryptionKeyAndProof<{ SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    PvssEncryptionKeyAndProof<{ SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
    PvssEncryptionKeyAndProof<{ RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS }>,
);

const CRT_FIXTURE: &[u8] = include_bytes!("unsafe_mock_keygen_fixtures/crt.bcs");
const PVSS_FIXTURE: &[u8] = include_bytes!("unsafe_mock_keygen_fixtures/pvss.bcs");

/// Decode the embedded CRT class-groups encryption keys + proofs.
pub(crate) fn crt_encryption_keys_and_proofs() -> Result<CrtEncryptionKeysAndProofs> {
    bcs::from_bytes(CRT_FIXTURE).map_err(|_| Error::from(ErrorKind::InternalError))
}

/// Decode the embedded per-curve PVSS encryption keys + proofs. A fixed decryption
/// key placeholder is added back by the keygen entry points; only the (public)
/// encryption keys + proofs are embedded.
pub(crate) fn pvss_encryption_keys_and_proofs() -> Result<PvssEncryptionKeysAndProofs> {
    bcs::from_bytes(PVSS_FIXTURE).map_err(|_| Error::from(ErrorKind::InternalError))
}

#[cfg(test)]
mod regen {
    //! Regenerates the embedded fixtures. Ignored by default (it derives the
    //! class-group setup parameters, which is slow). Run manually after a
    //! serialization-format change.
    use group::GroupElement as _;
    use proof::GroupsPublicParametersAccessors as _;

    use super::super::chinese_remainder_theorem::{
        construct_knowledge_of_decryption_key_public_parameters_per_crt_prime,
        construct_setup_parameters_per_crt_prime, KnowledgeOfDiscreteLogUCProof,
        CRT_DECRYPTION_KEY_WITNESS_LIMBS,
    };
    use super::super::small_prime::encryption::derive_mock_pvss_keypair;
    use super::{CrtEncryptionKeysAndProofs, PvssEncryptionKeysAndProofs};
    use crate::{
        EquivalenceClass, DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER,
        RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS, RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS, SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    };

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/publicly_verifiable_secret_sharing/unsafe_mock_keygen_fixtures")
    }

    #[test]
    #[ignore = "regenerates committed fixtures; run manually"]
    fn regenerate_fixtures() {
        // CRT: neutral encryption key + new_default proof per prime.
        let setup =
            construct_setup_parameters_per_crt_prime(DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER)
                .unwrap();
        let language =
            construct_knowledge_of_decryption_key_public_parameters_per_crt_prime(setup.each_ref())
                .unwrap();
        let crt: CrtEncryptionKeysAndProofs = language.map(|lpp| {
            let key = EquivalenceClass::neutral_from_public_parameters(
                lpp.statement_space_public_parameters(),
            )
            .unwrap()
            .value();
            let proof = KnowledgeOfDiscreteLogUCProof::new_default(
                lpp.witness_space_public_parameters(),
                lpp.statement_space_public_parameters(),
            )
            .unwrap();
            (key, proof)
        });
        std::fs::write(fixtures_dir().join("crt.bcs"), bcs::to_bytes(&crt).unwrap()).unwrap();

        // PVSS: the per-curve mock twin already yields a neutral key + default proof.
        let (k1_key, k1_proof, _) = derive_mock_pvss_keypair::<
            { group::secp256k1::SCALAR_LIMBS },
            { SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crypto_bigint::U1024::LIMBS },
            { SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crypto_bigint::U4096::LIMBS },
            { CRT_DECRYPTION_KEY_WITNESS_LIMBS },
            group::secp256k1::GroupElement,
        >(group::secp256k1::scalar::PublicParameters::default())
        .unwrap();
        let (r1_key, r1_proof, _) = derive_mock_pvss_keypair::<
            { group::secp256r1::SCALAR_LIMBS },
            { SECP256R1_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crypto_bigint::U1024::LIMBS },
            { SECP256R1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crypto_bigint::U4096::LIMBS },
            { CRT_DECRYPTION_KEY_WITNESS_LIMBS },
            group::secp256r1::GroupElement,
        >(group::secp256r1::scalar::PublicParameters::default())
        .unwrap();
        let (ri_key, ri_proof, _) = derive_mock_pvss_keypair::<
            { group::ristretto::SCALAR_LIMBS },
            { RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crypto_bigint::U1024::LIMBS },
            { RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS },
            { crypto_bigint::U4096::LIMBS },
            { CRT_DECRYPTION_KEY_WITNESS_LIMBS },
            group::ristretto::GroupElement,
        >(group::ristretto::scalar::PublicParameters::default())
        .unwrap();
        let pvss: PvssEncryptionKeysAndProofs =
            ((k1_key, k1_proof), (r1_key, r1_proof), (ri_key, ri_proof));
        std::fs::write(
            fixtures_dir().join("pvss.bcs"),
            bcs::to_bytes(&pvss).unwrap(),
        )
        .unwrap();
    }
}
