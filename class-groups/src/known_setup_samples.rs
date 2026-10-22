// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! The sampled inputs of every production setup parameter set, recorded as constants.
//!
//! A setup parameter set is a deterministic function of the plaintext-space order $q$, the
//! computational security parameter, and two sampled primes: $p$ with $\Delta_k = -pq$, and the
//! Kronecker prime $\ell$ whose prime form generates $h$. Everything else (the discriminants,
//! $h$ itself, the accelerator tables, the sampling bounds) is computed from those.
//!
//! Historically the two primes were sampled from a ChaCha20 RNG seeded with SHA3-256 of $q$.
//! That made every public parameter depend on the exact RNG consumption of the sampling code
//! in crypto-bigint and crypto-primes, which upstream does not keep stable. The values below
//! were captured from that historical derivation and are now the only source for these
//! parameter sets: a recorded set is never re-sampled, so changing a sampler cannot change a
//! production discriminant or generator. Plaintext spaces without a record still fall back to
//! the seeded derivation, which lives in `setup` and is private to it. The tests in `setup`
//! check every recorded set against that derivation and pin its serialization.

use crypto_bigint::{Limb, NonZero, Uint};

/// The sampled inputs of one setup parameter set. Every value is big-endian hex at the exact
/// width of the integer type it is parsed into, as `Uint::from_be_hex` requires.
pub(crate) struct KnownSetupSample {
    /// The plaintext-space order $q$.
    plaintext_space_order: &'static str,
    computational_security_parameter: u32,
    /// The prime $p$ with $\Delta_k = -pq$.
    p: &'static str,
    /// The prime $\ell$ whose prime form generates $h$.
    h_kronecker_prime: &'static str,
}

/// Captured from the seeded derivation at commit `0d5046df` (crypto-bigint fork `8aabcee5`,
/// crypto-primes 0.7.0-pre.3) with `DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER`, by
/// `setup::tests::print_historical_samples`.
pub(crate) const KNOWN_SETUP_SAMPLES: &[KnownSetupSample] = &[
    // secp256k1
    KnownSetupSample {
        plaintext_space_order: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        computational_security_parameter: 112,
        p: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d2bb1f3c5dc9f51f383756e9d0464477fe01b325da603a754b2037b5303a9a0082494478c471c6975804cc0e754918f43a265eff1ab83af22bc037aef7fcc34c558e38f9230cb58ec29d42226c7466bad7490746db9c6492cce819f4cad8a0d07d84c9bc42eac0af0f6efb6866f87c6d56b262215c3def83da9e3ca0bb069f4ce9f7c80f523264cdf",
        h_kronecker_prime: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080d2bc611639eaaf6d7385877bdefcbb",
    },
    // secp256r1
    KnownSetupSample {
        plaintext_space_order: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        computational_security_parameter: 112,
        p: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f1018352cb58ea10aa8e73144e8eae197d442de9c8439079e157a6000c2330e08bfcae67e0b0b68d46d8bab33372429791e9ea668f444c3fe1bbdc05b7b545e210f6807b4da7f786d8f55ebfce4aa6034d166210ad8e4ba9f4fbbca3ce82f91dd642baba6af7bddebd7b65f7f9f4e4856af82347fe02b6fdca7c80e4948fa3fbcc3ddc35d274bde07",
        h_kronecker_prime: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f649aafc2e75194085536518dddadbd9",
    },
    // ristretto and curve25519 (same scalar field)
    KnownSetupSample {
        plaintext_space_order: "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        computational_security_parameter: 112,
        p: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004af663eeabd09dfd506a9953372b3425c4dfbcd5166c42795feaf08717409b37c2e21cc02d79d15c181159239a9b9032353155272a35d0b5621cd541709f9915269c1b7a1fdc599628018b88a7d721108901a7bda787d82b9ed82cfff1f55496b7fcd3fbbb31eddb2739032a260ff6f65a92e13595f26aa171f6ab11640a0c612244977f2b647758e7",
        h_kronecker_prime: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e0a1e58735461ac15e83a8ad04f8b0b5",
    },
    // CRT prime 0
    KnownSetupSample {
        plaintext_space_order: "ac30997be3c3c4a6d232fdd789c1f1e1f709ae3aa916f644b8b6d955935e2ef467c176db0d447fdfe096bb6070606038bcc1994d5eddd82204cd1e88ccbc1a63556fad90a4b7de80bbab0690c2d1621d",
        computational_security_parameter: 112,
        p: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bd43b7b81836e4e9ae53afab10ca7cb87f97f426b1d6be74ac85f3a607d211701e5dc464535db51a9446558db988547dcad3b752b256f4c7f98ed098a91b52d9718f09ef987aa07dd242f38602c506301193305406dfc1da7",
        h_kronecker_prime: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac16364e9ab2f1c9b5ce90ee4749e933",
    },
    // CRT prime 1
    KnownSetupSample {
        plaintext_space_order: "8e79988e730d9886e2bddd9b43d48ad80f1dc6fc691650b7858aac148ce2330ddeafac85ecf1ead7406949b00bd636e744b6b25191089bef9240cbb5ff09921009a801f014762109eb05427eec2d2ceb",
        computational_security_parameter: 112,
        p: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d6ea8b9ac7460b03a821a4166f661b7ad6d9060fc50f6f3fc868b9b5adf89a149ab3545a065ac915d2660eda102906d099d24ec376c6bfa842c95c0c066fd6c74b432c55bccb538e14f1fc3c8eaf141e79a9879df5dfe3281",
        h_kronecker_prime: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000aa50bce6a670fc31576314088b9760db",
    },
    // CRT prime 2
    KnownSetupSample {
        plaintext_space_order: "88ac82347e3fca10b42cb276819ebcf70927efdd8519df7ea071bec241bb482c07edfde55818208928e4e501259094060ea847fd20f02df1150129f077566edbf5274d83e3f070efd14cb1a3f1fcccd9",
        computational_security_parameter: 112,
        p: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000da15e369bc0df82849e5dfef6c84209ba623d54fc1d2e31cf904c0f6dc60c2f51f359e8134c793b79ad9a03c146187be7c45220bbdd9e89a0581c645d5baa779b0f9c0f375b74fff52049d55084e58d7e18ad1798cd597797",
        h_kronecker_prime: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008dfea9be8719d88804d35c3ef55a1767",
    },
];

/// Look up the recorded primes for the plaintext-space order `q` at the given security
/// parameter. Returns `None` if this plaintext space has no recorded sample.
///
/// A row belongs to the caller's parameter widths exactly when its hex strings have the
/// widths of the caller's integer types; rows of other widths are skipped by that check.
pub(crate) fn find<const Q_LIMBS: usize, const P_LIMBS: usize, const H_PRIME_LIMBS: usize>(
    q: &Uint<Q_LIMBS>,
    computational_security_parameter: u32,
) -> Option<(NonZero<Uint<P_LIMBS>>, NonZero<Uint<H_PRIME_LIMBS>>)> {
    KNOWN_SETUP_SAMPLES
        .iter()
        .filter(|sample| {
            sample.computational_security_parameter == computational_security_parameter
        })
        .filter(|sample| {
            sample.plaintext_space_order.len() == hex_width::<Q_LIMBS>()
                && sample.p.len() == hex_width::<P_LIMBS>()
                && sample.h_kronecker_prime.len() == hex_width::<H_PRIME_LIMBS>()
        })
        .find(|sample| Uint::<Q_LIMBS>::from_be_hex(sample.plaintext_space_order) == *q)
        .map(|sample| {
            let p = NonZero::new(Uint::<P_LIMBS>::from_be_hex(sample.p))
                .expect("a recorded prime is non-zero");
            let h_kronecker_prime =
                NonZero::new(Uint::<H_PRIME_LIMBS>::from_be_hex(sample.h_kronecker_prime))
                    .expect("a recorded prime is non-zero");

            (p, h_kronecker_prime)
        })
}

/// The number of hex characters `Uint::<LIMBS>::from_be_hex` expects.
const fn hex_width<const LIMBS: usize>() -> usize {
    LIMBS * Limb::BYTES * 2
}
