// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::{Int, Limb, Uint, U1536, U2048, U64};

pub use accelerator::MultiFoldNupowAccelerator;
pub use decryption_key::{DecryptionKey, DiscreteLogInF};
#[cfg(feature = "threshold")]
pub use decryption_key_share::DecryptionKeyShare;
pub use encryption_key::EncryptionKey;
pub use equivalence_class::EquivalenceClass;
use group::bounded_natural_numbers_group::MAURER_PROOFS_DIFF_UPPER_BOUND_BITS;
use group::{ristretto, secp256k1, PartyID, StatisticalSecuritySizedNumber};
pub use ibqf::compact::CompactIbqf;
use mpc::secret_sharing::shamir::over_the_integers::{
    computation_decryption_key_shares_interpolation_upper_bound, find_closest_crypto_bigint_size,
    secret_key_share_size_upper_bound, MAX_PLAYERS, MAX_THRESHOLD,
};
#[allow(unused_imports)]
pub(crate) use parameters::Parameters;
#[allow(unused_imports)]
pub(crate) use setup::SetupParameters;

#[cfg(feature = "threshold")]
use crate::decryption_key_share::PartialDecryptionProof;

mod decryption_key;
mod discriminant;
pub mod encryption_key;
pub mod equivalence_class;
mod helpers;
mod ibqf;
mod parameters;
pub mod setup;

mod accelerator;
#[cfg(feature = "threshold")]
pub mod decryption_key_share;
#[cfg(feature = "threshold")]
pub mod dkg;
#[cfg(feature = "threshold")]
pub mod publicly_verifiable_secret_sharing;
mod randomizer;
#[cfg(feature = "threshold")]
pub mod reconfiguration;

pub const DEFAULT_COMPUTATIONAL_SECURITY_PARAMETER: u32 = 112;
pub const MINIMUM_FUNDAMENTAL_DISCRIMINANT_112BIT_SECURITY_BITS: u32 = 1348;
pub const MINIMUM_FUNDAMENTAL_DISCRIMINANT_128BIT_SECURITY_BITS: u32 = 1827;

/// The size of the class group is bounded from above by $log_2{Δ}/2 + log_2{log_2{Δ}}$ by the class number formula.
/// We add a statistical security parameter so the public key is indistinguishable from random.
/// One can provide better bounds via computation for a specific discriminant.
const fn decryption_key_size_from_fundamental_discriminant_size(
    minimum_fundamental_discriminant_bit_size: u32,
) -> u32 {
    minimum_fundamental_discriminant_bit_size / 2
        + StatisticalSecuritySizedNumber::BITS
        + minimum_fundamental_discriminant_bit_size.ilog2()
        + 1
}

pub const DECRYPTION_KEY_BITS_112BIT_SECURITY: u32 =
    decryption_key_size_from_fundamental_discriminant_size(
        MINIMUM_FUNDAMENTAL_DISCRIMINANT_112BIT_SECURITY_BITS,
    );

pub const DECRYPTION_KEY_BITS_128BIT_SECURITY: u32 =
    decryption_key_size_from_fundamental_discriminant_size(
        MINIMUM_FUNDAMENTAL_DISCRIMINANT_128BIT_SECURITY_BITS,
    );

/// Default number of parts a [MultiFoldNupowAccelerator] will cut an exponent into.
const DEFAULT_ACCELERATOR_FOLDING_DEGREE: u32 = 9;

/// Highest number of parts a [MultiFoldNupowAccelerator] will cut an exponent into.
const HIGHEST_ACCELERATOR_FOLDING_DEGREE: u32 = 12;

pub const RISTRETTO_SCALAR_LIMBS: usize = group::ristretto::SCALAR_LIMBS;
pub const RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U1536::LIMBS;
pub const RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U2048::LIMBS;

/// A bound on the size of a coefficient during secure evaluation.
/// The coefficients are largest when they are randomized for secure evaluation when the ciphertexts aren't trusted because no ZK-proof verified their validity of construction.
/// The largest witness is of the form $s=(\alpha+rq)$ where q is the plaintext space, $\alpha\leq q$ and $r$ is an encryption randomizers.
/// Thus, the bound on the witness is: `RISTRETTO_SCALAR_LIMBS + RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS + U64`.
///
/// When computing the response during a Maurer proof, we mask the witness multiplied by the challenge
/// and thus have to add `MAURER_PROOFS_DELTA_UPPER_BOUND_BITS`.
pub const RISTRETTO_MESSAGE_LIMBS: usize = find_closest_crypto_bigint_size(
    ((RISTRETTO_SCALAR_LIMBS + RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS + U64::LIMBS)
        * Limb::BITS as usize)
        + (MAURER_PROOFS_DIFF_UPPER_BOUND_BITS as usize),
) / Limb::BITS as usize;

pub const SECP256K1_SCALAR_LIMBS: usize = group::secp256k1::SCALAR_LIMBS;
pub const SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U1536::LIMBS;
pub const SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize = U2048::LIMBS;

/// A bound on the size of a coefficient during secure evaluation.
/// The coefficients are largest when they are randomized for secure evaluation when the ciphertexts aren't trusted because no ZK-proof verified their validity of construction.
/// The largest witness is of the form $s=(\alpha+rq)$ where q is the plaintext space, $\alpha\leq q$ and $r$ is an encryption randomizers.
/// Thus, the bound on the witness is: `SECP256K1_SCALAR_LIMBS + SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS + U64`.
///
/// When computing the response during a Maurer proof, we mask the witness multiplied by the challenge
/// and thus have to add `MAURER_PROOFS_DELTA_UPPER_BOUND_BITS`.
pub const SECP256K1_MESSAGE_LIMBS: usize = find_closest_crypto_bigint_size(
    ((SECP256K1_SCALAR_LIMBS + SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS + U64::LIMBS)
        * Limb::BITS as usize)
        + (MAURER_PROOFS_DIFF_UPPER_BOUND_BITS as usize),
) / Limb::BITS as usize;

pub type Secp256k1EncryptionSchemePublicParameters = encryption_key::PublicParameters<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::scalar::PublicParameters,
>;
pub type Secp256k1EncryptionKey = EncryptionKey<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;
pub type Secp256k1DecryptionKey = DecryptionKey<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;
#[cfg(feature = "threshold")]
pub type Secp256k1DecryptionKeyShare = DecryptionKeyShare<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::GroupElement,
>;
#[cfg(feature = "threshold")]
pub type Secp256k1DecryptionKeySharePublicParameters = decryption_key_share::PublicParameters<
    SECP256K1_SCALAR_LIMBS,
    SECP256K1_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    secp256k1::scalar::PublicParameters,
>;
#[cfg(feature = "threshold")]
pub type Secp256k1PartialDecryptionProof =
    PartialDecryptionProof<SECP256K1_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;

pub type RistrettoEncryptionSchemePublicParameters = encryption_key::PublicParameters<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::scalar::PublicParameters,
>;
pub type RistrettoEncryptionKey = EncryptionKey<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;
pub type RistrettoDecryptionKey = DecryptionKey<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;
#[cfg(feature = "threshold")]
pub type RistrettoDecryptionKeyShare = DecryptionKeyShare<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::GroupElement,
>;
#[cfg(feature = "threshold")]
pub type RistrettoDecryptionKeySharePublicParameters = decryption_key_share::PublicParameters<
    RISTRETTO_SCALAR_LIMBS,
    RISTRETTO_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    ristretto::scalar::PublicParameters,
>;
#[cfg(feature = "threshold")]
pub type RistrettoPartialDecryptionProof =
    PartialDecryptionProof<RISTRETTO_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;

pub type CiphertextSpaceGroupElement<const DISCRIMINANT_LIMBS: usize> =
    group::self_product::GroupElement<2, EquivalenceClass<DISCRIMINANT_LIMBS>>;

pub type CiphertextSpaceValue<const DISCRIMINANT_LIMBS: usize> =
    group::self_product::Value<2, CompactIbqf<DISCRIMINANT_LIMBS>>;

pub type CiphertextSpacePublicParameters<const DISCRIMINANT_LIMBS: usize> =
    group::self_product::PublicParameters<
        2,
        equivalence_class::PublicParameters<DISCRIMINANT_LIMBS>,
    >;

pub type RandomnessSpaceGroupElement<const RANDOMNESS_SPACE_LIMBS: usize> =
    group::bounded_natural_numbers_group::GroupElement<RANDOMNESS_SPACE_LIMBS>;

pub type RandomnessSpacePublicParameters<const DISCRIMINANT_LIMBS: usize> =
    group::bounded_natural_numbers_group::PublicParameters<DISCRIMINANT_LIMBS>;

pub const SECRET_KEY_SHARE_SIZE_UPPER_BOUND: u32 = secret_key_share_size_upper_bound(
    MAX_PLAYERS,
    MAX_THRESHOLD,
    DECRYPTION_KEY_BITS_112BIT_SECURITY,
);
pub const SECRET_KEY_SHARE_LIMBS: usize =
    find_closest_crypto_bigint_size(SECRET_KEY_SHARE_SIZE_UPPER_BOUND as usize)
        / Limb::BITS as usize;
pub type SecretKeyShareSizedNumber = Uint<SECRET_KEY_SHARE_LIMBS>;
pub type SecretKeyShareSizedInteger = Int<SECRET_KEY_SHARE_LIMBS>;

pub const COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_UPPER_BOUND: u32 =
    computation_decryption_key_shares_interpolation_upper_bound(
        MAX_PLAYERS,
        MAX_THRESHOLD,
        DECRYPTION_KEY_BITS_112BIT_SECURITY,
    );
pub const COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_LIMBS: usize =
    find_closest_crypto_bigint_size(
        COMPUTATION_DECRYPTION_KEY_SHARES_INTERPOLATION_UPPER_BOUND as usize,
    ) / Limb::BITS as usize;

pub const SECRET_KEY_SHARE_WITNESS_LIMBS: usize = find_closest_crypto_bigint_size(
    (SECRET_KEY_SHARE_SIZE_UPPER_BOUND + MAURER_PROOFS_DIFF_UPPER_BOUND_BITS) as usize,
) / Limb::BITS as usize;

/// Class Group Error.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("cannot combine forms that belong to a different class")]
    CombiningRequiresSameDiscriminant,
    #[error("this compact form does not match this discriminant")]
    CompactFormDiscriminantMismatch,
    #[error("computational security too high; this is not supported")]
    ComputationalSecurityTooHigh,
    #[error("cannot use forms that are not primitive")]
    FormNotPrimitive,
    #[error("this function cannot use forms that are not randomized")]
    FormNotRandomized,
    #[error("attempted to create a discriminant from an invalid set of parameters")]
    InvalidDiscriminantParameters,
    #[error("this encryption key is invalid w.r.t. the public parameters")]
    InvalidEncryptionKey,
    #[error("attempted to create an Ibqf from an invalid set of parameters")]
    InvalidFormParameters,
    #[error("the parameters used to construct this space are invalid")]
    InvalidPublicParameters,
    #[error("this randomizer cannot be used for this input")]
    InvalidRandomizer,
    #[error("cannot use this scaling base for this exponent")]
    InvalidScalingBase,
    #[error("this secret key has an invalid size")]
    InvalidSecretKeySize,
    #[error("failed to solve linear congruence")]
    LinearCongruenceFailure,
    #[error("failed to compute a modular inverse.")]
    NoModInverse,
    #[error("there does not exist a quadratic non-residue mod 2")]
    NoQuadraticNonResidueMod2,
    #[error("smallest_kronecker_prime: no solution found among the small primes being checked")]
    NoSolutionAmongSmallPrimes,
    #[error("p is not an odd prime")]
    PIsNotAnOddPrime,
    #[error("p is not prime")]
    PIsNotPrime,
    #[error("sqrt_mod: a quadratic non-residue does not have a square root")]
    QuadraticNonResidueHasNoSqrt,
    #[error("the provided upper bound of scalar is too large")]
    ScalarBoundTooLarge,
    #[error("too few limbs")]
    UintConversionFailed,
    #[error("form is not reduced")]
    Unreduced,
    #[error("decryption failure")]
    Decryption,
    #[error(
        "the following parties {:?} submitted invalid public contributions to the randomized plaintext order residue element", .0
    )]
    InvalidPublicContribution(Vec<PartyID>),
    #[error("the following parties {:?} behaved maliciously by submitting invalid proofs", .0)]
    ProofVerificationError(Vec<PartyID>),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("invalid message")]
    InvalidMessage,
    #[error("invalid table size")]
    InvalidTableSize,
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("homomorphic-encryption error")]
    HomomorphicEncryption(#[from] homomorphic_encryption::Error),
    #[error("mpc error")]
    MPC(#[from] mpc::Error),
    #[cfg(feature = "threshold")]
    #[error("maurer error")]
    Maurer(#[from] maurer::Error),
}

/// Class Group Operations Result.
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::ProofVerificationError(malicious_parties) => {
                mpc::Error::MaliciousMessage(malicious_parties)
            }
            Error::Group(e) => mpc::Error::Group(e),
            Error::InternalError => mpc::Error::InternalError,
            Error::InvalidParameters => mpc::Error::InvalidParameters,
            Error::InvalidPublicParameters => mpc::Error::InvalidParameters,
            Error::MPC(e) => e,
            #[cfg(feature = "threshold")]
            Error::Maurer(e) => e.into(),
            e => mpc::Error::Consumer(format!("class groups error {e:?}")),
        }
    }
}

#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub mod test_helpers {
    #[cfg(feature = "threshold")]
    pub use crate::decryption_key_share::test_helpers::*;
    #[cfg(feature = "threshold")]
    pub use crate::dkg::test_helpers::*;
    #[cfg(feature = "threshold")]
    pub use crate::reconfiguration::test_helpers::*;
    pub use crate::setup::test_helpers::*;
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(
    benches,
    helpers::partial_xgcd::benches::benchmark,
    encryption_key::benches::benchmark,
    decryption_key_share::benches::benchmark_decryption_key_share_semi_honest_secp256k1,
    decryption_key_share::benches::benchmark_decryption_key_share_secp256k1,
    decryption_key_share::benches::benchmark_decryption_key_share_semi_honest_ristretto,
    decryption_key_share::benches::benchmark_decryption_key_share_ristretto,
    accelerator::benches::benchmark,
    decryption_key::benches::benchmark,
    ibqf::benches::benchmark,
    parameters::benches::benchmark,
    publicly_verifiable_secret_sharing::chinese_remainder_theorem::benches::benchmark,
);
