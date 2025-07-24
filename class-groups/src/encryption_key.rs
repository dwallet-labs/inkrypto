// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;
use std::ops::Deref;

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{
    CheckedMul, Concat, ConstantTimeSelect, Encoding, Gcd, Int, Integer, InvMod, NonZero, Split,
    Uint, Zero,
};
use serde::{Deserialize, Serialize};

use group::{GroupElement as _, PrimeGroupElement};
use group::{KnownOrderGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
pub use public_parameters::PublicParameters;

use crate::equivalence_class::EquivalenceClass;
use crate::ibqf::Ibqf;
use crate::parameters::Parameters;
use crate::{CiphertextSpaceGroupElement, RandomnessSpaceGroupElement};

mod public_parameters;
/// The (public) encryption key is an EquivalenceClass
#[derive(Clone, Debug, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub struct EncryptionKey<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize, // TODO: not used in definition.
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>(
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    PhantomData<GroupElement>,
)
where
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding;

pub(crate) type Plaintext<const PLAINTEXT_LIMBS: usize> = Uint<PLAINTEXT_LIMBS>;

pub(crate) type Randomness<const RANDOMNESS_LIMBS: usize> = Uint<RANDOMNESS_LIMBS>;

pub(crate) type Ciphertext<const DISCRIMINANT_LIMBS: usize> = (
    EquivalenceClass<DISCRIMINANT_LIMBS>,
    EquivalenceClass<DISCRIMINANT_LIMBS>,
);

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding
        + InvMod<
            Modulus = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
            Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// This encryption key.
    pub(crate) fn key(&self) -> &EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        &self.0
    }

    /// Encode a plaintext message `m` as a class-group element.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Theorem 5.
    pub(crate) fn encode_plaintext(
        plaintext: &Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        class_group_parameters: &Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        let zero_message = plaintext.is_zero();

        // safe to unwrap; delta_qk is a valid discriminant
        let zero_encoding =
            Ibqf::unit_for_discriminant(class_group_parameters.delta_qk.deref()).unwrap();

        let non_zero_plaintext = Uint::ct_select(plaintext, &Uint::ONE, zero_message);
        // safe to unwrap; value is non-zero by construction.
        let non_zero_encoding =
            Self::power_of_f(&non_zero_plaintext.to_nz().unwrap(), class_group_parameters);

        let plaintext_encoding = Ibqf::ct_select(&non_zero_encoding, &zero_encoding, zero_message)
            .reduce_vartime()
            .unwrap();

        // safe to unwrap; form is correct by construction
        // TODO(#101): don't unwrap on returned values.
        EquivalenceClass::try_from(plaintext_encoding).unwrap()
    }

    /// Compute `f^m` for non-zero `m`.
    ///
    /// Note: the returned form may be unreduced.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Theorem 5.
    pub(crate) fn power_of_f(
        m: &NonZero<Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>>,
        class_group_parameters: &Parameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    ) -> Ibqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        // TODO(#17): take into account the k>1 case.

        // safe to unwrap; non-zero `m` always has an inverse mod prime `q`.
        let inv_m_mod_q = m
            .inv_mod(&class_group_parameters.q)
            .unwrap()
            .resize::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>();

        // L(m) is an odd representative of m⁻¹ mod q in [-q, q].
        // safe to cast; [-q, q] fits in DISCRIMINANT_LIMBS
        let q_ = class_group_parameters
            .q
            .resize::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>();
        let lm = Uint::ct_select(
            &inv_m_mod_q.wrapping_sub(&q_),
            &inv_m_mod_q,
            inv_m_mod_q.is_odd(),
        )
        .as_int();

        // Construct the form [q^2, q*L(m), ...]
        // safe to unwrap; q² <= ∆(qk). Hence, this fits.
        let a = q_.checked_square().unwrap();
        // safe to cast; q_ always fits in DISCRIMINANT_LIMBS.
        // safe to unwrap; |b| <= |a|. Hence, this fits.
        let b = q_.as_int().checked_mul(&lm).unwrap();

        // safe to unwrap; this form is correct by construction.
        Ibqf::new(
            a.to_int().unwrap().to_nz().unwrap(),
            b,
            &class_group_parameters.delta_qk,
        )
        .unwrap()
    }
}
impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    >
    EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding
        + InvMod<
            Modulus = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
            Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + InvMod<
            Modulus = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Encrypt `plaintext` with `randomness` under this (`self`) key.
    ///
    /// To encrypt, three steps are performed:
    /// 1. Encode randomness: map `r` to `(h^r, pk^r)`.
    /// 2. Encode message: map `m` to `f^m`.
    /// 3. Combine: map `(f^m, (h^r, pk^r))` to `(h^r, f^m * pk^r)`.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 2.
    pub(crate) fn encrypt_with_randomness_internal<ScalarPublicParameters>(
        &self,
        plaintext: &Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        randomness: &Randomness<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        _randomness_bits_bound: u32,
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
    ) -> Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    {
        let setup_parameters = &public_parameters.setup_parameters;

        // Encode randomness
        // TODO(#46): make const-time. Replace `pow_vartime` by `pow_bounded(..., _randomness_bits_bound)`
        let encoded_randomness = (
            setup_parameters.power_of_h_vartime(randomness),
            self.key().pow_vartime(randomness),
        );

        // Encode plaintext
        let encoded_plaintext =
            Self::encode_plaintext(plaintext, &setup_parameters.class_group_parameters);

        // Combine plaintext with randomness to form ciphertext
        // safe to unwrap: plaintext and pk_exp_randomness have same valid discriminant.
        (
            encoded_randomness.0,
            encoded_randomness.1.mul(&encoded_plaintext).unwrap(),
        )
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        GroupElement: PrimeGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>
    for EncryptionKey<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >
where
    Int<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding
        + InvMod<
            Modulus = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
            Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        >,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: InvMod<
        Modulus = NonZero<Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    >,
    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + InvMod<
            Modulus = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Gcd<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    group::PublicParameters<GroupElement::Scalar>: Eq,
{
    type PlaintextSpaceGroupElement = GroupElement::Scalar;

    // safe to use SMALL; the randomness upperbound fits in FUNDAMENTAL_DISCRIMINANT_LIMBS when the
    // small discriminant is >767 bits. Given that the lowest computational security parameter
    // requires a >1347-bit discriminant, we are safe.
    type RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>;
    type CiphertextSpaceGroupElement =
        CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>;
    type PublicParameters = PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> homomorphic_encryption::Result<Self> {
        Ok(Self(public_parameters.encryption_key, PhantomData))
    }

    fn encrypt_with_randomness(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
    ) -> Self::CiphertextSpaceGroupElement {
        // safe to unwrap; always OK()
        let encryption_key = Self::new(public_parameters).unwrap();
        let (c1, c2) = encryption_key.encrypt_with_randomness_internal(
            &(*plaintext).into(),
            &randomness.value(),
            // we do not know the randomness size, but it should never exceed this bound.
            public_parameters
                .setup_parameters
                .encryption_randomness_upper_bound_bits(),
            public_parameters,
        );

        [c1, c2].into()
    }

    fn encrypt(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> homomorphic_encryption::Result<(
        Self::RandomnessSpaceGroupElement,
        Self::CiphertextSpaceGroupElement,
    )> {
        let randomness = Self::RandomnessSpaceGroupElement::sample(
            public_parameters.randomness_space_public_parameters(),
            rng,
        )?;

        // safe to unwrap; always OK()
        let encryption_key = Self::new(public_parameters).unwrap();
        let (c1, c2) = encryption_key.encrypt_with_randomness_internal(
            &(*plaintext).into(),
            &randomness.value(),
            // we know the randomness to be of this bit size
            public_parameters
                .setup_parameters
                .encryption_randomness_bits(),
            public_parameters,
        );

        Ok((randomness, [c1, c2].into()))
    }

    fn sample_mask_for_secure_function_evaluation<
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
    >(
        _coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        _ciphertexts_and_encoded_messages_upper_bounds: &[(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        _modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        public_parameters: &Self::PublicParameters,
        _rng: &mut impl CryptoRngCore,
    ) -> homomorphic_encryption::Result<Self::PlaintextSpaceGroupElement> {
        // In class-groups, there is no need to mask the plaintext as the plaintext order and the curve order coincide.
        Self::PlaintextSpaceGroupElement::neutral_from_public_parameters(
            public_parameters.plaintext_space_public_parameters(),
        )
        .map_err(homomorphic_encryption::Error::from)
    }

    fn securely_evaluate_linear_combination_with_randomness<
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
    >(
        &self,
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        ciphertexts_and_encoded_messages_upper_bounds: [(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        _mask: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
    ) -> homomorphic_encryption::Result<
        CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    > {
        if DIMENSION == 0 {
            return Err(homomorphic_encryption::Error::ZeroDimension);
        }

        let plaintext_order: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            Self::PlaintextSpaceGroupElement::order_from_public_parameters(
                public_parameters.plaintext_space_public_parameters(),
            );

        if &plaintext_order != modulus || MESSAGE_LIMBS < PLAINTEXT_SPACE_SCALAR_LIMBS {
            return Err(homomorphic_encryption::Error::InvalidParameters);
        }

        let ciphertexts =
            ciphertexts_and_encoded_messages_upper_bounds.map(|(ciphertext, _)| ciphertext);

        let linear_combination = Self::evaluate_linear_combination(coefficients, &ciphertexts)?;

        // Re-randomize evaluated ciphertext.
        // In class-groups, there is no need to mask the plaintext as the plaintext order and the curve order coincide.
        let mask = GroupElement::Scalar::neutral_from_public_parameters(
            public_parameters.plaintext_space_public_parameters(),
        )?;
        let encryption_with_fresh_randomness =
            self.encrypt_with_randomness(&mask, randomness, public_parameters);

        Ok(linear_combination + encryption_with_fresh_randomness)
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{black_box, BenchmarkGroup, Criterion};
    use crypto_bigint::{NonZero, Random};
    use rand_core::OsRng;

    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };
    use crate::{
        RistrettoDecryptionKey, RistrettoEncryptionKey, Secp256k1DecryptionKey,
        Secp256k1EncryptionKey,
    };

    fn bench_secp256k1(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (pp, _) = Secp256k1DecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

        let m = NonZero::random(&mut OsRng);
        group.bench_function("power_of_f", |b| {
            b.iter(|| {
                black_box(Secp256k1EncryptionKey::power_of_f(
                    &m,
                    &pp.setup_parameters.class_group_parameters,
                ))
            })
        });
    }

    fn bench_ed25519(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let (pp, _) = RistrettoDecryptionKey::generate(setup_parameters, &mut OsRng).unwrap();

        let m = NonZero::random(&mut OsRng);
        group.bench_function("power_of_f", |b| {
            b.iter(|| {
                black_box(RistrettoEncryptionKey::power_of_f(
                    &m,
                    &pp.setup_parameters.class_group_parameters,
                ))
            })
        });
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        bench_secp256k1(&mut _c.benchmark_group("encryption_key/secp256k1"));
        bench_ed25519(&mut _c.benchmark_group("encryption_key/ed25519"));
    }
}
