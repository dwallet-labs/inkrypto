// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;

use crypto_bigint::{
    CheckedMul, Concat, ConstantTimeSelect, Encoding, Int, Integer, InvertMod, NonZero, Split,
    Uint, Zero,
};
use serde::{Deserialize, Serialize};

use group::{CsRng, LinearlyCombinable};
use group::{GroupElement as _, PrimeGroupElement, Scale};
use group::{KnownOrderGroupElement, Samplable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
pub use public_parameters::PublicParameters;

use crate::equivalence_class::EquivalenceClass;
use crate::parameters::Parameters;
use crate::{CiphertextSpaceGroupElement, Error, RandomnessSpaceGroupElement};

pub mod public_parameters;

/// The (public) encryption key is an EquivalenceClass
///
/// TODO(#300): the serialization of this object should not be sent over a wire.
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
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding;

pub(crate) type Plaintext<const PLAINTEXT_LIMBS: usize> = Uint<PLAINTEXT_LIMBS>;

pub(crate) type Randomness<const RANDOMNESS_LIMBS: usize> = Uint<RANDOMNESS_LIMBS>;

pub(crate) type Ciphertext<const DISCRIMINANT_LIMBS: usize> = (
    EquivalenceClass<DISCRIMINANT_LIMBS>,
    EquivalenceClass<DISCRIMINANT_LIMBS>,
);

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
        const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Encoding + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// This encryption key.
    pub fn key(&self) -> &EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
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

        let zero_encoding = EquivalenceClass::unit_for_class(&class_group_parameters.delta_qk);

        let non_zero_plaintext = Uint::ct_select(plaintext, &Uint::ONE, zero_message)
            .to_nz()
            .expect("value is non-zero by construction");
        let non_zero_encoding = Self::power_of_f(&non_zero_plaintext, class_group_parameters);

        EquivalenceClass::ct_select(&non_zero_encoding, &zero_encoding, zero_message)
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
    ) -> EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS> {
        // TODO(#17): take into account the k>1 case.

        let inv_m_mod_q = m
            .invert_mod(&class_group_parameters.q)
            .expect("non-zero m has an inverse mod prime q")
            .resize::<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>();

        // L(m) is an odd representative of m⁻¹ mod q in [-q, q].
        // safe to cast; [-q, q] fits in DISCRIMINANT_LIMBS
        let q_ = class_group_parameters
            .q
            .resize::<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>();
        let lm = *Uint::ct_select(
            &inv_m_mod_q.wrapping_sub(&q_),
            &inv_m_mod_q,
            inv_m_mod_q.is_odd(),
        )
        .as_int();

        let a = q_
            .checked_square()
            .expect("no overflow; q² < q³ ≤ p·q³ ≤ |∆(qk)| ≤ Int::<NON_FUNDAMENTAL...>::MAX + 1")
            .to_nz()
            .expect("is non-zero; q ≠ 0 -> q² ≠ 0");
        let b = q_
            .try_into_int()
            .expect("safe cast; q < |∆(qk)| ≤ Int::<NON_FUNDAMENTAL...>::MAX + 1")
            .checked_mul(&lm)
            .expect("no overflow; |q·L(m)| < |q²| = |a| ≤ |∆(qk)|");

        // Construct the form (q², q·L(m), [L(m)² - ∆(qk)/q²]/4) with discriminant ∆(qk).
        //
        // Note that L(m)² - ∆(qk)/q² = 0 mod 4 since
        //  i) L(m)² = 1 mod 4, because L(m) is odd, and
        // ii) ∆(qk)/q² = -p·q = 1 mod 4 by construction.
        //
        // Hence, this form is valid.
        //
        // More over, note that                                 (*)
        // c = [L(m)² - ∆(qk)/q²]/4 > [L(m)² - ∆(k)]/4 > -∆(k)/4 > q² > a
        // where (*) follows from the fact that -∆(k) ≥ 4q² + 1, since we're not in the large
        // message variant. Hence, this class is reduced by construction.
        //
        // Safe to vartime; delta_qk is a public value.
        EquivalenceClass::new_from_coefficients_reduced_vartime_discriminant(
            a,
            b,
            class_group_parameters.delta_qk,
        )
        .expect("is valid and reduced by construction")
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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
{
    /// Encrypt `plaintext` with `randomness` under this (`self`) key.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 2.
    #[allow(unused_variables)]
    pub(crate) fn encrypt_internal<ScalarPublicParameters>(
        &self,
        plaintext: &Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        randomness: &Randomness<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        randomness_bits: u32,
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        is_vartime: bool,
    ) -> Result<Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    {
        if is_vartime {
            self.encrypt_with_randomness_vartime(plaintext, randomness, public_parameters)
        } else {
            // Note that h is always randomized as outputted from the setup parameter and every valid public key $\textsf{pk}=h^{r}$ is randomized.
            self.encrypt_with_randomness_randomized(
                plaintext,
                randomness,
                randomness_bits,
                public_parameters,
            )
        }
    }

    /// Encrypt `plaintext` with `randomness` under this (`self`) key.
    ///
    /// Assumes both `h` and `pk` are randomized forms, i.e., `*_randomized` functions can be used
    /// in the computation of `h^r` and `pk^r`, allowing execution to speed up.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 2.
    pub(crate) fn encrypt_with_randomness_randomized<ScalarPublicParameters>(
        &self,
        plaintext: &Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        randomness: &Randomness<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        randomness_bits_bound: u32,
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
    ) -> Result<Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    {
        let encoded_randomness = (
            public_parameters
                .setup_parameters
                .power_of_h_bounded_randomized(randomness, randomness_bits_bound),
            public_parameters.power_of_pk_bounded_randomized(randomness, randomness_bits_bound),
        );

        let is_vartime = false;
        self.encrypt_with_encoded_randomness(
            plaintext,
            encoded_randomness,
            public_parameters,
            is_vartime,
        )
    }

    /// Variation to [EncryptionKey::encrypt_with_randomness_randomized]` that executes in variable
    /// time.
    ///
    /// Executes in variable time w.r.t. all parameters.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 2.
    #[allow(dead_code)]
    pub(crate) fn encrypt_with_randomness_vartime<ScalarPublicParameters>(
        &self,
        plaintext: &Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        randomness: &Randomness<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
    ) -> Result<Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    {
        let randomness_bits = randomness.bits();

        let encoded_randomness = (
            public_parameters
                .setup_parameters
                .power_of_h_bounded_vartime(randomness, randomness_bits),
            public_parameters.power_of_pk_bounded_vartime(randomness, randomness_bits),
        );

        let is_vartime = true;
        self.encrypt_with_encoded_randomness(
            plaintext,
            encoded_randomness,
            public_parameters,
            is_vartime,
        )
    }

    /// Given randomness `(h^r, pk^r)` and plaintext `m`, construct `(h^r, f^m · pk^r)`.
    ///
    /// Ref: [BICYCL Implements CryptographY in CLass groups](https://eprint.iacr.org/archive/2022/1466/1694590466.pdf),
    /// Algorithm 2.
    pub(crate) fn encrypt_with_encoded_randomness<ScalarPublicParameters>(
        &self,
        plaintext: &Plaintext<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        encoded_randomness: (
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        ),
        public_parameters: &PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            ScalarPublicParameters,
        >,
        is_vartime: bool,
    ) -> Result<Ciphertext<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>, Error>
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    {
        let encoded_plaintext = Self::encode_plaintext(
            plaintext,
            &public_parameters.setup_parameters.class_group_parameters,
        );

        let (h_r, pk_r) = encoded_randomness;
        if !pk_r.is_from_the_same_class_as(&encoded_plaintext) {
            return Err(Error::InvalidParameters);
        }

        let c1 = h_r;
        let c2 = if is_vartime {
            pk_r.mul_vartime(&encoded_plaintext)
        } else {
            pk_r.mul(&encoded_plaintext)
        }
        .expect("successful multiplication; same discriminant");

        Ok((c1, c2))
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
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
        Encoding + InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

    Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
        Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
        + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
        + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
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
        is_vartime: bool,
    ) -> Self::CiphertextSpaceGroupElement {
        // we do not know the randomness size, but it should never exceed this bound.
        let randomness_bits_bound = public_parameters
            .setup_parameters
            .encryption_randomness_upper_bound_bits();

        let (c1, c2) = self
            .encrypt_internal(
                &(*plaintext).into(),
                &randomness.value(),
                randomness_bits_bound,
                public_parameters,
                is_vartime,
            )
            .expect("encryption succeeds");

        [c1, c2].into()
    }

    fn encrypt(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
        is_vartime: bool,
        rng: &mut impl CsRng,
    ) -> homomorphic_encryption::Result<(
        Self::RandomnessSpaceGroupElement,
        Self::CiphertextSpaceGroupElement,
    )> {
        let randomness = Self::RandomnessSpaceGroupElement::sample(
            public_parameters.randomness_space_public_parameters(),
            rng,
        )?;
        let randomness_bits_bound = public_parameters
            .setup_parameters
            .encryption_randomness_bits();

        let (c1, c2) = self
            .encrypt_internal(
                &(*plaintext).into(),
                &randomness.value(),
                randomness_bits_bound,
                public_parameters,
                is_vartime,
            )
            .expect("encryption succeeds");

        Ok((randomness, [c1, c2].into()))
    }

    fn evaluate_linear_combination<const MESSAGE_LIMBS: usize, const DIMENSION: usize>(
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        coefficient_upper_bound_bits: u32,
        ciphertexts: &[Self::CiphertextSpaceGroupElement; DIMENSION],
        public_parameters: &Self::PublicParameters,
        is_vartime: bool,
    ) -> homomorphic_encryption::Result<
        CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
    > {
        if DIMENSION == 0 {
            return Err(homomorphic_encryption::Error::ZeroDimension);
        }

        let linear_combination = if is_vartime {
            let bases_and_multiplicands = ciphertexts
                .iter()
                .copied()
                .zip(coefficients.iter().copied())
                .collect();

            let coefficient_upper_bound_bits = *coefficients
                .map(|coefficient| coefficient.bits_vartime())
                .iter()
                .max()
                .ok_or(homomorphic_encryption::Error::InvalidParameters)?;

            CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::linearly_combine_bounded_vartime(bases_and_multiplicands, coefficient_upper_bound_bits)?
        } else {
            coefficients
                .iter()
                .zip(ciphertexts.iter())
                .map(|(coefficient, ciphertext)| {
                    ciphertext.scale_randomized_bounded_accelerated(
                        coefficient,
                        public_parameters.ciphertext_space_public_parameters(),
                        coefficient_upper_bound_bits,
                    )
                })
                .reduce(|a, b| a.add_randomized(&b))
                .ok_or(homomorphic_encryption::Error::InvalidParameters)?
        };

        Ok(linear_combination)
    }

    fn securely_evaluate_linear_combination_with_randomness<
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
    >(
        &self,
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        coefficient_upper_bound_bits: u32,
        ciphertexts_and_encoded_messages_upper_bounds: [(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        _mask: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
        is_vartime: bool,
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

        let linear_combination = Self::evaluate_linear_combination(
            coefficients,
            coefficient_upper_bound_bits,
            &ciphertexts,
            public_parameters,
            is_vartime,
        )?;

        // Re-randomize evaluated ciphertext.
        // In class-groups, there is no need to mask the plaintext as the plaintext order and the curve order coincide.
        let mask = GroupElement::Scalar::neutral_from_public_parameters(
            public_parameters.plaintext_space_public_parameters(),
        )?;
        let encryption_with_fresh_randomness =
            self.encrypt_with_randomness(&mask, randomness, public_parameters, is_vartime);

        let securely_evaluated_linear_combination = if is_vartime {
            linear_combination.add_vartime(&encryption_with_fresh_randomness)
        } else {
            linear_combination.add_randomized(&encryption_with_fresh_randomness)
        };

        Ok(securely_evaluated_linear_combination)
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
        _rng: &mut impl CsRng,
    ) -> homomorphic_encryption::Result<Self::PlaintextSpaceGroupElement> {
        // In class-groups, there is no need to mask the plaintext as the plaintext order and the curve order coincide.
        Self::PlaintextSpaceGroupElement::neutral_from_public_parameters(
            public_parameters.plaintext_space_public_parameters(),
        )
        .map_err(homomorphic_encryption::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{U256, U768};

    use group::OsCsRng;

    use crate::test_helpers::get_setup_parameters_secp256k1_112_bits_deterministic;
    use crate::Secp256k1DecryptionKey;

    #[test]
    fn test_encryption_internal() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (pp, sk) =
            Secp256k1DecryptionKey::generate_with_setup_parameters(sp, &mut OsCsRng).unwrap();
        let pk = sk.encryption_key;

        let plaintext =
            U256::from_be_hex("3231F872D11D6F4886DEE97DF3B024FD523154BD01482D276347434451AB5600");
        let randomness = U768::from_be_hex(concat![
            "037AF187F852EACDBB7A951D31F813DCA4D10D0CDC98B6C0301857C43EE94B95",
            "5428AE7D4A1F666093DA6204C8DE6FF672F1FA939FD2FB2F7F8760538981F1ED",
            "E6E84A74F291AFB480CA2CD7C11F0DF89D20FAEA92DD9358AE9CA2FECFF0A950"
        ])
        .resize();
        assert_eq!(
            pk.encrypt_internal(&plaintext, &randomness, 768, &pp, false)
                .unwrap(),
            pk.encrypt_internal(&plaintext, &randomness, 768, &pp, true)
                .unwrap(),
        )
    }

    #[test]
    fn test_encryption_function_equivalence() {
        let sp = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (pp, sk) =
            Secp256k1DecryptionKey::generate_with_setup_parameters(sp, &mut OsCsRng).unwrap();
        let pk = sk.encryption_key;

        let plaintext =
            U256::from_be_hex("196D0F826C53306E24154CB4C43B50581CEE782B9745A80467092353B0E753C6");
        let randomness = U768::from_be_hex(concat![
            "0EE89AC2FD6455BB7A5C5A408CE64CBFF9F77A2C55CFACF7F55CBF30690BC684",
            "ADFB63E3E5509F261C562C9CA9CCD831D8A83247022F88E048A7115FEA892E8A",
            "93E5D2E71F890C40813E35B78250AD6FA25649D3A7B26F66A603AA1528E2D83E"
        ])
        .resize();
        assert_eq!(
            pk.encrypt_with_randomness_randomized(&plaintext, &randomness, 768, &pp)
                .unwrap(),
            pk.encrypt_with_randomness_vartime(&plaintext, &randomness, &pp)
                .unwrap(),
        )
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use std::hint::black_box;
    use std::time::Duration;

    use criterion::measurement::WallTime;
    use criterion::{BatchSize, BenchmarkGroup, Criterion};
    use crypto_bigint::{Concat, Encoding, Int, InvertMod, NonZero, Random, Split, Uint};

    use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
    use group::{GroupElement, OsCsRng, PrimeGroupElement, Samplable};
    use homomorphic_encryption::{
        AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors,
    };

    use crate::encryption_key::public_parameters::Instantiate;
    use crate::encryption_key::PublicParameters;
    use crate::test_helpers::{
        get_setup_parameters_ristretto_112_bits_deterministic,
        get_setup_parameters_secp256k1_112_bits_deterministic,
    };
    use crate::RandomnessSpaceGroupElement;
    use crate::{
        encryption_key, EncryptionKey, RistrettoDecryptionKey, RistrettoEncryptionKey,
        Secp256k1DecryptionKey, Secp256k1EncryptionKey,
    };

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
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>:
            Encoding + InvertMod<Output = Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>>,

        Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
        Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

        Int<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:,
        Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,

        Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
            Concat<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding
            + Concat<Output = Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>
            + Split<Output = Uint<HALF_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
        Uint<DOUBLE_NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>:
            Split<Output = Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,

        group::PublicParameters<GroupElement::Scalar>: Eq,
    {
        pub(crate) fn benchmark_pow_h(
            g: &mut BenchmarkGroup<WallTime>,
            public_parameters: &PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
        ) {
            let acc = public_parameters.setup_parameters.get_h_accelerator(
                public_parameters
                    .randomness_space_public_parameters()
                    .sample_bits,
            );

            let randomizer_acc = public_parameters.setup_parameters.get_h_accelerator(
                public_parameters
                    .randomness_space_public_parameters()
                    .sample_bits
                    + MAURER_RANDOMIZER_DIFF_BITS,
            );

            g.bench_function(
                format!(
                    "pow h acc({}/{}) vt {}",
                    acc.nr_lanes,
                    acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters
                                .setup_parameters
                                .power_of_h_bounded_vartime(
                                    &randomness,
                                    public_parameters
                                        .randomness_space_public_parameters()
                                        .sample_bits,
                                );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            g.bench_function(
                format!(
                    "pow h direct acc({}/{}) vt {}",
                    acc.nr_lanes,
                    acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let randomness = RandomnessSpaceGroupElement::sample(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value();

                            randomness
                        },
                        |randomness| {
                            let enc = acc.encode_bounded_exponent(
                                &randomness,
                                public_parameters
                                    .randomness_space_public_parameters()
                                    .sample_bits,
                            );
                            let x = acc.pow_vartime(&enc);

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            g.bench_function(
                format!(
                    "pow h acc({}/{}) vt randomizer {}",
                    randomizer_acc.nr_lanes,
                    randomizer_acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                        + MAURER_RANDOMIZER_DIFF_BITS
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample_randomizer(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters
                                .setup_parameters
                                .power_of_h_bounded_vartime(
                                    &randomness,
                                    public_parameters
                                        .randomness_space_public_parameters()
                                        .sample_bits
                                        + MAURER_RANDOMIZER_DIFF_BITS,
                                );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            g.bench_function(
                format!(
                    "pow h acc({}/{}) rt {}",
                    acc.nr_lanes,
                    acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters
                                .setup_parameters
                                .power_of_h_bounded_randomized(
                                    &randomness,
                                    public_parameters
                                        .randomness_space_public_parameters()
                                        .sample_bits,
                                );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            g.bench_function(
                format!(
                    "pow h acc({}/{}) rt randomizer {}",
                    randomizer_acc.nr_lanes,
                    randomizer_acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                        + MAURER_RANDOMIZER_DIFF_BITS
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample_randomizer(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters
                                .setup_parameters
                                .power_of_h_bounded_randomized(
                                    &randomness,
                                    public_parameters
                                        .randomness_space_public_parameters()
                                        .sample_bits
                                        + MAURER_RANDOMIZER_DIFF_BITS,
                                );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }

        pub(crate) fn benchmark_pow_pk(
            g: &mut BenchmarkGroup<WallTime>,
            public_parameters: &PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
        ) {
            let acc = public_parameters.get_encryption_key_accelerator(
                public_parameters
                    .randomness_space_public_parameters()
                    .sample_bits,
            );

            let randomizer_acc = public_parameters.get_encryption_key_accelerator(
                public_parameters
                    .randomness_space_public_parameters()
                    .sample_bits
                    + MAURER_RANDOMIZER_DIFF_BITS,
            );

            g.bench_function(
                format!(
                    "pow pk acc({}/{}) vt {}",
                    acc.nr_lanes,
                    acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters.power_of_pk_bounded_vartime(
                                &randomness,
                                public_parameters
                                    .randomness_space_public_parameters()
                                    .sample_bits,
                            );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            g.bench_function(
                format!(
                    "pow pk acc({}/{}) vt randomizer {}",
                    randomizer_acc.nr_lanes,
                    randomizer_acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                        + MAURER_RANDOMIZER_DIFF_BITS,
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample_randomizer(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters.power_of_pk_bounded_vartime(
                                &randomness,
                                public_parameters
                                    .randomness_space_public_parameters()
                                    .sample_bits
                                    + MAURER_RANDOMIZER_DIFF_BITS,
                            );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            g.bench_function(
                format!(
                    "pow pk acc({}/{}) rt {}",
                    acc.nr_lanes,
                    acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits,
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters.power_of_pk_bounded_randomized(
                                &randomness,
                                public_parameters
                                    .randomness_space_public_parameters()
                                    .sample_bits,
                            );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            g.bench_function(
                format!(
                    "pow pk acc({}/{}) rt randomizer {}",
                    randomizer_acc.nr_lanes,
                    randomizer_acc.target_bits,
                    public_parameters
                        .randomness_space_public_parameters()
                        .sample_bits
                        + MAURER_RANDOMIZER_DIFF_BITS,
                ),
                |b| {
                    b.iter_batched(
                        || {
                            RandomnessSpaceGroupElement::sample_randomizer(
                                public_parameters.randomness_space_public_parameters(),
                                &mut OsCsRng,
                            )
                            .unwrap()
                            .value()
                        },
                        |randomness| {
                            let x = public_parameters.power_of_pk_bounded_randomized(
                                &randomness,
                                public_parameters
                                    .randomness_space_public_parameters()
                                    .sample_bits
                                    + MAURER_RANDOMIZER_DIFF_BITS,
                            );

                            black_box(x)
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }

        pub(crate) fn benchmark_encrypt(
            g: &mut BenchmarkGroup<WallTime>,
            encryption_key: &EncryptionKey<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                GroupElement,
            >,
            public_parameters: &PublicParameters<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                FUNDAMENTAL_DISCRIMINANT_LIMBS,
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
                group::PublicParameters<GroupElement::Scalar>,
            >,
        ) {
            let acc = public_parameters.get_encryption_key_accelerator(
                public_parameters
                    .randomness_space_public_parameters()
                    .sample_bits,
            );

            g.bench_function(format!("encrypt vartime({})", acc.nr_lanes,), |b| {
                b.iter_batched(
                    || {
                        let randomness = RandomnessSpaceGroupElement::sample(
                            public_parameters.randomness_space_public_parameters(),
                            &mut OsCsRng,
                        )
                        .unwrap();

                        let plaintext = GroupElement::Scalar::sample(
                            public_parameters.plaintext_space_public_parameters(),
                            &mut OsCsRng,
                        )
                        .unwrap();

                        (randomness, plaintext)
                    },
                    |(randomness, plaintext)| {
                        let ct = encryption_key.encrypt_with_randomness(
                            &plaintext,
                            &randomness,
                            public_parameters,
                            true,
                        );

                        black_box(ct)
                    },
                    BatchSize::SmallInput,
                )
            });

            g.bench_function(format!("encrypt const-time({})", acc.nr_lanes,), |b| {
                b.iter_batched(
                    || {
                        let randomness = RandomnessSpaceGroupElement::sample(
                            public_parameters.randomness_space_public_parameters(),
                            &mut OsCsRng,
                        )
                        .unwrap();

                        let plaintext = GroupElement::Scalar::sample(
                            public_parameters.plaintext_space_public_parameters(),
                            &mut OsCsRng,
                        )
                        .unwrap();

                        (randomness, plaintext)
                    },
                    |(randomness, plaintext)| {
                        let ct = encryption_key.encrypt_with_randomness(
                            &plaintext,
                            &randomness,
                            public_parameters,
                            false,
                        );

                        black_box(ct)
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }

    fn bench_secp256k1(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_secp256k1_112_bits_deterministic();
        let (pp, decryption_key) = Secp256k1DecryptionKey::generate_with_setup_parameters(
            setup_parameters.clone(),
            &mut OsCsRng,
        )
        .unwrap();
        let encryption_key = decryption_key.encryption_key;

        let normally_accelerated_public_parameters =
            PublicParameters::new(setup_parameters.clone(), pp.encryption_key).unwrap();

        let highly_accelerated_public_parameters = PublicParameters::new_maximally_accelerated(
            setup_parameters,
            normally_accelerated_public_parameters.encryption_key,
        )
        .unwrap();

        let m = NonZero::random(&mut OsCsRng);
        group.bench_function("power_of_f", |b| {
            b.iter(|| {
                black_box(Secp256k1EncryptionKey::power_of_f(
                    &m,
                    &normally_accelerated_public_parameters
                        .setup_parameters
                        .class_group_parameters,
                ))
            })
        });

        Secp256k1EncryptionKey::benchmark_pow_h(group, &normally_accelerated_public_parameters);

        Secp256k1EncryptionKey::benchmark_pow_pk(group, &normally_accelerated_public_parameters);
        Secp256k1EncryptionKey::benchmark_pow_pk(group, &highly_accelerated_public_parameters);

        Secp256k1EncryptionKey::benchmark_encrypt(
            group,
            &encryption_key,
            &normally_accelerated_public_parameters,
        );

        Secp256k1EncryptionKey::benchmark_encrypt(
            group,
            &encryption_key,
            &highly_accelerated_public_parameters,
        );
    }

    fn bench_ed25519(group: &mut BenchmarkGroup<WallTime>) {
        group.warm_up_time(Duration::from_secs(5));
        group.measurement_time(Duration::from_secs(10));

        let setup_parameters = get_setup_parameters_ristretto_112_bits_deterministic();
        let (pp, decryption_key) = RistrettoDecryptionKey::generate_with_setup_parameters(
            setup_parameters.clone(),
            &mut OsCsRng,
        )
        .unwrap();
        let encryption_key = decryption_key.encryption_key;

        let normally_accelerated_public_parameters =
            PublicParameters::new(setup_parameters.clone(), pp.encryption_key).unwrap();

        let highly_accelerated_public_parameters =
            encryption_key::PublicParameters::new_maximally_accelerated(
                setup_parameters,
                normally_accelerated_public_parameters.encryption_key,
            )
            .unwrap();

        let m = NonZero::random(&mut OsCsRng);
        group.bench_function("power_of_f", |b| {
            b.iter(|| {
                black_box(RistrettoEncryptionKey::power_of_f(
                    &m,
                    &normally_accelerated_public_parameters
                        .setup_parameters
                        .class_group_parameters,
                ))
            })
        });

        RistrettoEncryptionKey::benchmark_pow_h(group, &normally_accelerated_public_parameters);

        RistrettoEncryptionKey::benchmark_pow_pk(group, &normally_accelerated_public_parameters);
        RistrettoEncryptionKey::benchmark_pow_pk(group, &highly_accelerated_public_parameters);

        RistrettoEncryptionKey::benchmark_encrypt(
            group,
            &encryption_key,
            &normally_accelerated_public_parameters,
        );
        RistrettoEncryptionKey::benchmark_encrypt(
            group,
            &encryption_key,
            &highly_accelerated_public_parameters,
        );
    }

    pub(crate) fn benchmark(_c: &mut Criterion) {
        bench_secp256k1(&mut _c.benchmark_group("encryption_key/secp256k1"));
        bench_ed25519(&mut _c.benchmark_group("encryption_key/ed25519"));
    }
}
