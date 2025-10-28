// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::array;
use std::marker::PhantomData;

use crypto_bigint::{Encoding, NonZero, Uint};
use serde::{Deserialize, Serialize};

use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
use group::direct_product::ThreeWayPublicParameters;
use group::helpers::FlatMapResults;
use group::{
    bounded_natural_numbers_group, direct_product, self_product, GroupElement as _,
    KnownOrderGroupElement,
};
use group::{Reduce, Transcribeable};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use proof::GroupsPublicParameters;

use crate::Error;
use crate::SOUND_PROOFS_REPETITIONS;

/// Encryption of a Tuple Maurer Language
///
/// SECURITY NOTICE:
/// This language implicitly assumes that the plaintext space of the encryption scheme and the
/// scalar group coincide (same exponent) like class-groups. Using generic encryption schemes is permitted if and only
/// if we use this language in its enhanced form, i.e. `enhanced_maurer::EnhancedLanguage`.
///
/// SECURITY NOTICE (2):
/// Furthermore, even when using `EnhancedLanguage`, note that ENC_DH proves a correct computation
/// that is not a secure function evaluation. That is, the result is not safe to send to a holder of the secret key, as it does
/// not hide the number of arithmetic reductions. For secure function evaluation, use
/// `DComEval` (enhanced) language. Because correctness and zero-knowledge is guaranteed for any
/// group and additively homomorphic encryption scheme in this language, we choose to provide a
/// fully generic implementation.
///
/// However knowledge-soundness proofs are group and encryption scheme dependent, and thus we can
/// only assure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
///
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier` and `class_groups`, which are groups of unknown order.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const N: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Witness Space Group Element of the Encryption of a Tuple Maurer Language.
pub type WitnessSpaceGroupElement<
    const N: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    EncryptionKey,
> = direct_product::ThreeWayGroupElement<
    bounded_natural_numbers_group::GroupElement<MESSAGE_LIMBS>,
    homomorphic_encryption::RandomnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    self_product::GroupElement<
        N,
        homomorphic_encryption::RandomnessSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
    >,
>;

/// The Statement Space Group Element of the Encryption of a Tuple Maurer Language.
pub type StatementSpaceGroupElement<
    const N: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    EncryptionKey,
> = direct_product::GroupElement<
    homomorphic_encryption::CiphertextSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    self_product::GroupElement<
        N,
        homomorphic_encryption::CiphertextSpaceGroupElement<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >,
    >,
>;

/// The Public Parameters of the Encryption of a Tuple Maurer Language.
/// The `lower_bound` of `ciphertext` should be verified independently,
/// e.g. by verifying (and following) a sequence of enhanced proofs over the homomorphic
/// computations that yields it.
pub type PublicParameters<
    const N: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = private::PublicParameters<
    N,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    MESSAGE_LIMBS,
    group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
    homomorphic_encryption::RandomnessSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::CiphertextSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
>;

impl<
        const N: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<
        N,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    type WitnessSpaceGroupElement =
        WitnessSpaceGroupElement<N, PLAINTEXT_SPACE_SCALAR_LIMBS, MESSAGE_LIMBS, EncryptionKey>;

    type StatementSpaceGroupElement =
        StatementSpaceGroupElement<N, PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, EncryptionKey>;

    type PublicParameters = PublicParameters<
        N,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey,
    >;

    const NAME: &'static str = "Encryption of a Tuple";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        is_randomizer: bool,
        is_verify: bool,
    ) -> crate::Result<Self::StatementSpaceGroupElement> {
        if SCALAR_LIMBS > PLAINTEXT_SPACE_SCALAR_LIMBS {
            return Err(Error::InvalidPublicParameters);
        }

        let group_order = Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
            &GroupElement::Scalar::order_from_public_parameters(
                &language_public_parameters.scalar_group_public_parameters,
            ),
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)
                .map_err(|_| crate::Error::InvalidPublicParameters)?;

        let ciphertexts = language_public_parameters
            .ciphertexts
            .map(|ciphertext| {
                homomorphic_encryption::CiphertextSpaceGroupElement::<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    EncryptionKey,
                >::new(
                    ciphertext,
                    language_public_parameters
                        .encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters(),
                )
            })
            .flat_map_results()?;

        let plaintext_group_order =
            EncryptionKey::PlaintextSpaceGroupElement::order_from_public_parameters(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            );
        let plaintext_group_order =
            Option::<_>::from(NonZero::new(plaintext_group_order)).ok_or(Error::InternalError)?;
        let multiplicand_value = witness
            .multiplicand()
            .value()
            .reduce(&plaintext_group_order)
            .into();
        let multiplicand_plaintext = EncryptionKey::PlaintextSpaceGroupElement::new(
            multiplicand_value,
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;

        let encryption_of_multiplicand = encryption_key.encrypt_with_randomness(
            &multiplicand_plaintext,
            witness.multiplicand_randomness(),
            &language_public_parameters.encryption_scheme_public_parameters,
            is_verify,
        );

        // No masking of the plaintext is needed, as we don't need secure function evaluation.
        let mask = EncryptionKey::PlaintextSpaceGroupElement::neutral_from_public_parameters(
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;

        let coefficient = witness.multiplicand().value();
        let coefficient_upper_bound_bits: u32 = if is_verify {
            coefficient.bits_vartime()
        } else if is_randomizer {
            language_public_parameters
                .message_group_public_parameters()
                .sample_bits
                + MAURER_RANDOMIZER_DIFF_BITS
        } else {
            language_public_parameters
                .message_group_public_parameters()
                .sample_bits
        };

        let product_randomnesses: [_; N] = (*witness.product_randomnesses()).into();
        let encryptions_of_product = array::from_fn(|i| {
            let ciphertext = ciphertexts[i];
            let product_randomness = product_randomnesses[i];

            encryption_key
                .securely_evaluate_linear_combination_with_randomness(
                    &[coefficient],
                    coefficient_upper_bound_bits,
                    [(ciphertext, language_public_parameters.upper_bound)],
                    &group_order,
                    &mask,
                    &product_randomness,
                    &language_public_parameters.encryption_scheme_public_parameters,
                    is_verify,
                )
                .map_err(|_| crate::Error::InvalidPublicParameters)
        })
        .flat_map_results()?;

        Ok((encryption_of_multiplicand, encryptions_of_product.into()).into())
    }
}

pub(super) mod private {
    use super::*;
    use crypto_bigint::Encoding;
    use group::Transcribeable;
    use proof::CanonicalGroupsPublicParameters;

    #[derive(Clone, Debug, PartialEq, Serialize, Eq)]
    #[allow(clippy::type_complexity)]
    pub struct PublicParameters<
        const N: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue: Serialize,
    >
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        pub groups_public_parameters: GroupsPublicParameters<
            ThreeWayPublicParameters<
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                RandomnessSpacePublicParameters,
                self_product::PublicParameters<N, RandomnessSpacePublicParameters>,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<N, CiphertextSpacePublicParameters>,
            >,
        >,
        pub scalar_group_public_parameters: ScalarPublicParameters,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        #[serde(with = "group::helpers::const_generic_array_serialization")]
        pub ciphertexts: [CiphertextSpaceValue; N],
        pub upper_bound: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    }

    #[derive(Serialize)]
    #[allow(clippy::type_complexity)]
    pub struct CanonicalPublicParameters<
        const N: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpacePublicParameters: Transcribeable + Serialize,
        EncryptionKeyPublicParameters: Transcribeable + Serialize,
        CiphertextSpaceValue: Serialize,
    >
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        pub(super) canonical_groups_public_parameters: CanonicalGroupsPublicParameters<
            ThreeWayPublicParameters<
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                RandomnessSpacePublicParameters,
                self_product::PublicParameters<N, RandomnessSpacePublicParameters>,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<N, CiphertextSpacePublicParameters>,
            >,
        >,
        pub(super) canonical_scalar_group_public_parameters:
            ScalarPublicParameters::CanonicalRepresentation,
        pub(super) canonical_encryption_scheme_public_parameters:
            EncryptionKeyPublicParameters::CanonicalRepresentation,
        #[serde(with = "group::helpers::const_generic_array_serialization")]
        pub(super) ciphertexts: [CiphertextSpaceValue; N],
        pub(super) upper_bound: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    }
}

impl<
        const N: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue: Serialize,
    >
    AsRef<
        GroupsPublicParameters<
            ThreeWayPublicParameters<
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                RandomnessSpacePublicParameters,
                self_product::PublicParameters<N, RandomnessSpacePublicParameters>,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<N, CiphertextSpacePublicParameters>,
            >,
        >,
    >
    for private::PublicParameters<
        N,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        ThreeWayPublicParameters<
            bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
            RandomnessSpacePublicParameters,
            self_product::PublicParameters<N, RandomnessSpacePublicParameters>,
        >,
        direct_product::PublicParameters<
            CiphertextSpacePublicParameters,
            self_product::PublicParameters<N, CiphertextSpacePublicParameters>,
        >,
    > {
        &self.groups_public_parameters
    }
}
impl<
        const N: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue: Serialize,
    >
    private::PublicParameters<
        N,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    pub fn new<
        const SCALAR_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey,
    >(
        scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        ciphertexts: [CiphertextSpaceValue; N],
        upper_bound: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    ) -> crate::Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = EncryptionKeyPublicParameters,
        >,
        EncryptionKey::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        EncryptionKey::CiphertextSpaceGroupElement:
            group::GroupElement<PublicParameters = CiphertextSpacePublicParameters>,
        EncryptionKey::PublicParameters: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                group::PublicParameters<EncryptionKey::PlaintextSpaceGroupElement>,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    {
        let message_group_public_parameters =
            bounded_natural_numbers_group::PublicParameters::new_with_randomizer_upper_bound(
                Uint::<SCALAR_LIMBS>::BITS,
            )?;

        Ok(Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    message_group_public_parameters,
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                    self_product::PublicParameters::new(
                        encryption_scheme_public_parameters
                            .randomness_space_public_parameters()
                            .clone(),
                    ),
                )
                    .into(),
                statement_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                    group::PublicParameters::<
                        self_product::GroupElement<N, EncryptionKey::CiphertextSpaceGroupElement>,
                    >::new(
                        encryption_scheme_public_parameters
                            .ciphertext_space_public_parameters()
                            .clone(),
                    ),
                )
                    .into(),
            },
            scalar_group_public_parameters,
            encryption_scheme_public_parameters,
            ciphertexts,
            upper_bound,
        })
    }

    pub fn message_group_public_parameters(
        &self,
    ) -> &bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS> {
        let (message_group_public_parameters, _, _) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        message_group_public_parameters
    }
}

impl<
        const N: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpacePublicParameters: Transcribeable + Serialize,
        EncryptionKeyPublicParameters: Transcribeable + Serialize,
        CiphertextSpaceValue: Serialize,
    >
    From<
        private::PublicParameters<
            N,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            ScalarPublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
            EncryptionKeyPublicParameters,
            CiphertextSpaceValue,
        >,
    >
    for private::CanonicalPublicParameters<
        N,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    fn from(
        value: private::PublicParameters<
            N,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            ScalarPublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
            EncryptionKeyPublicParameters,
            CiphertextSpaceValue,
        >,
    ) -> Self {
        Self {
            canonical_groups_public_parameters: value.groups_public_parameters.into(),
            canonical_encryption_scheme_public_parameters: value
                .encryption_scheme_public_parameters
                .into(),
            canonical_scalar_group_public_parameters: value.scalar_group_public_parameters.into(),
            ciphertexts: value.ciphertexts,
            upper_bound: value.upper_bound,
        }
    }
}

impl<
        const N: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpacePublicParameters: Transcribeable + Serialize,
        EncryptionKeyPublicParameters: Transcribeable + Serialize,
        CiphertextSpaceValue: Serialize,
    > Transcribeable
    for private::PublicParameters<
        N,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    type CanonicalRepresentation = private::CanonicalPublicParameters<
        N,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >;
}

pub trait WitnessAccessors<
    const N: usize,
    MessageGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn multiplicand(&self) -> &MessageGroupElement;

    fn multiplicand_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn product_randomnesses(&self) -> &self_product::GroupElement<N, RandomnessSpaceGroupElement>;
}

impl<
        const N: usize,
        MessageGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<N, MessageGroupElement, RandomnessSpaceGroupElement>
    for direct_product::ThreeWayGroupElement<
        MessageGroupElement,
        RandomnessSpaceGroupElement,
        self_product::GroupElement<N, RandomnessSpaceGroupElement>,
    >
{
    fn multiplicand(&self) -> &MessageGroupElement {
        let (multiplicand, ..): (&_, &_, &_) = self.into();

        multiplicand
    }

    fn multiplicand_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, multiplicand_randomness, _): (&_, &_, &_) = self.into();

        multiplicand_randomness
    }

    fn product_randomnesses(&self) -> &self_product::GroupElement<N, RandomnessSpaceGroupElement> {
        let (_, _, product_randomness): (&_, &_, &_) = self.into();

        product_randomness
    }
}

pub trait StatementAccessors<const N: usize, CiphertextSpaceGroupElement: group::GroupElement> {
    fn encryption_of_multiplicand(&self) -> &CiphertextSpaceGroupElement;

    fn encryption_of_product(&self) -> &self_product::GroupElement<N, CiphertextSpaceGroupElement>;
}

impl<const N: usize, CiphertextSpaceGroupElement: group::GroupElement>
    StatementAccessors<N, CiphertextSpaceGroupElement>
    for direct_product::GroupElement<
        CiphertextSpaceGroupElement,
        self_product::GroupElement<N, CiphertextSpaceGroupElement>,
    >
{
    fn encryption_of_multiplicand(&self) -> &CiphertextSpaceGroupElement {
        let (encryption_of_multiplicand, _) = self.into();

        encryption_of_multiplicand
    }

    fn encryption_of_product(&self) -> &self_product::GroupElement<N, CiphertextSpaceGroupElement> {
        let (_, encryption_of_product) = self.into();

        encryption_of_product
    }
}
