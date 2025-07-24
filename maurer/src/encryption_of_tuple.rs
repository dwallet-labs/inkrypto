// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;

use crypto_bigint::{Encoding, NonZero, Uint};
use serde::{Deserialize, Serialize};

use group::direct_product::ThreeWayPublicParameters;
use group::Reduce;
use group::{
    bounded_natural_numbers_group, direct_product, self_product, GroupElement as _,
    KnownOrderGroupElement,
};
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
/// that is not a secure function evaluation. That is, the result is not safe to decrypt, as it does
/// not hide the number of arithmetic reductions mod q. For secure function evaluation, use
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
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier` and `class_groups`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
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
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    EncryptionKey,
> = direct_product::ThreeWayGroupElement<
    bounded_natural_numbers_group::GroupElement<MESSAGE_LIMBS>,
    homomorphic_encryption::RandomnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::RandomnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
>;

/// The Statement Space Group Element of the Encryption of a Tuple Maurer Language.
pub type StatementSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    EncryptionKey,
> = self_product::GroupElement<
    2,
    homomorphic_encryption::CiphertextSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
>;

/// The Public Parameters of the Encryption of a Tuple Maurer Language.
/// The `lower_bound` of `ciphertext` should be verified independently,
/// e.g. by verifying (and following) a sequence of enhanced proofs over the homomorphic
/// computations that yields it.
pub type PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = private::PublicParameters<
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
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<
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
        WitnessSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, MESSAGE_LIMBS, EncryptionKey>;

    type StatementSpaceGroupElement =
        StatementSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, EncryptionKey>;

    type PublicParameters = PublicParameters<
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

        let ciphertext = homomorphic_encryption::CiphertextSpaceGroupElement::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >::new(
            language_public_parameters.ciphertext,
            language_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )?;

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
        );

        // No masking of the plaintext is needed, as we don't need secure function evaluation.
        let mask = EncryptionKey::PlaintextSpaceGroupElement::neutral_from_public_parameters(
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;

        let encryption_of_product = encryption_key
            .securely_evaluate_linear_combination_with_randomness(
                &[witness.multiplicand().value()],
                [(ciphertext, language_public_parameters.upper_bound)],
                &group_order,
                &mask,
                witness.product_randomness(),
                &language_public_parameters.encryption_scheme_public_parameters,
            )
            .map_err(|_| crate::Error::InvalidPublicParameters)?;

        Ok([encryption_of_multiplicand, encryption_of_product].into())
    }
}

pub(super) mod private {
    use crypto_bigint::Encoding;

    use super::*;

    #[derive(Clone, Debug, PartialEq, Serialize, Eq)]
    pub struct PublicParameters<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
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
        pub groups_public_parameters: GroupsPublicParameters<
            ThreeWayPublicParameters<
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                RandomnessSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
        >,
        pub scalar_group_public_parameters: ScalarPublicParameters,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        pub ciphertext: CiphertextSpaceValue,
        pub upper_bound: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    AsRef<
        GroupsPublicParameters<
            ThreeWayPublicParameters<
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                RandomnessSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
        >,
    >
    for private::PublicParameters<
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
            RandomnessSpacePublicParameters,
        >,
        self_product::PublicParameters<2, CiphertextSpacePublicParameters>,
    > {
        &self.groups_public_parameters
    }
}
impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    private::PublicParameters<
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
        ciphertext: CiphertextSpaceValue,
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
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                )
                    .into(),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, EncryptionKey::CiphertextSpaceGroupElement>,
                >::new(
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                ),
            },
            scalar_group_public_parameters,
            encryption_scheme_public_parameters,
            ciphertext,
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

pub trait WitnessAccessors<
    MessageGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn multiplicand(&self) -> &MessageGroupElement;

    fn multiplicand_randomness(&self) -> &RandomnessSpaceGroupElement;

    fn product_randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        MessageGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<MessageGroupElement, RandomnessSpaceGroupElement>
    for direct_product::ThreeWayGroupElement<
        MessageGroupElement,
        RandomnessSpaceGroupElement,
        RandomnessSpaceGroupElement,
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

    fn product_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, _, product_randomness): (&_, &_, &_) = self.into();

        product_randomness
    }
}

pub trait StatementAccessors<CiphertextSpaceGroupElement: group::GroupElement> {
    fn encryption_of_multiplicand(&self) -> &CiphertextSpaceGroupElement;

    fn encryption_of_product(&self) -> &CiphertextSpaceGroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement>
    for self_product::GroupElement<2, CiphertextSpaceGroupElement>
{
    fn encryption_of_multiplicand(&self) -> &CiphertextSpaceGroupElement {
        let value: &[_; 2] = self.into();

        &value[0]
    }

    fn encryption_of_product(&self) -> &CiphertextSpaceGroupElement {
        let value: &[_; 2] = self.into();

        &value[1]
    }
}
