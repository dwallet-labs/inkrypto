// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
use std::marker::PhantomData;

use crypto_bigint::{Encoding, Uint};
use serde::{Deserialize, Serialize};

use crate::{Error, SOUND_PROOFS_REPETITIONS};
use group::{
    bounded_natural_numbers_group, direct_product, GroupElement, KnownOrderGroupElement,
    PrimeGroupElement,
};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use homomorphic_encryption::GroupsPublicParametersAccessors as _;
use proof::GroupsPublicParameters;

/// Scaling of a Discrete Log Maurer Language
///
/// SECURITY NOTICE:
/// This language implicitly assumes that the plaintext space of the encryption scheme and the
/// scalar group coincide (same exponent) like class-groups. Using generic encryption schemes is permitted if and only
/// if we use this language in its enhanced form, i.e., `enhanced_maurer::EnhancedLanguage`.
///
/// SECURITY NOTICE (2):
/// Furthermore, even when using `EnhancedLanguage`, note that `ENC_DH` proves a correct computation
/// that is not a secure function evaluation. That is, the result is unsafe to decrypt, as it does
/// not hide the number of arithmetic reductions mod q. For secure function evaluation, use
/// `DComEval` (enhanced) language. Because correctness and zero-knowledge is guaranteed for any
/// group and additively homomorphic encryption scheme in this language, we choose to provide a
/// fully generic implementation.
///
/// However, knowledge-soundness proofs are group and encryption scheme-dependent, and thus we can
/// only ensure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
///
/// Regarding additively homomorphic encryption schemes, we proved it for `paillier` and `class_groups`.
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

/// The Witness Space Group Element of the Scaling of a Discrete Log Maurer Language.
pub type WitnessSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    EncryptionKey,
> = direct_product::GroupElement<
    bounded_natural_numbers_group::GroupElement<MESSAGE_LIMBS>,
    homomorphic_encryption::RandomnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
>;

/// The Statement Space Group Element of the Scaling of a Discrete Log Maurer Language.
pub type StatementSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = direct_product::GroupElement<
    homomorphic_encryption::CiphertextSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    GroupElement,
>;

/// The Public Parameters of the Scaling of a Discrete Log Maurer Language.
/// The `lower_bound` of `ciphertext` should be verified independently,
/// e.g., by verifying (and following) a sequence of enhanced proofs over the homomorphic
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
    group::PublicParameters<GroupElement>,
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
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
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

    type StatementSpaceGroupElement = StatementSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >;

    type PublicParameters = PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey,
    >;

    const NAME: &'static str = "Scaling of a Discrete Log";

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

        let generator = GroupElement::generator_from_public_parameters(
            language_public_parameters.group_public_parameters(),
        )?;

        let base_by_discrete_log = generator.scale(&witness.discrete_log().value());

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)
                .map_err(|_| Error::InvalidPublicParameters)?;

        let ciphertext = homomorphic_encryption::CiphertextSpaceGroupElement::<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            EncryptionKey,
        >::new(
            language_public_parameters.ciphertext,
            language_public_parameters
                .encryption_scheme_public_parameters
                .ciphertext_space_public_parameters(),
        )?;

        // No masking of the plaintext is needed, as we don't need secure function evaluation.
        // However, we do want to re-randomize the ciphertext when doing the scalar multiplication,
        // to ensure circuit privacy against an adversary that does not hold the private key, that
        // is, the centralised party A.
        let mask = EncryptionKey::PlaintextSpaceGroupElement::neutral_from_public_parameters(
            language_public_parameters
                .encryption_scheme_public_parameters
                .plaintext_space_public_parameters(),
        )?;

        let scaled_ciphertext = encryption_key
            .securely_evaluate_linear_combination_with_randomness(
                &[witness.discrete_log().value()],
                [(ciphertext, language_public_parameters.upper_bound)],
                &group_order,
                &mask,
                witness.randomness(),
                &language_public_parameters.encryption_scheme_public_parameters,
            )
            .map_err(|_| Error::InvalidPublicParameters)?;

        Ok((scaled_ciphertext, base_by_discrete_log).into())
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
        GroupPublicParameters,
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
            direct_product::PublicParameters<
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
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
        GroupPublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
    >
    for private::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        ScalarPublicParameters,
        GroupPublicParameters,
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
        direct_product::PublicParameters<
            bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters,
        CiphertextSpaceValue,
    >
    private::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        ScalarPublicParameters,
        GroupPublicParameters,
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
        group_public_parameters: GroupPublicParameters,
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
                )
                    .into(),
                statement_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                    group_public_parameters,
                )
                    .into(),
            },
            scalar_group_public_parameters,
            encryption_scheme_public_parameters,
            ciphertext,
            upper_bound,
        })
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        group_public_parameters
    }

    pub fn message_group_public_parameters(
        &self,
    ) -> &bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS> {
        let (message_group_public_parameters, _) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        message_group_public_parameters
    }
}

pub trait WitnessAccessors<
    MessageGroupElement: GroupElement,
    RandomnessSpaceGroupElement: GroupElement,
>
{
    fn discrete_log(&self) -> &MessageGroupElement;

    fn randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        MessageGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<MessageGroupElement, RandomnessSpaceGroupElement>
    for direct_product::GroupElement<MessageGroupElement, RandomnessSpaceGroupElement>
{
    fn discrete_log(&self) -> &MessageGroupElement {
        let (discrete_log, _): (&_, &_) = self.into();

        discrete_log
    }

    fn randomness(&self) -> &RandomnessSpaceGroupElement {
        let (_, randomness): (&_, &_) = self.into();

        randomness
    }
}

pub trait StatementAccessors<
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    fn scaled_ciphertext(&self) -> &CiphertextSpaceGroupElement;

    fn base_by_discrete_log(&self) -> &GroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement, GroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>
{
    fn scaled_ciphertext(&self) -> &CiphertextSpaceGroupElement {
        let (scaled_ciphertext, _): (&_, &_) = self.into();

        scaled_ciphertext
    }

    fn base_by_discrete_log(&self) -> &GroupElement {
        let (_, base_by_discrete_log): (&_, &_) = self.into();

        base_by_discrete_log
    }
}
