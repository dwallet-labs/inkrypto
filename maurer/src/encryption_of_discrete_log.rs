// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::marker::PhantomData;

use crypto_bigint::{NonZero, Uint};
use serde::Serialize;

use commitment::Error;
use group::{direct_product, GroupElement, KnownOrderGroupElement, Reduce, Samplable, Scale};
use homomorphic_encryption::{AdditivelyHomomorphicEncryptionKey, GroupsPublicParametersAccessors};
use proof::GroupsPublicParameters;

use crate::SOUND_PROOFS_REPETITIONS;

/// Encryption of Discrete Log Maurer Language
///
/// SECURITY NOTICE:
/// This language implicitly assumes that the plaintext space of the encryption scheme and the
/// scalar group coincide (same exponent) like class-groups. Using generic encryption schemes is permitted if and only
/// if we use this language in its enhanced form, i.e. `enhanced_maurer::EnhancedLanguage`.
///
/// Because correctness and zero-knowledge is guaranteed for any group and additively homomorphic
/// encryption scheme in this language, we choose to provide a fully generic
/// implementation.
///
/// However knowledge-soundness proofs are group and encryption scheme dependent, and thus we can
/// only assure security for groups and encryption schemes for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
///
/// In regards to additively homomorphic encryption schemes, we proved it for `paillier` and `class_groups`.
#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DISCRETE_LOG_LIMBS: usize,
    DiscreteLogGroupElement,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _discrete_log_group_element_choice: PhantomData<DiscreteLogGroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Witness Space Group Element of the Encryption of Discrete Log Maurer Language.
pub type WitnessSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    DiscreteLogGroupElement,
    EncryptionKey,
> = direct_product::GroupElement<
    DiscreteLogGroupElement,
    homomorphic_encryption::RandomnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
>;

/// The Statement Space Group Element of the Encryption of Discrete Log Maurer Language.
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

/// The Public Parameters of the Encryption of Discrete Log Maurer Language.
pub type PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DISCRETE_LOG_LIMBS: usize,
    DiscreteLogGroupElement,
    GroupElement,
    EncryptionKey,
> = private::PublicParameters<
    group::PublicParameters<DiscreteLogGroupElement>,
    group::PublicParameters<GroupElement>,
    group::Value<GroupElement>,
    homomorphic_encryption::RandomnessSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::CiphertextSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
>;

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const DISCRETE_LOG_LIMBS: usize,
        DiscreteLogGroupElement: group::BoundedGroupElement<DISCRETE_LOG_LIMBS> + Samplable,
        GroupElement: group::GroupElement,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DISCRETE_LOG_LIMBS,
        DiscreteLogGroupElement,
        GroupElement,
        EncryptionKey,
    >
where
    GroupElement: Scale<DiscreteLogGroupElement::Value>,
    DiscreteLogGroupElement::Value: Reduce<PLAINTEXT_SPACE_SCALAR_LIMBS>,
{
    type WitnessSpaceGroupElement = WitnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        DiscreteLogGroupElement,
        EncryptionKey,
    >;

    type StatementSpaceGroupElement = StatementSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >;

    type PublicParameters = PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DISCRETE_LOG_LIMBS,
        DiscreteLogGroupElement,
        GroupElement,
        EncryptionKey,
    >;

    const NAME: &'static str = "Encryption of Discrete Log";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self::StatementSpaceGroupElement> {
        let base = GroupElement::new(
            language_public_parameters.base,
            language_public_parameters.group_public_parameters(),
        )?;

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)
                .map_err(|_| crate::Error::InvalidPublicParameters)?;

        let plaintext_space_order =
            EncryptionKey::PlaintextSpaceGroupElement::order_from_public_parameters(
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            );
        let plaintext_space_order = NonZero::new(plaintext_space_order)
            .into_option()
            .ok_or(Error::InvalidPublicParameters)?;

        let discrete_log = witness.discrete_log().value();
        let discrete_log_reduced_modulo_plaintext_order =
            discrete_log.reduce(&plaintext_space_order);
        let discrete_log_as_plaintext_group_element =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                discrete_log_reduced_modulo_plaintext_order.into(),
                language_public_parameters
                    .encryption_scheme_public_parameters
                    .plaintext_space_public_parameters(),
            )?;

        let encryption_of_discrete_log = encryption_key.encrypt_with_randomness(
            &discrete_log_as_plaintext_group_element,
            witness.randomness(),
            &language_public_parameters.encryption_scheme_public_parameters,
        );

        let discrete_log_upper_bound_bits = language_public_parameters
            .discrete_log_upper_bound_bits
            .unwrap_or(Uint::<DISCRETE_LOG_LIMBS>::BITS);
        let base_by_discrete_log =
            base.scale_bounded_generic(&discrete_log, discrete_log_upper_bound_bits);

        Ok((encryption_of_discrete_log, base_by_discrete_log).into())
    }
}

pub(super) mod private {
    use super::*;
    use proof::GroupsPublicParameters;

    #[derive(Clone, Debug, PartialEq, Serialize, Eq)]
    pub struct PublicParameters<
        DiscreteLogGroupElementPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    > {
        pub groups_public_parameters: GroupsPublicParameters<
            direct_product::PublicParameters<
                DiscreteLogGroupElementPublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        pub base: GroupElementValue,
        pub discrete_log_upper_bound_bits: Option<u32>,
    }
}

impl<
        DiscreteLogGroupElementPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::PublicParameters<
                DiscreteLogGroupElementPublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                GroupPublicParameters,
            >,
        >,
    >
    for private::PublicParameters<
        DiscreteLogGroupElementPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            DiscreteLogGroupElementPublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<CiphertextSpacePublicParameters, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

impl<
        DiscreteLogGroupElementPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        EncryptionKeyPublicParameters,
    >
    private::PublicParameters<
        DiscreteLogGroupElementPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        EncryptionKeyPublicParameters,
    >
{
    pub fn new<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        EncryptionKey,
    >(
        discrete_log_public_parameters: DiscreteLogGroupElementPublicParameters,
        group_public_parameters: GroupPublicParameters,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        base: GroupElementValue,
        discrete_log_upper_bound_bits: Option<u32>,
    ) -> Self
    where
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
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    discrete_log_public_parameters,
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
            encryption_scheme_public_parameters,
            base,
            discrete_log_upper_bound_bits,
        }
    }

    pub fn discrete_log_public_parameters(&self) -> &DiscreteLogGroupElementPublicParameters {
        let (discrete_log_public_parameters, _) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        discrete_log_public_parameters
    }

    pub fn randomness_space_public_parameters(&self) -> &RandomnessSpacePublicParameters {
        let (_, randomness_space_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        randomness_space_public_parameters
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        group_public_parameters
    }
}

pub trait WitnessAccessors<
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement;

    fn randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    > WitnessAccessors<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
    for direct_product::GroupElement<PlaintextSpaceGroupElement, RandomnessSpaceGroupElement>
{
    fn discrete_log(&self) -> &PlaintextSpaceGroupElement {
        let (plaintext, _): (&_, &_) = self.into();

        plaintext
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
    fn encryption_of_discrete_log(&self) -> &CiphertextSpaceGroupElement;

    fn base_by_discrete_log(&self) -> &GroupElement;
}

impl<CiphertextSpaceGroupElement: group::GroupElement, GroupElement: group::GroupElement>
    StatementAccessors<CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<CiphertextSpaceGroupElement, GroupElement>
{
    fn encryption_of_discrete_log(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn base_by_discrete_log(&self) -> &GroupElement {
        let (_, base_by_discrete_log): (&_, &_) = self.into();

        base_by_discrete_log
    }
}
