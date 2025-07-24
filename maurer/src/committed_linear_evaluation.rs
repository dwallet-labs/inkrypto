// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0
#![allow(clippy::type_complexity)]

use std::marker::PhantomData;

use crypto_bigint::{Encoding, NonZero, Uint};
use serde::{Deserialize, Serialize};

use commitment::{HomomorphicCommitmentScheme, MultiPedersen};
use group::bounded_natural_numbers_group::MAURER_RANDOMIZER_DIFF_BITS;
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

/// Committed Linear Evaluation Maurer Language
///
/// This language allows to prove a linear combination have been homomorphically evaluated on a
/// vector of ciphertexts. If one wishes to prove an affine evaluation instead of a linear one,
/// as is required in the paper, the first ciphertexts should be set to an encryption of one with
/// randomness zero ($\Enc(1; 0)$). This would allow the first coefficient to be evaluated as the
/// free variable of an affine transformation.
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
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> {
    _group_element_choice: PhantomData<GroupElement>,
    _encryption_key_choice: PhantomData<EncryptionKey>,
}

/// The Witness Space Group Element of the Committed Linear Evaluation Maurer Language
pub type WitnessSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> = direct_product::FourWayGroupElement<
    self_product::GroupElement<
        DIMENSION,
        bounded_natural_numbers_group::GroupElement<MESSAGE_LIMBS>,
    >,
    self_product::GroupElement<DIMENSION, group::Scalar<SCALAR_LIMBS, GroupElement>>,
    homomorphic_encryption::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    homomorphic_encryption::RandomnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
>;

/// The Statement Space Group Element Committed Linear Evaluation Maurer Language.
pub type StatementSpaceGroupElement<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> = direct_product::GroupElement<
    homomorphic_encryption::CiphertextSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    self_product::GroupElement<DIMENSION, GroupElement>,
>;

/// The Public Parameters of the Committed Linear Evaluation Maurer Language.
///
/// In order to prove an affine transformation, set `ciphertexts[0]` to an encryption of one with
/// randomness zero ($\Enc(1; 0)$).
///
/// The corresponding `lower_bounds` in `ciphertexts_and_lower_bounds` should be verified
/// independently, e.g. by verifying (and following) a sequence of enhanced proofs over the
/// homomorphic computations that yields them.
pub type PublicParameters<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    const DIMENSION: usize,
    GroupElement,
    EncryptionKey,
> = private::PublicParameters<
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    MESSAGE_LIMBS,
    DIMENSION,
    group::PublicParameters<group::Scalar<SCALAR_LIMBS, GroupElement>>,
    group::PublicParameters<GroupElement>,
    group::Value<GroupElement>,
    homomorphic_encryption::PlaintextSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::RandomnessSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::CiphertextSpacePublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    homomorphic_encryption::CiphertextSpaceValue<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    homomorphic_encryption::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
>;

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
        GroupElement: KnownOrderGroupElement<SCALAR_LIMBS>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    > crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    type WitnessSpaceGroupElement = WitnessSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    type StatementSpaceGroupElement = StatementSpaceGroupElement<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    type PublicParameters = PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >;

    const NAME: &'static str = "Committed Linear Evaluation";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
        is_randomizer: bool,
        is_verify: bool,
    ) -> crate::Result<Self::StatementSpaceGroupElement> {
        if SCALAR_LIMBS > PLAINTEXT_SPACE_SCALAR_LIMBS {
            return Err(Error::InvalidPublicParameters);
        }

        let group_order = GroupElement::Scalar::order_from_public_parameters(
            language_public_parameters.scalar_group_public_parameters(),
        );

        let encryption_key =
            EncryptionKey::new(&language_public_parameters.encryption_scheme_public_parameters)
                .map_err(|_| crate::Error::InvalidPublicParameters)?;

        let commitment_scheme =
            MultiPedersen::new(&language_public_parameters.commitment_scheme_public_parameters)
                .map_err(|_| crate::Error::InvalidPublicParameters)?;

        let ciphertexts_and_encoded_messages_upper_bounds = language_public_parameters
            .ciphertexts_and_encoded_messages_upper_bounds
            .map(|(value, upper_bound)| {
                homomorphic_encryption::CiphertextSpaceGroupElement::<
                    PLAINTEXT_SPACE_SCALAR_LIMBS,
                    EncryptionKey,
                >::new(
                    value,
                    language_public_parameters
                        .encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters(),
                )
                .map(|ciphertext| (ciphertext, upper_bound))
                .map_err(|_| crate::Error::InvalidPublicParameters)
            })
            .flat_map_results()?;

        let coefficients: &[_; DIMENSION] = witness.coefficients().into();
        let coefficients: [Uint<MESSAGE_LIMBS>; DIMENSION] =
            coefficients.map(|coefficient| coefficient.value());

        let coefficient_upper_bound_bits: u32 = if is_verify {
            *coefficients
                .map(|coefficient| coefficient.bits_vartime())
                .iter()
                .max()
                .ok_or(Error::InvalidParameters)?
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

        let evaluated_ciphertext = encryption_key
            .securely_evaluate_linear_combination_with_randomness(
                &coefficients,
                coefficient_upper_bound_bits,
                ciphertexts_and_encoded_messages_upper_bounds,
                &((&group_order).into()),
                witness.mask(),
                witness.encryption_randomness(),
                &language_public_parameters.encryption_scheme_public_parameters,
                is_verify,
            )
            .map_err(|_| crate::Error::InvalidPublicParameters)?;

        let coefficients: [_; DIMENSION] = (*witness.coefficients()).into();

        let group_order = Option::<_>::from(NonZero::new(group_order))
            .ok_or(crate::Error::InternalError)
            .map_err(|_| crate::Error::InvalidPublicParameters)?;

        let coefficients = coefficients
            .map(|coefficient| {
                let coefficient = coefficient.value().reduce(&group_order).into();

                GroupElement::Scalar::new(
                    coefficient,
                    language_public_parameters.scalar_group_public_parameters(),
                )
                .map_err(|_| crate::Error::InvalidPublicParameters)
            })
            .flat_map_results()?;

        let commitment =
            commitment_scheme.commit(&coefficients.into(), witness.commitment_randomness());

        Ok((evaluated_ciphertext, commitment).into())
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters,
    >
    AsRef<
        GroupsPublicParameters<
            direct_product::FourWayPublicParameters<
                self_product::PublicParameters<
                    DIMENSION,
                    bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                >,
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
            >,
        >,
    >
    for private::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::FourWayPublicParameters<
            self_product::PublicParameters<
                DIMENSION,
                bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
            >,
            self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        direct_product::PublicParameters<
            CiphertextSpacePublicParameters,
            self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
        >,
    > {
        &self.groups_public_parameters
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters: Clone,
        RandomnessSpacePublicParameters: Clone,
        CiphertextSpacePublicParameters: Clone,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters: AsRef<
            homomorphic_encryption::GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    >
    private::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    pub fn new<const SCALAR_LIMBS: usize, GroupElement, EncryptionKey>(
        scalar_group_public_parameters: ScalarPublicParameters,
        group_public_parameters: GroupPublicParameters,
        encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        commitment_scheme_public_parameters: commitment::PublicParameters<
            SCALAR_LIMBS,
            MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >,
        ciphertexts_and_encoded_messages_upper_bounds: [(
            homomorphic_encryption::CiphertextSpaceValue<
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                EncryptionKey,
            >,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        coefficient_sample_bits: u32,
    ) -> crate::Result<Self>
    where
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + KnownOrderGroupElement<SCALAR_LIMBS>,
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PublicParameters = EncryptionKeyPublicParameters,
        >,
        EncryptionKey::PlaintextSpaceGroupElement:
            group::GroupElement<PublicParameters = PlaintextSpacePublicParameters>,
        EncryptionKey::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        EncryptionKey::CiphertextSpaceGroupElement: group::GroupElement<
            Value = CiphertextSpaceValue,
            PublicParameters = CiphertextSpacePublicParameters,
        >,
    {
        let message_group_public_parameters =
            bounded_natural_numbers_group::PublicParameters::new_with_randomizer_upper_bound(
                coefficient_sample_bits,
            )?;

        Ok(Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: (
                    self_product::PublicParameters::<DIMENSION, _>::new(
                        message_group_public_parameters,
                    ),
                    self_product::PublicParameters::<DIMENSION, _>::new(
                        scalar_group_public_parameters,
                    ),
                    encryption_scheme_public_parameters
                        .plaintext_space_public_parameters()
                        .clone(),
                    encryption_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                )
                    .into(),
                statement_space_public_parameters: (
                    encryption_scheme_public_parameters
                        .ciphertext_space_public_parameters()
                        .clone(),
                    self_product::PublicParameters::<DIMENSION, _>::new(group_public_parameters),
                )
                    .into(),
            },
            encryption_scheme_public_parameters,
            commitment_scheme_public_parameters,
            ciphertexts_and_encoded_messages_upper_bounds,
        })
    }

    pub fn plaintext_space_public_parameters(&self) -> &PlaintextSpacePublicParameters {
        let (_, _, plaintext_space_public_parameters, _): (&_, &_, &_, &_) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        plaintext_space_public_parameters
    }

    pub fn randomness_space_public_parameters(&self) -> &RandomnessSpacePublicParameters {
        let (_, randomness_space_public_parameters) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        randomness_space_public_parameters
    }

    pub fn scalar_group_public_parameters(&self) -> &ScalarPublicParameters {
        let (_, scalar_group_public_parameters, ..): (&_, &_, &_, &_) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        &scalar_group_public_parameters.0
    }

    pub fn group_public_parameters(&self) -> &GroupPublicParameters {
        let (_, group_public_parameters) = (&self
            .groups_public_parameters
            .statement_space_public_parameters)
            .into();

        &group_public_parameters.0
    }

    pub fn message_group_public_parameters(
        &self,
    ) -> &bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS> {
        let (message_group_public_parameters, _, _, _) = (&self
            .groups_public_parameters
            .witness_space_public_parameters)
            .into();

        &message_group_public_parameters.0
    }
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
        GroupElementValue: Serialize,
        PlaintextSpacePublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters: Transcribeable,
    > Transcribeable
    for private::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    type CanonicalRepresentation = private::CanonicalPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >;
}

impl<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
        GroupElementValue: Serialize,
        PlaintextSpacePublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters: Transcribeable,
    >
    From<
        private::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            DIMENSION,
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
            CiphertextSpaceValue,
            EncryptionKeyPublicParameters,
        >,
    >
    for private::CanonicalPublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        MESSAGE_LIMBS,
        DIMENSION,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue,
        EncryptionKeyPublicParameters,
    >
where
    Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    fn from(
        value: private::PublicParameters<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            MESSAGE_LIMBS,
            DIMENSION,
            ScalarPublicParameters,
            GroupPublicParameters,
            GroupElementValue,
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
            CiphertextSpaceValue,
            EncryptionKeyPublicParameters,
        >,
    ) -> Self {
        Self {
            canonical_groups_public_parameters: value.groups_public_parameters.into(),
            canonical_encryption_scheme_public_parameters: value
                .encryption_scheme_public_parameters
                .into(),
            canonical_commitment_scheme_public_parameters: value
                .commitment_scheme_public_parameters
                .into(),
            ciphertexts_and_encoded_messages_upper_bounds: value
                .ciphertexts_and_encoded_messages_upper_bounds,
        }
    }
}

pub trait WitnessAccessors<
    const DIMENSION: usize,
    Scalar: group::GroupElement,
    MessageGroupElement: group::GroupElement,
    PlaintextSpaceGroupElement: group::GroupElement,
    RandomnessSpaceGroupElement: group::GroupElement,
>
{
    fn coefficients(&self) -> &self_product::GroupElement<DIMENSION, MessageGroupElement>;

    fn mask(&self) -> &PlaintextSpaceGroupElement;
    fn commitment_randomness(&self) -> &self_product::GroupElement<DIMENSION, Scalar>;
    fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement;
}

impl<
        const DIMENSION: usize,
        Scalar: group::GroupElement,
        MessageGroupElement: group::GroupElement,
        PlaintextSpaceGroupElement: group::GroupElement,
        RandomnessSpaceGroupElement: group::GroupElement,
    >
    WitnessAccessors<
        DIMENSION,
        Scalar,
        MessageGroupElement,
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
    >
    for direct_product::FourWayGroupElement<
        self_product::GroupElement<DIMENSION, MessageGroupElement>,
        self_product::GroupElement<DIMENSION, Scalar>,
        PlaintextSpaceGroupElement,
        RandomnessSpaceGroupElement,
    >
{
    fn coefficients(&self) -> &self_product::GroupElement<DIMENSION, MessageGroupElement> {
        let (coefficients, ..): (&_, &_, &_, &_) = self.into();

        coefficients
    }

    fn mask(&self) -> &PlaintextSpaceGroupElement {
        let (_, _, mask, _): (&_, &_, &_, &_) = self.into();

        mask
    }
    fn commitment_randomness(&self) -> &self_product::GroupElement<DIMENSION, Scalar> {
        let (_, commitment_randomness, ..): (&_, &_, &_, &_) = self.into();

        commitment_randomness
    }
    fn encryption_randomness(&self) -> &RandomnessSpaceGroupElement {
        let (.., encryption_randomness): (&_, &_, &_, &_) = self.into();

        encryption_randomness
    }
}

pub trait StatementAccessors<
    const DIMENSION: usize,
    CiphertextSpaceGroupElement: group::GroupElement,
    GroupElement: group::GroupElement,
>
{
    fn evaluated_ciphertext(&self) -> &CiphertextSpaceGroupElement;

    fn commitments(&self) -> &self_product::GroupElement<DIMENSION, GroupElement>;
}

impl<
        const DIMENSION: usize,
        CiphertextSpaceGroupElement: group::GroupElement,
        GroupElement: group::GroupElement,
    > StatementAccessors<DIMENSION, CiphertextSpaceGroupElement, GroupElement>
    for direct_product::GroupElement<
        CiphertextSpaceGroupElement,
        self_product::GroupElement<DIMENSION, GroupElement>,
    >
{
    fn evaluated_ciphertext(&self) -> &CiphertextSpaceGroupElement {
        let (ciphertext, _): (&_, &_) = self.into();

        ciphertext
    }

    fn commitments(&self) -> &self_product::GroupElement<DIMENSION, GroupElement> {
        let (_, commitments): (&_, &_) = self.into();

        commitments
    }
}

pub(super) mod private {
    use super::*;
    use commitment::multipedersen;
    use group::Transcribeable;
    use proof::CanonicalGroupsPublicParameters;

    #[derive(Clone, Debug, PartialEq, Serialize, Eq)]
    pub struct PublicParameters<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters,
        GroupPublicParameters,
        GroupElementValue,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters,
    >
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        pub groups_public_parameters: GroupsPublicParameters<
            direct_product::FourWayPublicParameters<
                self_product::PublicParameters<
                    DIMENSION,
                    bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                >,
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
            >,
        >,
        pub encryption_scheme_public_parameters: EncryptionKeyPublicParameters,
        pub commitment_scheme_public_parameters: multipedersen::PublicParameters<
            DIMENSION,
            GroupElementValue,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,

        #[serde(with = "group::helpers::const_generic_array_serialization")]
        pub ciphertexts_and_encoded_messages_upper_bounds:
            [(CiphertextSpaceValue, Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>); DIMENSION],
    }

    #[derive(Serialize)]
    pub struct CanonicalPublicParameters<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
        ScalarPublicParameters: Transcribeable + Serialize,
        GroupPublicParameters: Transcribeable + Serialize,
        GroupElementValue: Serialize,
        PlaintextSpacePublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpaceValue: Serialize,
        EncryptionKeyPublicParameters: Transcribeable,
    >
    where
        Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>: Encoding,
        Uint<MESSAGE_LIMBS>: Encoding,
    {
        pub(super) canonical_groups_public_parameters: CanonicalGroupsPublicParameters<
            direct_product::FourWayPublicParameters<
                self_product::PublicParameters<
                    DIMENSION,
                    bounded_natural_numbers_group::PublicParameters<MESSAGE_LIMBS>,
                >,
                self_product::PublicParameters<DIMENSION, ScalarPublicParameters>,
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
            >,
            direct_product::PublicParameters<
                CiphertextSpacePublicParameters,
                self_product::PublicParameters<DIMENSION, GroupPublicParameters>,
            >,
        >,
        pub(super) canonical_encryption_scheme_public_parameters:
            EncryptionKeyPublicParameters::CanonicalRepresentation,
        pub(super) canonical_commitment_scheme_public_parameters:
            multipedersen::CanonicalPublicParameters<
                DIMENSION,
                GroupElementValue,
                ScalarPublicParameters,
                GroupPublicParameters,
            >,

        #[serde(with = "group::helpers::const_generic_array_serialization")]
        pub(super) ciphertexts_and_encoded_messages_upper_bounds:
            [(CiphertextSpaceValue, Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>); DIMENSION],
    }
}
