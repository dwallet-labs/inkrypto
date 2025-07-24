// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use core::fmt::Debug;
use std::{array, marker::PhantomData, ops::Mul};

use serde::{Deserialize, Serialize};

use group::{
    helpers::{const_generic_array_serialization, FlatMapResults},
    self_product, BoundedGroupElement, HashToGroup, PrimeGroupElement, Samplable,
};

use crate::{GroupsPublicParameters, GroupsPublicParametersAccessors, HomomorphicCommitmentScheme};

/// A Batched Pedersen Commitment:
/// $$\Com_\pp(m;\rho):=\Ped.\Com_{\GG,G,H,q}(\vec{m},\rho)=
/// m_1\cdot G_1 + \ldots + m_n\cdot G_n + \rho \cdot H$$
///
/// The public parameters [`PublicParameters`] for pedersen commitment should be carefully
/// constructed, as wrong choice of generators can break the commitment's binding and/or hiding
/// propert(ies). We offer a safe instantiation for prime-order groups with
/// [`PublicParameters::derive`] using [`HashToGroup`]. Otherwise, it is the responsibility of the
/// caller to assure their group and generator instantiation is sound.
#[derive(PartialEq, Clone, Debug, Eq)]
pub struct Pedersen<
    const BATCH_SIZE: usize,
    const SCALAR_LIMBS: usize,
    Scalar: group::GroupElement,
    GroupElement: group::GroupElement,
> {
    /// The generators used for the messages.
    message_generators: [GroupElement; BATCH_SIZE],
    /// The generator used for the randomness.
    randomness_generator: GroupElement,

    _scalar_choice: PhantomData<Scalar>,
}

impl<const BATCH_SIZE: usize, const SCALAR_LIMBS: usize, Scalar, GroupElement>
    HomomorphicCommitmentScheme<SCALAR_LIMBS>
    for Pedersen<BATCH_SIZE, SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: BoundedGroupElement<SCALAR_LIMBS>
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Samplable
        + Copy,
    GroupElement: group::GroupElement,
{
    type MessageSpaceGroupElement = self_product::GroupElement<BATCH_SIZE, Scalar>;
    type RandomnessSpaceGroupElement = Scalar;
    type CommitmentSpaceGroupElement = GroupElement;
    type PublicParameters = PublicParameters<
        BATCH_SIZE,
        GroupElement::Value,
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
    >;

    fn new(public_parameters: &Self::PublicParameters) -> crate::Result<Self> {
        if BATCH_SIZE == 0 {
            return Err(crate::Error::InvalidPublicParameters);
        }

        let message_generators = public_parameters
            .message_generators
            .map(|value| {
                GroupElement::new(
                    value,
                    public_parameters.commitment_space_public_parameters(),
                )
            })
            .flat_map_results()?;

        let randomness_generator = GroupElement::new(
            public_parameters.randomness_generator,
            public_parameters.commitment_space_public_parameters(),
        )?;

        if message_generators
            .iter()
            .any(|generator| bool::from(generator.is_neutral()))
            || bool::from(randomness_generator.is_neutral())
        {
            return Err(crate::Error::InvalidPublicParameters);
        }

        Ok(Self {
            message_generators,
            randomness_generator,
            _scalar_choice: PhantomData,
        })
    }

    fn commit(
        &self,
        message: &self_product::GroupElement<BATCH_SIZE, Scalar>,
        randomness: &Scalar,
    ) -> GroupElement {
        // $$\Com_\pp(m;\rho):=\Ped.\Com_{\GG,G,H,q}(\vec{m},\rho)=m_1\cdot G_1 + \ldots + m_n\cdot
        // G_n + \rho \cdot H$$.
        self.message_generators
            .iter()
            .zip::<&[Scalar; BATCH_SIZE]>(message.into())
            .fold(
                self.randomness_generator.neutral(),
                |acc, (generator, value)| acc + (*value * generator),
            )
            + (*randomness * self.randomness_generator)
    }
}

pub type MessageSpaceGroupElement<const BATCH_SIZE: usize, Scalar> =
    self_product::GroupElement<BATCH_SIZE, Scalar>;
pub type MessageSpacePublicParameters<const BATCH_SIZE: usize, Scalar> =
    group::PublicParameters<MessageSpaceGroupElement<BATCH_SIZE, Scalar>>;
pub type RandomnessSpaceGroupElement<Scalar> = Scalar;
pub type RandomnessSpacePublicParameters<Scalar> =
    group::PublicParameters<RandomnessSpaceGroupElement<Scalar>>;
pub type CommitmentSpaceGroupElement<GroupElement> = GroupElement;
pub type CommitmentSpacePublicParameters<GroupElement> =
    group::PublicParameters<CommitmentSpaceGroupElement<GroupElement>>;

/// The Public Parameters of a Pedersen Commitment.
///
/// This struct should be carefully instantiated,
/// as wrong choice of generators can break the commitment's binding and/or hiding propert(ies).
/// We offer a safe instantiation for prime-order groups with [`PublicParameters::derive`] using
/// `HashToGroup`. Otherwise, it is on the responsibility of the caller to assure their group and
/// generator instantiation is sound.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct PublicParameters<
    const BATCH_SIZE: usize,
    GroupElementValue,
    ScalarPublicParameters,
    GroupPublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
    #[serde(with = "const_generic_array_serialization")]
    pub message_generators: [GroupElementValue; BATCH_SIZE],
    pub randomness_generator: GroupElementValue,
}

impl<
        const BATCH_SIZE: usize,
        GroupElementValue: Clone,
        ScalarPublicParameters: Clone,
        GroupPublicParameters: Clone,
    >
    PublicParameters<BATCH_SIZE, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
{
    pub fn derive_default<const SCALAR_LIMBS: usize, GroupElement>() -> crate::Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
        ScalarPublicParameters: Default,
        GroupPublicParameters: Default,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + HashToGroup,
    {
        Self::derive::<SCALAR_LIMBS, GroupElement>(
            ScalarPublicParameters::default(),
            GroupPublicParameters::default(),
        )
    }

    pub fn derive<const SCALAR_LIMBS: usize, GroupElement>(
        scalar_public_parameters: group::PublicParameters<GroupElement::Scalar>,
        group_public_parameters: group::PublicParameters<GroupElement>,
    ) -> crate::Result<Self>
    where
        GroupElement::Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>,
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + PrimeGroupElement<SCALAR_LIMBS>
            + HashToGroup,
    {
        let message_generators = array::from_fn(|i| {
            if i == 0 {
                GroupElement::generator_from_public_parameters(&group_public_parameters)
            } else {
                GroupElement::hash_to_group(
                    format!("commitment/pedersen: message generator #{:?}", i).as_bytes(),
                )
            }
        })
        .flat_map_results()?;

        let message_generators = message_generators.map(|element| element.value());

        let randomness_generator =
            GroupElement::hash_to_group("commitment/pedersen: randomness generator".as_bytes())?
                .value();

        Ok(
            Self::new::<SCALAR_LIMBS, GroupElement::Scalar, GroupElement>(
                scalar_public_parameters,
                group_public_parameters,
                message_generators,
                randomness_generator,
            ),
        )
    }

    /// This function allows using custom Pedersen generators, which is extremely unsafe unless you
    /// know exactly what you're doing.
    ///
    /// It should be used, for example, for non-`PrimeGroupElement`
    /// groups for which security must be analized independently.
    ///
    /// Another use-case is for compatability reason, i.e. when needing to work with
    /// generators that were derived safely elsewhere.
    ///
    /// In any other case, when possible, e.g. for all traditional use-cases such as Pedersen over
    /// elliptic curves, use [`Self::derive`] or [`Self::derive_default`] instead.
    pub fn new<const SCALAR_LIMBS: usize, Scalar, GroupElement>(
        scalar_public_parameters: group::PublicParameters<Scalar>,
        group_public_parameters: group::PublicParameters<GroupElement>,
        message_generators: [group::Value<GroupElement>; BATCH_SIZE],
        randomness_generator: group::Value<GroupElement>,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + BoundedGroupElement<SCALAR_LIMBS>
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Samplable
            + Copy,
        GroupElement: group::GroupElement<Value = GroupElementValue, PublicParameters = GroupPublicParameters>
            + group::GroupElement,
        Scalar: group::GroupElement,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                message_space_public_parameters: self_product::PublicParameters::new(
                    scalar_public_parameters.clone(),
                ),
                randomness_space_public_parameters: scalar_public_parameters,
                commitment_space_public_parameters: group_public_parameters,
            },
            message_generators,
            randomness_generator,
        }
    }

    pub fn with_altered_message_generators(
        &self,
        message_generators: [GroupElementValue; BATCH_SIZE],
    ) -> Self {
        Self {
            groups_public_parameters: self.groups_public_parameters.clone(),
            message_generators,
            randomness_generator: self.randomness_generator.clone(),
        }
    }

    pub fn with_altered_randomness_generator(
        &self,
        randomness_generator: GroupElementValue,
    ) -> Self {
        Self {
            groups_public_parameters: self.groups_public_parameters.clone(),
            message_generators: self.message_generators.clone(),
            randomness_generator,
        }
    }
}

impl<const BATCH_SIZE: usize, GroupElementValue, ScalarPublicParameters, GroupPublicParameters>
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
            ScalarPublicParameters,
            GroupPublicParameters,
        >,
    >
    for PublicParameters<
        BATCH_SIZE,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<BATCH_SIZE, ScalarPublicParameters>,
        ScalarPublicParameters,
        GroupPublicParameters,
    > {
        &self.groups_public_parameters
    }
}

#[cfg(test)]
mod tests {
    use bulletproofs::PedersenGens;
    use rand_core::OsRng;

    use group::ristretto;

    use super::*;

    #[test]
    fn commits() {
        let scalar_public_parameters = ristretto::scalar::PublicParameters::default();
        let group_public_parameters = ristretto::group_element::PublicParameters::default();

        let message = ristretto::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();
        let randomness = ristretto::Scalar::sample(&scalar_public_parameters, &mut OsRng).unwrap();

        let commitment_generators = PedersenGens::default();

        let commitment_scheme_public_parameters = crate::PublicParameters::<
            { ristretto::SCALAR_LIMBS },
            Pedersen<1, { ristretto::SCALAR_LIMBS }, ristretto::Scalar, ristretto::GroupElement>,
        >::new::<
            { ristretto::SCALAR_LIMBS },
            ristretto::Scalar,
            ristretto::GroupElement,
        >(
            scalar_public_parameters,
            group_public_parameters,
            [commitment_generators.B.compress().try_into().unwrap()],
            commitment_generators
                .B_blinding
                .compress()
                .try_into()
                .unwrap(),
        );

        let commitment_scheme = Pedersen::<
            1,
            { ristretto::SCALAR_LIMBS },
            ristretto::Scalar,
            ristretto::GroupElement,
        >::new(&commitment_scheme_public_parameters)
        .unwrap();

        let expected_commitment = commitment_generators.commit(message.into(), randomness.into());

        let commitment = commitment_scheme
            .commit(&([message].into()), &randomness)
            .into();

        assert_eq!(expected_commitment, commitment)
    }

    #[test]
    fn test_homomorphic_commitment_scheme() {
        let public_parameters = PublicParameters::derive_default::<
            { group::secp256k1::SCALAR_LIMBS },
            group::secp256k1::GroupElement,
        >()
        .unwrap();

        crate::test_helpers::test_homomorphic_commitment_scheme::<
            { group::secp256k1::SCALAR_LIMBS },
            Pedersen<
                3,
                { group::secp256k1::SCALAR_LIMBS },
                group::secp256k1::Scalar,
                group::secp256k1::GroupElement,
            >,
        >(&public_parameters);
    }
}
