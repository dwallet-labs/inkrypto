// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use core::fmt::Debug;

use crypto_bigint::{Concat, Limb};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use group::{
    BoundedGroupElement, ComputationalSecuritySizedNumber, GroupElement, PartyID, Samplable,
};
pub use multipedersen::MultiPedersen;
pub use pedersen::Pedersen;

pub mod multipedersen;
pub mod pedersen;

/// Commitment error.
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

/// Commitment result.
pub type Result<T> = std::result::Result<T, Error>;

/// Represents an unsigned integer sized based on the commitment size that matches security
/// parameter, which is double in size, as collisions can be found in the root of the space.
pub type CommitmentSizedNumber = <ComputationalSecuritySizedNumber as Concat>::Output;

#[derive(PartialEq, Debug, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct Commitment(CommitmentSizedNumber);

impl Commitment {
    /// Create a commitment from a transcript that holds the data and, potentially, other context.
    /// Supply a `context` to distinguish commitments between different protocols,
    /// e.g., a string containing the protocol name & round name.
    pub fn commit_transcript(
        party_id: PartyID,
        context: String,
        transcript: &mut Transcript,
        commitment_randomness: &ComputationalSecuritySizedNumber,
    ) -> Self {
        transcript.append_message(b"party ID", party_id.to_le_bytes().as_ref());

        transcript.append_message(b"context", context.as_bytes());

        transcript.append_message(
            b"commitment randomness",
            commitment_randomness.to_le_bytes().as_ref(),
        );

        let mut buf: Vec<u8> = vec![0u8; CommitmentSizedNumber::LIMBS * Limb::BYTES];
        transcript.challenge_bytes(b"commitment", buf.as_mut_slice());

        Commitment(CommitmentSizedNumber::from_le_slice(&buf))
    }
}

/// A Homomorphic Commitment Scheme
///
/// The commitment algorithm of a non-interactive commitment scheme $\Com_{\pp}$
/// defines a function $\calM_{\pp}\times \calR_{\pp} \rightarrow \calC_{\pp}$ for message space
/// $\calM_{\pp}$, randomness space $\calR_{\pp}$ and commitment space $\calC_{\pp}$.
///
/// In a homomorphic commitment $\calM,\calR$ and $\calC$ are all Abelian groups,
/// and for all $\vec{m}_1, \vec{m}_2 \in \calM$, $\rho_1, \rho_2\in \calR$ we have
/// (in the following, `$+$' is defined differently for each group): $$ \Com(\vec{m}_1; \rho_1) +
/// \Com(\vec{m}_2; \rho_2) = \Com(\vec{m}_1 + \vec{m}_2; \rho_1 + \rho_2) $$
///
/// As defined in Definitions 2.4, 2.5 in the paper.
pub trait HomomorphicCommitmentScheme<const MESSAGE_SPACE_SCALAR_LIMBS: usize>:
    PartialEq + Clone + Debug + Eq + Send + Sync
{
    /// The Message space group element of the commitment scheme
    type MessageSpaceGroupElement: BoundedGroupElement<MESSAGE_SPACE_SCALAR_LIMBS> + Samplable;
    /// The Randomness space group element of the commitment scheme
    type RandomnessSpaceGroupElement: GroupElement + Samplable;
    /// The Commitment space group element of the commitment scheme
    type CommitmentSpaceGroupElement: GroupElement;

    /// The public parameters of the commitment scheme $\Com_{\pp}$.
    ///
    /// Includes the public parameters of the message, randomness and commitment groups.
    ///
    /// Used in [`Self::commit()`] to define the commitment algorithm $\Com_{\pp}$.
    /// As such, it uniquely identifies the commitment-scheme (alongside the type `Self`) and will
    /// be used for Fiat-Shamir Transcripts).
    type PublicParameters: AsRef<
            GroupsPublicParameters<
                MessageSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, Self>,
                RandomnessSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, Self>,
                CommitmentSpacePublicParameters<MESSAGE_SPACE_SCALAR_LIMBS, Self>,
            >,
        > + Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + PartialEq
        + Eq
        + Debug
        + Send
        + Sync;

    /// Instantiate the commitment scheme from its public parameters and the commitment space group
    /// public parameters.
    fn new(public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// $\Com_{\pp}$: the commitment function $\calM_{\pp}\times \calR_{\pp} \rightarrow
    /// \calC_{\pp}$ for message space $\calM_{\pp}$, randomness space $\calR_{\pp}$ and
    /// commitment space $\calC_{\pp}$.
    ///
    /// For a message $\vec{m}\in \calM_{\pp}$, the algorithm draws $\rho \gets R_{\pp}$ uniformly
    /// at random, and computes commitment $C = \Com_{\pp}(\vec{m};\rho)$.
    ///
    /// Since this is a homomorphic commitment scheme, we have that $\calM,\calR$ and $\calC$ are
    /// all Abelian groups, and for all $\vec{m}_1, \vec{m}_2 \in \calM$, $\rho_1, \rho_2\in \calR$
    /// we have (in the following, `$+$' is defined differently for each group):
    /// $$ \Com(\vec{m}_1; \rho_1) + \Com(\vec{m}_2; \rho_2) = \Com(\vec{m}_1 + \vec{m}_2; \rho_1 +
    /// \rho_2) $$
    fn commit(
        &self,
        message: &Self::MessageSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
    ) -> Self::CommitmentSpaceGroupElement;
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
> {
    pub message_space_public_parameters: MessageSpacePublicParameters,
    pub randomness_space_public_parameters: RandomnessSpacePublicParameters,
    pub commitment_space_public_parameters: CommitmentSpacePublicParameters,
}

pub trait GroupsPublicParametersAccessors<
    'a,
    MessageSpacePublicParameters: 'a,
    RandomnessSpacePublicParameters: 'a,
    CommitmentSpacePublicParameters: 'a,
>:
    AsRef<
    GroupsPublicParameters<
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    >,
>
{
    fn message_space_public_parameters(&'a self) -> &'a MessageSpacePublicParameters {
        &self.as_ref().message_space_public_parameters
    }

    fn randomness_space_public_parameters(&'a self) -> &'a RandomnessSpacePublicParameters {
        &self.as_ref().randomness_space_public_parameters
    }

    fn commitment_space_public_parameters(&'a self) -> &'a CommitmentSpacePublicParameters {
        &self.as_ref().commitment_space_public_parameters
    }
}

impl<
        'a,
        MessageSpacePublicParameters: 'a,
        RandomnessSpacePublicParameters: 'a,
        CommitmentSpacePublicParameters: 'a,
        T: AsRef<
            GroupsPublicParameters<
                MessageSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CommitmentSpacePublicParameters,
            >,
        >,
    >
    GroupsPublicParametersAccessors<
        'a,
        MessageSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CommitmentSpacePublicParameters,
    > for T
{
}

pub type PublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::PublicParameters;
pub type MessageSpaceGroupElement<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::MessageSpaceGroupElement;
pub type MessageSpacePublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    group::PublicParameters<
        <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::MessageSpaceGroupElement,
    >;
pub type MessageSpaceValue<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> = group::Value<
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::MessageSpaceGroupElement,
>;

pub type RandomnessSpaceGroupElement<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement;
pub type RandomnessSpacePublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    group::PublicParameters<
        <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement,
    >;
pub type RandomnessSpaceValue<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> = group::Value<
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement,
>;
pub type CommitmentSpaceGroupElement<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentSpaceGroupElement;
pub type CommitmentSpacePublicParameters<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> =
    group::PublicParameters<
        <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentSpaceGroupElement,
    >;
pub type CommitmentSpaceValue<const MESSAGE_SPACE_SCALAR_LIMBS: usize, C> = group::Value<
    <C as HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>>::CommitmentSpaceGroupElement,
>;

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use rand_core::OsRng;

    use super::*;

    pub fn test_homomorphic_commitment_scheme<
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
    >(
        public_parameters: &CommitmentScheme::PublicParameters,
    ) {
        let first_message = CommitmentScheme::MessageSpaceGroupElement::sample(
            public_parameters.message_space_public_parameters(),
            &mut OsRng,
        )
        .unwrap();
        let second_message = CommitmentScheme::MessageSpaceGroupElement::sample(
            public_parameters.message_space_public_parameters(),
            &mut OsRng,
        )
        .unwrap();

        let first_randomness = CommitmentScheme::RandomnessSpaceGroupElement::sample(
            public_parameters.randomness_space_public_parameters(),
            &mut OsRng,
        )
        .unwrap();
        let second_randomness = CommitmentScheme::RandomnessSpaceGroupElement::sample(
            public_parameters.randomness_space_public_parameters(),
            &mut OsRng,
        )
        .unwrap();

        let commitment_scheme = CommitmentScheme::new(public_parameters).unwrap();
        let first_commitment = commitment_scheme.commit(&first_message, &first_randomness);
        let second_commitment = commitment_scheme.commit(&second_message, &second_randomness);

        assert_ne!(
            first_commitment, second_commitment,
            "commitments over different messages should differ"
        );
        assert_ne!(
            first_commitment,
            commitment_scheme.commit(&first_message, &second_randomness),
            "commitments over the same message using different randomness should differ"
        );

        assert_eq!(
            first_commitment + second_commitment,
            commitment_scheme.commit(
                &(first_message + second_message),
                &(first_randomness + second_randomness),
            ),
            "commit should be homomorphic"
        );
    }
}
