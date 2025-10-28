// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity, clippy::too_many_arguments)]

use crate::{Error, ProtocolContext, Result};
use commitment::{MultiPedersen, Pedersen};
use crypto_bigint::{Encoding, Int, Uint};
use group::{
    bounded_integers_group, self_product, CsRng, KnownOrderGroupElement, PrimeGroupElement, Scale,
};
use maurer::{
    commitment_of_discrete_log, encryption_of_discrete_log, encryption_of_tuple,
    equality_between_commitments_with_different_public_parameters, knowledge_of_decommitment,
    knowledge_of_discrete_log, language, scaling_of_discrete_log,
    vector_commitment_of_discrete_log, vector_commitment_of_discrete_log::StatementAccessors as _,
    SOUND_PROOFS_REPETITIONS,
};
use maurer::{extended_encryption_of_tuple, UC_PROOFS_REPETITIONS};

pub mod class_groups;

/// The dimension of the Committed Affine Evaluation language used in the signing protocol.
pub const DIMENSION: usize = 2;

/// Knowledge of Discrete Log Maurer Language $L_DCom$.
pub type KnowledgeOfDiscreteLogLanguage<const SCALAR_LIMBS: usize, GroupElement> =
    knowledge_of_discrete_log::Language<
        <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
        GroupElement,
    >;

/// The Public Parameters of the Knowledge of Discrete Log Maurer Language $L_{\textsf{DCom}}$.
pub type KnowledgeOfDiscreteLogPublicParameters<const SCALAR_LIMBS: usize, GroupElement> =
    language::PublicParameters<
        SOUND_PROOFS_REPETITIONS,
        KnowledgeOfDiscreteLogLanguage<SCALAR_LIMBS, GroupElement>,
    >;

/// A Knowledge of Discrete Log Maurer Proof $\Pi_{\textsf{zk}}^{L_{\sf{DL}}[(\mathbb{G},
/// G,q)]}(x\cdot G;x)$
pub type KnowledgeOfDiscreteLogProof<const SCALAR_LIMBS: usize, GroupElement> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    KnowledgeOfDiscreteLogLanguage<SCALAR_LIMBS, GroupElement>,
    ProtocolContext,
>;

/// Knowledge of Discrete Log UC Maurer Language $L_DCom$.
pub type KnowledgeOfDiscreteLogUCLanguage<const SCALAR_LIMBS: usize, GroupElement> =
    knowledge_of_discrete_log::FischlinLanguage<
        UC_PROOFS_REPETITIONS,
        <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
        GroupElement,
    >;

/// The Public Parameters of the Knowledge of Discrete Log UC Maurer Language $L_{\textsf{DCom}}$.
pub type KnowledgeOfDiscreteLogUCPublicParameters<const SCALAR_LIMBS: usize, GroupElement> =
    language::PublicParameters<
        UC_PROOFS_REPETITIONS,
        KnowledgeOfDiscreteLogUCLanguage<SCALAR_LIMBS, GroupElement>,
    >;

/// A Knowledge of Discrete Log UC Maurer Proof $\Pi_{\textsf{zk-uc}}^{L_{\sf{DL}}[(\mathbb{G},
/// G,q)]}(x\cdot G;x)$
pub type KnowledgeOfDiscreteLogUCProof<const SCALAR_LIMBS: usize, GroupElement> =
    maurer::fischlin::Proof<
        UC_PROOFS_REPETITIONS,
        KnowledgeOfDiscreteLogUCLanguage<SCALAR_LIMBS, GroupElement>,
        ProtocolContext,
    >;

/// Knowledge of Decommitment Maurer Language $L_\textsf{{DCom}}$.
pub type KnowledgeOfDecommitmentLanguage<const SCALAR_LIMBS: usize, GroupElement> =
    knowledge_of_decommitment::Language<
        SOUND_PROOFS_REPETITIONS,
        SCALAR_LIMBS,
        Pedersen<
            1,
            SCALAR_LIMBS,
            <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
            GroupElement,
        >,
    >;

/// The Public Parameters of the Knowledge of Decommitment Maurer Language $L_{\textsf{DCom}}$.
pub type KnowledgeOfDecommitmentPublicParameters<const SCALAR_LIMBS: usize, GroupElement> =
    language::PublicParameters<
        SOUND_PROOFS_REPETITIONS,
        KnowledgeOfDecommitmentLanguage<SCALAR_LIMBS, GroupElement>,
    >;

/// A Knowledge of Decommitment Maurer Proof $\Pi_{\textsf{zk}}^{L_{\textsf{Dcom}[G,H]}}(G;w,\rho)$.
pub type KnowledgeOfDecommitmentProof<const SCALAR_LIMBS: usize, GroupElement> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    KnowledgeOfDecommitmentLanguage<SCALAR_LIMBS, GroupElement>,
    ProtocolContext,
>;

/// Knowledge of Decommitment Maurer Language $L_{\textsf{DCom}}$.
pub type KnowledgeOfDecommitmentUCLanguage<const SCALAR_LIMBS: usize, GroupElement> =
    knowledge_of_decommitment::Language<
        UC_PROOFS_REPETITIONS,
        SCALAR_LIMBS,
        Pedersen<
            1,
            SCALAR_LIMBS,
            <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
            GroupElement,
        >,
    >;

/// The Public Parameters of the Knowledge of Decommitment Maurer Language $L_{\textsf{DCom}}$.
pub type KnowledgeOfDecommitmentUCPublicParameters<const SCALAR_LIMBS: usize, GroupElement> =
    language::PublicParameters<
        UC_PROOFS_REPETITIONS,
        KnowledgeOfDecommitmentUCLanguage<SCALAR_LIMBS, GroupElement>,
    >;

/// A Knowledge of Decommitment Maurer Proof
/// $\Pi_{\textsf{zk-uc}}^{L_{\textsf{Dcom}[G,H]}}(G;w,\rho)$.
pub type KnowledgeOfDecommitmentUCProof<const SCALAR_LIMBS: usize, GroupElement> =
    maurer::fischlin::Proof<
        UC_PROOFS_REPETITIONS,
        KnowledgeOfDecommitmentUCLanguage<SCALAR_LIMBS, GroupElement>,
        ProtocolContext,
    >;

/// Commitment of Discrete Log Language $L_{\textsf{DComDL}}$.
pub type CommitmentOfDiscreteLogLanguage<const SCALAR_LIMBS: usize, GroupElement> =
    commitment_of_discrete_log::Language<
        SCALAR_LIMBS,
        <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
        GroupElement,
        Pedersen<
            1,
            SCALAR_LIMBS,
            <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
            GroupElement,
        >,
    >;

/// The Public Parameters of the Commitment of Discrete Log Language $L_{\textsf{DComDL}}$.
pub type CommitmentOfDiscreteLogPublicParameters<const SCALAR_LIMBS: usize, GroupElement> =
    language::PublicParameters<
        SOUND_PROOFS_REPETITIONS,
        CommitmentOfDiscreteLogLanguage<SCALAR_LIMBS, GroupElement>,
    >;

/// A Commitment of Discrete Log Proof
/// $\Pi_{\textsf{zk}}^{L_{\sf DComDL}[G,H,(\mathbb{G},R,q)]}(C_{k}, R; k, \rho_0)$.
pub type CommitmentOfDiscreteLogProof<const SCALAR_LIMBS: usize, GroupElement> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    CommitmentOfDiscreteLogLanguage<SCALAR_LIMBS, GroupElement>,
    ProtocolContext,
>;

/// Vector Commitment of Discrete Log Language $L_{\textsf{VecDComDL}}$.
pub type VectorCommitmentOfDiscreteLogLanguage<const SCALAR_LIMBS: usize, GroupElement> =
    vector_commitment_of_discrete_log::Language<
        2,
        SCALAR_LIMBS,
        <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
        GroupElement,
        MultiPedersen<
            2,
            SCALAR_LIMBS,
            <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
            GroupElement,
        >,
    >;

/// The Public Parameters of the Vector Commitment of Discrete Log Language $L_{\textsf{VecDComDL}}$.
pub type VectorCommitmentOfDiscreteLogPublicParameters<const SCALAR_LIMBS: usize, GroupElement> =
    language::PublicParameters<
        SOUND_PROOFS_REPETITIONS,
        VectorCommitmentOfDiscreteLogLanguage<SCALAR_LIMBS, GroupElement>,
    >;

/// A Vector Commitment of Discrete Log Proof
/// $\Pi_{\textsf{zk}}^{L_{\sf
/// VecDComDL}[(G,H),(\mathbb{G},\hat{R},G),q)]}(C_{\alpha},C_{\beta}),R; (\alpha,\beta),
/// \rho_0,\rho_0)$.
pub type VectorCommitmentOfDiscreteLogProof<const SCALAR_LIMBS: usize, GroupElement> =
    maurer::Proof<
        SOUND_PROOFS_REPETITIONS,
        VectorCommitmentOfDiscreteLogLanguage<SCALAR_LIMBS, GroupElement>,
        ProtocolContext,
    >;

/// Equality Between Two Commitments With Different Public Parameters Language $L_{\textsf{DcomEq}}$.
pub type EqualityBetweenCommitmentsWithDifferentPublicParametersLanguage<
    const SCALAR_LIMBS: usize,
    GroupElement,
> = equality_between_commitments_with_different_public_parameters::Language<
    SCALAR_LIMBS,
    Pedersen<
        1,
        SCALAR_LIMBS,
        <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
        GroupElement,
    >,
>;

/// The Public Parameters of the Equality Between Two Commitments With Different Public Parameters
/// Language $L_{\textsf{DcomEq}}$.
pub type EqualityBetweenCommitmentsWithDifferentPublicParametersPublicParameters<
    const SCALAR_LIMBS: usize,
    GroupElement,
> = language::PublicParameters<
    SOUND_PROOFS_REPETITIONS,
    EqualityBetweenCommitmentsWithDifferentPublicParametersLanguage<SCALAR_LIMBS, GroupElement>,
>;

/// A Equality Between Two Commitments With Different Public Parameters Proof
/// $\Pi_{\textsf {zk}}^{L_{\sf DcomEq}[(G,H),(\hat{G},\hat{H})]}(
/// C_w,\hat{C_w};w,\rho_0,\rho_1)$
pub type EqualityBetweenCommitmentsWithDifferentPublicParametersProof<
    const SCALAR_LIMBS: usize,
    GroupElement,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    EqualityBetweenCommitmentsWithDifferentPublicParametersLanguage<SCALAR_LIMBS, GroupElement>,
    ProtocolContext,
>;

/// Encryption of Discrete Log Language $L_{\textsf{EncDL}}$.
pub type EncryptionOfDiscreteLogLanguage<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = encryption_of_discrete_log::Language<
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    SCALAR_LIMBS,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    homomorphic_encryption::PlaintextSpaceGroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    GroupElement,
    EncryptionKey,
>;

/// Scaling of Discrete Log Language $L_{\textsf{ScaleDL}}$.
pub type ScalingOfDiscreteLogLanguage<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = scaling_of_discrete_log::Language<
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey,
>;

/// Encryption of Tuple Language $L_{\textsf{EncDH}}$.
pub type EncryptionOfTupleLanguage<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = encryption_of_tuple::Language<
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey,
>;

/// Encryption of Tuple Language $L_{\textsf{EncDH}}$.
pub type ExtendedEncryptionOfTupleLanguage<
    const N: usize,
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = extended_encryption_of_tuple::Language<
    N,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey,
>;

/// A proof of equality of discrete logs $(g_1,g_1^x), (g_2,g_2^x), ..., (g_n,g_3^n)$ under different hidden order groups $g_1\in G_1, g_2 \in G_2,...,g_n \in G_n$.
/// In a hidden order we group, we can use a knowledge of discrete log proof to prove the equality of discrete logs of two bases:
/// Let $G_{1}$ and $G_{2}$ be groups of unknown order containing elements $g_{1},g_{2}, ..., g_{n}$ respectively.
/// The prover shows it knows a number $s \in \mathbb{Z}$ such that $v_{1}=g_{1}^s,v_{2}=g_{2}^s,...,v_{n}=g_{n}^s$.
///
/// We don't decide the structure of the group element here, and take a generic one,
/// supporting a combination of direct- and self-products of hidden-order groups (which we don't enforce here, the user must guarantee for safety.)
pub type EqualityOfDiscreteLogsInHiddenOrderGroupProof<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    HiddenOrderGroupElement,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    knowledge_of_discrete_log::Language<
        bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
        HiddenOrderGroupElement,
    >,
    ProtocolContext,
>;

/// The public parameters of an equality of discrete logs in hidden order group.
/// See [`EqualityOfDiscreteLogsInHiddenOrderGroupProof`].
pub type EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    HiddenOrderGroupElement,
> = knowledge_of_discrete_log::PublicParameters<
    bounded_integers_group::PublicParameters<DISCRETE_LOG_WITNESS_LIMBS>,
    group::PublicParameters<HiddenOrderGroupElement>,
    group::Value<HiddenOrderGroupElement>,
>;

/// Construct $L_{\textsf{DCom}}$ language parameters.
pub fn construct_knowledge_of_decommitment_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
) -> KnowledgeOfDecommitmentPublicParameters<SCALAR_LIMBS, GroupElement> {
    knowledge_of_decommitment::PublicParameters::new::<
        SOUND_PROOFS_REPETITIONS,
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >(commitment_scheme_public_parameters)
}

/// Helper for Sign Step (1c):
/// Run the protocols $\Pi_{\textsf{zk}}^{L_{\textsf{Dcom}[G,H]}}(G;w,\rho)$
pub fn prove_knowledge_of_decommitment<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    witness: GroupElement::Scalar,
    randomness: GroupElement::Scalar,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    KnowledgeOfDecommitmentProof<SCALAR_LIMBS, GroupElement>,
    GroupElement,
)> {
    let language_public_parameters = construct_knowledge_of_decommitment_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(commitment_scheme_public_parameters);

    let (proof, statement) = KnowledgeOfDecommitmentProof::<SCALAR_LIMBS, GroupElement>::prove(
        protocol_context,
        &language_public_parameters,
        vec![([witness].into(), randomness).into()],
        rng,
    )?;

    let statement = *statement.first().ok_or(Error::InternalError)?;

    Ok((proof, statement))
}

/// Helper for Sign Step (2d):
/// Verify $\Pi_{\textsf{zk}}^{L_{\textsf{Dcom}[G,H]}}(G;w,\rho)$
pub fn verify_knowledge_of_decommitment<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    commitment: GroupElement,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    protocol_context: &ProtocolContext,
    proof: KnowledgeOfDecommitmentProof<SCALAR_LIMBS, GroupElement>,
) -> Result<()> {
    let language_public_parameters = construct_knowledge_of_decommitment_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(commitment_scheme_public_parameters);

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![commitment],
    )?;

    Ok(())
}

/// Construct $L_{\textsf{DCom}}$ language parameters.
pub fn construct_uc_knowledge_of_decommitment_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
) -> KnowledgeOfDecommitmentUCPublicParameters<SCALAR_LIMBS, GroupElement> {
    knowledge_of_decommitment::PublicParameters::new::<
        UC_PROOFS_REPETITIONS,
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >(commitment_scheme_public_parameters)
}

/// Helper for Sign Step (1c):
/// Run the protocols $\Pi_{\textsf{zk-uc}}^{L_{\textsf{Dcom}[G,H]}}(G;w,\rho)$
pub fn uc_prove_knowledge_of_decommitment<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    witness: GroupElement::Scalar,
    randomness: GroupElement::Scalar,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    KnowledgeOfDecommitmentUCProof<SCALAR_LIMBS, GroupElement>,
    GroupElement,
)> {
    let language_public_parameters = construct_uc_knowledge_of_decommitment_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(commitment_scheme_public_parameters);

    let (proof, statement) = KnowledgeOfDecommitmentUCProof::<SCALAR_LIMBS, GroupElement>::prove(
        protocol_context,
        &language_public_parameters,
        ([witness].into(), randomness).into(),
        rng,
    )?;

    Ok((proof, statement))
}

/// Helper for Sign Step (2d):
/// Verify $\Pi_{\textsf{zk-uc}}^{L_{\textsf{Dcom}[G,H]}}(G;w,\rho)$
pub fn verify_uc_knowledge_of_decommitment<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    commitment: GroupElement,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    protocol_context: &ProtocolContext,
    proof: KnowledgeOfDecommitmentUCProof<SCALAR_LIMBS, GroupElement>,
) -> Result<()> {
    let language_public_parameters = construct_uc_knowledge_of_decommitment_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(commitment_scheme_public_parameters);

    proof.verify(protocol_context, &language_public_parameters, commitment)?;

    Ok(())
}

/// Construct $L_{\textsf{DCom}}$ language parameters.
pub fn construct_knowledge_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
) -> KnowledgeOfDiscreteLogPublicParameters<SCALAR_LIMBS, GroupElement> {
    let generator = GroupElement::generator_value_from_public_parameters(&group_public_parameters);

    knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
        scalar_group_public_parameters,
        group_public_parameters,
        generator,
        None,
    )
}

/// Run the protocols $\Pi_{\textsf{zk}}^{L_{\sf{DL}}[(\mathbb{G}, G,q)]}(x\cdot G;x)$
pub fn prove_knowledge_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    discrete_log: GroupElement::Scalar,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    GroupElement,
)> {
    let language_public_parameters = construct_knowledge_of_discrete_log_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(scalar_group_public_parameters, group_public_parameters);

    let (proof, statement) = KnowledgeOfDiscreteLogProof::<SCALAR_LIMBS, GroupElement>::prove(
        protocol_context,
        &language_public_parameters,
        vec![discrete_log],
        rng,
    )?;

    let base_by_discrete_log = *statement.first().ok_or(Error::InternalError)?;

    Ok((proof, base_by_discrete_log))
}

/// Verify $\Pi_{\textsf{zk}}^{L_{\sf{DL}}[(\mathbb{G}, G,q)]}(x\cdot G;x)$
pub fn verify_knowledge_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    base_by_discrete_log: GroupElement,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    proof: KnowledgeOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
) -> Result<()> {
    let language_public_parameters = construct_knowledge_of_discrete_log_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(scalar_group_public_parameters, group_public_parameters);

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![base_by_discrete_log],
    )?;

    Ok(())
}

/// Construct $L_{\textsf{DCom}}$ language parameters.
pub fn construct_uc_knowledge_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
) -> KnowledgeOfDiscreteLogUCPublicParameters<SCALAR_LIMBS, GroupElement> {
    let generator = GroupElement::generator_value_from_public_parameters(&group_public_parameters);

    knowledge_of_discrete_log::PublicParameters::new::<GroupElement::Scalar, GroupElement>(
        scalar_group_public_parameters,
        group_public_parameters,
        generator,
        None,
    )
}

/// Helper for DKG Step (2d):
/// Run the protocols $\Pi_{\textsf{zk-uc}}^{L_{\sf{DL}}[(\mathbb{G}, G,q)]}(x\cdot G;x)$
pub fn uc_prove_knowledge_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    discrete_log: GroupElement::Scalar,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
    GroupElement,
)> {
    let language_public_parameters = construct_uc_knowledge_of_discrete_log_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(scalar_group_public_parameters, group_public_parameters);

    let (proof, base_by_discrete_log) =
        KnowledgeOfDiscreteLogUCProof::<SCALAR_LIMBS, GroupElement>::prove(
            protocol_context,
            &language_public_parameters,
            discrete_log,
            rng,
        )?;

    Ok((proof, base_by_discrete_log))
}

/// Helper for DKG Step (3b):
/// Verify $\Pi_{\textsf{zk-uc}}^{L_{\sf{DL}}[(\mathbb{G}, G,q)]}(x\cdot G;x)$
pub fn verify_uc_knowledge_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    base_by_discrete_log: GroupElement,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    proof: KnowledgeOfDiscreteLogUCProof<SCALAR_LIMBS, GroupElement>,
) -> Result<()> {
    let language_public_parameters = construct_uc_knowledge_of_discrete_log_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(scalar_group_public_parameters, group_public_parameters);

    proof.verify(
        protocol_context,
        &language_public_parameters,
        base_by_discrete_log,
    )?;

    Ok(())
}

/// Construct $L_{\textsf{DComDL}}$ language parameters.
pub fn construct_commitment_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    base: GroupElement::Value,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
) -> CommitmentOfDiscreteLogPublicParameters<SCALAR_LIMBS, GroupElement> {
    commitment_of_discrete_log::PublicParameters::new::<
        SCALAR_LIMBS,
        GroupElement::Scalar,
        GroupElement,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        commitment_scheme_public_parameters,
        base,
    )
}

/// Helper function to the Sign Protocol (C.3) Step (f) ii.:
/// $\Pi_{\textsf{zk}}^{L_{\sf DComDL}[G,H,(\mathbb{G},R,q)]}(C_{k}, R;
/// k, \rho_0)$.
pub fn prove_commitment_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    signature_nonce_share: GroupElement::Scalar,
    signature_nonce_share_commitment_randomness: GroupElement::Scalar,
    base: GroupElement::Value,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    CommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    GroupElement,
    GroupElement,
)> {
    let language_public_parameters =
        construct_commitment_of_discrete_log_public_parameters::<SCALAR_LIMBS, GroupElement>(
            base,
            commitment_scheme_public_parameters,
            scalar_group_public_parameters,
            group_public_parameters,
        );

    let (proof, statement) = CommitmentOfDiscreteLogProof::<SCALAR_LIMBS, GroupElement>::prove(
        protocol_context,
        &language_public_parameters,
        vec![[
            signature_nonce_share,
            signature_nonce_share_commitment_randomness,
        ]
        .into()],
        rng,
    )?;

    let [first_commitment, second_commitment] =
        (*statement.first().ok_or(Error::InternalError)?).into();

    Ok((proof, first_commitment, second_commitment))
}

/// Helper for Sign Step (2d):
/// Verify $\Pi_{\textsf{zk}}^{L_{\sf DComDL}[G,H,(\mathbb{G},R,q)]}(C_{k}, R;
/// k, \rho_0)$.
pub fn verify_commitment_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    base: GroupElement::Value,
    commitment_of_discrete_log: GroupElement,
    base_by_discrete_log: GroupElement,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    proof: CommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
) -> Result<()> {
    let language_public_parameters =
        construct_commitment_of_discrete_log_public_parameters::<SCALAR_LIMBS, GroupElement>(
            base,
            commitment_scheme_public_parameters,
            scalar_group_public_parameters,
            group_public_parameters,
        );

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![self_product::GroupElement::from([
            commitment_of_discrete_log,
            base_by_discrete_log,
        ])],
    )?;

    Ok(())
}

/// Construct $L_{\textsf{DcomEq}}$ language parameters.
pub fn construct_equality_between_commitments_with_different_public_parameters_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    second_commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
) -> EqualityBetweenCommitmentsWithDifferentPublicParametersPublicParameters<
    SCALAR_LIMBS,
    GroupElement,
> {
    equality_between_commitments_with_different_public_parameters::PublicParameters::new::<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >(
        first_commitment_scheme_public_parameters.clone(),
        second_commitment_scheme_public_parameters,
    )
}

/// Helper for Sign Step (1f)i.:
/// $\Pi_{\textsf {zk}}^{L_{\sf DcomEq}[(G,H),(\hat{G},\hat{H})]}(
/// C_w,\hat{C_w};w,\rho_0,\rho_3)$
pub fn prove_equality_between_commitments_with_different_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    commitment_message: GroupElement::Scalar,
    first_commitment_randomness: GroupElement::Scalar,
    second_commitment_randomness: GroupElement::Scalar,
    first_commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    second_commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    EqualityBetweenCommitmentsWithDifferentPublicParametersProof<SCALAR_LIMBS, GroupElement>,
    GroupElement,
    GroupElement,
)> {
    let language_public_parameters =
        construct_equality_between_commitments_with_different_public_parameters_public_parameters::<
            SCALAR_LIMBS,
            GroupElement,
        >(
            first_commitment_scheme_public_parameters,
            second_commitment_scheme_public_parameters,
        );

    let (proof, statement) = EqualityBetweenCommitmentsWithDifferentPublicParametersProof::<
        SCALAR_LIMBS,
        GroupElement,
    >::prove(
        protocol_context,
        &language_public_parameters,
        vec![(
            [commitment_message].into(),
            [first_commitment_randomness, second_commitment_randomness].into(),
        )
            .into()],
        rng,
    )?;

    let [first_commitment, second_commitment] =
        (*statement.first().ok_or(Error::InternalError)?).into();

    Ok((proof, first_commitment, second_commitment))
}

/// Helper for Sign Step (2d):
/// Verify $\Pi_{\textsf {zk}}^{L_{\sf DcomEq}[(G,H),(\hat{G},\hat{H})]}(
/// C_w,\hat{C_w};w,\RandomCom_0,\RandomCom_1)$
pub fn verify_equality_between_commitments_with_different_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_commitment: GroupElement,
    second_commitment: GroupElement,
    first_commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    second_commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    protocol_context: &ProtocolContext,
    proof: EqualityBetweenCommitmentsWithDifferentPublicParametersProof<SCALAR_LIMBS, GroupElement>,
) -> Result<()> {
    let language_public_parameters =
        construct_equality_between_commitments_with_different_public_parameters_public_parameters::<
            SCALAR_LIMBS,
            GroupElement,
        >(
            first_commitment_scheme_public_parameters,
            second_commitment_scheme_public_parameters,
        );

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![self_product::GroupElement::from([
            first_commitment,
            second_commitment,
        ])],
    )?;

    Ok(())
}

/// Construct $L_VecDComDL$ language parameters.
pub fn construct_vector_commitment_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    base: GroupElement::Value,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<2, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
) -> VectorCommitmentOfDiscreteLogPublicParameters<SCALAR_LIMBS, GroupElement> {
    let generator = GroupElement::generator_value_from_public_parameters(&group_public_parameters);

    vector_commitment_of_discrete_log::PublicParameters::new::<
        SCALAR_LIMBS,
        GroupElement::Scalar,
        GroupElement,
        MultiPedersen<2, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        commitment_scheme_public_parameters,
        [base, generator],
    )
}

/// Helper for Sign Step (1f) iii.:
/// Run the protocol $\Pi_{\textsf{zk}}^{L_{\sf
/// VecDComDL}[(G,H),(\mathbb{G},\hat{R},G),q)]}(C_{\alpha},C_{\beta}),R; (\alpha,\beta),
/// \rho_1,\rho_2)$.
pub fn prove_vector_commitment_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    alpha_displacer: GroupElement::Scalar,
    alpha_displacer_commitment_randomness: GroupElement::Scalar,
    beta_displacer: GroupElement::Scalar,
    beta_displacer_commitment_randomness: GroupElement::Scalar,
    base: GroupElement::Value,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<2, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    VectorCommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    GroupElement,
)> {
    let language_public_parameters = construct_vector_commitment_of_discrete_log_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(
        base,
        commitment_scheme_public_parameters,
        scalar_group_public_parameters,
        group_public_parameters,
    );

    let (proof, statements) =
        VectorCommitmentOfDiscreteLogProof::<SCALAR_LIMBS, GroupElement>::prove(
            protocol_context,
            &language_public_parameters,
            vec![(
                [alpha_displacer, beta_displacer].into(),
                [
                    alpha_displacer_commitment_randomness,
                    beta_displacer_commitment_randomness,
                ]
                .into(),
            )
                .into()],
            rng,
        )?;

    let decentralized_party_nonce_public_share = *statements
        .first()
        .ok_or(crate::Error::InternalError)?
        .linear_combination_of_discrete_logs();

    Ok((proof, decentralized_party_nonce_public_share))
}

/// Helper for Sign Step (2d):
/// Verify $\Pi_{\textsf{zk}}^{L_{\sf
/// VecDComDL}[(G,H),(\GG,\hat{R},G),q)]}(C_{\alpha},C_{\beta}),R; (\alpha,\beta),
/// \RandomCom_0,\RandomCom_1)$.
pub fn verify_vector_commitment_of_discrete_log<
    const SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    base: GroupElement::Value,
    commitment_of_first_discrete_log: GroupElement,
    commitment_of_second_discrete_log: GroupElement,
    linear_combination_of_discrete_logs: GroupElement,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<2, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    protocol_context: &ProtocolContext,
    proof: VectorCommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
) -> Result<()> {
    let language_public_parameters = construct_vector_commitment_of_discrete_log_public_parameters::<
        SCALAR_LIMBS,
        GroupElement,
    >(
        base,
        commitment_scheme_public_parameters,
        scalar_group_public_parameters,
        group_public_parameters,
    );

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![(
            self_product::GroupElement::from([
                commitment_of_first_discrete_log,
                commitment_of_second_discrete_log,
            ]),
            linear_combination_of_discrete_logs,
        )
            .into()],
    )?;

    Ok(())
}

/// This function constructs the public parameters for the equality of discrete log in hidden order language.
pub fn construct_equality_of_discrete_log_public_parameters<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    HiddenOrderGroupElement,
>(
    discrete_log_group_public_parameters: bounded_integers_group::PublicParameters<
        DISCRETE_LOG_WITNESS_LIMBS,
    >,
    hidden_order_group_public_parameters: HiddenOrderGroupElement::PublicParameters,
    base: HiddenOrderGroupElement::Value,
) -> EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
    DISCRETE_LOG_WITNESS_LIMBS,
    HiddenOrderGroupElement,
>
where
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    HiddenOrderGroupElement: group::GroupElement + Scale<Int<DISCRETE_LOG_WITNESS_LIMBS>>,
{
    let upper_bound_bits = Some(discrete_log_group_public_parameters.sample_bits);

    knowledge_of_discrete_log::PublicParameters::new::<
        bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>,
        HiddenOrderGroupElement,
    >(
        discrete_log_group_public_parameters,
        hidden_order_group_public_parameters,
        base,
        upper_bound_bits,
    )
}

/// Prove equality between the discrete logs $(g_1,g_1^x_i), (g_2,g_2^x_i), ..., (g_n,g_n^x_i)$
/// under different hidden order groups $g_1\in G_1, g_2 \in G_2,...,g_n \in G_n$ for a batch $ {x_i}_i $.
pub fn prove_equality_of_discrete_log<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    HiddenOrderGroupElement,
>(
    language_public_parameters: EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
        DISCRETE_LOG_WITNESS_LIMBS,
        HiddenOrderGroupElement,
    >,
    discrete_logs: Vec<bounded_integers_group::GroupElement<DISCRETE_LOG_WITNESS_LIMBS>>,
    protocol_context: &ProtocolContext,
    rng: &mut impl CsRng,
) -> Result<(
    EqualityOfDiscreteLogsInHiddenOrderGroupProof<
        DISCRETE_LOG_WITNESS_LIMBS,
        HiddenOrderGroupElement,
    >,
    Vec<HiddenOrderGroupElement>,
)>
where
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    HiddenOrderGroupElement: group::GroupElement + Scale<Int<DISCRETE_LOG_WITNESS_LIMBS>>,
{
    let (proof, base_by_discrete_logs) = EqualityOfDiscreteLogsInHiddenOrderGroupProof::<
        DISCRETE_LOG_WITNESS_LIMBS,
        HiddenOrderGroupElement,
    >::prove(
        protocol_context,
        &language_public_parameters,
        discrete_logs,
        rng,
    )?;

    Ok((proof, base_by_discrete_logs))
}

/// Verify equality between the discrete logs $(g_1,g_1^x), (g_2,g_2^x), ..., (g_n,g_3^n)$ under different hidden order groups $g_1\in G_1, g_2 \in G_2,...,g_n \in G_n$.
pub fn verify_equality_of_discrete_log_proof<
    const DISCRETE_LOG_WITNESS_LIMBS: usize,
    HiddenOrderGroupElement,
>(
    language_public_parameters: &EqualityOfDiscreteLogsInHiddenOrderGroupPublicParameters<
        DISCRETE_LOG_WITNESS_LIMBS,
        HiddenOrderGroupElement,
    >,
    base_by_discrete_logs: Vec<HiddenOrderGroupElement>,
    protocol_context: &ProtocolContext,
    proof: &EqualityOfDiscreteLogsInHiddenOrderGroupProof<
        DISCRETE_LOG_WITNESS_LIMBS,
        HiddenOrderGroupElement,
    >,
) -> Result<()>
where
    Int<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    Uint<DISCRETE_LOG_WITNESS_LIMBS>: Encoding,
    HiddenOrderGroupElement: group::GroupElement + Scale<Int<DISCRETE_LOG_WITNESS_LIMBS>>,
{
    proof.verify(
        protocol_context,
        language_public_parameters,
        base_by_discrete_logs,
    )?;

    Ok(())
}
