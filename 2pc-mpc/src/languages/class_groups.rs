// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::fmt::Debug;

use crypto_bigint::{Encoding, Int, Uint};
use serde::Serialize;

use class_groups::equivalence_class::EquivalenceClassOps;
use class_groups::MultiFoldNupowAccelerator;
use class_groups::{
    encryption_key, equivalence_class, CiphertextSpaceGroupElement,
    CiphertextSpacePublicParameters, CiphertextSpaceValue, CompactIbqf, EncryptionKey,
    EquivalenceClass, RandomnessSpaceGroupElement, RandomnessSpacePublicParameters,
};
use commitment::MultiPedersen;
use group::helpers::FlatMapResults;
use group::{
    bounded_natural_numbers_group, direct_product, self_product, KnownOrderGroupElement,
    PrimeGroupElement, Samplable,
};
use group::{CsRng, GroupElement as _};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use homomorphic_encryption::GroupsPublicParametersAccessors;
use maurer::committed_linear_evaluation::StatementAccessors;
use maurer::{
    committed_linear_evaluation, encryption_of_discrete_log, encryption_of_tuple,
    scaling_of_discrete_log,
};
use maurer::{extended_encryption_of_tuple, SOUND_PROOFS_REPETITIONS};

use crate::languages::DIMENSION;
use crate::{Error, ProtocolContext, Result};

/// The Public Parameters of the Committed Linear Evaluation
/// Language $L_{\textsf{DComEval}}$.
pub type CommittedLinearEvaluationPublicParameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = committed_linear_evaluation::PublicParameters<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    DIMENSION,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// Committed Linear Evaluation Language $L_{\textsf{DComEval}}$.
pub type CommittedLinearEvaluationLanguage<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
    EncryptionKey,
> = committed_linear_evaluation::Language<
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    0,
    0,
    DIMENSION,
    GroupElement,
    EncryptionKey,
>;

/// A Committed Linear Evaluation Proof
/// $\Pi_{\textsf {zk}}^{L_{\sf DcomEq}[(G,H),(\hat{G},\hat{H})]}(
/// C_w,\hat{C_w};w,\rho_0,\rho_1)$
pub type CommittedLinearEvaluationProof<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    CommittedLinearEvaluationLanguage<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    ProtocolContext,
>;

/// The Public Parameters of the Encryption of Discrete Log
/// Language $L_{\textsf{EncDL}}$.
pub type EncryptionOfDiscreteLogPublicParameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = encryption_of_discrete_log::PublicParameters<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// Encryption of Discrete Log Language $L_{\textsf{EncDL}}$.
pub type EncryptionOfDiscreteLogLanguage<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = super::EncryptionOfDiscreteLogLanguage<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// Encryption of Discrete Log Witness.
pub type EncryptionOfDiscreteLogWitness<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
> = encryption_of_discrete_log::WitnessSpaceGroupElement<
    SCALAR_LIMBS,
    <GroupElement as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// A Encryption of Discrete Log Proof
/// $\Pi_{\textsf{zk}}^{L_{\sf EncDL}[\textsf{pk}, (\mathbb{G}, G, q)]}$
pub type EncryptionOfDiscreteLogProof<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement,
    PC,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    EncryptionOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
    PC,
>;

/// Scaling of Discrete Log Language $L_{\textsf{ScaleDL}}$.
pub type ScalingOfDiscreteLogLanguage<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = super::ScalingOfDiscreteLogLanguage<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

///  Scaling of Discrete Log  Witness.
pub type ScalingOfDiscreteLogWitness<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = scaling_of_discrete_log::WitnessSpaceGroupElement<
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// The Public Parameters of the Scaling of Discrete Log
/// Language $L_{\textsf{ScaleDL}}$.
pub type ScalingOfDiscreteLogPublicParameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = scaling_of_discrete_log::PublicParameters<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// A Scaling of Discrete Log Proof
/// $\Pi_{\textsf{zk}}^L_{\sf ScaleDL}[\textsf{pk},(\mathbb{G}, G, q),\textsf{ct}_0] =
/// \{ & (\textsf{ct}_1, X; x,\eta) \mid \ct=\textsf{AHE}.\textsf{Scale}(\textsf{pk},\textsf{ct}_0,x; \eta) \wedge \\
/// & X=x\cdot G \wedge x\in [0,q) \}$
pub type ScalingOfDiscreteLogProof<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    ScalingOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
    ProtocolContext,
>;

/// Encryption of Tuple Language $L_{\textsf{EncDH}}$.
pub type EncryptionOfTupleLanguage<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = super::EncryptionOfTupleLanguage<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// Encryption of Tuple Witness.
pub type EncryptionOfTupleWitness<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = encryption_of_tuple::WitnessSpaceGroupElement<
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// The Public Parameters of the Encryption of Tuple
/// Language $L_{\textsf{EncDH}}$.
pub type EncryptionOfTuplePublicParameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = encryption_of_tuple::PublicParameters<
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// An Encryption of Tuple Proof
/// $\Pi_{\textsf{zk}}^L_{\sf EncDH}[\textsf{pk}, \textsf{ct}_x] = \{ (\textsf{ct}_y, \textsf{ct}_z; y, \eta_y,
/// \eta_z) \mid  \textsf{ct}_y=\textsf{AHE}.\textsf{Enc}(\textsf{pk}, y; \eta_y) \wedge \textsf{ct}_z = {\sf
/// AHE}.\textsf{Eval}(\textsf{pk}, f, \textsf{ct}_x; 0, \eta_z) ~\text{s.t.}~ f(x)=y\cdot x \mod q \wedge y\in
/// [0,q)\}$
pub type EncryptionOfTupleProof<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    EncryptionOfTupleLanguage<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
    ProtocolContext,
>;

/// Encryption of Tuple Language $L_{\textsf{EncDH}}$.
pub type ExtendedEncryptionOfTupleLanguage<
    const N: usize,
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = super::ExtendedEncryptionOfTupleLanguage<
    N,
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// Encryption of Tuple Witness.
pub type ExtendedEncryptionOfTupleWitness<
    const N: usize,
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = extended_encryption_of_tuple::WitnessSpaceGroupElement<
    N,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// The Public Parameters of the Encryption of Tuple
/// Language $L_{\textsf{EncDH}}$.
pub type ExtendedEncryptionOfTuplePublicParameters<
    const N: usize,
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = extended_encryption_of_tuple::PublicParameters<
    N,
    SCALAR_LIMBS,
    SCALAR_LIMBS,
    MESSAGE_LIMBS,
    GroupElement,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >,
>;

/// An Encryption of Tuple Proof
/// $\Pi_{\textsf{zk}}^L_{\sf EncDH}[\textsf{pk}, \textsf{ct}_x] = \{ (\textsf{ct}_y, \textsf{ct}_z; y, \eta_y,
/// \eta_z) \mid  \textsf{ct}_y=\textsf{AHE}.\textsf{Enc}(\textsf{pk}, y; \eta_y) \wedge \textsf{ct}_z = {\sf
/// AHE}.\textsf{Eval}(\textsf{pk}, f, \textsf{ct}_x; 0, \eta_z) ~\text{s.t.}~ f(x)=y\cdot x \mod q \wedge y\in
/// [0,q)\}$
pub type ExtendedEncryptionOfTupleProof<
    const N: usize,
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement,
> = maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    ExtendedEncryptionOfTupleLanguage<
        N,
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
    ProtocolContext,
>;

/// Construct $L_{\textsf{DComEval}}$ language parameters.
pub fn construct_committed_linear_evaluation_public_parameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    second_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    // required for secure function evaluation when ciphertexts may not be well-formed
    rerandomize_coefficients: bool,
) -> Result<
    CommittedLinearEvaluationPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    let plaintext_space_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(encryption_scheme_public_parameters.plaintext_space_public_parameters());
    let scalar_group_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(&scalar_group_public_parameters);

    if plaintext_space_order != scalar_group_order {
        Err(Error::InvalidPublicParameters)?;
    }

    let coefficient_sample_bits = if rerandomize_coefficients {
        Uint::<SCALAR_LIMBS>::BITS
            + encryption_scheme_public_parameters
                .setup_parameters
                .encryption_randomness_bits()
            + 1
    } else {
        Uint::<SCALAR_LIMBS>::BITS
    };

    if coefficient_sample_bits >= Uint::<MESSAGE_LIMBS>::BITS
        || FUNDAMENTAL_DISCRIMINANT_LIMBS >= MESSAGE_LIMBS
    {
        return Err(Error::InvalidParameters);
    }

    // In class-groups, messages are always bound by the curve order.
    let upper_bound = scalar_group_order.wrapping_sub(&Uint::ONE);
    let ciphertexts_and_encoded_messages_upper_bounds = [
        (first_ciphertext, upper_bound),
        (second_ciphertext, upper_bound),
    ];

    Ok(CommittedLinearEvaluationPublicParameters::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >::new::<
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
        commitment_scheme_public_parameters,
        ciphertexts_and_encoded_messages_upper_bounds,
        coefficient_sample_bits,
    )?)
}

/// Helper for Sign Step (1f) iv, v.:
/// $\Pi_{\textsf{zk}}^{L_{\sfDComEval}[G,H,\textsf{AHE},(\textsf{ct}_1,\textsf{ct}_2,(\mathbb{G},G,q))]}(\textsf{ct},
/// (C_1,C_2);(a_1,a_2), \rho_3\cdot r+\rho_0\cdot
/// m,r\cdot\rho_0,\eta_1)$
///
/// `rerandomize_coefficients`: should be on in case the input ciphertexts (`first_ciphertext`, `second_ciphertext`)
/// are untrusted, i.e. we did not verify (in ZK) the validity of their construction.
/// In that case, we re-randomize the coefficients by adding a randomized multiple of the plaintext space order.
/// This keeps the value of the coefficient modulo the plaintext order (i.e. the plaintext) the same,
/// but does re-randomize the multiplicative mask, even if chosen adversarialy (See section F).
pub fn prove_committed_linear_evaluation<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    second_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    first_coefficient: GroupElement::Scalar,
    first_coefficient_commitment_randomness: GroupElement::Scalar,
    second_coefficient: GroupElement::Scalar,
    second_coefficient_commitment_randomness: GroupElement::Scalar,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    protocol_context: &ProtocolContext,
    rerandomize_coefficients: bool,
    rng: &mut impl CsRng,
) -> Result<(
    CommittedLinearEvaluationProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
    CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
)>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    let plaintext_order: Uint<SCALAR_LIMBS> =
        GroupElement::Scalar::order_from_public_parameters(&scalar_group_public_parameters);

    let encryption_randomness =
        RandomnessSpaceGroupElement::<FUNDAMENTAL_DISCRIMINANT_LIMBS>::sample(
            encryption_scheme_public_parameters.randomness_space_public_parameters(),
            rng,
        )?;

    // No need for masking in class-groups since we work with the same order for the plaintext space and scalar group.
    let mask = GroupElement::Scalar::neutral_from_public_parameters(
        encryption_scheme_public_parameters.plaintext_space_public_parameters(),
    )?;

    // = ρ (see DComEval language definition, Section 5.2)
    let commitment_randomness: self_product::GroupElement<DIMENSION, _> = [
        first_coefficient_commitment_randomness,
        second_coefficient_commitment_randomness,
    ]
    .into();

    let language_public_parameters = construct_committed_linear_evaluation_public_parameters::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >(
        first_ciphertext,
        second_ciphertext,
        commitment_scheme_public_parameters,
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters.clone(),
        rerandomize_coefficients,
    )?;

    // = A (see DComEval language definition, Section 5.2)
    let coefficients = [first_coefficient, second_coefficient]
        .map(|coefficient| {
            let coefficient: Uint<SCALAR_LIMBS> = coefficient.into();
            let coefficient = Uint::<MESSAGE_LIMBS>::from(&coefficient);
            let coefficient: Uint<MESSAGE_LIMBS> = if rerandomize_coefficients {
                // Re-randomize the coefficients by adding a randomized multiple of the plaintext space order.
                // This keeps the value of the coefficient modulo the plaintext order (i.e. the plaintext) the same,
                // but does re-randomize the multiplicative mask, even if chosen adversarialy (See section F).
                let randomizer = Uint::<MESSAGE_LIMBS>::from(
                    &RandomnessSpaceGroupElement::<FUNDAMENTAL_DISCRIMINANT_LIMBS>::sample(
                        encryption_scheme_public_parameters.randomness_space_public_parameters(),
                        rng,
                    )?
                    .value(),
                );

                // Cannot overflow since we checked the bounds in a sanity check during the public parameters' construction.
                coefficient + (randomizer * plaintext_order)
            } else {
                coefficient
            };

            bounded_natural_numbers_group::GroupElement::new(
                coefficient,
                language_public_parameters.message_group_public_parameters(),
            )
        })
        .flat_map_results()?;

    // = (A, \rho, \omega, \eta)
    let witness = direct_product::FourWayGroupElement::from((
        coefficients.into(),
        commitment_randomness,
        mask,
        encryption_randomness,
    ));

    let (proof, statement) = CommittedLinearEvaluationProof::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >::prove(
        protocol_context,
        &language_public_parameters,
        vec![witness],
        rng,
    )?;

    let statement = statement.first().ok_or(crate::Error::InternalError)?;
    let evaluated_ciphertext = *statement.evaluated_ciphertext(); // = ct_A

    Ok((proof, evaluated_ciphertext))
}

/// Helper function for Sign Step (2d):
/// Verify $\Pi_{\textsf{zk}}^{L_{\sfDComEval}[G,H,\AHEpk,(\ct_1,\ct_2,(\GG,G,q))]}(\ct,
/// (C_1,C_2);(a_1,a_2), \RandomCom_3\cdot r+\RandomCom_0\cdot
/// m,r\cdot\RandomCom_0,\Randomencryption_1)$
pub fn verify_committed_linear_evaluation<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    second_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    evaluated_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    first_coefficient_commitment: GroupElement,
    second_coefficient_commitment: GroupElement,
    proof: CommittedLinearEvaluationProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    protocol_context: &ProtocolContext,
    rerandomize_coefficients: bool,
) -> Result<()>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    let evaluated_ciphertext =
        CiphertextSpaceGroupElement::<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>::new(
            evaluated_ciphertext,
            encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
        )?;

    let language_public_parameters = construct_committed_linear_evaluation_public_parameters::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >(
        first_ciphertext,
        second_ciphertext,
        commitment_scheme_public_parameters,
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
        rerandomize_coefficients,
    )?;

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![(
            evaluated_ciphertext,
            [first_coefficient_commitment, second_coefficient_commitment].into(),
        )
            .into()],
    )?;

    Ok(())
}

/// Construct $L_{\textsf{EncDL}}$ language parameters.
pub fn construct_encryption_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
) -> EncryptionOfDiscreteLogPublicParameters<
    SCALAR_LIMBS,
    FUNDAMENTAL_DISCRIMINANT_LIMBS,
    NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
    GroupElement,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
{
    let generator = GroupElement::generator_value_from_public_parameters(&group_public_parameters);

    EncryptionOfDiscreteLogPublicParameters::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >::new::<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
        generator,
        None,
    )
}

/// Prove $\Pi_{\textsf{zk}}^{L_{\textsf{EncDL}$.
pub fn prove_encryption_of_discrete_log<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    PC: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
>(
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    protocol_context: &PC,
    discrete_log: GroupElement::Scalar,
    rng: &mut impl CsRng,
) -> Result<(
    EncryptionOfDiscreteLogProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
        PC,
    >,
    CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
)>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
{
    let language_public_parameters = construct_encryption_of_discrete_log_public_parameters(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters.clone(),
    );

    let encryption_randomness =
        RandomnessSpaceGroupElement::<FUNDAMENTAL_DISCRIMINANT_LIMBS>::sample(
            encryption_scheme_public_parameters.randomness_space_public_parameters(),
            rng,
        )?;

    let (proof, statement) = EncryptionOfDiscreteLogProof::<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
        PC,
    >::prove(
        protocol_context,
        &language_public_parameters,
        vec![(discrete_log, encryption_randomness).into()],
        rng,
    )?;

    let (&encryption_of_discrete_log, _) =
        statement.first().ok_or(crate::Error::InternalError)?.into();

    Ok((proof, encryption_of_discrete_log))
}

/// Verify $\Pi_{\textsf{zk}}^{L_{\textsf{EncDL}$.
pub fn verify_encryption_of_discrete_log<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    PC: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
>(
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    protocol_context: &PC,
    proof: EncryptionOfDiscreteLogProof<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
        PC,
    >,
    base_by_discrete_log: GroupElement::Value,
    encryption_of_discrete_log: CiphertextSpaceValue<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
) -> Result<()>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
{
    let base_by_discrete_log = GroupElement::new(base_by_discrete_log, &group_public_parameters)?;
    let encryption_of_discrete_log = CiphertextSpaceGroupElement::new(
        encryption_of_discrete_log,
        encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
    )?;

    let language_public_parameters = construct_encryption_of_discrete_log_public_parameters(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
    );

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![(encryption_of_discrete_log, base_by_discrete_log).into()],
    )?;

    Ok(())
}

/// Construct $L_\textsf{ScaleDL}$ language parameters.
pub fn construct_scaling_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
) -> Result<
    ScalingOfDiscreteLogPublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    let plaintext_space_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(encryption_scheme_public_parameters.plaintext_space_public_parameters());
    let scalar_group_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(&scalar_group_public_parameters);

    if plaintext_space_order != scalar_group_order {
        Err(Error::InvalidPublicParameters)?;
    }

    let upper_bound = scalar_group_order.wrapping_sub(&Uint::ONE);

    Ok(scaling_of_discrete_log::PublicParameters::<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >::new::<
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
        ciphertext,
        upper_bound,
    )?)
}

/// Construct $L_{\textsf{EncDL}}$ language parameters.
pub fn construct_encryption_of_tuple_public_parameters<
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
) -> Result<
    EncryptionOfTuplePublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    let plaintext_space_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(encryption_scheme_public_parameters.plaintext_space_public_parameters());
    let scalar_group_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(&scalar_group_public_parameters);

    if plaintext_space_order != scalar_group_order {
        Err(Error::InvalidPublicParameters)?;
    }

    let upper_bound = scalar_group_order.wrapping_sub(&Uint::ONE);

    Ok(encryption_of_tuple::PublicParameters::<
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >::new::<
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >(
        scalar_group_public_parameters,
        encryption_scheme_public_parameters,
        ciphertext,
        upper_bound,
    )?)
}

/// Construct $L_{\textsf{EncDL}}$ language parameters.
pub fn construct_extended_encryption_of_tuple_public_parameters<
    const N: usize,
    const SCALAR_LIMBS: usize,
    const FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const NON_FUNDAMENTAL_DISCRIMINANT_LIMBS: usize,
    const MESSAGE_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    ciphertexts: [homomorphic_encryption::CiphertextSpaceValue<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >; N],
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        SCALAR_LIMBS,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >,
) -> Result<
    ExtendedEncryptionOfTuplePublicParameters<
        N,
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
    >,
>
where
    Int<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: Encoding,
    Int<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Int<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    Uint<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: Encoding,
    EquivalenceClass<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>: group::GroupElement<
            Value = CompactIbqf<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            PublicParameters = equivalence_class::PublicParameters<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        > + EquivalenceClassOps<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            MultiFoldNupowAccelerator = MultiFoldNupowAccelerator<
                NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            >,
        >,
    EncryptionKey<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        GroupElement,
    >: AdditivelyHomomorphicEncryptionKey<
        SCALAR_LIMBS,
        PublicParameters = encryption_key::PublicParameters<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            group::PublicParameters<GroupElement::Scalar>,
        >,
        PlaintextSpaceGroupElement = GroupElement::Scalar,
        RandomnessSpaceGroupElement = RandomnessSpaceGroupElement<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        CiphertextSpaceGroupElement = CiphertextSpaceGroupElement<
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        >,
    >,
    encryption_key::PublicParameters<
        SCALAR_LIMBS,
        FUNDAMENTAL_DISCRIMINANT_LIMBS,
        NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
        group::PublicParameters<GroupElement::Scalar>,
    >: AsRef<
        homomorphic_encryption::GroupsPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            RandomnessSpacePublicParameters<FUNDAMENTAL_DISCRIMINANT_LIMBS>,
            CiphertextSpacePublicParameters<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>,
        >,
    >,
    Uint<MESSAGE_LIMBS>: Encoding,
{
    let plaintext_space_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(encryption_scheme_public_parameters.plaintext_space_public_parameters());
    let scalar_group_order = <GroupElement::Scalar as KnownOrderGroupElement<SCALAR_LIMBS>>::order_from_public_parameters(&scalar_group_public_parameters);

    if plaintext_space_order != scalar_group_order {
        Err(Error::InvalidPublicParameters)?;
    }

    let upper_bound = scalar_group_order.wrapping_sub(&Uint::ONE);

    Ok(extended_encryption_of_tuple::PublicParameters::<
        N,
        SCALAR_LIMBS,
        SCALAR_LIMBS,
        MESSAGE_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >::new::<
        SCALAR_LIMBS,
        GroupElement,
        EncryptionKey<
            SCALAR_LIMBS,
            FUNDAMENTAL_DISCRIMINANT_LIMBS,
            NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
            GroupElement,
        >,
    >(
        scalar_group_public_parameters,
        encryption_scheme_public_parameters,
        ciphertexts,
        upper_bound,
    )?)
}
