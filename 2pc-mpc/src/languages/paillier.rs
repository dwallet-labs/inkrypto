// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{CheckedAdd, CheckedMul, Uint};

use commitment::GroupsPublicParametersAccessors as _;
use commitment::MultiPedersen;
use enhanced_maurer::language::{composed_witness_upper_bound, EnhancedLanguageStatementAccessors};
use enhanced_maurer::{EnhancedLanguage, EnhancedPublicParameters};
use group::helpers::FlatMapResults;
use group::{
    bounded_natural_numbers_group, direct_product, self_product, GroupElement,
    KnownOrderGroupElement, PrimeGroupElement, Samplable,
};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;
use homomorphic_encryption::GroupsPublicParametersAccessors as _;
use maurer::committed_linear_evaluation::StatementAccessors;
use maurer::SOUND_PROOFS_REPETITIONS;
use maurer::{
    committed_linear_evaluation, encryption_of_discrete_log, encryption_of_tuple,
    scaling_of_discrete_log,
};
use proof::range::PublicParametersAccessors;

use crate::bulletproofs::{RangeProof, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS};
use crate::paillier::bulletproofs::UnboundedDComEvalWitness;
use crate::paillier::*;
use crate::{Error, ProtocolContext};

use super::{
    EncryptionOfDiscreteLogLanguage, EncryptionOfTupleLanguage, ScalingOfDiscreteLogLanguage,
    DIMENSION,
};

/// Committed Linear Evaluation Language $L_{\textsf{DComEval}}$.
pub type CommittedLinearEvaluationLanguage<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    GroupElement,
    EncryptionKey,
> = maurer::committed_linear_evaluation::Language<
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    SCALAR_LIMBS,
    PLAINTEXT_SPACE_SCALAR_LIMBS,
    RANGE_CLAIMS_PER_SCALAR,
    RANGE_CLAIMS_PER_MASK,
    DIMENSION,
    GroupElement,
    EncryptionKey,
>;

/// The Public Parameters of the Committed Linear Evaluation
/// Language $L_{\textsf{DComEval}}$.
pub type CommittedLinearEvaluationPublicParameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
    RangeProof,
    UnboundedDComEvalWitness,
> = EnhancedPublicParameters<
    SOUND_PROOFS_REPETITIONS,
    NUM_RANGE_CLAIMS,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedDComEvalWitness,
    CommittedLinearEvaluationLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        GroupElement,
        EncryptionKey,
    >,
>;

/// A Committed Linear Evaluation Proof
/// $\Pi_{\textsf {zk}}^{L_{\sf DcomEq}[(G,H),(\hat{G},\hat{H})]}(
/// C_w,\hat{C_w};w,\rho_0,\rho_1)$
pub type CommittedLinearEvaluationProof<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS: usize,
    const NUM_RANGE_CLAIMS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement,
    EncryptionKey,
    RangeProof,
    UnboundedDComEvalWitness,
> = enhanced_maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    NUM_RANGE_CLAIMS,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedDComEvalWitness,
    CommittedLinearEvaluationLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

/// The Encryption of Discrete Log Enhanced Language $L_{\textsf{EncDL}}$.
pub type EncryptionOfDiscreteLogEnhancedLanguage<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = EnhancedLanguage<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedEncDLWitness,
    EncryptionOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
>;

/// An Encryption of Discrete Log Witness.
pub type EncryptionOfDiscreteLogWitness<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = maurer::language::WitnessSpaceGroupElement<
    SOUND_PROOFS_REPETITIONS,
    EncryptionOfDiscreteLogEnhancedLanguage<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
>;

/// The Public Parameters of the Encryption of Discrete Log
/// Language $L_{\textsf{EncDL}}$.
pub type EncryptionOfDiscreteLogPublicParameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = EnhancedPublicParameters<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedEncDLWitness,
    EncryptionOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
>;

/// A Encryption of Discrete Log Proof
/// $\Pi_{\textsf{zk}}^{L_{\sf EncDL}[\textsf{pk}, (\mathbb{G}, G, q)]}$
pub type EncryptionOfDiscreteLogProof<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = enhanced_maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedEncDLWitness,
    EncryptionOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

/// The Scaling of Discrete Log Enhanced Language $L_{\textsf{EncDL}}$.
pub type ScalingOfDiscreteLogEnhancedLanguage<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = EnhancedLanguage<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedScaleDLWitness,
    ScalingOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
>;

/// A Scaling of Discrete Log Witness.
pub type ScalingOfDiscreteLogWitness<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = maurer::language::WitnessSpaceGroupElement<
    SOUND_PROOFS_REPETITIONS,
    ScalingOfDiscreteLogEnhancedLanguage<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
>;

/// The Public Parameters of the Scaling of Discrete Log
/// Language $L_{\textsf{ScaleDL}}$.
pub type ScalingOfDiscreteLogPublicParameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = EnhancedPublicParameters<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedScaleDLWitness,
    ScalingOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
>;

/// A Scaling of Discrete Log Proof
/// $\Pi_{\textsf{zk}}^L_{\sf ScaleDL}[\textsf{pk},(\mathbb{G}, G, q),\textsf{ct{_0] =
/// \{ & (\textsf{ct}_1, X; x,\eta) \mid \ct=\textsf{AHE}.\textsf{Scale}(\textsf{pk},\textsf{ct}_0,x; \eta) \wedge \\
/// & X=x\cdot G \wedge x\in [0,q) \}$
pub type ScalingOfDiscreteLogProof<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = enhanced_maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedScaleDLWitness,
    ScalingOfDiscreteLogLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

/// The Encryption of Tuple Enhanced Language $L_\textsf{EncDL}$.
pub type EncryptionOfTupleEnhancedLanguage<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = EnhancedLanguage<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedEncDHWitness,
    EncryptionOfTupleLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
>;

/// An Encryption of Tuple Witness.
pub type EncryptionOfTupleWitness<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = maurer::language::WitnessSpaceGroupElement<
    SOUND_PROOFS_REPETITIONS,
    EncryptionOfTupleEnhancedLanguage<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
>;

/// The Public Parameters of the Encryption of Tuple
/// Language $L_EncDH$.
pub type EncryptionOfTuplePublicParameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = EnhancedPublicParameters<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedEncDHWitness,
    EncryptionOfTupleLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
>;

/// An Encryption of Tuple Proof
/// $\Pi_{\textsf{zk}}^L_{\sf EncDH}[pk, \ct_x] = \{ (\ct_y, \ct_z; y, \Randomencryption_y,
/// \Randomencryption_z) \mid  \ct_y=\AHE.\Enc(pk, y; \Randomencryption_y) \wedge \ct_z = {\sf
/// AHE}.\Eval(pk, f, \ct_x; 0, \Randomencryption_z) ~\text{s.t.}~ f(x)=y\cdot x \mod q \wedge y\in
/// [0,q)\}$
pub type EncryptionOfTupleProof<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement,
> = enhanced_maurer::Proof<
    SOUND_PROOFS_REPETITIONS,
    RANGE_CLAIMS_PER_SCALAR,
    COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
    RangeProof,
    UnboundedEncDHWitness,
    EncryptionOfTupleLanguage<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >,
    ProtocolContext,
>;

/// Construct $L_DComEval$ language parameters.
pub fn construct_committed_linear_evaluation_public_parameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const NUM_RANGE_CLAIMS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    second_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    unbounded_dcom_eval_witness_public_parameters: group::PublicParameters<
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
    >,
    range_proof_public_parameters: proof::range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >,
    is_rerandomized: bool,
) -> crate::Result<
    CommittedLinearEvaluationPublicParameters<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
    >,
> {
    // This is specifically for languages of the structure $ct1 = E(a)$, $ct2 = E(ab)$ for $a,
    // b$ being `GroupElement::Scalar`. This fits the structure of both languages we
    // need in this protocol.
    // Note that in Paillier we use q-masking to achieve circuit privacy. But still our statements can conform to this structure. Thus the value a will be encrypted as Enc(a+mq) and the value b as Enc(b+nq) denoting a'=a+mq and b'=b+nq we get Enc(a'), Enc(a'b').
    let encryption_of_scalar_upper_bound = composed_witness_upper_bound::<
        RANGE_CLAIMS_PER_SCALAR,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
    >()?;

    let encryption_of_multiplication_of_scalars_upper_bound: Option<_> =
        composed_witness_upper_bound::<
            RANGE_CLAIMS_PER_SCALAR,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            RangeProof,
        >()?
        .checked_mul(&encryption_of_scalar_upper_bound)
        .into();

    let encryption_of_multiplication_of_scalars_upper_bound =
        encryption_of_multiplication_of_scalars_upper_bound
            .ok_or(Error::InvalidPublicParameters)?;

    let encryption_of_multiplication_of_scalars_upper_bound = if is_rerandomized {
        let masked_encryption_of_multiplication_of_scalars_upper_bound: Option<_> =
            composed_witness_upper_bound::<
                RANGE_CLAIMS_PER_SCALAR,
                PLAINTEXT_SPACE_SCALAR_LIMBS,
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                RangeProof,
            >()?
            .checked_mul(&encryption_of_multiplication_of_scalars_upper_bound)
            .into();

        let masked_encryption_of_multiplication_of_scalars_upper_bound =
            masked_encryption_of_multiplication_of_scalars_upper_bound
                .ok_or(Error::InvalidPublicParameters)?;

        let encryption_of_multiplication_of_scalars_upper_bound: Option<_> =
            encryption_of_multiplication_of_scalars_upper_bound
                .checked_add(&masked_encryption_of_multiplication_of_scalars_upper_bound)
                .into();

        encryption_of_multiplication_of_scalars_upper_bound.ok_or(Error::InvalidPublicParameters)?
    } else {
        encryption_of_multiplication_of_scalars_upper_bound
    };

    let ciphertexts_and_encoded_messages_upper_bounds = [
        (first_ciphertext, encryption_of_scalar_upper_bound),
        (
            second_ciphertext,
            encryption_of_multiplication_of_scalars_upper_bound,
        ),
    ];

    let language_public_parameters = maurer::committed_linear_evaluation::PublicParameters::<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        DIMENSION,
        GroupElement,
        EncryptionKey,
    >::new::<SCALAR_LIMBS, GroupElement, EncryptionKey>(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
        commitment_scheme_public_parameters,
        ciphertexts_and_encoded_messages_upper_bounds,
        Uint::<SCALAR_LIMBS>::BITS,
    )?;

    let language_public_parameters = EnhancedPublicParameters::<
        SOUND_PROOFS_REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        maurer::committed_linear_evaluation::Language<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            DIMENSION,
            GroupElement,
            EncryptionKey,
        >,
    >::new::<
        RangeProof,
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        committed_linear_evaluation::Language<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            DIMENSION,
            GroupElement,
            EncryptionKey,
        >,
    >(
        unbounded_dcom_eval_witness_public_parameters,
        range_proof_public_parameters,
        language_public_parameters,
    )?;

    Ok(language_public_parameters)
}

/// Helper for Sign Step (1f) iv, v.:
/// $\Pi_{\textsf{zk}}^{L_{\sfDComEval}[G,H,\AHEpk,(\ct_1,\ct_2,(\GG,G,q))]}(\ct,
/// (C_1,C_2);(a_1,a_2), \RandomCom_3\cdot r+\RandomCom_0\cdot
/// m,r\cdot\RandomCom_0,\Randomencryption_1)$
pub fn prove_committed_linear_evaluation<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const NUM_RANGE_CLAIMS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    second_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
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
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    unbounded_dcom_eval_witness_public_parameters: group::PublicParameters<
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
    >,
    range_proof_public_parameters: proof::range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >,
    protocol_context: &ProtocolContext,
    is_rerandomized: bool,
    rng: &mut impl CryptoRngCore,
) -> crate::Result<(
    CommittedLinearEvaluationProof<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
    >,
    proof::range::CommitmentSchemeCommitmentSpaceGroupElement<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >,
    CiphertextSpaceGroupElement,
)> {
    let language_public_parameters = construct_committed_linear_evaluation_public_parameters::<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        GroupElement,
    >(
        first_ciphertext,
        second_ciphertext,
        commitment_scheme_public_parameters,
        scalar_group_public_parameters.clone(),
        group_public_parameters,
        encryption_scheme_public_parameters.clone(),
        unbounded_dcom_eval_witness_public_parameters,
        range_proof_public_parameters,
        is_rerandomized,
    )?;

    let ciphertexts_and_encoded_messages_upper_bounds = language_public_parameters
        .language_public_parameters
        .ciphertexts_and_encoded_messages_upper_bounds
        .map(|(ciphertext, upper_bound)| {
            CiphertextSpaceGroupElement::new(
                ciphertext,
                encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
            )
            .map(|ciphertext| (ciphertext, upper_bound))
        })
        .flat_map_results()?;

    let encryption_randomness = RandomnessSpaceGroupElement::sample(
        encryption_scheme_public_parameters.randomness_space_public_parameters(),
        rng,
    )?;

    // = A (see DComEval language definition, Section 5.2)
    let coefficients: [Uint<SCALAR_LIMBS>; DIMENSION] =
        [first_coefficient, second_coefficient].map(|coefficient| coefficient.into());
    let coefficients: [Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>; DIMENSION] =
        coefficients.each_ref().map(Uint::from);

    // Required for secure evaluation of the DComEval function.
    // See `homomorphic-encryption::AdditivelyHomomorphicEncryptionKey::securely_evaluate_linear_combination_with_randomness`
    // as well as Section 5.2 of the paper.
    let mask = EncryptionKey::sample_mask_for_secure_function_evaluation(
        &coefficients,
        &ciphertexts_and_encoded_messages_upper_bounds,
        &Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(
            &GroupElement::Scalar::order_from_public_parameters(&scalar_group_public_parameters),
        ),
        &encryption_scheme_public_parameters,
        rng,
    )?;

    let message_group_public_parameters =
        bounded_natural_numbers_group::PublicParameters::new_with_randomizer_upper_bound(
            Uint::<SCALAR_LIMBS>::BITS,
        )?;

    let coefficients: self_product::GroupElement<DIMENSION, _> = coefficients
        .map(|coefficient| {
            bounded_natural_numbers_group::GroupElement::new(
                Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&coefficient),
                &message_group_public_parameters,
            )
        })
        .flat_map_results()?
        .into();

    // = ρ (see DComEval language definition, Section 5.2)
    let commitment_randomness: self_product::GroupElement<DIMENSION, _> = [
        first_coefficient_commitment_randomness,
        second_coefficient_commitment_randomness,
    ]
    .into();

    // = (A, ρ, ω, η)
    let witness = direct_product::FourWayGroupElement::from((
        coefficients,
        commitment_randomness,
        mask,
        encryption_randomness,
    ));

    // === Compute ct_A ===
    // Protocol 6, step 1d and step 1e, dash 3
    let witness = EnhancedLanguage::<
        SOUND_PROOFS_REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        committed_linear_evaluation::Language<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            DIMENSION,
            GroupElement,
            EncryptionKey,
        >,
    >::generate_witness(witness, &language_public_parameters, rng)?;

    let (proof, statement) = CommittedLinearEvaluationProof::<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        RangeProof,
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
    >::prove(
        protocol_context,
        &language_public_parameters,
        vec![witness],
        rng,
    )?;

    let statement = statement.first().ok_or(crate::Error::InternalError)?;

    let range_proof_commitment = *statement.range_proof_commitment();
    let evaluated_ciphertext = *statement.language_statement().evaluated_ciphertext(); // = ct_A

    Ok((proof, range_proof_commitment, evaluated_ciphertext))
}

/// Helper function for Sign Step (2d):
/// Verify $\Pi_{\textsf{zk}}^{L_{\sfDComEval}[G,H,\AHEpk,(\ct_1,\ct_2,(\GG,G,q))]}(\ct,
/// (C_1,C_2);(a_1,a_2), \RandomCom_3\cdot r+\RandomCom_0\cdot
/// m,r\cdot\RandomCom_0,\Randomencryption_1)$
pub fn verify_committed_linear_evaluation<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    const RANGE_CLAIMS_PER_MASK: usize,
    const NUM_RANGE_CLAIMS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    first_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    second_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    evaluated_ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    first_coefficient_commitment: GroupElement,
    second_coefficient_commitment: GroupElement,
    range_proof_commitment: proof::range::CommitmentSchemeCommitmentSpaceValue<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >,
    proof: enhanced_maurer::Proof<
        SOUND_PROOFS_REPETITIONS,
        NUM_RANGE_CLAIMS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
        committed_linear_evaluation::Language<
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            RANGE_CLAIMS_PER_SCALAR,
            RANGE_CLAIMS_PER_MASK,
            DIMENSION,
            GroupElement,
            EncryptionKey,
        >,
        ProtocolContext,
    >,
    commitment_scheme_public_parameters: commitment::PublicParameters<
        SCALAR_LIMBS,
        MultiPedersen<DIMENSION, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    unbounded_dcom_eval_witness_public_parameters: group::PublicParameters<
        UnboundedDComEvalWitness<SCALAR_LIMBS, GroupElement>,
    >,
    range_proof_public_parameters: proof::range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >,
    protocol_context: &ProtocolContext,
    is_rerandomized: bool,
    rng: &mut impl CryptoRngCore,
) -> crate::Result<()> {
    let language_public_parameters = construct_committed_linear_evaluation_public_parameters::<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        GroupElement,
    >(
        first_ciphertext,
        second_ciphertext,
        commitment_scheme_public_parameters,
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters.clone(),
        unbounded_dcom_eval_witness_public_parameters,
        range_proof_public_parameters.clone(),
        is_rerandomized,
    )?;

    let evaluated_ciphertext = CiphertextSpaceGroupElement::new(
        evaluated_ciphertext,
        encryption_scheme_public_parameters.ciphertext_space_public_parameters(),
    )?;

    let range_proof_commitment = proof::range::CommitmentSchemeCommitmentSpaceGroupElement::<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        NUM_RANGE_CLAIMS,
        RangeProof,
    >::new(
        range_proof_commitment,
        range_proof_public_parameters
            .commitment_scheme_public_parameters()
            .commitment_space_public_parameters(),
    )?;

    proof.verify(
        protocol_context,
        &language_public_parameters,
        vec![(
            range_proof_commitment,
            (
                evaluated_ciphertext,
                [first_coefficient_commitment, second_coefficient_commitment].into(),
            )
                .into(),
        )
            .into()],
        rng,
    )?;

    Ok(())
}

/// Construct $L_EncDL$ language parameters.
pub fn construct_encryption_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    unbounded_encdl_witness_public_parameters: group::PublicParameters<UnboundedEncDLWitness>,
    range_proof_public_parameters: proof::range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RangeProof,
    >,
) -> crate::Result<
    EncryptionOfDiscreteLogPublicParameters<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
> {
    let generator = GroupElement::generator_value_from_public_parameters(&group_public_parameters);

    let language_public_parameters = encryption_of_discrete_log::PublicParameters::<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        PlaintextSpaceGroupElement,
        GroupElement,
        EncryptionKey,
    >::new::<PLAINTEXT_SPACE_SCALAR_LIMBS, SCALAR_LIMBS, EncryptionKey>(
        encryption_scheme_public_parameters
            .plaintext_space_public_parameters()
            .clone(),
        group_public_parameters,
        encryption_scheme_public_parameters,
        generator,
        None,
    );

    let enhanced_language_public_parameters = EncryptionOfDiscreteLogPublicParameters::<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        GroupElement,
    >::new::<
        RangeProof,
        UnboundedEncDLWitness,
        EncryptionOfDiscreteLogLanguage<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >,
    >(
        unbounded_encdl_witness_public_parameters,
        range_proof_public_parameters,
        language_public_parameters,
    )?;

    Ok(enhanced_language_public_parameters)
}

/// Construct $L_ScaleDL$ language parameters.
pub fn construct_scaling_of_discrete_log_public_parameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    group_public_parameters: GroupElement::PublicParameters,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    unbounded_scaledl_witness_public_parameters: group::PublicParameters<UnboundedScaleDLWitness>,
    range_proof_public_parameters: proof::range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RangeProof,
    >,
) -> crate::Result<
    ScalingOfDiscreteLogPublicParameters<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
> {
    // This is for languages that multiply by a `ciphertext` public parameter that is an encryption
    // of a scalar, as for the presign protocol.
    let ciphertext_upper_bound = composed_witness_upper_bound::<
        RANGE_CLAIMS_PER_SCALAR,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
    >()?;

    let language_public_parameters = scaling_of_discrete_log::PublicParameters::<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >::new::<SCALAR_LIMBS, GroupElement, EncryptionKey>(
        scalar_group_public_parameters,
        group_public_parameters,
        encryption_scheme_public_parameters,
        ciphertext,
        ciphertext_upper_bound,
    )?;

    let enhanced_language_public_parameters = ScalingOfDiscreteLogPublicParameters::<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        GroupElement,
    >::new::<
        RangeProof,
        UnboundedScaleDLWitness,
        ScalingOfDiscreteLogLanguage<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >,
    >(
        unbounded_scaledl_witness_public_parameters,
        range_proof_public_parameters,
        language_public_parameters,
    )?;

    Ok(enhanced_language_public_parameters)
}

/// Construct $L_EncDL$ language parameters.
pub fn construct_encryption_of_tuple_public_parameters<
    const SCALAR_LIMBS: usize,
    const RANGE_CLAIMS_PER_SCALAR: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
>(
    ciphertext: homomorphic_encryption::CiphertextSpaceValue<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    scalar_group_public_parameters: group::PublicParameters<GroupElement::Scalar>,
    encryption_scheme_public_parameters: homomorphic_encryption::PublicParameters<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        EncryptionKey,
    >,
    unbounded_encdh_witness_public_parameters: group::PublicParameters<UnboundedEncDHWitness>,
    range_proof_public_parameters: proof::range::PublicParameters<
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        RangeProof,
    >,
) -> crate::Result<
    EncryptionOfTuplePublicParameters<SCALAR_LIMBS, RANGE_CLAIMS_PER_SCALAR, GroupElement>,
> {
    // This is for languages that multiply by a `ciphertext` public parameter that is an encryption
    // of a scalar, as for the presign protocol.
    let ciphertext_upper_bound = composed_witness_upper_bound::<
        RANGE_CLAIMS_PER_SCALAR,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
        RangeProof,
    >()?;

    let language_public_parameters = encryption_of_tuple::PublicParameters::<
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
    >::new::<SCALAR_LIMBS, GroupElement, EncryptionKey>(
        scalar_group_public_parameters,
        encryption_scheme_public_parameters,
        ciphertext,
        ciphertext_upper_bound,
    )?;

    let enhanced_language_public_parameters = EncryptionOfTuplePublicParameters::<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        GroupElement,
    >::new::<
        RangeProof,
        UnboundedEncDHWitness,
        EncryptionOfTupleLanguage<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >,
    >(
        unbounded_encdh_witness_public_parameters,
        range_proof_public_parameters,
        language_public_parameters,
    )?;

    Ok(enhanced_language_public_parameters)
}
