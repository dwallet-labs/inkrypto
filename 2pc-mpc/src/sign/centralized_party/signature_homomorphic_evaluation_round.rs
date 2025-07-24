// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

#![allow(clippy::type_complexity)]

use std::fmt::Debug;
use std::marker::PhantomData;

use crypto_bigint::{ConcatMixed, Encoding, Uint};
use serde::{Deserialize, Serialize};

use commitment::{pedersen, CommitmentSizedNumber, HomomorphicCommitmentScheme, Pedersen};
use group::{
    AffineXCoordinate, CsRng, GroupElement as _, HashToGroup, Invert, PrimeGroupElement, Samplable,
    StatisticalSecuritySizedNumber,
};
use homomorphic_encryption::AdditivelyHomomorphicEncryptionKey;

use crate::dkg::centralized_party::SecretKeyShare;
use crate::languages::{
    CommitmentOfDiscreteLogProof, EqualityBetweenCommitmentsWithDifferentPublicParametersProof,
    KnowledgeOfDecommitmentProof, KnowledgeOfDecommitmentUCProof,
    VectorCommitmentOfDiscreteLogProof,
};
use crate::Party::CentralizedParty;
use crate::{dkg, languages, presign, sign, Error, ProtocolContext, Result};

#[cfg(feature = "class_groups")]
mod class_groups;

#[cfg(all(feature = "paillier", feature = "bulletproofs"))]
mod paillier;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Party<
    const SCALAR_LIMBS: usize,
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
    SignMessage,
    ProtocolPublicParameters,
>(
    PhantomData<GroupElement>,
    PhantomData<EncryptionKey>,
    PhantomData<SignMessage>,
    PhantomData<ProtocolPublicParameters>,
);

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        SignMessage,
        ProtocolPublicParameters,
    >
    Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        SignMessage,
        ProtocolPublicParameters,
    >
where
    ProtocolPublicParameters: AsRef<
        crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
    >,
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
{
    /// This function implements round 1 of Protocol C.3 (Sign):
    /// Computes \textsf{ct}_A, \textsf{ct}_{\alpha,\beta}, R  and constructs zk-proofs their generation.
    /// src: <https://eprint.iacr.org/archive/2024/253/20240217:153208>
    ///
    /// Evaluate the encrypted partial signature, the encrypted translated final signature nonce and the translated public nonce.
    /// Note: `hashed_message` is a `Scalar` which must be a hash on the message bytes translated into a
    /// 32-byte number.
    fn evaluate_encryption_of_partial_signature_prehash(
        hashed_message: GroupElement::Scalar,
        centralized_party_secret_key_share: group::Value<GroupElement::Scalar>,
        centralized_party_dkg_public_output: dkg::centralized_party::PublicOutput<
            GroupElement::Value,
        >,
        presign: presign::Presign<
            GroupElement::Value,
            group::Value<EncryptionKey::CiphertextSpaceGroupElement>,
        >,
        protocol_public_parameters: &ProtocolPublicParameters,
        session_id: CommitmentSizedNumber,
        rng: &mut impl CsRng,
    ) -> Result<(
        GroupElement::Scalar,
        GroupElement::Scalar,
        GroupElement::Scalar,
        GroupElement::Scalar,
        GroupElement::Scalar,
        GroupElement::Scalar,
        GroupElement::Scalar,
        GroupElement::Scalar,
        GroupElement,
        GroupElement,
        GroupElement,
        GroupElement,
        GroupElement,
        GroupElement,
        EncryptionKey::CiphertextSpaceGroupElement,
        KnowledgeOfDecommitmentProof<SCALAR_LIMBS, GroupElement>,
        KnowledgeOfDecommitmentProof<SCALAR_LIMBS, GroupElement>,
        KnowledgeOfDecommitmentUCProof<SCALAR_LIMBS, GroupElement>,
        EqualityBetweenCommitmentsWithDifferentPublicParametersProof<SCALAR_LIMBS, GroupElement>,
        CommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
        VectorCommitmentOfDiscreteLogProof<SCALAR_LIMBS, GroupElement>,
    )> {
        if presign.public_key != centralized_party_dkg_public_output.public_key {
            return Err(Error::InvalidParameters);
        }

        let protocol_public_parameters = protocol_public_parameters.as_ref();

        let commitment_scheme_public_parameters =
            pedersen::PublicParameters::derive::<SCALAR_LIMBS, GroupElement>(
                protocol_public_parameters
                    .scalar_group_public_parameters
                    .clone(),
                protocol_public_parameters.group_public_parameters.clone(),
            )?;

        // --- Step (1b) ---
        // i.:
        // Sample $k_{A}$ and $\rho_0$, and compute:
        // $C_{k}=\textsf{Pedersen}.\textsf{Com}_{G,H}(k_A;\rho_0)$
        // $(k_{A}, \rho_0,  C_{k})$
        let (
            signature_nonce_share,
            signature_nonce_share_commitment_randomness,
            signature_nonce_share_commitment,
        ) = Self::sample_and_commit_to_witness(
            &commitment_scheme_public_parameters,
            protocol_public_parameters,
            rng,
        )?;

        // ii.:
        // Sample $\alpha$ and $\rho_1$, and compute:
        // $C_\alpha=\textsf{Pedersen}.\textsf{Com}_{G,H}(\alpha;\rho_1)$
        // $(\alpha, \rho_1,  C_\alpha)$
        let (alpha_displacer, alpha_displacer_commitment_randomness, alpha_displacer_commitment) =
            Self::sample_and_commit_to_witness(
                &commitment_scheme_public_parameters,
                protocol_public_parameters,
                rng,
            )?;

        // iii.:
        // Sample $\beta$ and $\rho_2$, and compute:
        // $C_\beta=\textsf{Pedersen}.\textsf{Com}_{G,H}(\beta;\rho_2)$
        // $(\beta, \rho_2,  C_\beta)$
        let (beta_displacer, beta_displacer_commitment_randomness, beta_displacer_commitment) =
            Self::sample_and_commit_to_witness(
                &commitment_scheme_public_parameters,
                protocol_public_parameters,
                rng,
            )?;

        // iv.:
        // Sample $\rho_3$, and compute:
        // $C_{kx}=\textsf{Pedersen}.\textsf{Com}_{X_{A},H}(k_A;\rho_3) [=\textsf{Pedersen}.\textsf{Com}_{G,H}(k_A x_A;\rho_3)]$
        // $(k_{A}, \rho_3,  C_{kx})$
        let (
            signature_nonce_share_by_secret_share_commitment_randomness,
            signature_nonce_share_by_secret_share_commitment,
        ) = Self::commit_to_witness(
            signature_nonce_share,
            &commitment_scheme_public_parameters.with_altered_message_generators([
                centralized_party_dkg_public_output.public_key_share,
            ]),
            protocol_public_parameters,
            rng,
        )?;

        // --- Step (1c) ---
        // $ (k_{A})^{-1} $
        let inverted_signature_nonce_share = signature_nonce_share.invert();
        if inverted_signature_nonce_share.is_none().into() {
            // This has negligible probability of failing.
            return Err(Error::InternalError);
        }
        let inverted_signature_nonce_share = inverted_signature_nonce_share.unwrap();

        let (
            non_zero_commitment_to_signature_nonce_share_protocol_context,
            non_zero_commitment_to_alpha_displacer_share_protocol_context,
            commitment_to_beta_displacer_share_protocol_context,
            equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments_protocol_context,
            decentralized_party_nonce_public_share_displacement_protocol_context,
            public_signature_nonce_protocol_context,
            ..,
        ) = generate_protocol_contexts(session_id, &centralized_party_dkg_public_output.public_key);

        // Compute FS-proof $\pi_{k} =
        // \Pi_{\textsf{zk}}^{L_{\textsf{Dcom}[C_{k},H]}}(G;k_{A}^{-1},-k_{
        // A}^{-1}\rho_{0})$
        let (non_zero_commitment_to_signature_nonce_share_proof, _) =
            languages::prove_knowledge_of_decommitment(
                inverted_signature_nonce_share,
                (-inverted_signature_nonce_share) * signature_nonce_share_commitment_randomness,
                commitment_scheme_public_parameters
                    .with_altered_message_generators([signature_nonce_share_commitment.value()])
                    .clone(),
                &non_zero_commitment_to_signature_nonce_share_protocol_context,
                rng,
            )?;

        // $ (\alpha)^{-1} $
        let inverted_alpha_displacer = alpha_displacer.invert();
        if inverted_alpha_displacer.is_none().into() {
            // This has negligible probability of failing.
            return Err(Error::InternalError);
        }
        let inverted_alpha_displacer = inverted_alpha_displacer.unwrap();

        // Compute FS-proof $\pi_{\alpha} = \Pi_{\textsf {zk}}^{L_{\sf
        // Dcom}[C_{\alpha},H]}(G;(\alpha^{-1},-\alpha^{-1}\rho_1)$
        let (non_zero_commitment_to_alpha_displacer_share_proof, _) =
            languages::prove_knowledge_of_decommitment(
                inverted_alpha_displacer,
                (-inverted_alpha_displacer) * alpha_displacer_commitment_randomness,
                commitment_scheme_public_parameters
                    .with_altered_message_generators([alpha_displacer_commitment.value()])
                    .clone(),
                &non_zero_commitment_to_alpha_displacer_share_protocol_context,
                rng,
            )?;

        // Compute UC-extractable Fischlin proof $\pi_{\beta} = \Pi_{\textsf {zk-uc}}^{L_{\sf Dcom}[G,H]}(
        // C_\beta;\beta,\rho_2)$
        let (commitment_to_beta_displacer_share_uc_proof, _) =
            languages::uc_prove_knowledge_of_decommitment(
                beta_displacer,
                beta_displacer_commitment_randomness,
                commitment_scheme_public_parameters.clone(),
                &commitment_to_beta_displacer_share_protocol_context,
                rng,
            )?;

        // --- Step (1d) ---
        // Call the random oracle
        // $\mathcal{H}(\textsf{sid},\mathbb{G},G,q,H,X,\textsf{pres}_{X,\textsf{sid}},C_{k},C_{kx},X_{A},C_{\
        // alpha},C_{\beta},\pi_{k},\pi_{\alpha},\pi_{\beta})$, and receives $\mu_{k}$. It then
        // computes:
        // - $\textsf{ct}_{\gamma\cdot k_{0}}=(\textsf{ct}_{\gamma\cdot k})\oplus(\mu_{k}\odot\textsf{ct}_{\gamma\cdot k_{1}})$
        // - $R'_B=( R_{B,0})+(\mu_{k}\cdot R_{B,1})$

        // ($\textsf{ct}_{\gamma\cdot k}$, $R'_B$)
        let (encryption_of_masked_decentralized_party_nonce_share_before_displacing, decentralized_party_nonce_public_share_before_displacing) = sign::derive_randomized_decentralized_party_public_nonce_share_and_encryption_of_nonce_share::<
            SCALAR_LIMBS,
            PLAINTEXT_SPACE_SCALAR_LIMBS,
            GroupElement,
            EncryptionKey,
        >(
            session_id,
            &hashed_message,
            presign.clone(),
            &protocol_public_parameters.encryption_scheme_public_parameters,
            &protocol_public_parameters.group_public_parameters,
            &commitment_scheme_public_parameters,
            &centralized_party_dkg_public_output.public_key,
            &centralized_party_dkg_public_output.public_key_share,
            &signature_nonce_share_commitment,
            &alpha_displacer_commitment,
            &beta_displacer_commitment,
            &signature_nonce_share_by_secret_share_commitment,
            &non_zero_commitment_to_signature_nonce_share_proof,
            &non_zero_commitment_to_alpha_displacer_share_proof,
            &commitment_to_beta_displacer_share_uc_proof,
        )?;

        // --- Step (1e) ---
        // This step samples encryption randomizers for homomorphic evaluation, we delay this to step (f), as
        // some of the statements and proofs are independent of those randomizers.
        // --- Step (1f) ---
        // (f) i. $ (\pi_{kx},C_k,C_{kx}) $
        let (
            proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments,
            ..,
        ) = languages::prove_equality_between_commitments_with_different_public_parameters(
            signature_nonce_share,
            signature_nonce_share_commitment_randomness,
            signature_nonce_share_by_secret_share_commitment_randomness,
            commitment_scheme_public_parameters.clone(),
            commitment_scheme_public_parameters
                .with_altered_message_generators([centralized_party_dkg_public_output.public_key_share]),
            &equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments_protocol_context,
            rng,
        )?;

        // (f) iii. $(\pi_{R_{B}}, R_B)$
        let (
            decentralized_party_nonce_public_share_displacement_proof,
            decentralized_party_nonce_public_share,
        ) = languages::prove_vector_commitment_of_discrete_log::<SCALAR_LIMBS, GroupElement>(
            alpha_displacer,
            alpha_displacer_commitment_randomness,
            beta_displacer,
            beta_displacer_commitment_randomness,
            decentralized_party_nonce_public_share_before_displacing.value(),
            commitment_scheme_public_parameters.clone().into(),
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            &decentralized_party_nonce_public_share_displacement_protocol_context,
            rng,
        )?;

        // (e) iii. $R=k_A^{-1}\cdot R_B$
        let public_signature_nonce =
            inverted_signature_nonce_share * decentralized_party_nonce_public_share;

        // (e) iii. and $r=R_{x-axis}$
        let nonce_x_coordinate = public_signature_nonce.x();

        // (f) ii. $\pi_{R}$
        let (public_signature_nonce_proof, ..) = languages::prove_commitment_of_discrete_log(
            signature_nonce_share,
            signature_nonce_share_commitment_randomness,
            public_signature_nonce.value(),
            commitment_scheme_public_parameters.clone(),
            protocol_public_parameters
                .scalar_group_public_parameters
                .clone(),
            protocol_public_parameters.group_public_parameters.clone(),
            &public_signature_nonce_protocol_context,
            rng,
        )?;

        let secret_key_share = GroupElement::Scalar::new(
            centralized_party_secret_key_share,
            &protocol_public_parameters.scalar_group_public_parameters,
        )?;

        // (e) iv. $ a_1=r\cdot k_A\cdot x_\A+m\cdot k_A $
        let first_coefficient = (nonce_x_coordinate * signature_nonce_share * secret_key_share)
            + (hashed_message * signature_nonce_share);

        // (f) v. $ \rho_3\cdot r+\rho_0\cdot m $
        let first_coefficient_commitment_randomness = (nonce_x_coordinate
            * signature_nonce_share_by_secret_share_commitment_randomness)
            + (hashed_message * signature_nonce_share_commitment_randomness);

        // (e) iv. $ a_2=r\cdot k_A$
        let second_coefficient = nonce_x_coordinate * signature_nonce_share;

        // (f) v. $ r\cdot \rho_0 $
        let second_coefficient_commitment_randomness =
            nonce_x_coordinate * signature_nonce_share_commitment_randomness;

        Ok((
            beta_displacer,
            beta_displacer_commitment_randomness,
            alpha_displacer,
            alpha_displacer_commitment_randomness,
            first_coefficient,
            first_coefficient_commitment_randomness,
            second_coefficient,
            second_coefficient_commitment_randomness,
            public_signature_nonce,
            decentralized_party_nonce_public_share,
            signature_nonce_share_commitment,
            alpha_displacer_commitment,
            beta_displacer_commitment,
            signature_nonce_share_by_secret_share_commitment,
            encryption_of_masked_decentralized_party_nonce_share_before_displacing,
            non_zero_commitment_to_signature_nonce_share_proof,
            non_zero_commitment_to_alpha_displacer_share_proof,
            commitment_to_beta_displacer_share_uc_proof,
            proof_of_equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments,
            public_signature_nonce_proof,
            decentralized_party_nonce_public_share_displacement_proof,
        ))
    }

    /// Helper for Step (1b):
    /// Sample $w$ and $\rho$, and compute:
    /// $C=\textsf{Pedersen}.\textsf{Com}_{G,H}(w;\rho)$
    fn sample_and_commit_to_witness(
        commitment_scheme_public_parameters: &commitment::PublicParameters<
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >,
        protocol_public_parameters: &crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(GroupElement::Scalar, GroupElement::Scalar, GroupElement)> {
        let witness = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )?;

        let (randomness, commitment) = Self::commit_to_witness(
            witness,
            commitment_scheme_public_parameters,
            protocol_public_parameters,
            rng,
        )?;

        Ok((witness, randomness, commitment))
    }

    /// Helper for Step (1b):
    /// Sample $\rho$, and compute:
    /// $C=\textsf{Pedersen}.\textsf{Com}_{G,H}(w;\rho)$
    fn commit_to_witness(
        witness: GroupElement::Scalar,
        commitment_scheme_public_parameters: &commitment::PublicParameters<
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>,
        >,
        protocol_public_parameters: &crate::ProtocolPublicParameters<
            group::PublicParameters<GroupElement::Scalar>,
            GroupElement::PublicParameters,
            EncryptionKey::PublicParameters,
        >,
        rng: &mut impl CsRng,
    ) -> Result<(GroupElement::Scalar, GroupElement)> {
        let randomness = GroupElement::Scalar::sample(
            &protocol_public_parameters.scalar_group_public_parameters,
            rng,
        )?;

        let commitment_scheme =
            Pedersen::<1, SCALAR_LIMBS, GroupElement::Scalar, GroupElement>::new(
                commitment_scheme_public_parameters,
            )?;

        let commitment = commitment_scheme.commit(&[witness].into(), &randomness);

        Ok((randomness, commitment))
    }
}

pub(crate) fn generate_protocol_contexts<GroupElementValue: Serialize>(
    session_id: CommitmentSizedNumber,
    public_key: &GroupElementValue,
) -> (
    ProtocolContext,
    ProtocolContext,
    ProtocolContext,
    ProtocolContext,
    ProtocolContext,
    ProtocolContext,
    ProtocolContext,
    ProtocolContext,
) {
    let non_zero_commitment_to_signature_nonce_share_protocol_context: ProtocolContext =
        generate_protocol_context(
            session_id,
            "$\\pi_{k}$ - Non-Zero Commitment to Centralized Party Signature Nonce Share Proof",
            public_key,
        );
    let non_zero_commitment_to_alpha_displacer_share_protocol_context: ProtocolContext =
        generate_protocol_context(
            session_id,
            "$\\pi_{\\alpha}$ - Non-Zero Commitment to Alpha Displacer Proof",
            public_key,
        );
    let commitment_to_beta_displacer_share_protocol_context: ProtocolContext =
        generate_protocol_context(
            session_id,
            "$\\pi_{\\beta}$ - Commitment to Beta Displacer UC Proof",
            public_key,
        );
    let equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments_protocol_context: ProtocolContext = generate_protocol_context(session_id, "$\\pi_{kx}$ - Proof of Equality Between Centralized Party Nonce Share and Nonce Share by Secret Key Share Commitments", public_key);
    let decentralized_party_nonce_public_share_displacement_protocol_context: ProtocolContext = generate_protocol_context(session_id, "$\\pi_{R_{\\DistributedParty}$ - Decentralized Party Nonce Public Share Displacement Proof", public_key);
    let public_signature_nonce_protocol_context: ProtocolContext = generate_protocol_context(
        session_id,
        "$\\pi_{R}$ - Public Signature Nonce Proof",
        public_key,
    );
    let encryption_of_displaced_decentralized_party_nonce_share_protocol_context: ProtocolContext =
        generate_protocol_context(
            session_id,
            "$\\pi_{\\ctab}$ - Encryption of Displaced Decentralized Party Nonce Share Proof",
            public_key,
        );
    let encryption_of_partial_signature_protocol_context: ProtocolContext =
        generate_protocol_context(
            session_id,
            "$\\pi_{\\ct_{\\CentralizedParty}}$ - Encryption of Partial Signature Proof",
            public_key,
        );

    (non_zero_commitment_to_signature_nonce_share_protocol_context, non_zero_commitment_to_alpha_displacer_share_protocol_context, commitment_to_beta_displacer_share_protocol_context, equality_between_nonce_share_and_nonce_share_by_secret_key_share_commitments_protocol_context, decentralized_party_nonce_public_share_displacement_protocol_context, public_signature_nonce_protocol_context, encryption_of_displaced_decentralized_party_nonce_share_protocol_context, encryption_of_partial_signature_protocol_context)
}

fn generate_protocol_context<GroupElementValue: Serialize>(
    session_id: CommitmentSizedNumber,
    proof_name: &str,
    public_key: &GroupElementValue,
) -> ProtocolContext {
    ProtocolContext {
        party: CentralizedParty,
        session_id,
        protocol_name: "2PC-MPC Sign".to_string(),
        round_name: "1 - Signature Homomorphic Evaluation".to_string(),
        proof_name: proof_name.to_string(),
        public_key: serde_json::to_vec(public_key).ok(),
    }
}

/// The public input of the decentralized party's Sign protocol.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicInput<Scalar, DKGOutput, Presign, ProtocolPublicParameters> {
    pub hashed_message: Scalar,
    pub dkg_output: DKGOutput,
    pub presign: Presign,
    pub protocol_public_parameters: ProtocolPublicParameters,
}

impl<Scalar, DKGOutput, Presign, ProtocolPublicParameters>
    From<(Scalar, DKGOutput, Presign, ProtocolPublicParameters)>
    for PublicInput<Scalar, DKGOutput, Presign, ProtocolPublicParameters>
{
    fn from(
        (hashed_message, dkg_output, presign, protocol_public_parameters): (
            Scalar,
            DKGOutput,
            Presign,
            ProtocolPublicParameters,
        ),
    ) -> Self {
        Self {
            hashed_message,
            dkg_output,
            presign,
            protocol_public_parameters,
        }
    }
}

impl<
        const SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS> + AffineXCoordinate<SCALAR_LIMBS> + group::HashToGroup,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        SignMessage: Serialize + for<'a> Deserialize<'a> + Clone + Serialize + Debug + PartialEq + Eq,
        ProtocolPublicParameters: Clone + Serialize + Debug + PartialEq + Eq + Send + Sync,
    > Default
    for Party<
        SCALAR_LIMBS,
        PLAINTEXT_SPACE_SCALAR_LIMBS,
        GroupElement,
        EncryptionKey,
        SignMessage,
        ProtocolPublicParameters,
    >
{
    fn default() -> Self {
        Self(PhantomData, PhantomData, PhantomData, PhantomData)
    }
}
