// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use std::collections::HashSet;
use std::{collections::HashMap, fmt::Debug};

use crypto_bigint::{subtle::CtOption, Uint};
use serde::{Deserialize, Serialize};

use group::{
    CsRng, GroupElement, KnownOrderScalar, LinearlyCombinable, PartyID, Samplable, Transcribeable,
};

/// An error in encryption-related operations.
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("zero dimension: cannot evaluate a zero-dimension linear combination")]
    ZeroDimension,
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("the requested function cannot be securely evaluated")]
    SecureFunctionEvaluation,
}

/// The Result of `new()` operation for types implementing the
/// [`AdditivelyHomomorphicEncryptionKey`] trait.
pub type Result<T> = std::result::Result<T, Error>;

/// An Encryption Key of an Additively Homomorphic Encryption scheme.
pub trait AdditivelyHomomorphicEncryptionKey<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize>:
    PartialEq + Clone + Debug + Eq + Send + Sync
{
    type PlaintextSpaceGroupElement: KnownOrderScalar<PLAINTEXT_SPACE_SCALAR_LIMBS>;
    type RandomnessSpaceGroupElement: GroupElement + Samplable;
    type CiphertextSpaceGroupElement: GroupElement;

    /// The public parameters of the encryption scheme.
    ///
    /// Includes the public parameters of the plaintext, randomness and ciphertext groups.
    ///
    /// Used in [`Self::encrypt()`] to define the encryption algorithm.
    /// As such, it uniquely identifies the encryption-scheme (alongside the type `Self`) and will
    /// be used for Fiat-Shamir Transcripts.
    type PublicParameters: AsRef<
            GroupsPublicParameters<
                PlaintextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, Self>,
                RandomnessSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, Self>,
                CiphertextSpacePublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, Self>,
            >,
        > + Transcribeable
        + Serialize
        + for<'r> Deserialize<'r>
        + PartialEq
        + Clone
        + Debug
        + Eq
        + Send
        + Sync;

    /// Instantiate the encryption key from the public parameters of the encryption scheme.
    fn new(public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// $\Enc(pk, \pt; \eta_{\sf enc}) \to \ct$: Encrypt `plaintext` to `self` using
    /// `randomness`.
    ///
    /// A deterministic algorithm that inputs a public key $pk$, a plaintext $\pt \in \calP_{pk}$
    /// and randomness $\eta_{\sf enc} \in \calR_{pk}$, outputs a ciphertext $\ct \in \calC_{pk}$.
    fn encrypt_with_randomness(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
        is_vartime: bool,
    ) -> Self::CiphertextSpaceGroupElement;

    /// $\Enc(pk, \pt)$: a probabilistic algorithm that first uniformly samples `randomness`
    /// $\eta_{\sf enc} \in \calR_{pk}$ from `rng` and then calls
    /// [`Self::encrypt_with_randomness()`] to encrypt `plaintext` to `self` using the sampled
    /// randomness.
    fn encrypt(
        &self,
        plaintext: &Self::PlaintextSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
        is_vartime: bool,
        rng: &mut impl CsRng,
    ) -> Result<(
        Self::RandomnessSpaceGroupElement,
        Self::CiphertextSpaceGroupElement,
    )> {
        let randomness = Self::RandomnessSpaceGroupElement::sample(
            public_parameters.randomness_space_public_parameters(),
            rng,
        )?;

        let ciphertext =
            self.encrypt_with_randomness(plaintext, &randomness, public_parameters, is_vartime);

        Ok((randomness, ciphertext))
    }

    /// Efficient homomorphic evaluation of the linear
    /// combination defined by `coefficients` and `ciphertexts`.
    /// Returns $a_1 \odot \ct_1 \oplus \ldots \oplus a_\ell \odot \ct_\ell$.
    /// For an affine transformation, prepend ciphertexts with $\ct_0 = \Enc(1)$.
    ///
    /// SECURITY NOTE: This method *doesn't* assure circuit privacy.
    /// For circuit private implementation, use [`Self::securely_evaluate_linear_combination`].
    fn evaluate_linear_combination<const MESSAGE_LIMBS: usize, const DIMENSION: usize>(
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        coefficient_upper_bound_bits: u32,
        ciphertexts: &[Self::CiphertextSpaceGroupElement; DIMENSION],
        _public_parameters: &Self::PublicParameters,
        is_vartime: bool,
    ) -> Result<Self::CiphertextSpaceGroupElement> {
        let bases_and_multiplicands = ciphertexts
            .iter()
            .copied()
            .zip(coefficients.iter().copied())
            .collect();

        let linear_combination = if is_vartime {
            Self::CiphertextSpaceGroupElement::linearly_combine_bounded_vartime(
                bases_and_multiplicands,
                coefficient_upper_bound_bits,
            )?
        } else {
            Self::CiphertextSpaceGroupElement::linearly_combine_bounded(
                bases_and_multiplicands,
                coefficient_upper_bound_bits,
            )?
        };

        Ok(linear_combination)
    }

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_\ell; \omega, \eta)$: Secure function evaluation.
    ///
    /// This function securely computes an efficient homomorphic evaluation of the
    /// linear combination defined by `coefficients` and `ciphertexts`:
    /// $f(x_1,\ldots,x_\ell)=\sum_{i=1}^{\ell}{a_i x_i}$ where
    /// $a_i\in [0,q)$, and $\ell$ ciphertexts $\ct_1,\ldots,\ct_\ell$.
    ///
    /// For an affine transformation, prepend ciphertexts with $\ct_0 = \Enc(1)$.
    ///
    /// _Secure function evaluation_ states that giving the resulting ciphertext of the above
    /// evaluation to the decryption key owner for decryption does not reveal anything about $f$
    /// except what can be learned from the (decrypted) result alone.
    ///
    /// This is ensured by masking the linear combination with a random (`mask`)
    /// multiplication $\omega$ of the `modulus` $q$, and adding a fresh `randomness` $\eta$, which
    /// can be thought of as decrypting and re-encrypting with a fresh randomness:
    /// \ct = \Enc(pk, \omega q; \eta) \bigoplus_{i=1}^\ell \left(  a_i \odot \ct_i  \right)
    ///
    /// Let $\PT_i$ be the upper bound associated with $\ct_i$ (that is, this is the maximal value
    /// one obtains from decrypting $\ct_i$, but without reducing modulo $q$),
    /// where $\omega$ is uniformly chosen from $[0,2^s\PTsum)$ and $\eta$ is uniformly chosen from
    /// $\ZZ_N^*$.
    /// Then, the upper bound associated with the resulting $\ct$ is
    /// $$ \PT_{\sf eval} = (2^s+1)\cdot q\cdot \PTsum $$ and
    /// Correctness is assured as long as $\PT_{\sf eval}<N$.
    ///
    /// In more detail, these steps are taken to generically assure circuit privacy:
    /// 1. Re-randomization. This should be done by adding encryption of zero with fresh (uniformly
    ///    sampled) randomness to the outputted ciphertext.
    ///
    /// 2. Masking. Our evaluation should be masked by a random multiplication of the homomorphic
    ///    evaluation group order $q$.
    ///
    ///    While the decryption modulo $q$ will remain correct,
    ///    assuming that the mask was "big enough", i.e., $\omega$ is uniformly chosen from
    ///    $[0,2^s\PTsum)$, The decryption will also be statistically indistinguishable from
    ///    random.
    ///
    ///    *NOTE*: this function cannot (and in fact, does not) guarantee that
    ///    each of the given ciphertexts $\ct_i$ is in fact bounded by its corresponding
    ///    upper-bound $\PT_i$.
    ///    Instead, this responsibility is on the caller, which needs to ensure
    ///    that by verifying appropriate zero-knowledge (and range) proofs.
    ///    An exception to the above is when the ciphertext was encrypted by the caller,
    ///    in which case the caller knows the corresponding plaintext.
    ///
    /// 3. No modulations. The size of our evaluation $\PT_{\sf eval}$ should be smaller than the
    ///    order of the encryption plaintext group $N$ to ensure it does not go through modulation
    ///    in the plaintext space.
    ///
    /// In the case that the plaintext order is the same as the evaluation `modulus`, steps 2, 3 are
    /// skipped.
    ///
    /// See: Definition $2.1, B.2, B.3, D.1$ in "2PC-MPC: Threshold ECDSA in $\calO(1)$".
    #[allow(clippy::too_many_arguments)]
    fn securely_evaluate_linear_combination_with_randomness<
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
    >(
        &self,
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        coefficient_upper_bound_bits: u32,
        ciphertexts_and_encoded_messages_upper_bounds: [(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        mask: &Self::PlaintextSpaceGroupElement,
        randomness: &Self::RandomnessSpaceGroupElement,
        public_parameters: &Self::PublicParameters,
        is_vartime: bool,
    ) -> Result<Self::CiphertextSpaceGroupElement>;

    /// Samples the mask $\omega$ is uniformly from $[0,2^s\PTsum)$, as required for secure function
    /// evaluation.
    fn sample_mask_for_secure_function_evaluation<
        const MESSAGE_LIMBS: usize,
        const DIMENSION: usize,
    >(
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        ciphertexts_and_encoded_messages_upper_bounds: &[(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> Result<Self::PlaintextSpaceGroupElement>;

    /// $\Eval(pk,f, \ct_1,\ldots,\ct_t; \eta_{\sf eval})$: Secure function evaluation.
    ///
    /// This is the probabilistic linear combination algorithm that samples `mask` and `randomness`
    /// from `rng` and calls [`Self::securely_evaluate_linear_combination_with_randomness()`].
    #[allow(clippy::too_many_arguments)]
    fn securely_evaluate_linear_combination<const MESSAGE_LIMBS: usize, const DIMENSION: usize>(
        &self,
        coefficients: &[Uint<MESSAGE_LIMBS>; DIMENSION],
        coefficient_upper_bound_bits: u32,
        ciphertexts_and_encoded_messages_upper_bounds: [(
            Self::CiphertextSpaceGroupElement,
            Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        ); DIMENSION],
        modulus: &Uint<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        public_parameters: &Self::PublicParameters,
        is_vartime: bool,
        rng: &mut impl CsRng,
    ) -> Result<(
        Self::PlaintextSpaceGroupElement,
        Self::RandomnessSpaceGroupElement,
        Self::CiphertextSpaceGroupElement,
    )> {
        let randomness = Self::RandomnessSpaceGroupElement::sample(
            public_parameters.randomness_space_public_parameters(),
            rng,
        )?;

        let mask =
            // Then sample the mask uniformly from $[0,2^s\PTsum)$.
            Self::sample_mask_for_secure_function_evaluation(
                coefficients,
                &ciphertexts_and_encoded_messages_upper_bounds,
                modulus,
                public_parameters,
                rng,
            )?;

        let evaluated_ciphertext = self.securely_evaluate_linear_combination_with_randomness(
            coefficients,
            coefficient_upper_bound_bits,
            ciphertexts_and_encoded_messages_upper_bounds,
            modulus,
            &mask,
            &randomness,
            public_parameters,
            is_vartime,
        )?;

        Ok((mask, randomness, evaluated_ciphertext))
    }
}

/// A Decryption Key of an Additively Homomorphic Encryption scheme.
pub trait AdditivelyHomomorphicDecryptionKey<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>: AsRef<EncryptionKey> + Clone + PartialEq + Send + Sync
{
    /// The decryption key used for decryption.
    type SecretKey;

    /// Instantiate the decryption key from the public parameters of the encryption scheme,
    /// and the secret key.
    fn new(
        secret_key: Self::SecretKey,
        public_parameters: &EncryptionKey::PublicParameters,
    ) -> Result<Self>;

    /// $\Dec(sk, \ct) \to \pt$: Decrypt `ciphertext` using `decryption_key`.
    /// A deterministic algorithm that inputs a secret key $sk$ and a ciphertext $\ct \in
    /// \calC_{pk}$ outputs a plaintext $\pt \in \calP_{pk}$.
    ///
    /// SECURITY NOTE: in some decryption schemes, like RLWE-based schemes, decryption can fail, and
    /// this could in turn leak secret data if not handled carefully.
    /// In this case, this
    /// function must execute in constant time.
    /// However, that isn't sufficient; the caller must also
    /// handle the results in constant time.
    /// One way is by verifying zero-knowledge proofs
    /// before decrypting, so you only decrypt when you know you've succeeded.
    /// Another is the
    /// classic way of handling `CtOption`, which is to perform some computation over garbage (e.g.
    /// `Default`) values if `.is_none()`.
    /// An example for this is RLWE-based key-exchange
    /// protocols, where you decrypt and if you fail, you perform the computation over a garbage
    /// value and send it anyway.
    fn decrypt(
        &self,
        ciphertext: &EncryptionKey::CiphertextSpaceGroupElement,
        public_parameters: &EncryptionKey::PublicParameters,
    ) -> CtOption<EncryptionKey::PlaintextSpaceGroupElement>;
}

/// A Decryption Key Share of a Threshold Additively Homomorphic Encryption scheme.
pub trait AdditivelyHomomorphicDecryptionKeyShare<
    const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
    EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
>: AsRef<EncryptionKey> + Clone + PartialEq + Send + Sync
{
    /// The decryption key share used for decryption.
    type SecretKeyShare;
    /// A decryption share of a ciphertext in the process of Threshold Decryption.
    type DecryptionShare: Clone + Debug + PartialEq + Eq + Default + Send + Sync;
    /// A proof that a decryption share was correctly computed on a ciphertext using the decryption
    /// key share `Self`.
    type PartialDecryptionProof: Clone + Debug + PartialEq + Eq + Send + Sync;
    /// A lagrange coefficient used for Threshold Decryption.
    /// These values are passed to the `Self::combine_decryption_shares` methods
    /// separately from `Self::PublicParameters` as they depend on the decrypter set.
    type LagrangeCoefficient: Clone + Debug + PartialEq + Eq;
    /// The public parameters of the threshold decryption scheme.
    type PublicParameters: AsRef<EncryptionKey::PublicParameters>
        + Serialize
        + for<'r> Deserialize<'r>
        + PartialEq
        + Clone
        + Debug
        + Eq
        + Send
        + Sync;

    /// An error in threshold decryption.
    type Error: Debug + Send + Sync + Clone;

    /// Instantiate the decryption key share from the public parameters of the threshold decryption
    /// scheme, and the secret key share.
    fn new(
        party_id: PartyID,
        secret_key_share: Self::SecretKeyShare,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> std::result::Result<Self, Self::Error>;

    /// The party id $j$ of the decryption key share $x_j$.
    fn party_id(&self) -> PartyID;

    /// The threshold $t$.
    fn threshold(public_parameters: &Self::PublicParameters) -> PartyID;

    /// The number of parties $n$.
    fn number_of_parties(public_parameters: &Self::PublicParameters) -> PartyID;

    /// The Semi-honest variant of Partial Decryption, returns the decryption share without proving
    /// correctness.
    ///
    /// SECURITY NOTE: see the corresponding note in
    /// [`AdditivelyHomomorphicDecryptionKey::decrypt`]; the same applies here.
    fn generate_decryption_share_semi_honest(
        &self,
        ciphertext: &EncryptionKey::CiphertextSpaceGroupElement,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> CtOption<Self::DecryptionShare>;

    /// Performs the Maliciously secure Partial Decryption in which decryption shares are computed
    /// and proven correct.
    ///
    /// SECURITY NOTE: see the corresponding note in
    /// [`AdditivelyHomomorphicDecryptionKey::decrypt`]; the same applies here.
    fn generate_decryption_shares(
        &self,
        ciphertexts: Vec<EncryptionKey::CiphertextSpaceGroupElement>,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> CtOption<(Vec<Self::DecryptionShare>, Self::PartialDecryptionProof)>;

    /// Finalizes the Threshold Decryption protocol by combining decryption shares. This is the
    /// Semi-Honest variant in which no proofs are verified.
    ///
    /// Correct decryption isn't assured upon success,
    /// and one should be able to verify the output independently or trust the process was done
    /// correctly.
    fn combine_decryption_shares_semi_honest(
        ciphertexts: Vec<EncryptionKey::CiphertextSpaceGroupElement>,
        decryption_shares: HashMap<PartyID, Vec<Self::DecryptionShare>>,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> std::result::Result<Vec<EncryptionKey::PlaintextSpaceGroupElement>, Self::Error>;

    /// For malicious security, verify partial decryption zero-knowledge proofs
    /// and report the players who sent wrong decryption shares.
    fn identify_malicious_decrypters(
        ciphertexts: Vec<EncryptionKey::CiphertextSpaceGroupElement>,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (Vec<Self::DecryptionShare>, Self::PartialDecryptionProof),
        >,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> std::result::Result<Vec<PartyID>, Self::Error>;

    /// In case that the happy flow ('semi-honest' like threshold decryption without zk-proofs) failed we need to identify which party has caused the failure.
    /// As no proofs were generated we need to use the decryption shares generated in the sad flow to interpolate the expected decryption share that should have been sent in the happy flow.
    /// This is done via interpolation in the exponent.
    /// First you compute the expected decryption share (without any adaptations for the expected group) as $\textsf{ds}_{\textsf{expected}}=\Pi_{\j\in S_{\textsf{identification}}}\tilde{\textsf{ds}}_{j}^{\lambada_{j^*,j}^{S_{\textsf{identification}}}}$.
    /// The actual decryption share that was sent by $j^*$ is denoted by $\bar{\textsf{ds}}_{j^*}$ and if $$\bar{\textsf{ds}}_{j^*}^{\Delta}\neq \textsf{ds}_{\textsf{expected}}^{\binom{n}{j^*}\Pi_{j\in [n]/\bar{S}}|j-j^*|}$ identify $j^*$ as malicious.
    fn identify_malicious_semi_honest_decrypters(
        invalid_semi_honest_decryption_shares: HashMap<PartyID, Vec<Self::DecryptionShare>>,
        valid_maliciously_secure_decryption_shares: HashMap<PartyID, Vec<Self::DecryptionShare>>,
        expected_decrypters: HashSet<PartyID>,
        public_parameters: &Self::PublicParameters,
    ) -> std::result::Result<Vec<PartyID>, Self::Error>;

    /// Finalizes the Threshold Decryption protocol by combining decryption shares. This is the
    /// Maliciously secure variant in which the corresponding zero-knowledge proofs are verified,
    /// and correct decryption is assured upon success.
    #[allow(clippy::type_complexity)]
    fn combine_decryption_shares(
        ciphertexts: Vec<EncryptionKey::CiphertextSpaceGroupElement>,
        decryption_shares_and_proofs: HashMap<
            PartyID,
            (Vec<Self::DecryptionShare>, Self::PartialDecryptionProof),
        >,
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> std::result::Result<
        (Vec<PartyID>, Vec<EncryptionKey::PlaintextSpaceGroupElement>),
        Self::Error,
    > {
        let malicious_decrypters = Self::identify_malicious_decrypters(
            ciphertexts.clone(),
            decryption_shares_and_proofs.clone(),
            public_parameters,
            rng,
        )?;

        let decryption_shares = decryption_shares_and_proofs
            .into_iter()
            .map(|(party_id, (decryption_shares, _))| (party_id, decryption_shares))
            .filter(|(party_id, _)| !malicious_decrypters.contains(party_id))
            .collect();

        let plaintexts = Self::combine_decryption_shares_semi_honest(
            ciphertexts,
            decryption_shares,
            // Note that taking the expected decryptors subset to be all parties returns to the regular Lagrange coefficients calculation.
            // The product $\Pi_{j\in\bar{S}/S}|j-i|$ goes to $\Pi_{j\in[n]/S}|j-i|$ and we grunted that $S\subset [n]$ in this case this product is the only difference in the formulas.
            HashSet::<PartyID>::from_iter(1..=Self::number_of_parties(public_parameters)),
            public_parameters,
        );

        plaintexts.map(|plaintexts| (malicious_decrypters, plaintexts))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<
    PlaintextSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CiphertextSpacePublicParameters,
> {
    pub plaintext_space_public_parameters: PlaintextSpacePublicParameters,
    pub randomness_space_public_parameters: RandomnessSpacePublicParameters,
    pub ciphertext_space_public_parameters: CiphertextSpacePublicParameters,
}

pub trait GroupsPublicParametersAccessors<
    'a,
    PlaintextSpacePublicParameters: 'a,
    RandomnessSpacePublicParameters: 'a,
    CiphertextSpacePublicParameters: 'a,
>:
    AsRef<
    GroupsPublicParameters<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    >,
>
{
    fn plaintext_space_public_parameters(&'a self) -> &'a PlaintextSpacePublicParameters {
        &self.as_ref().plaintext_space_public_parameters
    }

    fn randomness_space_public_parameters(&'a self) -> &'a RandomnessSpacePublicParameters {
        &self.as_ref().randomness_space_public_parameters
    }

    fn ciphertext_space_public_parameters(&'a self) -> &'a CiphertextSpacePublicParameters {
        &self.as_ref().ciphertext_space_public_parameters
    }
}

impl<
        'a,
        PlaintextSpacePublicParameters: 'a,
        RandomnessSpacePublicParameters: 'a,
        CiphertextSpacePublicParameters: 'a,
        T: AsRef<
            GroupsPublicParameters<
                PlaintextSpacePublicParameters,
                RandomnessSpacePublicParameters,
                CiphertextSpacePublicParameters,
            >,
        >,
    >
    GroupsPublicParametersAccessors<
        'a,
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    > for T
{
}

impl<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    > AsRef<Self>
    for GroupsPublicParameters<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    >
{
    fn as_ref(&self) -> &Self {
        self
    }
}

pub type PlaintextSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement;
pub type PlaintextSpacePublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
group::PublicParameters<<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement>;
pub type PlaintextSpaceValue<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
group::Value<<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PlaintextSpaceGroupElement>;

pub type RandomnessSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement;
pub type RandomnessSpacePublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
group::PublicParameters<<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement>;
pub type RandomnessSpaceValue<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
group::Value<<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::RandomnessSpaceGroupElement>;
pub type CiphertextSpaceGroupElement<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::CiphertextSpaceGroupElement;
pub type CiphertextSpacePublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
group::PublicParameters<<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::CiphertextSpaceGroupElement>;
pub type CiphertextSpaceValue<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
group::Value<<E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::CiphertextSpaceGroupElement>;
pub type PublicParameters<const PLAINTEXT_SPACE_SCALAR_LIMBS: usize, E> =
    <E as AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>>::PublicParameters;

#[derive(Serialize)]
pub struct CanonicalGroupsPublicParameters<
    PlaintextSpacePublicParameters: Transcribeable + Serialize,
    RandomnessSpacePublicParameters: Transcribeable + Serialize,
    CiphertextSpacePublicParameters: Transcribeable + Serialize,
> {
    pub canonical_plaintext_space_public_parameters:
        PlaintextSpacePublicParameters::CanonicalRepresentation,
    pub canonical_randomness_space_public_parameters:
        RandomnessSpacePublicParameters::CanonicalRepresentation,
    pub canonical_ciphertext_space_public_parameters:
        CiphertextSpacePublicParameters::CanonicalRepresentation,
}

impl<
        PlaintextSpacePublicParameters: Transcribeable + Serialize,
        RandomnessSpacePublicParameters: Transcribeable + Serialize,
        CiphertextSpacePublicParameters: Transcribeable + Serialize,
    >
    From<
        GroupsPublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
        >,
    >
    for CanonicalGroupsPublicParameters<
        PlaintextSpacePublicParameters,
        RandomnessSpacePublicParameters,
        CiphertextSpacePublicParameters,
    >
{
    fn from(
        value: GroupsPublicParameters<
            PlaintextSpacePublicParameters,
            RandomnessSpacePublicParameters,
            CiphertextSpacePublicParameters,
        >,
    ) -> Self {
        Self {
            canonical_plaintext_space_public_parameters: value
                .plaintext_space_public_parameters
                .into(),
            canonical_randomness_space_public_parameters: value
                .randomness_space_public_parameters
                .into(),
            canonical_ciphertext_space_public_parameters: value
                .ciphertext_space_public_parameters
                .into(),
        }
    }
}

#[allow(clippy::erasing_op)]
#[allow(clippy::identity_op)]
#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use std::hint::black_box;

    use criterion::Criterion;
    use crypto_bigint::{NonZero, Uint, U64};
    use rayon::iter::IntoParallelRefIterator;
    use rayon::iter::ParallelIterator;

    use group::helpers::DeduplicateAndSort;
    use group::{GroupElement, KnownOrderGroupElement, OsCsRng, Value};

    use super::*;

    pub fn encrypt_decrypts<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKey: AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        decryption_key: DecryptionKey,
        public_parameters: &EncryptionKey::PublicParameters,
        rng: &mut impl CsRng,
    ) {
        let encryption_key = decryption_key.as_ref();

        let plaintext: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(42u64)).into();
        let plaintext: EncryptionKey::PlaintextSpaceGroupElement =
            EncryptionKey::PlaintextSpaceGroupElement::new(
                plaintext.into(),
                public_parameters.plaintext_space_public_parameters(),
            )
            .unwrap();

        let (_, ciphertext) = encryption_key
            .encrypt(&plaintext, public_parameters, true, rng)
            .unwrap();

        assert_eq!(
            plaintext,
            decryption_key
                .decrypt(&ciphertext, public_parameters)
                .unwrap(),
            "decrypted ciphertext should match the plaintext"
        );

        let plaintext: EncryptionKey::PlaintextSpaceGroupElement =
            EncryptionKey::PlaintextSpaceGroupElement::sample(
                public_parameters.plaintext_space_public_parameters(),
                rng,
            )
            .unwrap();

        let (_, ciphertext) = encryption_key
            .encrypt(&plaintext, public_parameters, true, rng)
            .unwrap();

        assert_eq!(
            plaintext,
            decryption_key
                .decrypt(&ciphertext, public_parameters)
                .unwrap(),
            "decrypted ciphertext should match the random plaintext"
        );
    }

    pub fn evaluates<
        const EVALUATION_GROUP_SCALAR_LIMBS: usize,
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EvaluationGroupElement: KnownOrderScalar<EVALUATION_GROUP_SCALAR_LIMBS>
            + From<Value<EncryptionKey::PlaintextSpaceGroupElement>>,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKey: AdditivelyHomomorphicDecryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        decryption_key: DecryptionKey,
        evaluation_group_public_parameters: &EvaluationGroupElement::PublicParameters,
        public_parameters: &PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
        rng: &mut impl CsRng,
    ) {
        let encryption_key = decryption_key.as_ref();

        let zero: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(0u64)).into();
        let zero = EncryptionKey::PlaintextSpaceGroupElement::new(
            zero.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let one: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(1u64)).into();
        let one = EncryptionKey::PlaintextSpaceGroupElement::new(
            one.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();
        let two: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(2u64)).into();
        let two = EncryptionKey::PlaintextSpaceGroupElement::new(
            two.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();
        let five: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(5u64)).into();
        let five = EncryptionKey::PlaintextSpaceGroupElement::new(
            five.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();
        let seven: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(7u64)).into();
        let seven = EncryptionKey::PlaintextSpaceGroupElement::new(
            seven.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();
        let seventy_three: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&U64::from(73u64)).into();
        let seventy_three = EncryptionKey::PlaintextSpaceGroupElement::new(
            seventy_three.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let (_, encryption_of_two) = encryption_key
            .encrypt(&two, public_parameters, true, rng)
            .unwrap();

        let (_, encryption_of_five) = encryption_key
            .encrypt(&five, public_parameters, true, rng)
            .unwrap();

        let (_, encryption_of_seven) = encryption_key
            .encrypt(&seven, public_parameters, true, rng)
            .unwrap();

        let evaluated_ciphertext = encryption_of_five.scale(&U64::from(1u64))
            + encryption_of_seven.scale(&U64::from(0u64))
            + encryption_of_two.scale(&U64::from(73u64));

        let expected_evaluation_result: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> =
            (&U64::from(1u64 * 5 + 0 * 7 + 73 * 2)).into();
        let expected_evaluation_result = EncryptionKey::PlaintextSpaceGroupElement::new(
            expected_evaluation_result.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        assert_eq!(
            expected_evaluation_result,
            decryption_key
                .decrypt(&evaluated_ciphertext, public_parameters)
                .unwrap(),
            "homomorphic evaluation on small messages (no modulation in message space) with uniformly sampled randomness should match plaintext evaluation."
        );

        let secure_evaluation_randomness = EncryptionKey::RandomnessSpaceGroupElement::sample(
            public_parameters.randomness_space_public_parameters(),
            rng,
        )
        .unwrap();

        let evaluation_order = (&EvaluationGroupElement::order_from_public_parameters(
            evaluation_group_public_parameters,
        ))
            .into();

        let ciphertexts_and_encoded_messages_upper_bounds = [
            (encryption_of_five, evaluation_order),
            (encryption_of_seven, evaluation_order),
            (encryption_of_two, evaluation_order),
        ];

        let plaintext_order =
            EncryptionKey::PlaintextSpaceGroupElement::order_from_public_parameters(
                public_parameters.plaintext_space_public_parameters(),
            );

        let coefficients = [
            one.value().into(),
            zero.value().into(),
            seventy_three.value().into(),
        ];
        let mask = EncryptionKey::sample_mask_for_secure_function_evaluation(
            &coefficients,
            &ciphertexts_and_encoded_messages_upper_bounds,
            &evaluation_order,
            public_parameters,
            rng,
        )
        .unwrap();

        let privately_evaluated_ciphertext = encryption_key
            .securely_evaluate_linear_combination_with_randomness(
                &coefficients,
                Uint::<EVALUATION_GROUP_SCALAR_LIMBS>::BITS,
                ciphertexts_and_encoded_messages_upper_bounds,
                &evaluation_order,
                &mask,
                &secure_evaluation_randomness,
                public_parameters,
                true,
            )
            .unwrap();

        assert_ne!(
            evaluated_ciphertext, privately_evaluated_ciphertext,
            "privately evaluating the linear combination should result in a different ciphertext due to added randomness"
        );

        if plaintext_order != evaluation_order {
            assert_ne!(
                decryption_key.decrypt(&evaluated_ciphertext, public_parameters).unwrap(),
                decryption_key.decrypt(&privately_evaluated_ciphertext, public_parameters).unwrap(),
                "decryptions of privately evaluated linear combinations should be statistically indistinguishable from straightforward ones"
            );
        }

        assert_eq!(
            EvaluationGroupElement::from(decryption_key.decrypt(&evaluated_ciphertext, public_parameters).unwrap().value()),
            EvaluationGroupElement::from(decryption_key.decrypt(&privately_evaluated_ciphertext, public_parameters).unwrap().value()),
            "decryptions of privately evaluated linear combinations should match straightforward ones modulu the evaluation group order"
        );

        let (first_zero_encryption_randomness, first_encryption_of_zero) = encryption_key
            .encrypt(&zero, public_parameters, true, rng)
            .unwrap();
        let (second_zero_encryption_randomness, second_encryption_of_zero) = encryption_key
            .encrypt(&zero, public_parameters, true, rng)
            .unwrap();
        let encryption_of_zero_with_sum_randomness = encryption_key.encrypt_with_randomness(
            &zero,
            &(first_zero_encryption_randomness + second_zero_encryption_randomness),
            public_parameters,
            true,
        );

        assert_eq!(
            encryption_of_zero_with_sum_randomness,
            first_encryption_of_zero + second_encryption_of_zero,
            "encryptions of zero with randomnesses r1, r2 should sum up to be an encryption of zero with randomness r1 + r2"
        );

        let m1_value: Uint<EVALUATION_GROUP_SCALAR_LIMBS> =
            EvaluationGroupElement::sample(evaluation_group_public_parameters, rng)
                .unwrap()
                .value()
                .into();
        let m1 = EncryptionKey::PlaintextSpaceGroupElement::new(
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&m1_value).into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let m2_value: Uint<EVALUATION_GROUP_SCALAR_LIMBS> =
            EvaluationGroupElement::sample(evaluation_group_public_parameters, rng)
                .unwrap()
                .value()
                .into();
        let m2 = EncryptionKey::PlaintextSpaceGroupElement::new(
            Uint::<PLAINTEXT_SPACE_SCALAR_LIMBS>::from(&m2_value).into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let s: Uint<EVALUATION_GROUP_SCALAR_LIMBS> =
            EvaluationGroupElement::sample(evaluation_group_public_parameters, rng)
                .unwrap()
                .value()
                .into();

        let (m1_encryption_randomness, encryption_of_m1) = encryption_key
            .encrypt(&m1, public_parameters, true, rng)
            .unwrap();

        let (_, encryption_of_m2) = encryption_key
            .encrypt(&m2, public_parameters, true, rng)
            .unwrap();

        let evaluated_ciphertext = encryption_of_m1 + encryption_of_m2;

        let m1_scalar =
            EvaluationGroupElement::new(m1_value.into(), evaluation_group_public_parameters)
                .unwrap();
        let m2_scalar =
            EvaluationGroupElement::new(m2_value.into(), evaluation_group_public_parameters)
                .unwrap();

        let expected_evaluation_result: EvaluationGroupElement = m1_scalar + m2_scalar;

        let decrypted = decryption_key
            .decrypt(&evaluated_ciphertext, public_parameters)
            .unwrap();

        let decrypted_evaluation = <Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> as group::Reduce<
            EVALUATION_GROUP_SCALAR_LIMBS,
        >>::reduce(
            &decrypted.into(),
            &NonZero::new(EvaluationGroupElement::order_from_public_parameters(
                evaluation_group_public_parameters,
            ))
            .unwrap(),
        );

        assert_eq!(
            expected_evaluation_result.value().into(),
            decrypted_evaluation,
            "randomly sampled ciphertexts should be added properly"
        );

        let evaluted_ciphertext = encryption_of_m1.scale(&s) + encryption_of_m2;

        let s_scalar =
            EvaluationGroupElement::new(s.into(), evaluation_group_public_parameters).unwrap();

        let expected_evaluation_result: EvaluationGroupElement = (s_scalar * m1_scalar) + m2_scalar;

        let decrypted = decryption_key
            .decrypt(&evaluted_ciphertext, public_parameters)
            .unwrap();

        let decrypted_evaluation = <Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> as group::Reduce<
            EVALUATION_GROUP_SCALAR_LIMBS,
        >>::reduce(
            &decrypted.into(),
            &NonZero::new(EvaluationGroupElement::order_from_public_parameters(
                evaluation_group_public_parameters,
            ))
            .unwrap(),
        );

        assert_eq!(
            expected_evaluation_result.value().into(),
            decrypted_evaluation,
            "randomly sampled ciphertexts should be evaluated properly"
        );

        let ciphertexts_and_encoded_messages_upper_bounds = [(encryption_of_m1, evaluation_order)];

        let s_value: Uint<EVALUATION_GROUP_SCALAR_LIMBS> = s_scalar.value().into();
        let s: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&s_value).into();
        let evaluated_ciphertext = encryption_of_m1.scale(&s);
        let s = EncryptionKey::PlaintextSpaceGroupElement::new(
            s.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let privately_evaluted_ciphertext = encryption_key
            .securely_evaluate_linear_combination_with_randomness(
                &[s.value().into()],
                Uint::<EVALUATION_GROUP_SCALAR_LIMBS>::BITS,
                ciphertexts_and_encoded_messages_upper_bounds,
                &evaluation_order,
                &mask,
                &secure_evaluation_randomness,
                public_parameters,
                true,
            )
            .unwrap();

        assert_eq!(
            EvaluationGroupElement::from(decryption_key.decrypt(&evaluated_ciphertext, public_parameters).unwrap().value()),
            EvaluationGroupElement::from(decryption_key.decrypt(&privately_evaluted_ciphertext, public_parameters).unwrap().value()),
            "decryptions of privately evaluated linear combinations should match straightforward ones modulu the evaluation group order"
        );

        let mask = mask.neutral();
        let privately_evaluted_ciphertext = encryption_key
            .securely_evaluate_linear_combination_with_randomness(
                &[s.value().into()],
                Uint::<EVALUATION_GROUP_SCALAR_LIMBS>::BITS,
                ciphertexts_and_encoded_messages_upper_bounds,
                &evaluation_order,
                &mask,
                &secure_evaluation_randomness,
                public_parameters,
                true,
            )
            .unwrap();

        let s_pt: Uint<EVALUATION_GROUP_SCALAR_LIMBS> = s_scalar.value().into();
        let s_pt: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&s_pt).into();
        let s_pt = EncryptionKey::PlaintextSpaceGroupElement::new(
            s_pt.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let m1_pt: Uint<EVALUATION_GROUP_SCALAR_LIMBS> = m1_scalar.value().into();
        let m1_pt: Uint<PLAINTEXT_SPACE_SCALAR_LIMBS> = (&m1_pt).into();
        let m1_pt = EncryptionKey::PlaintextSpaceGroupElement::new(
            m1_pt.into(),
            public_parameters.plaintext_space_public_parameters(),
        )
        .unwrap();

        let pt = s_pt * m1_pt;

        let expected_evaluation_result = encryption_key.encrypt_with_randomness(
            &pt,
            &((m1_encryption_randomness.scale(&s_value)) + secure_evaluation_randomness),
            public_parameters,
            true,
        );
        assert_eq!(
            privately_evaluted_ciphertext, expected_evaluation_result,
            "privately evaluated linear combinations evaluated wrongly"
        );
    }

    pub fn threshold_decrypts<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        threshold: PartyID,
        batch_size: usize,
        decryption_key_shares: HashMap<PartyID, DecryptionKeyShare>,
        public_parameters: &DecryptionKeyShare::PublicParameters,
        rng: &mut impl CsRng,
    ) {
        let number_of_parties = DecryptionKeyShare::number_of_parties(public_parameters);
        let encryption_key = decryption_key_shares
            .values()
            .next()
            .unwrap()
            .as_ref()
            .clone();
        let encryption_scheme_public_parameters = public_parameters.as_ref();

        let plaintexts = EncryptionKey::PlaintextSpaceGroupElement::sample_batch(
            encryption_scheme_public_parameters.plaintext_space_public_parameters(),
            batch_size,
            rng,
        )
        .unwrap();

        let ciphertexts: Vec<_> = plaintexts
            .iter()
            .map(|plaintext| {
                let (_, ciphertext) = encryption_key
                    .encrypt(plaintext, encryption_scheme_public_parameters, true, rng)
                    .unwrap();

                ciphertext
            })
            .collect();

        let mut expected_decrypters = HashSet::from_iter(1..=threshold);
        if number_of_parties > threshold {
            expected_decrypters.insert(threshold + 1);
        }

        let decryption_shares: HashMap<PartyID, _> = decryption_key_shares
            .iter()
            .map(|(j, decryption_key_share)| {
                let decryption_shares: Vec<_> = ciphertexts
                    .clone()
                    .into_iter()
                    .map(|ciphertext| {
                        let decryption_share = decryption_key_share
                            .generate_decryption_share_semi_honest(
                                &ciphertext,
                                expected_decrypters.clone(),
                                public_parameters,
                            );

                        assert_eq!(
                            decryption_share.is_some().unwrap_u8(),
                            1,
                            "semi honest partial decryption should succeed"
                        );

                        decryption_share.unwrap()
                    })
                    .collect();

                (*j, decryption_shares)
            })
            .collect();

        let res = if number_of_parties > threshold {
            // Try the case when just one of the expected parties weren't available, which is the expected case since we passed an expected group of size `t + 1`.
            DecryptionKeyShare::combine_decryption_shares_semi_honest(
                ciphertexts.clone(),
                decryption_shares
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| *party_id != 2)
                    .collect(),
                expected_decrypters.clone(),
                public_parameters,
            )
        } else {
            DecryptionKeyShare::combine_decryption_shares_semi_honest(
                ciphertexts.clone(),
                decryption_shares.clone(),
                expected_decrypters.clone(),
                public_parameters,
            )
        };

        assert!(
            res.is_ok(),
            "semi-honest threshold decryption should succeed in the expected case; got error: {:?}",
            res.err().unwrap()
        );

        assert_eq!(
            plaintexts,
            res.unwrap(),
            "semi-honest threshold decryption should match the plaintext in the expected case"
        );

        if number_of_parties > threshold {
            let expected_decrypters = HashSet::from_iter(1..=threshold);

            let decryption_shares: HashMap<PartyID, _> = decryption_key_shares
                .iter()
                .map(|(j, decryption_key_share)| {
                    let decryption_shares: Vec<_> = ciphertexts
                        .clone()
                        .into_iter()
                        .map(|ciphertext| {
                            let decryption_share = decryption_key_share
                                .generate_decryption_share_semi_honest(
                                    &ciphertext,
                                    expected_decrypters.clone(),
                                    public_parameters,
                                );

                            assert_eq!(
                                decryption_share.is_some().unwrap_u8(),
                                1,
                                "semi honest partial decryption should succeed"
                            );

                            decryption_share.unwrap()
                        })
                        .collect();

                    (*j, decryption_shares)
                })
                .collect();

            // Now try the case when one of the expected parties weren't available, which is the unexpected case since we passed an expected group of size `t`.
            let res = DecryptionKeyShare::combine_decryption_shares_semi_honest(
                ciphertexts.clone(),
                decryption_shares
                    .clone()
                    .into_iter()
                    .filter(|(party_id, _)| *party_id != 2)
                    .collect(),
                expected_decrypters.clone(),
                public_parameters,
            );

            assert!(
                res.is_ok(),
                "semi-honest threshold decryption should succeed in the unexpected case; got error: {:?}",
                res.err().unwrap()
            );

            assert_eq!(
                plaintexts,
                res.unwrap(),
                "semi-honest threshold decryption should match the plaintext in the unexpected case"
            );
        }

        let decryption_shares_and_proofs: HashMap<PartyID, (_, _)> = decryption_key_shares
            .iter()
            .map(|(j, decryption_key_share)| {
                let decryption_shares = decryption_key_share.generate_decryption_shares(
                    ciphertexts.clone(),
                    public_parameters,
                    rng,
                );

                assert_eq!(
                    decryption_shares.is_some().unwrap_u8(),
                    1,
                    "partial decryption should succeed"
                );

                (*j, decryption_shares.unwrap())
            })
            .collect();

        let res = DecryptionKeyShare::combine_decryption_shares(
            ciphertexts,
            decryption_shares_and_proofs,
            public_parameters,
            rng,
        );

        assert!(
            res.is_ok(),
            "threshold decryption should succeed; got error: {:?}",
            res.err().unwrap()
        );

        let (malicious_decrypters, decrypted) = res.unwrap();

        assert_eq!(
            plaintexts, decrypted,
            "threshold decrypted ciphertext should match the plaintext"
        );

        assert!(
            malicious_decrypters.is_empty(),
            "honest threshold decrypted should have no malicious decrypters"
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn benchmark_decryption_key_share<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        threshold: PartyID,
        number_of_parties: PartyID,
        batch_size: usize,
        decryption_key_shares: HashMap<PartyID, DecryptionKeyShare>,
        public_parameters: &DecryptionKeyShare::PublicParameters,
        encryption_scheme_name: &str,
        c: &mut Criterion,
        rng: &mut impl CsRng,
    ) {
        let encryption_key = decryption_key_shares
            .values()
            .next()
            .unwrap()
            .as_ref()
            .clone();
        let encryption_scheme_public_parameters = public_parameters.as_ref();

        let plaintexts = EncryptionKey::PlaintextSpaceGroupElement::sample_batch(
            encryption_scheme_public_parameters.plaintext_space_public_parameters(),
            batch_size,
            rng,
        )
        .unwrap();

        let ciphertexts: Vec<_> = plaintexts
            .iter()
            .map(|plaintext| {
                let (_, ciphertext) = encryption_key
                    .encrypt(plaintext, encryption_scheme_public_parameters, true, rng)
                    .unwrap();

                ciphertext
            })
            .collect();

        let mut g = c.benchmark_group(format!(
            "{encryption_scheme_name}/generate_decryption_shares()"
        ));
        g.sample_size(10);
        let j = 1;
        let decryption_key_share = decryption_key_shares.get(&j).unwrap();
        g.bench_function(format!("{threshold}-out-of-{number_of_parties}"), |bench| {
            bench.iter(|| {
                black_box(decryption_key_share.generate_decryption_shares(
                    ciphertexts.clone(),
                    public_parameters,
                    rng,
                ))
            });
        });
        g.finish();

        let decryption_shares_and_proofs: HashMap<PartyID, _> = decryption_key_shares
            .par_iter()
            .filter(|(j, _)| **j <= threshold)
            .map(|(j, decryption_key_share)| {
                let decryption_shares = decryption_key_share.generate_decryption_shares(
                    ciphertexts.clone(),
                    public_parameters,
                    &mut OsCsRng,
                );

                assert_eq!(
                    decryption_shares.is_some().unwrap_u8(),
                    1,
                    "partial decryption should succeed"
                );

                (*j, decryption_shares.unwrap())
            })
            .collect();

        println!("num {:?}", decryption_shares_and_proofs.len()); // todo

        let mut g = c.benchmark_group(format!(
            "{encryption_scheme_name}/combine_decryption_shares()"
        ));
        g.sample_size(10);

        g.bench_function(format!("{threshold}-out-of-{number_of_parties}"), |bench| {
            bench.iter(|| {
                let res = DecryptionKeyShare::combine_decryption_shares(
                    ciphertexts.clone(),
                    decryption_shares_and_proofs.clone(),
                    public_parameters,
                    rng,
                );

                assert!(
                    res.is_ok(),
                    "threshold decryption should succeed; got error: {:?}",
                    res.err().unwrap()
                );

                let (malicious_decrypters, decrypted) = res.unwrap();

                assert_eq!(
                    plaintexts, decrypted,
                    "threshold decrypted ciphertext should match the plaintext"
                );

                assert!(
                    malicious_decrypters.is_empty(),
                    "honest threshold decrypted should have no malicious decrypters"
                );
            });
        });
        g.finish();
    }

    #[allow(clippy::too_many_arguments)]
    pub fn benchmark_decryption_key_share_semi_honest<
        const PLAINTEXT_SPACE_SCALAR_LIMBS: usize,
        EncryptionKey: AdditivelyHomomorphicEncryptionKey<PLAINTEXT_SPACE_SCALAR_LIMBS>,
        DecryptionKeyShare: AdditivelyHomomorphicDecryptionKeyShare<PLAINTEXT_SPACE_SCALAR_LIMBS, EncryptionKey>,
    >(
        threshold: PartyID,
        number_of_parties: PartyID,
        delta: PartyID,
        batch_size: usize,
        decryption_key_shares: HashMap<PartyID, DecryptionKeyShare>,
        public_parameters: &DecryptionKeyShare::PublicParameters,
        expected_case: bool,
        encryption_scheme_name: &str,
        c: &mut Criterion,
        rng: &mut impl CsRng,
    ) {
        let encryption_key = decryption_key_shares
            .values()
            .next()
            .unwrap()
            .as_ref()
            .clone();
        let encryption_scheme_public_parameters = public_parameters.as_ref();

        let plaintexts = EncryptionKey::PlaintextSpaceGroupElement::sample_batch(
            encryption_scheme_public_parameters.plaintext_space_public_parameters(),
            batch_size,
            rng,
        )
        .unwrap();

        let ciphertexts: Vec<_> = plaintexts
            .iter()
            .map(|plaintext| {
                let (_, ciphertext) = encryption_key
                    .encrypt(plaintext, encryption_scheme_public_parameters, true, rng)
                    .unwrap();

                ciphertext
            })
            .collect();

        assert!(threshold + delta <= number_of_parties);
        let decrypters: HashSet<PartyID> = if expected_case {
            HashSet::from_iter(1..=threshold)
        } else {
            assert!((number_of_parties - (delta + 1)) >= threshold);
            assert!(delta < number_of_parties - threshold);
            HashSet::from_iter((number_of_parties - threshold - 1)..=number_of_parties)
        };
        let decrypters = decrypters.deduplicate_and_sort();
        let expected_decrypters = HashSet::from_iter(1..=(threshold + delta));

        if expected_case {
            let mut g = c.benchmark_group(format!(
                "{encryption_scheme_name}/generate_decryption_share_semi_honest()"
            ));
            g.sample_size(10);
            let j = 1;
            let decryption_key_share = decryption_key_shares.get(&j).unwrap();
            let ciphertext = ciphertexts.first().unwrap();

            g.bench_function(
                format!("{threshold}-out-of-{number_of_parties}/+{delta}"),
                |bench| {
                    bench.iter(|| {
                        black_box(decryption_key_share.generate_decryption_share_semi_honest(
                            ciphertext,
                            expected_decrypters.clone(),
                            public_parameters,
                        ))
                    });
                },
            );
            g.finish();
        }

        let decryption_shares: HashMap<PartyID, _> = decryption_key_shares
            .par_iter()
            .filter(|(j, _)| decrypters.contains(j))
            .map(|(j, decryption_key_share)| {
                let decryption_shares: Vec<_> = ciphertexts
                    .clone()
                    .into_iter()
                    .map(|ciphertext| {
                        let decryption_share = decryption_key_share
                            .generate_decryption_share_semi_honest(
                                &ciphertext,
                                expected_decrypters.clone(),
                                public_parameters,
                            );

                        assert_eq!(
                            decryption_share.is_some().unwrap_u8(),
                            1,
                            "semi honest partial decryption should succeed"
                        );

                        decryption_share.unwrap()
                    })
                    .collect();

                (*j, decryption_shares)
            })
            .collect();

        let mut g = c.benchmark_group(format!(
            "{encryption_scheme_name}/combine_decryption_shares_semi_honest()"
        ));
        g.sample_size(10);

        g.bench_function(
            format!(
                "{threshold}-out-of-{number_of_parties}/+{delta} {}",
                if expected_case {
                    "expected"
                } else {
                    "unexpected"
                }
            ),
            |bench| {
                bench.iter(|| {
                    let res = DecryptionKeyShare::combine_decryption_shares_semi_honest(
                        ciphertexts.clone(),
                        decryption_shares.clone(),
                        expected_decrypters.clone(),
                        public_parameters,
                    );

                    assert!(
                        res.is_ok(),
                        "semi-honest threshold decryption should succeed; got error: {:?}",
                        res.err().unwrap()
                    );

                    assert_eq!(
                        plaintexts,
                        res.unwrap(),
                        "semi-honest threshold decryption should match the plaintext"
                    );
                });
            },
        );
        g.finish();
    }
}
