// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use core::{fmt::Debug, iter, ops::Mul};

use crypto_bigint::{Int, Uint, U128, U64};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

pub use reduce::Reduce;

pub mod helpers;

pub mod additive;
pub mod bounded_integers_group;
pub mod bounded_natural_numbers_group;
pub mod const_additive;
mod csrng;
pub mod curve25519;
pub mod direct_product;
mod hash_to_scalar;
pub mod linear_combination;
mod reduce;
pub mod ristretto;
pub mod scalar;
pub mod secp256k1;
pub mod secp256r1;
mod seedable_collection;
pub mod self_product;
mod transcription;

pub use hash_to_scalar::{hash, hash_to_scalar, HashContext, HashScheme};
pub use transcription::Transcribeable;
#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub mod test_helpers {
    pub use crate::transcription::test_helpers::*;
}

use crate::linear_combination::linearly_combine_bounded;
#[cfg(any(test, feature = "os_rng"))]
pub use csrng::OsCsRng;
pub use csrng::{CsRng, SeedableRng};
pub use linear_combination::linearly_combine_bounded_or_scale;
pub use seedable_collection::SeedableCollection;

/// Represents an unsigned integer sized based on the computation security parameter, denoted as
/// $\kappa$.
pub type ComputationalSecuritySizedNumber = U128;

/// Represents an unsigned integer sized based on the statistical security parameter, denoted as
/// $s$. Configured for 64-bit statistical security using U64.
pub type StatisticalSecuritySizedNumber = U64;

/// A unique identifier of a party in an MPC protocol.
pub type PartyID = u16;

/// Group error wrapper that carries a backtrace captured at construction.
///
/// The backtrace is captured by `Backtrace::capture()`, gated by `RUST_BACKTRACE`
/// (or `RUST_LIB_BACKTRACE`) — set to `1` (or `full`) to see the line where
/// each error was minted (or, for cross-crate `?` chains, the conversion site).
#[derive(thiserror::Error, Clone, Debug)]
#[error("{kind}\n{backtrace}")]
pub struct Error {
    pub kind: ErrorKind,
    pub backtrace: std::sync::Arc<std::backtrace::Backtrace>,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl<E> From<E> for Error
where
    ErrorKind: From<E>,
{
    fn from(value: E) -> Self {
        Self {
            kind: ErrorKind::from(value),
            backtrace: std::sync::Arc::new(std::backtrace::Backtrace::capture()),
        }
    }
}

/// Group error kind.
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum ErrorKind {
    #[error("unsupported public parameters: the implementation doesn't support the public parameters, whether it identifies a valid group."
    )]
    UnsupportedPublicParameters,

    #[error(
        "invalid public parameters: no valid group can be identified by the public parameters."
    )]
    InvalidPublicParameters,

    #[error("invalid group element: the value does not belong to the group identified by the public parameters."
    )]
    InvalidGroupElement,

    #[error("unsupported hash type")]
    UnsupportedHashType,

    #[error("hash to group: failed to encode bytes to a group element.")]
    HashToGroup,

    #[error("transcription error")]
    Transcription,

    #[error("invalid parameters")]
    InvalidParameters,

    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

/// The Result of `new()` operation for types implementing the [`GroupElement`] trait
pub type Result<T> = std::result::Result<T, Error>;

/// An element of an abelian group, in additive notation.
///
/// Group operations are only valid between elements
/// within the group (otherwise the result is undefined).
///
/// All group operations are guaranteed to be constant time
pub trait GroupElement:
    Into<Self::Value> + Debug + PartialEq + Eq + Clone + ConstantTimeEq + Send + Sync
{
    /// The actual value of the group point used for encoding/decoding.
    ///
    /// For some groups (e.g. `group::secp256k1::Secp256k1GroupElement`) the group parameters and
    /// equations are statically hard-coded into the code,
    /// and then they would have `Self::Value = Self`.
    ///
    /// However, other groups (e.g. `group::paillier::PaillierCiphertextGroupElement`) rely on
    /// dynamic values to determine group operations in runtime (like the Paillier modulus
    /// $N^2$).
    ///
    /// In those cases, it is both inefficient communication-wise to serialize these statements
    /// as they are known by the deserializing side, and even worse, it is a security risk as
    /// malicious actors could try and craft groups in which they can break security assumptions
    /// in order to e.g. bypass zk-proof verification and have the verifier use those groups.
    ///
    /// To mitigate these risks and save on communication, we separate the value of the
    /// point from the group parameters.
    type Value: Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + ConstantTimeEq
        + Default
        + Send
        + Sync;

    /// Returns the value of this group element.
    fn value(&self) -> Self::Value {
        self.clone().into()
    }

    /// Perform a batched conversion of group elements to their values.
    fn batch_normalize(group_elements: Vec<Self>) -> Vec<Self::Value> {
        // default to a trivial implementation.
        group_elements
            .iter()
            .map(|group_element| group_element.value())
            .collect()
    }

    /// Perform a batched conversion of group elements to their values.
    fn batch_normalize_const_generic<const N: usize>(
        group_elements: [Self; N],
    ) -> [Self::Value; N] {
        // default to a trivial implementation.
        group_elements.map(|group_element| group_element.value())
    }

    /// The public parameters of the group, used for group operations.
    ///
    /// These include both dynamic information for runtime calculations
    /// (that provides the required context for [`Self::new()`] alongside the [`Self::Value`] to
    /// instantiate a [`GroupElement`]), and static information hardcoded into the code
    /// (that, together with the dynamic information, uniquely identifies a group and will be used
    /// for Fiat-Shamir Transcripts).
    type PublicParameters: Transcribeable
        + Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + PartialEq
        + Eq
        + Debug
        + Send
        + Sync;

    /// Instantiate the group element from its value and the caller supplied parameters.
    ///
    /// *** NOTICE ***: `Self::new()` must check that the
    /// `value` belongs to the group identified by `params` and return an error otherwise!
    ///
    /// Even for static groups where `Self::Value = Self`, it must be assured the value is an
    /// element of the group either here or in deserialization.
    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// Instantiate the group element from its value and the caller supplied parameters.
    ///
    /// *** SECURITY NOTICE ***: `Self::new_unchecked()` might not check that the
    /// `value` belongs to the group identified by `params` if it is computation costly,
    /// and as such is generally UNSAFE unless proven secure in a very specific protocol and context.
    fn new_unchecked(
        value: Self::Value,
        public_parameters: &Self::PublicParameters,
    ) -> Result<Self> {
        Self::new(value, public_parameters)
    }

    /// Returns the additive identity, also known as the "neutral element".
    fn neutral(&self) -> Self;

    /// Returns the additive identity, also known as the "neutral element".
    fn neutral_from_public_parameters(public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// Determines if this point is the identity in constant-time.
    fn is_neutral(&self) -> Choice {
        self.value().ct_eq(&self.neutral().value())
    }

    /// Constant-time addition.
    fn add_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self;

    /// Constant-time subtraction.
    fn sub_constant_time(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self;

    /// Constant-time negation.
    fn neg_constant_time(&self, public_parameters: &Self::PublicParameters) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar)
    fn scale<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar)
    fn scale_integer<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Variable-time Multiplication by (any bounded) natural number (scalar)
    fn scale_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Variable-time Multiplication by (any bounded) integer (scalar)
    fn scale_integer_vartime<const LIMBS: usize>(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scale_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scale_integer_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Variable-time Multiplication by (any bounded) natural number (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_bounded_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Variable-time Multiplication by (any bounded) integer (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_integer_bounded_vartime<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let positive = self.scale_bounded_vartime(&integer.abs(), scalar_bits, public_parameters);

        if bool::from(integer.is_negative()) {
            positive.neg_constant_time(public_parameters)
        } else {
            positive
        }
    }

    /// Multiplication by (any bounded) natural number (scalar),
    /// variable-time in the scalar value, constant-time in the base.
    /// Computes `bits_vartime()` to determine the number of bits to process,
    /// but uses constant-time scalar multiplication.
    fn scale_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Multiplication by (any bounded) integer (scalar),
    /// variable-time in the scalar value, constant-time in the base.
    /// Computes `abs().bits_vartime()` to determine the number of bits to process,
    /// but uses constant-time scalar multiplication (and variable-time sign handling).
    fn scale_integer_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let abs = integer.abs();
        let positive = self.scale_vartime_scalar(&abs, public_parameters);

        if bool::from(integer.is_negative()) {
            positive.neg_constant_time(public_parameters)
        } else {
            positive
        }
    }

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// where the base is public (known to all parties).
    /// Implementations may use acceleration (e.g. precomputed tables) when available.
    fn scale_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// where the base is public (known to all parties),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    /// Implementations may use acceleration (e.g. precomputed tables) when available.
    fn scale_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// where the base is public (known to all parties).
    /// Implementations may use acceleration (e.g. precomputed tables) when available.
    fn scale_integer_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// where the base is public (known to all parties),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    /// Implementations may use acceleration (e.g. precomputed tables) when available.
    fn scale_integer_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// using randomized arithmetic (e.g. randomized representation in class groups).
    /// Defaults to `scale()` for groups without randomized arithmetic.
    fn scale_randomized<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// using randomized arithmetic,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_randomized_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// using randomized arithmetic, where the base is public (known to all parties).
    /// Implementations may use acceleration (e.g. precomputed tables) when available.
    fn scale_randomized_public_base<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// using randomized arithmetic, where the base is public (known to all parties),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// using randomized arithmetic.
    /// Defaults to `scale_integer()` for groups without randomized arithmetic.
    fn scale_integer_randomized<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// using randomized arithmetic,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_integer_randomized_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// using randomized arithmetic, where the base is public (known to all parties).
    /// Implementations may use acceleration (e.g. precomputed tables) when available.
    fn scale_integer_randomized_public_base<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// using randomized arithmetic, where the base is public (known to all parties),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_integer_randomized_public_base_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Multiplication by (any bounded) natural number (scalar),
    /// using randomized arithmetic,
    /// variable-time in the scalar value, constant-time in the base.
    fn scale_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Multiplication by (any bounded) integer (scalar),
    /// using randomized arithmetic,
    /// variable-time in the scalar value, constant-time in the base.
    fn scale_integer_randomized_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        let abs = integer.abs();
        let positive = self.scale_randomized_vartime_scalar(&abs, public_parameters);

        if bool::from(integer.is_negative()) {
            positive.neg_constant_time(public_parameters)
        } else {
            positive
        }
    }

    /// Add two randomized group elements in constant-time.
    fn add_randomized(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self;

    /// Variable-time Addition.
    fn add_vartime(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self;

    /// Sub two randomized group elements in constant-time.
    fn sub_randomized(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self;

    /// Variable-time Subtraction.
    fn sub_vartime(&self, other: &Self, public_parameters: &Self::PublicParameters) -> Self;

    /// Double this point in constant-time.
    #[must_use]
    fn double(&self, public_parameters: &Self::PublicParameters) -> Self;

    /// Double this point in variable-time.
    #[must_use]
    fn double_vartime(&self, public_parameters: &Self::PublicParameters) -> Self;

    /// Performs constant-time "modular multi-exponentiation" (i.e. linear combination).
    fn linearly_combine<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        Self::linearly_combine_bounded(
            bases_and_multiplicands,
            Uint::<RHS_LIMBS>::BITS,
            public_parameters,
        )
    }

    /// Performs constant-time "modular multi-exponentiation" (i.e. linear combination).
    /// `exponent_bits` represents the number of bits to take into account for the exponent.
    fn linearly_combine_bounded<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self>;

    /// Performs variable-time "modular multi-exponentiation" (i.e. linear combination).
    fn linearly_combine_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self> {
        let multiplicand_bits_upper_bound = bases_and_multiplicands
            .iter()
            .map(|(_, multiplicand)| multiplicand.bits_vartime())
            .max()
            .unwrap_or(Uint::<RHS_LIMBS>::BITS);

        Self::linearly_combine_bounded_vartime(
            bases_and_multiplicands,
            multiplicand_bits_upper_bound,
            public_parameters,
        )
    }

    /// Performs variable-time "modular multi-exponentiation" (i.e. linear combination).
    /// `exponent_bits` represents the number of bits to take into account for the exponent.
    fn linearly_combine_bounded_vartime<const RHS_LIMBS: usize>(
        bases_and_multiplicands: Vec<(Self, Uint<RHS_LIMBS>)>,
        exponent_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> crate::Result<Self>;
}

/// A bench implementation for groups whose underlying implementation does not expose a
/// bounded multiplication function, using linear combination of just one value, it operates in double-and-add fashion.
pub fn scale_bounded<const LIMBS: usize, T: GroupElement + Copy + ConditionallySelectable>(
    group_element: &T,
    scalar: &Uint<LIMBS>,
    scalar_bits: u32,
    constant_time: bool,
    public_parameters: &T::PublicParameters,
) -> T {
    // Safe to unwrap, can only fail on sanity checks that aren't relevant here
    linearly_combine_bounded(
        vec![(*group_element, *scalar)],
        scalar_bits,
        constant_time,
        public_parameters,
    )
    .unwrap()
}

/// Constant-time multiplication by a bounded integer, using `ConditionallySelectable` for the sign.
///
/// This is the shared implementation for `GroupElement::scale_integer_bounded` for types that are
/// `Copy + ConditionallySelectable`. Concrete `GroupElement` implementations should call this
/// from their `scale_integer_bounded` method.
pub fn scale_integer_bounded<
    const LIMBS: usize,
    T: GroupElement + Copy + ConditionallySelectable,
>(
    group_element: &T,
    integer: &Int<LIMBS>,
    scalar_bits: u32,
    public_parameters: &T::PublicParameters,
) -> T {
    let positive = group_element.scale_bounded(&integer.abs(), scalar_bits, public_parameters);
    let negated = positive.neg_constant_time(public_parameters);

    <T as ConditionallySelectable>::conditional_select(
        &positive,
        &negated,
        integer.is_negative().into(),
    )
}

/// Constant-time multiplication by a bounded integer where the base is public.
/// Uses `ConditionallySelectable` for constant-time sign handling.
pub fn scale_integer_public_base_bounded<
    const LIMBS: usize,
    T: GroupElement + Copy + ConditionallySelectable,
>(
    group_element: &T,
    integer: &Int<LIMBS>,
    scalar_bits: u32,
    public_parameters: &T::PublicParameters,
) -> T {
    let positive =
        group_element.scale_public_base_bounded(&integer.abs(), scalar_bits, public_parameters);
    let negated = positive.neg_constant_time(public_parameters);

    <T as ConditionallySelectable>::conditional_select(
        &positive,
        &negated,
        integer.is_negative().into(),
    )
}

/// Constant-time multiplication by a bounded integer using randomized arithmetic.
/// Uses `ConditionallySelectable` for constant-time sign handling.
pub fn scale_integer_randomized_bounded<
    const LIMBS: usize,
    T: GroupElement + Copy + ConditionallySelectable,
>(
    group_element: &T,
    integer: &Int<LIMBS>,
    scalar_bits: u32,
    public_parameters: &T::PublicParameters,
) -> T {
    let positive =
        group_element.scale_randomized_bounded(&integer.abs(), scalar_bits, public_parameters);
    let negated = positive.neg_constant_time(public_parameters);

    <T as ConditionallySelectable>::conditional_select(
        &positive,
        &negated,
        integer.is_negative().into(),
    )
}

/// Constant-time multiplication by a bounded integer using randomized arithmetic,
/// where the base is public. Uses `ConditionallySelectable` for constant-time sign handling.
pub fn scale_integer_randomized_public_base_bounded<
    const LIMBS: usize,
    T: GroupElement + Copy + ConditionallySelectable,
>(
    group_element: &T,
    integer: &Int<LIMBS>,
    scalar_bits: u32,
    public_parameters: &T::PublicParameters,
) -> T {
    let positive = group_element.scale_randomized_public_base_bounded(
        &integer.abs(),
        scalar_bits,
        public_parameters,
    );
    let negated = positive.neg_constant_time(public_parameters);

    <T as ConditionallySelectable>::conditional_select(
        &positive,
        &negated,
        integer.is_negative().into(),
    )
}

pub type Value<G> = <G as GroupElement>::Value;

pub type PublicParameters<G> = <G as GroupElement>::PublicParameters;

/// Scale a base by a scalar of type `T`.
/// This trait provides a generic interface for scaling by different scalar types
/// (e.g. native Scalar, Value<Scalar>, Uint, Int), delegating to the appropriate
/// GroupElement methods. Method names use `scale_by` prefix to avoid collision
/// with GroupElement methods.
pub trait Scale<T>: GroupElement {
    /// Constant-time Multiplication of a base by a Scalar.
    fn scale_by(&self, scalar: &T, public_parameters: &Self::PublicParameters) -> Self;

    /// Variable-time Multiplication by a Scalar.
    fn scale_vartime_by(&self, scalar: &T, public_parameters: &Self::PublicParameters) -> Self;

    /// Constant-time Multiplication by a scalar,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scale_bounded_by(
        &self,
        scalar: &T,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Variable-time Multiplication by a scalar,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_bounded_vartime_by(
        &self,
        scalar: &T,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Multiplication by a scalar, variable-time in the scalar value,
    /// constant-time in the base.
    fn scale_vartime_scalar_by(
        &self,
        scalar: &T,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by a scalar where the base is public
    /// (known to all parties). May use acceleration when available.
    fn scale_public_base_by(&self, scalar: &T, public_parameters: &Self::PublicParameters) -> Self;

    /// Constant-time Multiplication by a scalar where the base is public,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar. May use acceleration when available.
    fn scale_public_base_bounded_by(
        &self,
        scalar: &T,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by a scalar using randomized arithmetic.
    fn scale_randomized_by(&self, scalar: &T, public_parameters: &Self::PublicParameters) -> Self;

    /// Constant-time Multiplication by a scalar using randomized arithmetic,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_randomized_bounded_by(
        &self,
        scalar: &T,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Multiplication by a scalar using randomized arithmetic,
    /// variable-time in the scalar value, constant-time in the base.
    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &T,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by a scalar using randomized arithmetic,
    /// where the base is public. May use acceleration when available.
    fn scale_randomized_public_base_by(
        &self,
        scalar: &T,
        public_parameters: &Self::PublicParameters,
    ) -> Self;

    /// Constant-time Multiplication by a scalar using randomized arithmetic,
    /// where the base is public, with `scalar_bits` bound.
    /// May use acceleration when available.
    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &T,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self;
}

/// Blanket implementation of `Scale<Uint<LIMBS>>` for all `GroupElement` types.
///
/// Delegates to the corresponding `GroupElement::scale*` methods.
impl<const LIMBS: usize, G: GroupElement> Scale<Uint<LIMBS>> for G {
    fn scale_by(&self, scalar: &Uint<LIMBS>, public_parameters: &Self::PublicParameters) -> Self {
        self.scale(scalar, public_parameters)
    }

    fn scale_vartime_by(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_vartime(scalar, public_parameters)
    }

    fn scale_bounded_by(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_bounded_vartime(scalar, scalar_bits, public_parameters)
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_vartime_scalar(scalar, public_parameters)
    }

    fn scale_public_base_by(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_public_base(scalar, public_parameters)
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_public_base_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_randomized_by(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized(scalar, public_parameters)
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_vartime_scalar(scalar, public_parameters)
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &Uint<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_public_base(scalar, public_parameters)
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_randomized_public_base_bounded(scalar, scalar_bits, public_parameters)
    }
}

/// Blanket implementation of `Scale<Int<LIMBS>>` for all `GroupElement` types.
///
/// Delegates to the corresponding `GroupElement::scale_integer*` methods.
impl<const LIMBS: usize, G: GroupElement> Scale<Int<LIMBS>> for G {
    fn scale_by(&self, scalar: &Int<LIMBS>, public_parameters: &Self::PublicParameters) -> Self {
        self.scale_integer(scalar, public_parameters)
    }

    fn scale_vartime_by(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_vartime(scalar, public_parameters)
    }

    fn scale_bounded_by(
        &self,
        scalar: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_bounded_vartime_by(
        &self,
        scalar: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_bounded_vartime(scalar, scalar_bits, public_parameters)
    }

    fn scale_vartime_scalar_by(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_vartime_scalar(scalar, public_parameters)
    }

    fn scale_public_base_by(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_public_base(scalar, public_parameters)
    }

    fn scale_public_base_bounded_by(
        &self,
        scalar: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_public_base_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_randomized_by(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized(scalar, public_parameters)
    }

    fn scale_randomized_bounded_by(
        &self,
        scalar: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_bounded(scalar, scalar_bits, public_parameters)
    }

    fn scale_randomized_vartime_scalar_by(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_vartime_scalar(scalar, public_parameters)
    }

    fn scale_randomized_public_base_by(
        &self,
        scalar: &Int<LIMBS>,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_public_base(scalar, public_parameters)
    }

    fn scale_randomized_public_base_bounded_by(
        &self,
        scalar: &Int<LIMBS>,
        scalar_bits: u32,
        public_parameters: &Self::PublicParameters,
    ) -> Self {
        self.scale_integer_randomized_public_base_bounded(scalar, scalar_bits, public_parameters)
    }
}

/// A marker-trait for an element of an abelian group of bounded (by [`Uint<SCALAR_LIMBS>::MAX`])
/// order, in additive notation.
pub trait BoundedGroupElement<const SCALAR_LIMBS: usize>: GroupElement {
    /// Returns a (tight) lower-bound on the scalar group
    fn lower_bound(public_parameters: &Self::PublicParameters) -> Uint<SCALAR_LIMBS>;
}

/// An element of a natural numbers group.
/// This trait encapsulates both known and unknown order number groups, by allowing the group value
/// to be transitional to and from a bounded natural number.
///
/// This way allows us to capture both elliptic curve
/// scalars (which has their own serialization format captured by their types &
/// standards, and thus cannot have a `Uint<>` as their `Value`) and hidden-order groups like
/// Paillier's, where we cannot have `T: From<Uint<>>` as we cannot construct a group element
/// without the modulus which is specified in the public parameters.
///
/// Using `Self::Value` we can convert in and out of numbers, and instantiate group elements in a
/// unified way using `Self::new()` which receives the public parameters and can fail upon invalid
/// inputs.
pub trait NumbersGroupElement<const SCALAR_LIMBS: usize>:
    GroupElement<Value = Self::ValueExt>
    + BoundedGroupElement<SCALAR_LIMBS>
    + Into<Uint<SCALAR_LIMBS>>
    + Samplable
{
    type ValueExt: From<Uint<SCALAR_LIMBS>>
        + Into<Uint<SCALAR_LIMBS>>
        + Reduce<SCALAR_LIMBS>
        + Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + PartialOrd
        + ConstantTimeEq
        + ConditionallySelectable
        + Copy
        + Send
        + Sync;
}

impl<
        const SCALAR_LIMBS: usize,
        T: GroupElement + BoundedGroupElement<SCALAR_LIMBS> + Into<Uint<SCALAR_LIMBS>> + Samplable,
    > NumbersGroupElement<SCALAR_LIMBS> for T
where
    T::Value: From<Uint<SCALAR_LIMBS>>
        + Into<Uint<SCALAR_LIMBS>>
        + Reduce<SCALAR_LIMBS>
        + PartialOrd
        + ConditionallySelectable,
{
    type ValueExt = Self::Value;
}

pub trait KnownOrderScalar<const SCALAR_LIMBS: usize>:
    KnownOrderGroupElement<SCALAR_LIMBS, Scalar = Self>
    + NumbersGroupElement<SCALAR_LIMBS>
    + Mul<Self, Output = Self>
    + for<'r> Mul<&'r Self, Output = Self>
    + Invert
    + Samplable
    + Copy
    + Into<Uint<SCALAR_LIMBS>>
{
}

/// An element of a known-order abelian group, in additive notation.
pub trait KnownOrderGroupElement<const SCALAR_LIMBS: usize>:
    BoundedGroupElement<SCALAR_LIMBS> + Scale<Self::Scalar> + Scale<Value<Self::Scalar>>
{
    type Scalar: KnownOrderScalar<SCALAR_LIMBS>
        + Mul<Self, Output = Self>
        + for<'r> Mul<&'r Self, Output = Self>;

    /// Returns the order of the group
    fn order_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Uint<SCALAR_LIMBS>;
}

pub type Scalar<const SCALAR_LIMBS: usize, G> = <G as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar;
pub type ScalarPublicParameters<const SCALAR_LIMBS: usize, G> =
    PublicParameters<<G as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar>;
pub type ScalarValue<const SCALAR_LIMBS: usize, G> =
    Value<<G as KnownOrderGroupElement<SCALAR_LIMBS>>::Scalar>;

/// Constant-time multiplication by the generator.
///
/// May use optimizations (e.g., precomputed tables) when available.
pub trait MulByGenerator<T> {
    /// Multiply by the generator of the cyclic group in constant-time.
    #[must_use]
    fn mul_by_generator(&self, scalar: T) -> Self;
}

/// An element of an abelian, cyclic group of bounded (by `Uint<SCALAR_LIMBS>::MAX`) order, in
/// additive notation.
pub trait CyclicGroupElement: GroupElement {
    /// Returns the generator of the group.
    fn generator(&self) -> Self;

    /// Returns the value of generator of the group.
    fn generator_value_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Self::Value;

    /// Attempts to instantiate the generator of the group.
    fn generator_from_public_parameters(
        public_parameters: &Self::PublicParameters,
    ) -> Result<Self> {
        Self::new(
            Self::generator_value_from_public_parameters(public_parameters),
            public_parameters,
        )
    }
}

/// A marker trait for elements of a (known) prime-order group.
/// Any prime-order group is also cyclic.
/// In additive notation.
pub trait PrimeGroupElement<const SCALAR_LIMBS: usize>:
    KnownOrderGroupElement<SCALAR_LIMBS>
    + CyclicGroupElement
    + MulByGenerator<Self::Scalar>
    + for<'r> MulByGenerator<&'r Self::Scalar>
{
}

pub trait Samplable: GroupElement {
    /// Uniformly sample a random element.
    fn sample(public_parameters: &Self::PublicParameters, rng: &mut impl CsRng) -> Result<Self>;

    /// Uniformly sample a batch of random elements.
    fn sample_batch(
        public_parameters: &Self::PublicParameters,
        batch_size: usize,
        rng: &mut impl CsRng,
    ) -> Result<Vec<Self>> {
        iter::repeat_with(|| Self::sample(public_parameters, rng))
            .take(batch_size)
            .collect()
    }

    /// Uniformly sample a random element that statistically hides a group element sampled using `Self::sample()` when added to it.
    /// This is necessary for hidden order scalar groups where you don't know how to go through modulation.
    /// For any other group, the bench implementation simply calls `Self::sample()`,
    /// as adding a uniform randomizer modulo the group order perfectly hides the group element it is added to.
    fn sample_randomizer(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CsRng,
    ) -> Result<Self>;
}

/// Perform an inversion on a field element (i.e., base field element or scalar)
pub trait Invert: Sized {
    /// Invert a field element.
    fn invert(&self) -> CtOption<Self>;

    /// Batch invert a slice of field elements in-place using Montgomery's trick for supported types.
    ///
    /// This is much more efficient than inverting each element individually:
    /// instead of `n` inversions, it performs `1` inversion and `3(n-1)` multiplications.
    ///
    /// Zero elements are left as zero.
    fn batch_invert(elements: &mut [Self]) {
        // Default implementation: invert each element individually
        // Implementations should override this with an optimized batch inversion
        for element in elements.iter_mut() {
            if let Some(inv) = Option::<Self>::from(element.invert()) {
                *element = inv;
            }
        }
    }
}

/// Uniform encoding of arbitrary sequences for bytes to group elements.
pub trait HashToGroup: GroupElement {
    /// Computes the hash to group (a.k.a. `hash2curve`) routine, which takes an arbitrary sequence
    /// of `bytes` and returns a `GroupElement` of type `Self`.
    ///
    /// This method *uniformly* encodes `data` to the group. That is, the distribution of its
    /// output is statistically close to uniform over G. In addition,
    /// discrete log of the output point with respect to any other predetermined
    /// group element should be infeasible to compute. This is an important trait, e.g., for
    /// choosing commitment generators, as in `Pedersen`, where discrete log relations between
    /// the generators must be kept hidden.
    fn hash_to_group(bytes: &[u8]) -> Result<Self>;
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(benches, linear_combination::benches::benchmark);
