// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use core::{
    fmt::Debug,
    iter,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use crypto_bigint::{rand_core::CryptoRngCore, Int, Uint, U128, U64};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

pub use linear_combination::LinearlyCombinable;
pub use reduce::Reduce;

pub mod helpers;

pub mod additive;
pub mod bounded_integers_group;
pub mod bounded_natural_numbers_group;
pub mod const_additive;
pub mod direct_product;
pub mod linear_combination;
mod reduce;
pub mod ristretto;
pub mod scalar;
pub mod secp256k1;
pub mod self_product;

/// Represents an unsigned integer sized based on the computation security parameter, denoted as
/// $\kappa$.
pub type ComputationalSecuritySizedNumber = U128;

/// Represents an unsigned integer sized based on the statistical security parameter, denoted as
/// $s$. Configured for 64-bit statistical security using U64.
pub type StatisticalSecuritySizedNumber = U64;

/// A unique identifier of a party in an MPC protocol.
pub type PartyID = u16;

/// Group error.
#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
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

    #[error("hash to group: failed to encode bytes to a group element.")]
    HashToGroup,

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
    Neg<Output = Self>
    + Add<Self, Output = Self>
    + for<'r> Add<&'r Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'r> Sub<&'r Self, Output = Self>
    + AddAssign<Self>
    + for<'r> AddAssign<&'r Self>
    + SubAssign<Self>
    + for<'r> SubAssign<&'r Self>
    + Into<Self::Value>
    + Into<Self::PublicParameters>
    + Debug
    + PartialEq
    + Eq
    + Copy
    + Clone
    + LinearlyCombinable
    + ConstantTimeEq
    + ConditionallySelectable
    + Send
    + Sync
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
        + ConditionallySelectable
        + Copy
        + Default
        + Send
        + Sync;

    /// Returns the value of this group element.
    fn value(&self) -> Self::Value {
        (*self).into()
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
    type PublicParameters: Serialize
        + for<'r> Deserialize<'r>
        + Clone
        + PartialEq
        + Eq
        + Debug
        + Send
        + Sync;

    /// Returns the public parameters of this group element
    fn public_parameters(&self) -> Self::PublicParameters {
        (*self).into()
    }

    /// Instantiate the group element from its value and the caller supplied parameters.
    ///
    /// *** NOTICE ***: `Self::new()` must check that the
    /// `value` belongs to the group identified by `params` and return an error otherwise!
    ///
    /// Even for static groups where `Self::Value = Self`, it must be assured the value is an
    /// element of the group either here or in deserialization.
    fn new(value: Self::Value, public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// Returns the additive identity, also known as the "neutral element".
    fn neutral(&self) -> Self;

    /// Returns the additive identity, also known as the "neutral element".
    fn neutral_from_public_parameters(public_parameters: &Self::PublicParameters) -> Result<Self>;

    /// Determines if this point is the identity in constant-time.
    fn is_neutral(&self) -> Choice {
        self.value().ct_eq(&self.neutral().value())
    }

    /// Constant-time Multiplication by (any bounded) natural number (scalar)
    fn scale<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        self.scale_bounded(scalar, Uint::<LIMBS>::BITS)
    }

    /// Constant-time Multiplication by (any bounded) integer (scalar)
    fn scale_integer<const LIMBS: usize>(&self, integer: &Int<LIMBS>) -> Self {
        self.scale_integer_bounded(integer, Uint::<LIMBS>::BITS)
    }

    /// Variable-time Multiplication by (any bounded) natural number (scalar)
    fn scale_vartime<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>) -> Self {
        self.scale_bounded_vartime(scalar, scalar.bits_vartime())
    }

    /// Variable-time Multiplication by (any bounded) integer (scalar)
    fn scale_integer_vartime<const LIMBS: usize>(&self, scalar: &Int<LIMBS>) -> Self {
        self.scale_integer_bounded_vartime(scalar, scalar.abs().bits_vartime())
    }

    /// Constant-time Multiplication by (any bounded) natural number (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scale_bounded<const LIMBS: usize>(&self, scalar: &Uint<LIMBS>, scalar_bits: u32) -> Self {
        // Safe to `.unwrap()` here as we assure `bases_and_multiplicands` is non-empty
        Self::linearly_combine_bounded(vec![(*self, *scalar)], scalar_bits).unwrap()
    }

    /// Constant-time Multiplication by (any bounded) integer (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scale_integer_bounded<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        let positive = self.scale_bounded(&integer.abs(), scalar_bits);
        let negated = positive.neg();

        <Self as ConditionallySelectable>::conditional_select(
            &positive,
            &negated,
            integer.is_negative().into(),
        )
    }

    /// Variable-time Multiplication by (any bounded) natural number (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_bounded_vartime<const LIMBS: usize>(
        &self,
        scalar: &Uint<LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        self.scale_bounded(scalar, scalar_bits)
    }

    /// Variable-time Multiplication by (any bounded) integer (scalar),
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_integer_bounded_vartime<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        let positive = self.scale_bounded_vartime(&integer.abs(), scalar_bits);

        if bool::from(integer.is_negative()) {
            positive.neg()
        } else {
            positive
        }
    }

    /// Multiplication by (any bounded) integer (scalar),
    /// variable-time in respect to the sign of `integer` only.
    /// `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_integer_bounded_vartime_scalar<const LIMBS: usize>(
        &self,
        integer: &Int<LIMBS>,
        scalar_bits: u32,
    ) -> Self {
        let positive = self.scale_bounded_vartime(&integer.abs(), scalar_bits);

        if bool::from(integer.is_negative()) {
            positive.neg()
        } else {
            positive
        }
    }

    /// Variable-time Addition.
    fn add_vartime(self, other: &Self) -> Self {
        self + other
    }

    /// Double this point in constant-time.
    #[must_use]
    fn double(&self) -> Self;

    /// Double this point in variable-time.
    #[must_use]
    fn double_vartime(&self) -> Self {
        self.double()
    }
}

pub trait Scale<T> {
    /// Constant-time Multiplication by a Scalar
    fn scale_generic(&self, scalar: &T) -> Self;

    /// Constant-time Multiplication by a scalar,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    ///
    /// NOTE: `scalar_bits` may be leaked in the time pattern.
    fn scale_bounded_generic(&self, scalar: &T, scalar_bits: u32) -> Self;

    /// Variable-time Multiplication by a scalar,
    /// with `scalar_bits` representing the number of (least significant) bits
    /// to take into account for the scalar.
    fn scale_bounded_vartime_generic(&self, scalar: &T, scalar_bits: u32) -> Self;
}

impl<const LIMBS: usize, G: GroupElement> Scale<Uint<LIMBS>> for G {
    fn scale_generic(&self, scalar: &Uint<LIMBS>) -> Self {
        self.scale(scalar)
    }

    fn scale_bounded_generic(&self, scalar: &Uint<LIMBS>, scalar_bits: u32) -> Self {
        self.scale_bounded(scalar, scalar_bits)
    }

    fn scale_bounded_vartime_generic(&self, scalar: &Uint<LIMBS>, scalar_bits: u32) -> Self {
        self.scale_bounded_vartime(scalar, scalar_bits)
    }
}

impl<const LIMBS: usize, G: GroupElement> Scale<Int<LIMBS>> for G {
    fn scale_generic(&self, scalar: &Int<LIMBS>) -> Self {
        self.scale_integer(scalar)
    }

    fn scale_bounded_generic(&self, scalar: &Int<LIMBS>, scalar_bits: u32) -> Self {
        self.scale_integer_bounded(scalar, scalar_bits)
    }

    fn scale_bounded_vartime_generic(&self, scalar: &Int<LIMBS>, scalar_bits: u32) -> Self {
        self.scale_integer_bounded_vartime(scalar, scalar_bits)
    }
}

/// A bench implementation for groups whose underlying implementation does not expose a
/// bounded multiplication function, and operates in constant-time. This implementation
/// simply assures that only the required bits out of the multiplied value is taken; this
/// is a correctness adaptation and not a performance one.
pub fn scale_bounded<const LIMBS: usize, T: GroupElement>(
    group_element: &T,
    scalar: &Uint<LIMBS>,
    scalar_bits: u32,
) -> T {
    // First, take only the `scalar_bits` least significant bits
    let mask = (Uint::<LIMBS>::ONE.wrapping_shl(scalar_bits)).wrapping_sub(&Uint::<LIMBS>::ONE);
    let scalar = scalar & mask;

    // Call the underlying scalar mul function, which now only use the `scalar_bits` least
    // significant bits, but will still take the same time to compute due to
    // constant-timeness.
    group_element.scale(&scalar)
}

pub type Value<G> = <G as GroupElement>::Value;

pub type PublicParameters<G> = <G as GroupElement>::PublicParameters;

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
    T::Value:
        From<Uint<SCALAR_LIMBS>> + Into<Uint<SCALAR_LIMBS>> + Reduce<SCALAR_LIMBS> + PartialOrd,
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
    fn order(&self) -> Uint<SCALAR_LIMBS> {
        Self::order_from_public_parameters(&self.public_parameters())
    }

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
    fn sample(
        public_parameters: &Self::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self>;

    /// Uniformly sample a batch of random elements.
    fn sample_batch(
        public_parameters: &Self::PublicParameters,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
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
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        Self::sample(public_parameters, rng)
    }
}

/// Perform an inversion on a field element (i.e., base field element or scalar)
pub trait Invert: Sized {
    /// Invert a field element.
    fn invert(&self) -> CtOption<Self>;
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

/// Access to the x affine coordinate of an elliptic curve point, for ECDSA.
pub trait AffineXCoordinate<const SCALAR_LIMBS: usize>: PrimeGroupElement<SCALAR_LIMBS> {
    /// Get the affine x-coordinate as a scalar.
    fn x(&self) -> Self::Scalar;
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(benches, linear_combination::benches::benchmark);
