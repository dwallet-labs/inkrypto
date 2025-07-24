// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use group::additive;

use crate::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

pub(super) mod multiplicative;

pub const PLAINTEXT_SPACE_SCALAR_LIMBS: usize = LargeBiPrimeSizedNumber::LIMBS;
pub const RANDOMNESS_SPACE_SCALAR_LIMBS: usize = LargeBiPrimeSizedNumber::LIMBS;

pub const CIPHERTEXT_SPACE_SCALAR_LIMBS: usize = PaillierModulusSizedNumber::LIMBS;

pub type PlaintextSpaceGroupElement = additive::GroupElement<PLAINTEXT_SPACE_SCALAR_LIMBS>;
pub type RandomnessSpaceGroupElement = multiplicative::GroupElement<RANDOMNESS_SPACE_SCALAR_LIMBS>;
pub type CiphertextSpaceGroupElement = multiplicative::GroupElement<CIPHERTEXT_SPACE_SCALAR_LIMBS>;

pub type PlaintextSpacePublicParameters = additive::PublicParameters<PLAINTEXT_SPACE_SCALAR_LIMBS>;
pub type RandomnessSpacePublicParameters =
    multiplicative::PublicParameters<RANDOMNESS_SPACE_SCALAR_LIMBS>;
pub type CiphertextSpacePublicParameters =
    multiplicative::PublicParameters<CIPHERTEXT_SPACE_SCALAR_LIMBS>;

pub type PlaintextSpaceValue = LargeBiPrimeSizedNumber;
pub type RandomnessSpaceValue = multiplicative::Value<RANDOMNESS_SPACE_SCALAR_LIMBS>;
pub type CiphertextSpaceValue = multiplicative::Value<CIPHERTEXT_SPACE_SCALAR_LIMBS>;
