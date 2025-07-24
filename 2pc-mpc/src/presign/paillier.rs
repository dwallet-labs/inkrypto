// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! This file implements the `Presign` protocol trait for Paillier

use crypto_bigint::{ConcatMixed, Encoding, Uint};

use group::{PrimeGroupElement, StatisticalSecuritySizedNumber};
use tiresias::CiphertextSpaceValue;

use crate::paillier::asynchronous::Protocol;
use crate::paillier::Presign;
use crate::presign::decentralized_party::PublicInput;

impl<
        const RANGE_CLAIMS_PER_SCALAR: usize,
        const RANGE_CLAIMS_PER_MASK: usize,
        const NUM_RANGE_CLAIMS: usize,
        const SCALAR_LIMBS: usize,
        GroupElement: PrimeGroupElement<SCALAR_LIMBS>,
    > super::Protocol
    for Protocol<
        RANGE_CLAIMS_PER_SCALAR,
        RANGE_CLAIMS_PER_MASK,
        NUM_RANGE_CLAIMS,
        SCALAR_LIMBS,
        GroupElement,
    >
where
    Uint<SCALAR_LIMBS>: Encoding,
    Uint<SCALAR_LIMBS>: ConcatMixed<StatisticalSecuritySizedNumber>
        + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        > + for<'a> From<
            &'a <Uint<SCALAR_LIMBS> as ConcatMixed<StatisticalSecuritySizedNumber>>::MixedOutput,
        >,
    Uint<RANGE_CLAIMS_PER_SCALAR>: Encoding,
{
    type Presign = Presign<GroupElement>;
    type PresignPublicInput =
        PublicInput<GroupElement::Value, CiphertextSpaceValue, Self::ProtocolPublicParameters>;
    type PresignParty = crate::paillier::PresignAsyncParty<
        SCALAR_LIMBS,
        RANGE_CLAIMS_PER_SCALAR,
        NUM_RANGE_CLAIMS,
        GroupElement,
    >;
}
