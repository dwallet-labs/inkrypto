// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

// The backward-compatible Reconfiguration `PublicOutput` is the Reconfiguration public
// output without the Shamir sharing of the secret key share parts. That shape lives as
// `decentralized_party::reconfiguration::PublicOutputCore`; we re-export it here so both
// protocols share one struct, one implementation, and one BCS encoding.

pub use crate::decentralized_party::reconfiguration::PublicOutputCore as PublicOutput;
