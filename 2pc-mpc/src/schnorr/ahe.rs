// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # AHE-Based Schnorr 2PC-MPC Protocol
//!
//! This module contains the Additively Homomorphic Encryption (AHE) based implementation
//! of the 2PC-MPC Schnorr signature protocol. It uses class groups for threshold encryption.
//!
//! ## Protocol Overview
//!
//! The protocol uses threshold additive homomorphic encryption (TAHE) to enable
//! distributed signing without reconstructing the secret key. The key components are:
//!
//! - **Presign**: Generates encrypted nonce shares $\ct_{k_0}, \ct_{k_1}$ and public nonce points
//!   $K_{B,0} = k_0 \cdot G$, $K_{B,1} = k_1 \cdot G$
//! - **Sign**: Uses homomorphic operations on ciphertexts followed by threshold decryption
//!
//! ## References
//!
//! See the original 2PC-MPC paper for the full protocol specification.

pub mod presign;
pub mod sign;

pub use presign::Presign;
