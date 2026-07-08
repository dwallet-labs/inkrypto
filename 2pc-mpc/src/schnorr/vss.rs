// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

//! # SSS-Based Schnorr 2PC-MPC Protocol
//!
//! This module contains the Shamir Secret Sharing (SSS) based implementation
//! of the 2PC-MPC Schnorr signature protocol, as described in Section 9 of the
//! 2PC-MPC v3 Provisionals document.
//!
//! ## Protocol Overview
//!
//! The protocol relies solely on Shamir Secret Sharing instead of threshold additive
//! homomorphic encryption. It can operate in either:
//! - **Synchronous mode**: Using Verifiable Secret Sharing (VSS)
//! - **Asynchronous mode**: Using Publicly Verifiable Secret Sharing (PVSS)
//!
//! Throughout this module, we refer to both variants collectively as VSS.
//!
//! ## Protocol Suite
//!
//! The complete protocol consists of:
//!
//! ### Key Generation (Protocol 9.1: $\Pi_{\textsf{keygen}}^{\textsf{SSS-Schnorr-keygen}}$)
//!
//! Each distributed party $B_i$ samples $x_0^i, x_1^i \gets \mathbb{Z}_q$ and uses VSS to share them.
//! The centralized party $A$ contributes $X_A = x_A \cdot G$ with a proof $\pi_{\textsf{DL}}$.
//!
//! **Output**:
//! - Public key parts: $X_{B,0}, X_{B,1} \in \mathbb{G}$
//! - Secret shares: $[x_0]_i, [x_1]_i \in \mathbb{Z}_q$
//! - Full public key: $X = X_A + X_{B,0} + \mu_x \cdot X_{B,1}$
//!
//! where $\mu_x = \mathcal{H}(\textsf{sid}, \mathbb{G}, G, q, X_A, X_{B,0}, X_{B,1}, \pi_{\textsf{DL}})$
//!
//! ### Pre-signing (Protocol 9.2: $\Pi_{\textsf{pres}}^{\textsf{Schnorr}}$)
//!
//! Each distributed party $B_i$ samples nonces $k_0^i, k_1^i \gets \mathbb{Z}_q$ and uses VSS to share them.
//!
//! **Output**:
//! - Nonce public shares: $K_{B,0} = k_0 \cdot G$, $K_{B,1} = k_1 \cdot G$
//! - Secret shares: $[k_0]_i, [k_1]_i \in \mathbb{Z}_q$
//!
//! ### Signing (Protocol 9.3: $\Pi_{\textsf{sign}}^{\textsf{SSS-Schnorr}}$)
//!
//! 1. Centralized party $A$ samples $k_A \gets \mathbb{Z}_q$, computes $K_A = k_A \cdot G$
//! 2. Random oracle: $\mu_k = \mathcal{H}(\textsf{sid}, X, \textsf{pres}_{X,\textsf{sid}}, K_A, \textsf{msg})$
//! 3. Compute nonce: $K = K_{B,0} + \mu_k \cdot K_{B,1} + K_A$
//! 4. Challenge: $e = \mathcal{H}(K, X, \textsf{msg})$
//! 5. $A$ computes: $z_A = k_A + e \cdot x_A$
//! 6. Each $B_i$ computes share: $[\sigma]_i = [k]_i + e \cdot [x_B]_i + [z_A]_i$
//! 7. Reconstruct: $\sigma = \textsf{Reconstruct}(\{[\sigma]_i\}_{i \in S})$
//!
//! ### VSS (Protocol 9.4: $\Pi_{\textsf{VVSS}}^{\textsf{Hybrid}}$)
//!
//! Hybrid VSS scheme using:
//! - Pedersen-style commitments: $C_\ell = a_\ell \cdot G$ for polynomial coefficients
//! - Asymmetric encryption for key derivation
//! - Symmetric encryption (AES) for share encryption
//!
//! **Verification**: $\sum_{\ell \in [0,t-1]} i^\ell \cdot C_\ell = [s]_i \cdot G$
//!
//! ## References
//!
//! - Section 9: "Optimized SSS-Based Schnorr" from 2PC-MPC v3 Provisionals
//! - Protocol 9.1: SSS Schnorr Based Key Generation
//! - Protocol 9.2: SSS Schnorr Based Pre-sign
//! - Protocol 9.3: SSS Schnorr Based Sign
//! - Protocol 9.4: Hybrid VSS

pub use presign::Presign;

pub mod presign;
pub mod sign;
