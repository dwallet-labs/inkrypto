// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

use group::PartyID;
pub use language::{
    EnhanceableLanguage, EnhancedLanguage, EnhancedPublicParameters, PublicParameters,
    StatementSpaceGroupElement, WitnessSpaceGroupElement,
};
pub use proof::Proof;

pub mod aggregation;
pub mod committed_linear_evaluation;
pub mod encryption_of_discrete_log;
pub mod encryption_of_tuple;
pub mod language;
pub mod proof;
pub mod scaling_of_discrete_log;

/// Maurer error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("mpc error")]
    MPC(#[from] ::mpc::Error),
    #[error("proof error")]
    ProofAggregation(#[from] ::proof::aggregation::Error),
    #[error("maurer error")]
    Maurer(#[from] maurer::Error),
    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),
    #[error("randomizer(s) out of range: proof verification failed")]
    OutOfRange,
    #[error(
        "parties {:?} sent mismatching range proof commitments in the Maurer aggregation and range proof aggregation protocols", .0
    )]
    MismatchingRangeProofMaurerCommitments(Vec<PartyID>),
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

/// Maurer result.
pub type Result<T> = std::result::Result<T, Error>;

impl TryInto<::proof::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<::proof::Error, Self::Error> {
        match self {
            Error::Proof(e) => Ok(e),
            e => Err(e),
        }
    }
}

impl TryInto<::proof::aggregation::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<::proof::aggregation::Error, Self::Error> {
        match self {
            Error::Proof(::proof::Error::Aggregation(e)) => Ok(e),
            Error::Maurer(maurer::Error::Aggregation(e)) => Ok(e),
            Error::MismatchingRangeProofMaurerCommitments(malicious_parties) => {
                Ok(mpc::Error::MaliciousMessage(malicious_parties).into())
            }
            e => Err(e),
        }
    }
}

impl From<Error> for ::mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::MPC(e) => e,
            Error::Proof(::proof::Error::Aggregation(e)) => e.into(),
            Error::Maurer(maurer::Error::Aggregation(e)) => e.into(),
            Error::Group(e) => mpc::Error::Group(e),
            Error::InternalError => mpc::Error::InternalError,
            Error::InvalidParameters => mpc::Error::InvalidParameters,
            Error::InvalidPublicParameters => mpc::Error::InvalidParameters,
            e => mpc::Error::Consumer(format!("enhanced maurer error {:?}", e)),
        }
    }
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(benches, encryption_of_tuple::benches::benchmark);
