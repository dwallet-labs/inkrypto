// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: CC-BY-NC-ND-4.0

pub use language::Language;
pub use proof::{
    fischlin, fischlin::UC_PROOFS_REPETITIONS, Proof, BIT_SOUNDNESS_PROOFS_REPETITIONS,
    SOUND_PROOFS_REPETITIONS,
};

pub mod aggregation;
pub mod commitment_of_discrete_log;
pub mod discrete_log_ratio_of_committed_values;
pub mod knowledge_of_decommitment;
pub mod knowledge_of_discrete_log;

pub mod committed_linear_evaluation;
pub mod encryption_of_discrete_log;
pub mod encryption_of_tuple;
pub mod equality_between_commitments_with_different_public_parameters;
pub mod equality_of_discrete_logs;
pub mod language;
mod proof;
pub mod scaling_of_discrete_log;
pub mod vector_commitment_of_discrete_log;

#[cfg(any(test, feature = "test_helpers"))]
#[allow(unused_imports)]
pub mod test_helpers {
    pub use crate::{
        aggregation::test_helpers::*,
        language::test_helpers::*,
        proof::{fischlin::test_helpers::*, test_helpers::*},
    };
}

/// Maurer error.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("group error")]
    Group(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("commitment error")]
    Commitment(#[from] commitment::Error),
    #[error("mpc error")]
    MPC(#[from] ::mpc::Error),
    #[error("aggregation error")]
    Aggregation(#[from] ::proof::aggregation::Error),
    #[error("unsupported repetitions")]
    UnsupportedRepetitions,
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("serialization/deserialization error: {0:?}")]
    Serialization(String),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
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
            Error::Aggregation(e) => Ok(e),
            e => Err(e),
        }
    }
}

impl From<Error> for ::mpc::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::MPC(e) => e,
            Error::Aggregation(e) => e.into(),
            Error::Group(e) => mpc::Error::Group(e),
            Error::InternalError => mpc::Error::InternalError,
            Error::InvalidParameters => mpc::Error::InvalidParameters,
            Error::InvalidPublicParameters => mpc::Error::InvalidParameters,
            e => mpc::Error::Consumer(format!("maurer error {e:?}")),
        }
    }
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(
    benches,
    knowledge_of_discrete_log::benches::benchmark,
    knowledge_of_decommitment::benches::benchmark,
    commitment_of_discrete_log::benches::benchmark,
    vector_commitment_of_discrete_log::benches::benchmark,
    discrete_log_ratio_of_committed_values::benches::benchmark,
    equality_between_commitments_with_different_public_parameters::benches::benchmark,
    equality_of_discrete_logs::benches::benchmark
);
