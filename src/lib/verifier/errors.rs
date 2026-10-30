//! The errors of the verifier.

/// A commitment was the identity or the generator `G`, which would let any
/// per-message proof trivially "verify" without binding anything.
#[derive(thiserror::Error, Debug, Clone, Copy, Eq, PartialEq)]
#[error("weak {0} commitment is not allowed")]
pub struct WeakCommitmentError(pub &'static str);

/// Failure mode for `register_*_commitments` calls. Either the supplied
/// commitment is weak, or the cache rejected the registration (conflicting
/// value already present, or cache is full).
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum RegisterCommitmentsError {
    #[error(transparent)]
    /// The commitment is weak.
    Weak(#[from] WeakCommitmentError),
    #[error(transparent)]
    /// The cache refused the registration.
    Cache(#[from] super::cache::CacheRegistrationError),
}

/// Structured failure mode for `verify_*` / `verified_reconstruct_*` methods.
///
/// Distinguishes between cryptographic failure (`ProofRejected`), a cache
/// miss (`UnknownCommitment`), a weak / unusable commitment, and the absence
/// of master keys (only relevant on the `verifiable-derivation` path).
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum VerifyError {
    /// The proof did not verify against the supplied statement.
    #[error("proof rejected")]
    ProofRejected,
    /// No commitments registered for the requested transcryptor/transition.
    #[error("no commitments registered for this transition")]
    UnknownCommitment,
    /// Commitments are present but are weak / invalid.
    #[error("weak {commitment_type} commitment")]
    WeakCommitment {
        /// Which commitment is weak.
        commitment_type: &'static str,
    },
    /// Master keys are not registered (needed for verifiable-derivation paths).
    #[error("master keys not registered for this transcryptor")]
    MasterKeysNotRegistered,
}
