//! Verifier for verifiable transcryption operations.
//!
//! With the forward-only constructions, commitments are stored per
//! *transition* (`(d_from, d_to, c_from, c_to)` for pseudonymization,
//! `(c_from, c_to)` for rekeying) and already encode the combined factor.

pub mod cache;
#[allow(clippy::module_inception)]
pub mod verifier;

pub use cache::{
    AttributeRekeyCommitmentsCache, CacheRegistrationError, CommitmentsCache,
    InMemoryCommitmentsCache, PseudonymRekeyCommitmentsCache, PseudonymizationCommitmentsCache,
};
pub use verifier::{RegisterCommitmentsError, Verifier, VerifyError, WeakCommitmentError};
