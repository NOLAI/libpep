//! Verifier for verifiable transcryption operations.
//!
//! The verifier enforces integrity by ensuring transcryptors use consistent factors
//! for each user (domain) and session (context).
//!
//! # Cache Organization
//!
//! - **Reshuffle commitments**: Per pseudonymization domain (user-specific)
//! - **Rekey commitments**: Per encryption context (session-specific)
//!
//! Each cache stores both `val` and `inv` for the factor commitments.

pub mod cache;
pub mod verifier;

pub use cache::{
    AttributeRekeyCommitmentsCache, CommitmentsCache, InMemoryCommitmentsCache,
    PseudonymRekeyCommitmentsCache, ReshuffleCommitmentsCache,
};
pub use verifier::Verifier;
