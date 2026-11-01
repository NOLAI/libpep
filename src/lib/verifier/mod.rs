//! Verifier for verifiable transcryption operations.
//!
//! The verifier checks that operations were performed with the factors a transcryptor
//! committed to:
//!
//!   * For a pseudonymization transition `(d_from, d_to, c_from, c_to)` the
//!     transcryptor publishes the *combined* commitments
//!     `S = (s_from⁻¹ · s_to)·G` and `K = (k_from⁻¹ · k_to)·G`. The verifier
//!     stores them under the chosen transition key.
//!   * For an attribute rekey transition `(c_from, c_to)` the transcryptor
//!     publishes the combined commitment `K = (k_from⁻¹ · k_to)·G`.
//!   * Per-message verifiable proofs are verified against those combined
//!     commitments.
//!
//! The commitments need no proof of well-formedness: every per-message proof
//! binds the operation to the forward commitment directly.
//!
//! # Per-message and batch verification
//!
//! This module verifies per-message proofs:
//! [`verify_pseudonymization`](Verifier::verify_pseudonymization),
//! [`verify_rekey`](Verifier::verify_rekey), and
//! [`verify_transcryption`](Verifier::verify_transcryption) (for composite
//! record/JSON values). Each is polymorphic over any encrypted type
//! implementing the matching `Verifiable*` trait (simple values, long
//! values, records, JSON).
//!
//! Batch proofs (`BatchPseudonymizationProof`
//! and its rekey and transcryption counterparts) implement the same traits and go through the
//! same methods. To verify a batch against cached commitments, fetch them with
//! [`pseudonymization_commitments`](Verifier::pseudonymization_commitments),
//! [`pseudonym_rekey_commitments`](Verifier::pseudonym_rekey_commitments) or
//! [`attribute_rekey_commitments`](Verifier::attribute_rekey_commitments).

pub mod cache;
mod errors;
mod verify;

pub use cache::{
    AttributeRekeyCommitmentsCache, CacheRegistrationError, CommitmentsCache,
    InMemoryCommitmentsCache, PseudonymRekeyCommitmentsCache, PseudonymizationCommitmentsCache,
};
pub use errors::{RegisterCommitmentsError, VerifyError, WeakCommitmentError};
pub use verify::{PseudonymizationKey, RekeyTransitionKey, Verifier, VerifierCache};
