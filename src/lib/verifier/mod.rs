//! Verifier for verifiable transcryption operations.
//!
//! A verifier (a user or another transcryptor) checks that a transcryptor transformed a ciphertext
//! with the factors it committed to, so that integrity does not depend on trusting the
//! transcryptor. A transcryptor publishes a commitment to each reshuffle and rekey factor it
//! uses for a domain or session, and the verifier records the commitments to enforce that the
//! same factor is used for the same domain or session every time. The factors stay secret. The
//! verifier is not trusted.
//!
//! A commitment makes the use of a factor consistent, but it does not show how the factor was
//! derived or that it was sampled uniformly. With distributed transcryption the effective factor
//! is still uniform as long as one transcryptor samples honestly.
//!
//! Who verifies is a deployment choice. Verifying a rerandomization needs the original
//! ciphertext, so a verifier learns the link between a ciphertext and its rerandomized copy.
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
