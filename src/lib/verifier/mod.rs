//! Verifier for verifiable transcryption operations.
//!
//! The verifier checks that operations were performed against published
//! forward commitments. Concretely:
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
//! No proof of well-formedness of the commitments themselves is needed any
//! more: every per-message proof binds the operation to the forward
//! commitment directly.
//!
//! # Per-message vs batch verification
//!
//! This module exposes verification for *per-message* proofs:
//! [`verify_pseudonymization`](Verifier::verify_pseudonymization),
//! [`verify_rekey`](Verifier::verify_rekey), and
//! [`verify_transcryption`](Verifier::verify_transcryption) (for composite
//! record/JSON values). Each is polymorphic over any encrypted type
//! implementing the matching `Verifiable*` trait (simple values, long
//! values, records, JSON).
//!
//! Batch proofs are verified through the
//! [`EncryptedBatch`](crate::data::batch::EncryptedBatch) type directly
//! (`batch.verified_reconstruct_pseudonymize`, `verified_reconstruct_rekey`,
//! `verified_reconstruct_transcrypt`). Those methods take commitments
//! explicitly; if you want cached-commitment lookup at batch level, fetch
//! the commitments from this verifier's cache (`has_*_commitments` query
//! APIs) and pass them into the batch method.

pub mod cache;
pub mod generic;

pub use cache::{
    AttributeRekeyCommitmentsCache, CacheRegistrationError, CommitmentsCache,
    InMemoryCommitmentsCache, PseudonymRekeyCommitmentsCache, PseudonymizationCommitmentsCache,
};

use crate::elgamal::arithmetic::Ristretto255;

/// The [`Verifier`](generic::Verifier) over ristretto255.
pub type Verifier = generic::Verifier<Ristretto255>;
/// The [`VerifierCache`](generic::VerifierCache) over ristretto255.
pub type VerifierCache<'a> = generic::VerifierCache<'a, Ristretto255>;
pub use generic::{PseudonymizationKey, RekeyTransitionKey};

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
    Cache(#[from] cache::CacheRegistrationError),
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
    /// Which commitment is weak.
    WeakCommitment {
        /// Which commitment is weak.
        commitment_type: &'static str,
    },
    /// Master keys are not registered (needed for verifiable-derivation paths).
    #[error("master keys not registered for this transcryptor")]
    MasterKeysNotRegistered,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::contexts::{EncryptionContext, PseudonymizationDomain};
    use crate::elgamal::arithmetic::group_elements::{GroupElement, G};
    use crate::elgamal::verifiable::generic::{
        FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
    };
    use crate::factors::VerifiablePseudonymizationCommitment;

    fn weak_pseudonymization_commitments(
        weak: GroupElement,
    ) -> VerifiablePseudonymizationCommitment {
        VerifiablePseudonymizationCommitment {
            reshuffle_commitment: PseudonymizationFactorCommitment(FactorCommitment(weak)),
            rekey_commitment: RekeyFactorCommitment(FactorCommitment(weak)),
        }
    }

    #[test]
    fn register_rejects_weak_commitments_without_panicking() {
        let mut verifier = Verifier::new();
        let id = String::from("t1");
        let d1 = PseudonymizationDomain::from("d1");
        let d2 = PseudonymizationDomain::from("d2");
        let c1 = EncryptionContext::from("c1");
        let c2 = EncryptionContext::from("c2");

        // Identity commitments must be rejected with an Err, not a panic.
        let identity_commitments = weak_pseudonymization_commitments(GroupElement::identity());
        assert!(verifier
            .register_pseudonymization_commitments(&id, &d1, &d2, &c1, &c2, identity_commitments)
            .is_err());

        // Generator-equal commitments must also be rejected.
        let g_commitments = weak_pseudonymization_commitments(G);
        assert!(verifier
            .register_pseudonymization_commitments(&id, &d1, &d2, &c1, &c2, g_commitments)
            .is_err());

        // Cache must remain untouched after a failed registration.
        assert!(verifier.cache().is_empty());
    }
}
