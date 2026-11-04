//! The verifier and its commitment caches. The commitment registry is in
//! [`commitments`](super::commitments) and the verification operations in
//! [`operations`](super::operations).

use super::cache::{
    AttributeRekeyCommitmentsCache, CommitmentsCache, PseudonymRekeyCommitmentsCache,
    PseudonymizationCommitmentsCache,
};
use crate::ciphersuite::Ciphersuite;
use crate::ciphersuite::Ristretto255Sha512;
use crate::contexts::TranscryptorId;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
#[cfg(feature = "verifiable-derivation")]
use crate::factors::verifiable::{MasterPseudonymizationPublicKey, MasterRekeyingPublicKey};
use crate::group::Group;
use crate::group::Ristretto255;
use crate::keys::distribution::proofs::BlindingCommitment;
use std::collections::HashMap;

/// A verifier with per-transition commitment caching.
///
/// Stored commitments are *combined* for a given transition (i.e. already
/// encode the `s_from⁻¹·s_to` / `k_from⁻¹·k_to` product). Verification of
/// individual transcryption operations then reduces to a single
/// [`VerifiableRRSK`](crate::elgamal::verifiable::VerifiableRRSK) or
/// [`VerifiableRekey`](crate::elgamal::verifiable::VerifiableRekey) check against
/// these commitments.
pub struct Verifier<C: Ciphersuite = Ristretto255Sha512> {
    pub(super) pseudonymization_cache: PseudonymizationCommitmentsCache<C::Group>,
    pub(super) pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache<C::Group>,
    pub(super) attribute_rekey_cache: AttributeRekeyCommitmentsCache<C::Group>,
    /// Blinding commitments per transcryptor, for session-key-share verification.
    pub(super) blinding_commitments: HashMap<TranscryptorId, BlindingCommitment<C::Group>>,
    #[cfg(feature = "verifiable-derivation")]
    pub(super) master_pseudonym_keys: HashMap<TranscryptorId, MasterPseudonymizationPublicKey<C>>,
    #[cfg(feature = "verifiable-derivation")]
    pub(super) master_rekey_keys: HashMap<TranscryptorId, MasterRekeyingPublicKey<C>>,
}

/// Key identifying a pseudonymization transition.
pub type PseudonymizationKey = (
    TranscryptorId,
    PseudonymizationDomain,
    PseudonymizationDomain,
    EncryptionContext,
    EncryptionContext,
);

/// Key identifying a rekey transition.
pub type RekeyTransitionKey = (TranscryptorId, EncryptionContext, EncryptionContext);

impl Verifier {
    /// A verifier with empty, unbounded caches, for ristretto255 with SHA-512.
    ///
    /// See [`new_generic`](Verifier::new_generic) for another ciphersuite.
    #[must_use]
    pub fn new() -> Self {
        Self::new_generic()
    }

    /// A verifier with each commitment cache capped at `max_entries`, for ristretto255 with
    /// SHA-512. See [`with_cache_capacity_generic`](Verifier::with_cache_capacity_generic).
    #[must_use]
    pub fn with_cache_capacity(max_entries: usize) -> Self {
        Self::with_cache_capacity_generic(max_entries)
    }
}

impl<C: Ciphersuite> Verifier<C> {
    /// A verifier with empty, unbounded caches, for ciphersuite `C`.
    ///
    /// [`Verifier::new`] is this function for ristretto255 with SHA-512.
    #[must_use]
    pub fn new_generic() -> Self {
        Self {
            pseudonymization_cache: PseudonymizationCommitmentsCache::<C::Group>::new(),
            pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache::<C::Group>::new(),
            attribute_rekey_cache: AttributeRekeyCommitmentsCache::<C::Group>::new(),
            blinding_commitments: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_pseudonym_keys: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_rekey_keys: HashMap::new(),
        }
    }

    /// Construct a verifier with each commitment cache capped at
    /// `max_entries`. Once a cache is at its cap, further
    /// `register_*_commitments` calls return
    /// [`CacheRegistrationError::CacheFull`](super::cache::CacheRegistrationError::CacheFull)
    /// (wrapped in [`RegisterCommitmentsError`](super::RegisterCommitmentsError)). Idempotent re-registration
    /// of an existing key remains allowed at the cap.
    ///
    /// Use this when commitment registration is reachable from untrusted code
    /// and memory must be bounded.
    ///
    /// [`Verifier::with_cache_capacity`] is this function for ristretto255 with SHA-512.
    #[must_use]
    pub fn with_cache_capacity_generic(max_entries: usize) -> Self {
        Self {
            pseudonymization_cache: PseudonymizationCommitmentsCache::<C::Group>::with_max_entries(
                max_entries,
            ),
            pseudonym_rekey_cache: PseudonymRekeyCommitmentsCache::<C::Group>::with_max_entries(
                max_entries,
            ),
            attribute_rekey_cache: AttributeRekeyCommitmentsCache::<C::Group>::with_max_entries(
                max_entries,
            ),
            blinding_commitments: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_pseudonym_keys: HashMap::new(),
            #[cfg(feature = "verifiable-derivation")]
            master_rekey_keys: HashMap::new(),
        }
    }
}

/// Read-only view of the verifier's cache.
pub struct VerifierCache<'a, G: Group = Ristretto255> {
    pub(super) pseudonymization: &'a PseudonymizationCommitmentsCache<G>,
    pub(super) pseudonym_rekey: &'a PseudonymRekeyCommitmentsCache<G>,
    pub(super) attribute_rekey: &'a AttributeRekeyCommitmentsCache<G>,
}

impl<G: Group> VerifierCache<'_, G> {
    /// Whether no commitments are cached.
    pub fn is_empty(&self) -> bool {
        self.pseudonymization.is_empty()
            && self.pseudonym_rekey.is_empty()
            && self.attribute_rekey.is_empty()
    }

    /// The number of cached commitments over all transitions.
    pub fn total_count(&self) -> usize {
        self.pseudonymization.len() + self.pseudonym_rekey.len() + self.attribute_rekey.len()
    }

    /// The number of cached pseudonymization transitions.
    pub fn pseudonymization_count(&self) -> usize {
        self.pseudonymization.len()
    }

    /// The number of cached pseudonym rekey transitions.
    pub fn pseudonym_rekey_count(&self) -> usize {
        self.pseudonym_rekey.len()
    }

    /// The number of cached attribute rekey transitions.
    pub fn attribute_rekey_count(&self) -> usize {
        self.attribute_rekey.len()
    }
}

impl<C: Ciphersuite> Default for Verifier<C> {
    fn default() -> Self {
        Self::new_generic()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::ciphersuite::Ristretto255Sha512;
    use crate::contexts::{EncryptionContext, PseudonymizationDomain};
    use crate::elgamal::verifiable::{
        FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
    };
    use crate::factors::VerifiablePseudonymizationCommitment;
    use crate::group::group_elements::{GroupElement, G};
    use crate::group::Ristretto255;

    type Verifier = super::Verifier<Ristretto255Sha512>;

    fn weak_pseudonymization_commitments(
        weak: GroupElement,
    ) -> VerifiablePseudonymizationCommitment<Ristretto255> {
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
