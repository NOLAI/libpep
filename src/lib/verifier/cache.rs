//! Commitment cache for storing and retrieving factor commitments.
//!
//! Transcryptors must use consistent factors for each user (domain) and session (context).
//! This cache enforces integrity by storing verified commitments indexed by:
//! - **Reshuffle factors**: Per pseudonymization domain (user-specific)
//! - **Rekey factors**: Per encryption context (session-specific)
//!
//! The cache follows the pattern from the distributed verifier, storing both `val` and `inv`
//! for each factor after verification.

use crate::factors::{
    EncryptionContext, PseudonymizationDomain, VerifiablePseudonymizationCommitment,
    VerifiableRekeyCommitment,
};
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Error returned when registering a commitment fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheRegistrationError {
    /// A different commitment was already registered under this key.
    /// Re-registering the *same* value is idempotent and never returns this.
    ConflictingValue,
    /// The cache has reached its configured maximum size.
    CacheFull,
}

impl std::fmt::Display for CacheRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConflictingValue => {
                write!(
                    f,
                    "a different commitment is already registered for this key"
                )
            }
            Self::CacheFull => write!(f, "commitment cache is full"),
        }
    }
}

impl std::error::Error for CacheRegistrationError {}

/// Trait for commitment caches.
///
/// This trait defines the interface for storing and retrieving factor commitments.
/// Implementations can use different storage backends (in-memory, persistent, etc.).
pub trait CommitmentsCache {
    /// The key type for cache lookups (domain or context).
    type Key;
    /// The commitment type stored in the cache.
    type Commitments;

    /// Create a new empty cache.
    fn new() -> Self
    where
        Self: Sized;

    /// Store commitments for a specific key.
    ///
    /// Returns `Err(ConflictingValue)` if a *different* value is already
    /// registered under this key (registering the same value is idempotent),
    /// or `Err(CacheFull)` if the cache is at its configured size limit.
    fn store(
        &mut self,
        key: Self::Key,
        commitments: Self::Commitments,
    ) -> Result<(), CacheRegistrationError>;

    /// Retrieve commitments for a specific key.
    fn retrieve(&self, key: &Self::Key) -> Option<&Self::Commitments>;

    /// Check if commitments exist for a specific key.
    fn has(&self, key: &Self::Key) -> bool;

    /// Check if the cache contains specific commitments (regardless of key).
    fn contains(&self, commitments: &Self::Commitments) -> bool;

    /// Get the number of entries in the cache.
    fn len(&self) -> usize;

    /// Check if the cache is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries from the cache.
    fn clear(&mut self);

    /// Dump all entries as a vector of (key, commitments) pairs.
    fn dump(&self) -> Vec<(Self::Key, Self::Commitments)>;
}

/// In-memory implementation of a commitments cache.
///
/// This cache stores commitments in a HashMap for fast O(1) lookups.
/// Re-registering a *different* value under an existing key is rejected
/// to prevent silent overwrite by a malicious or buggy caller; re-registering
/// the same value is idempotent. An optional `max_entries` cap protects
/// against memory-DoS when registration is reachable from untrusted code.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InMemoryCommitmentsCache<Key, Commitments>
where
    Key: Eq + Hash,
{
    cache: HashMap<Key, Commitments>,
    max_entries: Option<usize>,
}

impl<Key, Commitments> InMemoryCommitmentsCache<Key, Commitments>
where
    Key: Eq + Hash,
{
    /// Create a new empty in-memory cache without a size cap.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            max_entries: None,
        }
    }

    /// Create a new empty in-memory cache with a maximum number of entries.
    /// `store` will return `CacheFull` once the cap is reached.
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_entries: Some(max_entries),
        }
    }
}

impl<Key, Commitments> Default for InMemoryCommitmentsCache<Key, Commitments>
where
    Key: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

// Note: the trait bound `Commitments: PartialEq + Clone` on the impl below
// covers `store`'s equality check; without it, conflicting-value detection
// can't tell same from different.

impl<Key, Commitments> CommitmentsCache for InMemoryCommitmentsCache<Key, Commitments>
where
    Key: Eq + Hash + Clone,
    Commitments: PartialEq + Clone,
{
    type Key = Key;
    type Commitments = Commitments;

    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            max_entries: None,
        }
    }

    fn store(
        &mut self,
        key: Self::Key,
        commitments: Self::Commitments,
    ) -> Result<(), CacheRegistrationError> {
        if let Some(existing) = self.cache.get(&key) {
            if existing == &commitments {
                return Ok(());
            }
            return Err(CacheRegistrationError::ConflictingValue);
        }
        if let Some(cap) = self.max_entries {
            if self.cache.len() >= cap {
                return Err(CacheRegistrationError::CacheFull);
            }
        }
        self.cache.insert(key, commitments);
        Ok(())
    }

    fn retrieve(&self, key: &Self::Key) -> Option<&Self::Commitments> {
        self.cache.get(key)
    }

    fn has(&self, key: &Self::Key) -> bool {
        self.cache.contains_key(key)
    }

    fn contains(&self, commitments: &Self::Commitments) -> bool {
        self.cache.values().any(|v| v == commitments)
    }

    fn len(&self) -> usize {
        self.cache.len()
    }

    fn clear(&mut self) {
        self.cache.clear();
    }

    fn dump(&self) -> Vec<(Self::Key, Self::Commitments)> {
        self.cache
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

use crate::transcryptor::TranscryptorId;

/// Cache keyed by `(transcryptor, domain_from, domain_to, context_from, context_to)`
/// storing the combined pseudonymization commitments for a transition.
pub type PseudonymizationCommitmentsCache = InMemoryCommitmentsCache<
    (
        TranscryptorId,
        PseudonymizationDomain,
        PseudonymizationDomain,
        EncryptionContext,
        EncryptionContext,
    ),
    VerifiablePseudonymizationCommitment,
>;

/// Cache keyed by `(transcryptor, context_from, context_to)` storing the
/// combined pseudonym-rekey commitment for a transition.
pub type PseudonymRekeyCommitmentsCache = InMemoryCommitmentsCache<
    (TranscryptorId, EncryptionContext, EncryptionContext),
    VerifiableRekeyCommitment,
>;

/// Cache keyed by `(transcryptor, context_from, context_to)` storing the
/// combined attribute-rekey commitment for a transition.
pub type AttributeRekeyCommitmentsCache = InMemoryCommitmentsCache<
    (TranscryptorId, EncryptionContext, EncryptionContext),
    VerifiableRekeyCommitment,
>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic_operations() {
        let mut cache = InMemoryCommitmentsCache::<String, i32>::new();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.store("key1".to_string(), 42).expect("store");
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.has(&"key1".to_string()));
        assert_eq!(cache.retrieve(&"key1".to_string()), Some(&42));

        cache.store("key2".to_string(), 100).expect("store");
        assert_eq!(cache.len(), 2);

        assert!(cache.contains(&42));
        assert!(cache.contains(&100));
        assert!(!cache.contains(&999));

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_dump() {
        let mut cache = InMemoryCommitmentsCache::<String, i32>::new();
        cache.store("a".to_string(), 1).expect("store");
        cache.store("b".to_string(), 2).expect("store");

        let dump = cache.dump();
        assert_eq!(dump.len(), 2);
        assert!(dump.contains(&("a".to_string(), 1)));
        assert!(dump.contains(&("b".to_string(), 2)));
    }

    #[test]
    fn test_cache_rejects_conflicting_value() {
        let mut cache = InMemoryCommitmentsCache::<String, i32>::new();
        cache.store("key".to_string(), 1).expect("first store");
        assert_eq!(
            cache.store("key".to_string(), 2),
            Err(CacheRegistrationError::ConflictingValue),
        );
        // The original value is preserved.
        assert_eq!(cache.retrieve(&"key".to_string()), Some(&1));
    }

    #[test]
    fn test_cache_same_value_is_idempotent() {
        let mut cache = InMemoryCommitmentsCache::<String, i32>::new();
        cache.store("key".to_string(), 1).expect("first store");
        cache
            .store("key".to_string(), 1)
            .expect("idempotent re-store");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_enforces_max_entries() {
        let mut cache = InMemoryCommitmentsCache::<String, i32>::with_max_entries(2);
        cache.store("a".to_string(), 1).expect("first store");
        cache.store("b".to_string(), 2).expect("second store");
        assert_eq!(
            cache.store("c".to_string(), 3),
            Err(CacheRegistrationError::CacheFull),
        );
        // Idempotent re-store of an existing key is still allowed at the cap.
        cache.store("a".to_string(), 1).expect("idempotent at cap");
    }
}
