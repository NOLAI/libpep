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
    EncryptionContext, ProvedRekeyCommitments, ProvedReshuffleCommitments, PseudonymizationDomain,
};
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

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
    fn store(&mut self, key: Self::Key, commitments: Self::Commitments);

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
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InMemoryCommitmentsCache<Key, Commitments>
where
    Key: Eq + Hash,
{
    cache: HashMap<Key, Commitments>,
}

impl<Key, Commitments> InMemoryCommitmentsCache<Key, Commitments>
where
    Key: Eq + Hash,
{
    /// Create a new empty in-memory cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
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
        }
    }

    fn store(&mut self, key: Self::Key, commitments: Self::Commitments) {
        self.cache.insert(key, commitments);
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

/// Type alias for reshuffle commitments cache (indexed by transcryptor ID and domain).
pub type ReshuffleCommitmentsCache =
    InMemoryCommitmentsCache<(TranscryptorId, PseudonymizationDomain), ProvedReshuffleCommitments>;

/// Type alias for pseudonym rekey commitments cache (indexed by transcryptor ID and context).
pub type PseudonymRekeyCommitmentsCache =
    InMemoryCommitmentsCache<(TranscryptorId, EncryptionContext), ProvedRekeyCommitments>;

/// Type alias for attribute rekey commitments cache (indexed by transcryptor ID and context).
pub type AttributeRekeyCommitmentsCache =
    InMemoryCommitmentsCache<(TranscryptorId, EncryptionContext), ProvedRekeyCommitments>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic_operations() {
        let mut cache = InMemoryCommitmentsCache::<String, i32>::new();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.store("key1".to_string(), 42);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert!(cache.has(&"key1".to_string()));
        assert_eq!(cache.retrieve(&"key1".to_string()), Some(&42));

        cache.store("key2".to_string(), 100);
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
        cache.store("a".to_string(), 1);
        cache.store("b".to_string(), 2);

        let dump = cache.dump();
        assert_eq!(dump.len(), 2);
        assert!(dump.contains(&("a".to_string(), 1)));
        assert!(dump.contains(&("b".to_string(), 2)));
    }
}
