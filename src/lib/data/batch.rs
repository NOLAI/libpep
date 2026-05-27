//! Polymorphic batches of encrypted values that share a single recipient session.
//!
//! [`EncryptedBatch<E>`] is the central type for batch operations. It works
//! uniformly across every encrypted type in the library — simple
//! ([`EncryptedPseudonym`](crate::data::simple::EncryptedPseudonym),
//! [`EncryptedAttribute`](crate::data::simple::EncryptedAttribute)), long,
//! records, and JSON — via the polymorphism already present in
//! [`Encryptable::PublicKeyType`](crate::data::traits::Encryptable::PublicKeyType).
//!
//! Under `elgamal2` with the `batch-pk` feature, the batch carries the
//! recipient public key at the batch level so that transcryptor operations
//! need no extra arguments to drive the rerandomize step. Without `batch-pk`
//! the field is dropped and the same operations require the caller to pass
//! `pk` per call. In `elgamal3` mode the field is always dropped (each
//! ciphertext already carries its own `gy`).
//!
//! Construction validates that all items share the same
//! [`HasStructure::structure`](crate::data::traits::HasStructure::structure) so
//! that subsequent batch operations can shuffle the items without enabling
//! linkability through structural fingerprinting.

use crate::data::traits::{Encryptable, Encrypted, HasStructure};
use rand_core::{CryptoRng, Rng};
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Error type for batch operation failures.
#[derive(Debug, Error)]
pub enum BatchError {
    /// Items in the batch have inconsistent structures.
    ///
    /// All items in a batch must have the same structure to prevent linkability.
    /// If items had different structures (e.g., different numbers of blocks in long values,
    /// different JSON shapes, or different numbers of pseudonyms/attributes in records),
    /// an attacker could potentially link items across batches based on their structure,
    /// defeating the privacy protection provided by shuffling.
    #[error("Inconsistent structure in batch. Entry at index {index} has structure {actual_structure}, expected {expected_structure}.")]
    InconsistentStructure {
        index: usize,
        expected_structure: String,
        actual_structure: String,
    },
    #[cfg(feature = "json")]
    #[error(transparent)]
    UnifyError(#[from] crate::data::json::UnifyError),
    #[cfg(feature = "json")]
    #[error(transparent)]
    JsonError(#[from] crate::data::json::JsonError),
}

/// A polymorphic batch of ciphertexts that share a recipient session.
///
/// `E` may be any encrypted wrapper: simple (`EncryptedPseudonym`,
/// `EncryptedAttribute`), long, composite (`EncryptedRecord`,
/// `LongEncryptedRecord`, `EncryptedPEPJSONValue`).
///
/// Under `elgamal2` with the `batch-pk` feature, the recipient public key
/// (or key bundle for composite types) is stored once at the batch level;
/// without `batch-pk` the field is omitted and ops require `pk` per call.
/// In `elgamal3` mode every item already carries `gy` and the field is
/// always omitted.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound(
        serialize = "E: Serialize, <E::UnencryptedType as Encryptable>::PublicKeyType: Serialize",
        deserialize = "E: Deserialize<'de>, <E::UnencryptedType as Encryptable>::PublicKeyType: Deserialize<'de>"
    ))
)]
pub struct EncryptedBatch<E: Encrypted> {
    /// Recipient public key material the items are encrypted under.
    ///
    /// The associated-type indirection means this is
    /// `PseudonymSessionPublicKey` for `EncryptedBatch<EncryptedPseudonym>`,
    /// `AttributeSessionPublicKey` for `EncryptedBatch<EncryptedAttribute>`,
    /// `SessionKeys` for composite types, etc.
    ///
    /// Present only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub public_key: <E::UnencryptedType as Encryptable>::PublicKeyType,

    /// The encrypted items.
    pub items: Vec<E>,
}

// Manual Clone/Debug impls — `derive` adds spurious bounds we don't want.
#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl<E> Clone for EncryptedBatch<E>
where
    E: Encrypted + Clone,
    <E::UnencryptedType as Encryptable>::PublicKeyType: Clone,
{
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            items: self.items.clone(),
        }
    }
}

#[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
impl<E: Encrypted + Clone> Clone for EncryptedBatch<E> {
    fn clone(&self) -> Self {
        Self {
            items: self.items.clone(),
        }
    }
}

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl<E> std::fmt::Debug for EncryptedBatch<E>
where
    E: Encrypted + std::fmt::Debug,
    <E::UnencryptedType as Encryptable>::PublicKeyType: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedBatch")
            .field("public_key", &self.public_key)
            .field("items", &self.items)
            .finish()
    }
}

#[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
impl<E: Encrypted + std::fmt::Debug> std::fmt::Debug for EncryptedBatch<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedBatch")
            .field("items", &self.items)
            .finish()
    }
}

impl<E> EncryptedBatch<E>
where
    E: Encrypted + HasStructure,
{
    /// Construct a batch from items and a recipient public key, validating
    /// that all items share the same structure.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::InconsistentStructure`] if the items do not all
    /// have the same structure.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn new(
        items: Vec<E>,
        public_key: <E::UnencryptedType as Encryptable>::PublicKeyType,
    ) -> Result<Self, BatchError> {
        validate_structure(&items)?;
        Ok(Self { public_key, items })
    }

    /// Construct a batch from items, validating that all items share the same
    /// structure. Used under `elgamal3` (each item carries its own `gy`) and
    /// under `(not batch-pk, not elgamal3)` (callers pass `pk` per op).
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::InconsistentStructure`] if the items do not all
    /// have the same structure.
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    pub fn new(items: Vec<E>) -> Result<Self, BatchError> {
        validate_structure(&items)?;
        Ok(Self { items })
    }

    /// Number of items in the batch.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<E: Encrypted> EncryptedBatch<E> {
    /// Consume the batch and return the inner items.
    pub fn into_items(self) -> Vec<E> {
        self.items
    }

    /// Borrow the inner items.
    pub fn as_items(&self) -> &[E] {
        &self.items
    }
}

impl<E: Encrypted> AsRef<[E]> for EncryptedBatch<E> {
    fn as_ref(&self) -> &[E] {
        &self.items
    }
}

impl<E: Encrypted> std::ops::Deref for EncryptedBatch<E> {
    type Target = [E];

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

/// Fisher–Yates shuffle using a `rand_core` RNG.
pub(crate) fn shuffle<T, R: Rng + CryptoRng>(slice: &mut [T], rng: &mut R) {
    for i in (1..slice.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        slice.swap(i, j);
    }
}

/// Validate that all items in a slice have the same structure.
pub(crate) fn validate_structure<E: HasStructure>(encrypted: &[E]) -> Result<(), BatchError> {
    if let Some(first) = encrypted.first() {
        let expected_structure = first.structure();
        for (index, item) in encrypted.iter().enumerate().skip(1) {
            let item_structure = item.structure();
            if item_structure != expected_structure {
                return Err(BatchError::InconsistentStructure {
                    index,
                    expected_structure: format!("{:?}", expected_structure),
                    actual_structure: format!("{:?}", item_structure),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::data::simple::EncryptedPseudonym;
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    use crate::keys::PseudonymSessionPublicKey;

    #[test]
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn empty_batch_is_valid() {
        let pk = PseudonymSessionPublicKey::from(crate::arithmetic::group_elements::G);
        let batch = EncryptedBatch::<EncryptedPseudonym>::new(Vec::new(), pk).expect("construct");
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    fn empty_batch_is_valid_no_pk() {
        let batch = EncryptedBatch::<EncryptedPseudonym>::new(Vec::new()).expect("construct");
        assert!(batch.is_empty());
    }
}
