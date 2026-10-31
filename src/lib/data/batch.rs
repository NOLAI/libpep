//! Polymorphic batches of encrypted values that share a single recipient session.
//!
//! [`EncryptedBatch<E>`] is the type for batch operations. It works
//! for every encrypted type in the library: simple
//! ([`EncryptedPseudonym`](crate::data::simple::EncryptedPseudonym),
//! [`EncryptedAttribute`](crate::data::simple::EncryptedAttribute)), long,
//! records, and JSON. It does this through [`Encryptable::PublicKeyType`].
//!
//! With the `batch-pk` feature (and without `elgamal3`), the batch carries the
//! public key its items are encrypted under, so that the transcryptor operations
//! need no key argument for their rerandomize step. Without `batch-pk` the
//! operations take the key per call, and with `elgamal3` every ciphertext
//! carries its own key.
//!
//! Construction validates that all items share the same
//! [`HasStructure::structure`], so
//! that later batch operations can shuffle the items without making them linkable
//! through structural fingerprinting.

#[cfg(feature = "json")]
use crate::data::json::{unify_structures, JsonError, PepJsonValue, UnifyError};
#[cfg(feature = "long")]
use crate::data::long::{LongAttribute, LongPseudonym};
#[cfg(feature = "long")]
use crate::data::records::LongRecord;
use crate::data::records::Record;
use crate::data::simple::{Attribute, Pseudonym};
use crate::data::traits::Encryptable;
use crate::data::traits::{Encrypted, HasStructure};
use crate::elgamal::arithmetic::group::Group;
#[cfg(feature = "json")]
use crate::elgamal::arithmetic::group::InvertibleEncoding;
use rand_core::{CryptoRng, Rng};
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An error in a batch operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BatchError {
    /// Items in the batch have inconsistent structures.
    ///
    /// All items in a batch must have the same structure to prevent linkability. If items had
    /// different structures (for example different numbers of blocks in long values, different
    /// JSON shapes, or different numbers of pseudonyms or attributes in records), an attacker
    /// could link items across batches by their structure, defeating the privacy protection of
    /// shuffling.
    #[error("Inconsistent structure in batch. Entry at index {index} has structure {actual_structure}, expected {expected_structure}.")]
    InconsistentStructure {
        /// The index of the first item whose structure differs.
        index: usize,
        /// The structure of the first item.
        expected_structure: String,
        /// The structure of the item at `index`.
        actual_structure: String,
    },
    /// Decryption of an item in the batch failed because the secret key does not match.
    ///
    /// Only occurs with the `elgamal3` feature, where ciphertexts encode the public key they
    /// were encrypted for and decryption with a mismatched key is detected.
    #[error("Decryption failed for entry at index {index}.")]
    DecryptionFailed {
        /// The index of the item that failed to decrypt.
        index: usize,
    },
    /// The JSON values in the batch cannot be brought to one structure.
    #[cfg(feature = "json")]
    #[error(transparent)]
    UnifyError(#[from] UnifyError),
    /// A JSON value in the batch is malformed.
    #[cfg(feature = "json")]
    #[error(transparent)]
    JsonError(#[from] JsonError),
}

/// A value that can be encrypted as part of a batch.
///
/// The hook [`preprocess_for_batch`](Self::preprocess_for_batch) brings the items of a batch to
/// a common shape before they are encrypted. The default passes them through; JSON values
/// override it.
pub trait Batchable: Encryptable + Clone {
    /// Hook for batch-level preprocessing before encryption. Override it when the encrypted
    /// batch needs items to share a uniform shape (for example JSON values padded to a unified
    /// structure).
    ///
    /// # Errors
    ///
    /// Returns an error if the items cannot be brought to one shape.
    fn preprocess_for_batch(items: &[Self]) -> Result<Vec<Self>, BatchError> {
        Ok(items.to_vec())
    }
}

impl<G: Group> Batchable for Pseudonym<G> {}
impl<G: Group> Batchable for Attribute<G> {}
#[cfg(feature = "long")]
impl<G: Group> Batchable for LongPseudonym<G> {}
#[cfg(feature = "long")]
impl<G: Group> Batchable for LongAttribute<G> {}
impl<G: Group> Batchable for Record<G> {}
#[cfg(feature = "long")]
impl<G: Group> Batchable for LongRecord<G> {}

/// JSON values must share one structure inside a batch, so they are padded to the unified
/// structure before encryption; otherwise the batch would be rejected for an inconsistent
/// shape, and the differing shapes would leak through the batch anyway.
#[cfg(feature = "json")]
impl<G: InvertibleEncoding> Batchable for PepJsonValue<G> {
    fn preprocess_for_batch(items: &[Self]) -> Result<Vec<Self>, BatchError> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let structures: Vec<_> = items.iter().map(|v| v.structure()).collect();
        let unified = unify_structures(&structures)?;
        Ok(items
            .iter()
            .map(|item| item.pad_to(&unified))
            .collect::<Result<Vec<_>, _>>()?)
    }
}

/// A polymorphic batch of ciphertexts that share a recipient session.
///
/// `E` may be any encrypted wrapper: simple (`EncryptedPseudonym`,
/// `EncryptedAttribute`), long, composite (`EncryptedRecord`,
/// `LongEncryptedRecord`, `EncryptedPepJsonValue`).
///
/// With the `batch-pk` feature (and without `elgamal3`), the public key the
/// items are encrypted under (a key bundle for composite types) is stored once
/// in the batch; otherwise the operations take the key per call, or the
/// ciphertexts carry it (`elgamal3`).
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(bound(
        serialize = "E: Serialize, <E::UnencryptedType as Encryptable>::PublicKeyType: Serialize"
    ))
)]
pub struct EncryptedBatch<E: Encrypted> {
    /// Recipient public key material the items are encrypted under.
    ///
    /// The associated-type indirection means this is
    /// `PseudonymSessionPublicKey` for `EncryptedBatch<EncryptedPseudonym>`,
    /// `AttributeSessionPublicKey` for `EncryptedBatch<EncryptedAttribute>`,
    /// `SessionPublicKeys` for composite types, etc.
    ///
    /// Present only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub(crate) public_key: <E::UnencryptedType as Encryptable>::PublicKeyType,

    /// The encrypted items. Private: a batch is only built through [`new`](Self::new) or
    /// deserialization, both of which check that the items share one structure.
    pub(crate) items: Vec<E>,
}

/// The fields of a batch as serialized; deserializing goes through the structure check.
#[cfg(feature = "serde")]
#[derive(Deserialize)]
#[serde(
    rename = "EncryptedBatch",
    bound(
        deserialize = "E: Deserialize<'de>, <E::UnencryptedType as Encryptable>::PublicKeyType: Deserialize<'de>"
    )
)]
struct RawBatch<E: Encrypted> {
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    public_key: <E::UnencryptedType as Encryptable>::PublicKeyType,
    items: Vec<E>,
}

#[cfg(feature = "serde")]
impl<'de, E> Deserialize<'de> for EncryptedBatch<E>
where
    E: Encrypted + HasStructure + Deserialize<'de>,
    <E::UnencryptedType as Encryptable>::PublicKeyType: Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawBatch::<E>::deserialize(deserializer)?;
        validate_structure(&raw.items).map_err(serde::de::Error::custom)?;
        Ok(Self {
            #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
            public_key: raw.public_key,
            items: raw.items,
        })
    }
}

// Manual Clone/Debug impls: `derive` would add unwanted bounds.
#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl<E> Clone for EncryptedBatch<E>
where
    E: Encrypted + Clone,
    <E::UnencryptedType as Encryptable>::PublicKeyType: Clone,
{
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key,
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
    /// The public key the items are encrypted under.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn public_key(&self) -> &<E::UnencryptedType as Encryptable>::PublicKeyType {
        &self.public_key
    }

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

/// Uniformly random index in `0..n` (n > 0), by rejection sampling on the random 64-bit output so
/// that the result is unbiased (a plain `% n` is biased for n not dividing 2^64).
fn random_index<R: Rng + CryptoRng>(n: usize, rng: &mut R) -> usize {
    let n = n as u64;
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = rng.next_u64();
        if v < zone {
            return (v % n) as usize;
        }
    }
}

/// Fisher-Yates shuffle with unbiased index sampling.
pub(crate) fn shuffle<T, R: Rng + CryptoRng>(slice: &mut [T], rng: &mut R) {
    for i in (1..slice.len()).rev() {
        let j = random_index(i + 1, rng);
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
    use crate::elgamal::arithmetic::Ristretto255;
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    use crate::keys::PublicKey;

    type EncryptedPseudonym = crate::data::simple::EncryptedPseudonym<Ristretto255>;
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    type PseudonymSessionPublicKey = crate::keys::PseudonymSessionPublicKey<Ristretto255>;

    #[test]
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    fn empty_batch_is_valid() {
        let pk =
            PseudonymSessionPublicKey::from_point(crate::elgamal::arithmetic::group_elements::G);
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

    #[test]
    fn random_index_stays_in_range() {
        let rng = &mut rand::rng();
        for n in [1usize, 2, 3, 7, 100, 1000] {
            for _ in 0..1000 {
                assert!(random_index(n, rng) < n);
            }
        }
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let rng = &mut rand::rng();
        let original: Vec<u32> = (0..50).collect();
        let mut shuffled = original.clone();
        shuffle(&mut shuffled, rng);
        let mut sorted = shuffled.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, original);
        assert_ne!(shuffled, original);
    }

    /// Regression test for the modulo bias.
    ///
    /// `random_index` must sample uniformly. The naive `rng.next_u64() % n` is biased
    /// whenever `n` does not divide `2^64`: the low residues occur more often than the
    /// high ones. That bias is invisible in a permutation check, so it has silently
    /// returned before through an unrelated merge. This test pins the uniformity down.
    ///
    /// The bias is tiny for small `n`, so the test uses a modulus chosen so that a biased
    /// implementation puts roughly 1.5x the expected mass on the first residue class.
    #[test]
    fn random_index_is_not_modulo_biased() {
        // For this n, floor(2^64 / n) leaves a remainder covering half the range, so a
        // plain `% n` would put ~1.5x the expected mass on index 0.
        let n = (1usize << 63) + (1usize << 62);
        let rng = &mut rand::rng();
        let samples = 20_000;
        let mut low = 0usize;
        for _ in 0..samples {
            if random_index(n, rng) < n / 2 {
                low += 1;
            }
        }
        // Unbiased: ~50% land in the lower half. The biased `% n` yields ~66%.
        let ratio = low as f64 / samples as f64;
        assert!(
            (0.45..0.55).contains(&ratio),
            "random_index looks biased: {ratio} of samples in the lower half (expected ~0.5). \
             A modulo-based implementation would give ~0.66."
        );
    }
}
