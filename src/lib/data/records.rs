//! Record types for encrypting multiple pseudonyms and attributes together.
//!
//! A `Record` represents a collection of pseudonyms and attributes that belong to the same entity.
//! When encrypted, it becomes an `EncryptedRecord`.
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// Structure descriptor for Records - describes the shape without the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordStructure {
    pub num_pseudonyms: usize,
    pub num_attributes: usize,
}

/// Structure descriptor for LongRecords - describes the shape including block counts.
#[cfg(feature = "long")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongRecordStructure {
    /// Number of blocks in each long pseudonym
    pub pseudonym_blocks: Vec<usize>,
    /// Number of blocks in each long attribute
    pub attribute_blocks: Vec<usize>,
}

/// The [`Record`](generic::Record) over ristretto255.
pub type Record = generic::Record<Ristretto255>;
/// The [`EncryptedRecord`](generic::EncryptedRecord) over ristretto255.
pub type EncryptedRecord = generic::EncryptedRecord<Ristretto255>;
/// The [`LongRecord`](generic::LongRecord) over ristretto255.
#[cfg(feature = "long")]
pub type LongRecord = generic::LongRecord<Ristretto255>;
/// The [`LongEncryptedRecord`](generic::LongEncryptedRecord) over ristretto255.
#[cfg(feature = "long")]
pub type LongEncryptedRecord = generic::LongEncryptedRecord<Ristretto255>;
