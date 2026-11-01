//! Record types for encrypting multiple pseudonyms and attributes together.
//!
//! A `Record` represents a collection of pseudonyms and attributes that belong to the same entity.
//! When encrypted, it becomes an `EncryptedRecord`.

pub mod data;
pub mod structure;

pub use crate::data::errors::ParseError;
pub use data::{EncryptedRecord, Record};
#[cfg(feature = "long")]
pub use data::{LongEncryptedRecord, LongRecord};
#[cfg(feature = "long")]
pub use structure::LongRecordStructure;
pub use structure::RecordStructure;
