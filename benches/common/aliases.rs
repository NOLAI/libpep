//! Ristretto255 instances of the generic high-level types, for the benchmarks.
#![allow(dead_code, unused_imports)]

pub use libpep::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};

pub type Client = libpep::client::types::Client<Ristretto255>;
#[cfg(feature = "long")]
pub type LongPseudonym = libpep::data::long::LongPseudonym<Ristretto255>;
#[cfg(feature = "long")]
pub type LongAttribute = libpep::data::long::LongAttribute<Ristretto255>;
pub type EncryptedRecord = libpep::data::records::EncryptedRecord<Ristretto255>;
pub type Pseudonym = libpep::data::simple::Pseudonym<Ristretto255>;
pub type Attribute = libpep::data::simple::Attribute<Ristretto255>;
pub type EncryptedPseudonym = libpep::data::simple::EncryptedPseudonym<Ristretto255>;
pub type EncryptedAttribute = libpep::data::simple::EncryptedAttribute<Ristretto255>;
pub type SessionPublicKeys = libpep::keys::types::SessionPublicKeys<Ristretto255>;
pub type DistributedTranscryptor =
    libpep::transcryptor::distributed::DistributedTranscryptor<Ristretto255Sha512>;
