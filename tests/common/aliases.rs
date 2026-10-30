//! Ristretto255 instances of the generic high-level types, for the tests.
#![allow(dead_code, unused_imports)]

pub use libpep::elgamal::arithmetic::Ristretto255;

pub type Client = libpep::client::types::Client<Ristretto255>;
#[cfg(feature = "json")]
pub type PepJsonBuilder = libpep::data::json::builder::PepJsonBuilder<Ristretto255>;
#[cfg(feature = "long")]
pub type LongPseudonym = libpep::data::long::LongPseudonym<Ristretto255>;
#[cfg(feature = "long")]
pub type LongAttribute = libpep::data::long::LongAttribute<Ristretto255>;
pub type Record = libpep::data::records::Record<Ristretto255>;
pub type EncryptedRecord = libpep::data::records::EncryptedRecord<Ristretto255>;
#[cfg(feature = "long")]
pub type LongEncryptedRecord = libpep::data::records::LongEncryptedRecord<Ristretto255>;
pub type Pseudonym = libpep::data::simple::Pseudonym<Ristretto255>;
pub type Attribute = libpep::data::simple::Attribute<Ristretto255>;
pub type EncryptedPseudonym = libpep::data::simple::EncryptedPseudonym<Ristretto255>;
pub type EncryptedAttribute = libpep::data::simple::EncryptedAttribute<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type PseudonymPseudonymizationBatchProof =
    libpep::data::verifiable::simple::PseudonymPseudonymizationBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiablePseudonymizationCommitment =
    libpep::factors::commitments::VerifiablePseudonymizationCommitment<Ristretto255>;
pub type PseudonymRekeyFactor = libpep::factors::types::PseudonymRekeyFactor<Ristretto255>;
pub type PseudonymizationInfo = libpep::factors::types::PseudonymizationInfo<Ristretto255>;
pub type PseudonymRekeyInfo = libpep::factors::types::PseudonymRekeyInfo<Ristretto255>;
pub type AttributeRekeyInfo = libpep::factors::types::AttributeRekeyInfo<Ristretto255>;
pub type TranscryptionInfo = libpep::factors::types::TranscryptionInfo<Ristretto255>;
#[cfg(feature = "verifiable-derivation")]
pub type MasterPseudonymizationSecret =
    libpep::factors::verifiable::MasterPseudonymizationSecret<Ristretto255>;
#[cfg(feature = "verifiable-derivation")]
pub type MasterRekeyingSecret = libpep::factors::verifiable::MasterRekeyingSecret<Ristretto255>;
pub type BlindingFactor = libpep::keys::distribution::blinding::BlindingFactor<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type BlindingCommitment = libpep::keys::distribution::proofs::BlindingCommitment<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type SessionKeyShareProof =
    libpep::keys::distribution::proofs::SessionKeyShareProof<Ristretto255>;
pub type PseudonymGlobalSecretKey = libpep::keys::types::PseudonymGlobalSecretKey<Ristretto255>;
pub type AttributeGlobalSecretKey = libpep::keys::types::AttributeGlobalSecretKey<Ristretto255>;
pub type SessionKeys = libpep::keys::types::SessionKeys<Ristretto255>;
pub type SessionPublicKeys = libpep::keys::types::SessionPublicKeys<Ristretto255>;
pub type PseudonymSessionKeys = libpep::keys::types::PseudonymSessionKeys<Ristretto255>;
pub type AttributeSessionKeys = libpep::keys::types::AttributeSessionKeys<Ristretto255>;
pub type PseudonymSessionPublicKey = libpep::keys::types::PseudonymSessionPublicKey<Ristretto255>;
pub type DistributedTranscryptor =
    libpep::transcryptor::distributed::DistributedTranscryptor<Ristretto255>;
pub type Transcryptor = libpep::transcryptor::types::Transcryptor<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type Verifier = libpep::verifier::Verifier<Ristretto255>;
