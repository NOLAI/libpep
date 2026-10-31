//! ristretto255 aliases of the generic libpep types, used by the bindings.
//!
//! The core crate is generic over the group; the Python module only exposes ristretto255, so the
//! binding layer fixes the group once here.

#![allow(unused_imports)]

use libpep::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};

// data::simple
pub type Pseudonym = libpep::data::simple::Pseudonym<Ristretto255>;
pub type Attribute = libpep::data::simple::Attribute<Ristretto255>;
pub type EncryptedPseudonym = libpep::data::simple::EncryptedPseudonym<Ristretto255>;
pub type EncryptedAttribute = libpep::data::simple::EncryptedAttribute<Ristretto255>;

// data::long
pub type LongPseudonym = libpep::data::long::LongPseudonym<Ristretto255>;
pub type LongAttribute = libpep::data::long::LongAttribute<Ristretto255>;
pub type LongEncryptedPseudonym = libpep::data::long::LongEncryptedPseudonym<Ristretto255>;
pub type LongEncryptedAttribute = libpep::data::long::LongEncryptedAttribute<Ristretto255>;

// data::records
pub type Record = libpep::data::records::Record<Ristretto255>;
pub type EncryptedRecord = libpep::data::records::EncryptedRecord<Ristretto255>;
#[cfg(feature = "long")]
pub type LongRecord = libpep::data::records::LongRecord<Ristretto255>;
#[cfg(feature = "long")]
pub type LongEncryptedRecord = libpep::data::records::LongEncryptedRecord<Ristretto255>;

// data::json
pub type PepJsonBuilder = libpep::data::json::builder::PepJsonBuilder<Ristretto255>;
pub type PepJsonValue = libpep::data::json::data::PepJsonValue<Ristretto255>;
pub type EncryptedPepJsonValue = libpep::data::json::data::EncryptedPepJsonValue<Ristretto255>;

// client / transcryptor / verifier
pub type Client = libpep::client::Client<Ristretto255>;
#[cfg(feature = "offline")]
pub type OfflineClient = libpep::client::OfflineClient<Ristretto255>;
pub type Transcryptor = libpep::transcryptor::Transcryptor<Ristretto255Sha512>;
pub type DistributedTranscryptor =
    libpep::transcryptor::DistributedTranscryptor<Ristretto255Sha512>;
#[cfg(feature = "verifiable")]
pub type Verifier = libpep::verifier::Verifier<Ristretto255Sha512>;

// data::verifiable
pub type PseudonymPseudonymizationProof =
    libpep::data::verifiable::simple::PseudonymPseudonymizationProof<Ristretto255>;
pub type PseudonymRekeyProof = libpep::data::verifiable::simple::PseudonymRekeyProof<Ristretto255>;
pub type AttributeRekeyProof = libpep::data::verifiable::simple::AttributeRekeyProof<Ristretto255>;
pub type LongPseudonymPseudonymizationProof =
    libpep::data::verifiable::long::LongPseudonymPseudonymizationProof<Ristretto255>;
pub type LongPseudonymRekeyProof =
    libpep::data::verifiable::long::LongPseudonymRekeyProof<Ristretto255>;
pub type LongAttributeRekeyProof =
    libpep::data::verifiable::long::LongAttributeRekeyProof<Ristretto255>;
pub type RecordTranscryptionProof =
    libpep::data::verifiable::records::RecordTranscryptionProof<Ristretto255>;
#[cfg(feature = "long")]
pub type LongRecordTranscryptionProof =
    libpep::data::verifiable::records::LongRecordTranscryptionProof<Ristretto255>;
pub type JsonTranscryptionProof =
    libpep::data::verifiable::json::JsonTranscryptionProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type PseudonymPseudonymizationBatchProof =
    libpep::data::verifiable::simple::PseudonymPseudonymizationBatchProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type PseudonymRekeyBatchProof =
    libpep::data::verifiable::simple::PseudonymRekeyBatchProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type AttributeRekeyBatchProof =
    libpep::data::verifiable::simple::AttributeRekeyBatchProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type LongPseudonymPseudonymizationBatchProof =
    libpep::data::verifiable::long::LongPseudonymPseudonymizationBatchProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type LongPseudonymRekeyBatchProof =
    libpep::data::verifiable::long::LongPseudonymRekeyBatchProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type LongAttributeRekeyBatchProof =
    libpep::data::verifiable::long::LongAttributeRekeyBatchProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type RecordTranscryptionBatchProof =
    libpep::data::verifiable::records::RecordTranscryptionBatchProof<Ristretto255>;
#[cfg(all(feature = "batch", feature = "long"))]
pub type LongRecordTranscryptionBatchProof =
    libpep::data::verifiable::records::LongRecordTranscryptionBatchProof<Ristretto255>;
#[cfg(feature = "batch")]
pub type JsonTranscryptionBatchProof =
    libpep::data::verifiable::json::JsonTranscryptionBatchProof<Ristretto255>;

// factors
pub type RerandomizeFactor = libpep::factors::RerandomizeFactor<Ristretto255>;
pub type ReshuffleFactor = libpep::factors::ReshuffleFactor<Ristretto255>;
pub type PseudonymRekeyFactor = libpep::factors::PseudonymRekeyFactor<Ristretto255>;
pub type AttributeRekeyFactor = libpep::factors::AttributeRekeyFactor<Ristretto255>;
pub type PseudonymizationInfo = libpep::factors::PseudonymizationInfo<Ristretto255>;
pub type PseudonymRekeyInfo = libpep::factors::PseudonymRekeyInfo<Ristretto255>;
pub type AttributeRekeyInfo = libpep::factors::AttributeRekeyInfo<Ristretto255>;
pub type TranscryptionInfo = libpep::factors::TranscryptionInfo<Ristretto255>;
pub type VerifiablePseudonymizationCommitment =
    libpep::factors::VerifiablePseudonymizationCommitment<Ristretto255>;
pub type VerifiableRekeyCommitment = libpep::factors::VerifiableRekeyCommitment<Ristretto255>;
pub type VerifiableTranscryptionCommitment =
    libpep::factors::VerifiableTranscryptionCommitment<Ristretto255>;
#[cfg(feature = "verifiable-derivation")]
pub type MasterPseudonymizationSecret =
    libpep::factors::verifiable::MasterPseudonymizationSecret<Ristretto255Sha512>;
#[cfg(feature = "verifiable-derivation")]
pub type MasterPseudonymizationPublicKey =
    libpep::factors::verifiable::MasterPseudonymizationPublicKey<Ristretto255Sha512>;
#[cfg(feature = "verifiable-derivation")]
pub type MasterRekeyingSecret =
    libpep::factors::verifiable::MasterRekeyingSecret<Ristretto255Sha512>;
#[cfg(feature = "verifiable-derivation")]
pub type MasterRekeyingPublicKey =
    libpep::factors::verifiable::MasterRekeyingPublicKey<Ristretto255Sha512>;

// keys
pub type GlobalPublicKeys = libpep::keys::GlobalPublicKeys<Ristretto255>;
pub type GlobalSecretKeys = libpep::keys::GlobalSecretKeys<Ristretto255>;
pub type PseudonymGlobalPublicKey = libpep::keys::PseudonymGlobalPublicKey<Ristretto255>;
pub type PseudonymGlobalSecretKey = libpep::keys::PseudonymGlobalSecretKey<Ristretto255>;
pub type AttributeGlobalPublicKey = libpep::keys::AttributeGlobalPublicKey<Ristretto255>;
pub type AttributeGlobalSecretKey = libpep::keys::AttributeGlobalSecretKey<Ristretto255>;
pub type SessionKeys = libpep::keys::SessionKeys<Ristretto255>;
pub type SessionPublicKeys = libpep::keys::SessionPublicKeys<Ristretto255>;
pub type PseudonymSessionKeys = libpep::keys::PseudonymSessionKeys<Ristretto255>;
pub type AttributeSessionKeys = libpep::keys::AttributeSessionKeys<Ristretto255>;
pub type PseudonymSessionPublicKey = libpep::keys::PseudonymSessionPublicKey<Ristretto255>;
pub type PseudonymSessionSecretKey = libpep::keys::PseudonymSessionSecretKey<Ristretto255>;
pub type AttributeSessionPublicKey = libpep::keys::AttributeSessionPublicKey<Ristretto255>;
pub type AttributeSessionSecretKey = libpep::keys::AttributeSessionSecretKey<Ristretto255>;
pub type BlindingFactor = libpep::keys::distribution::BlindingFactor<Ristretto255>;
pub type BlindedPseudonymGlobalSecretKey =
    libpep::keys::distribution::BlindedPseudonymGlobalSecretKey<Ristretto255>;
pub type BlindedAttributeGlobalSecretKey =
    libpep::keys::distribution::BlindedAttributeGlobalSecretKey<Ristretto255>;
pub type BlindedGlobalSecretKeys =
    libpep::keys::distribution::BlindedGlobalSecretKeys<Ristretto255>;
pub type BlindingCommitment = libpep::keys::distribution::BlindingCommitment<Ristretto255>;
pub type SessionKeyShareProof = libpep::keys::distribution::SessionKeyShareProof<Ristretto255>;
pub type PseudonymSessionKeyShare =
    libpep::keys::distribution::PseudonymSessionKeyShare<Ristretto255>;
pub type AttributeSessionKeyShare =
    libpep::keys::distribution::AttributeSessionKeyShare<Ristretto255>;
pub type SessionKeyShares = libpep::keys::distribution::SessionKeyShares<Ristretto255>;

// elgamal::verifiable
pub type FactorCommitment = libpep::elgamal::verifiable::FactorCommitment<Ristretto255>;
pub type PseudonymizationFactorCommitment =
    libpep::elgamal::verifiable::PseudonymizationFactorCommitment<Ristretto255>;
pub type RekeyFactorCommitment = libpep::elgamal::verifiable::RekeyFactorCommitment<Ristretto255>;
pub type VerifiableRerandomize = libpep::elgamal::verifiable::VerifiableRerandomize<Ristretto255>;
pub type VerifiableReshuffle = libpep::elgamal::verifiable::VerifiableReshuffle<Ristretto255>;
pub type VerifiableReshuffle2 = libpep::elgamal::verifiable::VerifiableReshuffle2<Ristretto255>;
pub type VerifiableRekey = libpep::elgamal::verifiable::VerifiableRekey<Ristretto255>;
pub type VerifiableRekey2 = libpep::elgamal::verifiable::VerifiableRekey2<Ristretto255>;
pub type VerifiableRSK = libpep::elgamal::verifiable::VerifiableRSK<Ristretto255>;
pub type VerifiableRSK2 = libpep::elgamal::verifiable::VerifiableRSK2<Ristretto255>;
pub type VerifiableRSKInner = libpep::elgamal::verifiable::VerifiableRSKInner<Ristretto255>;
pub type VerifiableRRSK = libpep::elgamal::verifiable::VerifiableRRSK<Ristretto255>;
pub type VerifiableRRSK2 = libpep::elgamal::verifiable::VerifiableRRSK2<Ristretto255>;
pub type VerifiableRerandomizeBatch =
    libpep::elgamal::verifiable::VerifiableRerandomizeBatch<Ristretto255>;
pub type VerifiableReshuffleBatch =
    libpep::elgamal::verifiable::VerifiableReshuffleBatch<Ristretto255>;
pub type VerifiableReshuffle2Batch =
    libpep::elgamal::verifiable::VerifiableReshuffle2Batch<Ristretto255>;
pub type VerifiableRekeyBatch = libpep::elgamal::verifiable::VerifiableRekeyBatch<Ristretto255>;
pub type VerifiableRekey2Batch = libpep::elgamal::verifiable::VerifiableRekey2Batch<Ristretto255>;
pub type VerifiableRSKBatch = libpep::elgamal::verifiable::VerifiableRSKBatch<Ristretto255>;
pub type VerifiableRSK2Batch = libpep::elgamal::verifiable::VerifiableRSK2Batch<Ristretto255>;
pub type VerifiableRRSKBatch = libpep::elgamal::verifiable::VerifiableRRSKBatch<Ristretto255>;
pub type VerifiableRRSK2Batch = libpep::elgamal::verifiable::VerifiableRRSK2Batch<Ristretto255>;
