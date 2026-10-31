//! Ristretto255 instances of the generic libpep types, as used by these bindings.

use libpep::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};

pub type Client = libpep::client::types::Client<Ristretto255>;
#[cfg(feature = "offline")]
pub type OfflineClient = libpep::client::types::OfflineClient<Ristretto255>;
#[cfg(feature = "json")]
pub type PepJsonBuilder = libpep::data::json::builder::PepJsonBuilder<Ristretto255>;
#[cfg(feature = "json")]
pub type PepJsonValue = libpep::data::json::data::PepJsonValue<Ristretto255>;
#[cfg(feature = "json")]
pub type EncryptedPepJsonValue = libpep::data::json::data::EncryptedPepJsonValue<Ristretto255>;
#[cfg(feature = "long")]
pub type LongPseudonym = libpep::data::long::LongPseudonym<Ristretto255>;
#[cfg(feature = "long")]
pub type LongAttribute = libpep::data::long::LongAttribute<Ristretto255>;
#[cfg(feature = "long")]
pub type LongEncryptedPseudonym = libpep::data::long::LongEncryptedPseudonym<Ristretto255>;
#[cfg(feature = "long")]
pub type LongEncryptedAttribute = libpep::data::long::LongEncryptedAttribute<Ristretto255>;
pub type Record = libpep::data::records::Record<Ristretto255>;
pub type EncryptedRecord = libpep::data::records::EncryptedRecord<Ristretto255>;
#[cfg(feature = "long")]
pub type LongRecord = libpep::data::records::LongRecord<Ristretto255>;
#[cfg(feature = "long")]
pub type LongEncryptedRecord = libpep::data::records::LongEncryptedRecord<Ristretto255>;
pub type Pseudonym = libpep::data::simple::Pseudonym<Ristretto255>;
pub type Attribute = libpep::data::simple::Attribute<Ristretto255>;
pub type EncryptedPseudonym = libpep::data::simple::EncryptedPseudonym<Ristretto255>;
pub type EncryptedAttribute = libpep::data::simple::EncryptedAttribute<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type JsonTranscryptionProof =
    libpep::data::verifiable::json::JsonTranscryptionProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type JsonTranscryptionBatchProof =
    libpep::data::verifiable::json::JsonTranscryptionBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type LongPseudonymPseudonymizationProof =
    libpep::data::verifiable::long::LongPseudonymPseudonymizationProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type LongPseudonymRekeyProof =
    libpep::data::verifiable::long::LongPseudonymRekeyProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type LongAttributeRekeyProof =
    libpep::data::verifiable::long::LongAttributeRekeyProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type LongPseudonymPseudonymizationBatchProof =
    libpep::data::verifiable::long::LongPseudonymPseudonymizationBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type LongPseudonymRekeyBatchProof =
    libpep::data::verifiable::long::LongPseudonymRekeyBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type LongAttributeRekeyBatchProof =
    libpep::data::verifiable::long::LongAttributeRekeyBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type RecordTranscryptionProof =
    libpep::data::verifiable::records::RecordTranscryptionProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "long")]
pub type LongRecordTranscryptionProof =
    libpep::data::verifiable::records::LongRecordTranscryptionProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type RecordTranscryptionBatchProof =
    libpep::data::verifiable::records::RecordTranscryptionBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(all(feature = "batch", feature = "long"))]
pub type LongRecordTranscryptionBatchProof =
    libpep::data::verifiable::records::LongRecordTranscryptionBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type PseudonymPseudonymizationProof =
    libpep::data::verifiable::simple::PseudonymPseudonymizationProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type PseudonymRekeyProof = libpep::data::verifiable::simple::PseudonymRekeyProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type AttributeRekeyProof = libpep::data::verifiable::simple::AttributeRekeyProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type PseudonymPseudonymizationBatchProof =
    libpep::data::verifiable::simple::PseudonymPseudonymizationBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type PseudonymRekeyBatchProof =
    libpep::data::verifiable::simple::PseudonymRekeyBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
#[cfg(feature = "batch")]
pub type AttributeRekeyBatchProof =
    libpep::data::verifiable::simple::AttributeRekeyBatchProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiablePseudonymizationCommitment =
    libpep::factors::commitments::VerifiablePseudonymizationCommitment<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRekeyCommitment =
    libpep::factors::commitments::VerifiableRekeyCommitment<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableTranscryptionCommitment =
    libpep::factors::commitments::VerifiableTranscryptionCommitment<Ristretto255>;
pub type RerandomizeFactor = libpep::factors::types::RerandomizeFactor<Ristretto255>;
pub type ReshuffleFactor = libpep::factors::types::ReshuffleFactor<Ristretto255>;
pub type PseudonymRekeyFactor = libpep::factors::types::PseudonymRekeyFactor<Ristretto255>;
pub type AttributeRekeyFactor = libpep::factors::types::AttributeRekeyFactor<Ristretto255>;
pub type PseudonymizationInfo = libpep::factors::types::PseudonymizationInfo<Ristretto255>;
pub type PseudonymRekeyInfo = libpep::factors::types::PseudonymRekeyInfo<Ristretto255>;
pub type AttributeRekeyInfo = libpep::factors::types::AttributeRekeyInfo<Ristretto255>;
pub type TranscryptionInfo = libpep::factors::types::TranscryptionInfo<Ristretto255>;
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
pub type BlindingFactor = libpep::keys::distribution::blinding::BlindingFactor<Ristretto255>;
pub type BlindedPseudonymGlobalSecretKey =
    libpep::keys::distribution::blinding::BlindedPseudonymGlobalSecretKey<Ristretto255>;
pub type BlindedAttributeGlobalSecretKey =
    libpep::keys::distribution::blinding::BlindedAttributeGlobalSecretKey<Ristretto255>;
pub type BlindedGlobalSecretKeys =
    libpep::keys::distribution::blinding::BlindedGlobalSecretKeys<Ristretto255>;
pub type BlindingCommitment = libpep::keys::distribution::proofs::BlindingCommitment<Ristretto255>;
pub type SessionKeyShareProof =
    libpep::keys::distribution::proofs::SessionKeyShareProof<Ristretto255>;
pub type PseudonymSessionKeyShare =
    libpep::keys::distribution::shares::PseudonymSessionKeyShare<Ristretto255>;
pub type AttributeSessionKeyShare =
    libpep::keys::distribution::shares::AttributeSessionKeyShare<Ristretto255>;
pub type SessionKeyShares = libpep::keys::distribution::shares::SessionKeyShares<Ristretto255>;
pub type GlobalPublicKeys = libpep::keys::types::GlobalPublicKeys<Ristretto255>;
pub type GlobalSecretKeys = libpep::keys::types::GlobalSecretKeys<Ristretto255>;
pub type PseudonymGlobalPublicKey = libpep::keys::types::PseudonymGlobalPublicKey<Ristretto255>;
pub type PseudonymGlobalSecretKey = libpep::keys::types::PseudonymGlobalSecretKey<Ristretto255>;
pub type AttributeGlobalPublicKey = libpep::keys::types::AttributeGlobalPublicKey<Ristretto255>;
pub type AttributeGlobalSecretKey = libpep::keys::types::AttributeGlobalSecretKey<Ristretto255>;
pub type SessionKeys = libpep::keys::types::SessionKeys<Ristretto255>;
pub type SessionPublicKeys = libpep::keys::types::SessionPublicKeys<Ristretto255>;
pub type PseudonymSessionKeys = libpep::keys::types::PseudonymSessionKeys<Ristretto255>;
pub type AttributeSessionKeys = libpep::keys::types::AttributeSessionKeys<Ristretto255>;
pub type PseudonymSessionPublicKey = libpep::keys::types::PseudonymSessionPublicKey<Ristretto255>;
pub type PseudonymSessionSecretKey = libpep::keys::types::PseudonymSessionSecretKey<Ristretto255>;
pub type AttributeSessionPublicKey = libpep::keys::types::AttributeSessionPublicKey<Ristretto255>;
pub type AttributeSessionSecretKey = libpep::keys::types::AttributeSessionSecretKey<Ristretto255>;
pub type DistributedTranscryptor =
    libpep::transcryptor::distributed::DistributedTranscryptor<Ristretto255Sha512>;
pub type Transcryptor = libpep::transcryptor::types::Transcryptor<Ristretto255Sha512>;
#[cfg(feature = "verifiable")]
pub type Verifier = libpep::verifier::Verifier<Ristretto255Sha512>;
#[cfg(feature = "verifiable")]
pub type FactorCommitment = libpep::elgamal::verifiable::FactorCommitment<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type PseudonymizationFactorCommitment =
    libpep::elgamal::verifiable::PseudonymizationFactorCommitment<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type RekeyFactorCommitment = libpep::elgamal::verifiable::RekeyFactorCommitment<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRerandomize = libpep::elgamal::verifiable::VerifiableRerandomize<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableReshuffle = libpep::elgamal::verifiable::VerifiableReshuffle<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableReshuffle2 = libpep::elgamal::verifiable::VerifiableReshuffle2<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRekey = libpep::elgamal::verifiable::VerifiableRekey<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRekey2 = libpep::elgamal::verifiable::VerifiableRekey2<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRSK = libpep::elgamal::verifiable::VerifiableRSK<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRSK2 = libpep::elgamal::verifiable::VerifiableRSK2<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRSKInner = libpep::elgamal::verifiable::VerifiableRSKInner<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRRSK = libpep::elgamal::verifiable::VerifiableRRSK<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRRSK2 = libpep::elgamal::verifiable::VerifiableRRSK2<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRerandomizeBatch =
    libpep::elgamal::verifiable::VerifiableRerandomizeBatch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableReshuffleBatch =
    libpep::elgamal::verifiable::VerifiableReshuffleBatch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableReshuffle2Batch =
    libpep::elgamal::verifiable::VerifiableReshuffle2Batch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRekeyBatch = libpep::elgamal::verifiable::VerifiableRekeyBatch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRekey2Batch = libpep::elgamal::verifiable::VerifiableRekey2Batch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRSKBatch = libpep::elgamal::verifiable::VerifiableRSKBatch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRSK2Batch = libpep::elgamal::verifiable::VerifiableRSK2Batch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRRSKBatch = libpep::elgamal::verifiable::VerifiableRRSKBatch<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type VerifiableRRSK2Batch = libpep::elgamal::verifiable::VerifiableRRSK2Batch<Ristretto255>;
