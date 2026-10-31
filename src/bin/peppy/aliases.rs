//! Ristretto255 instances of the generic high-level types used by the CLI.

pub use libpep::elgamal::arithmetic::{Ristretto255, Ristretto255Sha512};

#[cfg(feature = "json")]
pub type PepJsonBuilder = libpep::data::json::builder::PepJsonBuilder<Ristretto255>;
#[cfg(feature = "long")]
pub type LongPseudonym = libpep::data::long::LongPseudonym<Ristretto255>;
#[cfg(feature = "long")]
pub type LongAttribute = libpep::data::long::LongAttribute<Ristretto255>;
#[cfg(feature = "long")]
pub type LongEncryptedPseudonym = libpep::data::long::LongEncryptedPseudonym<Ristretto255>;
#[cfg(feature = "long")]
pub type LongEncryptedAttribute = libpep::data::long::LongEncryptedAttribute<Ristretto255>;
pub type Pseudonym = libpep::data::simple::Pseudonym<Ristretto255>;
pub type Attribute = libpep::data::simple::Attribute<Ristretto255>;
pub type EncryptedPseudonym = libpep::data::simple::EncryptedPseudonym<Ristretto255>;
pub type EncryptedAttribute = libpep::data::simple::EncryptedAttribute<Ristretto255>;
#[cfg(all(feature = "json", feature = "verifiable"))]
pub type JsonTranscryptionProof =
    libpep::data::verifiable::json::JsonTranscryptionProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type LongPseudonymPseudonymizationProof =
    libpep::data::verifiable::long::LongPseudonymPseudonymizationProof<Ristretto255>;
#[cfg(feature = "verifiable")]
pub type PseudonymPseudonymizationProof =
    libpep::data::verifiable::simple::PseudonymPseudonymizationProof<Ristretto255>;
pub type VerifiablePseudonymizationCommitment =
    libpep::factors::commitments::VerifiablePseudonymizationCommitment<Ristretto255>;
pub type VerifiableRekeyCommitment =
    libpep::factors::commitments::VerifiableRekeyCommitment<Ristretto255>;
pub type VerifiableTranscryptionCommitment =
    libpep::factors::commitments::VerifiableTranscryptionCommitment<Ristretto255>;
pub type ReshuffleFactor = libpep::factors::types::ReshuffleFactor<Ristretto255>;
pub type PseudonymRekeyFactor = libpep::factors::types::PseudonymRekeyFactor<Ristretto255>;
pub type AttributeRekeyFactor = libpep::factors::types::AttributeRekeyFactor<Ristretto255>;
pub type PseudonymizationInfo = libpep::factors::types::PseudonymizationInfo<Ristretto255>;
pub type PseudonymRekeyInfo = libpep::factors::types::PseudonymRekeyInfo<Ristretto255>;
pub type AttributeRekeyInfo = libpep::factors::types::AttributeRekeyInfo<Ristretto255>;
pub type TranscryptionInfo = libpep::factors::types::TranscryptionInfo<Ristretto255>;
pub type BlindingFactor = libpep::keys::distribution::blinding::BlindingFactor<Ristretto255>;
pub type BlindedPseudonymGlobalSecretKey =
    libpep::keys::distribution::blinding::BlindedPseudonymGlobalSecretKey<Ristretto255>;
pub type BlindedAttributeGlobalSecretKey =
    libpep::keys::distribution::blinding::BlindedAttributeGlobalSecretKey<Ristretto255>;
pub type BlindedGlobalSecretKeys =
    libpep::keys::distribution::blinding::BlindedGlobalSecretKeys<Ristretto255>;
pub type PseudonymSessionKeyShare =
    libpep::keys::distribution::shares::PseudonymSessionKeyShare<Ristretto255>;
pub type AttributeSessionKeyShare =
    libpep::keys::distribution::shares::AttributeSessionKeyShare<Ristretto255>;
pub type SessionKeyShares = libpep::keys::distribution::shares::SessionKeyShares<Ristretto255>;
#[cfg(feature = "json")]
pub type GlobalPublicKeys = libpep::keys::types::GlobalPublicKeys<Ristretto255>;
pub type PseudonymGlobalPublicKey = libpep::keys::types::PseudonymGlobalPublicKey<Ristretto255>;
pub type PseudonymGlobalSecretKey = libpep::keys::types::PseudonymGlobalSecretKey<Ristretto255>;
pub type AttributeGlobalPublicKey = libpep::keys::types::AttributeGlobalPublicKey<Ristretto255>;
pub type AttributeGlobalSecretKey = libpep::keys::types::AttributeGlobalSecretKey<Ristretto255>;
#[cfg(feature = "json")]
pub type SessionKeys = libpep::keys::types::SessionKeys<Ristretto255>;
pub type PseudonymSessionKeys = libpep::keys::types::PseudonymSessionKeys<Ristretto255>;
pub type AttributeSessionKeys = libpep::keys::types::AttributeSessionKeys<Ristretto255>;
pub type PseudonymSessionPublicKey = libpep::keys::types::PseudonymSessionPublicKey<Ristretto255>;
pub type PseudonymSessionSecretKey = libpep::keys::types::PseudonymSessionSecretKey<Ristretto255>;
pub type AttributeSessionPublicKey = libpep::keys::types::AttributeSessionPublicKey<Ristretto255>;
pub type AttributeSessionSecretKey = libpep::keys::types::AttributeSessionSecretKey<Ristretto255>;
#[cfg(all(feature = "json", not(feature = "elgamal3")))]
pub type SessionPublicKeys = libpep::keys::types::SessionPublicKeys<Ristretto255>;
