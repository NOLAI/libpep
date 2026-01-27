//! Record types for encrypting multiple pseudonyms and attributes together.
//!
//! A `Record` represents a collection of pseudonyms and attributes that belong to the same entity.
//! When encrypted, it becomes an `EncryptedRecord`.

use crate::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::data::traits::{Encryptable, Encrypted, Transcryptable};
use crate::factors::TranscryptionInfo;
use crate::keys::{GlobalPublicKeys, SessionKeys};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "verifiable")]
use crate::core::proved::{RSKFactorsProof, VerifiableRSK, VerifiableRekey};
#[cfg(feature = "verifiable")]
use crate::data::traits::VerifiableTranscryptable;

#[cfg(feature = "long")]
use crate::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};

#[cfg(feature = "batch")]
use crate::data::traits::HasStructure;

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

/// A record containing multiple pseudonyms and attributes for a single entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub pseudonyms: Vec<Pseudonym>,
    pub attributes: Vec<Attribute>,
}

/// An encrypted record containing multiple encrypted pseudonyms and attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord {
    pub pseudonyms: Vec<EncryptedPseudonym>,
    pub attributes: Vec<EncryptedAttribute>,
}

/// A long record containing multiple long pseudonyms and attributes for a single entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongRecord {
    pub pseudonyms: Vec<LongPseudonym>,
    pub attributes: Vec<LongAttribute>,
}

/// An encrypted long record containing multiple encrypted long pseudonyms and attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongEncryptedRecord {
    pub pseudonyms: Vec<LongEncryptedPseudonym>,
    pub attributes: Vec<LongEncryptedAttribute>,
}

impl Record {
    /// Create a new Record with the given pseudonyms and attributes.
    pub fn new(pseudonyms: Vec<Pseudonym>, attributes: Vec<Attribute>) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }
}

impl EncryptedRecord {
    /// Create a new EncryptedRecord with the given encrypted pseudonyms and attributes.
    pub fn new(pseudonyms: Vec<EncryptedPseudonym>, attributes: Vec<EncryptedAttribute>) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }
}

impl LongRecord {
    /// Create a new LongRecord with the given long pseudonyms and attributes.
    pub fn new(pseudonyms: Vec<LongPseudonym>, attributes: Vec<LongAttribute>) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }
}

impl LongEncryptedRecord {
    /// Create a new LongEncryptedRecord with the given encrypted long pseudonyms and attributes.
    pub fn new(
        pseudonyms: Vec<LongEncryptedPseudonym>,
        attributes: Vec<LongEncryptedAttribute>,
    ) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }
}

impl Encryptable for Record {
    type EncryptedType = EncryptedRecord;
    type PublicKeyType = SessionKeys;

    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = GlobalPublicKeys;

    fn encrypt<R>(&self, keys: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        EncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.encrypt(&keys.pseudonym.public, rng))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.encrypt(&keys.attribute.public, rng))
                .collect(),
        }
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        keys: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        EncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.encrypt_global(&keys.pseudonym, rng))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.encrypt_global(&keys.attribute, rng))
                .collect(),
        }
    }
}

impl Encrypted for EncryptedRecord {
    type UnencryptedType = Record;
    type SecretKeyType = SessionKeys;

    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = crate::keys::GlobalSecretKeys;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        let mut pseudonyms = Vec::with_capacity(self.pseudonyms.len());
        for p in &self.pseudonyms {
            pseudonyms.push(p.decrypt(&keys.pseudonym.secret)?);
        }

        let mut attributes = Vec::with_capacity(self.attributes.len());
        for a in &self.attributes {
            attributes.push(a.decrypt(&keys.attribute.secret)?);
        }

        Some(Record {
            pseudonyms,
            attributes,
        })
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Self::UnencryptedType {
        Record {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.decrypt(&keys.pseudonym.secret))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.decrypt(&keys.attribute.secret))
                .collect(),
        }
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(&self, keys: &Self::GlobalSecretKeyType) -> Option<Self::UnencryptedType> {
        let mut pseudonyms = Vec::with_capacity(self.pseudonyms.len());
        for p in &self.pseudonyms {
            pseudonyms.push(p.decrypt_global(&keys.pseudonym)?);
        }

        let mut attributes = Vec::with_capacity(self.attributes.len());
        for a in &self.attributes {
            attributes.push(a.decrypt_global(&keys.attribute)?);
        }

        Some(Record {
            pseudonyms,
            attributes,
        })
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, keys: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        Record {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.decrypt_global(&keys.pseudonym))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.decrypt_global(&keys.attribute))
                .collect(),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        EncryptedRecord {
            pseudonyms: self.pseudonyms.iter().map(|p| p.rerandomize(rng)).collect(),
            attributes: self.attributes.iter().map(|a| a.rerandomize(rng)).collect(),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(&self, keys: &SessionKeys, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        EncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.rerandomize(&keys.pseudonym.public, rng))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.rerandomize(&keys.attribute.public, rng))
                .collect(),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &crate::factors::RerandomizeFactor) -> Self {
        EncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.rerandomize_known(factor))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.rerandomize_known(factor))
                .collect(),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        keys: &SessionKeys,
        factor: &crate::factors::RerandomizeFactor,
    ) -> Self {
        EncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.rerandomize_known(&keys.pseudonym.public, factor))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.rerandomize_known(&keys.attribute.public, factor))
                .collect(),
        }
    }
}

impl Transcryptable for EncryptedRecord {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        EncryptedRecord {
            pseudonyms: self.pseudonyms.iter().map(|p| p.transcrypt(info)).collect(),
            attributes: self.attributes.iter().map(|a| a.transcrypt(info)).collect(),
        }
    }
}

impl Encryptable for LongRecord {
    type EncryptedType = LongEncryptedRecord;
    type PublicKeyType = SessionKeys;

    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = GlobalPublicKeys;

    fn encrypt<R>(&self, keys: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        LongEncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.encrypt(&keys.pseudonym.public, rng))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.encrypt(&keys.attribute.public, rng))
                .collect(),
        }
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        keys: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        LongEncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.encrypt_global(&keys.pseudonym, rng))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.encrypt_global(&keys.attribute, rng))
                .collect(),
        }
    }
}

// Implement Encrypted for LongEncryptedRecord
impl Encrypted for LongEncryptedRecord {
    type UnencryptedType = LongRecord;
    type SecretKeyType = SessionKeys;

    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = crate::keys::GlobalSecretKeys;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        let mut pseudonyms = Vec::with_capacity(self.pseudonyms.len());
        for p in &self.pseudonyms {
            pseudonyms.push(p.decrypt(&keys.pseudonym.secret)?);
        }

        let mut attributes = Vec::with_capacity(self.attributes.len());
        for a in &self.attributes {
            attributes.push(a.decrypt(&keys.attribute.secret)?);
        }

        Some(LongRecord {
            pseudonyms,
            attributes,
        })
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Self::UnencryptedType {
        LongRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.decrypt(&keys.pseudonym.secret))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.decrypt(&keys.attribute.secret))
                .collect(),
        }
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(&self, keys: &Self::GlobalSecretKeyType) -> Option<Self::UnencryptedType> {
        let mut pseudonyms = Vec::with_capacity(self.pseudonyms.len());
        for p in &self.pseudonyms {
            pseudonyms.push(p.decrypt_global(&keys.pseudonym)?);
        }

        let mut attributes = Vec::with_capacity(self.attributes.len());
        for a in &self.attributes {
            attributes.push(a.decrypt_global(&keys.attribute)?);
        }

        Some(LongRecord {
            pseudonyms,
            attributes,
        })
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, keys: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        LongRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.decrypt_global(&keys.pseudonym))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.decrypt_global(&keys.attribute))
                .collect(),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        LongEncryptedRecord {
            pseudonyms: self.pseudonyms.iter().map(|p| p.rerandomize(rng)).collect(),
            attributes: self.attributes.iter().map(|a| a.rerandomize(rng)).collect(),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(&self, keys: &SessionKeys, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        LongEncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.rerandomize(&keys.pseudonym.public, rng))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.rerandomize(&keys.attribute.public, rng))
                .collect(),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &crate::factors::RerandomizeFactor) -> Self {
        LongEncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.rerandomize_known(factor))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.rerandomize_known(factor))
                .collect(),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        keys: &SessionKeys,
        factor: &crate::factors::RerandomizeFactor,
    ) -> Self {
        LongEncryptedRecord {
            pseudonyms: self
                .pseudonyms
                .iter()
                .map(|p| p.rerandomize_known(&keys.pseudonym.public, factor))
                .collect(),
            attributes: self
                .attributes
                .iter()
                .map(|a| a.rerandomize_known(&keys.attribute.public, factor))
                .collect(),
        }
    }
}

impl Transcryptable for LongEncryptedRecord {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        LongEncryptedRecord {
            pseudonyms: self.pseudonyms.iter().map(|p| p.transcrypt(info)).collect(),
            attributes: self.attributes.iter().map(|a| a.transcrypt(info)).collect(),
        }
    }
}

impl HasStructure for EncryptedRecord {
    type Structure = RecordStructure;

    fn structure(&self) -> Self::Structure {
        RecordStructure {
            num_pseudonyms: self.pseudonyms.len(),
            num_attributes: self.attributes.len(),
        }
    }
}

impl HasStructure for LongEncryptedRecord {
    type Structure = LongRecordStructure;

    fn structure(&self) -> Self::Structure {
        LongRecordStructure {
            pseudonym_blocks: self.pseudonyms.iter().map(|p| p.0.len()).collect(),
            attribute_blocks: self.attributes.iter().map(|a| a.0.len()).collect(),
        }
    }
}

// Verifiable transcryption

/// Proof bundle for verifiable transcryption of a simple record.
///
/// Contains proofs for both pseudonymization and attribute rekeying.
#[cfg(feature = "verifiable")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordTranscryptionProof {
    /// Operation proofs for each pseudonym (RSK proofs)
    pub pseudonym_operation_proofs: Vec<VerifiableRSK>,
    /// Shared factors proof for all pseudonyms
    pub pseudonym_factors_proof: RSKFactorsProof,
    /// Operation proofs for each attribute (Rekey proofs)
    pub attribute_operation_proofs: Vec<VerifiableRekey>,
}

/// Proof bundle for verifiable transcryption of a long record.
///
/// Contains proofs for both pseudonymization and attribute rekeying,
/// with multiple proofs per long pseudonym/attribute (one per block).
#[cfg(feature = "verifiable")]
#[cfg(feature = "long")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongRecordTranscryptionProof {
    /// Operation proofs for each long pseudonym (vectors of RSK proofs)
    pub pseudonym_operation_proofs: Vec<Vec<VerifiableRSK>>,
    /// Shared factors proof for all pseudonyms
    pub pseudonym_factors_proof: RSKFactorsProof,
    /// Operation proofs for each long attribute (vectors of Rekey proofs)
    pub attribute_operation_proofs: Vec<Vec<VerifiableRekey>>,
}

#[cfg(feature = "verifiable")]
impl VerifiableTranscryptable for EncryptedRecord {
    type TranscryptionProof = RecordTranscryptionProof;

    fn verifiable_transcrypt<R: RngCore + CryptoRng>(
        &self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Self::TranscryptionProof {
        use crate::data::traits::{VerifiablePseudonymizable, VerifiableRekeyable};

        let mut pseudonym_operation_proofs = Vec::with_capacity(self.pseudonyms.len());

        // Generate proofs for all pseudonyms
        for pseudonym in &self.pseudonyms {
            let operation_proof = pseudonym.verifiable_pseudonymize(&info.pseudonym, rng);
            pseudonym_operation_proofs.push(operation_proof);
        }

        // Generate shared factors proof once (not message-specific)
        let pseudonym_factors_proof =
            RSKFactorsProof::new(&info.pseudonym.s.0, &info.pseudonym.k.0, rng);

        // Generate proofs for all attributes
        let mut attribute_operation_proofs = Vec::with_capacity(self.attributes.len());
        for attribute in &self.attributes {
            let operation_proof = attribute.verifiable_rekey(&info.attribute, rng);
            attribute_operation_proofs.push(operation_proof);
        }

        RecordTranscryptionProof {
            pseudonym_operation_proofs,
            pseudonym_factors_proof,
            attribute_operation_proofs,
        }
    }
}

#[cfg(feature = "verifiable")]
#[cfg(feature = "long")]
impl VerifiableTranscryptable for LongEncryptedRecord {
    type TranscryptionProof = LongRecordTranscryptionProof;

    fn verifiable_transcrypt<R: RngCore + CryptoRng>(
        &self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Self::TranscryptionProof {
        use crate::data::traits::{VerifiablePseudonymizable, VerifiableRekeyable};

        let mut pseudonym_operation_proofs = Vec::with_capacity(self.pseudonyms.len());

        // Generate proofs for all long pseudonyms (returns Vec<VerifiableRSK> per pseudonym)
        for pseudonym in &self.pseudonyms {
            let operation_proofs = pseudonym.verifiable_pseudonymize(&info.pseudonym, rng);
            pseudonym_operation_proofs.push(operation_proofs);
        }

        // Generate shared factors proof once (not message-specific)
        let pseudonym_factors_proof =
            RSKFactorsProof::new(&info.pseudonym.s.0, &info.pseudonym.k.0, rng);

        // Generate proofs for all long attributes (returns Vec<VerifiableRekey> per attribute)
        let mut attribute_operation_proofs = Vec::with_capacity(self.attributes.len());
        for attribute in &self.attributes {
            let operation_proofs = attribute.verifiable_rekey(&info.attribute, rng);
            attribute_operation_proofs.push(operation_proofs);
        }

        LongRecordTranscryptionProof {
            pseudonym_operation_proofs,
            pseudonym_factors_proof,
            attribute_operation_proofs,
        }
    }
}
