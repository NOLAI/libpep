//! Record types for encrypting multiple pseudonyms and attributes together.
//!
//! A `Record` represents a collection of pseudonyms and attributes that belong to the same entity.
//! When encrypted, it becomes an `EncryptedRecord`.

use crate::core::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::core::data::traits::{Encryptable, Encrypted, Transcryptable};
use crate::core::factors::TranscryptionInfo;
use crate::core::keys::{GlobalPublicKeys, SessionKeys};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "long")]
use crate::core::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};

#[cfg(feature = "batch")]
use crate::core::batch::HasStructure;

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
    type GlobalSecretKeyType = crate::core::keys::GlobalSecretKeys;

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
    fn rerandomize_known(&self, factor: &crate::core::factors::RerandomizeFactor) -> Self {
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
        factor: &crate::core::factors::RerandomizeFactor,
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
    type GlobalSecretKeyType = crate::core::keys::GlobalSecretKeys;

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
    fn rerandomize_known(&self, factor: &crate::core::factors::RerandomizeFactor) -> Self {
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
        factor: &crate::core::factors::RerandomizeFactor,
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
