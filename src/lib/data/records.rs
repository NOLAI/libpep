//! Record types for encrypting multiple pseudonyms and attributes together.
//!
//! A `Record` represents a collection of pseudonyms and attributes that belong to the same entity.
//! When encrypted, it becomes an `EncryptedRecord`.

use crate::data::simple::{
    Attribute, ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym, Pseudonym,
};
use crate::data::traits::{Encryptable, Encrypted, Transcryptable};
use crate::factors::TranscryptionInfo;
use crate::keys::{GlobalPublicKeys, SessionKeys};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Error, ErrorKind};

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
#[cfg(feature = "long")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongRecord {
    pub pseudonyms: Vec<LongPseudonym>,
    pub attributes: Vec<LongAttribute>,
}

/// An encrypted long record containing multiple encrypted long pseudonyms and attributes.
#[cfg(feature = "long")]
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

    /// Serializes an `EncryptedRecord` to a string.
    ///
    /// Individual items are base64-encoded and joined with `"|"`.
    /// Pseudonyms and attributes are separated by `";"`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use libpep::data::records::EncryptedRecord;
    ///
    /// let record = EncryptedRecord::new(vec![/* ... */], vec![/* ... */]);
    /// let serialized = record.serialize();
    /// ```
    pub fn serialize(&self) -> String {
        let pseudonyms = self
            .pseudonyms
            .iter()
            .map(|p| p.to_base64())
            .collect::<Vec<_>>()
            .join("|");
        let attributes = self
            .attributes
            .iter()
            .map(|a| a.to_base64())
            .collect::<Vec<_>>()
            .join("|");
        format!("{};{}", pseudonyms, attributes)
    }

    /// Deserializes an `EncryptedRecord` from a string.
    ///
    /// Expects the format produced by [`serialize`](Self::serialize):
    /// pseudonyms and attributes separated by `";"`, with individual items
    /// separated by `"|"`.
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid or any base64-encoded part cannot be decoded.
    pub fn deserialize(s: &str) -> Result<Self, Error> {
        let parts: Vec<&str> = s.splitn(2, ';').collect();
        if parts.len() != 2 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Expected pseudonyms and attributes separated by ';'",
            ));
        }

        let pseudonyms = if parts[0].is_empty() {
            vec![]
        } else {
            parts[0]
                .split('|')
                .map(|part| {
                    EncryptedPseudonym::from_base64(part).ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid base64 encoding: {}", part),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let attributes = if parts[1].is_empty() {
            vec![]
        } else {
            parts[1]
                .split('|')
                .map(|part| {
                    EncryptedAttribute::from_base64(part).ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!("Invalid base64 encoding: {}", part),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(EncryptedRecord {
            pseudonyms,
            attributes,
        })
    }
}

#[cfg(feature = "long")]
impl LongRecord {
    /// Create a new LongRecord with the given long pseudonyms and attributes.
    pub fn new(pseudonyms: Vec<LongPseudonym>, attributes: Vec<LongAttribute>) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }
}

#[cfg(feature = "long")]
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

    /// Serializes a `LongEncryptedRecord` to a string.
    ///
    /// Each long encrypted item is serialized using its own `serialize` method (which uses `"|"`).
    /// Items within the same group are separated by `"~"`.
    /// Pseudonyms and attributes groups are separated by `";"`.
    pub fn serialize(&self) -> String {
        let pseudonyms = self
            .pseudonyms
            .iter()
            .map(|p| p.serialize())
            .collect::<Vec<_>>()
            .join("~");
        let attributes = self
            .attributes
            .iter()
            .map(|a| a.serialize())
            .collect::<Vec<_>>()
            .join("~");
        format!("{};{}", pseudonyms, attributes)
    }

    /// Deserializes a `LongEncryptedRecord` from a string.
    ///
    /// Expects the format produced by [`serialize`](Self::serialize):
    /// pseudonyms and attributes separated by `";"`, with individual long items
    /// separated by `"~"`.
    ///
    /// # Errors
    ///
    /// Returns an error if the format is invalid or any part cannot be decoded.
    pub fn deserialize(s: &str) -> Result<Self, Error> {
        let parts: Vec<&str> = s.splitn(2, ';').collect();
        if parts.len() != 2 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Expected pseudonyms and attributes separated by ';'",
            ));
        }

        let pseudonyms = if parts[0].is_empty() {
            vec![]
        } else {
            parts[0]
                .split('~')
                .map(LongEncryptedPseudonym::deserialize)
                .collect::<Result<Vec<_>, _>>()?
        };

        let attributes = if parts[1].is_empty() {
            vec![]
        } else {
            parts[1]
                .split('~')
                .map(LongEncryptedAttribute::deserialize)
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(LongEncryptedRecord {
            pseudonyms,
            attributes,
        })
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

#[cfg(feature = "serde")]
impl Serialize for EncryptedRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for EncryptedRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "long")]
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
#[cfg(feature = "long")]
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

#[cfg(feature = "long")]
impl Transcryptable for LongEncryptedRecord {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        LongEncryptedRecord {
            pseudonyms: self.pseudonyms.iter().map(|p| p.transcrypt(info)).collect(),
            attributes: self.attributes.iter().map(|a| a.transcrypt(info)).collect(),
        }
    }
}

#[cfg(all(feature = "serde", feature = "long"))]
impl Serialize for LongEncryptedRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialize())
    }
}

#[cfg(all(feature = "serde", feature = "long"))]
impl<'de> Deserialize<'de> for LongEncryptedRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::deserialize(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "batch")]
impl HasStructure for EncryptedRecord {
    type Structure = RecordStructure;

    fn structure(&self) -> Self::Structure {
        RecordStructure {
            num_pseudonyms: self.pseudonyms.len(),
            num_attributes: self.attributes.len(),
        }
    }
}

#[cfg(all(feature = "batch", feature = "long"))]
impl HasStructure for LongEncryptedRecord {
    type Structure = LongRecordStructure;

    fn structure(&self) -> Self::Structure {
        LongRecordStructure {
            pseudonym_blocks: self.pseudonyms.iter().map(|p| p.0.len()).collect(),
            attribute_blocks: self.attributes.iter().map(|a| a.0.len()).collect(),
        }
    }
}
