//! Record types generic over the [`Group`].

#[cfg(feature = "long")]
use crate::data::long::generic::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
#[cfg(feature = "long")]
use crate::data::padding::PaddingError;
#[cfg(feature = "long")]
use crate::data::records::LongRecordStructure;
#[cfg(feature = "batch")]
use crate::data::records::RecordStructure;
use crate::data::simple::generic::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use crate::data::simple::ElGamalEncrypted;
#[cfg(feature = "batch")]
use crate::data::traits::HasStructure;
use crate::data::traits::{Encryptable, Encrypted, Transcryptable};
use crate::elgamal::arithmetic::group::Group;
#[cfg(feature = "long")]
use crate::elgamal::arithmetic::group::InvertibleEncoding;
use crate::errors::ParseError;
use crate::factors::types::generic::{RerandomizeFactor, TranscryptionInfo};
#[cfg(feature = "offline")]
use crate::keys::types::generic::GlobalPublicKeys;
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::generic::GlobalSecretKeys;
use crate::keys::types::generic::{SessionKeys, SessionPublicKeys};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The pseudonyms and attributes of one entity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<G: Group> {
    /// The pseudonyms of the entity.
    pub pseudonyms: Vec<Pseudonym<G>>,
    /// The attributes of the entity.
    pub attributes: Vec<Attribute<G>>,
}

/// An encrypted [`Record`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord<G: Group> {
    /// The encrypted pseudonyms.
    pub pseudonyms: Vec<EncryptedPseudonym<G>>,
    /// The encrypted attributes.
    pub attributes: Vec<EncryptedAttribute<G>>,
}

/// The long pseudonyms and long attributes of one entity.
#[cfg(feature = "long")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongRecord<G: Group> {
    /// The pseudonyms of the entity.
    pub pseudonyms: Vec<LongPseudonym<G>>,
    /// The attributes of the entity.
    pub attributes: Vec<LongAttribute<G>>,
}

/// An encrypted [`LongRecord`].
#[cfg(feature = "long")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongEncryptedRecord<G: Group> {
    /// The encrypted pseudonyms.
    pub pseudonyms: Vec<LongEncryptedPseudonym<G>>,
    /// The encrypted attributes.
    pub attributes: Vec<LongEncryptedAttribute<G>>,
}

/// The constructors, encryption, decryption, rerandomization and transcryption of a record pair:
/// every operation applies to the pseudonyms with the pseudonym key and to the attributes with
/// the attribute key.
macro_rules! impl_record_pair {
    ($plain:ident / $enc:ident, $p:ident / $a:ident, $ep:ident / $ea:ident) => {
        impl<G: Group> $plain<G> {
            /// A record with the given pseudonyms and attributes.
            pub fn new(pseudonyms: Vec<$p<G>>, attributes: Vec<$a<G>>) -> Self {
                Self {
                    pseudonyms,
                    attributes,
                }
            }
        }

        impl<G: Group> $enc<G> {
            /// An encrypted record with the given encrypted pseudonyms and attributes.
            pub fn new(pseudonyms: Vec<$ep<G>>, attributes: Vec<$ea<G>>) -> Self {
                Self {
                    pseudonyms,
                    attributes,
                }
            }
        }

        impl<G: Group> Encryptable for $plain<G> {
            type Group = G;
            type EncryptedType = $enc<G>;
            type PublicKeyType = SessionPublicKeys<G>;
            #[cfg(feature = "offline")]
            type GlobalPublicKeyType = GlobalPublicKeys<G>;

            fn encrypt<R>(&self, keys: &SessionPublicKeys<G>, rng: &mut R) -> $enc<G>
            where
                R: Rng + CryptoRng,
            {
                $enc {
                    pseudonyms: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.encrypt(&keys.pseudonym, rng))
                        .collect(),
                    attributes: self
                        .attributes
                        .iter()
                        .map(|a| a.encrypt(&keys.attribute, rng))
                        .collect(),
                }
            }

            #[cfg(feature = "offline")]
            fn encrypt_global<R>(&self, keys: &GlobalPublicKeys<G>, rng: &mut R) -> $enc<G>
            where
                R: Rng + CryptoRng,
            {
                $enc {
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

        impl<G: Group> Encrypted for $enc<G> {
            type Group = G;
            type UnencryptedType = $plain<G>;
            type SecretKeyType = SessionKeys<G>;
            #[cfg(all(feature = "offline", feature = "insecure"))]
            type GlobalSecretKeyType = GlobalSecretKeys<G>;

            #[cfg(feature = "elgamal3")]
            fn decrypt(&self, keys: &SessionKeys<G>) -> Option<$plain<G>> {
                Some($plain {
                    pseudonyms: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.decrypt(&keys.pseudonym.secret))
                        .collect::<Option<_>>()?,
                    attributes: self
                        .attributes
                        .iter()
                        .map(|a| a.decrypt(&keys.attribute.secret))
                        .collect::<Option<_>>()?,
                })
            }

            #[cfg(not(feature = "elgamal3"))]
            fn decrypt(&self, keys: &SessionKeys<G>) -> $plain<G> {
                $plain {
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
            fn decrypt_global(&self, keys: &GlobalSecretKeys<G>) -> Option<$plain<G>> {
                Some($plain {
                    pseudonyms: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.decrypt_global(&keys.pseudonym))
                        .collect::<Option<_>>()?,
                    attributes: self
                        .attributes
                        .iter()
                        .map(|a| a.decrypt_global(&keys.attribute))
                        .collect::<Option<_>>()?,
                })
            }

            #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
            fn decrypt_global(&self, keys: &GlobalSecretKeys<G>) -> $plain<G> {
                $plain {
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
                R: Rng + CryptoRng,
            {
                Self {
                    pseudonyms: self.pseudonyms.iter().map(|p| p.rerandomize(rng)).collect(),
                    attributes: self.attributes.iter().map(|a| a.rerandomize(rng)).collect(),
                }
            }

            #[cfg(not(feature = "elgamal3"))]
            fn rerandomize<R>(&self, keys: &SessionPublicKeys<G>, rng: &mut R) -> Self
            where
                R: Rng + CryptoRng,
            {
                Self {
                    pseudonyms: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.rerandomize(&keys.pseudonym, rng))
                        .collect(),
                    attributes: self
                        .attributes
                        .iter()
                        .map(|a| a.rerandomize(&keys.attribute, rng))
                        .collect(),
                }
            }

            #[cfg(feature = "elgamal3")]
            fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
                Self {
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
                keys: &SessionPublicKeys<G>,
                factor: &RerandomizeFactor<G>,
            ) -> Self {
                Self {
                    pseudonyms: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.rerandomize_known(&keys.pseudonym, factor))
                        .collect(),
                    attributes: self
                        .attributes
                        .iter()
                        .map(|a| a.rerandomize_known(&keys.attribute, factor))
                        .collect(),
                }
            }
        }

        impl<G: Group> Transcryptable for $enc<G> {
            fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
                Self {
                    pseudonyms: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.transcrypt_raw(info))
                        .collect(),
                    attributes: self
                        .attributes
                        .iter()
                        .map(|a| a.transcrypt_raw(info))
                        .collect(),
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<G: Group> Serialize for $enc<G> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.serialize())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, G: Group> Deserialize<'de> for $enc<G> {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::deserialize(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_record_pair!(
    Record / EncryptedRecord,
    Pseudonym / Attribute,
    EncryptedPseudonym / EncryptedAttribute
);
#[cfg(feature = "long")]
impl_record_pair!(
    LongRecord / LongEncryptedRecord,
    LongPseudonym / LongAttribute,
    LongEncryptedPseudonym / LongEncryptedAttribute
);

/// Split the string encoding of a record into its pseudonym and attribute parts.
fn split_record(s: &str) -> Result<(&str, &str), ParseError> {
    s.split_once(';').ok_or(ParseError::MissingSeparator)
}

/// Parse the items of one part of a record, separated by `sep`; the empty part has no items.
fn parse_items<T>(
    part: &str,
    sep: char,
    parse: impl Fn(&str) -> Result<T, ParseError>,
) -> Result<Vec<T>, ParseError> {
    if part.is_empty() {
        return Ok(vec![]);
    }
    part.split(sep).map(parse).collect()
}

impl<G: Group> EncryptedRecord<G> {
    /// Encode as the base64 encodings of the pseudonyms joined with `|`, a `;`, and those of
    /// the attributes joined with `|`.
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
        format!("{pseudonyms};{attributes}")
    }

    /// Decode the format of [`serialize`](Self::serialize).
    ///
    /// # Errors
    ///
    /// Returns an error if the separator is missing or a part is not a base64-encoded
    /// ciphertext.
    pub fn deserialize(s: &str) -> Result<Self, ParseError> {
        let (pseudonyms, attributes) = split_record(s)?;
        Ok(Self {
            pseudonyms: parse_items(pseudonyms, '|', |part| {
                EncryptedPseudonym::from_base64(part)
                    .ok_or_else(|| ParseError::InvalidCiphertext(part.to_string()))
            })?,
            attributes: parse_items(attributes, '|', |part| {
                EncryptedAttribute::from_base64(part)
                    .ok_or_else(|| ParseError::InvalidCiphertext(part.to_string()))
            })?,
        })
    }
}

#[cfg(feature = "long")]
impl<G: Group> LongEncryptedRecord<G> {
    /// Encode as the encodings of the long pseudonyms (see
    /// [`LongEncryptedPseudonym::serialize`]) joined with `~`, a `;`, and those of the long
    /// attributes joined with `~`.
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
        format!("{pseudonyms};{attributes}")
    }

    /// Decode the format of [`serialize`](Self::serialize).
    ///
    /// # Errors
    ///
    /// Returns an error if the separator is missing or a part is not a base64-encoded
    /// ciphertext.
    pub fn deserialize(s: &str) -> Result<Self, ParseError> {
        let (pseudonyms, attributes) = split_record(s)?;
        Ok(Self {
            pseudonyms: parse_items(pseudonyms, '~', LongEncryptedPseudonym::deserialize)?,
            attributes: parse_items(attributes, '~', LongEncryptedAttribute::deserialize)?,
        })
    }
}

#[cfg(feature = "long")]
impl<G: InvertibleEncoding> LongRecord<G> {
    /// Pad every pseudonym and attribute with external padding blocks to the block counts of
    /// `structure`, so that records in a batch share one structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the numbers of pseudonyms or attributes differ from the structure,
    /// or a value has more blocks than the structure allows.
    pub fn pad_to(&self, structure: &LongRecordStructure) -> Result<Self, PaddingError> {
        if self.pseudonyms.len() != structure.pseudonym_blocks.len() {
            return Err(PaddingError::CountMismatch {
                current: self.pseudonyms.len(),
                target: structure.pseudonym_blocks.len(),
            });
        }
        if self.attributes.len() != structure.attribute_blocks.len() {
            return Err(PaddingError::CountMismatch {
                current: self.attributes.len(),
                target: structure.attribute_blocks.len(),
            });
        }
        Ok(Self {
            pseudonyms: self
                .pseudonyms
                .iter()
                .zip(&structure.pseudonym_blocks)
                .map(|(p, &blocks)| p.pad_to(blocks))
                .collect::<Result<_, _>>()?,
            attributes: self
                .attributes
                .iter()
                .zip(&structure.attribute_blocks)
                .map(|(a, &blocks)| a.pad_to(blocks))
                .collect::<Result<_, _>>()?,
        })
    }

    /// The number of blocks of every pseudonym and attribute.
    pub fn structure(&self) -> LongRecordStructure {
        LongRecordStructure {
            pseudonym_blocks: self.pseudonyms.iter().map(|p| p.0.len()).collect(),
            attribute_blocks: self.attributes.iter().map(|a| a.0.len()).collect(),
        }
    }
}

#[cfg(feature = "batch")]
impl<G: Group> HasStructure for EncryptedRecord<G> {
    type Structure = RecordStructure;

    fn structure(&self) -> Self::Structure {
        RecordStructure {
            num_pseudonyms: self.pseudonyms.len(),
            num_attributes: self.attributes.len(),
        }
    }
}

#[cfg(all(feature = "batch", feature = "long"))]
impl<G: Group> HasStructure for LongEncryptedRecord<G> {
    type Structure = LongRecordStructure;

    fn structure(&self) -> Self::Structure {
        LongRecordStructure {
            pseudonym_blocks: self.pseudonyms.iter().map(|p| p.0.len()).collect(),
            attribute_blocks: self.attributes.iter().map(|a| a.0.len()).collect(),
        }
    }
}
