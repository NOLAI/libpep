//! Encryption, decryption and transcryption of [`PepJsonValue`] and [`EncryptedPepJsonValue`]:
//! the [`Encryptable`], [`Encrypted`] and [`Transcryptable`] impls.

use crate::data::json::data::{EncryptedPepJsonValue, PepJsonValue};
use crate::data::traits::{Encryptable, Encrypted, Transcryptable};
use crate::factors::types::{RerandomizeFactor, TranscryptionInfo};
use crate::group::InvertibleEncoding;
#[cfg(feature = "offline")]
use crate::keys::types::GlobalPublicKeys;
#[cfg(all(feature = "offline", feature = "insecure"))]
use crate::keys::types::GlobalSecretKeys;
use crate::keys::types::{SessionKeys, SessionPublicKeys};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "elgamal3")]
use std::collections::BTreeMap;

impl<G: InvertibleEncoding> Encryptable for PepJsonValue<G> {
    type Group = G;
    type EncryptedType = EncryptedPepJsonValue<G>;
    type PublicKeyType = SessionPublicKeys<G>;

    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = GlobalPublicKeys<G>;

    fn encrypt<R: Rng + CryptoRng>(
        &self,
        keys: &Self::PublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType {
        match self {
            PepJsonValue::Null => EncryptedPepJsonValue::Null,
            PepJsonValue::Bool(attr) => {
                EncryptedPepJsonValue::Bool(attr.encrypt(&keys.attribute, rng))
            }
            PepJsonValue::Number(attr) => {
                EncryptedPepJsonValue::Number(attr.encrypt(&keys.attribute, rng))
            }
            PepJsonValue::String(attr) => {
                EncryptedPepJsonValue::String(attr.encrypt(&keys.attribute, rng))
            }
            PepJsonValue::LongString(long_attr) => {
                EncryptedPepJsonValue::LongString(long_attr.encrypt(&keys.attribute, rng))
            }
            PepJsonValue::Pseudonym(pseudo) => {
                EncryptedPepJsonValue::Pseudonym(pseudo.encrypt(&keys.pseudonym, rng))
            }
            PepJsonValue::LongPseudonym(long_pseudo) => {
                EncryptedPepJsonValue::LongPseudonym(long_pseudo.encrypt(&keys.pseudonym, rng))
            }
            PepJsonValue::Array(arr) => EncryptedPepJsonValue::Array(
                arr.iter().map(|item| item.encrypt(keys, rng)).collect(),
            ),
            PepJsonValue::Object(obj) => EncryptedPepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.encrypt(keys, rng)))
                    .collect(),
            ),
        }
    }
    #[cfg(feature = "offline")]
    fn encrypt_global<R: Rng + CryptoRng>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType {
        match self {
            PepJsonValue::Null => EncryptedPepJsonValue::Null,
            PepJsonValue::Bool(attr) => {
                EncryptedPepJsonValue::Bool(attr.encrypt_global(&public_key.attribute, rng))
            }
            PepJsonValue::Number(attr) => {
                EncryptedPepJsonValue::Number(attr.encrypt_global(&public_key.attribute, rng))
            }
            PepJsonValue::String(attr) => {
                EncryptedPepJsonValue::String(attr.encrypt_global(&public_key.attribute, rng))
            }
            PepJsonValue::LongString(long_attr) => EncryptedPepJsonValue::LongString(
                long_attr.encrypt_global(&public_key.attribute, rng),
            ),
            PepJsonValue::Pseudonym(pseudo) => {
                EncryptedPepJsonValue::Pseudonym(pseudo.encrypt_global(&public_key.pseudonym, rng))
            }
            PepJsonValue::LongPseudonym(long_pseudo) => EncryptedPepJsonValue::LongPseudonym(
                long_pseudo.encrypt_global(&public_key.pseudonym, rng),
            ),
            PepJsonValue::Array(arr) => EncryptedPepJsonValue::Array(
                arr.iter()
                    .map(|item| item.encrypt_global(public_key, rng))
                    .collect(),
            ),
            PepJsonValue::Object(obj) => EncryptedPepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.encrypt_global(public_key, rng)))
                    .collect(),
            ),
        }
    }
}

impl<G: InvertibleEncoding> Encrypted for EncryptedPepJsonValue<G> {
    type Group = G;
    type UnencryptedType = PepJsonValue<G>;
    type SecretKeyType = SessionKeys<G>;

    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = GlobalSecretKeys<G>;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        match self {
            EncryptedPepJsonValue::Null => Some(PepJsonValue::Null),
            EncryptedPepJsonValue::Bool(enc) => {
                Some(PepJsonValue::Bool(enc.decrypt(&keys.attribute.secret)?))
            }
            EncryptedPepJsonValue::Number(enc) => {
                Some(PepJsonValue::Number(enc.decrypt(&keys.attribute.secret)?))
            }
            EncryptedPepJsonValue::String(enc) => {
                Some(PepJsonValue::String(enc.decrypt(&keys.attribute.secret)?))
            }
            EncryptedPepJsonValue::LongString(enc) => Some(PepJsonValue::LongString(
                enc.decrypt(&keys.attribute.secret)?,
            )),
            EncryptedPepJsonValue::Pseudonym(enc) => Some(PepJsonValue::Pseudonym(
                enc.decrypt(&keys.pseudonym.secret)?,
            )),
            EncryptedPepJsonValue::LongPseudonym(enc) => Some(PepJsonValue::LongPseudonym(
                enc.decrypt(&keys.pseudonym.secret)?,
            )),
            EncryptedPepJsonValue::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(item.decrypt(keys)?);
                }
                Some(PepJsonValue::Array(out))
            }
            EncryptedPepJsonValue::Object(obj) => {
                let mut out = BTreeMap::new();
                for (k, v) in obj {
                    out.insert(k.clone(), v.decrypt(keys)?);
                }
                Some(PepJsonValue::Object(out))
            }
        }
    }
    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, keys: &Self::SecretKeyType) -> Self::UnencryptedType {
        match self {
            EncryptedPepJsonValue::Null => PepJsonValue::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                PepJsonValue::Bool(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPepJsonValue::Number(enc) => {
                PepJsonValue::Number(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPepJsonValue::String(enc) => {
                PepJsonValue::String(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                PepJsonValue::LongString(enc.decrypt(&keys.attribute.secret))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                PepJsonValue::Pseudonym(enc.decrypt(&keys.pseudonym.secret))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => {
                PepJsonValue::LongPseudonym(enc.decrypt(&keys.pseudonym.secret))
            }
            EncryptedPepJsonValue::Array(arr) => {
                PepJsonValue::Array(arr.iter().map(|x| x.decrypt(keys)).collect())
            }
            EncryptedPepJsonValue::Object(obj) => PepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.decrypt(keys)))
                    .collect(),
            ),
        }
    }

    // Global decryption for offline+insecure+elgamal3
    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        match self {
            EncryptedPepJsonValue::Null => Some(PepJsonValue::Null),
            EncryptedPepJsonValue::Bool(enc) => Some(PepJsonValue::Bool(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPepJsonValue::Number(enc) => Some(PepJsonValue::Number(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPepJsonValue::String(enc) => Some(PepJsonValue::String(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPepJsonValue::LongString(enc) => Some(PepJsonValue::LongString(
                enc.decrypt_global(&secret_key.attribute)?,
            )),
            EncryptedPepJsonValue::Pseudonym(enc) => Some(PepJsonValue::Pseudonym(
                enc.decrypt_global(&secret_key.pseudonym)?,
            )),
            EncryptedPepJsonValue::LongPseudonym(enc) => Some(PepJsonValue::LongPseudonym(
                enc.decrypt_global(&secret_key.pseudonym)?,
            )),
            EncryptedPepJsonValue::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(item.decrypt_global(secret_key)?);
                }
                Some(PepJsonValue::Array(out))
            }
            EncryptedPepJsonValue::Object(obj) => {
                let mut out = BTreeMap::new();
                for (k, v) in obj {
                    out.insert(k.clone(), v.decrypt_global(secret_key)?);
                }
                Some(PepJsonValue::Object(out))
            }
        }
    }

    // Global decryption for offline+insecure (no elgamal3)
    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        match self {
            EncryptedPepJsonValue::Null => PepJsonValue::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                PepJsonValue::Bool(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPepJsonValue::Number(enc) => {
                PepJsonValue::Number(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPepJsonValue::String(enc) => {
                PepJsonValue::String(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                PepJsonValue::LongString(enc.decrypt_global(&secret_key.attribute))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                PepJsonValue::Pseudonym(enc.decrypt_global(&secret_key.pseudonym))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => {
                PepJsonValue::LongPseudonym(enc.decrypt_global(&secret_key.pseudonym))
            }
            EncryptedPepJsonValue::Array(arr) => {
                PepJsonValue::Array(arr.iter().map(|x| x.decrypt_global(secret_key)).collect())
            }
            EncryptedPepJsonValue::Object(obj) => PepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.decrypt_global(secret_key)))
                    .collect(),
            ),
        }
    }

    /// Every leaf gets its own factor: with one factor the differences between the leaves
    /// would survive transcryption and link the document to its input.
    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        match self {
            EncryptedPepJsonValue::Null => EncryptedPepJsonValue::Null,
            EncryptedPepJsonValue::Bool(enc) => EncryptedPepJsonValue::Bool(enc.rerandomize(rng)),
            EncryptedPepJsonValue::Number(enc) => {
                EncryptedPepJsonValue::Number(enc.rerandomize(rng))
            }
            EncryptedPepJsonValue::String(enc) => {
                EncryptedPepJsonValue::String(enc.rerandomize(rng))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                EncryptedPepJsonValue::LongString(enc.rerandomize(rng))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                EncryptedPepJsonValue::Pseudonym(enc.rerandomize(rng))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => {
                EncryptedPepJsonValue::LongPseudonym(enc.rerandomize(rng))
            }
            EncryptedPepJsonValue::Array(arr) => {
                EncryptedPepJsonValue::Array(arr.iter().map(|x| x.rerandomize(rng)).collect())
            }
            EncryptedPepJsonValue::Object(obj) => EncryptedPepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.rerandomize(rng)))
                    .collect(),
            ),
        }
    }

    /// Every leaf gets its own factor: with one factor the differences between the leaves
    /// would survive transcryption and link the document to its input.
    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        match self {
            EncryptedPepJsonValue::Null => EncryptedPepJsonValue::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                EncryptedPepJsonValue::Bool(enc.rerandomize(&public_key.attribute, rng))
            }
            EncryptedPepJsonValue::Number(enc) => {
                EncryptedPepJsonValue::Number(enc.rerandomize(&public_key.attribute, rng))
            }
            EncryptedPepJsonValue::String(enc) => {
                EncryptedPepJsonValue::String(enc.rerandomize(&public_key.attribute, rng))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                EncryptedPepJsonValue::LongString(enc.rerandomize(&public_key.attribute, rng))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                EncryptedPepJsonValue::Pseudonym(enc.rerandomize(&public_key.pseudonym, rng))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => {
                EncryptedPepJsonValue::LongPseudonym(enc.rerandomize(&public_key.pseudonym, rng))
            }
            EncryptedPepJsonValue::Array(arr) => EncryptedPepJsonValue::Array(
                arr.iter().map(|x| x.rerandomize(public_key, rng)).collect(),
            ),
            EncryptedPepJsonValue::Object(obj) => EncryptedPepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.rerandomize(public_key, rng)))
                    .collect(),
            ),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor<G>) -> Self {
        match self {
            EncryptedPepJsonValue::Null => EncryptedPepJsonValue::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                EncryptedPepJsonValue::Bool(enc.rerandomize_known(factor))
            }
            EncryptedPepJsonValue::Number(enc) => {
                EncryptedPepJsonValue::Number(enc.rerandomize_known(factor))
            }
            EncryptedPepJsonValue::String(enc) => {
                EncryptedPepJsonValue::String(enc.rerandomize_known(factor))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                EncryptedPepJsonValue::LongString(enc.rerandomize_known(factor))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                EncryptedPepJsonValue::Pseudonym(enc.rerandomize_known(factor))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => {
                EncryptedPepJsonValue::LongPseudonym(enc.rerandomize_known(factor))
            }
            EncryptedPepJsonValue::Array(arr) => EncryptedPepJsonValue::Array(
                arr.iter().map(|x| x.rerandomize_known(factor)).collect(),
            ),
            EncryptedPepJsonValue::Object(obj) => EncryptedPepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.rerandomize_known(factor)))
                    .collect(),
            ),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor<G>,
    ) -> Self {
        match self {
            EncryptedPepJsonValue::Null => EncryptedPepJsonValue::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                EncryptedPepJsonValue::Bool(enc.rerandomize_known(&public_key.attribute, factor))
            }
            EncryptedPepJsonValue::Number(enc) => {
                EncryptedPepJsonValue::Number(enc.rerandomize_known(&public_key.attribute, factor))
            }
            EncryptedPepJsonValue::String(enc) => {
                EncryptedPepJsonValue::String(enc.rerandomize_known(&public_key.attribute, factor))
            }
            EncryptedPepJsonValue::LongString(enc) => EncryptedPepJsonValue::LongString(
                enc.rerandomize_known(&public_key.attribute, factor),
            ),
            EncryptedPepJsonValue::Pseudonym(enc) => EncryptedPepJsonValue::Pseudonym(
                enc.rerandomize_known(&public_key.pseudonym, factor),
            ),
            EncryptedPepJsonValue::LongPseudonym(enc) => EncryptedPepJsonValue::LongPseudonym(
                enc.rerandomize_known(&public_key.pseudonym, factor),
            ),
            EncryptedPepJsonValue::Array(arr) => EncryptedPepJsonValue::Array(
                arr.iter()
                    .map(|x| x.rerandomize_known(public_key, factor))
                    .collect(),
            ),
            EncryptedPepJsonValue::Object(obj) => EncryptedPepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.rerandomize_known(public_key, factor)))
                    .collect(),
            ),
        }
    }
}

// Transcryption trait implementation for JSON

impl<G: InvertibleEncoding> Transcryptable for EncryptedPepJsonValue<G> {
    fn transcrypt_raw(&self, info: &TranscryptionInfo<G>) -> Self {
        match self {
            EncryptedPepJsonValue::Null => EncryptedPepJsonValue::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                EncryptedPepJsonValue::Bool(enc.transcrypt_raw(info))
            }
            EncryptedPepJsonValue::Number(enc) => {
                EncryptedPepJsonValue::Number(enc.transcrypt_raw(info))
            }
            EncryptedPepJsonValue::String(enc) => {
                EncryptedPepJsonValue::String(enc.transcrypt_raw(info))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                EncryptedPepJsonValue::LongString(enc.transcrypt_raw(info))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                EncryptedPepJsonValue::Pseudonym(enc.transcrypt_raw(info))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => {
                EncryptedPepJsonValue::LongPseudonym(enc.transcrypt_raw(info))
            }
            EncryptedPepJsonValue::Array(arr) => {
                EncryptedPepJsonValue::Array(arr.iter().map(|x| x.transcrypt_raw(info)).collect())
            }
            EncryptedPepJsonValue::Object(obj) => EncryptedPepJsonValue::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.transcrypt_raw(info)))
                    .collect(),
            ),
        }
    }
}

#[cfg(feature = "batch")]
impl<G: InvertibleEncoding> crate::data::traits::HasStructure for EncryptedPepJsonValue<G> {
    type Structure = crate::data::json::structure::JsonStructure;

    fn structure(&self) -> Self::Structure {
        self.structure()
    }
}
