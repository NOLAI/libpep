//! Core data types for pseudonyms and attributes, their encrypted versions,
//! and session-key based encryption and decryption operations.

use crate::arithmetic::group_elements::GroupElement;
use crate::base::elgamal::{ElGamal, ELGAMAL_LENGTH};
use crate::core::keys::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A pseudonym (in the background, this is a [`GroupElement`]) that can be used to identify a user
/// within a specific context, which can be encrypted, rekeyed and reshuffled.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct Pseudonym {
    pub value: GroupElement,
}
/// An attribute (in the background, this is a [`GroupElement`]), which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct Attribute {
    pub value: GroupElement,
}
/// An encrypted pseudonym, which is an [`ElGamal`] encryption of a [`Pseudonym`].
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
/// An encrypted attribute, which is an [`ElGamal`] encryption of an [`Attribute`].
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedAttribute {
    pub value: ElGamal,
}

#[cfg(feature = "serde")]
impl Serialize for EncryptedAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for EncryptedAttribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ElGamal::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

#[cfg(feature = "serde")]
impl Serialize for EncryptedPseudonym {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for EncryptedPseudonym {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ElGamal::deserialize(deserializer)?;
        Ok(Self { value })
    }
}

/// A trait for encrypted data types, that can be encrypted and decrypted from and into [`Encryptable`] types.
pub trait Encrypted {
    type UnencryptedType: Encryptable;
    /// Get the [ElGamal] ciphertext value.
    fn value(&self) -> &ElGamal;
    /// Create from an [ElGamal] ciphertext.
    fn from_value(value: ElGamal) -> Self
    where
        Self: Sized;
    /// Encode as a byte array.
    fn to_bytes(&self) -> [u8; ELGAMAL_LENGTH] {
        self.value().to_bytes()
    }
    /// Decode from a byte array.
    fn from_bytes(v: &[u8; ELGAMAL_LENGTH]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_bytes(v).map(|x| Self::from_value(x))
    }
    /// Decode from a slice of bytes.
    fn from_slice(v: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_slice(v).map(|x| Self::from_value(x))
    }
    /// Encode as a base64 string.
    fn to_base64(&self) -> String {
        self.value().to_base64()
    }
    /// Decode from a base64 string.
    /// Returns `None` if the input is not a valid base64 encoding of an [ElGamal] ciphertext.
    fn from_base64(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_base64(s).map(|x| Self::from_value(x))
    }
}

/// A trait for encryptable data types, that can be encrypted and decrypted from and into
/// [`Encrypted`] types, and have several ways to encode and decode them.
pub trait Encryptable {
    type EncryptedType: Encrypted;
    fn value(&self) -> &GroupElement;
    fn from_value(value: GroupElement) -> Self
    where
        Self: Sized;

    /// Create from a [`GroupElement`].
    fn from_point(value: GroupElement) -> Self
    where
        Self: Sized,
    {
        Self::from_value(value)
    }

    /// Create with a random value.
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self
    where
        Self: Sized,
    {
        Self::from_point(GroupElement::random(rng))
    }
    /// Encode as a byte array of length 32.
    /// See [`GroupElement::to_bytes`].
    fn to_bytes(&self) -> [u8; 32] {
        self.value().to_bytes()
    }
    /// Convert to a hexadecimal string of 64 characters.
    fn to_hex(&self) -> String {
        self.value().to_hex()
    }
    /// Create from a byte array of length 32.
    /// Returns `None` if the input is not a valid encoding of a [`GroupElement`].
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::from_bytes(bytes).map(Self::from_point)
    }
    /// Create from a slice of bytes.
    /// Returns `None` if the input is not a valid encoding of a [`GroupElement`].
    fn from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::from_slice(slice).map(Self::from_point)
    }
    /// Create from a hexadecimal string.
    /// Returns `None` if the input is not a valid encoding of a [`GroupElement`].
    fn from_hex(hex: &str) -> Option<Self>
    where
        Self: Sized,
    {
        GroupElement::from_hex(hex).map(Self::from_point)
    }
    /// Create from a hash value.
    /// See [`GroupElement::from_hash`].
    fn from_hash(hash: &[u8; 64]) -> Self
    where
        Self: Sized,
    {
        Self::from_point(GroupElement::from_hash(hash))
    }
    /// Create from a byte array of length 16 using lizard encoding.
    /// This is useful for creating a pseudonym from an existing identifier or encoding attributes,
    /// as it accepts any 16-byte value.
    /// See [`GroupElement::from_lizard`].
    fn from_lizard(data: &[u8; 16]) -> Self
    where
        Self: Sized,
    {
        Self::from_point(GroupElement::from_lizard(data))
    }
    /// Encode as a byte array of length 16 using lizard encoding.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// See [`GroupElement::to_lizard`].
    /// If the value was created using [`Encryptable::from_lizard`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    fn to_lizard(&self) -> Option<[u8; 16]> {
        self.value().to_lizard()
    }
}

impl Encryptable for Pseudonym {
    type EncryptedType = EncryptedPseudonym;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}
impl Encryptable for Attribute {
    type EncryptedType = EncryptedAttribute;
    fn value(&self) -> &GroupElement {
        &self.value
    }
    fn from_value(value: GroupElement) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}

/// Trait that associates a type with its corresponding session key types.
/// This trait is implemented by both single-block types (Pseudonym, Attribute)
/// and multi-block types (LongPseudonym, LongAttribute).
pub trait HasSessionKeys {
    type SessionPublicKey: PublicKey;
    type SessionSecretKey: SecretKey;
}

/// Trait that associates an encryptable type with its corresponding global key types.
pub trait HasGlobalKeys: Encryptable {
    type GlobalPublicKey: PublicKey;
    type GlobalSecretKey: SecretKey;
}

impl HasSessionKeys for Pseudonym {
    type SessionPublicKey = PseudonymSessionPublicKey;
    type SessionSecretKey = PseudonymSessionSecretKey;
}

impl HasSessionKeys for Attribute {
    type SessionPublicKey = AttributeSessionPublicKey;
    type SessionSecretKey = AttributeSessionSecretKey;
}

impl HasGlobalKeys for Pseudonym {
    type GlobalPublicKey = PseudonymGlobalPublicKey;
    type GlobalSecretKey = PseudonymGlobalSecretKey;
}

impl HasGlobalKeys for Attribute {
    type GlobalPublicKey = AttributeGlobalPublicKey;
    type GlobalSecretKey = AttributeGlobalSecretKey;
}

impl Encrypted for EncryptedPseudonym {
    type UnencryptedType = Pseudonym;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}
impl Encrypted for EncryptedAttribute {
    type UnencryptedType = Attribute;
    fn value(&self) -> &ElGamal {
        &self.value
    }
    fn from_value(value: ElGamal) -> Self
    where
        Self: Sized,
    {
        Self { value }
    }
}

// Encryption and decryption operations

/// Polymorphic encrypt function that works for both pseudonyms and attributes.
/// Uses the appropriate session key type based on the message type.
pub fn encrypt<M, R>(message: &M, public_key: &M::SessionPublicKey, rng: &mut R) -> M::EncryptedType
where
    M: Encryptable + HasSessionKeys,
    R: RngCore + CryptoRng,
{
    M::EncryptedType::from_value(crate::base::elgamal::encrypt(
        message.value(),
        public_key.value(),
        rng,
    ))
}

/// Polymorphic decrypt function that works for both encrypted pseudonyms and attributes.
/// Uses the appropriate session key type based on the encrypted message type.
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
#[cfg(feature = "elgamal3")]
pub fn decrypt<E, S>(encrypted: &E, secret_key: &S) -> Option<E::UnencryptedType>
where
    E: Encrypted,
    E::UnencryptedType: HasSessionKeys<SessionSecretKey = S>,
    S: SecretKey,
{
    crate::base::elgamal::decrypt(encrypted.value(), secret_key.value())
        .map(E::UnencryptedType::from_value)
}

/// Polymorphic decrypt function that works for both encrypted pseudonyms and attributes.
/// Uses the appropriate session key type based on the encrypted message type.
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt<E, S>(encrypted: &E, secret_key: &S) -> E::UnencryptedType
where
    E: Encrypted,
    E::UnencryptedType: HasSessionKeys<SessionSecretKey = S>,
    S: SecretKey,
{
    E::UnencryptedType::from_value(crate::base::elgamal::decrypt(
        encrypted.value(),
        secret_key.value(),
    ))
}

/// Encrypt a pseudonym using a [`PseudonymSessionPublicKey`].
pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
    message: &Pseudonym,
    public_key: &PseudonymSessionPublicKey,
    rng: &mut R,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from_value(crate::base::elgamal::encrypt(
        message.value(),
        public_key.value(),
        rng,
    ))
}

/// Encrypt an attribute using a [`AttributeSessionPublicKey`].
pub fn encrypt_attribute<R: RngCore + CryptoRng>(
    message: &Attribute,
    public_key: &AttributeSessionPublicKey,
    rng: &mut R,
) -> EncryptedAttribute {
    EncryptedAttribute::from_value(crate::base::elgamal::encrypt(
        message.value(),
        public_key.value(),
        rng,
    ))
}

/// Decrypt an encrypted pseudonym using a [`PseudonymSessionSecretKey`].
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
#[cfg(feature = "elgamal3")]
pub fn decrypt_pseudonym(
    encrypted: &EncryptedPseudonym,
    secret_key: &PseudonymSessionSecretKey,
) -> Option<Pseudonym> {
    crate::base::elgamal::decrypt(encrypted.value(), &secret_key.0).map(Pseudonym::from_value)
}

/// Decrypt an encrypted pseudonym using a [`PseudonymSessionSecretKey`].
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt_pseudonym(
    encrypted: &EncryptedPseudonym,
    secret_key: &PseudonymSessionSecretKey,
) -> Pseudonym {
    Pseudonym::from_value(crate::base::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

/// Decrypt an encrypted attribute using a [`AttributeSessionSecretKey`].
/// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
#[cfg(feature = "elgamal3")]
pub fn decrypt_attribute(
    encrypted: &EncryptedAttribute,
    secret_key: &AttributeSessionSecretKey,
) -> Option<Attribute> {
    crate::base::elgamal::decrypt(encrypted.value(), &secret_key.0).map(Attribute::from_value)
}

/// Decrypt an encrypted attribute using a [`AttributeSessionSecretKey`].
#[cfg(not(feature = "elgamal3"))]
pub fn decrypt_attribute(
    encrypted: &EncryptedAttribute,
    secret_key: &AttributeSessionSecretKey,
) -> Attribute {
    Attribute::from_value(crate::base::elgamal::decrypt(
        encrypted.value(),
        &secret_key.0,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::transcryption::contexts::EncryptionContext;
    use crate::core::transcryption::secrets::EncryptionSecret;

    #[test]
    fn pseudonym_encode_decode() {
        let mut rng = rand::rng();
        let original = Pseudonym::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = Pseudonym::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn attribute_encode_decode() {
        let mut rng = rand::rng();
        let original = Attribute::random(&mut rng);
        let encoded = original.to_bytes();
        let decoded = Attribute::from_bytes(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn pseudonym_from_lizard_roundtrip() {
        let data = b"test identifier!";
        let pseudonym = Pseudonym::from_lizard(data);
        let decoded = pseudonym
            .to_lizard()
            .expect("lizard encoding should succeed");
        assert_eq!(decoded, *data);
    }

    #[test]
    fn attribute_from_lizard_roundtrip() {
        let data = b"some attribute!!";
        let attribute = Attribute::from_lizard(data);
        let decoded = attribute
            .to_lizard()
            .expect("lizard encoding should succeed");
        assert_eq!(decoded, *data);
    }

    #[test]
    fn pseudonym_hex_roundtrip() {
        let mut rng = rand::rng();
        let original = Pseudonym::random(&mut rng);
        let hex = original.to_hex();
        let decoded = Pseudonym::from_hex(&hex).expect("hex decoding should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn encrypt_decrypt_pseudonym() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

        let original = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt_pseudonym(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_pseudonym(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_decrypt_attribute() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_attribute_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_attribute_session_keys(&global_secret, &session, &enc_secret);

        let original = Attribute::random(&mut rng);
        let encrypted = encrypt_attribute(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted =
            decrypt_attribute(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt_attribute(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypted_pseudonym_base64_roundtrip() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, _) =
            make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

        let pseudonym = Pseudonym::random(&mut rng);
        let encrypted = encrypt_pseudonym(&pseudonym, &session_public, &mut rng);
        let base64 = encrypted.to_base64();
        let decoded =
            EncryptedPseudonym::from_base64(&base64).expect("base64 decoding should succeed");

        assert_eq!(decoded, encrypted);
    }

    #[test]
    fn encrypted_attribute_serde_json() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_attribute_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, _) =
            make_attribute_session_keys(&global_secret, &session, &enc_secret);

        let attribute = Attribute::random(&mut rng);
        let encrypted = encrypt_attribute(&attribute, &session_public, &mut rng);
        let json = serde_json::to_string(&encrypted).expect("serialization should succeed");
        let deserialized: EncryptedAttribute =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(deserialized, encrypted);
    }

    #[test]
    fn polymorphic_encrypt_decrypt() {
        let mut rng = rand::rng();
        let (_, global_secret) = make_pseudonym_global_keys(&mut rng);
        let enc_secret = EncryptionSecret::from("test-secret".as_bytes().to_vec());
        let session = EncryptionContext::from("session-1");
        let (session_public, session_secret) =
            make_pseudonym_session_keys(&global_secret, &session, &enc_secret);

        let original = Pseudonym::random(&mut rng);
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

        assert_eq!(decrypted, original);
    }
}
