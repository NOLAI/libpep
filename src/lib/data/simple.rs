//! Core data types for pseudonyms and attributes, their encrypted versions,
//! and session-key based encryption and decryption operations.

use crate::arithmetic::group_elements::GroupElement;
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::elgamal::{ElGamal, ELGAMAL_LENGTH};
use crate::data::traits::{Encryptable, Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::TranscryptionInfo;
use crate::factors::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, RerandomizeFactor,
};
use crate::keys::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A pseudonym (in the background, this is a [`GroupElement`]) that can be used to identify a user
/// within a specific context, which can be encrypted, rekeyed and reshuffled.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct Pseudonym {
    pub value: GroupElement,
}
/// An attribute (in the background, this is a [`GroupElement`]), which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct Attribute {
    pub value: GroupElement,
}
/// An encrypted pseudonym, which is an [`ElGamal`] encryption of a [`Pseudonym`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
/// An encrypted attribute, which is an [`ElGamal`] encryption of an [`Attribute`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Deref, From)]
pub struct EncryptedAttribute {
    pub value: ElGamal,
}

/// A marker trait for encrypted types that use ElGamal encryption with a single ciphertext value.
/// This enables access to ElGamal-specific operations like serialization.
pub trait ElGamalEncrypted: Encrypted {
    type UnencryptedType: ElGamalEncryptable<EncryptedType = Self>;

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
    fn from_bytes(bytes: &[u8; ELGAMAL_LENGTH]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_bytes(bytes).map(Self::from_value)
    }

    /// Decode from a byte slice.
    fn from_slice(slice: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_slice(slice).map(Self::from_value)
    }

    /// Convert to base64 string.
    fn to_base64(&self) -> String {
        self.value().to_base64()
    }

    /// Convert from base64 string.
    fn from_base64(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ElGamal::from_base64(s).map(Self::from_value)
    }
}

/// A marker trait for encryptable types that use ElGamal encryption with a single plaintext value.
/// This enables access to ElGamal-specific operations like serialization and special encodings.
pub trait ElGamalEncryptable: Encryptable {
    /// Get the [`GroupElement`] plaintext value.
    fn value(&self) -> &GroupElement;
    /// Create from a [`GroupElement`].
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
    /// If the value was created using [`ElGamalEncryptable::from_lizard`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    fn to_lizard(&self) -> Option<[u8; 16]> {
        self.value().to_lizard()
    }
}

impl Encryptable for Pseudonym {
    type EncryptedType = EncryptedPseudonym;
    type PublicKeyType = PseudonymSessionPublicKey;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = PseudonymGlobalPublicKey;

    fn encrypt<R>(&self, public_key: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        EncryptedPseudonym::from_value(crate::core::elgamal::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        EncryptedPseudonym::from_value(crate::core::elgamal::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }
}

impl Encryptable for Attribute {
    type EncryptedType = EncryptedAttribute;
    type PublicKeyType = AttributeSessionPublicKey;
    #[cfg(feature = "offline")]
    type GlobalPublicKeyType = AttributeGlobalPublicKey;

    fn encrypt<R>(&self, public_key: &Self::PublicKeyType, rng: &mut R) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        EncryptedAttribute::from_value(crate::core::elgamal::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }

    #[cfg(feature = "offline")]
    fn encrypt_global<R>(
        &self,
        public_key: &Self::GlobalPublicKeyType,
        rng: &mut R,
    ) -> Self::EncryptedType
    where
        R: RngCore + CryptoRng,
    {
        EncryptedAttribute::from_value(crate::core::elgamal::encrypt(
            self.value(),
            public_key.value(),
            rng,
        ))
    }
}

impl ElGamalEncryptable for Pseudonym {
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

impl ElGamalEncryptable for Attribute {
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

impl Encrypted for EncryptedPseudonym {
    type UnencryptedType = Pseudonym;
    type SecretKeyType = PseudonymSessionSecretKey;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = PseudonymGlobalSecretKey;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        crate::core::elgamal::decrypt(self.value(), secret_key.value()).map(Pseudonym::from_value)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Self::UnencryptedType {
        Pseudonym::from_value(crate::core::elgamal::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        crate::core::elgamal::decrypt(self.value(), secret_key.value()).map(Pseudonym::from_value)
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        Pseudonym::from_value(crate::core::elgamal::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor) -> Self {
        EncryptedPseudonym::from_value(crate::core::primitives::rerandomize(
            self.value(),
            &factor.0,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor,
    ) -> Self {
        EncryptedPseudonym::from_value(crate::core::primitives::rerandomize(
            self.value(),
            public_key.value(),
            &factor.0,
        ))
    }
}

impl Encrypted for EncryptedAttribute {
    type UnencryptedType = Attribute;
    type SecretKeyType = AttributeSessionSecretKey;
    #[cfg(all(feature = "offline", feature = "insecure"))]
    type GlobalSecretKeyType = AttributeGlobalSecretKey;

    #[cfg(feature = "elgamal3")]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Option<Self::UnencryptedType> {
        crate::core::elgamal::decrypt(self.value(), secret_key.value()).map(Attribute::from_value)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn decrypt(&self, secret_key: &Self::SecretKeyType) -> Self::UnencryptedType {
        Attribute::from_value(crate::core::elgamal::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
    fn decrypt_global(
        &self,
        secret_key: &Self::GlobalSecretKeyType,
    ) -> Option<Self::UnencryptedType> {
        crate::core::elgamal::decrypt(self.value(), secret_key.value()).map(Attribute::from_value)
    }

    #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
    fn decrypt_global(&self, secret_key: &Self::GlobalSecretKeyType) -> Self::UnencryptedType {
        Attribute::from_value(crate::core::elgamal::decrypt(
            self.value(),
            secret_key.value(),
        ))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize<R>(&self, rng: &mut R) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(&RerandomizeFactor(r))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize<R>(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        let r = ScalarNonZero::random(rng);
        self.rerandomize_known(public_key, &RerandomizeFactor(r))
    }

    #[cfg(feature = "elgamal3")]
    fn rerandomize_known(&self, factor: &RerandomizeFactor) -> Self {
        EncryptedAttribute::from_value(crate::core::primitives::rerandomize(
            self.value(),
            &factor.0,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn rerandomize_known(
        &self,
        public_key: &<Self::UnencryptedType as Encryptable>::PublicKeyType,
        factor: &RerandomizeFactor,
    ) -> Self {
        EncryptedAttribute::from_value(crate::core::primitives::rerandomize(
            self.value(),
            public_key.value(),
            &factor.0,
        ))
    }
}

impl ElGamalEncrypted for EncryptedPseudonym {
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
impl ElGamalEncrypted for EncryptedAttribute {
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

// Transcryption trait implementations

impl Pseudonymizable for EncryptedPseudonym {
    fn pseudonymize(&self, info: &PseudonymizationInfo) -> Self {
        EncryptedPseudonym::from_value(crate::core::primitives::rsk(
            self.value(),
            &info.s.0,
            &info.k.0,
        ))
    }
}

impl Rekeyable for EncryptedPseudonym {
    type RekeyInfo = PseudonymRekeyInfo;

    fn rekey(&self, info: &Self::RekeyInfo) -> Self {
        EncryptedPseudonym::from_value(crate::core::primitives::rekey(self.value(), &info.0))
    }
}

impl Rekeyable for EncryptedAttribute {
    type RekeyInfo = AttributeRekeyInfo;

    fn rekey(&self, info: &Self::RekeyInfo) -> Self {
        EncryptedAttribute::from_value(crate::core::primitives::rekey(self.value(), &info.0))
    }
}

impl Transcryptable for EncryptedPseudonym {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        self.pseudonymize(&info.pseudonym)
    }
}

impl Transcryptable for EncryptedAttribute {
    fn transcrypt(&self, info: &TranscryptionInfo) -> Self {
        self.rekey(&info.attribute)
    }
}
#[cfg(feature = "batch")]
impl crate::data::traits::HasStructure for EncryptedPseudonym {
    type Structure = ();

    fn structure(&self) -> Self::Structure {}
}

#[cfg(feature = "batch")]
impl crate::data::traits::HasStructure for EncryptedAttribute {
    type Structure = ();

    fn structure(&self) -> Self::Structure {}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::client::{decrypt, encrypt};
    use crate::factors::contexts::EncryptionContext;
    use crate::factors::EncryptionSecret;

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
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

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
        let encrypted = encrypt(&original, &session_public, &mut rng);
        #[cfg(feature = "elgamal3")]
        let decrypted = decrypt(&encrypted, &session_secret).expect("decryption should succeed");
        #[cfg(not(feature = "elgamal3"))]
        let decrypted = decrypt(&encrypted, &session_secret);

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
        let encrypted = encrypt(&pseudonym, &session_public, &mut rng);
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
        let encrypted = encrypt(&attribute, &session_public, &mut rng);
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
