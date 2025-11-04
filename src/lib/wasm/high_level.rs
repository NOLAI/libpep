use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::high_level::padding::{LongAttribute, LongPseudonym, Padded};
use crate::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use crate::internal::arithmetic::{GroupElement, ScalarNonZero};
use crate::low_level::elgamal::ElGamal;
use crate::wasm::arithmetic::{WASMGroupElement, WASMScalarNonZero};
use crate::wasm::elgamal::WASMElGamal;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::wasm_bindgen;

/// A session secret key used to decrypt pseudonyms with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymSessionSecretKey)]
pub struct WASMPseudonymSessionSecretKey(pub WASMScalarNonZero);

/// A session secret key used to decrypt attributes with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeSessionSecretKey)]
pub struct WASMAttributeSessionSecretKey(pub WASMScalarNonZero);

/// A global secret key for pseudonyms from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymGlobalSecretKey)]
pub struct WASMPseudonymGlobalSecretKey(pub WASMScalarNonZero);

/// A global secret key for attributes from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = AttributeGlobalSecretKey)]
pub struct WASMAttributeGlobalSecretKey(pub WASMScalarNonZero);

/// A session public key used to encrypt pseudonyms against, associated with a [`WASMPseudonymSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymSessionPublicKey)]
pub struct WASMPseudonymSessionPublicKey(pub WASMGroupElement);

/// A session public key used to encrypt attributes against, associated with a [`WASMAttributeSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeSessionPublicKey)]
pub struct WASMAttributeSessionPublicKey(pub WASMGroupElement);

/// A global public key for pseudonyms associated with the [`WASMPseudonymGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt pseudonyms against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymGlobalPublicKey)]
pub struct WASMPseudonymGlobalPublicKey(pub WASMGroupElement);

/// A global public key for attributes associated with the [`WASMAttributeGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt attributes against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = AttributeGlobalPublicKey)]
pub struct WASMAttributeGlobalPublicKey(pub WASMGroupElement);

#[wasm_bindgen(js_class = "PseudonymGlobalPublicKey")]
impl WASMPseudonymGlobalPublicKey {
    /// Creates a new global public key from a group element.
    #[wasm_bindgen(constructor)]
    pub fn from_point(x: WASMGroupElement) -> Self {
        Self(GroupElement::from(x).into())
    }
    /// Returns the group element associated with this public key.
    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(self) -> WASMGroupElement {
        self.0
    }
    /// Encodes the public key as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    /// Decodes a public key from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        let x = GroupElement::decode_from_hex(hex)?;
        Some(Self(x.into()))
    }
}

#[wasm_bindgen(js_class = "AttributeGlobalPublicKey")]
impl WASMAttributeGlobalPublicKey {
    /// Creates a new global public key from a group element.
    #[wasm_bindgen(constructor)]
    pub fn from_point(x: WASMGroupElement) -> Self {
        Self(GroupElement::from(x).into())
    }
    /// Returns the group element associated with this public key.
    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(self) -> WASMGroupElement {
        self.0
    }
    /// Encodes the public key as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    /// Decodes a public key from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        let x = GroupElement::decode_from_hex(hex)?;
        Some(Self(x.into()))
    }
}

/// Pseudonymization secret used to derive a [`WASMReshuffleFactor`] from a pseudonymization domain (see [`WASMPseudonymizationInfo`]).
/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from domains and sessions.
#[derive(Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymizationSecret)]
pub struct WASMPseudonymizationSecret(PseudonymizationSecret);

/// Encryption secret used to derive rekey factors from an encryption context (see [`WASMPseudonymRekeyInfo`] and [`WASMAttributeRekeyInfo`]).
/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from domains and sessions.
#[derive(Clone, Debug, From)]
#[wasm_bindgen(js_name = EncryptionSecret)]
pub struct WASMEncryptionSecret(EncryptionSecret);

#[wasm_bindgen(js_class = "PseudonymizationSecret")]
impl WASMPseudonymizationSecret {
    #[wasm_bindgen(constructor)]
    pub fn from(data: Vec<u8>) -> Self {
        Self(PseudonymizationSecret::from(data))
    }
}
#[wasm_bindgen(js_class = "EncryptionSecret")]
impl WASMEncryptionSecret {
    #[wasm_bindgen(constructor)]
    pub fn from(data: Vec<u8>) -> Self {
        Self(EncryptionSecret::from(data))
    }
}

/// A pseudonym that can be used to identify a user
/// within a specific domain, which can be encrypted, rekeyed and reshuffled.
#[wasm_bindgen(js_name = Pseudonym)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMPseudonym(pub(crate) Pseudonym);

/// An attribute which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[wasm_bindgen(js_name = Attribute)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMAttribute(pub(crate) Attribute);

/// An encrypted pseudonym, which is an [`WASMElGamal`] encryption of a [`WASMPseudonym`].
#[wasm_bindgen(js_name = EncryptedPseudonym)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMEncryptedPseudonym(pub(crate) EncryptedPseudonym);

/// An encrypted attribute, which is an [`WASMElGamal`] encryption of a [`WASMAttribute`].
#[wasm_bindgen(js_name = EncryptedAttribute)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMEncryptedAttribute(pub(crate) EncryptedAttribute);

#[wasm_bindgen(js_class = "Pseudonym")]
impl WASMPseudonym {
    /// Create from a [`WASMGroupElement`].
    #[wasm_bindgen(constructor)]
    pub fn from_point(x: WASMGroupElement) -> Self {
        Self(Pseudonym::from_point(GroupElement::from(x)))
    }
    /// Convert to a [`WASMGroupElement`].
    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(self) -> WASMGroupElement {
        self.0.value.into()
    }
    /// Generate a random pseudonym.
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self(Pseudonym::random(&mut rng))
    }
    /// Encode the pseudonym as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Encode the pseudonym as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a pseudonym from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<Self> {
        Pseudonym::decode_from_slice(bytes.as_slice()).map(Self)
    }
    /// Decode a pseudonym from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Pseudonym::decode_from_hex(hex).map(Self)
    }
    /// Decode a pseudonym from a 64-byte hash value
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> Self {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Pseudonym::from_hash(&arr).into()
    }
    /// Decode from a byte array of length 16.
    /// This is useful for creating a pseudonym from an existing identifier,
    /// as it accepts any 16-byte value.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data);
        Self(Pseudonym::from_bytes(&arr))
    }
    /// Encode as a byte array of length 16.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`WASMPseudonym::from_bytes`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[wasm_bindgen(js_name = asBytes)]
    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        self.0.as_bytes().map(|x| x.to_vec())
    }

    /// Encodes a byte array (up to 16 bytes) into a `Pseudonym` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: &[u8]) -> Option<Self> {
        Pseudonym::from_bytes_padded(data).ok().map(Self)
    }

    /// Encodes a string (up to 16 bytes) into a `Pseudonym` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Option<Self> {
        Pseudonym::from_string_padded(text).ok().map(Self)
    }

    /// Decodes the `Pseudonym` back to the original string.
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Option<String> {
        self.0.to_string_padded().ok()
    }

    /// Decodes the `Pseudonym` back to the original byte array.
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Option<Vec<u8>> {
        self.0.to_bytes_padded().ok()
    }
}

#[wasm_bindgen(js_class = "Attribute")]
impl WASMAttribute {
    /// Create from a [`WASMGroupElement`].
    #[wasm_bindgen(constructor)]
    pub fn from_point(x: WASMGroupElement) -> Self {
        Self(Attribute::from_point(GroupElement::from(x)))
    }
    /// Convert to a [`WASMGroupElement`].
    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(self) -> WASMGroupElement {
        self.0.value.into()
    }
    /// Generate a random attribute.
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self(Attribute::random(&mut rng))
    }
    /// Encode the attribute as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Encode the attribute as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode an attribute from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<Self> {
        Attribute::decode_from_slice(bytes.as_slice()).map(Self)
    }
    /// Decode an attribute from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        Attribute::decode_from_hex(hex).map(Self)
    }
    /// Decode an attribute from a 64-byte hash value
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> Self {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Attribute::from_hash(&arr).into()
    }
    /// Decode from a byte array of length 16.
    /// This is useful for encoding attributes,
    /// as it accepts any 16-byte value.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data);
        Self(Attribute::from_bytes(&arr))
    }

    /// Encode as a byte array of length 16.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`WASMAttribute::from_bytes`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[wasm_bindgen(js_name = asBytes)]
    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        self.0.as_bytes().map(|x| x.to_vec())
    }

    /// Encodes a byte array (up to 16 bytes) into an `Attribute` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: &[u8]) -> Option<Self> {
        Attribute::from_bytes_padded(data).ok().map(Self)
    }

    /// Encodes a string (up to 16 bytes) into an `Attribute` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Option<Self> {
        Attribute::from_string_padded(text).ok().map(Self)
    }

    /// Decodes the `Attribute` back to the original string.
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Option<String> {
        self.0.to_string_padded().ok()
    }

    /// Decodes the `Attribute` back to the original byte array.
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Option<Vec<u8>> {
        self.0.to_bytes_padded().ok()
    }
}

/// A collection of pseudonyms that together represent a larger pseudonym value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// The length (number of blocks) of a `LongPseudonym` may reveal information about the original data.
/// Consider padding your data to a fixed size before encoding to prevent length-based information leakage.
#[wasm_bindgen(js_name = LongPseudonym)]
#[derive(Clone, From, Deref)]
pub struct WASMLongPseudonym(pub(crate) LongPseudonym);

#[wasm_bindgen(js_class = "LongPseudonym")]
impl WASMLongPseudonym {
    /// Create from a vector of pseudonyms.
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonyms: Vec<WASMPseudonym>) -> Self {
        let rust_pseudonyms: Vec<Pseudonym> = pseudonyms.into_iter().map(|p| p.0).collect();
        Self(LongPseudonym(rust_pseudonyms))
    }

    /// Encodes an arbitrary-length string into a `LongPseudonym` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Option<WASMLongPseudonym> {
        LongPseudonym::from_string_padded(text).ok().map(Self)
    }

    /// Encodes an arbitrary-length byte array into a `LongPseudonym` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: &[u8]) -> Option<WASMLongPseudonym> {
        LongPseudonym::from_bytes_padded(data).ok().map(Self)
    }

    /// Decodes the `LongPseudonym` back to the original string.
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Option<String> {
        self.0.to_string_padded().ok()
    }

    /// Decodes the `LongPseudonym` back to the original byte array.
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Option<Vec<u8>> {
        self.0.to_bytes_padded().ok()
    }

    /// Get the underlying pseudonyms.
    #[wasm_bindgen(js_name = pseudonyms)]
    pub fn pseudonyms(&self) -> Vec<WASMPseudonym> {
        self.0 .0.iter().map(|p| WASMPseudonym(*p)).collect()
    }

    /// Get the number of pseudonym blocks.
    #[wasm_bindgen(js_name = length)]
    pub fn length(&self) -> usize {
        self.0 .0.len()
    }
}

/// A collection of attributes that together represent a larger data value using PKCS#7 padding.
///
/// # Privacy Warning
///
/// The length (number of blocks) of a `LongAttribute` may reveal information about the original data.
/// Consider padding your data to a fixed size before encoding to prevent length-based information leakage.
#[wasm_bindgen(js_name = LongAttribute)]
#[derive(Clone, From, Deref)]
pub struct WASMLongAttribute(pub(crate) LongAttribute);

#[wasm_bindgen(js_class = "LongAttribute")]
impl WASMLongAttribute {
    /// Create from a vector of attributes.
    #[wasm_bindgen(constructor)]
    pub fn new(attributes: Vec<WASMAttribute>) -> Self {
        let rust_attributes: Vec<Attribute> = attributes.into_iter().map(|a| a.0).collect();
        Self(LongAttribute(rust_attributes))
    }

    /// Encodes an arbitrary-length string into a `LongAttribute` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Option<WASMLongAttribute> {
        LongAttribute::from_string_padded(text).ok().map(Self)
    }

    /// Encodes an arbitrary-length byte array into a `LongAttribute` using PKCS#7 padding.
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: &[u8]) -> Option<WASMLongAttribute> {
        LongAttribute::from_bytes_padded(data).ok().map(Self)
    }

    /// Decodes the `LongAttribute` back to the original string.
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(&self) -> Option<String> {
        self.0.to_string_padded().ok()
    }

    /// Decodes the `LongAttribute` back to the original byte array.
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(&self) -> Option<Vec<u8>> {
        self.0.to_bytes_padded().ok()
    }

    /// Get the underlying attributes.
    #[wasm_bindgen(js_name = attributes)]
    pub fn attributes(&self) -> Vec<WASMAttribute> {
        self.0 .0.iter().map(|a| WASMAttribute(*a)).collect()
    }

    /// Get the number of attribute blocks.
    #[wasm_bindgen(js_name = length)]
    pub fn length(&self) -> usize {
        self.0 .0.len()
    }
}

#[wasm_bindgen(js_class = "EncryptedPseudonym")]
impl WASMEncryptedPseudonym {
    /// Create from an [`WASMElGamal`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        Self(EncryptedPseudonym::from(ElGamal::from(x)))
    }
    /// Encode the encrypted pseudonym as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode an encrypted pseudonym from a byte array.
    #[wasm_bindgen]
    pub fn decode(v: Vec<u8>) -> Option<Self> {
        EncryptedPseudonym::decode_from_slice(v.as_slice()).map(Self)
    }
    /// Encode the encrypted pseudonym as a base64 string.
    #[wasm_bindgen(js_name = asBase64)]
    pub fn as_base64(&self) -> String {
        self.encode_as_base64()
    }
    /// Decode an encrypted pseudonym from a base64 string.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<Self> {
        EncryptedPseudonym::from_base64(s).map(Self)
    }
}

#[wasm_bindgen(js_class = "EncryptedAttribute")]
impl WASMEncryptedAttribute {
    /// Create from an [`WASMElGamal`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        Self(EncryptedAttribute::from(ElGamal::from(x)))
    }
    /// Encode the encrypted attribute as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode an encrypted attribute from a byte array.
    #[wasm_bindgen]
    pub fn decode(v: Vec<u8>) -> Option<Self> {
        EncryptedAttribute::decode_from_slice(v.as_slice()).map(Self)
    }
    /// Encode the encrypted attribute as a base64 string.
    #[wasm_bindgen(js_name = asBase64)]
    pub fn as_base64(&self) -> String {
        self.encode_as_base64()
    }
    /// Decode an encrypted attribute from a base64 string.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<Self> {
        EncryptedAttribute::from_base64(s).map(Self)
    }
}

/// A global key pair for pseudonyms consisting of a public key and a secret key.
// We cannot return a tuple from a wasm_bindgen function, so we return a struct instead
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymGlobalKeyPair)]
pub struct WASMPseudonymGlobalKeyPair {
    pub public: WASMPseudonymGlobalPublicKey,
    pub secret: WASMPseudonymGlobalSecretKey,
}

/// A global key pair for attributes consisting of a public key and a secret key.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = AttributeGlobalKeyPair)]
pub struct WASMAttributeGlobalKeyPair {
    pub public: WASMAttributeGlobalPublicKey,
    pub secret: WASMAttributeGlobalSecretKey,
}

/// A session key pair for pseudonyms consisting of a public key and a secret key.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = PseudonymSessionKeyPair)]
pub struct WASMPseudonymSessionKeyPair {
    pub public: WASMPseudonymSessionPublicKey,
    pub secret: WASMPseudonymSessionSecretKey,
}

/// A session key pair for attributes consisting of a public key and a secret key.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = AttributeSessionKeyPair)]
pub struct WASMAttributeSessionKeyPair {
    pub public: WASMAttributeSessionPublicKey,
    pub secret: WASMAttributeSessionSecretKey,
}

/// Generate a new global key pair for pseudonyms.
#[wasm_bindgen(js_name = makePseudonymGlobalKeys)]
pub fn wasm_make_pseudonym_global_keys() -> WASMPseudonymGlobalKeyPair {
    let mut rng = rand::thread_rng();
    let (public, secret) = crate::high_level::keys::make_pseudonym_global_keys(&mut rng);
    WASMPseudonymGlobalKeyPair {
        public: WASMPseudonymGlobalPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMPseudonymGlobalSecretKey::from(WASMScalarNonZero::from(secret.0)),
    }
}

/// Generate a new global key pair for attributes.
#[wasm_bindgen(js_name = makeAttributeGlobalKeys)]
pub fn wasm_make_attribute_global_keys() -> WASMAttributeGlobalKeyPair {
    let mut rng = rand::thread_rng();
    let (public, secret) = crate::high_level::keys::make_attribute_global_keys(&mut rng);
    WASMAttributeGlobalKeyPair {
        public: WASMAttributeGlobalPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMAttributeGlobalSecretKey::from(WASMScalarNonZero::from(secret.0)),
    }
}

/// Generate session keys for pseudonyms from a [`WASMPseudonymGlobalSecretKey`], a session and an [`WASMEncryptionSecret`].
#[wasm_bindgen(js_name = makePseudonymSessionKeys)]
pub fn wasm_make_pseudonym_session_keys(
    global: &WASMPseudonymGlobalSecretKey,
    session: &str,
    secret: &WASMEncryptionSecret,
) -> WASMPseudonymSessionKeyPair {
    let (public, secret_key) = crate::high_level::keys::make_pseudonym_session_keys(
        &PseudonymGlobalSecretKey(global.0 .0),
        &EncryptionContext::from(session),
        &secret.0,
    );
    WASMPseudonymSessionKeyPair {
        public: WASMPseudonymSessionPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMPseudonymSessionSecretKey::from(WASMScalarNonZero::from(secret_key.0)),
    }
}

/// Generate session keys for attributes from a [`WASMAttributeGlobalSecretKey`], a session and an [`WASMEncryptionSecret`].
#[wasm_bindgen(js_name = makeAttributeSessionKeys)]
pub fn wasm_make_attribute_session_keys(
    global: &WASMAttributeGlobalSecretKey,
    session: &str,
    secret: &WASMEncryptionSecret,
) -> WASMAttributeSessionKeyPair {
    let (public, secret_key) = crate::high_level::keys::make_attribute_session_keys(
        &AttributeGlobalSecretKey(global.0 .0),
        &EncryptionContext::from(session),
        &secret.0,
    );
    WASMAttributeSessionKeyPair {
        public: WASMAttributeSessionPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMAttributeSessionSecretKey::from(WASMScalarNonZero::from(secret_key.0)),
    }
}

/// Encrypt a pseudonym using a pseudonym session public key.
#[wasm_bindgen(js_name = encryptPseudonym)]
pub fn wasm_encrypt_pseudonym(
    message: &WASMPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym(encrypt_pseudonym(
        &message.0,
        &PseudonymSessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Decrypt an encrypted pseudonym using a pseudonym session secret key.
#[wasm_bindgen(js_name = decryptPseudonym)]
pub fn wasm_decrypt_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    secret_key: &WASMPseudonymSessionSecretKey,
) -> WASMPseudonym {
    WASMPseudonym(decrypt_pseudonym(
        &encrypted.0,
        &PseudonymSessionSecretKey::from(ScalarNonZero::from(secret_key.0)),
    ))
}

/// Encrypt an attribute using an attribute session public key.
#[wasm_bindgen(js_name = encryptData)]
pub fn wasm_encrypt_data(
    message: &WASMAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::thread_rng();
    WASMEncryptedAttribute(encrypt_attribute(
        &message.0,
        &AttributeSessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Decrypt an encrypted attribute using an attribute session secret key.
#[wasm_bindgen(js_name = decryptData)]
pub fn wasm_decrypt_data(
    encrypted: &WASMEncryptedAttribute,
    secret_key: &WASMAttributeSessionSecretKey,
) -> WASMAttribute {
    WASMAttribute(decrypt_attribute(
        &EncryptedAttribute::from(encrypted.value),
        &AttributeSessionSecretKey::from(ScalarNonZero::from(secret_key.0)),
    ))
}

/// High-level type for the factor used to [`wasm_rerandomize`](crate::wasm::primitives::wasm_rerandomize) an [WASMElGamal](crate::wasm::elgamal::WASMElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = RerandomizeFactor)]
pub struct WASMRerandomizeFactor(RerandomizeFactor);
/// High-level type for the factor used to [`wasm_reshuffle`](crate::wasm::primitives::wasm_reshuffle) an [WASMElGamal](crate::wasm::elgamal::WASMElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = ReshuffleFactor)]
pub struct WASMReshuffleFactor(ReshuffleFactor);
/// High-level type for the factor used to rekey pseudonyms.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = PseudonymRekeyFactor)]
pub struct WASMPseudonymRekeyFactor(PseudonymRekeyFactor);
/// High-level type for the factor used to rekey attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = AttributeRekeyFactor)]
pub struct WASMAttributeRekeyFactor(AttributeRekeyFactor);

/// Rerandomize an encrypted pseudonym using a random factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizePseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(rerandomize(
        &EncryptedPseudonym::from(encrypted.value),
        &mut rng,
    ))
}

/// Rerandomize an encrypted attribute using a random factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeData)]
pub fn wasm_rerandomize_encrypted(encrypted: &WASMEncryptedAttribute) -> WASMEncryptedAttribute {
    let mut rng = rand::thread_rng();
    WASMEncryptedAttribute::from(rerandomize(
        &EncryptedAttribute::from(encrypted.value),
        &mut rng,
    ))
}

/// Rerandomize an encrypted pseudonym using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(rerandomize(
        &EncryptedPseudonym::from(encrypted.value),
        &PseudonymSessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Rerandomize an encrypted attribute using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeData)]
pub fn wasm_rerandomize_encrypted(
    encrypted: &WASMEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::thread_rng();
    WASMEncryptedAttribute::from(rerandomize(
        &EncryptedAttribute::from(encrypted.value),
        &AttributeSessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Rerandomize a global encrypted pseudonym using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonymGlobal)]
pub fn wasm_rerandomize_encrypted_pseudonym_global(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymGlobalPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(rerandomize(
        &EncryptedPseudonym::from(encrypted.value),
        &PseudonymGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Rerandomize a global encrypted attribute using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeDataGlobal)]
pub fn wasm_rerandomize_encrypted_global(
    encrypted: &WASMEncryptedAttribute,
    public_key: &WASMAttributeGlobalPublicKey,
) -> WASMEncryptedAttribute {
    let mut rng = rand::thread_rng();
    WASMEncryptedAttribute::from(rerandomize(
        &EncryptedAttribute::from(encrypted.value),
        &AttributeGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizePseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    encrypted: &WASMEncryptedPseudonym,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedPseudonym {
    WASMEncryptedPseudonym::from(rerandomize_known(
        &EncryptedPseudonym::from(encrypted.value),
        &r.0,
    ))
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeDataKnown)]
pub fn wasm_rerandomize_encrypted_known(
    encrypted: &WASMEncryptedAttribute,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedAttribute {
    WASMEncryptedAttribute::from(rerandomize_known(
        &EncryptedAttribute::from(encrypted.value),
        &r.0,
    ))
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymSessionPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedPseudonym {
    WASMEncryptedPseudonym::from(rerandomize_known(
        &EncryptedPseudonym::from(encrypted.value),
        &PseudonymSessionPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// Rerandomize an encrypted attribute using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeDataKnown)]
pub fn wasm_rerandomize_encrypted_known(
    encrypted: &WASMEncryptedAttribute,
    public_key: &WASMAttributeSessionPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedAttribute {
    WASMEncryptedAttribute::from(rerandomize_known(
        &EncryptedAttribute::from(encrypted.value),
        &AttributeSessionPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// Rerandomize a global encrypted pseudonym using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonymGlobalKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_global_known(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMPseudonymGlobalPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedPseudonym {
    WASMEncryptedPseudonym::from(rerandomize_known(
        &EncryptedPseudonym::from(encrypted.value),
        &PseudonymGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// Rerandomize a global encrypted attribute using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeDataGlobalKnown)]
pub fn wasm_rerandomize_encrypted_global_known(
    encrypted: &WASMEncryptedAttribute,
    public_key: &WASMAttributeGlobalPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedAttribute {
    WASMEncryptedAttribute::from(rerandomize_known(
        &EncryptedAttribute::from(encrypted.value),
        &AttributeGlobalPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// High-level type for the factors used to pseudonymize (RSK) pseudonyms.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = PseudonymRSKFactors)]
pub struct WASMPseudonymRSKFactors {
    pub s: WASMReshuffleFactor,
    pub k: WASMPseudonymRekeyFactor,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymizationInfo)]
pub struct WASMPseudonymizationInfo(pub WASMPseudonymRSKFactors);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeRekeyInfo)]
pub struct WASMAttributeRekeyInfo(pub WASMAttributeRekeyFactor);
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = TranscryptionInfo)]
pub struct WASMTranscryptionInfo {
    pub pseudonym: WASMPseudonymizationInfo,
    pub attribute: WASMAttributeRekeyInfo,
}

#[wasm_bindgen(js_class = PseudonymizationInfo)]
impl WASMPseudonymizationInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let x = PseudonymizationInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );
        let s = WASMReshuffleFactor(x.s);
        let k = WASMPseudonymRekeyFactor(x.k);
        WASMPseudonymizationInfo(WASMPseudonymRSKFactors { s, k })
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMPseudonymizationInfo(WASMPseudonymRSKFactors {
            s: WASMReshuffleFactor(ReshuffleFactor(self.0.s.0 .0.invert())),
            k: WASMPseudonymRekeyFactor(PseudonymRekeyFactor(self.0.k.0 .0.invert())),
        })
    }
}

#[wasm_bindgen(js_class = AttributeRekeyInfo)]
impl WASMAttributeRekeyInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        session_from: &str,
        session_to: &str,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let x = AttributeRekeyInfo::new(
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &encryption_secret.0,
        );
        WASMAttributeRekeyInfo(WASMAttributeRekeyFactor(x))
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMAttributeRekeyInfo(WASMAttributeRekeyFactor(AttributeRekeyFactor(
            self.0 .0 .0.invert(),
        )))
    }
}

#[wasm_bindgen(js_class = TranscryptionInfo)]
impl WASMTranscryptionInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        domain_from: &str,
        domain_to: &str,
        session_from: &str,
        session_to: &str,
        pseudonymization_secret: &WASMPseudonymizationSecret,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let x = TranscryptionInfo::new(
            &PseudonymizationDomain::from(domain_from),
            &PseudonymizationDomain::from(domain_to),
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &pseudonymization_secret.0,
            &encryption_secret.0,
        );
        Self {
            pseudonym: WASMPseudonymizationInfo::from(x.pseudonym),
            attribute: WASMAttributeRekeyInfo::from(x.attribute),
        }
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        Self {
            pseudonym: self.pseudonym.rev(),
            attribute: self.attribute.rev(),
        }
    }
}

impl From<PseudonymizationInfo> for WASMPseudonymizationInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        let s = WASMReshuffleFactor(x.s);
        let k = WASMPseudonymRekeyFactor(x.k);
        WASMPseudonymizationInfo(WASMPseudonymRSKFactors { s, k })
    }
}

impl From<&WASMPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &WASMPseudonymizationInfo) -> Self {
        let s = x.s.0;
        let k = x.k.0;
        PseudonymizationInfo { s, k }
    }
}

impl From<AttributeRekeyInfo> for WASMAttributeRekeyInfo {
    fn from(x: AttributeRekeyInfo) -> Self {
        WASMAttributeRekeyInfo(WASMAttributeRekeyFactor(x))
    }
}

impl From<&WASMAttributeRekeyInfo> for AttributeRekeyInfo {
    fn from(x: &WASMAttributeRekeyInfo) -> Self {
        Self(x.0 .0 .0)
    }
}

impl From<TranscryptionInfo> for WASMTranscryptionInfo {
    fn from(x: TranscryptionInfo) -> Self {
        Self {
            pseudonym: WASMPseudonymizationInfo::from(x.pseudonym),
            attribute: WASMAttributeRekeyInfo::from(x.attribute),
        }
    }
}

impl From<&WASMTranscryptionInfo> for TranscryptionInfo {
    fn from(x: &WASMTranscryptionInfo) -> Self {
        Self {
            pseudonym: PseudonymizationInfo::from(&x.pseudonym),
            attribute: AttributeRekeyInfo::from(&x.attribute),
        }
    }
}

/// Pseudonymize an encrypted pseudonym, from one domain and session to another
#[wasm_bindgen(js_name = pseudonymize)]
pub fn wasm_pseudonymize(
    encrypted: &WASMEncryptedPseudonym,
    pseudo_info: &WASMPseudonymizationInfo,
) -> WASMEncryptedPseudonym {
    let x = pseudonymize(
        &EncryptedPseudonym::from(encrypted.value),
        &PseudonymizationInfo::from(pseudo_info),
    );
    WASMEncryptedPseudonym(x)
}

/// Rekey an encrypted attribute, encrypted with one session key, to be decrypted by another session key
#[wasm_bindgen(js_name = rekeyData)]
pub fn wasm_rekey_data(
    encrypted: &WASMEncryptedAttribute,
    rekey_info: &WASMAttributeRekeyInfo,
) -> WASMEncryptedAttribute {
    let x = rekey(
        &EncryptedAttribute::from(encrypted.value),
        &AttributeRekeyInfo::from(rekey_info),
    );
    WASMEncryptedAttribute(x)
}

#[wasm_bindgen(js_name = pseudonymizeBatch)]
pub fn wasm_pseudonymize_batch(
    encrypted: Vec<WASMEncryptedPseudonym>,
    pseudo_info: &WASMPseudonymizationInfo,
) -> Box<[WASMEncryptedPseudonym]> {
    let mut rng = rand::thread_rng();
    let mut encrypted = encrypted.iter().map(|x| x.0).collect::<Vec<_>>();
    pseudonymize_batch(
        &mut encrypted,
        &PseudonymizationInfo::from(pseudo_info),
        &mut rng,
    )
    .iter()
    .map(|x| WASMEncryptedPseudonym(*x))
    .collect()
}

#[wasm_bindgen(js_name = rekeyBatch)]
pub fn wasm_rekey_batch(
    encrypted: Vec<WASMEncryptedAttribute>,
    rekey_info: &WASMAttributeRekeyInfo,
) -> Box<[WASMEncryptedAttribute]> {
    let mut rng = rand::thread_rng();
    let mut encrypted = encrypted.iter().map(|x| x.0).collect::<Vec<_>>();
    rekey_batch(
        &mut encrypted,
        &AttributeRekeyInfo::from(rekey_info),
        &mut rng,
    )
    .iter()
    .map(|x| WASMEncryptedAttribute(*x))
    .collect()
}
#[wasm_bindgen(js_name = EncryptedData)]
pub struct WASMEncryptedData {
    pseudonyms: Vec<WASMEncryptedPseudonym>,
    attributes: Vec<WASMEncryptedAttribute>,
}

#[wasm_bindgen(js_class = EncryptedData)]
impl WASMEncryptedData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonyms: Vec<WASMEncryptedPseudonym>,
        attributes: Vec<WASMEncryptedAttribute>,
    ) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }
    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMEncryptedPseudonym> {
        self.pseudonyms.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMEncryptedAttribute> {
        self.attributes.clone()
    }
}

#[wasm_bindgen(js_name = transcryptBatch)]
pub fn wasm_transcrypt_batch(
    data: Vec<WASMEncryptedData>,
    transcryption_info: &WASMTranscryptionInfo,
) -> Vec<WASMEncryptedData> {
    let mut rng = rand::thread_rng();

    let mut transcryption_data = data
        .iter()
        .map(|x| {
            let pseudonyms = x.pseudonyms.iter().map(|x| x.0).collect();
            let attributes = x.attributes.iter().map(|x| x.0).collect();
            (pseudonyms, attributes)
        })
        .collect();

    let transcrypted = transcrypt_batch(
        &mut transcryption_data,
        &transcryption_info.into(),
        &mut rng,
    );

    transcrypted
        .iter()
        .map(|(pseudonyms, attributes)| {
            let pseudonyms = pseudonyms
                .iter()
                .map(|x| WASMEncryptedPseudonym(*x))
                .collect();
            let attributes = attributes
                .iter()
                .map(|x| WASMEncryptedAttribute(*x))
                .collect();
            WASMEncryptedData {
                pseudonyms,
                attributes,
            }
        })
        .collect()
}
