use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::internal::arithmetic::{GroupElement, ScalarNonZero};
use crate::low_level::elgamal::ElGamal;
use crate::wasm::arithmetic::{WASMGroupElement, WASMScalarNonZero};
use crate::wasm::elgamal::WASMElGamal;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::wasm_bindgen;

/// A session secret key used to decrypt messages with.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionSecretKey)]
pub struct WASMSessionSecretKey(pub WASMScalarNonZero);

/// A global secret key from which session keys are derived.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = GlobalSecretKey)]
pub struct WASMGlobalSecretKey(pub WASMScalarNonZero);

/// A session public key used to encrypt messages against, associated with a [`WASMSessionSecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = SessionPublicKey)]
pub struct WASMSessionPublicKey(pub WASMGroupElement);

/// A global public key associated with the [`WASMGlobalSecretKey`] from which session keys are derived.
/// Can also be used to encrypt messages against, if no session key is available or using a session
/// key may leak information.
#[derive(Copy, Clone, Debug, From)]
#[wasm_bindgen(js_name = GlobalPublicKey)]
pub struct WASMGlobalPublicKey(pub WASMGroupElement);
#[wasm_bindgen(js_class = "GlobalPublicKey")]
impl WASMGlobalPublicKey {
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
// TODO: more methods required for keys?

/// Pseudonymization secret used to derive a [`WASMReshuffleFactor`] from a pseudonymization domain (see [`WASMPseudonymizationInfo`]).
/// A `secret` is a byte array of arbitrary length, which is used to derive pseudonymization and rekeying factors from domains and sessions.
#[derive(Clone, Debug, From)]
#[wasm_bindgen(js_name = PseudonymizationSecret)]
pub struct WASMPseudonymizationSecret(PseudonymizationSecret);

/// Encryption secret used to derive a [`WASMRekeyFactor`] from an encryption context (see [`WASMRekeyInfo`]).
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

/// A data point which should not be identifiable
/// and can be encrypted and rekeyed, but not reshuffled.
#[wasm_bindgen(js_name = DataPoint)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMDataPoint(pub(crate) DataPoint);

/// An encrypted pseudonym, which is an [`WASMElGamal`] encryption of a [`WASMPseudonym`].
#[wasm_bindgen(js_name = EncryptedPseudonym)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMEncryptedPseudonym(pub(crate) EncryptedPseudonym);

/// An encrypted data point, which is an [`WASMElGamal`] encryption of a [`WASMDataPoint`].
#[wasm_bindgen(js_name = EncryptedDataPoint)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct WASMEncryptedDataPoint(pub(crate) EncryptedDataPoint);

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

    /// Create a collection of pseudonyms from an arbitrary-length string
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Vec<WASMPseudonym> {
        Pseudonym::from_string_padded(text)
            .into_iter()
            .map(WASMPseudonym::from)
            .collect()
    }

    /// Create a collection of pseudonyms from an arbitrary-length byte array
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: Vec<u8>) -> Vec<WASMPseudonym> {
        Pseudonym::from_bytes_padded(&data)
            .into_iter()
            .map(WASMPseudonym::from)
            .collect()
    }

    /// Convert a collection of pseudonyms back to the original string
    /// Returns null if the decoding fails (e.g., invalid padding or UTF-8)
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(pseudonyms: Vec<WASMPseudonym>) -> Option<String> {
        let rust_pseudonyms: Vec<Pseudonym> = pseudonyms.into_iter().map(|p| p.0).collect();
        Pseudonym::to_string_padded(&rust_pseudonyms).ok()
    }

    /// Convert a collection of pseudonyms back to the original byte array
    /// Returns null if the decoding fails (e.g., invalid padding)
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(pseudonyms: Vec<WASMPseudonym>) -> Option<Vec<u8>> {
        let rust_pseudonyms: Vec<Pseudonym> = pseudonyms.into_iter().map(|p| p.0).collect();
        Pseudonym::to_bytes_padded(&rust_pseudonyms).ok()
    }
}

#[wasm_bindgen(js_class = "DataPoint")]
impl WASMDataPoint {
    /// Create from a [`WASMGroupElement`].
    #[wasm_bindgen(constructor)]
    pub fn from_point(x: WASMGroupElement) -> Self {
        Self(DataPoint::from_point(GroupElement::from(x)))
    }
    /// Convert to a [`WASMGroupElement`].
    #[wasm_bindgen(js_name = toPoint)]
    pub fn to_point(self) -> WASMGroupElement {
        self.0.value.into()
    }
    /// Generate a random data point.
    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self(DataPoint::random(&mut rng))
    }
    /// Encode the data point as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Encode the data point as a hexadecimal string.
    #[wasm_bindgen(js_name = asHex)]
    pub fn as_hex(&self) -> String {
        self.0.encode_as_hex()
    }
    /// Decode a data point from a byte array.
    #[wasm_bindgen]
    pub fn decode(bytes: Vec<u8>) -> Option<Self> {
        DataPoint::decode_from_slice(bytes.as_slice()).map(Self)
    }
    /// Decode a data point from a hexadecimal string.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        DataPoint::decode_from_hex(hex).map(Self)
    }
    /// Decode a data point from a 64-byte hash value
    #[wasm_bindgen(js_name = fromHash)]
    pub fn from_hash(v: Vec<u8>) -> Self {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        DataPoint::from_hash(&arr).into()
    }
    /// Decode from a byte array of length 16.
    /// This is useful for encoding data points,
    /// as it accepts any 16-byte value.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&data);
        Self(DataPoint::from_bytes(&arr))
    }

    /// Encode as a byte array of length 16.
    /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
    /// If the value was created using [`WASMDataPoint::from_bytes`], this will return a valid value,
    /// but otherwise it will most likely return `None`.
    #[wasm_bindgen(js_name = asBytes)]
    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        self.0.as_bytes().map(|x| x.to_vec())
    }

    /// Create a collection of data points from an arbitrary-length string
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[wasm_bindgen(js_name = fromStringPadded)]
    pub fn from_string_padded(text: &str) -> Vec<WASMDataPoint> {
        DataPoint::from_string_padded(text)
            .into_iter()
            .map(WASMDataPoint::from)
            .collect()
    }

    /// Create a collection of data points from an arbitrary-length byte array
    /// Uses PKCS#7 style padding where the padding byte value equals the number of padding bytes
    #[wasm_bindgen(js_name = fromBytesPadded)]
    pub fn from_bytes_padded(data: Vec<u8>) -> Vec<WASMDataPoint> {
        DataPoint::from_bytes_padded(&data)
            .into_iter()
            .map(WASMDataPoint::from)
            .collect()
    }

    /// Convert a collection of data points back to the original string
    /// Returns null if the decoding fails (e.g., invalid padding or UTF-8)
    #[wasm_bindgen(js_name = toStringPadded)]
    pub fn to_string_padded(data_points: Vec<WASMDataPoint>) -> Option<String> {
        let rust_data_points: Vec<DataPoint> = data_points.into_iter().map(|p| p.0).collect();
        DataPoint::to_string_padded(&rust_data_points).ok()
    }

    /// Convert a collection of data points back to the original byte array
    /// Returns null if the decoding fails (e.g., invalid padding)
    #[wasm_bindgen(js_name = toBytesPadded)]
    pub fn to_bytes_padded(data_points: Vec<WASMDataPoint>) -> Option<Vec<u8>> {
        let rust_data_points: Vec<DataPoint> = data_points.into_iter().map(|p| p.0).collect();
        DataPoint::to_bytes_padded(&rust_data_points).ok()
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

#[wasm_bindgen(js_class = "EncryptedDataPoint")]
impl WASMEncryptedDataPoint {
    /// Create from an [`WASMElGamal`].
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMElGamal) -> Self {
        Self(EncryptedDataPoint::from(ElGamal::from(x)))
    }
    /// Encode the encrypted data point as a byte array.
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    /// Decode an encrypted data point from a byte array.
    #[wasm_bindgen]
    pub fn decode(v: Vec<u8>) -> Option<Self> {
        EncryptedDataPoint::decode_from_slice(v.as_slice()).map(Self)
    }
    /// Encode the encrypted data point as a base64 string.
    #[wasm_bindgen(js_name = asBase64)]
    pub fn as_base64(&self) -> String {
        self.encode_as_base64()
    }
    /// Decode an encrypted data point from a base64 string.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<Self> {
        EncryptedDataPoint::from_base64(s).map(Self)
    }
}

/// A global key pair consisting of a public key and a secret key.
// We cannot return a tuple from a wasm_bindgen function, so we return a struct instead
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = GlobalKeyPair)]
pub struct WASMGlobalKeyPair {
    pub public: WASMGlobalPublicKey,
    pub secret: WASMGlobalSecretKey,
}

/// A session key pair consisting of a public key and a secret key.
#[derive(Copy, Clone, Debug)]
#[wasm_bindgen(js_name = SessionKeyPair)]
pub struct WASMSessionKeyPair {
    pub public: WASMSessionPublicKey,
    pub secret: WASMSessionSecretKey,
}

/// Generate a new global key pair.
#[wasm_bindgen(js_name = makeGlobalKeys)]
pub fn wasm_make_global_keys() -> WASMGlobalKeyPair {
    let mut rng = rand::thread_rng();
    let (public, secret) = crate::high_level::keys::make_global_keys(&mut rng);
    WASMGlobalKeyPair {
        public: WASMGlobalPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMGlobalSecretKey::from(WASMScalarNonZero::from(secret.0)),
    }
}

/// Generate session keys from a [`WASMGlobalSecretKey`], a session and an [`WASMEncryptionSecret`].
#[wasm_bindgen(js_name = makeSessionKeys)]
pub fn wasm_make_session_keys(
    global: &WASMGlobalSecretKey,
    session: &str,
    secret: &WASMEncryptionSecret,
) -> WASMSessionKeyPair {
    let (public, secret_key) = crate::high_level::keys::make_session_keys(
        &GlobalSecretKey(global.0 .0),
        &EncryptionContext::from(session),
        &secret.0,
    );
    WASMSessionKeyPair {
        public: WASMSessionPublicKey::from(WASMGroupElement::from(public.0)),
        secret: WASMSessionSecretKey::from(WASMScalarNonZero::from(secret_key.0)),
    }
}

/// Encrypt a pseudonym using a session public key.
#[wasm_bindgen(js_name = encryptPseudonym)]
pub fn wasm_encrypt_pseudonym(
    message: &WASMPseudonym,
    public_key: &WASMSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym(encrypt(
        &message.0,
        &SessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Decrypt an encrypted pseudonym using a session secret key.
#[wasm_bindgen(js_name = decryptPseudonym)]
pub fn wasm_decrypt_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    secret_key: &WASMSessionSecretKey,
) -> WASMPseudonym {
    WASMPseudonym(decrypt(
        &encrypted.0,
        &SessionSecretKey::from(ScalarNonZero::from(secret_key.0)),
    ))
}

/// Encrypt a data point using a session public key.
#[wasm_bindgen(js_name = encryptData)]
pub fn wasm_encrypt_data(
    message: &WASMDataPoint,
    public_key: &WASMSessionPublicKey,
) -> WASMEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    WASMEncryptedDataPoint(encrypt(
        &message.0,
        &SessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Decrypt an encrypted data point using a session secret key.
#[wasm_bindgen(js_name = decryptData)]
pub fn wasm_decrypt_data(
    encrypted: &WASMEncryptedDataPoint,
    secret_key: &WASMSessionSecretKey,
) -> WASMDataPoint {
    WASMDataPoint(decrypt(
        &EncryptedDataPoint::from(encrypted.value),
        &SessionSecretKey::from(ScalarNonZero::from(secret_key.0)),
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
/// High-level type for the factor used to [`wasm_rekey`](crate::wasm::primitives::wasm_rekey) an [WASMElGamal](crate::wasm::elgamal::WASMElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
#[wasm_bindgen(js_name = RekeyFactor)]
pub struct WASMRekeyFactor(RekeyFactor);

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

/// Rerandomize an encrypted data point using a random factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeData)]
pub fn wasm_rerandomize_encrypted(encrypted: &WASMEncryptedDataPoint) -> WASMEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    WASMEncryptedDataPoint::from(rerandomize(
        &EncryptedDataPoint::from(encrypted.value),
        &mut rng,
    ))
}

/// Rerandomize an encrypted pseudonym using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonym)]
pub fn wasm_rerandomize_encrypted_pseudonym(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMSessionPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(rerandomize(
        &EncryptedPseudonym::from(encrypted.value),
        &SessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Rerandomize an encrypted data point using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeData)]
pub fn wasm_rerandomize_encrypted(
    encrypted: &WASMEncryptedDataPoint,
    public_key: &WASMSessionPublicKey,
) -> WASMEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    WASMEncryptedDataPoint::from(rerandomize(
        &EncryptedDataPoint::from(encrypted.value),
        &SessionPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Rerandomize a global encrypted pseudonym using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonymGlobal)]
pub fn wasm_rerandomize_encrypted_pseudonym_global(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMGlobalPublicKey,
) -> WASMEncryptedPseudonym {
    let mut rng = rand::thread_rng();
    WASMEncryptedPseudonym::from(rerandomize(
        &EncryptedPseudonym::from(encrypted.value),
        &GlobalPublicKey::from(GroupElement::from(public_key.0)),
        &mut rng,
    ))
}

/// Rerandomize a global encrypted data point using a random factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeDataGlobal)]
pub fn wasm_rerandomize_encrypted_global(
    encrypted: &WASMEncryptedDataPoint,
    public_key: &WASMGlobalPublicKey,
) -> WASMEncryptedDataPoint {
    let mut rng = rand::thread_rng();
    WASMEncryptedDataPoint::from(rerandomize(
        &EncryptedDataPoint::from(encrypted.value),
        &GlobalPublicKey::from(GroupElement::from(public_key.0)),
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

/// Rerandomize an encrypted data point using a known factor.
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomizeDataKnown)]
pub fn wasm_rerandomize_encrypted_known(
    encrypted: &WASMEncryptedDataPoint,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedDataPoint {
    WASMEncryptedDataPoint::from(rerandomize_known(
        &EncryptedDataPoint::from(encrypted.value),
        &r.0,
    ))
}

/// Rerandomize an encrypted pseudonym using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonymKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_known(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMSessionPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedPseudonym {
    WASMEncryptedPseudonym::from(rerandomize_known(
        &EncryptedPseudonym::from(encrypted.value),
        &SessionPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// Rerandomize an encrypted data point using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeDataKnown)]
pub fn wasm_rerandomize_encrypted_known(
    encrypted: &WASMEncryptedDataPoint,
    public_key: &WASMSessionPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedDataPoint {
    WASMEncryptedDataPoint::from(rerandomize_known(
        &EncryptedDataPoint::from(encrypted.value),
        &SessionPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// Rerandomize a global encrypted pseudonym using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizePseudonymGlobalKnown)]
pub fn wasm_rerandomize_encrypted_pseudonym_global_known(
    encrypted: &WASMEncryptedPseudonym,
    public_key: &WASMGlobalPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedPseudonym {
    WASMEncryptedPseudonym::from(rerandomize_known(
        &EncryptedPseudonym::from(encrypted.value),
        &GlobalPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// Rerandomize a global encrypted data point using a known factor.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomizeDataGlobalKnown)]
pub fn wasm_rerandomize_encrypted_global_known(
    encrypted: &WASMEncryptedDataPoint,
    public_key: &WASMGlobalPublicKey,
    r: &WASMRerandomizeFactor,
) -> WASMEncryptedDataPoint {
    WASMEncryptedDataPoint::from(rerandomize_known(
        &EncryptedDataPoint::from(encrypted.value),
        &GlobalPublicKey::from(GroupElement::from(public_key.0)),
        &r.0,
    ))
}

/// High-level type for the factors used to [`rsk`](crate::wasm::primitives::rsk) an [WASMElGamal](crate::wasm::elgamal::WASMElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = RSKFactors)]
pub struct WASMRSKFactors {
    pub s: WASMReshuffleFactor,
    pub k: WASMRekeyFactor,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymizationInfo)]
pub struct WASMPseudonymizationInfo(pub WASMRSKFactors);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = RekeyInfo)]
pub struct WASMRekeyInfo(pub WASMRekeyFactor);

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
        let k = WASMRekeyFactor(x.k);
        WASMPseudonymizationInfo(WASMRSKFactors { s, k })
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMPseudonymizationInfo(WASMRSKFactors {
            s: WASMReshuffleFactor(ReshuffleFactor(self.0.s.0 .0.invert())),
            k: WASMRekeyFactor(RekeyFactor(self.0.k.0 .0.invert())),
        })
    }
}

#[wasm_bindgen(js_class = RekeyInfo)]
impl WASMRekeyInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        session_from: &str,
        session_to: &str,
        encryption_secret: &WASMEncryptionSecret,
    ) -> Self {
        let x = RekeyInfo::new(
            Some(&EncryptionContext::from(session_from)),
            Some(&EncryptionContext::from(session_to)),
            &encryption_secret.0,
        );
        WASMRekeyInfo(WASMRekeyFactor(x))
    }

    #[wasm_bindgen]
    pub fn rev(&self) -> Self {
        WASMRekeyInfo(WASMRekeyFactor(RekeyFactor(self.0 .0 .0.invert())))
    }
    #[wasm_bindgen(js_name = fromPseudoInfo)]
    pub fn from_pseudo_info(x: &WASMPseudonymizationInfo) -> Self {
        WASMRekeyInfo(x.0.k)
    }
}

impl From<PseudonymizationInfo> for WASMPseudonymizationInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        let s = WASMReshuffleFactor(x.s);
        let k = WASMRekeyFactor(x.k);
        WASMPseudonymizationInfo(WASMRSKFactors { s, k })
    }
}

impl From<&WASMPseudonymizationInfo> for PseudonymizationInfo {
    fn from(x: &WASMPseudonymizationInfo) -> Self {
        let s = x.s.0;
        let k = x.k.0;
        PseudonymizationInfo { s, k }
    }
}

impl From<RekeyInfo> for WASMRekeyInfo {
    fn from(x: RekeyInfo) -> Self {
        WASMRekeyInfo(WASMRekeyFactor(x))
    }
}

impl From<&WASMRekeyInfo> for RekeyInfo {
    fn from(x: &WASMRekeyInfo) -> Self {
        Self(x.0 .0 .0)
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

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
#[wasm_bindgen(js_name = rekeyData)]
pub fn wasm_rekey_data(
    encrypted: &WASMEncryptedDataPoint,
    rekey_info: &WASMRekeyInfo,
) -> WASMEncryptedDataPoint {
    let x = rekey(
        &EncryptedDataPoint::from(encrypted.value),
        &RekeyInfo::from(rekey_info),
    );
    WASMEncryptedDataPoint(x)
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
    encrypted: Vec<WASMEncryptedDataPoint>,
    rekey_info: &WASMRekeyInfo,
) -> Box<[WASMEncryptedDataPoint]> {
    let mut rng = rand::thread_rng();
    let mut encrypted = encrypted.iter().map(|x| x.0).collect::<Vec<_>>();
    rekey_batch(&mut encrypted, &RekeyInfo::from(rekey_info), &mut rng)
        .iter()
        .map(|x| WASMEncryptedDataPoint(*x))
        .collect()
}
#[wasm_bindgen(js_name = EncryptedEntityData)]
pub struct WASMEncryptedEntityData {
    pseudonyms: Vec<WASMEncryptedPseudonym>,
    data_points: Vec<WASMEncryptedDataPoint>,
}

#[wasm_bindgen(js_class = EncryptedEntityData)]
impl WASMEncryptedEntityData {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonyms: Vec<WASMEncryptedPseudonym>,
        data_points: Vec<WASMEncryptedDataPoint>,
    ) -> Self {
        Self {
            pseudonyms,
            data_points,
        }
    }
    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMEncryptedPseudonym> {
        self.pseudonyms.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn data_points(&self) -> Vec<WASMEncryptedDataPoint> {
        self.data_points.clone()
    }
}

#[wasm_bindgen(js_name = transcryptBatch)]
pub fn wasm_transcrypt_batch(
    data: Vec<WASMEncryptedEntityData>,
    transcryption_info: &WASMPseudonymizationInfo,
) -> Vec<WASMEncryptedEntityData> {
    let mut rng = rand::thread_rng();

    let mut transcryption_data = data
        .iter()
        .map(|x| {
            let pseudonyms = x.pseudonyms.iter().map(|x| x.0).collect();
            let data_points = x.data_points.iter().map(|x| x.0).collect();
            (pseudonyms, data_points)
        })
        .collect();

    let transcrypted = transcrypt_batch(
        &mut transcryption_data,
        &transcryption_info.into(),
        &mut rng,
    );

    transcrypted
        .iter()
        .map(|(pseudonyms, data_points)| {
            let pseudonyms = pseudonyms
                .iter()
                .map(|x| WASMEncryptedPseudonym(*x))
                .collect();
            let data_points = data_points
                .iter()
                .map(|x| WASMEncryptedDataPoint(*x))
                .collect();
            WASMEncryptedEntityData {
                pseudonyms,
                data_points,
            }
        })
        .collect()
}
