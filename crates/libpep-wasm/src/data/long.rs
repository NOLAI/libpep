use crate::data::simple::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::macros::{wasm_long_encrypted_impl, wasm_long_plaintext_impl};
use derive_more::{Deref, From};
use libpep::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use libpep::data::simple::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use wasm_bindgen::prelude::*;

/// A collection of pseudonyms that together represent a larger pseudonym value using PKCS#7 padding.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongPseudonym)]
pub struct WASMLongPseudonym(pub(crate) LongPseudonym);

wasm_long_plaintext_impl!(WASMLongPseudonym wraps LongPseudonym of WASMPseudonym(Pseudonym) as LongPseudonym,
    ctor(pseudonyms, doc = "Create from a vector of pseudonyms."),
    items(pseudonyms, doc = "Get the underlying pseudonyms."));

/// A collection of attributes that together represent a larger data value using PKCS#7 padding.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongAttribute)]
pub struct WASMLongAttribute(pub(crate) LongAttribute);

wasm_long_plaintext_impl!(WASMLongAttribute wraps LongAttribute of WASMAttribute(Attribute) as LongAttribute,
    ctor(attributes, doc = "Create from a vector of attributes."),
    items(attributes, doc = "Get the underlying attributes."));

/// A collection of encrypted pseudonyms that can be serialized as a pipe-delimited string.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongEncryptedPseudonym)]
pub struct WASMLongEncryptedPseudonym(pub(crate) LongEncryptedPseudonym);

wasm_long_encrypted_impl!(WASMLongEncryptedPseudonym wraps LongEncryptedPseudonym of WASMEncryptedPseudonym(EncryptedPseudonym) as LongEncryptedPseudonym,
    ctor(encrypted_pseudonyms, doc = "Create from a vector of encrypted pseudonyms."),
    items(encrypted_pseudonyms as encryptedPseudonyms, doc = "Get the underlying encrypted pseudonyms."));

/// A collection of encrypted attributes that can be serialized as a pipe-delimited string.
#[derive(Clone, Eq, PartialEq, Debug, From, Deref)]
#[wasm_bindgen(js_name = LongEncryptedAttribute)]
pub struct WASMLongEncryptedAttribute(pub(crate) LongEncryptedAttribute);

wasm_long_encrypted_impl!(WASMLongEncryptedAttribute wraps LongEncryptedAttribute of WASMEncryptedAttribute(EncryptedAttribute) as LongEncryptedAttribute,
    ctor(encrypted_attributes, doc = "Create from a vector of encrypted attributes."),
    items(encrypted_attributes as encryptedAttributes, doc = "Get the underlying encrypted attributes."));

#[cfg(feature = "batch")]
use crate::factors::contexts::WASMTranscryptionInfo;
#[cfg(feature = "batch")]
use crate::factors::types::WASMPseudonymRekeyFactor;
/// WASM bindings for batch operations on long (multi-block) data types.
#[cfg(feature = "batch")]
use libpep::data::records::LongEncryptedRecord;
#[cfg(feature = "batch")]
use libpep::factors::TranscryptionInfo;
#[cfg(feature = "batch")]
use libpep::transcryptor::{rekey_batch, transcrypt_batch};

/// Batch rekeying of long encrypted pseudonyms.
/// The order of the pseudonyms is randomly shuffled to avoid linking them.
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = rekeyLongPseudonymBatch)]
pub fn wasm_rekey_long_pseudonym_batch(
    encrypted: Vec<WASMLongEncryptedPseudonym>,
    rekey_info: &WASMPseudonymRekeyFactor,
) -> Result<Vec<WASMLongEncryptedPseudonym>, JsValue> {
    let mut rng = rand::rng();
    let mut enc: Vec<_> = encrypted.into_iter().map(|e| e.0).collect();
    let result = rekey_batch(&mut enc, &rekey_info.0, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(result
        .into_vec()
        .into_iter()
        .map(WASMLongEncryptedPseudonym)
        .collect())
}

/// A pair of long encrypted pseudonyms and attributes for batch transcryption.
#[wasm_bindgen(js_name = LongEncryptedRecord)]
pub struct WASMLongEncryptedRecord {
    pseudonyms: Vec<WASMLongEncryptedPseudonym>,
    attributes: Vec<WASMLongEncryptedAttribute>,
}

#[wasm_bindgen(js_class = "LongEncryptedRecord")]
impl WASMLongEncryptedRecord {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonyms: Vec<WASMLongEncryptedPseudonym>,
        attributes: Vec<WASMLongEncryptedAttribute>,
    ) -> Self {
        Self {
            pseudonyms,
            attributes,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMLongEncryptedPseudonym> {
        self.pseudonyms.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMLongEncryptedAttribute> {
        self.attributes.clone()
    }
}

/// Batch transcryption of long encrypted data.
/// Each item contains a list of long encrypted pseudonyms and a list of long encrypted attributes.
/// The order of the items is randomly shuffled to avoid linking them.
///
/// # Errors
///
/// Throws an error if the encrypted data do not all have the same structure.
#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = transcryptLongBatch)]
pub fn wasm_transcrypt_long_batch(
    encrypted: Vec<WASMLongEncryptedRecord>,
    transcryption_info: &WASMTranscryptionInfo,
) -> Result<Vec<WASMLongEncryptedRecord>, JsValue> {
    let mut rng = rand::rng();
    let mut enc: Vec<LongEncryptedRecord> = encrypted
        .into_iter()
        .map(|pair| LongEncryptedRecord {
            pseudonyms: pair.pseudonyms.into_iter().map(|p| p.0).collect(),
            attributes: pair.attributes.into_iter().map(|a| a.0).collect(),
        })
        .collect();
    let info = TranscryptionInfo {
        pseudonym: transcryption_info.0.pseudonym,
        attribute: transcryption_info.0.attribute,
    };
    let result = transcrypt_batch(&mut enc, &info, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{}", e)))?;
    Ok(result
        .into_vec()
        .into_iter()
        .map(|rec| WASMLongEncryptedRecord {
            pseudonyms: rec
                .pseudonyms
                .into_iter()
                .map(WASMLongEncryptedPseudonym)
                .collect(),
            attributes: rec
                .attributes
                .into_iter()
                .map(WASMLongEncryptedAttribute)
                .collect(),
        })
        .collect())
}
