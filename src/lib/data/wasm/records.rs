//! WASM bindings for Record types - standalone encrypt/decrypt operations.

use crate::data::records::{EncryptedRecord, Record};
use crate::data::wasm::simple::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use wasm_bindgen::prelude::*;

#[cfg(feature = "long")]
use crate::data::records::{LongEncryptedRecord, LongRecord};
#[cfg(feature = "long")]
use crate::data::wasm::long::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};

/// A record containing multiple pseudonyms and attributes for a single entity.
#[wasm_bindgen(js_name = Record)]
pub struct WASMRecord {
    pseudonyms: Vec<WASMPseudonym>,
    attributes: Vec<WASMAttribute>,
}

#[wasm_bindgen(js_class = Record)]
impl WASMRecord {
    /// Create a new Record with the given pseudonyms and attributes.
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonyms: Vec<WASMPseudonym>, attributes: Vec<WASMAttribute>) -> Self {
        WASMRecord {
            pseudonyms,
            attributes,
        }
    }

    /// Get the pseudonyms in this record.
    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMPseudonym> {
        self.pseudonyms.clone()
    }

    /// Get the attributes in this record.
    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMAttribute> {
        self.attributes.clone()
    }
}

impl From<WASMRecord> for Record {
    fn from(record: WASMRecord) -> Self {
        Record::new(
            record.pseudonyms.into_iter().map(|p| p.0).collect(),
            record.attributes.into_iter().map(|a| a.0).collect(),
        )
    }
}

impl From<Record> for WASMRecord {
    fn from(record: Record) -> Self {
        WASMRecord {
            pseudonyms: record.pseudonyms.into_iter().map(WASMPseudonym).collect(),
            attributes: record.attributes.into_iter().map(WASMAttribute).collect(),
        }
    }
}

/// An encrypted record containing multiple encrypted pseudonyms and attributes.
/// This is the encrypted version of a Record that can be decrypted back.
#[wasm_bindgen(js_name = RecordEncrypted)]
pub struct WASMRecordEncrypted {
    pseudonyms: Vec<WASMEncryptedPseudonym>,
    attributes: Vec<WASMEncryptedAttribute>,
}

#[wasm_bindgen(js_class = RecordEncrypted)]
impl WASMRecordEncrypted {
    /// Create a new encrypted record.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonyms: Vec<WASMEncryptedPseudonym>,
        attributes: Vec<WASMEncryptedAttribute>,
    ) -> Self {
        WASMRecordEncrypted {
            pseudonyms,
            attributes,
        }
    }

    /// Get the encrypted pseudonyms in this record.
    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMEncryptedPseudonym> {
        self.pseudonyms.clone()
    }

    /// Get the encrypted attributes in this record.
    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMEncryptedAttribute> {
        self.attributes.clone()
    }
}

impl From<EncryptedRecord> for WASMRecordEncrypted {
    fn from(record: EncryptedRecord) -> Self {
        WASMRecordEncrypted {
            pseudonyms: record
                .pseudonyms
                .into_iter()
                .map(WASMEncryptedPseudonym)
                .collect(),
            attributes: record
                .attributes
                .into_iter()
                .map(WASMEncryptedAttribute)
                .collect(),
        }
    }
}

impl From<WASMRecordEncrypted> for EncryptedRecord {
    fn from(record: WASMRecordEncrypted) -> Self {
        EncryptedRecord::new(
            record.pseudonyms.into_iter().map(|p| p.0).collect(),
            record.attributes.into_iter().map(|a| a.0).collect(),
        )
    }
}

// Long Record types (only when 'long' feature is enabled)

#[cfg(feature = "long")]
/// A long record containing multiple long pseudonyms and attributes for a single entity.
#[wasm_bindgen(js_name = LongRecord)]
pub struct WASMLongRecord {
    pseudonyms: Vec<WASMLongPseudonym>,
    attributes: Vec<WASMLongAttribute>,
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongRecord)]
impl WASMLongRecord {
    /// Create a new LongRecord with the given long pseudonyms and attributes.
    #[wasm_bindgen(constructor)]
    pub fn new(pseudonyms: Vec<WASMLongPseudonym>, attributes: Vec<WASMLongAttribute>) -> Self {
        WASMLongRecord {
            pseudonyms,
            attributes,
        }
    }

    /// Get the long pseudonyms in this record.
    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMLongPseudonym> {
        self.pseudonyms.clone()
    }

    /// Get the long attributes in this record.
    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMLongAttribute> {
        self.attributes.clone()
    }
}

#[cfg(feature = "long")]
impl From<WASMLongRecord> for LongRecord {
    fn from(record: WASMLongRecord) -> Self {
        LongRecord::new(
            record.pseudonyms.into_iter().map(|p| p.0).collect(),
            record.attributes.into_iter().map(|a| a.0).collect(),
        )
    }
}

#[cfg(feature = "long")]
impl From<LongRecord> for WASMLongRecord {
    fn from(record: LongRecord) -> Self {
        WASMLongRecord {
            pseudonyms: record
                .pseudonyms
                .into_iter()
                .map(WASMLongPseudonym)
                .collect(),
            attributes: record
                .attributes
                .into_iter()
                .map(WASMLongAttribute)
                .collect(),
        }
    }
}

#[cfg(feature = "long")]
/// An encrypted long record containing multiple encrypted long pseudonyms and attributes.
/// This is the encrypted version of a LongRecord that can be decrypted back.
#[wasm_bindgen(js_name = LongRecordEncrypted)]
pub struct WASMLongRecordEncrypted {
    pseudonyms: Vec<WASMLongEncryptedPseudonym>,
    attributes: Vec<WASMLongEncryptedAttribute>,
}

#[cfg(feature = "long")]
#[wasm_bindgen(js_class = LongRecordEncrypted)]
impl WASMLongRecordEncrypted {
    /// Create a new encrypted long record.
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonyms: Vec<WASMLongEncryptedPseudonym>,
        attributes: Vec<WASMLongEncryptedAttribute>,
    ) -> Self {
        WASMLongRecordEncrypted {
            pseudonyms,
            attributes,
        }
    }

    /// Get the encrypted long pseudonyms in this record.
    #[wasm_bindgen(getter)]
    pub fn pseudonyms(&self) -> Vec<WASMLongEncryptedPseudonym> {
        self.pseudonyms.clone()
    }

    /// Get the encrypted long attributes in this record.
    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<WASMLongEncryptedAttribute> {
        self.attributes.clone()
    }
}

#[cfg(feature = "long")]
impl From<LongEncryptedRecord> for WASMLongRecordEncrypted {
    fn from(record: LongEncryptedRecord) -> Self {
        WASMLongRecordEncrypted {
            pseudonyms: record
                .pseudonyms
                .into_iter()
                .map(WASMLongEncryptedPseudonym)
                .collect(),
            attributes: record
                .attributes
                .into_iter()
                .map(WASMLongEncryptedAttribute)
                .collect(),
        }
    }
}

#[cfg(feature = "long")]
impl From<WASMLongRecordEncrypted> for LongEncryptedRecord {
    fn from(record: WASMLongRecordEncrypted) -> Self {
        LongEncryptedRecord::new(
            record.pseudonyms.into_iter().map(|p| p.0).collect(),
            record.attributes.into_iter().map(|a| a.0).collect(),
        )
    }
}
