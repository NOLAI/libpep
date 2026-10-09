//! WASM bindings for the ciphersuite.

use libpep::ciphersuite::Ciphersuite;
use wasm_bindgen::prelude::*;

/// The ciphersuite identifier, from which the context string `"coPRFV1-" || identifier` is built.
///
/// Hashes that take no secret, in particular `hashToGroup`, are domain-separated with it, so all
/// parties of a deployment must use the same one. The default, and the only suite this build
/// implements, is `ristretto255-SHA512`.
///
/// This is not an `EncryptionContext` or a `PseudonymizationDomain`: those name a session and a
/// domain within a deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[wasm_bindgen(js_name = Ciphersuite)]
pub struct WASMCiphersuite(pub(crate) Ciphersuite);

#[wasm_bindgen(js_class = "Ciphersuite")]
impl WASMCiphersuite {
    /// Create a ciphersuite from its identifier.
    #[wasm_bindgen(constructor)]
    pub fn new(identifier: &str) -> Self {
        Self(Ciphersuite::new(identifier))
    }

    /// The ciphersuite this build implements: `ristretto255-SHA512`.
    #[wasm_bindgen(js_name = current)]
    pub fn current() -> Self {
        Self(Ciphersuite::current())
    }

    /// The ciphersuite identifier.
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> Vec<u8> {
        self.0.identifier().to_vec()
    }

    /// The context string `"coPRFV1-" || identifier`.
    ///
    /// The name is the spec's: RFC 9497 and draft-doesburg-cfrg-coprf both call this value
    /// `contextString`.
    #[wasm_bindgen(js_name = contextString)]
    pub fn context_string(&self) -> Vec<u8> {
        self.0.context_string()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        self.0.to_string()
    }

    /// Whether two ciphersuites are the same.
    #[wasm_bindgen]
    pub fn equals(&self, other: &WASMCiphersuite) -> bool {
        self.0 == other.0
    }
}

/// The ciphersuite of an optional argument, or the one this build implements.
///
/// wasm-bindgen cannot pass an exported class by optional reference, so the ciphersuite arrives as
/// a JS object and is read through its `identifier` property. A `Ciphersuite` instance (through
/// its getter) and a plain `{identifier}` object (identifier a string or a `Uint8Array`) both
/// work. A malformed value throws.
pub(crate) fn ciphersuite_or_current(ciphersuite: Option<&js_sys::Object>) -> Ciphersuite {
    let Some(obj) = ciphersuite else {
        return Ciphersuite::current();
    };
    let identifier =
        js_sys::Reflect::get(obj, &JsValue::from_str("identifier")).unwrap_or(JsValue::UNDEFINED);
    let identifier = if let Some(s) = identifier.as_string() {
        s.into_bytes()
    } else if identifier.is_instance_of::<js_sys::Uint8Array>() {
        js_sys::Uint8Array::from(identifier).to_vec()
    } else {
        wasm_bindgen::throw_str("ciphersuite: identifier must be a string or a Uint8Array")
    };
    Ciphersuite::new(identifier)
}
