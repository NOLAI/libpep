//! WASM bindings for the protocol context.

use libpep::protocol::{Context, Mode};
use wasm_bindgen::prelude::*;

/// The protocol mode, the second component of the context string.
#[wasm_bindgen(js_name = Mode)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WASMMode {
    /// Plain (non-verifiable) transcryption, `modeCoPRF = 0x00`.
    CoPRF = 0,
    /// Verifiable transcryption, `modeVcoPRF = 0x01`.
    VcoPRF = 1,
}

impl From<WASMMode> for Mode {
    fn from(mode: WASMMode) -> Self {
        match mode {
            WASMMode::CoPRF => Mode::CoPRF,
            WASMMode::VcoPRF => Mode::VcoPRF,
        }
    }
}

impl From<Mode> for WASMMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::CoPRF => WASMMode::CoPRF,
            Mode::VcoPRF => WASMMode::VcoPRF,
        }
    }
}

/// The protocol context: mode and ciphersuite identifier, from which the context string
/// `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier` is built.
///
/// Every derived factor and hashed pseudonym is domain-separated with it, so all parties of a
/// deployment must use the same context. The default is `ristretto255-SHA512` in `Mode.CoPRF`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[wasm_bindgen(js_name = Context)]
pub struct WASMContext(pub(crate) Context);

#[wasm_bindgen(js_class = "Context")]
impl WASMContext {
    /// Create a context in `Mode.CoPRF` from a ciphersuite identifier.
    #[wasm_bindgen(constructor)]
    pub fn new(identifier: &str) -> Self {
        Self(Context::from_identifier(identifier))
    }

    /// Create a context with the given mode and identifier.
    #[wasm_bindgen(js_name = withMode)]
    pub fn with_mode(mode: WASMMode, identifier: &str) -> Self {
        Self(Context::new(mode.into(), identifier))
    }

    /// The default context: `ristretto255-SHA512` in `Mode.CoPRF`.
    #[wasm_bindgen(js_name = "default")]
    pub fn default_context() -> Self {
        Self(Context::default())
    }

    /// The protocol mode.
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> WASMMode {
        self.0.mode.into()
    }

    /// The ciphersuite identifier.
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> Vec<u8> {
        self.0.identifier.clone()
    }

    /// The context string `"coPRFV1-" || I2OSP(mode, 1) || "-" || identifier`.
    #[wasm_bindgen(js_name = contextString)]
    pub fn context_string(&self) -> Vec<u8> {
        self.0.context_string()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        self.0.to_string()
    }

    /// Whether two contexts are the same.
    #[wasm_bindgen]
    pub fn equals(&self, other: &WASMContext) -> bool {
        self.0 == other.0
    }
}

/// The context of an optional argument, or the default context.
///
/// wasm-bindgen cannot pass an exported class by optional reference, so the context arrives as a
/// JS object and is read through its `mode` and `identifier` properties. A `Context` instance
/// (through its getters) and a plain `{mode, identifier}` object (identifier a string or a
/// `Uint8Array`) both work. A malformed value throws.
pub(crate) fn context_or_default(context: Option<&js_sys::Object>) -> Context {
    let Some(obj) = context else {
        return Context::default();
    };
    let mode = js_sys::Reflect::get(obj, &JsValue::from_str("mode"))
        .ok()
        .and_then(|v| v.as_f64());
    let mode = mode.and_then(|m| (m == m.trunc() && (0.0..=255.0).contains(&m)).then_some(m as u8));
    let mode = match mode {
        Some(0) => Mode::CoPRF,
        Some(1) => Mode::VcoPRF,
        _ => wasm_bindgen::throw_str("context: mode must be Mode.CoPRF (0) or Mode.VcoPRF (1)"),
    };
    let identifier =
        js_sys::Reflect::get(obj, &JsValue::from_str("identifier")).unwrap_or(JsValue::UNDEFINED);
    let identifier = if let Some(s) = identifier.as_string() {
        s.into_bytes()
    } else if identifier.is_instance_of::<js_sys::Uint8Array>() {
        js_sys::Uint8Array::from(identifier).to_vec()
    } else {
        wasm_bindgen::throw_str("context: identifier must be a string or a Uint8Array")
    };
    Context::new(mode, identifier)
}
