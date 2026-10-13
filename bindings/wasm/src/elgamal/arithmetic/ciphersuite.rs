//! WASM bindings for the ciphersuite.

use libpep::elgamal::arithmetic::{Ciphersuite, Group, Ristretto255};
use wasm_bindgen::prelude::*;

/// The ciphersuite identifier, from which the context string `"coPRFV1-" || identifier` is built.
///
/// Hashes that take no secret, in particular `hashToGroup`, are domain-separated with it. An
/// identifier names a group *and* a hash, so it belongs to the group rather than being chosen per
/// call; `ristretto255-SHA512` is the only suite this build implements.
///
/// This is not an `EncryptionContext` or a `PseudonymizationDomain`: those name a session and a
/// domain within a deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[wasm_bindgen(js_name = Ciphersuite)]
pub struct WASMCiphersuite(pub(crate) Ciphersuite);

#[wasm_bindgen(js_class = "Ciphersuite")]
impl WASMCiphersuite {
    /// The ciphersuite of the group this build implements: `ristretto255-SHA512`.
    ///
    /// A ciphersuite cannot be built from an arbitrary identifier: it names a group and a hash
    /// together, and pairing one group's identifier with another group's operations would produce
    /// hashes tagged for the wrong curve.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::current()
    }

    /// The ciphersuite this build implements: `ristretto255-SHA512`.
    #[wasm_bindgen(js_name = current)]
    pub fn current() -> Self {
        Self(Ristretto255::CIPHERSUITE)
    }

    /// The ciphersuite identifier.
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> Vec<u8> {
        self.0.identifier().as_bytes().to_vec()
    }

    /// The context string `"coPRFV1-" || identifier`.
    ///
    /// The name is the spec's: RFC 9497 and draft-doesburg-cfrg-coprf both call this value
    /// `contextString`.
    #[wasm_bindgen(js_name = contextString)]
    pub fn context_string(&self) -> Vec<u8> {
        self.0.context_string().to_vec()
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

impl Default for WASMCiphersuite {
    fn default() -> Self {
        Self::current()
    }
}
