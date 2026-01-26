//! WASM bindings for cryptographic factor types.

use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::factors::types::*;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A factor used to rerandomize an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = RerandomizeFactor)]
pub struct WASMRerandomizeFactor(pub(crate) RerandomizeFactor);

#[wasm_bindgen(js_class = RerandomizeFactor)]
impl WASMRerandomizeFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(RerandomizeFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0 .0)
    }
}

/// A factor used to reshuffle an ElGamal ciphertext.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = ReshuffleFactor)]
pub struct WASMReshuffleFactor(pub(crate) ReshuffleFactor);

#[wasm_bindgen(js_class = ReshuffleFactor)]
impl WASMReshuffleFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(ReshuffleFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0 .0)
    }
}

/// A factor used to rekey pseudonyms between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymRekeyFactor)]
pub struct WASMPseudonymRekeyFactor(pub(crate) PseudonymRekeyFactor);

#[wasm_bindgen(js_class = PseudonymRekeyFactor)]
impl WASMPseudonymRekeyFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(PseudonymRekeyFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0 .0)
    }
}

/// A factor used to rekey attributes between sessions.
#[derive(Copy, Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeRekeyFactor)]
pub struct WASMAttributeRekeyFactor(pub(crate) AttributeRekeyFactor);

#[wasm_bindgen(js_class = AttributeRekeyFactor)]
impl WASMAttributeRekeyFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(scalar: &WASMScalarNonZero) -> Self {
        Self(AttributeRekeyFactor::from(scalar.0))
    }

    #[wasm_bindgen(js_name = scalar)]
    pub fn wasm_scalar(&self) -> WASMScalarNonZero {
        WASMScalarNonZero(self.0 .0)
    }
}

/// Factors for pseudonymization containing reshuffle and rekey factors.
#[derive(Clone, Copy)]
#[wasm_bindgen(js_name = PseudonymRSKFactors)]
pub struct WASMPseudonymRSKFactors {
    s: WASMReshuffleFactor,
    k: WASMPseudonymRekeyFactor,
}

#[wasm_bindgen(js_class = PseudonymRSKFactors)]
impl WASMPseudonymRSKFactors {
    #[wasm_bindgen(constructor)]
    pub fn new(s: WASMReshuffleFactor, k: WASMPseudonymRekeyFactor) -> Self {
        Self { s, k }
    }

    #[wasm_bindgen(getter)]
    pub fn s(&self) -> WASMReshuffleFactor {
        self.s
    }

    #[wasm_bindgen(setter)]
    pub fn set_s(&mut self, s: WASMReshuffleFactor) {
        self.s = s;
    }

    #[wasm_bindgen(getter)]
    pub fn k(&self) -> WASMPseudonymRekeyFactor {
        self.k
    }

    #[wasm_bindgen(setter)]
    pub fn set_k(&mut self, k: WASMPseudonymRekeyFactor) {
        self.k = k;
    }
}

impl From<&WASMPseudonymRSKFactors> for PseudonymRSKFactors {
    fn from(x: &WASMPseudonymRSKFactors) -> Self {
        PseudonymRSKFactors { s: x.s.0, k: x.k.0 }
    }
}

impl From<PseudonymRSKFactors> for WASMPseudonymRSKFactors {
    fn from(x: PseudonymRSKFactors) -> Self {
        WASMPseudonymRSKFactors {
            s: WASMReshuffleFactor(x.s),
            k: WASMPseudonymRekeyFactor(x.k),
        }
    }
}
