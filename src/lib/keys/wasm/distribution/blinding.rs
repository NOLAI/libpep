use crate::arithmetic::scalars::ScalarTraits;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::keys::distribution::*;
use crate::keys::types::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::keys::wasm::types::{WASMAttributeGlobalSecretKey, WASMPseudonymGlobalSecretKey};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A blinding factor.
#[derive(Copy, Clone, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindingFactor)]
pub struct WASMBlindingFactor(pub(crate) BlindingFactor);

#[wasm_bindgen(js_class = "BlindingFactor")]
impl WASMBlindingFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindingFactor(BlindingFactor(x.0))
    }

    #[wasm_bindgen]
    pub fn random() -> Self {
        let mut rng = rand::rng();
        WASMBlindingFactor(BlindingFactor::random(&mut rng))
    }

    #[wasm_bindgen(js_name = clone)]
    pub fn clone_js(&self) -> Self {
        WASMBlindingFactor(self.0)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMBlindingFactor> {
        BlindingFactor::from_slice(&bytes).map(WASMBlindingFactor)
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindingFactor> {
        BlindingFactor::from_hex(hex).map(WASMBlindingFactor)
    }
}

/// A blinded pseudonym global secret key.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedPseudonymGlobalSecretKey)]
pub struct WASMBlindedPseudonymGlobalSecretKey(pub(crate) BlindedPseudonymGlobalSecretKey);

#[wasm_bindgen(js_class = "BlindedPseudonymGlobalSecretKey")]
impl WASMBlindedPseudonymGlobalSecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindedPseudonymGlobalSecretKey(BlindedPseudonymGlobalSecretKey(x.0))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::from_slice(&bytes).map(WASMBlindedPseudonymGlobalSecretKey)
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::from_hex(hex).map(WASMBlindedPseudonymGlobalSecretKey)
    }
}

/// A blinded attribute global secret key.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedAttributeGlobalSecretKey)]
pub struct WASMBlindedAttributeGlobalSecretKey(pub(crate) BlindedAttributeGlobalSecretKey);

#[wasm_bindgen(js_class = "BlindedAttributeGlobalSecretKey")]
impl WASMBlindedAttributeGlobalSecretKey {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindedAttributeGlobalSecretKey(BlindedAttributeGlobalSecretKey(x.0))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::from_slice(&bytes).map(WASMBlindedAttributeGlobalSecretKey)
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::from_hex(hex).map(WASMBlindedAttributeGlobalSecretKey)
    }
}

/// A pair of blinded global secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = BlindedGlobalKeys)]
pub struct WASMBlindedGlobalKeys(pub(crate) BlindedGlobalKeys);

#[wasm_bindgen(js_class = "BlindedGlobalKeys")]
impl WASMBlindedGlobalKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMBlindedPseudonymGlobalSecretKey,
        attribute: WASMBlindedAttributeGlobalSecretKey,
    ) -> Self {
        WASMBlindedGlobalKeys(BlindedGlobalKeys {
            pseudonym: pseudonym.0,
            attribute: attribute.0,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMBlindedPseudonymGlobalSecretKey {
        WASMBlindedPseudonymGlobalSecretKey(self.0.pseudonym)
    }

    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMBlindedAttributeGlobalSecretKey {
        WASMBlindedAttributeGlobalSecretKey(self.0.attribute)
    }
}

/// Create blinded global keys.
#[wasm_bindgen(js_name = makeBlindedGlobalKeys)]
pub fn wasm_make_blinded_global_keys(
    pseudonym_global_secret_key: &WASMPseudonymGlobalSecretKey,
    attribute_global_secret_key: &WASMAttributeGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> Option<WASMBlindedGlobalKeys> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    make_blinded_global_keys(
        &PseudonymGlobalSecretKey::from(pseudonym_global_secret_key.0 .0),
        &AttributeGlobalSecretKey::from(attribute_global_secret_key.0 .0),
        &bs,
    )
    .map(WASMBlindedGlobalKeys)
}
