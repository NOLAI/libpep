use crate::elgamal::arithmetic::scalars::WASMScalarNonZero;
use crate::keys::types::{WASMAttributeGlobalSecretKey, WASMPseudonymGlobalSecretKey};
use crate::macros::wasm_scalar_key_impl;
use derive_more::{Deref, From, Into};
use libpep::keys::distribution::*;
use libpep::keys::types::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use libpep::keys::SecretKey;
use wasm_bindgen::prelude::*;

/// A blinding factor.
#[derive(Copy, Clone, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindingFactor)]
pub struct WASMBlindingFactor(pub(crate) BlindingFactor);

#[wasm_bindgen(js_class = "BlindingFactor")]
impl WASMBlindingFactor {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMBlindingFactor(BlindingFactor::from_scalar(x.0))
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

wasm_scalar_key_impl!(WASMBlindedPseudonymGlobalSecretKey wraps BlindedPseudonymGlobalSecretKey as "BlindedPseudonymGlobalSecretKey");

/// A blinded attribute global secret key.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = BlindedAttributeGlobalSecretKey)]
pub struct WASMBlindedAttributeGlobalSecretKey(pub(crate) BlindedAttributeGlobalSecretKey);

wasm_scalar_key_impl!(WASMBlindedAttributeGlobalSecretKey wraps BlindedAttributeGlobalSecretKey as "BlindedAttributeGlobalSecretKey");

/// A pair of blinded global secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = BlindedGlobalSecretKeys)]
pub struct WASMBlindedGlobalSecretKeys(pub(crate) BlindedGlobalSecretKeys);

#[wasm_bindgen(js_class = "BlindedGlobalSecretKeys")]
impl WASMBlindedGlobalSecretKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMBlindedPseudonymGlobalSecretKey,
        attribute: WASMBlindedAttributeGlobalSecretKey,
    ) -> Self {
        WASMBlindedGlobalSecretKeys(BlindedGlobalSecretKeys {
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
#[wasm_bindgen(js_name = makeBlindedGlobalSecretKeys)]
pub fn wasm_make_blinded_global_keys(
    pseudonym_global_secret_key: &WASMPseudonymGlobalSecretKey,
    attribute_global_secret_key: &WASMAttributeGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> Option<WASMBlindedGlobalSecretKeys> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor::from_scalar(*x.0.value()))
        .collect();
    make_blinded_global_keys(
        &PseudonymGlobalSecretKey::from_scalar(*pseudonym_global_secret_key.0),
        &AttributeGlobalSecretKey::from_scalar(*attribute_global_secret_key.0),
        &bs,
    )
    .map(WASMBlindedGlobalSecretKeys)
}
