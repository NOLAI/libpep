use super::blinding::{
    WASMBlindedAttributeGlobalSecretKey, WASMBlindedGlobalKeys,
    WASMBlindedPseudonymGlobalSecretKey, WASMBlindingFactor,
};
use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::keys::distribution::*;
use crate::keys::types::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::keys::wasm::types::{
    WASMAttributeGlobalPublicKey, WASMAttributeGlobalSecretKey, WASMGlobalPublicKeys,
    WASMPseudonymGlobalPublicKey, WASMPseudonymGlobalSecretKey,
};
use wasm_bindgen::prelude::*;

/// Setup a distributed system with global keys.
#[wasm_bindgen(js_name = makeDistributedGlobalKeys)]
pub fn wasm_make_distributed_global_keys(n: usize) -> Box<[JsValue]> {
    let mut rng = rand::rng();
    let (global_public_keys, blinded_keys, blinding_factors) =
        make_distributed_global_keys(n, &mut rng);

    let global_keys = WASMGlobalPublicKeys::new(
        WASMPseudonymGlobalPublicKey(WASMGroupElement(global_public_keys.pseudonym.0)),
        WASMAttributeGlobalPublicKey(WASMGroupElement(global_public_keys.attribute.0)),
    );
    let blinded = WASMBlindedGlobalKeys(blinded_keys);
    let factors: Vec<WASMBlindingFactor> = blinding_factors
        .into_iter()
        .map(WASMBlindingFactor)
        .collect();

    vec![
        JsValue::from(global_keys),
        JsValue::from(blinded),
        JsValue::from(
            factors
                .into_iter()
                .map(JsValue::from)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
    ]
    .into_boxed_slice()
}

/// Creates a blinded pseudonym global secret key.
#[wasm_bindgen(js_name = makeBlindedPseudonymGlobalSecretKey)]
pub fn wasm_make_blinded_pseudonym_global_secret_key(
    global_secret_key: &WASMPseudonymGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> Option<WASMBlindedPseudonymGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    make_blinded_pseudonym_global_secret_key(
        &PseudonymGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .map(WASMBlindedPseudonymGlobalSecretKey)
}

/// Creates a blinded attribute global secret key.
#[wasm_bindgen(js_name = makeBlindedAttributeGlobalSecretKey)]
pub fn wasm_make_blinded_attribute_global_secret_key(
    global_secret_key: &WASMAttributeGlobalSecretKey,
    blinding_factors: Vec<WASMBlindingFactor>,
) -> Option<WASMBlindedAttributeGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    make_blinded_attribute_global_secret_key(
        &AttributeGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .map(WASMBlindedAttributeGlobalSecretKey)
}

/// Generates distributed pseudonym global keys.
#[wasm_bindgen(js_name = makeDistributedPseudonymGlobalKeys)]
pub fn wasm_make_distributed_pseudonym_global_keys(n: usize) -> Box<[JsValue]> {
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_pseudonym_global_keys(n, &mut rng);

    let public = WASMPseudonymGlobalPublicKey(WASMGroupElement(public_key.0));
    let blinded = WASMBlindedPseudonymGlobalSecretKey(blinded_key);
    let factors: Vec<WASMBlindingFactor> = blinding_factors
        .into_iter()
        .map(WASMBlindingFactor)
        .collect();

    vec![
        JsValue::from(public),
        JsValue::from(blinded),
        JsValue::from(
            factors
                .into_iter()
                .map(JsValue::from)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
    ]
    .into_boxed_slice()
}

/// Generates distributed attribute global keys.
#[wasm_bindgen(js_name = makeDistributedAttributeGlobalKeys)]
pub fn wasm_make_distributed_attribute_global_keys(n: usize) -> Box<[JsValue]> {
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_attribute_global_keys(n, &mut rng);

    let public = WASMAttributeGlobalPublicKey(WASMGroupElement(public_key.0));
    let blinded = WASMBlindedAttributeGlobalSecretKey(blinded_key);
    let factors: Vec<WASMBlindingFactor> = blinding_factors
        .into_iter()
        .map(WASMBlindingFactor)
        .collect();

    vec![
        JsValue::from(public),
        JsValue::from(blinded),
        JsValue::from(
            factors
                .into_iter()
                .map(JsValue::from)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
    ]
    .into_boxed_slice()
}
