//! WASM bindings for key generation functions.

use super::types::*;
use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::factors::wasm::contexts::WASMEncryptionContext;
use crate::factors::wasm::secrets::WASMEncryptionSecret;
use crate::keys::generation::*;
use crate::keys::types::*;
use wasm_bindgen::prelude::*;

/// Generate both pseudonym and attribute global key pairs at once.
#[wasm_bindgen(js_name = makeGlobalKeys)]
pub fn wasm_make_global_keys() -> WASMGlobalKeyPairs {
    let mut rng = rand::rng();
    let (public, secret) = make_global_keys(&mut rng);
    WASMGlobalKeyPairs::new(
        WASMGlobalPublicKeys::new(
            WASMPseudonymGlobalPublicKey(WASMGroupElement::from(public.pseudonym.0)),
            WASMAttributeGlobalPublicKey(WASMGroupElement::from(public.attribute.0)),
        ),
        WASMGlobalSecretKeys::new(
            WASMPseudonymGlobalSecretKey(WASMScalarNonZero::from(secret.pseudonym.0)),
            WASMAttributeGlobalSecretKey(WASMScalarNonZero::from(secret.attribute.0)),
        ),
    )
}

/// Generate a new pseudonym global key pair.
#[wasm_bindgen(js_name = makePseudonymGlobalKeys)]
pub fn wasm_make_pseudonym_global_keys() -> WASMPseudonymGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_pseudonym_global_keys(&mut rng);
    WASMPseudonymGlobalKeyPair::new(
        WASMPseudonymGlobalPublicKey(WASMGroupElement::from(public.0)),
        WASMPseudonymGlobalSecretKey(WASMScalarNonZero::from(secret.0)),
    )
}

/// Generate a new attribute global key pair.
#[wasm_bindgen(js_name = makeAttributeGlobalKeys)]
pub fn wasm_make_attribute_global_keys() -> WASMAttributeGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_attribute_global_keys(&mut rng);
    WASMAttributeGlobalKeyPair::new(
        WASMAttributeGlobalPublicKey(WASMGroupElement::from(public.0)),
        WASMAttributeGlobalSecretKey(WASMScalarNonZero::from(secret.0)),
    )
}

/// Generate pseudonym session keys from a global secret key, session and secret.
#[wasm_bindgen(js_name = makePseudonymSessionKeys)]
pub fn wasm_make_pseudonym_session_keys(
    global: &WASMPseudonymGlobalSecretKey,
    session: &WASMEncryptionContext,
    secret: &WASMEncryptionSecret,
) -> WASMPseudonymSessionKeyPair {
    let (public, secret_key) = make_pseudonym_session_keys(
        &PseudonymGlobalSecretKey(global.0 .0),
        &session.0,
        &secret.0,
    );
    WASMPseudonymSessionKeyPair::new(
        WASMPseudonymSessionPublicKey(WASMGroupElement::from(public.0)),
        WASMPseudonymSessionSecretKey(WASMScalarNonZero::from(secret_key.0)),
    )
}

/// Generate attribute session keys from a global secret key, session and secret.
#[wasm_bindgen(js_name = makeAttributeSessionKeys)]
pub fn wasm_make_attribute_session_keys(
    global: &WASMAttributeGlobalSecretKey,
    session: &WASMEncryptionContext,
    secret: &WASMEncryptionSecret,
) -> WASMAttributeSessionKeyPair {
    let (public, secret_key) = make_attribute_session_keys(
        &AttributeGlobalSecretKey(global.0 .0),
        &session.0,
        &secret.0,
    );
    WASMAttributeSessionKeyPair::new(
        WASMAttributeSessionPublicKey(WASMGroupElement::from(public.0)),
        WASMAttributeSessionSecretKey(WASMScalarNonZero::from(secret_key.0)),
    )
}

/// Generate session keys for both pseudonyms and attributes.
#[wasm_bindgen(js_name = makeSessionKeys)]
pub fn wasm_make_session_keys(
    global: &WASMGlobalSecretKeys,
    session: &WASMEncryptionContext,
    secret: &WASMEncryptionSecret,
) -> WASMSessionKeys {
    let keys = make_session_keys(
        &GlobalSecretKeys {
            pseudonym: PseudonymGlobalSecretKey(global.pseudonym().0 .0),
            attribute: AttributeGlobalSecretKey(global.attribute().0 .0),
        },
        &session.0,
        &secret.0,
    );
    keys.into()
}
