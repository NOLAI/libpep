//! WASM bindings for key generation functions.

use super::types::*;
use crate::arithmetic::group_elements::WASMGroupElement;
use crate::arithmetic::scalars::WASMScalarNonZero;
use crate::factors::contexts::WASMEncryptionContext;
use crate::factors::secrets::WASMEncryptionSecret;
use libpep::keys::generation::*;
use libpep::keys::types::*;
use libpep::keys::SecretKey;
use wasm_bindgen::prelude::*;

/// Generate both pseudonym and attribute global key pairs at once.
#[wasm_bindgen(js_name = makeGlobalKeys)]
pub fn wasm_make_global_keys() -> WASMGlobalKeyPairs {
    let mut rng = rand::rng();
    let (public, secret) = make_global_keys(&mut rng);
    WASMGlobalKeyPairs::new(
        WASMGlobalPublicKeys::new(
            WASMPseudonymGlobalPublicKey(WASMGroupElement::from(*public.pseudonym)),
            WASMAttributeGlobalPublicKey(WASMGroupElement::from(*public.attribute)),
        ),
        WASMGlobalSecretKeys::new(
            WASMPseudonymGlobalSecretKey(WASMScalarNonZero::from(*secret.pseudonym.value())),
            WASMAttributeGlobalSecretKey(WASMScalarNonZero::from(*secret.attribute.value())),
        ),
    )
}

/// Generate a new pseudonym global key pair.
#[wasm_bindgen(js_name = makePseudonymGlobalKeys)]
pub fn wasm_make_pseudonym_global_keys() -> WASMPseudonymGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_pseudonym_global_keys(&mut rng);
    WASMPseudonymGlobalKeyPair::new(
        WASMPseudonymGlobalPublicKey(WASMGroupElement::from(*public)),
        WASMPseudonymGlobalSecretKey(WASMScalarNonZero::from(*secret.value())),
    )
}

/// Generate a new attribute global key pair.
#[wasm_bindgen(js_name = makeAttributeGlobalKeys)]
pub fn wasm_make_attribute_global_keys() -> WASMAttributeGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_attribute_global_keys(&mut rng);
    WASMAttributeGlobalKeyPair::new(
        WASMAttributeGlobalPublicKey(WASMGroupElement::from(*public)),
        WASMAttributeGlobalSecretKey(WASMScalarNonZero::from(*secret.value())),
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
        &PseudonymGlobalSecretKey::from(*global.0),
        &session.0,
        &secret.0,
    );
    WASMPseudonymSessionKeyPair::new(
        WASMPseudonymSessionPublicKey(WASMGroupElement::from(*public)),
        WASMPseudonymSessionSecretKey(WASMScalarNonZero::from(*secret_key)),
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
        &AttributeGlobalSecretKey::from(*global.0),
        &session.0,
        &secret.0,
    );
    WASMAttributeSessionKeyPair::new(
        WASMAttributeSessionPublicKey(WASMGroupElement::from(*public)),
        WASMAttributeSessionSecretKey(WASMScalarNonZero::from(*secret_key)),
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
            pseudonym: PseudonymGlobalSecretKey::from(global.pseudonym().0 .0),
            attribute: AttributeGlobalSecretKey::from(global.attribute().0 .0),
        },
        &session.0,
        &secret.0,
    );
    keys.into()
}
