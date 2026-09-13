//! WASM bindings for key generation functions.

use super::types::*;
use crate::contexts::WASMEncryptionContext;
use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::arithmetic::scalars::WASMScalarNonZero;
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
        &PseudonymGlobalSecretKey::from_scalar(*global.0),
        &session.0,
        &secret.0,
    );
    WASMPseudonymSessionKeyPair::new(
        WASMPseudonymSessionPublicKey(WASMGroupElement::from(*public)),
        WASMPseudonymSessionSecretKey(WASMScalarNonZero::from(*secret_key.value())),
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
        &AttributeGlobalSecretKey::from_scalar(*global.0),
        &session.0,
        &secret.0,
    );
    WASMAttributeSessionKeyPair::new(
        WASMAttributeSessionPublicKey(WASMGroupElement::from(*public)),
        WASMAttributeSessionSecretKey(WASMScalarNonZero::from(*secret_key.value())),
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
            pseudonym: PseudonymGlobalSecretKey::from_scalar(global.pseudonym().0 .0),
            attribute: AttributeGlobalSecretKey::from_scalar(global.attribute().0 .0),
        },
        &session.0,
        &secret.0,
    );
    keys.into()
}

/// Result bundle for `makePseudonymSessionKeysWithProof`.
#[cfg(feature = "verifiable-derivation")]
#[wasm_bindgen(js_name = PseudonymSessionKeysWithProof)]
#[derive(Clone)]
pub struct WASMPseudonymSessionKeysWithProof {
    public: WASMPseudonymSessionPublicKey,
    secret: WASMPseudonymSessionSecretKey,
    proof: crate::keys::distribution::proofs::WASMSessionKeyShareProof,
    blinding_commitment: crate::keys::distribution::proofs::WASMBlindingCommitment,
}

#[cfg(feature = "verifiable-derivation")]
#[wasm_bindgen(js_class = PseudonymSessionKeysWithProof)]
impl WASMPseudonymSessionKeysWithProof {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMPseudonymSessionPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMPseudonymSessionSecretKey {
        self.secret
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> crate::keys::distribution::proofs::WASMSessionKeyShareProof {
        self.proof
    }

    #[wasm_bindgen(getter, js_name = blindingCommitment)]
    pub fn blinding_commitment(&self) -> crate::keys::distribution::proofs::WASMBlindingCommitment {
        self.blinding_commitment
    }
}

/// Result bundle for `makeAttributeSessionKeysWithProof`.
#[cfg(feature = "verifiable-derivation")]
#[wasm_bindgen(js_name = AttributeSessionKeysWithProof)]
#[derive(Clone)]
pub struct WASMAttributeSessionKeysWithProof {
    public: WASMAttributeSessionPublicKey,
    secret: WASMAttributeSessionSecretKey,
    proof: crate::keys::distribution::proofs::WASMSessionKeyShareProof,
    blinding_commitment: crate::keys::distribution::proofs::WASMBlindingCommitment,
}

#[cfg(feature = "verifiable-derivation")]
#[wasm_bindgen(js_class = AttributeSessionKeysWithProof)]
impl WASMAttributeSessionKeysWithProof {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> WASMAttributeSessionPublicKey {
        self.public
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> WASMAttributeSessionSecretKey {
        self.secret
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> crate::keys::distribution::proofs::WASMSessionKeyShareProof {
        self.proof
    }

    #[wasm_bindgen(getter, js_name = blindingCommitment)]
    pub fn blinding_commitment(&self) -> crate::keys::distribution::proofs::WASMBlindingCommitment {
        self.blinding_commitment
    }
}

/// Generate pseudonym session keys together with a session-key-share proof.
#[cfg(feature = "verifiable-derivation")]
#[wasm_bindgen(js_name = makePseudonymSessionKeysWithProof)]
pub fn wasm_make_pseudonym_session_keys_with_proof(
    global: &WASMPseudonymGlobalSecretKey,
    session: &WASMEncryptionContext,
    secret: &WASMEncryptionSecret,
    blinding: &crate::keys::distribution::blinding::WASMBlindingFactor,
) -> Result<WASMPseudonymSessionKeysWithProof, JsValue> {
    let mut rng = rand::rng();
    let (public, secret_key, proof, blinding_commitment) = make_pseudonym_session_keys_with_proof(
        &PseudonymGlobalSecretKey::from_scalar(global.0 .0),
        &session.0,
        &secret.0,
        &blinding.0 .0,
        &mut rng,
    )
    .map_err(crate::errors::session_key_share_err_to_js)?;
    Ok(WASMPseudonymSessionKeysWithProof {
        public: WASMPseudonymSessionPublicKey(WASMGroupElement::from(public.0)),
        secret: WASMPseudonymSessionSecretKey(WASMScalarNonZero::from(secret_key.0)),
        proof: crate::keys::distribution::proofs::WASMSessionKeyShareProof(proof),
        blinding_commitment: crate::keys::distribution::proofs::WASMBlindingCommitment(
            blinding_commitment,
        ),
    })
}

/// Generate attribute session keys together with a session-key-share proof.
#[cfg(feature = "verifiable-derivation")]
#[wasm_bindgen(js_name = makeAttributeSessionKeysWithProof)]
pub fn wasm_make_attribute_session_keys_with_proof(
    global: &WASMAttributeGlobalSecretKey,
    session: &WASMEncryptionContext,
    secret: &WASMEncryptionSecret,
    blinding: &crate::keys::distribution::blinding::WASMBlindingFactor,
) -> Result<WASMAttributeSessionKeysWithProof, JsValue> {
    let mut rng = rand::rng();
    let (public, secret_key, proof, blinding_commitment) = make_attribute_session_keys_with_proof(
        &AttributeGlobalSecretKey::from_scalar(global.0 .0),
        &session.0,
        &secret.0,
        &blinding.0 .0,
        &mut rng,
    )
    .map_err(crate::errors::session_key_share_err_to_js)?;
    Ok(WASMAttributeSessionKeysWithProof {
        public: WASMAttributeSessionPublicKey(WASMGroupElement::from(public.0)),
        secret: WASMAttributeSessionSecretKey(WASMScalarNonZero::from(secret_key.0)),
        proof: crate::keys::distribution::proofs::WASMSessionKeyShareProof(proof),
        blinding_commitment: crate::keys::distribution::proofs::WASMBlindingCommitment(
            blinding_commitment,
        ),
    })
}
