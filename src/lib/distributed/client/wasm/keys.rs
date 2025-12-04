use super::super::keys::{
    make_attribute_session_key, make_pseudonym_session_key, make_session_keys_distributed,
    update_attribute_session_key, update_pseudonym_session_key, update_session_keys,
};
use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::core::wasm::keys::{
    WASMAttributeSessionKeyPair, WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey,
    WASMPseudonymSessionKeyPair, WASMPseudonymSessionPublicKey, WASMPseudonymSessionSecretKey,
    WASMSessionKeys,
};
use crate::distributed::server::keys::{
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
use crate::distributed::server::wasm::setup::{
    WASMBlindedAttributeGlobalSecretKey, WASMBlindedGlobalKeys, WASMBlindedPseudonymGlobalSecretKey,
};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A pseudonym session key share.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymSessionKeyShare)]
pub struct WASMPseudonymSessionKeyShare(pub(crate) PseudonymSessionKeyShare);

#[wasm_bindgen(js_class = "PseudonymSessionKeyShare")]
impl WASMPseudonymSessionKeyShare {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMPseudonymSessionKeyShare(PseudonymSessionKeyShare(x.0))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::from_slice(&bytes).map(WASMPseudonymSessionKeyShare)
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMPseudonymSessionKeyShare> {
        PseudonymSessionKeyShare::from_hex(hex).map(WASMPseudonymSessionKeyShare)
    }
}

/// An attribute session key share.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeSessionKeyShare)]
pub struct WASMAttributeSessionKeyShare(pub(crate) AttributeSessionKeyShare);

#[wasm_bindgen(js_class = "AttributeSessionKeyShare")]
impl WASMAttributeSessionKeyShare {
    #[wasm_bindgen(constructor)]
    pub fn new(x: WASMScalarNonZero) -> Self {
        WASMAttributeSessionKeyShare(AttributeSessionKeyShare(x.0))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Option<WASMAttributeSessionKeyShare> {
        AttributeSessionKeyShare::from_slice(&bytes).map(WASMAttributeSessionKeyShare)
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(hex: &str) -> Option<WASMAttributeSessionKeyShare> {
        AttributeSessionKeyShare::from_hex(hex).map(WASMAttributeSessionKeyShare)
    }
}

/// A pair of session key shares.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[wasm_bindgen(js_name = SessionKeyShares)]
pub struct WASMSessionKeyShares(pub(crate) SessionKeyShares);

#[wasm_bindgen(js_class = "SessionKeyShares")]
impl WASMSessionKeyShares {
    #[wasm_bindgen(constructor)]
    pub fn new(
        pseudonym: WASMPseudonymSessionKeyShare,
        attribute: WASMAttributeSessionKeyShare,
    ) -> Self {
        WASMSessionKeyShares(SessionKeyShares {
            pseudonym: pseudonym.0,
            attribute: attribute.0,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn pseudonym(&self) -> WASMPseudonymSessionKeyShare {
        WASMPseudonymSessionKeyShare(self.0.pseudonym)
    }

    #[wasm_bindgen(getter)]
    pub fn attribute(&self) -> WASMAttributeSessionKeyShare {
        WASMAttributeSessionKeyShare(self.0.attribute)
    }
}

/// Combines pseudonym session key shares.
#[wasm_bindgen(js_name = makePseudonymSessionKey)]
pub fn wasm_make_pseudonym_session_key(
    blinded_global_key: WASMBlindedPseudonymGlobalSecretKey,
    shares: Vec<WASMPseudonymSessionKeyShare>,
) -> WASMPseudonymSessionKeyPair {
    let shares: Vec<PseudonymSessionKeyShare> = shares.into_iter().map(|s| s.0).collect();
    let (public, secret) = make_pseudonym_session_key(blinded_global_key.0, &shares);
    WASMPseudonymSessionKeyPair::new(
        WASMPseudonymSessionPublicKey(WASMGroupElement(public.0)),
        WASMPseudonymSessionSecretKey(WASMScalarNonZero(secret.0)),
    )
}

/// Combines attribute session key shares.
#[wasm_bindgen(js_name = makeAttributeSessionKey)]
pub fn wasm_make_attribute_session_key(
    blinded_global_key: WASMBlindedAttributeGlobalSecretKey,
    shares: Vec<WASMAttributeSessionKeyShare>,
) -> WASMAttributeSessionKeyPair {
    let shares: Vec<AttributeSessionKeyShare> = shares.into_iter().map(|s| s.0).collect();
    let (public, secret) = make_attribute_session_key(blinded_global_key.0, &shares);
    WASMAttributeSessionKeyPair::new(
        WASMAttributeSessionPublicKey(WASMGroupElement(public.0)),
        WASMAttributeSessionSecretKey(WASMScalarNonZero(secret.0)),
    )
}

/// Combines session key shares.
#[wasm_bindgen(js_name = makeSessionKeysDistributed)]
pub fn wasm_make_session_keys_distributed(
    blinded_global_keys: WASMBlindedGlobalKeys,
    shares: Vec<WASMSessionKeyShares>,
) -> WASMSessionKeys {
    let keys = make_session_keys_distributed(
        blinded_global_keys.0,
        &shares.into_iter().map(|s| s.0).collect::<Vec<_>>(),
    );
    keys.into()
}

/// Updates a pseudonym session key.
#[wasm_bindgen(js_name = updatePseudonymSessionKey)]
pub fn wasm_update_pseudonym_session_key(
    session_secret_key: &WASMPseudonymSessionSecretKey,
    old_share: &WASMPseudonymSessionKeyShare,
    new_share: &WASMPseudonymSessionKeyShare,
) -> WASMPseudonymSessionKeyPair {
    let (public, secret) =
        update_pseudonym_session_key(session_secret_key.0 .0.into(), old_share.0, new_share.0);
    WASMPseudonymSessionKeyPair::new(
        WASMPseudonymSessionPublicKey(WASMGroupElement(public.0)),
        WASMPseudonymSessionSecretKey(WASMScalarNonZero(secret.0)),
    )
}

/// Updates an attribute session key.
#[wasm_bindgen(js_name = updateAttributeSessionKey)]
pub fn wasm_update_attribute_session_key(
    session_secret_key: &WASMAttributeSessionSecretKey,
    old_share: &WASMAttributeSessionKeyShare,
    new_share: &WASMAttributeSessionKeyShare,
) -> WASMAttributeSessionKeyPair {
    let (public, secret) =
        update_attribute_session_key(session_secret_key.0 .0.into(), old_share.0, new_share.0);
    WASMAttributeSessionKeyPair::new(
        WASMAttributeSessionPublicKey(WASMGroupElement(public.0)),
        WASMAttributeSessionSecretKey(WASMScalarNonZero(secret.0)),
    )
}

/// Updates session keys.
#[wasm_bindgen(js_name = updateSessionKeys)]
pub fn wasm_update_session_keys(
    session_keys: WASMSessionKeys,
    old_shares: WASMSessionKeyShares,
    new_shares: WASMSessionKeyShares,
) -> WASMSessionKeys {
    let updated = update_session_keys(session_keys.into(), old_shares.0, new_shares.0);
    updated.into()
}
