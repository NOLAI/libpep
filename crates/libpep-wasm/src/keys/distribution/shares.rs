use super::blinding::{
    WASMBlindedAttributeGlobalSecretKey, WASMBlindedGlobalKeys,
    WASMBlindedPseudonymGlobalSecretKey, WASMBlindingFactor,
};
use crate::arithmetic::group_elements::WASMGroupElement;
use crate::arithmetic::scalars::WASMScalarNonZero;
use crate::keys::types::{
    WASMAttributeSessionKeyPair, WASMAttributeSessionPublicKey, WASMAttributeSessionSecretKey,
    WASMPseudonymSessionKeyPair, WASMPseudonymSessionPublicKey, WASMPseudonymSessionSecretKey,
    WASMSessionKeys,
};
use crate::macros::wasm_scalar_key_impl;
use derive_more::{Deref, From, Into};
use libpep::arithmetic::scalars::ScalarTraits;
use libpep::client::distributed::{
    make_attribute_session_key, make_pseudonym_session_key, make_session_keys_distributed,
    update_attribute_session_key, update_pseudonym_session_key, update_session_keys,
};
use libpep::factors::{AttributeRekeyFactor, PseudonymRekeyFactor};
use libpep::keys::distribution::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_shares,
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
use libpep::keys::SecretKey;
use wasm_bindgen::prelude::*;

/// A pseudonym session key share.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymSessionKeyShare)]
pub struct WASMPseudonymSessionKeyShare(pub(crate) PseudonymSessionKeyShare);

wasm_scalar_key_impl!(WASMPseudonymSessionKeyShare wraps PseudonymSessionKeyShare as "PseudonymSessionKeyShare");

/// An attribute session key share.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = AttributeSessionKeyShare)]
pub struct WASMAttributeSessionKeyShare(pub(crate) AttributeSessionKeyShare);

wasm_scalar_key_impl!(WASMAttributeSessionKeyShare wraps AttributeSessionKeyShare as "AttributeSessionKeyShare");

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
        WASMPseudonymSessionPublicKey(WASMGroupElement(*public)),
        WASMPseudonymSessionSecretKey(WASMScalarNonZero(*secret.value())),
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
        WASMAttributeSessionPublicKey(WASMGroupElement(*public)),
        WASMAttributeSessionSecretKey(WASMScalarNonZero(*secret.value())),
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
        WASMPseudonymSessionPublicKey(WASMGroupElement(*public)),
        WASMPseudonymSessionSecretKey(WASMScalarNonZero(*secret.value())),
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
        WASMAttributeSessionPublicKey(WASMGroupElement(*public)),
        WASMAttributeSessionSecretKey(WASMScalarNonZero(*secret.value())),
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

/// Creates a pseudonym session key share.
#[wasm_bindgen(js_name = makePseudonymSessionKeyShare)]
pub fn wasm_make_pseudonym_session_key_share(
    rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMPseudonymSessionKeyShare {
    WASMPseudonymSessionKeyShare(make_pseudonym_session_key_share(
        &PseudonymRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Creates an attribute session key share.
#[wasm_bindgen(js_name = makeAttributeSessionKeyShare)]
pub fn wasm_make_attribute_session_key_share(
    rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMAttributeSessionKeyShare {
    WASMAttributeSessionKeyShare(make_attribute_session_key_share(
        &AttributeRekeyFactor::from(rekey_factor.0),
        &blinding_factor.0,
    ))
}

/// Creates session key shares.
#[wasm_bindgen(js_name = makeSessionKeyShares)]
pub fn wasm_make_session_key_shares(
    pseudonym_rekey_factor: &WASMScalarNonZero,
    attribute_rekey_factor: &WASMScalarNonZero,
    blinding_factor: &WASMBlindingFactor,
) -> WASMSessionKeyShares {
    WASMSessionKeyShares(make_session_key_shares(
        &PseudonymRekeyFactor::from(pseudonym_rekey_factor.0),
        &AttributeRekeyFactor::from(attribute_rekey_factor.0),
        &blinding_factor.0,
    ))
}
