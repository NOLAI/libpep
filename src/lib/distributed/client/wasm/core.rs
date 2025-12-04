use super::super::client::PEPClient;
use super::super::offline::OfflinePEPClient;
use super::keys::{
    WASMAttributeSessionKeyShare, WASMPseudonymSessionKeyShare, WASMSessionKeyShares,
};
use crate::core::keys::*;
#[cfg(feature = "long")]
use crate::core::long::wasm::data::{
    WASMLongAttribute, WASMLongEncryptedAttribute, WASMLongEncryptedPseudonym, WASMLongPseudonym,
};
use crate::core::wasm::data::{
    WASMAttribute, WASMEncryptedAttribute, WASMEncryptedPseudonym, WASMPseudonym,
};
use crate::core::wasm::keys::WASMGlobalPublicKeys;
use crate::core::wasm::keys::WASMSessionKeys;
use crate::distributed::server::keys::*;
use crate::distributed::server::setup::BlindedGlobalKeys;
use crate::distributed::server::wasm::setup::WASMBlindedGlobalKeys;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A PEP client.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PEPClient)]
pub struct WASMPEPClient(PEPClient);

#[wasm_bindgen(js_class = PEPClient)]
impl WASMPEPClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        blinded_global_keys: &WASMBlindedGlobalKeys,
        session_key_shares: Vec<WASMSessionKeyShares>,
    ) -> Self {
        let shares: Vec<SessionKeyShares> = session_key_shares
            .into_iter()
            .map(|x| SessionKeyShares {
                pseudonym: PseudonymSessionKeyShare(x.0.pseudonym.0),
                attribute: AttributeSessionKeyShare(x.0.attribute.0),
            })
            .collect();
        let blinded_keys = BlindedGlobalKeys {
            pseudonym: blinded_global_keys.0.pseudonym,
            attribute: blinded_global_keys.0.attribute,
        };
        Self(PEPClient::new(blinded_keys, &shares))
    }

    #[wasm_bindgen(js_name = restore)]
    pub fn wasm_restore(keys: &WASMSessionKeys) -> Self {
        Self(PEPClient::restore((*keys).into()))
    }

    #[wasm_bindgen(js_name = dump)]
    pub fn wasm_dump(&self) -> WASMSessionKeys {
        (*self.dump()).into()
    }

    #[wasm_bindgen(js_name = updatePseudonymSessionSecretKey)]
    pub fn wasm_update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: WASMPseudonymSessionKeyShare,
        new_key_share: WASMPseudonymSessionKeyShare,
    ) {
        self.0
            .update_pseudonym_session_secret_key(old_key_share.0, new_key_share.0);
    }

    #[wasm_bindgen(js_name = updateAttributeSessionSecretKey)]
    pub fn wasm_update_attribute_session_secret_key(
        &mut self,
        old_key_share: WASMAttributeSessionKeyShare,
        new_key_share: WASMAttributeSessionKeyShare,
    ) {
        self.0
            .update_attribute_session_secret_key(old_key_share.0, new_key_share.0);
    }

    #[wasm_bindgen(js_name = updateSessionSecretKeys)]
    pub fn wasm_update_session_secret_keys(
        &mut self,
        old_key_shares: WASMSessionKeyShares,
        new_key_shares: WASMSessionKeyShares,
    ) {
        self.0
            .update_session_secret_keys(old_key_shares.0, new_key_shares.0);
    }

    #[wasm_bindgen(js_name = decryptPseudonym)]
    #[cfg(feature = "elgamal3")]
    pub fn wasm_decrypt_pseudonym(
        &self,
        encrypted: &WASMEncryptedPseudonym,
    ) -> Option<WASMPseudonym> {
        self.decrypt_pseudonym(&encrypted.0)
            .map(WASMPseudonym::from)
    }

    #[wasm_bindgen(js_name = decryptPseudonym)]
    #[cfg(not(feature = "elgamal3"))]
    pub fn wasm_decrypt_pseudonym(&self, encrypted: &WASMEncryptedPseudonym) -> WASMPseudonym {
        WASMPseudonym::from(self.decrypt_pseudonym(&encrypted.0))
    }

    #[wasm_bindgen(js_name = decryptData)]
    #[cfg(feature = "elgamal3")]
    pub fn wasm_decrypt_data(&self, encrypted: &WASMEncryptedAttribute) -> Option<WASMAttribute> {
        self.decrypt_attribute(&encrypted.0)
            .map(WASMAttribute::from)
    }

    #[wasm_bindgen(js_name = decryptData)]
    #[cfg(not(feature = "elgamal3"))]
    pub fn wasm_decrypt_data(&self, encrypted: &WASMEncryptedAttribute) -> WASMAttribute {
        WASMAttribute::from(self.decrypt_attribute(&encrypted.0))
    }

    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMAttribute) -> WASMEncryptedAttribute {
        let mut rng = rand::rng();
        WASMEncryptedAttribute::from(self.encrypt_attribute(&message.0, &mut rng))
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMEncryptedPseudonym(self.encrypt_pseudonym(&message.0, &mut rng))
    }

    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongPseudonym)]
    pub fn wasm_encrypt_long_pseudonym(
        &self,
        message: &WASMLongPseudonym,
    ) -> WASMLongEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMLongEncryptedPseudonym::from(self.encrypt_long_pseudonym(&message.0, &mut rng))
    }

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = decryptLongPseudonym)]
    pub fn wasm_decrypt_long_pseudonym(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
    ) -> Option<WASMLongPseudonym> {
        self.decrypt_long_pseudonym(&encrypted.0)
            .map(WASMLongPseudonym::from)
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = decryptLongPseudonym)]
    pub fn wasm_decrypt_long_pseudonym(
        &self,
        encrypted: &WASMLongEncryptedPseudonym,
    ) -> WASMLongPseudonym {
        WASMLongPseudonym::from(self.decrypt_long_pseudonym(&encrypted.0))
    }

    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongData)]
    pub fn wasm_encrypt_long_data(
        &self,
        message: &WASMLongAttribute,
    ) -> WASMLongEncryptedAttribute {
        let mut rng = rand::rng();
        WASMLongEncryptedAttribute::from(self.encrypt_long_attribute(&message.0, &mut rng))
    }

    #[cfg(all(feature = "long", feature = "elgamal3"))]
    #[wasm_bindgen(js_name = decryptLongData)]
    pub fn wasm_decrypt_long_data(
        &self,
        encrypted: &WASMLongEncryptedAttribute,
    ) -> Option<WASMLongAttribute> {
        self.decrypt_long_attribute(&encrypted.0)
            .map(WASMLongAttribute::from)
    }

    #[cfg(all(feature = "long", not(feature = "elgamal3")))]
    #[wasm_bindgen(js_name = decryptLongData)]
    pub fn wasm_decrypt_long_data(
        &self,
        encrypted: &WASMLongEncryptedAttribute,
    ) -> WASMLongAttribute {
        WASMLongAttribute::from(self.decrypt_long_attribute(&encrypted.0))
    }
}

/// An offline PEP client.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = OfflinePEPClient)]
pub struct WASMOfflinePEPClient(OfflinePEPClient);

#[wasm_bindgen(js_class = OfflinePEPClient)]
impl WASMOfflinePEPClient {
    #[wasm_bindgen(constructor)]
    pub fn new(global_keys: &WASMGlobalPublicKeys) -> Self {
        let global_keys = GlobalPublicKeys {
            pseudonym: PseudonymGlobalPublicKey(*global_keys.pseudonym().0),
            attribute: AttributeGlobalPublicKey(*global_keys.attribute().0),
        };
        Self(OfflinePEPClient::new(global_keys))
    }

    #[wasm_bindgen(js_name = encryptData)]
    pub fn wasm_encrypt_data(&self, message: &WASMAttribute) -> WASMEncryptedAttribute {
        let mut rng = rand::rng();
        WASMEncryptedAttribute::from(self.encrypt_attribute(&message.0, &mut rng))
    }

    #[wasm_bindgen(js_name = encryptPseudonym)]
    pub fn wasm_encrypt_pseudonym(&self, message: &WASMPseudonym) -> WASMEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMEncryptedPseudonym(self.encrypt_pseudonym(&message.0, &mut rng))
    }

    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongPseudonym)]
    pub fn wasm_encrypt_long_pseudonym(
        &self,
        message: &WASMLongPseudonym,
    ) -> WASMLongEncryptedPseudonym {
        let mut rng = rand::rng();
        WASMLongEncryptedPseudonym::from(self.encrypt_long_pseudonym(&message.0, &mut rng))
    }

    #[cfg(feature = "long")]
    #[wasm_bindgen(js_name = encryptLongData)]
    pub fn wasm_encrypt_long_data(
        &self,
        message: &WASMLongAttribute,
    ) -> WASMLongEncryptedAttribute {
        let mut rng = rand::rng();
        WASMLongEncryptedAttribute::from(self.encrypt_long_attribute(&message.0, &mut rng))
    }

    // TODO: Implement encrypt_json and decrypt_json for OfflinePEPClient
    // These methods were removed during refactoring and need to be re-implemented
}
