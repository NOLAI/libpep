use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::WASMElGamal;
use crate::macros::{wasm_encrypted_impl, wasm_plaintext_impl};
use derive_more::{Deref, From, Into};
use libpep::data::padding::Padded;
use libpep::data::simple::*;
use wasm_bindgen::prelude::*;

/// A pseudonym that can be used to identify a user.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = Pseudonym)]
pub struct WASMPseudonym(pub(crate) Pseudonym);
wasm_plaintext_impl!(WASMPseudonym wraps Pseudonym as "Pseudonym");

/// An attribute which should not be identifiable.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = Attribute)]
pub struct WASMAttribute(pub(crate) Attribute);
wasm_plaintext_impl!(WASMAttribute wraps Attribute as "Attribute");

/// An encrypted pseudonym.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = EncryptedPseudonym)]
pub struct WASMEncryptedPseudonym(pub(crate) EncryptedPseudonym);
wasm_encrypted_impl!(WASMEncryptedPseudonym wraps EncryptedPseudonym as "EncryptedPseudonym");

/// An encrypted attribute.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = EncryptedAttribute)]
pub struct WASMEncryptedAttribute(pub(crate) EncryptedAttribute);
wasm_encrypted_impl!(WASMEncryptedAttribute wraps EncryptedAttribute as "EncryptedAttribute");
