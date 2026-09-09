//! Macros generating the repetitive wrapper-type boilerplate.
//!
//! Every macro reproduces the exposed JavaScript API of the previously hand-written
//! wrappers byte-exactly; a type whose surface deviates from these shapes stays
//! hand-written instead of growing macro parameters.

/// Methods of a plaintext value wrapper (a [`libpep::data::simple::Pseudonym`]-shaped type):
/// point conversions, random generation, byte/hex/hash/lizard/padded encodings.
macro_rules! wasm_plaintext_impl {
    ($w:ident wraps $core:ty as $js:literal) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[wasm_bindgen(constructor)]
            pub fn new(x: WASMGroupElement) -> Self {
                Self(<$core>::from_point(x.0))
            }

            #[wasm_bindgen(js_name = toPoint)]
            pub fn to_point(&self) -> WASMGroupElement {
                self.0.value.into()
            }

            #[wasm_bindgen]
            pub fn random() -> Self {
                let mut rng = rand::rng();
                Self(<$core>::random(&mut rng))
            }

            #[wasm_bindgen(js_name = toBytes)]
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes().to_vec()
            }

            #[wasm_bindgen(js_name = toHex)]
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            #[wasm_bindgen(js_name = fromBytes)]
            pub fn from_bytes(bytes: Vec<u8>) -> Option<$w> {
                <$core>::from_slice(&bytes).map(Self)
            }

            #[wasm_bindgen(js_name = fromHex)]
            pub fn from_hex(hex: &str) -> Option<$w> {
                <$core>::from_hex(hex).map(Self)
            }

            #[wasm_bindgen(js_name = fromHash)]
            pub fn from_hash(v: Vec<u8>) -> $w {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&v);
                <$core>::from_hash(&arr).into()
            }

            #[wasm_bindgen(js_name = fromLizard)]
            pub fn from_lizard(data: Vec<u8>) -> Option<$w> {
                if data.len() != 16 {
                    return None;
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&data);
                Some(Self(<$core>::from_lizard(&arr)))
            }

            #[wasm_bindgen(js_name = toLizard)]
            pub fn to_lizard(&self) -> Option<Vec<u8>> {
                self.0.to_lizard().map(|x| x.to_vec())
            }

            #[wasm_bindgen(js_name = fromBytesPadded)]
            pub fn from_bytes_padded(data: Vec<u8>) -> Option<$w> {
                <$core>::from_bytes_padded(&data).ok().map(Self)
            }

            #[wasm_bindgen(js_name = fromStringPadded)]
            pub fn from_string_padded(text: &str) -> Option<$w> {
                <$core>::from_string_padded(text).ok().map(Self)
            }

            #[wasm_bindgen(js_name = toStringPadded)]
            pub fn to_string_padded(&self) -> Option<String> {
                self.0.to_string_padded().ok()
            }

            #[wasm_bindgen(js_name = toBytesPadded)]
            pub fn to_bytes_padded(&self) -> Option<Vec<u8>> {
                self.0.to_bytes_padded().ok()
            }
        }
    };
}

/// Methods of an encrypted value wrapper (a [`libpep::data::simple::EncryptedPseudonym`]-shaped
/// type): ElGamal constructor plus byte and base64 encodings.
macro_rules! wasm_encrypted_impl {
    ($w:ident wraps $core:ty as $js:literal) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[wasm_bindgen(constructor)]
            pub fn new(x: WASMElGamal) -> Self {
                Self(<$core>::from(x.0))
            }

            #[wasm_bindgen(js_name = toBytes)]
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes().to_vec()
            }

            #[wasm_bindgen(js_name = fromBytes)]
            pub fn from_bytes(v: Vec<u8>) -> Option<$w> {
                <$core>::from_slice(&v).map(Self)
            }

            #[wasm_bindgen(js_name = toBase64)]
            pub fn to_base64(&self) -> String {
                self.0.to_base64()
            }

            #[wasm_bindgen(js_name = fromBase64)]
            pub fn from_base64(s: &str) -> Option<$w> {
                <$core>::from_base64(s).map(Self)
            }
        }
    };
}

/// Methods of a public-key wrapper backed by a group element: JS constructor from a
/// group element plus byte and hex encodings.
macro_rules! wasm_point_key_impl {
    ($w:ident as $js:literal) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[wasm_bindgen(constructor)]
            pub fn new(x: WASMGroupElement) -> Self {
                Self(x)
            }

            #[wasm_bindgen(js_name = toBytes)]
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0 .0.to_bytes().to_vec()
            }

            #[wasm_bindgen(js_name = fromBytes)]
            pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
                use libpep::arithmetic::group_elements::GroupElement;
                GroupElement::from_slice(&bytes).map(|x| Self(x.into()))
            }

            #[wasm_bindgen(js_name = toHex)]
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            #[wasm_bindgen(js_name = fromHex)]
            pub fn from_hex(hex: &str) -> Option<Self> {
                use libpep::arithmetic::group_elements::GroupElement;
                GroupElement::from_hex(hex).map(|x| Self(x.into()))
            }
        }
    };
}

/// Methods of a two-field wrapper: JS getters for both fields, and a constructor that is
/// either exposed to JS (`js_constructor`) or Rust-only.
macro_rules! wasm_pair_impl {
    ($w:ident as $js:literal { $f1:ident: $t1:ty, $f2:ident: $t2:ty }, js_constructor) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[wasm_bindgen(constructor)]
            pub fn new($f1: $t1, $f2: $t2) -> Self {
                Self { $f1, $f2 }
            }

            #[wasm_bindgen(getter)]
            pub fn $f1(&self) -> $t1 {
                self.$f1
            }

            #[wasm_bindgen(getter)]
            pub fn $f2(&self) -> $t2 {
                self.$f2
            }
        }
    };
    ($w:ident as $js:literal { $f1:ident: $t1:ty, $f2:ident: $t2:ty }) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[wasm_bindgen(getter)]
            pub fn $f1(&self) -> $t1 {
                self.$f1
            }

            #[wasm_bindgen(getter)]
            pub fn $f2(&self) -> $t2 {
                self.$f2
            }
        }

        impl $w {
            pub fn new($f1: $t1, $f2: $t2) -> Self {
                Self { $f1, $f2 }
            }
        }
    };
}

pub(crate) use {wasm_encrypted_impl, wasm_pair_impl, wasm_plaintext_impl, wasm_point_key_impl};
