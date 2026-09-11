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
                use libpep::elgamal::arithmetic::group_elements::GroupElement;
                GroupElement::from_slice(&bytes).map(|x| Self(x.into()))
            }

            #[wasm_bindgen(js_name = toHex)]
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            #[wasm_bindgen(js_name = fromHex)]
            pub fn from_hex(hex: &str) -> Option<Self> {
                use libpep::elgamal::arithmetic::group_elements::GroupElement;
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

/// Methods of a long plaintext wrapper (a [`libpep::data::long::LongPseudonym`]-shaped type):
/// vector constructor, padded string/byte codecs, block padding and accessors.
macro_rules! wasm_long_plaintext_impl {
    ($w:ident wraps $core:ident of $item_w:ident($item_core:ident) as $js:ident,
     ctor($arg:ident, doc = $ctor_doc:tt), items($items:ident, doc = $items_doc:tt)) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[doc = $ctor_doc]
            #[wasm_bindgen(constructor)]
            pub fn new($arg: Vec<$item_w>) -> Self {
                let rust_items: Vec<$item_core> = $arg.into_iter().map(|p| p.0).collect();
                Self($core(rust_items))
            }

            #[doc = concat!("Encodes an arbitrary-length string into a `", stringify!($core), "` using PKCS#7 padding.")]
            #[wasm_bindgen(js_name = fromStringPadded)]
            pub fn from_string_padded(text: &str) -> $w {
                Self($core::from_string_padded(text))
            }

            #[doc = concat!("Encodes an arbitrary-length byte array into a `", stringify!($core), "` using PKCS#7 padding.")]
            #[wasm_bindgen(js_name = fromBytesPadded)]
            pub fn from_bytes_padded(data: &[u8]) -> $w {
                Self($core::from_bytes_padded(data))
            }

            #[doc = concat!("Decodes the `", stringify!($core), "` back to the original string.")]
            #[wasm_bindgen(js_name = toStringPadded)]
            pub fn to_string_padded(&self) -> Result<String, JsError> {
                self.0
                    .to_string_padded()
                    .map_err(|e| JsError::new(&format!("Decoding failed: {e}")))
            }

            #[doc = concat!("Decodes the `", stringify!($core), "` back to the original byte array.")]
            #[wasm_bindgen(js_name = toBytesPadded)]
            pub fn to_bytes_padded(&self) -> Result<Vec<u8>, JsError> {
                self.0
                    .to_bytes_padded()
                    .map_err(|e| JsError::new(&format!("Decoding failed: {e}")))
            }

            #[doc = concat!("Pads this ", stringify!($core), " to a target number of blocks for batch unlinkability.")]
            ///
            /// In batch transcryption, all values must have identical structure to prevent
            /// linkability attacks. This method adds external padding blocks to normalize
            /// different-sized values to the same structure.
            #[wasm_bindgen(js_name = padTo)]
            pub fn pad_to(&self, target_blocks: usize) -> Result<$w, JsError> {
                self.0
                    .pad_to(target_blocks)
                    .map(Self)
                    .map_err(|e| JsError::new(&format!("Padding failed: {e}")))
            }

            #[doc = $items_doc]
            #[wasm_bindgen(getter)]
            pub fn $items(&self) -> Vec<$item_w> {
                self.0 .0.iter().map(|p| $item_w(*p)).collect()
            }

            /// Get the number of blocks.
            #[wasm_bindgen(getter)]
            pub fn length(&self) -> usize {
                self.0 .0.len()
            }

            /// Clone this object.
            #[wasm_bindgen(js_name = clone)]
            pub fn clone_js(&self) -> Self {
                self.clone()
            }
        }
    };
}

/// Methods of a long encrypted wrapper (a [`libpep::data::long::LongEncryptedPseudonym`]-shaped
/// type): vector constructor, pipe-delimited serialization and accessors.
macro_rules! wasm_long_encrypted_impl {
    ($w:ident wraps $core:ident of $item_w:ident($item_core:ident) as $js:ident,
     ctor($arg:ident, doc = $ctor_doc:tt), items($items:ident as $items_js:ident, doc = $items_doc:tt)) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[doc = $ctor_doc]
            #[wasm_bindgen(constructor)]
            pub fn new($arg: Vec<$item_w>) -> Self {
                let rust_items: Vec<$item_core> = $arg.into_iter().map(|p| p.0).collect();
                Self($core(rust_items))
            }

            /// Serializes to a pipe-delimited base64 string.
            #[wasm_bindgen]
            pub fn serialize(&self) -> String {
                self.0.serialize()
            }

            /// Deserializes from a pipe-delimited base64 string.
            #[wasm_bindgen]
            pub fn deserialize(s: &str) -> Result<$w, JsError> {
                $core::deserialize(s)
                    .map(Self)
                    .map_err(|e| JsError::new(&format!("Deserialization failed: {e}")))
            }

            #[doc = $items_doc]
            #[wasm_bindgen(getter, js_name = $items_js)]
            pub fn $items(&self) -> Vec<$item_w> {
                self.0 .0.iter().map(|p| $item_w(*p)).collect()
            }

            /// Get the number of blocks.
            #[wasm_bindgen(getter)]
            pub fn length(&self) -> usize {
                self.0 .0.len()
            }

            /// Clone this object.
            #[wasm_bindgen(js_name = clone)]
            pub fn clone_js(&self) -> Self {
                self.clone()
            }
        }
    };
}

/// Methods of a scalar-backed key wrapper (session key shares, blinding factors and blinded
/// keys): scalar constructor plus byte and hex codecs.
macro_rules! wasm_scalar_key_impl {
    ($w:ident wraps $core:ident as $js:literal) => {
        #[wasm_bindgen(js_class = $js)]
        impl $w {
            #[wasm_bindgen(constructor)]
            pub fn new(x: WASMScalarNonZero) -> Self {
                $w($core::from(x.0))
            }

            #[wasm_bindgen(js_name = toBytes)]
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.to_bytes().to_vec()
            }

            #[wasm_bindgen(js_name = fromBytes)]
            pub fn from_bytes(bytes: Vec<u8>) -> Option<$w> {
                $core::from_slice(&bytes).map($w)
            }

            #[wasm_bindgen(js_name = toHex)]
            pub fn to_hex(self) -> String {
                self.0.to_hex()
            }

            #[wasm_bindgen(js_name = fromHex)]
            pub fn from_hex(hex: &str) -> Option<$w> {
                $core::from_hex(hex).map($w)
            }
        }
    };
}

/// Generates the session encrypt/decrypt function triple (encrypt, decrypt under elgamal3
/// returning Option, decrypt otherwise) for one plaintext/encrypted type pair.
macro_rules! wasm_session_crypt_fns {
    ($($(#[$cfg:meta])* fns($enc_js:literal $encf:ident, $dec_js:literal $decf:ident)
        for $m:ty => $e:ty, key($kpub:ty => $ckpub:ident, $ksec:ty => $cksec:ident);)+) => {$(
        /// Encrypt using a session public key.
        $(#[$cfg])*
        #[wasm_bindgen(js_name = $enc_js)]
        pub fn $encf(m: &$m, public_key: &$kpub) -> $e {
            let mut rng = rand::rng();
            encrypt(&m.0, &<$ckpub as libpep::keys::ElGamalPublicKey>::from_point(*public_key.0), &mut rng).into()
        }

        /// Decrypt using a session secret key.
        $(#[$cfg])*
        #[cfg(feature = "elgamal3")]
        #[wasm_bindgen(js_name = $dec_js)]
        pub fn $decf(v: &$e, secret_key: &$ksec) -> Option<$m> {
            decrypt(&v.0, &<$cksec as libpep::keys::ElGamalSecretKey>::from_scalar(*secret_key.0)).map(|x| x.into())
        }

        /// Decrypt using a session secret key.
        $(#[$cfg])*
        #[cfg(not(feature = "elgamal3"))]
        #[wasm_bindgen(js_name = $dec_js)]
        pub fn $decf(v: &$e, secret_key: &$ksec) -> $m {
            decrypt(&v.0, &<$cksec as libpep::keys::ElGamalSecretKey>::from_scalar(*secret_key.0)).into()
        }
    )+};
}

/// Generates the global (offline) encrypt/decrypt function triple for one
/// plaintext/encrypted type pair.
macro_rules! wasm_global_crypt_fns {
    ($(fns($enc_js:literal $encf:ident, $dec_js:literal $decf:ident)
        for $m:ty => $e:ty, key($kpub:ty => $ckpub:ident, $ksec:ty => $cksec:ident);)+) => {$(
        /// Encrypt using a global public key (offline encryption).
        #[cfg(feature = "offline")]
        #[wasm_bindgen(js_name = $enc_js)]
        pub fn $encf(m: &$m, public_key: &$kpub) -> $e {
            let mut rng = rand::rng();
            let key = <$ckpub as libpep::keys::ElGamalPublicKey>::from_point(*public_key.0);
            encrypt_global(&m.0, &key, &mut rng).into()
        }

        /// Decrypt using a global secret key (offline decryption).
        #[cfg(all(feature = "offline", feature = "insecure", feature = "elgamal3"))]
        #[wasm_bindgen(js_name = $dec_js)]
        pub fn $decf(v: &$e, secret_key: &$ksec) -> Option<$m> {
            let key = <$cksec as libpep::keys::ElGamalSecretKey>::from_scalar(*secret_key.0);
            decrypt_global(&v.0, &key).map(|x| x.into())
        }

        /// Decrypt using a global secret key (offline decryption).
        #[cfg(all(feature = "offline", feature = "insecure", not(feature = "elgamal3")))]
        #[wasm_bindgen(js_name = $dec_js)]
        pub fn $decf(v: &$e, secret_key: &$ksec) -> $m {
            let key = <$cksec as libpep::keys::ElGamalSecretKey>::from_scalar(*secret_key.0);
            decrypt_global(&v.0, &key).into()
        }
    )+};
}

pub(crate) use {
    wasm_encrypted_impl, wasm_global_crypt_fns, wasm_long_encrypted_impl, wasm_long_plaintext_impl,
    wasm_pair_impl, wasm_plaintext_impl, wasm_point_key_impl, wasm_scalar_key_impl,
    wasm_session_crypt_fns,
};
