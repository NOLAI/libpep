//! Macros generating the repetitive wrapper-type boilerplate.
//!
//! Every macro reproduces the exposed Python API of the previously hand-written wrappers
//! exactly (method names, signatures, error behavior); a type whose surface deviates from
//! these shapes stays hand-written instead of growing macro parameters.

/// Methods of a plaintext value wrapper (a [`libpep::data::simple::Pseudonym`]-shaped type):
/// point conversions, random generation, byte/hex/hash/lizard/padded encodings, repr and
/// equality.
macro_rules! py_plaintext_impl {
    ($w:ident wraps $core:ident as $name:literal) => {
        #[pymethods]
        #[allow(clippy::wrong_self_convention)]
        impl $w {
            /// Create from a [`PyGroupElement`].
            #[new]
            fn new(x: PyGroupElement) -> Self {
                Self($core::from_point(x.0))
            }

            /// Convert to a [`PyGroupElement`].
            #[pyo3(name = "to_point")]
            fn to_point(&self) -> PyGroupElement {
                self.0.value.into()
            }

            /// Generate a random value.
            #[staticmethod]
            #[pyo3(name = "random")]
            fn random() -> Self {
                let mut rng = rand::rng();
                Self($core::random(&mut rng))
            }

            /// Encode as a byte array.
            #[pyo3(name = "to_bytes")]
            fn encode(&self, py: Python) -> Py<PyAny> {
                PyBytes::new(py, &self.0.to_bytes()).into()
            }

            /// Encode as a hexadecimal string.
            #[pyo3(name = "to_hex")]
            fn as_hex(&self) -> String {
                self.0.to_hex()
            }

            /// Decode from a byte array.
            #[staticmethod]
            #[pyo3(name = "from_bytes")]
            fn decode(bytes: &[u8]) -> Option<Self> {
                $core::from_slice(bytes).map(Self)
            }

            /// Decode from a hexadecimal string.
            #[staticmethod]
            #[pyo3(name = "from_hex")]
            fn from_hex(hex: &str) -> Option<Self> {
                $core::from_hex(hex).map(Self)
            }

            /// Decode from a 64-byte hash value.
            #[staticmethod]
            #[pyo3(name = "from_hash")]
            fn from_hash(v: &[u8]) -> PyResult<Self> {
                if v.len() != 64 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Hash must be 64 bytes",
                    ));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok($core::from_hash(&arr).into())
            }

            /// Decode from a byte array of length 16 using lizard encoding.
            /// This is useful for creating a value from an existing identifier,
            /// as it accepts any 16-byte value.
            #[staticmethod]
            #[pyo3(name = "from_lizard")]
            fn from_lizard(data: &[u8]) -> PyResult<Self> {
                if data.len() != 16 {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "Data must be 16 bytes",
                    ));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(data);
                Ok(Self($core::from_lizard(&arr)))
            }

            /// Encode as a byte array of length 16 using lizard encoding.
            /// Returns `None` if the point is not a valid lizard encoding of a 16-byte value.
            /// If the value was created using `from_lizard`, this will return a valid value,
            /// but otherwise it will most likely return `None`.
            #[pyo3(name = "to_lizard")]
            fn to_lizard(&self, py: Python) -> Option<Py<PyAny>> {
                self.0.to_lizard().map(|x| PyBytes::new(py, &x).into())
            }

            /// Encodes a byte array (up to 15 bytes) using PKCS#7 padding.
            #[staticmethod]
            #[pyo3(name = "from_bytes_padded")]
            fn from_bytes_padded(data: &[u8]) -> PyResult<Self> {
                $core::from_bytes_padded(data).map(Self).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}"))
                })
            }

            /// Encodes a string (up to 15 bytes) using PKCS#7 padding.
            #[staticmethod]
            #[pyo3(name = "from_string_padded")]
            fn from_string_padded(text: &str) -> PyResult<Self> {
                $core::from_string_padded(text).map(Self).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Encoding failed: {e}"))
                })
            }

            /// Decodes back to the original string.
            #[pyo3(name = "to_string_padded")]
            fn to_string_padded(&self) -> PyResult<String> {
                self.0.to_string_padded().map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
                })
            }

            /// Decodes back to the original byte array.
            #[pyo3(name = "to_bytes_padded")]
            fn to_bytes_padded(&self, py: Python) -> PyResult<Py<PyAny>> {
                let result = self.0.to_bytes_padded().map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
                })?;
                Ok(PyBytes::new(py, &result).into())
            }

            fn __repr__(&self) -> String {
                format!(concat!($name, "({})"), self.as_hex())
            }

            fn __str__(&self) -> String {
                self.as_hex()
            }

            fn __eq__(&self, other: &$w) -> bool {
                self.0 == other.0
            }
        }
    };
}

/// Methods of an encrypted value wrapper (a
/// [`libpep::data::simple::EncryptedPseudonym`]-shaped type): ElGamal constructor, byte and
/// base64 encodings, repr and equality.
macro_rules! py_encrypted_impl {
    ($w:ident wraps $core:ident as $name:literal) => {
        #[pymethods]
        #[allow(clippy::wrong_self_convention)]
        impl $w {
            /// Create from an [`PyElGamal`].
            #[new]
            fn new(x: PyElGamal) -> Self {
                Self($core::from(x.0))
            }

            /// Encode as a byte array.
            #[pyo3(name = "to_bytes")]
            fn encode(&self, py: Python) -> Py<PyAny> {
                PyBytes::new(py, &self.0.to_bytes()).into()
            }

            /// Decode from a byte array.
            #[staticmethod]
            #[pyo3(name = "from_bytes")]
            fn decode(v: &[u8]) -> Option<Self> {
                use libpep::elgamal::ElGamal;
                ElGamal::from_slice(v).map(|eg| Self($core::from(eg)))
            }

            /// Encode as a base64 string.
            #[pyo3(name = "to_base64")]
            fn as_base64(&self) -> String {
                self.to_base64()
            }

            /// Decode from a base64 string.
            #[staticmethod]
            #[pyo3(name = "from_base64")]
            fn from_base64(s: &str) -> Option<Self> {
                $core::from_base64(s).map(Self)
            }

            fn __repr__(&self) -> String {
                format!(concat!($name, "({})"), self.to_base64())
            }

            fn __str__(&self) -> String {
                self.to_base64()
            }

            fn __eq__(&self, other: &$w) -> bool {
                self.0 == other.0
            }
        }
    };
}

/// Methods of a session public key wrapper: point conversion plus byte and hex codecs.
macro_rules! py_session_pubkey_impl {
    ($w:ident) => {
        #[pymethods]
        #[allow(clippy::wrong_self_convention)]
        impl $w {
            /// Returns the group element associated with this public key.
            #[pyo3(name = "to_point")]
            fn to_point(&self) -> PyGroupElement {
                self.0
            }

            /// Encodes the public key as a byte array.
            #[pyo3(name = "to_bytes")]
            fn encode(&self, py: Python) -> Py<PyAny> {
                PyBytes::new(py, &self.0 .0.to_bytes()).into()
            }

            /// Decodes a public key from a byte array.
            #[staticmethod]
            #[pyo3(name = "from_bytes")]
            fn decode(bytes: &[u8]) -> Option<Self> {
                GroupElement::from_slice(bytes).map(|x| Self(x.into()))
            }

            /// Encodes the public key as a hexadecimal string.
            #[pyo3(name = "to_hex")]
            fn as_hex(&self) -> String {
                self.0.to_hex()
            }

            /// Decodes a public key from a hexadecimal string.
            #[staticmethod]
            #[pyo3(name = "from_hex")]
            fn from_hex(hex: &str) -> Option<Self> {
                GroupElement::from_hex(hex).map(|x| Self(x.into()))
            }
        }
    };
}

/// Methods of a global public key wrapper: constructor, point conversion, byte and hex
/// codecs, repr and str.
macro_rules! py_global_pubkey_impl {
    ($w:ident as $name:literal) => {
        #[pymethods]
        #[allow(clippy::wrong_self_convention)]
        impl $w {
            /// Creates a new global public key from a group element.
            #[new]
            fn new(x: PyGroupElement) -> Self {
                Self(x.0.into())
            }

            /// Returns the group element associated with this public key.
            #[pyo3(name = "to_point")]
            fn to_point(&self) -> PyGroupElement {
                self.0
            }

            /// Encodes the public key as a byte array.
            #[pyo3(name = "to_bytes")]
            fn encode(&self, py: Python) -> Py<PyAny> {
                PyBytes::new(py, &self.0 .0.to_bytes()).into()
            }

            /// Decodes a public key from a byte array.
            #[staticmethod]
            #[pyo3(name = "from_bytes")]
            fn decode(bytes: &[u8]) -> Option<Self> {
                GroupElement::from_slice(bytes).map(|x| Self(x.into()))
            }

            /// Encodes the public key as a hexadecimal string.
            #[pyo3(name = "to_hex")]
            fn as_hex(&self) -> String {
                self.0.to_hex()
            }

            /// Decodes a public key from a hexadecimal string.
            #[staticmethod]
            #[pyo3(name = "from_hex")]
            fn from_hex(hex: &str) -> Option<Self> {
                let x = GroupElement::from_hex(hex)?;
                Some(Self(x.into()))
            }

            fn __repr__(&self) -> String {
                format!(concat!($name, "::from({})"), self.as_hex())
            }

            fn __str__(&self) -> String {
                self.as_hex()
            }
        }
    };
}

/// Methods of a long plaintext wrapper (a [`libpep::data::long::LongPseudonym`]-shaped type):
/// vector constructor, padded string/byte codecs, block padding and accessors.
macro_rules! py_long_plaintext_impl {
    ($w:ident wraps $core:ident of $item_w:ident($item_core:ident) as $name:literal,
     ctor($arg:ident, doc = $ctor_doc:tt), items($items:ident, doc = $items_doc:tt)) => {
        #[pymethods]
        impl $w {
            #[doc = $ctor_doc]
            #[new]
            fn new($arg: Vec<$item_w>) -> Self {
                let rust_items: Vec<$item_core> = $arg.into_iter().map(|p| p.0).collect();
                Self($core(rust_items))
            }

            #[doc = concat!("Encodes an arbitrary-length string into a `", stringify!($core), "` using PKCS#7 padding.")]
            #[staticmethod]
            #[pyo3(name = "from_string_padded")]
            fn from_string_padded(text: &str) -> Self {
                Self($core::from_string_padded(text))
            }

            #[doc = concat!("Encodes an arbitrary-length byte array into a `", stringify!($core), "` using PKCS#7 padding.")]
            #[staticmethod]
            #[pyo3(name = "from_bytes_padded")]
            fn from_bytes_padded(data: &[u8]) -> Self {
                Self($core::from_bytes_padded(data))
            }

            #[doc = concat!("Decodes the `", stringify!($core), "` back to the original string.")]
            #[pyo3(name = "to_string_padded")]
            fn to_string_padded(&self) -> PyResult<String> {
                self.0.to_string_padded().map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
                })
            }

            #[doc = concat!("Decodes the `", stringify!($core), "` back to the original byte array.")]
            #[pyo3(name = "to_bytes_padded")]
            fn to_bytes_padded(&self, py: Python) -> PyResult<Py<PyAny>> {
                let result = self.0.to_bytes_padded().map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Decoding failed: {e}"))
                })?;
                Ok(PyBytes::new(py, &result).into())
            }

            #[doc = concat!("Pads this ", stringify!($core), " to a target number of blocks for batch unlinkability.")]
            ///
            /// In batch transcryption, all values must have identical structure to prevent
            /// linkability attacks. This method adds external padding blocks to normalize
            /// different-sized values to the same structure.
            ///
            /// Args:
            ///     target_blocks: The desired number of blocks (must be >= current block count)
            ///
            /// Raises:
            ///     ValueError: If the current number of blocks exceeds the target
            #[pyo3(name = "pad_to")]
            fn pad_to(&self, target_blocks: usize) -> PyResult<Self> {
                self.0.pad_to(target_blocks).map(Self).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Padding failed: {e}"))
                })
            }

            #[doc = $items_doc]
            fn $items(&self) -> Vec<$item_w> {
                self.0 .0.iter().map(|p| $item_w(*p)).collect()
            }

            /// Get the number of blocks.
            fn __len__(&self) -> usize {
                self.0 .0.len()
            }

            fn __repr__(&self) -> String {
                format!(concat!($name, "({} blocks)"), self.0 .0.len())
            }

            fn __eq__(&self, other: &$w) -> bool {
                self.0 == other.0
            }
        }
    };
}

/// Methods of a long encrypted wrapper (a [`libpep::data::long::LongEncryptedPseudonym`]-shaped
/// type): vector constructor, pipe-delimited serialization and accessors.
macro_rules! py_long_encrypted_impl {
    ($w:ident wraps $core:ident of $item_w:ident($item_core:ident) as $name:literal,
     ctor($arg:ident, doc = $ctor_doc:tt), items($items:ident, doc = $items_doc:tt)) => {
        #[pymethods]
        impl $w {
            #[doc = $ctor_doc]
            #[new]
            fn new($arg: Vec<$item_w>) -> Self {
                let rust_items: Vec<$item_core> = $arg.into_iter().map(|p| p.0).collect();
                Self($core(rust_items))
            }

            /// Serializes to a pipe-delimited base64 string.
            #[pyo3(name = "serialize")]
            fn serialize(&self) -> String {
                self.0.serialize()
            }

            /// Deserializes from a pipe-delimited base64 string.
            #[staticmethod]
            #[pyo3(name = "deserialize")]
            fn deserialize(s: &str) -> PyResult<Self> {
                $core::deserialize(s).map(Self).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Deserialization failed: {e}"))
                })
            }

            #[doc = $items_doc]
            fn $items(&self) -> Vec<$item_w> {
                self.0 .0.iter().map(|p| $item_w(*p)).collect()
            }

            /// Get the number of blocks.
            fn __len__(&self) -> usize {
                self.0 .0.len()
            }

            fn __repr__(&self) -> String {
                format!(concat!($name, "({} blocks)"), self.0 .0.len())
            }

            fn __eq__(&self, other: &$w) -> bool {
                self.0 == other.0
            }
        }
    };
}

/// Methods of a scalar-backed key wrapper (session key shares, blinding factors and blinded
/// keys): scalar constructor, byte and hex codecs, repr and equality.
macro_rules! py_scalar_key_impl {
    ($w:ident wraps $core:ident as $name:literal) => {
        #[pymethods]
        #[allow(clippy::wrong_self_convention)]
        impl $w {
            #[new]
            fn new(x: PyScalarNonZero) -> Self {
                $w($core::from_scalar(x.0))
            }

            #[pyo3(name = "to_bytes")]
            fn encode(&self, py: Python) -> Py<PyAny> {
                PyBytes::new(py, &self.0.to_bytes()).into()
            }

            #[staticmethod]
            #[pyo3(name = "from_bytes")]
            fn decode(bytes: &[u8]) -> Option<$w> {
                $core::from_slice(bytes).map($w)
            }

            #[pyo3(name = "to_hex")]
            fn as_hex(&self) -> String {
                self.0.to_hex()
            }

            #[staticmethod]
            #[pyo3(name = "from_hex")]
            fn from_hex(hex: &str) -> Option<$w> {
                $core::from_hex(hex).map($w)
            }

            fn __repr__(&self) -> String {
                format!(concat!($name, "::from({})"), self.as_hex())
            }

            fn __str__(&self) -> String {
                self.as_hex()
            }

            fn __eq__(&self, other: &$w) -> bool {
                self.0.value() == other.0.value()
            }
        }
    };
}

/// Generates a polymorphic dispatch function: each arm tries to extract the given Python
/// argument types in order (nested, so a cheap first extract short-circuits an expensive
/// second one) and runs its body, which is expected to `return`; falling through all arms
/// raises a `TypeError` with the given message.
macro_rules! py_dispatch {
    (
        $(#[$fmeta:meta])*
        fn $f:ident($first:ident $(, $arg:ident)*) with $py:ident err $err:literal {
            $( $(#[$cfg:meta])* ($($v:ident in $e:ident: $t:ty),+) => $body:block )+
        }
    ) => {
        $(#[$fmeta])*
        pub fn $f($first: &Bound<PyAny> $(, $arg: &Bound<PyAny>)*) -> PyResult<Py<PyAny>> {
            #[allow(unused_variables)]
            let $py = $first.py();
            $(
                $(#[$cfg])*
                py_dispatch!(@arm ($($v in $e: $t),+) => $body);
            )+
            Err(PyTypeError::new_err($err))
        }
    };
    (@arm ($v:ident in $e:ident: $t:ty) => $body:block) => {
        if let Ok($v) = $e.extract::<$t>() { $body }
    };
    (@arm ($v:ident in $e:ident: $t:ty, $($vr:ident in $er:ident: $tr:ty),+) => $body:block) => {
        if let Ok($v) = $e.extract::<$t>() {
            py_dispatch!(@arm ($($vr in $er: $tr),+) => $body);
        }
    };
}

pub(crate) use {
    py_dispatch, py_encrypted_impl, py_global_pubkey_impl, py_long_encrypted_impl,
    py_long_plaintext_impl, py_plaintext_impl, py_scalar_key_impl, py_session_pubkey_impl,
};
