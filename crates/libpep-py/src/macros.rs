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
                use libpep::core::elgamal::ElGamal;
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

pub(crate) use {py_encrypted_impl, py_plaintext_impl};
