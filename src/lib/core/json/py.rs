//! Python bindings for PEP JSON encryption.

use crate::core::json::builder::PEPJSONBuilder;
use crate::core::json::core::{EncryptedPEPJSONValue, JsonError, PEPJSONValue};
use crate::core::json::structure::JSONStructure;
use crate::core::json::transcryption::transcrypt_batch;
use crate::core::keys::SessionKeys;
use crate::core::long::data::LongPseudonym;
use crate::core::padding::Padded;
use crate::core::py::keys::{PyGlobalSecretKeys, PyPseudonymizationSecret};
use crate::core::transcryption::contexts::{
    EncryptionContext, PseudonymizationDomain, TranscryptionInfo,
};
use crate::core::transcryption::secrets::EncryptionSecret;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyList, PyString};
use serde_json::Value;
use std::collections::HashMap;

/// A PEP JSON value that can be encrypted.
///
/// This wraps JSON values where primitive types are stored as unencrypted PEP types.
#[pyclass(name = "PEPJSONValue")]
#[derive(Clone)]
pub struct PyPEPJSONValue(pub(crate) PEPJSONValue);

#[pymethods]
impl PyPEPJSONValue {
    /// Create a PEPJSONValue from a regular Python object.
    ///
    /// Args:
    ///     value: A JSON-serializable Python object
    ///
    /// Returns:
    ///     A PEPJSONValue
    #[staticmethod]
    #[pyo3(name = "from_value")]
    fn from_value(value: &Bound<PyAny>) -> PyResult<Self> {
        let json_value = python_to_json(value)?;
        Ok(Self(PEPJSONValue::from_value(&json_value)))
    }

    /// Encrypt this PEPJSONValue into an EncryptedPEPJSONValue.
    ///
    /// Args:
    ///     attribute_public_key: Attribute session public key
    ///     pseudonym_public_key: Pseudonym session public key
    ///
    /// Returns:
    ///     An EncryptedPEPJSONValue
    #[pyo3(name = "encrypt")]
    fn encrypt(
        &self,
        attribute_public_key: &PyAny,
        pseudonym_public_key: &PyAny,
    ) -> PyResult<PyEncryptedPEPJSONValue> {
        let mut rng = rand::rng();

        // Extract keys from the Python objects
        let attr_public = attribute_public_key.extract()?;
        let pseudo_public = pseudonym_public_key.extract()?;

        let keys = SessionKeys {
            attribute: crate::core::keys::AttributeSessionKeys {
                public: attr_public,
                secret: Default::default(), // Not needed for encryption
            },
            pseudonym: crate::core::keys::PseudonymSessionKeys {
                public: pseudo_public,
                secret: Default::default(), // Not needed for encryption
            },
        };

        let encrypted = self.0.encrypt(&keys, &mut rng);
        Ok(PyEncryptedPEPJSONValue(encrypted))
    }
}

/// An encrypted PEP JSON value.
///
/// This wraps JSON values where primitive types are encrypted as PEP types.
#[pyclass(name = "EncryptedPEPJSONValue")]
#[derive(Clone)]
pub struct PyEncryptedPEPJSONValue(pub(crate) EncryptedPEPJSONValue);

#[pymethods]
impl PyEncryptedPEPJSONValue {
    /// Decrypt this EncryptedPEPJSONValue back into a regular Python object.
    ///
    /// Args:
    ///     attribute_secret_key: Attribute session secret key
    ///     pseudonym_secret_key: Pseudonym session secret key
    ///
    /// Returns:
    ///     A Python object (dict, list, str, int, float, bool, or None)
    #[pyo3(name = "decrypt")]
    fn decrypt(
        &self,
        attribute_secret_key: &PyAny,
        pseudonym_secret_key: &PyAny,
    ) -> PyResult<Py<PyAny>> {
        // Extract keys from the Python objects
        let attr_secret = attribute_secret_key.extract()?;
        let pseudo_secret = pseudonym_secret_key.extract()?;

        let keys = SessionKeys {
            attribute: crate::core::keys::AttributeSessionKeys {
                public: Default::default(), // Not needed for decryption
                secret: attr_secret,
            },
            pseudonym: crate::core::keys::PseudonymSessionKeys {
                public: Default::default(), // Not needed for decryption
                secret: pseudo_secret,
            },
        };

        let decrypted = self
            .0
            .decrypt(&keys)
            .map_err(|e| PyValueError::new_err(format!("Decryption failed: {}", e)))?;

        Python::with_gil(|py| json_to_python(py, &decrypted))
    }

    /// Get the structure/shape of this EncryptedPEPJSONValue.
    ///
    /// Returns:
    ///     A JSONStructure describing the shape
    #[pyo3(name = "structure")]
    fn structure(&self) -> PyJSONStructure {
        PyJSONStructure(self.0.structure())
    }

    /// Transcrypt this EncryptedPEPJSONValue from one context to another.
    ///
    /// Args:
    ///     from_domain: Source pseudonymization domain
    ///     to_domain: Target pseudonymization domain
    ///     from_session: Source encryption session (optional)
    ///     to_session: Target encryption session (optional)
    ///     pseudonymization_secret: Pseudonymization secret
    ///     encryption_secret: Encryption secret
    ///
    /// Returns:
    ///     A transcrypted EncryptedPEPJSONValue
    #[pyo3(name = "transcrypt")]
    #[pyo3(signature = (from_domain, to_domain, from_session=None, to_session=None, pseudonymization_secret=None, encryption_secret=None))]
    fn transcrypt(
        &self,
        from_domain: &str,
        to_domain: &str,
        from_session: Option<&str>,
        to_session: Option<&str>,
        pseudonymization_secret: Option<PyPseudonymizationSecret>,
        encryption_secret: Option<&PyBytes>,
    ) -> PyResult<Self> {
        let from_domain = PseudonymizationDomain::from(from_domain);
        let to_domain = PseudonymizationDomain::from(to_domain);
        let from_session_ctx = from_session.map(EncryptionContext::from);
        let to_session_ctx = to_session.map(EncryptionContext::from);

        let pseudo_secret = pseudonymization_secret.map(|s| s.0).unwrap_or_else(|| {
            crate::core::transcryption::secrets::PseudonymizationSecret::from(vec![])
        });

        let enc_secret = encryption_secret
            .map(|b| EncryptionSecret::from(b.as_bytes().to_vec()))
            .unwrap_or_else(|| EncryptionSecret::from(vec![]));

        #[cfg(feature = "global")]
        let transcryption_info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            from_session_ctx.as_ref(),
            to_session_ctx.as_ref(),
            &pseudo_secret,
            &enc_secret,
        );

        #[cfg(not(feature = "global"))]
        let transcryption_info = TranscryptionInfo::new(
            &from_domain,
            &to_domain,
            &from_session_ctx.ok_or_else(|| {
                PyValueError::new_err("from_session required without global feature")
            })?,
            &to_session_ctx.ok_or_else(|| {
                PyValueError::new_err("to_session required without global feature")
            })?,
            &pseudo_secret,
            &enc_secret,
        );

        let transcrypted = self.0.transcrypt(&transcryption_info);
        Ok(Self(transcrypted))
    }

    /// Serialize to JSON string.
    ///
    /// Returns:
    ///     A JSON string representation
    #[pyo3(name = "to_json")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.0)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from JSON string.
    ///
    /// Args:
    ///     json_str: A JSON string
    ///
    /// Returns:
    ///     An EncryptedPEPJSONValue
    #[staticmethod]
    #[pyo3(name = "from_json")]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let value: EncryptedPEPJSONValue = serde_json::from_str(json_str)
            .map_err(|e| PyValueError::new_err(format!("Deserialization failed: {}", e)))?;
        Ok(Self(value))
    }
}

/// A JSON structure descriptor that describes the shape of an EncryptedPEPJSONValue.
#[pyclass(name = "JSONStructure")]
#[derive(Clone)]
pub struct PyJSONStructure(pub(crate) JSONStructure);

#[pymethods]
impl PyJSONStructure {
    /// Convert to a human-readable string.
    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }

    /// Compare two structures for equality.
    fn __eq__(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// Serialize to JSON string.
    ///
    /// Returns:
    ///     A JSON string representation
    #[pyo3(name = "to_json")]
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.0)
            .map_err(|e| PyValueError::new_err(format!("Serialization failed: {}", e)))
    }
}

/// Builder for constructing PEPJSONValue objects with mixed attribute and pseudonym fields.
#[pyclass(name = "PEPJSONBuilder")]
pub struct PyPEPJSONBuilder {
    builder: PEPJSONBuilder,
}

#[pymethods]
impl PyPEPJSONBuilder {
    /// Create a new builder.
    #[new]
    fn new() -> Self {
        Self {
            builder: PEPJSONBuilder::new(),
        }
    }

    /// Create a builder from a Python dict, marking specified fields as pseudonyms.
    ///
    /// Args:
    ///     value: A Python dict
    ///     pseudonyms: A list of field names that should be treated as pseudonyms
    ///
    /// Returns:
    ///     A PEPJSONBuilder
    #[staticmethod]
    #[pyo3(name = "from_dict")]
    fn from_dict(value: &Bound<PyDict>, pseudonyms: Vec<&str>) -> PyResult<Self> {
        let json_value = python_to_json(value.as_any())?;
        let builder = PEPJSONBuilder::from_json(&json_value, &pseudonyms).ok_or_else(|| {
            PyValueError::new_err("Invalid object or pseudonym field not a string")
        })?;
        Ok(Self { builder })
    }

    /// Add a field as a regular attribute.
    ///
    /// Args:
    ///     key: Field name
    ///     value: Field value (any JSON-serializable Python object)
    ///
    /// Returns:
    ///     Self (for chaining)
    #[pyo3(name = "attribute")]
    fn attribute(
        mut slf: PyRefMut<Self>,
        key: &str,
        value: &Bound<PyAny>,
    ) -> PyResult<PyRefMut<Self>> {
        let json_value = python_to_json(value)?;
        slf.builder = std::mem::take(&mut slf.builder).attribute(key, json_value);
        Ok(slf)
    }

    /// Add a string field as a pseudonym.
    ///
    /// Args:
    ///     key: Field name
    ///     value: String value
    ///
    /// Returns:
    ///     Self (for chaining)
    #[pyo3(name = "pseudonym")]
    fn pseudonym(mut slf: PyRefMut<Self>, key: &str, value: &str) -> PyResult<PyRefMut<Self>> {
        slf.builder = std::mem::take(&mut slf.builder).pseudonym(key, value);
        Ok(slf)
    }

    /// Build the final PEPJSONValue object.
    ///
    /// Returns:
    ///     A PEPJSONValue
    #[pyo3(name = "build")]
    fn build(&mut self) -> PyPEPJSONValue {
        let builder = std::mem::replace(&mut self.builder, PEPJSONBuilder::new());
        PyPEPJSONValue(builder.build())
    }
}

/// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
///
/// Args:
///     values: List of EncryptedPEPJSONValue objects
///     from_domain: Source pseudonymization domain
///     to_domain: Target pseudonymization domain
///     from_session: Source encryption session (optional)
///     to_session: Target encryption session (optional)
///     pseudonymization_secret: Pseudonymization secret
///     encryption_secret: Encryption secret
///
/// Returns:
///     A shuffled list of transcrypted EncryptedPEPJSONValue objects
#[pyfunction]
#[pyo3(name = "transcrypt_batch")]
#[pyo3(signature = (values, from_domain, to_domain, from_session=None, to_session=None, pseudonymization_secret=None, encryption_secret=None))]
pub fn py_transcrypt_batch(
    values: Vec<PyEncryptedPEPJSONValue>,
    from_domain: &str,
    to_domain: &str,
    from_session: Option<&str>,
    to_session: Option<&str>,
    pseudonymization_secret: Option<PyPseudonymizationSecret>,
    encryption_secret: Option<&PyBytes>,
) -> PyResult<Vec<PyEncryptedPEPJSONValue>> {
    let mut rng = rand::rng();

    let from_domain = PseudonymizationDomain::from(from_domain);
    let to_domain = PseudonymizationDomain::from(to_domain);
    let from_session_ctx = from_session.map(EncryptionContext::from);
    let to_session_ctx = to_session.map(EncryptionContext::from);

    let pseudo_secret = pseudonymization_secret.map(|s| s.0).unwrap_or_else(|| {
        crate::core::transcryption::secrets::PseudonymizationSecret::from(vec![])
    });

    let enc_secret = encryption_secret
        .map(|b| EncryptionSecret::from(b.as_bytes().to_vec()))
        .unwrap_or_else(|| EncryptionSecret::from(vec![]));

    #[cfg(feature = "global")]
    let transcryption_info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        from_session_ctx.as_ref(),
        to_session_ctx.as_ref(),
        &pseudo_secret,
        &enc_secret,
    );

    #[cfg(not(feature = "global"))]
    let transcryption_info = TranscryptionInfo::new(
        &from_domain,
        &to_domain,
        &from_session_ctx
            .ok_or_else(|| PyValueError::new_err("from_session required without global feature"))?,
        &to_session_ctx
            .ok_or_else(|| PyValueError::new_err("to_session required without global feature"))?,
        &pseudo_secret,
        &enc_secret,
    );

    let rust_values: Vec<EncryptedPEPJSONValue> = values.into_iter().map(|v| v.0).collect();
    let transcrypted = transcrypt_batch(rust_values, &transcryption_info, &mut rng);

    Ok(transcrypted
        .into_iter()
        .map(PyEncryptedPEPJSONValue)
        .collect())
}

// Helper functions to convert between Python and serde_json::Value

fn python_to_json(value: &Bound<PyAny>) -> PyResult<Value> {
    if value.is_none() {
        Ok(Value::Null)
    } else if let Ok(b) = value.extract::<bool>() {
        Ok(Value::Bool(b))
    } else if let Ok(i) = value.extract::<i64>() {
        Ok(Value::Number(i.into()))
    } else if let Ok(f) = value.extract::<f64>() {
        Ok(serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    } else if let Ok(s) = value.extract::<String>() {
        Ok(Value::String(s))
    } else if let Ok(list) = value.downcast::<PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(python_to_json(&item)?);
        }
        Ok(Value::Array(arr))
    } else if let Ok(dict) = value.downcast::<PyDict>() {
        let mut obj = serde_json::Map::new();
        for (key, val) in dict.iter() {
            let key_str = key.extract::<String>()?;
            obj.insert(key_str, python_to_json(&val)?);
        }
        Ok(Value::Object(obj))
    } else {
        Err(PyValueError::new_err(
            "Unsupported Python type for JSON conversion",
        ))
    }
}

pub(crate) fn json_to_python(py: Python, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_py(py)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Err(PyValueError::new_err("Invalid number"))
            }
        }
        Value::String(s) => Ok(s.into_py(py)),
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_to_python(py, item)?)?;
            }
            Ok(list.into())
        }
        Value::Object(obj) => {
            let dict = PyDict::new(py);
            for (key, val) in obj {
                dict.set_item(key, json_to_python(py, val)?)?;
            }
            Ok(dict.into())
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPEPJSONValue>()?;
    m.add_class::<PyEncryptedPEPJSONValue>()?;
    m.add_class::<PyJSONStructure>()?;
    m.add_class::<PyPEPJSONBuilder>()?;
    m.add_function(wrap_pyfunction!(py_transcrypt_batch, m)?)?;
    Ok(())
}
