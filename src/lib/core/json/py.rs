//! Python bindings for PEP JSON encryption.

use crate::core::json::builder::PEPJSONBuilder;
use crate::core::json::data::{decrypt_json, encrypt_json, EncryptedPEPJSONValue, PEPJSONValue};
#[cfg(all(feature = "insecure", feature = "offline"))]
use crate::core::json::offline::decrypt_json_global;
#[cfg(feature = "offline")]
use crate::core::json::offline::encrypt_json_global;
use crate::core::json::structure::JSONStructure;
use crate::core::json::transcryption::transcrypt_json_batch;
#[cfg(all(feature = "insecure", feature = "offline"))]
use crate::core::keys::GlobalSecretKeys;
use crate::core::keys::{GlobalPublicKeys, SessionKeys};
#[cfg(feature = "offline")]
use crate::core::py::keys::PyGlobalPublicKeys;
#[cfg(all(feature = "insecure", feature = "offline"))]
use crate::core::py::keys::PyGlobalSecretKeys;
use crate::core::py::keys::{PyEncryptionSecret, PyPseudonymizationSecret, PySessionKeys};
use crate::core::transcryption::contexts::TranscryptionInfo;
use crate::core::transcryption::py::contexts::{
    PyEncryptionContext, PyPseudonymizationDomain, PyTranscryptionInfo,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use serde_json::Value;

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

    /// Convert this PEPJSONValue to a regular Python object.
    ///
    /// Returns:
    ///     A Python object (dict, list, str, int, float, bool, or None)
    #[pyo3(name = "to_json")]
    fn to_json(&self) -> PyResult<Py<PyAny>> {
        let json_value = self
            .0
            .to_value()
            .map_err(|e| PyValueError::new_err(format!("Conversion failed: {}", e)))?;
        Python::attach(|py| json_to_python(py, &json_value))
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
    ///     from_session: Source encryption session
    ///     to_session: Target encryption session
    ///     pseudonymization_secret: Pseudonymization secret
    ///     encryption_secret: Encryption secret
    ///
    /// Returns:
    ///     A transcrypted EncryptedPEPJSONValue
    #[pyo3(name = "transcrypt")]
    fn transcrypt(
        &self,
        from_domain: &PyPseudonymizationDomain,
        to_domain: &PyPseudonymizationDomain,
        from_session: &PyEncryptionContext,
        to_session: &PyEncryptionContext,
        pseudonymization_secret: &PyPseudonymizationSecret,
        encryption_secret: &PyEncryptionSecret,
    ) -> PyResult<Self> {
        let transcryption_info = TranscryptionInfo::new(
            &from_domain.0,
            &to_domain.0,
            &from_session.0,
            &to_session.0,
            &pseudonymization_secret.0,
            &encryption_secret.0,
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

    /// Create a builder from a JSON object (dict), marking specified fields as pseudonyms.
    ///
    /// Args:
    ///     value: A Python dict or JSON-serializable object
    ///     pseudonyms: A list of field names that should be treated as pseudonyms
    ///
    /// Returns:
    ///     A PEPJSONBuilder
    #[staticmethod]
    #[pyo3(name = "from_json")]
    fn from_json(value: &Bound<PyAny>, pseudonyms: Vec<String>) -> PyResult<Self> {
        let json_value = python_to_json(value)?;
        let pseudonym_refs: Vec<&str> = pseudonyms.iter().map(|s| s.as_str()).collect();
        let builder = PEPJSONBuilder::from_json(&json_value, &pseudonym_refs).ok_or_else(|| {
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
    ///     Self for method chaining
    #[pyo3(name = "attribute")]
    fn attribute<'py>(
        slf: Bound<'py, Self>,
        key: &str,
        value: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        let json_value = python_to_json(value)?;
        let mut borrow = slf.borrow_mut();
        borrow.builder = std::mem::take(&mut borrow.builder).attribute(key, json_value);
        drop(borrow);
        Ok(slf)
    }

    /// Add a string field as a pseudonym.
    ///
    /// Args:
    ///     key: Field name
    ///     value: String value
    ///
    /// Returns:
    ///     Self for method chaining
    #[pyo3(name = "pseudonym")]
    fn pseudonym<'py>(slf: Bound<'py, Self>, key: &str, value: &str) -> PyResult<Bound<'py, Self>> {
        let mut borrow = slf.borrow_mut();
        borrow.builder = std::mem::take(&mut borrow.builder).pseudonym(key, value);
        drop(borrow);
        Ok(slf)
    }

    /// Build the final PEPJSONValue object.
    ///
    /// Returns:
    ///     A PEPJSONValue
    #[pyo3(name = "build")]
    fn build(&mut self) -> PyPEPJSONValue {
        let builder = std::mem::take(&mut self.builder);
        PyPEPJSONValue(builder.build())
    }
}

/// Transcrypt a batch of EncryptedPEPJSONValues and shuffle their order.
///
/// Args:
///     values: List of EncryptedPEPJSONValue objects
///     transcryption_info: TranscryptionInfo object containing domains, sessions, and secrets
///
/// Returns:
///     A shuffled list of transcrypted EncryptedPEPJSONValue objects
#[pyfunction]
#[pyo3(name = "transcrypt_batch")]
pub fn py_transcrypt_batch(
    values: Vec<PyEncryptedPEPJSONValue>,
    transcryption_info: &PyTranscryptionInfo,
) -> PyResult<Vec<PyEncryptedPEPJSONValue>> {
    let mut rng = rand::rng();
    let rust_values: Vec<EncryptedPEPJSONValue> = values.into_iter().map(|v| v.0).collect();
    let info: TranscryptionInfo = transcryption_info.into();
    let transcrypted = transcrypt_json_batch(rust_values, &info, &mut rng)
        .map_err(|e| PyValueError::new_err(format!("Batch transcryption failed: {}", e)))?;

    Ok(transcrypted
        .into_iter()
        .map(PyEncryptedPEPJSONValue)
        .collect())
}

/// Transcrypt a batch of EncryptedPEPJSONValues using a TranscryptionInfo object.
///
/// This is a simpler version that accepts a PyTranscryptionInfo.
#[pyfunction]
#[pyo3(name = "transcrypt_json_batch")]
pub fn py_transcrypt_json_batch(
    values: Vec<PyEncryptedPEPJSONValue>,
    transcryption_info: &PyTranscryptionInfo,
) -> PyResult<Vec<PyEncryptedPEPJSONValue>> {
    let mut rng = rand::rng();
    let rust_values: Vec<EncryptedPEPJSONValue> = values.into_iter().map(|v| v.0).collect();
    let info: TranscryptionInfo = transcryption_info.into();
    let transcrypted = transcrypt_json_batch(rust_values, &info, &mut rng)
        .map_err(|e| PyValueError::new_err(format!("Batch transcryption failed: {}", e)))?;

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
    } else if let Ok(list) = value.cast::<PyList>() {
        let mut arr = Vec::new();
        for item in list.iter() {
            arr.push(python_to_json(&item)?);
        }
        Ok(Value::Array(arr))
    } else if let Ok(dict) = value.cast::<PyDict>() {
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
        Value::Bool(b) => {
            let bound = (*b).into_pyobject(py)?;
            Ok(bound.as_any().clone().unbind())
        }
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                let bound = i.into_pyobject(py)?;
                Ok(bound.as_any().clone().unbind())
            } else if let Some(u) = n.as_u64() {
                let bound = u.into_pyobject(py)?;
                Ok(bound.as_any().clone().unbind())
            } else if let Some(f) = n.as_f64() {
                let bound = f.into_pyobject(py)?;
                Ok(bound.as_any().clone().unbind())
            } else {
                Err(PyValueError::new_err("Invalid number"))
            }
        }
        Value::String(s) => {
            let bound = s.as_str().into_pyobject(py)?;
            Ok(bound.as_any().clone().unbind())
        }
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

/// Encrypt a PEPJSONValue using session keys.
#[pyfunction]
#[pyo3(name = "encrypt_json")]
pub fn py_encrypt_json(
    value: &PyPEPJSONValue,
    session_keys: &PySessionKeys,
) -> PyEncryptedPEPJSONValue {
    let mut rng = rand::rng();
    let keys: SessionKeys = session_keys.clone().into();
    PyEncryptedPEPJSONValue(encrypt_json(&value.0, &keys, &mut rng))
}

/// Decrypt an EncryptedPEPJSONValue using session keys.
#[pyfunction]
#[pyo3(name = "decrypt_json")]
pub fn py_decrypt_json(
    encrypted: &PyEncryptedPEPJSONValue,
    session_keys: &PySessionKeys,
) -> PyResult<PyPEPJSONValue> {
    let keys: SessionKeys = session_keys.clone().into();
    let decrypted = decrypt_json(&encrypted.0, &keys)
        .map_err(|e| PyValueError::new_err(format!("Decryption failed: {}", e)))?;
    Ok(PyPEPJSONValue(decrypted))
}

/// Encrypt a PEPJSONValue using global public keys.
/// Can be used when encryption happens offline and no session key is available, or when using
/// a session key may leak information.
#[cfg(feature = "offline")]
#[pyfunction]
#[pyo3(name = "encrypt_json_global")]
pub fn py_encrypt_json_global(
    value: &PyPEPJSONValue,
    global_keys: &PyGlobalPublicKeys,
) -> PyEncryptedPEPJSONValue {
    let mut rng = rand::rng();
    let keys = GlobalPublicKeys {
        pseudonym: global_keys.pseudonym.0 .0.into(),
        attribute: global_keys.attribute.0 .0.into(),
    };
    PyEncryptedPEPJSONValue(encrypt_json_global(&value.0, &keys, &mut rng))
}

/// Decrypt an EncryptedPEPJSONValue using global secret keys.
/// Note: For most applications, the global secret key should be discarded and thus never exist.
#[cfg(all(feature = "insecure", feature = "offline"))]
#[pyfunction]
#[pyo3(name = "decrypt_json_global")]
pub fn py_decrypt_json_global(
    encrypted: &PyEncryptedPEPJSONValue,
    global_secret_keys: &PyGlobalSecretKeys,
) -> PyResult<PyPEPJSONValue> {
    let keys = GlobalSecretKeys {
        pseudonym: global_secret_keys.pseudonym.0 .0.into(),
        attribute: global_secret_keys.attribute.0 .0.into(),
    };
    let decrypted = decrypt_json_global(&encrypted.0, &keys)
        .map_err(|e| PyValueError::new_err(format!("Decryption failed: {}", e)))?;
    Ok(PyPEPJSONValue(decrypted))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // Register main JSON types at json module level
    m.add_class::<PyPEPJSONValue>()?;
    m.add_class::<PyEncryptedPEPJSONValue>()?;
    m.add_class::<PyJSONStructure>()?;

    // Session key functions
    m.add_function(wrap_pyfunction!(py_encrypt_json, m)?)?;
    m.add_function(wrap_pyfunction!(py_decrypt_json, m)?)?;

    // Batch transcryption functions
    m.add_function(wrap_pyfunction!(py_transcrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_json_batch, m)?)?;

    // Global key functions (offline feature)
    #[cfg(feature = "offline")]
    m.add_function(wrap_pyfunction!(py_encrypt_json_global, m)?)?;
    #[cfg(all(feature = "insecure", feature = "offline"))]
    m.add_function(wrap_pyfunction!(py_decrypt_json_global, m)?)?;

    // Create builder submodule to mirror Rust structure
    let builder_module = PyModule::new(py, "builder")?;
    builder_module.add_class::<PyPEPJSONBuilder>()?;
    m.add_submodule(&builder_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.json.builder", &builder_module)?;

    Ok(())
}
