//! Python bindings for transcryption functions.

use crate::arithmetic::py::PyScalarNonZero;
#[cfg(feature = "json")]
use crate::data::py::json::PyEncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::py::long::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::data::py::records::PyEncryptedRecord;
use crate::data::py::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::py::contexts::{
    PyAttributeRekeyInfo, PyPseudonymRekeyFactor, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use crate::factors::TranscryptionInfo;
use crate::factors::{AttributeRekeyInfo, PseudonymizationInfo, RerandomizeFactor};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::py::{PyAttributeSessionPublicKey, PyPseudonymSessionPublicKey};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey};
use crate::transcryptor::{pseudonymize, rekey, rerandomize, rerandomize_known, transcrypt};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

/// Polymorphic pseudonymize - works with EncryptedPseudonym or LongEncryptedPseudonym.
#[pyfunction]
#[pyo3(name = "pseudonymize")]
pub fn py_pseudonymize(
    encrypted: &Bound<PyAny>,
    pseudonymization_info: &PyPseudonymizationInfo,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let info = PseudonymizationInfo::from(pseudonymization_info);

    // Try EncryptedPseudonym
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        let result = pseudonymize(&ep.0, &info);
        return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
    }

    // Try LongEncryptedPseudonym
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        let result = pseudonymize(&lep.0, &info);
        return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
    }

    Err(PyTypeError::new_err(
        "pseudonymize() requires EncryptedPseudonym or LongEncryptedPseudonym",
    ))
}

/// Polymorphic rekey function - works with any rekeyable type.
/// Accepts EncryptedPseudonym, EncryptedAttribute, LongEncryptedPseudonym, or LongEncryptedAttribute.
/// The rekey_info must be either PyPseudonymRekeyFactor or PyAttributeRekeyInfo.
#[pyfunction]
#[pyo3(name = "rekey")]
pub fn py_rekey(encrypted: &Bound<PyAny>, rekey_info: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();

    // Try EncryptedPseudonym with PseudonymRekeyFactor
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
            let result = rekey(&ep.0, &info.0);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try LongEncryptedPseudonym with PseudonymRekeyFactor
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
            let result = rekey(&lep.0, &info.0);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try EncryptedAttribute with AttributeRekeyInfo
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
            let info_rust = AttributeRekeyInfo::from(&info);
            let result = rekey(&ea.0, &info_rust);
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }
    }

    // Try LongEncryptedAttribute with AttributeRekeyInfo
    #[cfg(feature = "long")]
    if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
        if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
            let info_rust = AttributeRekeyInfo::from(&info);
            let result = rekey(&lea.0, &info_rust);
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }
    }

    Err(PyTypeError::new_err(
        "rekey() requires (EncryptedPseudonym | LongEncryptedPseudonym, PseudonymRekeyFactor) or (EncryptedAttribute | LongEncryptedAttribute, AttributeRekeyInfo)"
    ))
}
/// Polymorphic transcrypt function - works with any transcryptable type.
#[pyfunction]
#[pyo3(name = "transcrypt")]
pub fn py_transcrypt(encrypted: &Bound<PyAny>, info: &PyTranscryptionInfo) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let transcryption_info = TranscryptionInfo::from(info);

    // Try EncryptedPseudonym
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        let transcrypted = transcrypt(&ep.0, &transcryption_info);
        return Ok(Py::new(py, PyEncryptedPseudonym(transcrypted))?.into_any());
    }

    // Try EncryptedAttribute
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        let transcrypted = transcrypt(&ea.0, &transcryption_info);
        return Ok(Py::new(py, PyEncryptedAttribute(transcrypted))?.into_any());
    }

    // Try EncryptedRecord
    if let Ok(er) = encrypted.extract::<PyEncryptedRecord>() {
        let transcrypted = transcrypt(&er.0, &transcryption_info);
        return Ok(Py::new(py, PyEncryptedRecord(transcrypted))?.into_any());
    }

    // Try EncryptedPEPJSONValue
    #[cfg(feature = "json")]
    if let Ok(ej) = encrypted.extract::<PyEncryptedPEPJSONValue>() {
        let transcrypted = transcrypt(&ej.0, &transcryption_info);
        return Ok(Py::new(py, PyEncryptedPEPJSONValue(transcrypted))?.into_any());
    }

    Err(PyTypeError::new_err(
        "transcrypt() requires a transcryptable encrypted type",
    ))
}
/// Polymorphic rerandomize function - works with any encrypted type.
/// Creates a binary unlinkable copy of the encrypted value.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize")]
pub fn py_rerandomize(encrypted: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let mut rng = rand::rng();

    // Try EncryptedPseudonym
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        let result = rerandomize(&ep.0, &mut rng);
        return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
    }

    // Try EncryptedAttribute
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        let result = rerandomize(&ea.0, &mut rng);
        return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
    }

    // Try LongEncryptedPseudonym
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        let result = rerandomize(&lep.0, &mut rng);
        return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
    }

    // Try LongEncryptedAttribute
    #[cfg(feature = "long")]
    if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
        let result = rerandomize(&lea.0, &mut rng);
        return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
    }

    Err(PyTypeError::new_err(
        "rerandomize() requires an encrypted type (EncryptedPseudonym, EncryptedAttribute, LongEncryptedPseudonym, or LongEncryptedAttribute)"
    ))
}

/// Polymorphic rerandomize function - works with any encrypted type.
/// Creates a binary unlinkable copy of the encrypted value.
/// Requires a public key for non-elgamal3 builds.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize")]
pub fn py_rerandomize(encrypted: &Bound<PyAny>, public_key: &Bound<PyAny>) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let mut rng = rand::rng();

    // Try EncryptedPseudonym with PseudonymSessionPublicKey
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
            let result = rerandomize(&ep.0, &PseudonymSessionPublicKey::from(pk.0 .0), &mut rng);
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try EncryptedAttribute with AttributeSessionPublicKey
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
            let result = rerandomize(&ea.0, &AttributeSessionPublicKey::from(pk.0 .0), &mut rng);
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }
    }

    // Try LongEncryptedPseudonym with PseudonymSessionPublicKey
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
            let result = rerandomize(&lep.0, &PseudonymSessionPublicKey::from(pk.0 .0), &mut rng);
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try LongEncryptedAttribute with AttributeSessionPublicKey
    #[cfg(feature = "long")]
    if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
        if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
            let result = rerandomize(&lea.0, &AttributeSessionPublicKey::from(pk.0 .0), &mut rng);
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }
    }

    Err(PyTypeError::new_err(
        "rerandomize() requires (encrypted_type, public_key) where types match",
    ))
}
/// Polymorphic rerandomize_known function - rerandomizes using a known factor.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize_known")]
pub fn py_rerandomize_known(
    encrypted: &Bound<PyAny>,
    factor: &PyScalarNonZero,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let rerand_factor = RerandomizeFactor(factor.0);

    // Try EncryptedPseudonym
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        let result = rerandomize_known(&ep.0, &rerand_factor);
        return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
    }

    // Try EncryptedAttribute
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        let result = rerandomize_known(&ea.0, &rerand_factor);
        return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
    }

    // Try LongEncryptedPseudonym
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        let result = rerandomize_known(&lep.0, &rerand_factor);
        return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
    }

    // Try LongEncryptedAttribute
    #[cfg(feature = "long")]
    if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
        let result = rerandomize_known(&lea.0, &rerand_factor);
        return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
    }

    Err(PyTypeError::new_err(
        "rerandomize_known() requires an encrypted type and a ScalarNonZero factor",
    ))
}

/// Polymorphic rerandomize_known function - rerandomizes using a known factor.
/// Requires a public key for non-elgamal3 builds.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize_known")]
pub fn py_rerandomize_known(
    encrypted: &Bound<PyAny>,
    public_key: &Bound<PyAny>,
    factor: &PyScalarNonZero,
) -> PyResult<Py<PyAny>> {
    let py = encrypted.py();
    let rerand_factor = RerandomizeFactor(factor.0);

    // Try EncryptedPseudonym with PseudonymSessionPublicKey
    if let Ok(ep) = encrypted.extract::<PyEncryptedPseudonym>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
            let result = rerandomize_known(
                &ep.0,
                &PseudonymSessionPublicKey::from(pk.0 .0),
                &rerand_factor,
            );
            return Ok(Py::new(py, PyEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try EncryptedAttribute with AttributeSessionPublicKey
    if let Ok(ea) = encrypted.extract::<PyEncryptedAttribute>() {
        if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
            let result = rerandomize_known(
                &ea.0,
                &AttributeSessionPublicKey::from(pk.0 .0),
                &rerand_factor,
            );
            return Ok(Py::new(py, PyEncryptedAttribute(result))?.into_any());
        }
    }

    // Try LongEncryptedPseudonym with PseudonymSessionPublicKey
    #[cfg(feature = "long")]
    if let Ok(lep) = encrypted.extract::<PyLongEncryptedPseudonym>() {
        if let Ok(pk) = public_key.extract::<PyPseudonymSessionPublicKey>() {
            let result = rerandomize_known(
                &lep.0,
                &PseudonymSessionPublicKey::from(pk.0 .0),
                &rerand_factor,
            );
            return Ok(Py::new(py, PyLongEncryptedPseudonym(result))?.into_any());
        }
    }

    // Try LongEncryptedAttribute with AttributeSessionPublicKey
    #[cfg(feature = "long")]
    if let Ok(lea) = encrypted.extract::<PyLongEncryptedAttribute>() {
        if let Ok(pk) = public_key.extract::<PyAttributeSessionPublicKey>() {
            let result = rerandomize_known(
                &lea.0,
                &AttributeSessionPublicKey::from(pk.0 .0),
                &rerand_factor,
            );
            return Ok(Py::new(py, PyLongEncryptedAttribute(result))?.into_any());
        }
    }

    Err(PyTypeError::new_err(
        "rerandomize_known() requires (encrypted_type, public_key, factor) where types match",
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_pseudonymize, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt, m)?)?;

    #[cfg(feature = "elgamal3")]
    {
        m.add_function(wrap_pyfunction!(py_rerandomize, m)?)?;
        m.add_function(wrap_pyfunction!(py_rerandomize_known, m)?)?;
    }

    #[cfg(not(feature = "elgamal3"))]
    {
        m.add_function(wrap_pyfunction!(py_rerandomize, m)?)?;
        m.add_function(wrap_pyfunction!(py_rerandomize_known, m)?)?;
    }

    Ok(())
}
