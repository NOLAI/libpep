//! Python bindings for batch transcryption operations.
//!
//! These wrap [`EncryptedBatch`] so the
//! Python surface stays close to the original `*_batch` free functions but
//! benefits from the new struct's lockstep public-key updates internally.

use crate::data::batch::EncryptedBatch;
#[cfg(feature = "json")]
use crate::data::py::json::PyEncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::py::long::{PyLongEncryptedAttribute, PyLongEncryptedPseudonym};
use crate::data::py::records::PyEncryptedRecord;
#[cfg(feature = "long")]
use crate::data::py::records::PyLongEncryptedRecord;
use crate::data::py::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::py::contexts::{
    PyAttributeRekeyInfo, PyPseudonymRekeyFactor, PyPseudonymizationInfo, PyTranscryptionInfo,
};
use crate::factors::{AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

/// Polymorphic batch pseudonymization.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "pseudonymize_batch")]
#[allow(clippy::expect_used)]
pub fn py_pseudonymize_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyPseudonymizationInfo,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    let mut rng = rand::rng();
    let pseudonymization_info = PseudonymizationInfo::from(info);

    if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| e.extract::<PyEncryptedPseudonym>())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.0)
            .collect();
        let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
        batch
            .pseudonymize(&pseudonymization_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    #[cfg(feature = "long")]
    if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| e.extract::<PyLongEncryptedPseudonym>())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.0)
            .collect();
        let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
        batch
            .pseudonymize(&pseudonymization_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyLongEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    Err(PyTypeError::new_err(
        "pseudonymize_batch() requires list of EncryptedPseudonym or LongEncryptedPseudonym",
    ))
}

#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "pseudonymize_batch")]
#[allow(clippy::expect_used)]
pub fn py_pseudonymize_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyPseudonymizationInfo,
    public_key: &crate::keys::py::PyPseudonymSessionPublicKey,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    let mut rng = rand::rng();
    let pseudonymization_info = PseudonymizationInfo::from(info);
    let pk = crate::keys::PseudonymSessionPublicKey::from(public_key.0 .0);

    if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| e.extract::<PyEncryptedPseudonym>())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.0)
            .collect();
        let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
        batch
            .pseudonymize(&pseudonymization_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    #[cfg(feature = "long")]
    if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| e.extract::<PyLongEncryptedPseudonym>())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|e| e.0)
            .collect();
        let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
        batch
            .pseudonymize(&pseudonymization_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyLongEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    Err(PyTypeError::new_err(
        "pseudonymize_batch() requires list of EncryptedPseudonym or LongEncryptedPseudonym",
    ))
}

/// Polymorphic batch rekeying.
///
/// Under `elgamal3`, every ciphertext carries its own `gy` and no
/// recipient public key is needed. Under `elgamal2`, the caller must supply
/// the recipient public key matching the encrypted-value variant
/// (`PseudonymSessionPublicKey` for pseudonyms,
/// `AttributeSessionPublicKey` for attributes); it is threaded through the
/// batch construction so the binding does not invent a fake key.
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rekey_batch")]
#[allow(clippy::expect_used)]
pub fn py_rekey_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    rekey_info: &Bound<PyAny>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    let mut rng = rand::rng();

    // EncryptedPseudonym × PseudonymRekeyFactor
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
        if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
            batch.rekey(&info.0, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    #[cfg(feature = "long")]
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
        if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
            batch.rekey(&info.0, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyLongEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
        if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let rust_info = AttributeRekeyInfo::from(&info);
            let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
            batch.rekey(&rust_info, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedAttribute(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    #[cfg(feature = "long")]
    if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
        if encrypted[0].extract::<PyLongEncryptedAttribute>().is_ok() {
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let rust_info = AttributeRekeyInfo::from(&info);
            let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
            batch.rekey(&rust_info, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyLongEncryptedAttribute(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    Err(PyTypeError::new_err(
        "rekey_batch() requires list of encrypted values and matching rekey info",
    ))
}

#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rekey_batch")]
#[allow(clippy::expect_used)]
pub fn py_rekey_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    rekey_info: &Bound<PyAny>,
    public_key: &Bound<PyAny>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    let mut rng = rand::rng();

    // EncryptedPseudonym × PseudonymRekeyFactor (requires PseudonymSessionPublicKey)
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
        if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
            let pk = public_key
                .extract::<crate::keys::py::PyPseudonymSessionPublicKey>()
                .map_err(|_| {
                    PyTypeError::new_err(
                        "rekey_batch on pseudonyms requires PseudonymSessionPublicKey",
                    )
                })?;
            let pk = crate::keys::PseudonymSessionPublicKey::from(pk.0 .0);
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
            batch.rekey(&info.0, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    #[cfg(feature = "long")]
    if let Ok(info) = rekey_info.extract::<PyPseudonymRekeyFactor>() {
        if encrypted[0].extract::<PyLongEncryptedPseudonym>().is_ok() {
            let pk = public_key
                .extract::<crate::keys::py::PyPseudonymSessionPublicKey>()
                .map_err(|_| {
                    PyTypeError::new_err(
                        "rekey_batch on long pseudonyms requires PseudonymSessionPublicKey",
                    )
                })?;
            let pk = crate::keys::PseudonymSessionPublicKey::from(pk.0 .0);
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedPseudonym>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
            batch.rekey(&info.0, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyLongEncryptedPseudonym(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
        if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
            let pk = public_key
                .extract::<crate::keys::py::PyAttributeSessionPublicKey>()
                .map_err(|_| {
                    PyTypeError::new_err(
                        "rekey_batch on attributes requires AttributeSessionPublicKey",
                    )
                })?;
            let pk = crate::keys::AttributeSessionPublicKey::from(pk.0 .0);
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                })
                .collect();
            let rust_info = AttributeRekeyInfo::from(&info);
            let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
            batch.rekey(&rust_info, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyEncryptedAttribute(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    #[cfg(feature = "long")]
    if let Ok(info) = rekey_info.extract::<PyAttributeRekeyInfo>() {
        if encrypted[0].extract::<PyLongEncryptedAttribute>().is_ok() {
            let pk = public_key
                .extract::<crate::keys::py::PyAttributeSessionPublicKey>()
                .map_err(|_| {
                    PyTypeError::new_err(
                        "rekey_batch on long attributes requires AttributeSessionPublicKey",
                    )
                })?;
            let pk = crate::keys::AttributeSessionPublicKey::from(pk.0 .0);
            let items: Vec<_> = encrypted
                .iter()
                .map(|e| {
                    e.extract::<PyLongEncryptedAttribute>()
                        .expect("type already validated")
                        .0
                        .clone()
                })
                .collect();
            let rust_info = AttributeRekeyInfo::from(&info);
            let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
            batch.rekey(&rust_info, &mut rng).map_err(PyErr::from)?;
            return Ok(batch
                .into_items()
                .into_iter()
                .map(|e| {
                    Py::new(py, PyLongEncryptedAttribute(e))
                        .expect("PyO3 allocation failed")
                        .into_any()
                })
                .collect());
        }
    }

    Err(PyTypeError::new_err(
        "rekey_batch() requires list of encrypted values and matching rekey info",
    ))
}

/// Polymorphic batch transcryption (elgamal3 mode — no public key needed).
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "transcrypt_batch")]
#[allow(clippy::expect_used)]
pub fn py_transcrypt_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyTranscryptionInfo,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    let mut rng = rand::rng();
    let transcryption_info = TranscryptionInfo::from(info);

    if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedPseudonym>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedAttribute>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedAttribute(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    if encrypted[0].extract::<PyEncryptedRecord>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedRecord>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedRecord(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    #[cfg(feature = "long")]
    if encrypted[0].extract::<PyLongEncryptedRecord>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyLongEncryptedRecord>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyLongEncryptedRecord(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    #[cfg(feature = "json")]
    if encrypted[0].extract::<PyEncryptedPEPJSONValue>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedPEPJSONValue>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPEPJSONValue(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    Err(PyTypeError::new_err(
        "transcrypt_batch() requires list of transcryptable encrypted types",
    ))
}

/// Polymorphic batch transcryption (elgamal2 mode — requires session keys
/// for pseudonyms/attributes, or full `SessionKeys` for record / JSON
/// payloads).
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "transcrypt_batch")]
#[allow(clippy::expect_used)]
pub fn py_transcrypt_batch(
    py: Python,
    encrypted: Vec<Bound<PyAny>>,
    info: &PyTranscryptionInfo,
    key: &Bound<PyAny>,
) -> PyResult<Vec<Py<PyAny>>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    let mut rng = rand::rng();
    let transcryption_info = TranscryptionInfo::from(info);

    if encrypted[0].extract::<PyEncryptedPseudonym>().is_ok() {
        let pk = key
            .extract::<crate::keys::py::PyPseudonymSessionPublicKey>()
            .map_err(|_| {
                PyTypeError::new_err(
                    "transcrypt_batch on pseudonyms requires PseudonymSessionPublicKey",
                )
            })?;
        let pk = crate::keys::PseudonymSessionPublicKey::from(pk.0 .0);
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedPseudonym>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPseudonym(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    if encrypted[0].extract::<PyEncryptedAttribute>().is_ok() {
        let pk = key
            .extract::<crate::keys::py::PyAttributeSessionPublicKey>()
            .map_err(|_| {
                PyTypeError::new_err(
                    "transcrypt_batch on attributes requires AttributeSessionPublicKey",
                )
            })?;
        let pk = crate::keys::AttributeSessionPublicKey::from(pk.0 .0);
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedAttribute>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items, pk).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedAttribute(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    // Record / JSON paths require SessionKeys.
    let session_keys = key
        .extract::<crate::keys::py::PySessionKeys>()
        .map_err(|_| {
            PyTypeError::new_err("transcrypt_batch on records or JSON requires SessionKeys")
        })?;
    let session_keys: crate::keys::SessionKeys = session_keys.clone().into();

    if encrypted[0].extract::<PyEncryptedRecord>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedRecord>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items, session_keys).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedRecord(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    #[cfg(feature = "long")]
    if encrypted[0].extract::<PyLongEncryptedRecord>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyLongEncryptedRecord>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items, session_keys).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyLongEncryptedRecord(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    #[cfg(feature = "json")]
    if encrypted[0].extract::<PyEncryptedPEPJSONValue>().is_ok() {
        let items: Vec<_> = encrypted
            .iter()
            .map(|e| {
                e.extract::<PyEncryptedPEPJSONValue>()
                    .expect("type already validated")
                    .0
            })
            .collect();
        let mut batch = EncryptedBatch::new(items, session_keys).map_err(PyErr::from)?;
        batch
            .transcrypt(&transcryption_info, &mut rng)
            .map_err(PyErr::from)?;
        return Ok(batch
            .into_items()
            .into_iter()
            .map(|e| {
                Py::new(py, PyEncryptedPEPJSONValue(e))
                    .expect("PyO3 allocation failed")
                    .into_any()
            })
            .collect());
    }

    Err(PyTypeError::new_err(
        "transcrypt_batch() requires list of transcryptable encrypted types",
    ))
}

pub fn register(m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    use pyo3::wrap_pyfunction;
    m.add_function(wrap_pyfunction!(py_pseudonymize_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey_batch, m)?)?;
    m.add_function(wrap_pyfunction!(py_transcrypt_batch, m)?)?;
    Ok(())
}
