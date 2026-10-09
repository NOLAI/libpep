//! Extraction of the secret key an encrypted value is decrypted with.
//!
//! Mirrors [`pk`](super::pk) for the decryption direction: a caller passes the one secret key for
//! this data type, or `SessionKeys` to take the matching half from. The *data's* type selects the
//! half, so a pseudonym is never decrypted with the attribute secret key.
#![allow(dead_code)]

use super::types::{PyAttributeSessionSecretKey, PyPseudonymSessionSecretKey};
use crate::keys::PySessionKeys;
use libpep::keys::{AttributeSessionSecretKey, PseudonymSessionSecretKey, SecretKey, SessionKeys};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;

/// The pseudonym session secret key. Accepts the key itself or `SessionKeys`.
pub fn pseudonym(obj: &Bound<PyAny>) -> PyResult<PseudonymSessionSecretKey> {
    if let Ok(sk) = obj.extract::<PyPseudonymSessionSecretKey>() {
        return Ok(PseudonymSessionSecretKey::from_scalar(*sk.0));
    }
    Ok(session_keys(obj)?.pseudonym.secret)
}

/// The attribute session secret key. Accepts the key itself or `SessionKeys`.
pub fn attribute(obj: &Bound<PyAny>) -> PyResult<AttributeSessionSecretKey> {
    if let Ok(sk) = obj.extract::<PyAttributeSessionSecretKey>() {
        return Ok(AttributeSessionSecretKey::from_scalar(*sk.0));
    }
    Ok(session_keys(obj)?.attribute.secret)
}

/// The session keys, for the projections above.
fn session_keys(obj: &Bound<PyAny>) -> PyResult<SessionKeys> {
    obj.extract::<PySessionKeys>()
        .map(SessionKeys::from)
        .map_err(|_| {
            PyTypeError::new_err(
                "secret key must be the session secret key for this data type, or SessionKeys",
            )
        })
}
