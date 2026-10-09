//! Extraction of the public key a ciphertext is encrypted under, for transcryption functions.
//!
//! Without the `elgamal3` feature a ciphertext does not carry its public key, so every
//! transcryption (which rerandomizes) takes it as a parameter. The Python signatures keep the
//! parameter in both builds (optional, ignored with `elgamal3`) so that the API is the same.
#![allow(dead_code)]

use super::types::{PyAttributeSessionPublicKey, PyPseudonymSessionPublicKey};
use crate::keys::distribution::shares::PySessionPublicKeys;
use libpep::keys::{
    AttributeSessionPublicKey, PseudonymSessionPublicKey, PublicKey, SessionPublicKeys,
};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;

fn required<'a>(obj: Option<&'a Bound<'a, PyAny>>, what: &str) -> PyResult<&'a Bound<'a, PyAny>> {
    obj.ok_or_else(|| {
        PyTypeError::new_err(format!(
            "public_key is required: the {what} the ciphertext is encrypted under"
        ))
    })
}

/// The pseudonym session public key a pseudonym ciphertext is encrypted under. Accepts the key
/// itself, or `SessionPublicKeys` / `SessionKeys` to take the pseudonym half from.
pub fn pseudonym(obj: Option<&Bound<PyAny>>) -> PyResult<PseudonymSessionPublicKey> {
    let obj = required(obj, "PseudonymSessionPublicKey")?;
    if let Ok(pk) = obj.extract::<PyPseudonymSessionPublicKey>() {
        return Ok(PseudonymSessionPublicKey::from_point(pk.0 .0));
    }
    Ok(session_keys(obj)?.pseudonym)
}

/// The attribute session public key an attribute ciphertext is encrypted under. Accepts the key
/// itself, or `SessionPublicKeys` / `SessionKeys` to take the attribute half from.
pub fn attribute(obj: Option<&Bound<PyAny>>) -> PyResult<AttributeSessionPublicKey> {
    let obj = required(obj, "AttributeSessionPublicKey")?;
    if let Ok(pk) = obj.extract::<PyAttributeSessionPublicKey>() {
        return Ok(AttributeSessionPublicKey::from_point(pk.0 .0));
    }
    Ok(session_keys(obj)?.attribute)
}

/// The session public keys from either bundle, for the projections above.
fn session_keys(obj: &Bound<PyAny>) -> PyResult<SessionPublicKeys> {
    if let Ok(keys) = obj.extract::<PySessionPublicKeys>() {
        return Ok(keys.into());
    }
    if let Ok(keys) = obj.extract::<crate::keys::PySessionKeys>() {
        return Ok(libpep::keys::SessionKeys::from(keys).public());
    }
    Err(PyTypeError::new_err(
        "public_key must be the session public key for this data type, SessionPublicKeys or SessionKeys",
    ))
}

/// The session public keys a record or JSON document is encrypted under. Accepts
/// `SessionPublicKeys` or `SessionKeys` (whose secret keys are ignored).
pub fn session(obj: Option<&Bound<PyAny>>) -> PyResult<SessionPublicKeys> {
    session_keys(required(obj, "SessionPublicKeys")?)
}
