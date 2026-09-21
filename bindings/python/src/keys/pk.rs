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

/// The pseudonym session public key a pseudonym ciphertext is encrypted under.
pub fn pseudonym(obj: Option<&Bound<PyAny>>) -> PyResult<PseudonymSessionPublicKey> {
    let pk: PyPseudonymSessionPublicKey = required(obj, "PseudonymSessionPublicKey")?
        .extract()
        .map_err(|_| PyTypeError::new_err("public_key must be a PseudonymSessionPublicKey"))?;
    Ok(PseudonymSessionPublicKey::from_point(pk.0 .0))
}

/// The attribute session public key an attribute ciphertext is encrypted under.
pub fn attribute(obj: Option<&Bound<PyAny>>) -> PyResult<AttributeSessionPublicKey> {
    let pk: PyAttributeSessionPublicKey = required(obj, "AttributeSessionPublicKey")?
        .extract()
        .map_err(|_| PyTypeError::new_err("public_key must be an AttributeSessionPublicKey"))?;
    Ok(AttributeSessionPublicKey::from_point(pk.0 .0))
}

/// The session public keys a record or JSON document is encrypted under. Accepts
/// `SessionPublicKeys` or `SessionKeys` (whose secret keys are ignored).
pub fn session(obj: Option<&Bound<PyAny>>) -> PyResult<SessionPublicKeys> {
    let obj = required(obj, "SessionPublicKeys")?;
    if let Ok(keys) = obj.extract::<PySessionPublicKeys>() {
        return Ok(keys.into());
    }
    if let Ok(keys) = obj.extract::<crate::keys::PySessionKeys>() {
        return Ok(libpep::keys::SessionKeys::from(keys).public_keys());
    }
    Err(PyTypeError::new_err(
        "public_key must be SessionPublicKeys or SessionKeys",
    ))
}
