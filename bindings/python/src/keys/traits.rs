//! Extraction of public and secret keys from the key arguments the Python API accepts.

/// Extraction of the public key a ciphertext is encrypted under, for transcryption functions.
///
/// Without the `elgamal3` feature a ciphertext does not carry its public key, so every
/// transcryption (which rerandomizes) takes it as a parameter. The Python signatures keep the
/// parameter in both builds (optional, ignored with `elgamal3`) so that the API is the same.
#[allow(dead_code)]
pub mod pk {

    use crate::keys::distribution::shares::PySessionPublicKeys;
    use crate::keys::types::{PyAttributeSessionPublicKey, PyPseudonymSessionPublicKey};
    use libpep::keys::{
        AttributeSessionPublicKey, PseudonymSessionPublicKey, PublicKey, SessionPublicKeys,
    };
    use pyo3::exceptions::PyTypeError;
    use pyo3::prelude::*;

    fn required<'a>(
        obj: Option<&'a Bound<'a, PyAny>>,
        what: &str,
    ) -> PyResult<&'a Bound<'a, PyAny>> {
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
}

/// Extraction of the secret key an encrypted value is decrypted with.
///
/// Mirrors [`pk`] for the decryption direction: a caller passes the one secret key for
/// this data type, or `SessionKeys` to take the matching half from. The *data's* type selects the
/// half, so a pseudonym is never decrypted with the attribute secret key.
#[allow(dead_code)]
pub mod sk {

    use crate::keys::types::{PyAttributeSessionSecretKey, PyPseudonymSessionSecretKey};
    use crate::keys::PySessionKeys;
    use libpep::keys::{
        AttributeSessionSecretKey, PseudonymSessionSecretKey, SecretKey, SessionKeys,
    };
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
}
