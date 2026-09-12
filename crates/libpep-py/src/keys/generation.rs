//! Python bindings for key generation functions.

use super::types::*;
use crate::arithmetic::group_elements::PyGroupElement;
use crate::arithmetic::scalars::PyScalarNonZero;
use libpep::keys::generation::*;
use libpep::keys::types::*;
use libpep::keys::SecretKey;
use pyo3::prelude::*;

/// Generate a new pseudonym global key pair.
#[pyfunction]
#[pyo3(name = "make_pseudonym_global_keys")]
pub fn py_make_pseudonym_global_keys() -> PyPseudonymGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_pseudonym_global_keys(&mut rng);
    PyPseudonymGlobalKeyPair {
        public: PyPseudonymGlobalPublicKey::from(PyGroupElement::from(*public)),
        secret: PyPseudonymGlobalSecretKey::from(PyScalarNonZero::from(*secret.value())),
    }
}

/// Generate a new attribute global key pair.
#[pyfunction]
#[pyo3(name = "make_attribute_global_keys")]
pub fn py_make_attribute_global_keys() -> PyAttributeGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_attribute_global_keys(&mut rng);
    PyAttributeGlobalKeyPair {
        public: PyAttributeGlobalPublicKey::from(PyGroupElement::from(*public)),
        secret: PyAttributeGlobalSecretKey::from(PyScalarNonZero::from(*secret.value())),
    }
}

/// Generate pseudonym session keys from a [`PyPseudonymGlobalSecretKey`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_keys")]
pub fn py_make_pseudonym_session_keys(
    global: &PyPseudonymGlobalSecretKey,
    session: &crate::factors::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PyPseudonymSessionKeyPair {
    let (public, secret_key) = make_pseudonym_session_keys(
        &PseudonymGlobalSecretKey::from(*global.0),
        &session.0,
        &secret.0,
    );
    PyPseudonymSessionKeyPair {
        public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(*public)),
        secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(*secret_key)),
    }
}

/// Generate attribute session keys from a [`PyAttributeGlobalSecretKey`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_attribute_session_keys")]
pub fn py_make_attribute_session_keys(
    global: &PyAttributeGlobalSecretKey,
    session: &crate::factors::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PyAttributeSessionKeyPair {
    let (public, secret_key) = make_attribute_session_keys(
        &AttributeGlobalSecretKey::from(*global.0),
        &session.0,
        &secret.0,
    );
    PyAttributeSessionKeyPair {
        public: PyAttributeSessionPublicKey::from(PyGroupElement::from(*public)),
        secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(*secret_key)),
    }
}

/// Generate new global key pairs for both pseudonyms and attributes.
#[pyfunction]
#[pyo3(name = "make_global_keys")]
pub fn py_make_global_keys() -> (PyGlobalPublicKeys, PyGlobalSecretKeys) {
    let mut rng = rand::rng();
    let (public, secret) = make_global_keys(&mut rng);
    (
        PyGlobalPublicKeys {
            pseudonym: PyPseudonymGlobalPublicKey::from(PyGroupElement::from(*public.pseudonym)),
            attribute: PyAttributeGlobalPublicKey::from(PyGroupElement::from(*public.attribute)),
        },
        PyGlobalSecretKeys {
            pseudonym: PyPseudonymGlobalSecretKey::from(PyScalarNonZero::from(
                *secret.pseudonym.value(),
            )),
            attribute: PyAttributeGlobalSecretKey::from(PyScalarNonZero::from(
                *secret.attribute.value(),
            )),
        },
    )
}

/// Generate session keys for both pseudonyms and attributes from a [`PyGlobalSecretKeys`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_session_keys")]
pub fn py_make_session_keys(
    global: &PyGlobalSecretKeys,
    session: &crate::factors::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PySessionKeys {
    let keys = make_session_keys(
        &GlobalSecretKeys {
            pseudonym: PseudonymGlobalSecretKey::from(*global.pseudonym.0),
            attribute: AttributeGlobalSecretKey::from(*global.attribute.0),
        },
        &session.0,
        &secret.0,
    );
    PySessionKeys {
        pseudonym: PyPseudonymSessionKeys {
            public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(*keys.pseudonym.public)),
            secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(
                *keys.pseudonym.secret,
            )),
        },
        attribute: PyAttributeSessionKeys {
            public: PyAttributeSessionPublicKey::from(PyGroupElement::from(*keys.attribute.public)),
            secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(
                *keys.attribute.secret,
            )),
        },
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_make_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_keys, m)?)?;
    Ok(())
}
