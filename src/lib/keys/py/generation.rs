//! Python bindings for key generation functions.

use super::types::*;
use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::arithmetic::py::scalars::PyScalarNonZero;
use crate::keys::generation::*;
use crate::keys::types::*;
use pyo3::prelude::*;

/// Generate a new pseudonym global key pair.
#[pyfunction]
#[pyo3(name = "make_pseudonym_global_keys")]
pub fn py_make_pseudonym_global_keys() -> PyPseudonymGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_pseudonym_global_keys(&mut rng);
    PyPseudonymGlobalKeyPair {
        public: PyPseudonymGlobalPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyPseudonymGlobalSecretKey::from(PyScalarNonZero::from(secret.0)),
    }
}

/// Generate a new attribute global key pair.
#[pyfunction]
#[pyo3(name = "make_attribute_global_keys")]
pub fn py_make_attribute_global_keys() -> PyAttributeGlobalKeyPair {
    let mut rng = rand::rng();
    let (public, secret) = make_attribute_global_keys(&mut rng);
    PyAttributeGlobalKeyPair {
        public: PyAttributeGlobalPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyAttributeGlobalSecretKey::from(PyScalarNonZero::from(secret.0)),
    }
}

/// Generate pseudonym session keys from a [`PyPseudonymGlobalSecretKey`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_keys")]
pub fn py_make_pseudonym_session_keys(
    global: &PyPseudonymGlobalSecretKey,
    session: &crate::factors::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PyPseudonymSessionKeyPair {
    let (public, secret_key) = make_pseudonym_session_keys(
        &PseudonymGlobalSecretKey(global.0 .0),
        &session.0,
        &secret.0,
    );
    PyPseudonymSessionKeyPair {
        public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(secret_key.0)),
    }
}

/// Generate attribute session keys from a [`PyAttributeGlobalSecretKey`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_attribute_session_keys")]
pub fn py_make_attribute_session_keys(
    global: &PyAttributeGlobalSecretKey,
    session: &crate::factors::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PyAttributeSessionKeyPair {
    let (public, secret_key) = make_attribute_session_keys(
        &AttributeGlobalSecretKey(global.0 .0),
        &session.0,
        &secret.0,
    );
    PyAttributeSessionKeyPair {
        public: PyAttributeSessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(secret_key.0)),
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
            pseudonym: PyPseudonymGlobalPublicKey::from(PyGroupElement::from(public.pseudonym.0)),
            attribute: PyAttributeGlobalPublicKey::from(PyGroupElement::from(public.attribute.0)),
        },
        PyGlobalSecretKeys {
            pseudonym: PyPseudonymGlobalSecretKey::from(PyScalarNonZero::from(secret.pseudonym.0)),
            attribute: PyAttributeGlobalSecretKey::from(PyScalarNonZero::from(secret.attribute.0)),
        },
    )
}

/// Generate session keys for both pseudonyms and attributes from a [`PyGlobalSecretKeys`], a session and an [`PyEncryptionSecret`].
#[pyfunction]
#[pyo3(name = "make_session_keys")]
pub fn py_make_session_keys(
    global: &PyGlobalSecretKeys,
    session: &crate::factors::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
) -> PySessionKeys {
    let keys = make_session_keys(
        &GlobalSecretKeys {
            pseudonym: PseudonymGlobalSecretKey(global.pseudonym.0 .0),
            attribute: AttributeGlobalSecretKey(global.attribute.0 .0),
        },
        &session.0,
        &secret.0,
    );
    PySessionKeys {
        pseudonym: PyPseudonymSessionKeys {
            public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(
                keys.pseudonym.public.0,
            )),
            secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(
                keys.pseudonym.secret.0,
            )),
        },
        attribute: PyAttributeSessionKeys {
            public: PyAttributeSessionPublicKey::from(PyGroupElement::from(
                keys.attribute.public.0,
            )),
            secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(
                keys.attribute.secret.0,
            )),
        },
    }
}

/// Result bundle for `make_pseudonym_session_keys_with_proof`.
#[cfg(feature = "verifiable-derivation")]
#[pyclass(name = "PseudonymSessionKeysWithProof", from_py_object)]
#[derive(Clone)]
pub struct PyPseudonymSessionKeysWithProof {
    #[pyo3(get)]
    pub public: PyPseudonymSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyPseudonymSessionSecretKey,
    #[pyo3(get)]
    pub proof: crate::keys::py::distribution::proofs::PySessionKeyShareProof,
    #[pyo3(get)]
    pub blinding_commitment: crate::keys::py::distribution::proofs::PyBlindingCommitment,
}

/// Result bundle for `make_attribute_session_keys_with_proof`.
#[cfg(feature = "verifiable-derivation")]
#[pyclass(name = "AttributeSessionKeysWithProof", from_py_object)]
#[derive(Clone)]
pub struct PyAttributeSessionKeysWithProof {
    #[pyo3(get)]
    pub public: PyAttributeSessionPublicKey,
    #[pyo3(get)]
    pub secret: PyAttributeSessionSecretKey,
    #[pyo3(get)]
    pub proof: crate::keys::py::distribution::proofs::PySessionKeyShareProof,
    #[pyo3(get)]
    pub blinding_commitment: crate::keys::py::distribution::proofs::PyBlindingCommitment,
}

/// Generate pseudonym session keys together with a session-key-share proof.
#[cfg(feature = "verifiable-derivation")]
#[pyfunction]
#[pyo3(name = "make_pseudonym_session_keys_with_proof")]
pub fn py_make_pseudonym_session_keys_with_proof(
    global: &PyPseudonymGlobalSecretKey,
    session: &crate::factors::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
    blinding: &crate::keys::py::distribution::blinding::PyBlindingFactor,
) -> PyPseudonymSessionKeysWithProof {
    let mut rng = rand::rng();
    let (public, secret_key, proof, blinding_commitment) = make_pseudonym_session_keys_with_proof(
        &PseudonymGlobalSecretKey(global.0 .0),
        &session.0,
        &secret.0,
        &blinding.0 .0,
        &mut rng,
    );
    PyPseudonymSessionKeysWithProof {
        public: PyPseudonymSessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyPseudonymSessionSecretKey::from(PyScalarNonZero::from(secret_key.0)),
        proof: proof.into(),
        blinding_commitment: blinding_commitment.into(),
    }
}

/// Generate attribute session keys together with a session-key-share proof.
#[cfg(feature = "verifiable-derivation")]
#[pyfunction]
#[pyo3(name = "make_attribute_session_keys_with_proof")]
pub fn py_make_attribute_session_keys_with_proof(
    global: &PyAttributeGlobalSecretKey,
    session: &crate::factors::py::contexts::PyEncryptionContext,
    secret: &PyEncryptionSecret,
    blinding: &crate::keys::py::distribution::blinding::PyBlindingFactor,
) -> PyAttributeSessionKeysWithProof {
    let mut rng = rand::rng();
    let (public, secret_key, proof, blinding_commitment) = make_attribute_session_keys_with_proof(
        &AttributeGlobalSecretKey(global.0 .0),
        &session.0,
        &secret.0,
        &blinding.0 .0,
        &mut rng,
    );
    PyAttributeSessionKeysWithProof {
        public: PyAttributeSessionPublicKey::from(PyGroupElement::from(public.0)),
        secret: PyAttributeSessionSecretKey::from(PyScalarNonZero::from(secret_key.0)),
        proof: proof.into(),
        blinding_commitment: blinding_commitment.into(),
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_make_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_pseudonym_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_attribute_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_session_keys, m)?)?;
    #[cfg(feature = "verifiable-derivation")]
    {
        m.add_class::<PyPseudonymSessionKeysWithProof>()?;
        m.add_class::<PyAttributeSessionKeysWithProof>()?;
        m.add_function(wrap_pyfunction!(
            py_make_pseudonym_session_keys_with_proof,
            m
        )?)?;
        m.add_function(wrap_pyfunction!(
            py_make_attribute_session_keys_with_proof,
            m
        )?)?;
    }
    Ok(())
}
