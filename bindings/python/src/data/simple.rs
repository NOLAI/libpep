use crate::elgamal::PyElGamal;
use crate::group::group_elements::PyGroupElement;
use crate::macros::{py_encrypted_impl, py_plaintext_impl};
use derive_more::{Deref, From, Into};
use libpep::data::padding::Padded;
#[cfg(feature = "verifiable")]
use libpep::data::verifiable::simple::{
    AttributeRekeyProof, PseudonymPseudonymizationProof, PseudonymRekeyProof,
};
use libpep::prelude::*;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A pseudonym is the identifier of a data subject in one pseudonymization domain. It can be
/// encrypted, rekeyed and reshuffled.
///
/// Reshuffling is a weak PRF, which is pseudorandom only for uniformly random inputs: origin
/// pseudonyms must be created with `random` or `from_lizard` (or be hashes), and not imported
/// with `from_bytes` or `from_hex` unless they are uniformly random.
#[pyclass(name = "Pseudonym", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyPseudonym(pub(crate) Pseudonym);
py_plaintext_impl!(PyPseudonym wraps Pseudonym as "Pseudonym");

/// An attribute is a fact about a data subject that should be neither identifiable nor linkable.
/// It can be encrypted and rekeyed, but not reshuffled.
#[pyclass(name = "Attribute", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyAttribute(pub(crate) Attribute);
py_plaintext_impl!(PyAttribute wraps Attribute as "Attribute");

/// An encrypted pseudonym, which is an [`PyElGamal`] encryption of a [`PyPseudonym`].
#[pyclass(name = "EncryptedPseudonym", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyEncryptedPseudonym(pub(crate) EncryptedPseudonym);
py_encrypted_impl!(PyEncryptedPseudonym wraps EncryptedPseudonym as "EncryptedPseudonym");

/// An encrypted attribute, which is an [`PyElGamal`] encryption of a [`PyAttribute`].
#[pyclass(name = "EncryptedAttribute", from_py_object)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
pub struct PyEncryptedAttribute(pub(crate) EncryptedAttribute);
py_encrypted_impl!(PyEncryptedAttribute wraps EncryptedAttribute as "EncryptedAttribute");

#[cfg(feature = "verifiable")]
crate::macros::py_proof_class!(
    /// Proof of a verifiable pseudonymization of an `EncryptedPseudonym`.
    PyPseudonymPseudonymizationProof(PseudonymPseudonymizationProof)
        as "PseudonymPseudonymizationProof"
);
#[cfg(feature = "verifiable")]
crate::macros::py_proof_class!(
    /// Proof of a verifiable rekeying of an `EncryptedPseudonym`.
    PyPseudonymRekeyProof(PseudonymRekeyProof) as "PseudonymRekeyProof"
);
#[cfg(feature = "verifiable")]
crate::macros::py_proof_class!(
    /// Proof of a verifiable rekeying of an `EncryptedAttribute`.
    PyAttributeRekeyProof(AttributeRekeyProof) as "AttributeRekeyProof"
);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(feature = "verifiable")]
    {
        m.add_class::<PyPseudonymPseudonymizationProof>()?;
        m.add_class::<PyPseudonymRekeyProof>()?;
        m.add_class::<PyAttributeRekeyProof>()?;
    }
    m.add_class::<PyPseudonym>()?;
    m.add_class::<PyAttribute>()?;
    m.add_class::<PyEncryptedPseudonym>()?;
    m.add_class::<PyEncryptedAttribute>()?;
    Ok(())
}
