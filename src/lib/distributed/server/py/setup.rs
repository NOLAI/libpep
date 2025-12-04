use crate::arithmetic::py::group_elements::PyGroupElement;
use crate::arithmetic::py::scalars::PyScalarNonZero;
use crate::core::keys::{AttributeGlobalSecretKey, PseudonymGlobalSecretKey};
use crate::core::py::keys::{
    PyAttributeGlobalPublicKey, PyAttributeGlobalSecretKey, PyGlobalPublicKeys, PyGlobalSecretKeys,
    PyPseudonymGlobalPublicKey, PyPseudonymGlobalSecretKey,
};
use crate::distributed::server::setup::*;
use derive_more::{Deref, From, Into};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use pyo3::Py;

/// A blinding factor used to blind a global secret key during system setup.
#[derive(Copy, Clone, Debug, From, Into, Deref)]
#[pyclass(name = "BlindingFactor")]
pub struct PyBlindingFactor(pub(crate) BlindingFactor);

#[pymethods]
impl PyBlindingFactor {
    /// Create a new [`PyBlindingFactor`] from a [`PyScalarNonZero`].
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyBlindingFactor(BlindingFactor(x.0))
    }

    /// Generate a random [`PyBlindingFactor`].
    #[staticmethod]
    #[pyo3(name = "random")]
    fn random() -> Self {
        let mut rng = rand::rng();
        let x = BlindingFactor::random(&mut rng);
        PyBlindingFactor(x)
    }

    /// Encode the [`PyBlindingFactor`] as a byte array.
    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    /// Decode a [`PyBlindingFactor`] from a byte array.
    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<PyBlindingFactor> {
        BlindingFactor::from_slice(bytes).map(PyBlindingFactor)
    }

    /// Encode the [`PyBlindingFactor`] as a hexadecimal string.
    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decode a [`PyBlindingFactor`] from a hexadecimal string.
    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyBlindingFactor> {
        BlindingFactor::from_hex(hex).map(PyBlindingFactor)
    }

    fn __repr__(&self) -> String {
        format!("BlindingFactor({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyBlindingFactor) -> bool {
        self.0 .0 == other.0 .0
    }
}

/// A blinded pseudonym global secret key.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "BlindedPseudonymGlobalSecretKey")]
pub struct PyBlindedPseudonymGlobalSecretKey(pub(crate) BlindedPseudonymGlobalSecretKey);

#[pymethods]
impl PyBlindedPseudonymGlobalSecretKey {
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyBlindedPseudonymGlobalSecretKey(BlindedPseudonymGlobalSecretKey(x.0))
    }

    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<PyBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::from_slice(bytes).map(PyBlindedPseudonymGlobalSecretKey)
    }

    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyBlindedPseudonymGlobalSecretKey> {
        BlindedPseudonymGlobalSecretKey::from_hex(hex).map(PyBlindedPseudonymGlobalSecretKey)
    }

    fn __repr__(&self) -> String {
        format!("BlindedPseudonymGlobalSecretKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyBlindedPseudonymGlobalSecretKey) -> bool {
        self.0 == other.0
    }
}

/// A blinded attribute global secret key.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[pyclass(name = "BlindedAttributeGlobalSecretKey")]
pub struct PyBlindedAttributeGlobalSecretKey(pub(crate) BlindedAttributeGlobalSecretKey);

#[pymethods]
impl PyBlindedAttributeGlobalSecretKey {
    #[new]
    fn new(x: PyScalarNonZero) -> Self {
        PyBlindedAttributeGlobalSecretKey(BlindedAttributeGlobalSecretKey(x.0))
    }

    #[pyo3(name = "to_bytes")]
    fn encode(&self, py: Python) -> Py<PyAny> {
        PyBytes::new(py, &self.0.to_bytes()).into()
    }

    #[staticmethod]
    #[pyo3(name = "from_bytes")]
    fn decode(bytes: &[u8]) -> Option<PyBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::from_slice(bytes).map(PyBlindedAttributeGlobalSecretKey)
    }

    #[pyo3(name = "to_hex")]
    fn as_hex(&self) -> String {
        self.0.to_hex()
    }

    #[staticmethod]
    #[pyo3(name = "from_hex")]
    fn from_hex(hex: &str) -> Option<PyBlindedAttributeGlobalSecretKey> {
        BlindedAttributeGlobalSecretKey::from_hex(hex).map(PyBlindedAttributeGlobalSecretKey)
    }

    fn __repr__(&self) -> String {
        format!("BlindedAttributeGlobalSecretKey({})", self.as_hex())
    }

    fn __str__(&self) -> String {
        self.as_hex()
    }

    fn __eq__(&self, other: &PyBlindedAttributeGlobalSecretKey) -> bool {
        self.0 == other.0
    }
}

/// A pair of blinded global secret keys.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into)]
#[pyclass(name = "BlindedGlobalKeys")]
pub struct PyBlindedGlobalKeys {
    #[pyo3(get)]
    pub pseudonym: PyBlindedPseudonymGlobalSecretKey,
    #[pyo3(get)]
    pub attribute: PyBlindedAttributeGlobalSecretKey,
}

#[pymethods]
impl PyBlindedGlobalKeys {
    #[new]
    fn new(
        pseudonym: PyBlindedPseudonymGlobalSecretKey,
        attribute: PyBlindedAttributeGlobalSecretKey,
    ) -> Self {
        PyBlindedGlobalKeys {
            pseudonym,
            attribute,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "BlindedGlobalKeys(pseudonym={}, attribute={})",
            self.pseudonym.as_hex(),
            self.attribute.as_hex()
        )
    }

    fn __eq__(&self, other: &PyBlindedGlobalKeys) -> bool {
        self.pseudonym == other.pseudonym && self.attribute == other.attribute
    }
}

/// Create a blinded pseudonym global secret key.
#[pyfunction]
#[pyo3(name = "make_blinded_pseudonym_global_secret_key")]
pub fn py_make_blinded_pseudonym_global_secret_key(
    global_secret_key: &PyPseudonymGlobalSecretKey,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedPseudonymGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_pseudonym_global_secret_key(
        &PseudonymGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedPseudonymGlobalSecretKey(result))
}

/// Create a blinded attribute global secret key.
#[pyfunction]
#[pyo3(name = "make_blinded_attribute_global_secret_key")]
pub fn py_make_blinded_attribute_global_secret_key(
    global_secret_key: &PyAttributeGlobalSecretKey,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedAttributeGlobalSecretKey> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_attribute_global_secret_key(
        &AttributeGlobalSecretKey::from(global_secret_key.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedAttributeGlobalSecretKey(result))
}

/// Create blinded global keys.
#[pyfunction]
#[pyo3(name = "make_blinded_global_keys")]
pub fn py_make_blinded_global_keys(
    global_secret_keys: &PyGlobalSecretKeys,
    blinding_factors: Vec<PyBlindingFactor>,
) -> PyResult<PyBlindedGlobalKeys> {
    let bs: Vec<BlindingFactor> = blinding_factors
        .into_iter()
        .map(|x| BlindingFactor(x.0 .0))
        .collect();
    let result = make_blinded_global_keys(
        &PseudonymGlobalSecretKey::from(global_secret_keys.pseudonym.0 .0),
        &AttributeGlobalSecretKey::from(global_secret_keys.attribute.0 .0),
        &bs,
    )
    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("Product of blinding factors is 1"))?;
    Ok(PyBlindedGlobalKeys {
        pseudonym: PyBlindedPseudonymGlobalSecretKey(result.pseudonym),
        attribute: PyBlindedAttributeGlobalSecretKey(result.attribute),
    })
}

/// Setup a distributed system with pseudonym global keys.
#[pyfunction]
#[pyo3(name = "make_distributed_pseudonym_global_keys")]
pub fn py_make_distributed_pseudonym_global_keys(
    n: usize,
) -> (
    PyPseudonymGlobalPublicKey,
    PyBlindedPseudonymGlobalSecretKey,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_pseudonym_global_keys(n, &mut rng);

    (
        PyPseudonymGlobalPublicKey(PyGroupElement(public_key.0)),
        PyBlindedPseudonymGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

/// Setup a distributed system with attribute global keys.
#[pyfunction]
#[pyo3(name = "make_distributed_attribute_global_keys")]
pub fn py_make_distributed_attribute_global_keys(
    n: usize,
) -> (
    PyAttributeGlobalPublicKey,
    PyBlindedAttributeGlobalSecretKey,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::rng();
    let (public_key, blinded_key, blinding_factors) =
        make_distributed_attribute_global_keys(n, &mut rng);

    (
        PyAttributeGlobalPublicKey(PyGroupElement(public_key.0)),
        PyBlindedAttributeGlobalSecretKey(blinded_key),
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

/// Setup a distributed system with both global keys.
#[pyfunction]
#[pyo3(name = "make_distributed_global_keys")]
pub fn py_make_distributed_global_keys(
    n: usize,
) -> (
    PyGlobalPublicKeys,
    PyBlindedGlobalKeys,
    Vec<PyBlindingFactor>,
) {
    let mut rng = rand::rng();
    let (global_public_keys, blinded_keys, blinding_factors) =
        make_distributed_global_keys(n, &mut rng);

    (
        PyGlobalPublicKeys {
            pseudonym: PyPseudonymGlobalPublicKey(PyGroupElement(global_public_keys.pseudonym.0)),
            attribute: PyAttributeGlobalPublicKey(PyGroupElement(global_public_keys.attribute.0)),
        },
        PyBlindedGlobalKeys {
            pseudonym: PyBlindedPseudonymGlobalSecretKey(blinded_keys.pseudonym),
            attribute: PyBlindedAttributeGlobalSecretKey(blinded_keys.attribute),
        },
        blinding_factors.into_iter().map(PyBlindingFactor).collect(),
    )
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBlindingFactor>()?;
    m.add_class::<PyBlindedPseudonymGlobalSecretKey>()?;
    m.add_class::<PyBlindedAttributeGlobalSecretKey>()?;
    m.add_class::<PyBlindedGlobalKeys>()?;
    m.add_function(wrap_pyfunction!(
        py_make_blinded_pseudonym_global_secret_key,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        py_make_blinded_attribute_global_secret_key,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(py_make_blinded_global_keys, m)?)?;
    m.add_function(wrap_pyfunction!(
        py_make_distributed_pseudonym_global_keys,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        py_make_distributed_attribute_global_keys,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(py_make_distributed_global_keys, m)?)?;
    Ok(())
}
