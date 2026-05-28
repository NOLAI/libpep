//! Python bindings for verifiable transcryption (`libpep.core.verifiable`).
//!
//! Mirrors the Rust `core::verifiable` API: factor commitments, per-message
//! proof types, batched proof types, and the corresponding `verifiable_*`
//! free functions.

#[cfg(not(feature = "elgamal3"))]
use crate::arithmetic::py::PyGroupElement;
use crate::arithmetic::py::PyScalarNonZero;
use crate::core::py::elgamal::PyElGamal;
use crate::core::verifiable::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRRSK,
    VerifiableRRSK2, VerifiableRSK, VerifiableRSK2, VerifiableRSKInner, VerifiableRekey,
    VerifiableRekey2, VerifiableRerandomize, VerifiableReshuffle, VerifiableReshuffle2,
};
#[cfg(feature = "batch")]
use crate::core::verifiable::{
    VerifiableRRSK2Batch, VerifiableRRSKBatch, VerifiableRSK2Batch, VerifiableRSKBatch,
    VerifiableRekey2Batch, VerifiableRekeyBatch, VerifiableRerandomizeBatch,
    VerifiableReshuffle2Batch, VerifiableReshuffleBatch,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[cfg(feature = "serde")]
macro_rules! py_serde_impl {
    ($PyTy:ident, $Inner:ty) => {
        #[pymethods]
        impl $PyTy {
            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.inner)
                    .map_err(|e| PyValueError::new_err(format!("Failed to serialize: {}", e)))
            }

            #[staticmethod]
            fn from_json(json: &str) -> PyResult<Self> {
                serde_json::from_str::<$Inner>(json)
                    .map(|inner| Self { inner })
                    .map_err(|e| PyValueError::new_err(format!("Failed to deserialize: {}", e)))
            }
        }
    };
}

#[cfg(not(feature = "serde"))]
macro_rules! py_serde_impl {
    ($PyTy:ident, $Inner:ty) => {};
}

// ---------------------------------------------------------------------------
// Factor commitments
// ---------------------------------------------------------------------------

/// Forward commitment `A = a·G` to a factor scalar `a`.
#[pyclass(name = "FactorCommitment", from_py_object)]
#[derive(Clone)]
pub struct PyFactorCommitment {
    pub(crate) inner: FactorCommitment,
}

#[pymethods]
impl PyFactorCommitment {
    /// Build a commitment to scalar `a`: `A = a · G`.
    #[staticmethod]
    fn new_from_scalar(a: &PyScalarNonZero) -> Self {
        Self {
            inner: FactorCommitment::new(&a.0),
        }
    }
}

/// Commitment `K = k·G` to a rekey factor.
#[pyclass(name = "RekeyFactorCommitment", from_py_object)]
#[derive(Clone)]
pub struct PyRekeyFactorCommitment {
    pub(crate) inner: RekeyFactorCommitment,
}

#[pymethods]
impl PyRekeyFactorCommitment {
    #[staticmethod]
    fn new_from_scalar(a: &PyScalarNonZero) -> Self {
        Self {
            inner: RekeyFactorCommitment::new(&a.0),
        }
    }
}

/// Commitment `S = s·G` to a pseudonymization (reshuffle) factor.
#[pyclass(name = "PseudonymizationFactorCommitment", from_py_object)]
#[derive(Clone)]
pub struct PyPseudonymizationFactorCommitment {
    pub(crate) inner: PseudonymizationFactorCommitment,
}

#[pymethods]
impl PyPseudonymizationFactorCommitment {
    #[staticmethod]
    fn new_from_scalar(a: &PyScalarNonZero) -> Self {
        Self {
            inner: PseudonymizationFactorCommitment::new(&a.0),
        }
    }
}

// ---------------------------------------------------------------------------
// VerifiableRerandomize (per-message)
// ---------------------------------------------------------------------------

#[pyclass(name = "VerifiableRerandomize", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRerandomize {
    pub(crate) inner: VerifiableRerandomize,
}

#[pymethods]
impl PyVerifiableRerandomize {
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(v: &PyElGamal, r: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRerandomize::new(&v.0.gy, &r.0, &mut rng),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(gy: &PyGroupElement, r: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRerandomize::new(&gy.0, &r.0, &mut rng),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn verify(&self, v: &PyElGamal) -> bool {
        self.inner.verify(&v.0.gy)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(&self, gy: &PyGroupElement) -> bool {
        self.inner.verify(&gy.0)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(&self, original: &PyElGamal) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &original.0.gy)
            .map(PyElGamal::from)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(&self, original: &PyElGamal, gy: &PyGroupElement) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &gy.0)
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &PyElGamal) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct(&original.0))
    }
}

#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize")]
fn py_verifiable_rerandomize(
    original: &PyElGamal,
    r: &PyScalarNonZero,
) -> (PyElGamal, PyVerifiableRerandomize) {
    let mut rng = rand::rng();
    let (result, proof) =
        crate::core::verifiable::verifiable_rerandomize(&original.0, &r.0, &mut rng);
    (
        PyElGamal::from(result),
        PyVerifiableRerandomize { inner: proof },
    )
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize")]
fn py_verifiable_rerandomize(
    original: &PyElGamal,
    gy: &PyGroupElement,
    r: &PyScalarNonZero,
) -> (PyElGamal, PyVerifiableRerandomize) {
    let mut rng = rand::rng();
    let (result, proof) =
        crate::core::verifiable::verifiable_rerandomize(&original.0, &gy.0, &r.0, &mut rng);
    (
        PyElGamal::from(result),
        PyVerifiableRerandomize { inner: proof },
    )
}

// ---------------------------------------------------------------------------
// VerifiableRekey / VerifiableRekey2
// ---------------------------------------------------------------------------

#[pyclass(name = "VerifiableRekey", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRekey {
    pub(crate) inner: VerifiableRekey,
}

#[pymethods]
impl PyVerifiableRekey {
    #[staticmethod]
    fn new_proof(v: &PyElGamal, k: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRekey::new(&v.0, &k.0, &mut rng),
        }
    }

    fn verify(&self, original: &PyElGamal, commitment: &PyRekeyFactorCommitment) -> bool {
        self.inner.verify(&original.0, &commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &commitment.inner)
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &PyElGamal) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct(&original.0))
    }
}

#[pyfunction]
#[pyo3(name = "verifiable_rekey")]
fn py_verifiable_rekey(m: &PyElGamal, k: &PyScalarNonZero) -> PyVerifiableRekey {
    let mut rng = rand::rng();
    PyVerifiableRekey {
        inner: VerifiableRekey::new(&m.0, &k.0, &mut rng),
    }
}

#[pyclass(name = "VerifiableRekey2", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRekey2 {
    pub(crate) inner: VerifiableRekey2,
}

#[pymethods]
impl PyVerifiableRekey2 {
    #[staticmethod]
    fn new_proof(v: &PyElGamal, k_from: &PyScalarNonZero, k_to: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRekey2::new(&v.0, &k_from.0, &k_to.0, &mut rng),
        }
    }

    fn verify_factor(
        &self,
        from_commitment: &PyRekeyFactorCommitment,
        to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    fn combined_commitment(&self) -> PyRekeyFactorCommitment {
        PyRekeyFactorCommitment {
            inner: self.inner.combined_commitment(),
        }
    }

    fn verify(
        &self,
        original: &PyElGamal,
        from_commitment: &PyRekeyFactorCommitment,
        to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner
            .verify(&original.0, &from_commitment.inner, &to_commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        from_commitment: &PyRekeyFactorCommitment,
        to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &from_commitment.inner, &to_commitment.inner)
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &PyElGamal) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct(&original.0))
    }
}

#[pyfunction]
#[pyo3(name = "verifiable_rekey2")]
fn py_verifiable_rekey2(
    m: &PyElGamal,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyVerifiableRekey2 {
    let mut rng = rand::rng();
    PyVerifiableRekey2 {
        inner: VerifiableRekey2::new(&m.0, &k_from.0, &k_to.0, &mut rng),
    }
}

// ---------------------------------------------------------------------------
// VerifiableReshuffle / VerifiableReshuffle2
// ---------------------------------------------------------------------------

#[pyclass(name = "VerifiableReshuffle", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableReshuffle {
    pub(crate) inner: VerifiableReshuffle,
}

#[pymethods]
impl PyVerifiableReshuffle {
    #[staticmethod]
    fn new_proof(v: &PyElGamal, s: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableReshuffle::new(&v.0, &s.0, &mut rng),
        }
    }

    fn verify(
        &self,
        original: &PyElGamal,
        commitment: &PyPseudonymizationFactorCommitment,
    ) -> bool {
        self.inner.verify(&original.0, &commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        commitment: &PyPseudonymizationFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &commitment.inner)
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &PyElGamal) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct(&original.0))
    }
}

#[pyfunction]
#[pyo3(name = "verifiable_reshuffle")]
fn py_verifiable_reshuffle(m: &PyElGamal, s: &PyScalarNonZero) -> PyVerifiableReshuffle {
    let mut rng = rand::rng();
    PyVerifiableReshuffle {
        inner: VerifiableReshuffle::new(&m.0, &s.0, &mut rng),
    }
}

#[pyclass(name = "VerifiableReshuffle2", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableReshuffle2 {
    pub(crate) inner: VerifiableReshuffle2,
}

#[pymethods]
impl PyVerifiableReshuffle2 {
    #[staticmethod]
    fn new_proof(v: &PyElGamal, s_from: &PyScalarNonZero, s_to: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableReshuffle2::new(&v.0, &s_from.0, &s_to.0, &mut rng),
        }
    }

    fn verify_factor(
        &self,
        from_commitment: &PyPseudonymizationFactorCommitment,
        to_commitment: &PyPseudonymizationFactorCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    fn combined_commitment(&self) -> PyPseudonymizationFactorCommitment {
        PyPseudonymizationFactorCommitment {
            inner: self.inner.combined_commitment(),
        }
    }

    fn verify(
        &self,
        original: &PyElGamal,
        from_commitment: &PyPseudonymizationFactorCommitment,
        to_commitment: &PyPseudonymizationFactorCommitment,
    ) -> bool {
        self.inner
            .verify(&original.0, &from_commitment.inner, &to_commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        from_commitment: &PyPseudonymizationFactorCommitment,
        to_commitment: &PyPseudonymizationFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &from_commitment.inner, &to_commitment.inner)
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &PyElGamal) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct(&original.0))
    }
}

#[pyfunction]
#[pyo3(name = "verifiable_reshuffle2")]
fn py_verifiable_reshuffle2(
    m: &PyElGamal,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
) -> PyVerifiableReshuffle2 {
    let mut rng = rand::rng();
    PyVerifiableReshuffle2 {
        inner: VerifiableReshuffle2::new(&m.0, &s_from.0, &s_to.0, &mut rng),
    }
}

// ---------------------------------------------------------------------------
// VerifiableRSKInner / VerifiableRSK / VerifiableRSK2
// ---------------------------------------------------------------------------

#[pyclass(name = "VerifiableRSKInner", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRSKInner {
    pub(crate) inner: VerifiableRSKInner,
}

#[pymethods]
impl PyVerifiableRSKInner {
    fn verify(
        &self,
        original: &PyElGamal,
        gt: &crate::arithmetic::py::PyGroupElement,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify(
            &original.0,
            &gt.0,
            &reshuffle_commitment.inner,
            &rekey_commitment.inner,
        )
    }

    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        gt: &crate::arithmetic::py::PyGroupElement,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(
                &original.0,
                &gt.0,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
            .map(PyElGamal::from)
    }
}

#[pyclass(name = "VerifiableRSK", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRSK {
    pub(crate) inner: VerifiableRSK,
}

#[pymethods]
impl PyVerifiableRSK {
    #[staticmethod]
    fn new_proof(v: &PyElGamal, s: &PyScalarNonZero, k: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRSK::new(&v.0, &s.0, &k.0, &mut rng),
        }
    }

    fn verify(
        &self,
        original: &PyElGamal,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify(
            &original.0,
            &reshuffle_commitment.inner,
            &rekey_commitment.inner,
        )
    }

    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(
                &original.0,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct())
    }
}

#[pyfunction]
#[pyo3(name = "verifiable_rsk")]
fn py_verifiable_rsk(m: &PyElGamal, s: &PyScalarNonZero, k: &PyScalarNonZero) -> PyVerifiableRSK {
    let mut rng = rand::rng();
    PyVerifiableRSK {
        inner: VerifiableRSK::new(&m.0, &s.0, &k.0, &mut rng),
    }
}

#[pyclass(name = "VerifiableRSK2", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRSK2 {
    pub(crate) inner: VerifiableRSK2,
}

#[pymethods]
impl PyVerifiableRSK2 {
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRSK2::new(&v.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng),
        }
    }

    fn verify_factor(
        &self,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify_factor(
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    fn combined_reshuffle_commitment(&self) -> PyPseudonymizationFactorCommitment {
        PyPseudonymizationFactorCommitment {
            inner: self.inner.combined_reshuffle_commitment(),
        }
    }

    fn combined_rekey_commitment(&self) -> PyRekeyFactorCommitment {
        PyRekeyFactorCommitment {
            inner: self.inner.combined_rekey_commitment(),
        }
    }

    fn verify(
        &self,
        original: &PyElGamal,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify(
            &original.0,
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(
                &original.0,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct())
    }
}

#[pyfunction]
#[pyo3(name = "verifiable_rsk2")]
fn py_verifiable_rsk2(
    m: &PyElGamal,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyVerifiableRSK2 {
    let mut rng = rand::rng();
    PyVerifiableRSK2 {
        inner: VerifiableRSK2::new(&m.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng),
    }
}

// ---------------------------------------------------------------------------
// VerifiableRRSK / VerifiableRRSK2
// ---------------------------------------------------------------------------

#[pyclass(name = "VerifiableRRSK", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRRSK {
    pub(crate) inner: VerifiableRRSK,
}

#[pymethods]
impl PyVerifiableRRSK {
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        r: &PyScalarNonZero,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRRSK::new(&v.0, &v.0.gy, &r.0, &s.0, &k.0, &mut rng),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        gy: &PyGroupElement,
        r: &PyScalarNonZero,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRRSK::new(&v.0, &gy.0, &r.0, &s.0, &k.0, &mut rng),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &PyElGamal,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify(
            &original.0,
            &original.0.gy,
            &reshuffle_commitment.inner,
            &rekey_commitment.inner,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &PyElGamal,
        gy: &PyGroupElement,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify(
            &original.0,
            &gy.0,
            &reshuffle_commitment.inner,
            &rekey_commitment.inner,
        )
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(
                &original.0,
                &original.0.gy,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
            .map(PyElGamal::from)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        gy: &PyGroupElement,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(
                &original.0,
                &gy.0,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct())
    }
}

#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk")]
fn py_verifiable_rrsk(
    m: &PyElGamal,
    r: &PyScalarNonZero,
    s: &PyScalarNonZero,
    k: &PyScalarNonZero,
) -> PyVerifiableRRSK {
    let mut rng = rand::rng();
    PyVerifiableRRSK {
        inner: VerifiableRRSK::new(&m.0, &m.0.gy, &r.0, &s.0, &k.0, &mut rng),
    }
}

#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk")]
fn py_verifiable_rrsk(
    m: &PyElGamal,
    gy: &PyGroupElement,
    r: &PyScalarNonZero,
    s: &PyScalarNonZero,
    k: &PyScalarNonZero,
) -> PyVerifiableRRSK {
    let mut rng = rand::rng();
    PyVerifiableRRSK {
        inner: VerifiableRRSK::new(&m.0, &gy.0, &r.0, &s.0, &k.0, &mut rng),
    }
}

#[pyclass(name = "VerifiableRRSK2", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRRSK2 {
    pub(crate) inner: VerifiableRRSK2,
}

#[pymethods]
impl PyVerifiableRRSK2 {
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        r: &PyScalarNonZero,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRRSK2::new(
                &v.0, &v.0.gy, &r.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
            ),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    fn new_proof(
        v: &PyElGamal,
        gy: &PyGroupElement,
        r: &PyScalarNonZero,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRRSK2::new(
                &v.0, &gy.0, &r.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
            ),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &PyElGamal,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify(
            &original.0,
            &original.0.gy,
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        original: &PyElGamal,
        gy: &PyGroupElement,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify(
            &original.0,
            &gy.0,
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(
                &original.0,
                &original.0.gy,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
            .map(PyElGamal::from)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    fn verified_reconstruct(
        &self,
        original: &PyElGamal,
        gy: &PyGroupElement,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(
                &original.0,
                &gy.0,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
            .map(PyElGamal::from)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self) -> PyElGamal {
        PyElGamal::from(self.inner.unverified_reconstruct())
    }
}

#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk2")]
fn py_verifiable_rrsk2(
    m: &PyElGamal,
    r: &PyScalarNonZero,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyVerifiableRRSK2 {
    let mut rng = rand::rng();
    PyVerifiableRRSK2 {
        inner: VerifiableRRSK2::new(
            &m.0, &m.0.gy, &r.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
        ),
    }
}

#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk2")]
#[allow(clippy::too_many_arguments)]
fn py_verifiable_rrsk2(
    m: &PyElGamal,
    gy: &PyGroupElement,
    r: &PyScalarNonZero,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyVerifiableRRSK2 {
    let mut rng = rand::rng();
    PyVerifiableRRSK2 {
        inner: VerifiableRRSK2::new(
            &m.0, &gy.0, &r.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
        ),
    }
}

// ---------------------------------------------------------------------------
// Batched proof types (feature = "batch")
// ---------------------------------------------------------------------------

#[cfg(feature = "batch")]
fn into_elgamal_vec(cts: &[PyElGamal]) -> Vec<crate::core::elgamal::ElGamal> {
    cts.iter().map(|c| c.0).collect()
}

#[cfg(feature = "batch")]
fn into_py_elgamal_vec(cts: Vec<crate::core::elgamal::ElGamal>) -> Vec<PyElGamal> {
    cts.into_iter().map(PyElGamal::from).collect()
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableRerandomizeBatch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRerandomizeBatch {
    pub(crate) inner: VerifiableRerandomizeBatch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableRerandomizeBatch {
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(n: usize, gy_source: &PyElGamal) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRerandomizeBatch::new(n, &gy_source.0.gy, &mut rng),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(n: usize, gy: &PyGroupElement) -> Self {
        let mut rng = rand::rng();
        Self {
            inner: VerifiableRerandomizeBatch::new(n, &gy.0, &mut rng),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn verify(&self, gy_source: &PyElGamal) -> bool {
        self.inner.verify(&gy_source.0.gy)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(&self, gy: &PyGroupElement) -> bool {
        self.inner.verify(&gy.0)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(&self, originals: Vec<PyElGamal>) -> Option<Vec<PyElGamal>> {
        if originals.is_empty() {
            return if self.inner.inners.is_empty() {
                Some(Vec::new())
            } else {
                None
            };
        }
        let gy = originals[0].0.gy;
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(&cts, &gy)
            .map(into_py_elgamal_vec)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        gy: &PyGroupElement,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(&cts, &gy.0)
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(all(feature = "batch", feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize_batch")]
fn py_verifiable_rerandomize_batch(
    originals: Vec<PyElGamal>,
) -> PyResult<(Vec<PyElGamal>, PyVerifiableRerandomizeBatch)> {
    if originals.is_empty() {
        return Err(PyValueError::new_err(
            "verifiable_rerandomize_batch requires at least one ciphertext",
        ));
    }
    let mut rng = rand::rng();
    let gy = originals[0].0.gy;
    let cts = into_elgamal_vec(&originals);
    let (results, proof) =
        crate::core::verifiable::verifiable_rerandomize_batch(&cts, &gy, &mut rng);
    Ok((
        into_py_elgamal_vec(results),
        PyVerifiableRerandomizeBatch { inner: proof },
    ))
}

#[cfg(all(feature = "batch", feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize_batch")]
fn py_verifiable_rerandomize_batch(
    originals: Vec<PyElGamal>,
    gy: &PyGroupElement,
) -> (Vec<PyElGamal>, PyVerifiableRerandomizeBatch) {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&originals);
    let (results, proof) =
        crate::core::verifiable::verifiable_rerandomize_batch(&cts, &gy.0, &mut rng);
    (
        into_py_elgamal_vec(results),
        PyVerifiableRerandomizeBatch { inner: proof },
    )
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableRekeyBatch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRekeyBatch {
    pub(crate) inner: VerifiableRekeyBatch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableRekeyBatch {
    #[staticmethod]
    fn new_proof(ciphertexts: Vec<PyElGamal>, k: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableRekeyBatch::new(&cts, &k.0, &mut rng),
        }
    }

    fn verify(&self, originals: Vec<PyElGamal>, commitment: &PyRekeyFactorCommitment) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner.verify(&cts, &commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(&cts, &commitment.inner)
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(feature = "batch")]
#[pyfunction]
#[pyo3(name = "verifiable_rekey_batch")]
fn py_verifiable_rekey_batch(
    ciphertexts: Vec<PyElGamal>,
    k: &PyScalarNonZero,
) -> PyVerifiableRekeyBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableRekeyBatch {
        inner: VerifiableRekeyBatch::new(&cts, &k.0, &mut rng),
    }
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableRekey2Batch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRekey2Batch {
    pub(crate) inner: VerifiableRekey2Batch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableRekey2Batch {
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableRekey2Batch::new(&cts, &k_from.0, &k_to.0, &mut rng),
        }
    }

    fn verify_factor(
        &self,
        from_commitment: &PyRekeyFactorCommitment,
        to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    fn combined_commitment(&self) -> PyRekeyFactorCommitment {
        PyRekeyFactorCommitment {
            inner: self.inner.combined_commitment(),
        }
    }

    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        from_commitment: &PyRekeyFactorCommitment,
        to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verify(&cts, &from_commitment.inner, &to_commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        from_commitment: &PyRekeyFactorCommitment,
        to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(&cts, &from_commitment.inner, &to_commitment.inner)
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(feature = "batch")]
#[pyfunction]
#[pyo3(name = "verifiable_rekey2_batch")]
fn py_verifiable_rekey2_batch(
    ciphertexts: Vec<PyElGamal>,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyVerifiableRekey2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableRekey2Batch {
        inner: VerifiableRekey2Batch::new(&cts, &k_from.0, &k_to.0, &mut rng),
    }
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableReshuffleBatch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableReshuffleBatch {
    pub(crate) inner: VerifiableReshuffleBatch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableReshuffleBatch {
    #[staticmethod]
    fn new_proof(ciphertexts: Vec<PyElGamal>, s: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableReshuffleBatch::new(&cts, &s.0, &mut rng),
        }
    }

    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        commitment: &PyPseudonymizationFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner.verify(&cts, &commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        commitment: &PyPseudonymizationFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(&cts, &commitment.inner)
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(feature = "batch")]
#[pyfunction]
#[pyo3(name = "verifiable_reshuffle_batch")]
fn py_verifiable_reshuffle_batch(
    ciphertexts: Vec<PyElGamal>,
    s: &PyScalarNonZero,
) -> PyVerifiableReshuffleBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableReshuffleBatch {
        inner: VerifiableReshuffleBatch::new(&cts, &s.0, &mut rng),
    }
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableReshuffle2Batch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableReshuffle2Batch {
    pub(crate) inner: VerifiableReshuffle2Batch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableReshuffle2Batch {
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableReshuffle2Batch::new(&cts, &s_from.0, &s_to.0, &mut rng),
        }
    }

    fn verify_factor(
        &self,
        from_commitment: &PyPseudonymizationFactorCommitment,
        to_commitment: &PyPseudonymizationFactorCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    fn combined_commitment(&self) -> PyPseudonymizationFactorCommitment {
        PyPseudonymizationFactorCommitment {
            inner: self.inner.combined_commitment(),
        }
    }

    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        from_commitment: &PyPseudonymizationFactorCommitment,
        to_commitment: &PyPseudonymizationFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verify(&cts, &from_commitment.inner, &to_commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        from_commitment: &PyPseudonymizationFactorCommitment,
        to_commitment: &PyPseudonymizationFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(&cts, &from_commitment.inner, &to_commitment.inner)
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(feature = "batch")]
#[pyfunction]
#[pyo3(name = "verifiable_reshuffle2_batch")]
fn py_verifiable_reshuffle2_batch(
    ciphertexts: Vec<PyElGamal>,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
) -> PyVerifiableReshuffle2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableReshuffle2Batch {
        inner: VerifiableReshuffle2Batch::new(&cts, &s_from.0, &s_to.0, &mut rng),
    }
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableRSKBatch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRSKBatch {
    pub(crate) inner: VerifiableRSKBatch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableRSKBatch {
    #[staticmethod]
    fn new_proof(ciphertexts: Vec<PyElGamal>, s: &PyScalarNonZero, k: &PyScalarNonZero) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableRSKBatch::new(&cts, &s.0, &k.0, &mut rng),
        }
    }

    fn verify_factor(
        &self,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&reshuffle_commitment.inner, &rekey_commitment.inner)
    }

    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verify(&cts, &reshuffle_commitment.inner, &rekey_commitment.inner)
    }

    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(&cts, &reshuffle_commitment.inner, &rekey_commitment.inner)
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(feature = "batch")]
#[pyfunction]
#[pyo3(name = "verifiable_rsk_batch")]
fn py_verifiable_rsk_batch(
    ciphertexts: Vec<PyElGamal>,
    s: &PyScalarNonZero,
    k: &PyScalarNonZero,
) -> PyVerifiableRSKBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableRSKBatch {
        inner: VerifiableRSKBatch::new(&cts, &s.0, &k.0, &mut rng),
    }
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableRSK2Batch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRSK2Batch {
    pub(crate) inner: VerifiableRSK2Batch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableRSK2Batch {
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableRSK2Batch::new(&cts, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng),
        }
    }

    fn verify_factor(
        &self,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.verify_factor(
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    fn combined_reshuffle_commitment(&self) -> PyPseudonymizationFactorCommitment {
        PyPseudonymizationFactorCommitment {
            inner: self.inner.combined_reshuffle_commitment(),
        }
    }

    fn combined_rekey_commitment(&self) -> PyRekeyFactorCommitment {
        PyRekeyFactorCommitment {
            inner: self.inner.combined_rekey_commitment(),
        }
    }

    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner.verify(
            &cts,
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(
                &cts,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(feature = "batch")]
#[pyfunction]
#[pyo3(name = "verifiable_rsk2_batch")]
fn py_verifiable_rsk2_batch(
    ciphertexts: Vec<PyElGamal>,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyVerifiableRSK2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableRSK2Batch {
        inner: VerifiableRSK2Batch::new(&cts, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng),
    }
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableRRSKBatch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRRSKBatch {
    pub(crate) inner: VerifiableRRSKBatch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableRRSKBatch {
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> PyResult<Self> {
        if ciphertexts.is_empty() {
            return Err(PyValueError::new_err(
                "VerifiableRRSKBatch requires at least one ciphertext",
            ));
        }
        let mut rng = rand::rng();
        let gy = ciphertexts[0].0.gy;
        let cts = into_elgamal_vec(&ciphertexts);
        Ok(Self {
            inner: VerifiableRRSKBatch::new(&cts, &gy, &s.0, &k.0, &mut rng),
        })
    }

    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        gy: &PyGroupElement,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableRRSKBatch::new(&cts, &gy.0, &s.0, &k.0, &mut rng),
        }
    }

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        if originals.is_empty() {
            return false;
        }
        let gy = originals[0].0.gy;
        let cts = into_elgamal_vec(&originals);
        self.inner.verify(
            &cts,
            &gy,
            &reshuffle_commitment.inner,
            &rekey_commitment.inner,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        gy: &PyGroupElement,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner.verify(
            &cts,
            &gy.0,
            &reshuffle_commitment.inner,
            &rekey_commitment.inner,
        )
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        if originals.is_empty() {
            return None;
        }
        let gy = originals[0].0.gy;
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(
                &cts,
                &gy,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
            .map(into_py_elgamal_vec)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        gy: &PyGroupElement,
        reshuffle_commitment: &PyPseudonymizationFactorCommitment,
        rekey_commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(
                &cts,
                &gy.0,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk_batch")]
fn py_verifiable_rrsk_batch(
    ciphertexts: Vec<PyElGamal>,
    s: &PyScalarNonZero,
    k: &PyScalarNonZero,
) -> PyResult<PyVerifiableRRSKBatch> {
    if ciphertexts.is_empty() {
        return Err(PyValueError::new_err(
            "verifiable_rrsk_batch requires at least one ciphertext",
        ));
    }
    let mut rng = rand::rng();
    let gy = ciphertexts[0].0.gy;
    let cts = into_elgamal_vec(&ciphertexts);
    Ok(PyVerifiableRRSKBatch {
        inner: VerifiableRRSKBatch::new(&cts, &gy, &s.0, &k.0, &mut rng),
    })
}

#[cfg(all(feature = "batch", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk_batch")]
fn py_verifiable_rrsk_batch(
    ciphertexts: Vec<PyElGamal>,
    gy: &PyGroupElement,
    s: &PyScalarNonZero,
    k: &PyScalarNonZero,
) -> PyVerifiableRRSKBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableRRSKBatch {
        inner: VerifiableRRSKBatch::new(&cts, &gy.0, &s.0, &k.0, &mut rng),
    }
}

#[cfg(feature = "batch")]
#[pyclass(name = "VerifiableRRSK2Batch", from_py_object)]
#[derive(Clone)]
pub struct PyVerifiableRRSK2Batch {
    pub(crate) inner: VerifiableRRSK2Batch,
}

#[cfg(feature = "batch")]
#[pymethods]
impl PyVerifiableRRSK2Batch {
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> PyResult<Self> {
        if ciphertexts.is_empty() {
            return Err(PyValueError::new_err(
                "VerifiableRRSK2Batch requires at least one ciphertext",
            ));
        }
        let mut rng = rand::rng();
        let gy = ciphertexts[0].0.gy;
        let cts = into_elgamal_vec(&ciphertexts);
        Ok(Self {
            inner: VerifiableRRSK2Batch::new(
                &cts, &gy, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
            ),
        })
    }

    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        gy: &PyGroupElement,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        Self {
            inner: VerifiableRRSK2Batch::new(
                &cts, &gy.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
            ),
        }
    }

    fn verify_factor(
        &self,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        self.inner.rsk2.verify_factor(
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        if originals.is_empty() {
            return false;
        }
        let gy = originals[0].0.gy;
        let cts = into_elgamal_vec(&originals);
        self.inner.verify(
            &cts,
            &gy,
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        gy: &PyGroupElement,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.inner.verify(
            &cts,
            &gy.0,
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        if originals.is_empty() {
            return None;
        }
        let gy = originals[0].0.gy;
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(
                &cts,
                &gy,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
            .map(into_py_elgamal_vec)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        gy: &PyGroupElement,
        s_from_commitment: &PyPseudonymizationFactorCommitment,
        s_to_commitment: &PyPseudonymizationFactorCommitment,
        k_from_commitment: &PyRekeyFactorCommitment,
        k_to_commitment: &PyRekeyFactorCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.inner
            .verified_reconstruct(
                &cts,
                &gy.0,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
            .map(into_py_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, originals: Vec<PyElGamal>) -> Vec<PyElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_py_elgamal_vec(self.inner.unverified_reconstruct(&cts))
    }
}

#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk2_batch")]
fn py_verifiable_rrsk2_batch(
    ciphertexts: Vec<PyElGamal>,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyResult<PyVerifiableRRSK2Batch> {
    if ciphertexts.is_empty() {
        return Err(PyValueError::new_err(
            "verifiable_rrsk2_batch requires at least one ciphertext",
        ));
    }
    let mut rng = rand::rng();
    let gy = ciphertexts[0].0.gy;
    let cts = into_elgamal_vec(&ciphertexts);
    Ok(PyVerifiableRRSK2Batch {
        inner: VerifiableRRSK2Batch::new(
            &cts, &gy, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
        ),
    })
}

#[cfg(all(feature = "batch", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "verifiable_rrsk2_batch")]
#[allow(clippy::too_many_arguments)]
fn py_verifiable_rrsk2_batch(
    ciphertexts: Vec<PyElGamal>,
    gy: &PyGroupElement,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyVerifiableRRSK2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    PyVerifiableRRSK2Batch {
        inner: VerifiableRRSK2Batch::new(
            &cts, &gy.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0, &mut rng,
        ),
    }
}

// Auto-generated serde JSON impls (separate impls to avoid macros-in-impl issue).
py_serde_impl!(PyFactorCommitment, FactorCommitment);
py_serde_impl!(PyRekeyFactorCommitment, RekeyFactorCommitment);
py_serde_impl!(
    PyPseudonymizationFactorCommitment,
    PseudonymizationFactorCommitment
);
py_serde_impl!(PyVerifiableRerandomize, VerifiableRerandomize);
py_serde_impl!(PyVerifiableRekey, VerifiableRekey);
py_serde_impl!(PyVerifiableRekey2, VerifiableRekey2);
py_serde_impl!(PyVerifiableReshuffle, VerifiableReshuffle);
py_serde_impl!(PyVerifiableReshuffle2, VerifiableReshuffle2);
py_serde_impl!(PyVerifiableRSKInner, VerifiableRSKInner);
py_serde_impl!(PyVerifiableRSK, VerifiableRSK);
py_serde_impl!(PyVerifiableRSK2, VerifiableRSK2);
py_serde_impl!(PyVerifiableRRSK, VerifiableRRSK);
py_serde_impl!(PyVerifiableRRSK2, VerifiableRRSK2);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableRerandomizeBatch, VerifiableRerandomizeBatch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableRekeyBatch, VerifiableRekeyBatch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableRekey2Batch, VerifiableRekey2Batch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableReshuffleBatch, VerifiableReshuffleBatch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableReshuffle2Batch, VerifiableReshuffle2Batch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableRSKBatch, VerifiableRSKBatch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableRSK2Batch, VerifiableRSK2Batch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableRRSKBatch, VerifiableRRSKBatch);
#[cfg(feature = "batch")]
py_serde_impl!(PyVerifiableRRSK2Batch, VerifiableRRSK2Batch);

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

pub fn register_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent_module.py(), "verifiable")?;

    // Commitments.
    m.add_class::<PyFactorCommitment>()?;
    m.add_class::<PyRekeyFactorCommitment>()?;
    m.add_class::<PyPseudonymizationFactorCommitment>()?;

    // Per-message proof types.
    m.add_class::<PyVerifiableRerandomize>()?;
    m.add_class::<PyVerifiableRekey>()?;
    m.add_class::<PyVerifiableRekey2>()?;
    m.add_class::<PyVerifiableReshuffle>()?;
    m.add_class::<PyVerifiableReshuffle2>()?;
    m.add_class::<PyVerifiableRSKInner>()?;
    m.add_class::<PyVerifiableRSK>()?;
    m.add_class::<PyVerifiableRSK2>()?;
    m.add_class::<PyVerifiableRRSK>()?;
    m.add_class::<PyVerifiableRRSK2>()?;

    // Per-message free functions.
    #[cfg(feature = "insecure")]
    m.add_function(wrap_pyfunction!(py_verifiable_rerandomize, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_rekey, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_rekey2, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_reshuffle, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_reshuffle2, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_rsk, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_rsk2, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_rrsk, &m)?)?;
    m.add_function(wrap_pyfunction!(py_verifiable_rrsk2, &m)?)?;

    // Batched proof types.
    #[cfg(feature = "batch")]
    {
        m.add_class::<PyVerifiableRerandomizeBatch>()?;
        m.add_class::<PyVerifiableRekeyBatch>()?;
        m.add_class::<PyVerifiableRekey2Batch>()?;
        m.add_class::<PyVerifiableReshuffleBatch>()?;
        m.add_class::<PyVerifiableReshuffle2Batch>()?;
        m.add_class::<PyVerifiableRSKBatch>()?;
        m.add_class::<PyVerifiableRSK2Batch>()?;
        m.add_class::<PyVerifiableRRSKBatch>()?;
        m.add_class::<PyVerifiableRRSK2Batch>()?;

        #[cfg(feature = "insecure")]
        m.add_function(wrap_pyfunction!(py_verifiable_rerandomize_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_rekey_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_rekey2_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_reshuffle_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_reshuffle2_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_rsk_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_rsk2_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_rrsk_batch, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_rrsk2_batch, &m)?)?;
    }

    parent_module.add_submodule(&m)?;
    parent_module
        .py()
        .import("sys")?
        .getattr("modules")?
        .set_item("libpep.core.verifiable", &m)?;
    Ok(())
}
