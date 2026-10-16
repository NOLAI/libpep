//! Python bindings for the verifiable primitives (`libpep.elgamal.verifiable`).
//!
//! Mirrors `libpep::elgamal::verifiable`: the factor commitments and one class per proof type,
//! single and batched. Every class has `new_proof`, `verify`, `verified_reconstruct` and (with
//! `insecure`) `unverified_reconstruct`; the two-factor proofs also have `verify_factor` and
//! their combined commitments. Without `elgamal3` the rerandomizing proofs take the public key
//! `gy` the ciphertexts are encrypted under; with `elgamal3` it is read from the ciphertexts.

#[cfg(not(feature = "elgamal3"))]
use crate::elgamal::arithmetic::PyGroupElement;
use crate::elgamal::arithmetic::PyScalarNonZero;
use crate::elgamal::PyElGamal;
#[cfg(feature = "elgamal3")]
use libpep::elgamal::arithmetic::group_elements::GroupElement;
use libpep::elgamal::verifiable::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRRSK,
    VerifiableRRSK2, VerifiableRRSK2Batch, VerifiableRRSKBatch, VerifiableRSK, VerifiableRSK2,
    VerifiableRSK2Batch, VerifiableRSKBatch, VerifiableRSKInner, VerifiableRekey, VerifiableRekey2,
    VerifiableRekey2Batch, VerifiableRekeyBatch, VerifiableRerandomize, VerifiableRerandomizeBatch,
    VerifiableReshuffle, VerifiableReshuffle2, VerifiableReshuffle2Batch, VerifiableReshuffleBatch,
};
use libpep::elgamal::ElGamal;
#[cfg(feature = "elgamal3")]
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// The library ciphertexts of a list of binding ciphertexts.
fn els(ciphertexts: &[PyElGamal]) -> Vec<ElGamal> {
    ciphertexts.iter().map(|c| c.0).collect()
}

/// A library result as its binding value.
trait ToPy {
    type Py;
    fn to_py(self) -> Self::Py;
}

impl ToPy for ElGamal {
    type Py = PyElGamal;
    fn to_py(self) -> PyElGamal {
        PyElGamal::from(self)
    }
}

impl ToPy for Vec<ElGamal> {
    type Py = Vec<PyElGamal>;
    fn to_py(self) -> Vec<PyElGamal> {
        self.into_iter().map(PyElGamal::from).collect()
    }
}

/// The key every one of `ciphertexts` carries, which a batch proof is made under.
#[cfg(feature = "elgamal3")]
fn common_gy(ciphertexts: &[PyElGamal]) -> PyResult<GroupElement> {
    let first = ciphertexts.first().ok_or_else(|| {
        PyValueError::new_err("the batch has no ciphertexts to read the key from")
    })?;
    if ciphertexts.iter().any(|c| c.0.gy != first.0.gy) {
        return Err(PyValueError::new_err(
            "the ciphertexts of a batch must carry one key",
        ));
    }
    Ok(first.0.gy)
}

/// A class wrapping a library type as `inner`, with JSON (de)serialization.
macro_rules! py_class {
    ($(#[$doc:meta])* $py:ident($inner:ty) as $name:literal) => {
        $(#[$doc])*
        #[pyclass(name = $name, from_py_object)]
        #[derive(Clone)]
        pub struct $py {
            pub(crate) inner: $inner,
        }

        impl From<$inner> for $py {
            fn from(inner: $inner) -> Self {
                Self { inner }
            }
        }

        #[cfg(feature = "serde")]
        #[pymethods]
        impl $py {
            /// Serialize to JSON.
            fn to_json(&self) -> PyResult<String> {
                serde_json::to_string(&self.inner).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize: {e}"))
                })
            }

            /// Deserialize from JSON.
            #[staticmethod]
            fn from_json(json: &str) -> PyResult<Self> {
                serde_json::from_str::<$inner>(json).map(Self::from).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Failed to deserialize: {e}"))
                })
            }
        }
    };
}

/// `verify` and `verified_reconstruct`, which take the same arguments; `$call` are the
/// library arguments built from them.
macro_rules! py_verify {
    ($(#[$cfg:meta])? $py:ident: ($($arg:ident: $ty:ty),*) -> $out:ty = [$($call:expr),*]) => {
        $(#[$cfg])?
        #[pymethods]
        impl $py {
            /// Verify the proof against the original ciphertext(s) and the commitments.
            fn verify(&self, $($arg: $ty),*) -> bool {
                self.inner.verify($($call),*)
            }

            /// Verify the proof and return the result, or `None` if it does not verify.
            fn verified_reconstruct(&self, $($arg: $ty),*) -> Option<$out> {
                self.inner.verified_reconstruct($($call),*).map(ToPy::to_py)
            }
        }
    };
}

/// `unverified_reconstruct` (`insecure` only).
macro_rules! py_unverified {
    ($py:ident: ($($arg:ident: $ty:ty),*) -> $out:ty = [$($call:expr),*]) => {
        #[cfg(feature = "insecure")]
        #[pymethods]
        impl $py {
            /// The result of the operation, without verifying the proof.
            fn unverified_reconstruct(&self, $($arg: $ty),*) -> $out {
                self.inner.unverified_reconstruct($($call),*).to_py()
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Factor commitments
// ---------------------------------------------------------------------------

macro_rules! py_commitment {
    ($(#[$doc:meta])* $py:ident($inner:ty) as $name:literal) => {
        py_class!($(#[$doc])* $py($inner) as $name);

        #[pymethods]
        impl $py {
            /// The commitment `a·G` to the scalar `a`.
            #[staticmethod]
            fn new_from_scalar(a: &PyScalarNonZero) -> Self {
                Self::from(<$inner>::new(&a.0))
            }
        }
    };
}

py_commitment!(
    /// Forward commitment `A = a·G` to a factor scalar `a`.
    PyFactorCommitment(FactorCommitment) as "FactorCommitment"
);
py_commitment!(
    /// Commitment `K = k·G` to a rekey factor.
    PyRekeyFactorCommitment(RekeyFactorCommitment) as "RekeyFactorCommitment"
);
py_commitment!(
    /// Commitment `S = s·G` to a pseudonymization (reshuffle) factor.
    PyPseudonymizationFactorCommitment(PseudonymizationFactorCommitment)
        as "PseudonymizationFactorCommitment"
);

type PyReshuffleCommitment = PyPseudonymizationFactorCommitment;
type PyRekeyCommitment = PyRekeyFactorCommitment;

// ---------------------------------------------------------------------------
// Per-message proofs
// ---------------------------------------------------------------------------

py_class!(PyVerifiableRerandomize(VerifiableRerandomize) as "VerifiableRerandomize");

#[pymethods]
impl PyVerifiableRerandomize {
    /// A proof of rerandomizing a ciphertext of `v` with `r`.
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(v: &PyElGamal, r: &PyScalarNonZero) -> Self {
        VerifiableRerandomize::new(&v.0.gy, &r.0, &mut rand::rng()).into()
    }

    /// A proof of rerandomizing a ciphertext under `gy` with `r`.
    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(gy: &PyGroupElement, r: &PyScalarNonZero) -> Self {
        VerifiableRerandomize::new(&gy.0, &r.0, &mut rand::rng()).into()
    }

    /// Verify the proof against the key of `v`.
    #[cfg(feature = "elgamal3")]
    fn verify(&self, v: &PyElGamal) -> bool {
        self.inner.verify(&v.0.gy)
    }

    /// Verify the proof against `gy`.
    #[cfg(not(feature = "elgamal3"))]
    fn verify(&self, gy: &PyGroupElement) -> bool {
        self.inner.verify(&gy.0)
    }

    /// Verify the proof and return the rerandomized ciphertext, or `None`.
    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(&self, original: &PyElGamal) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &original.0.gy)
            .map(ToPy::to_py)
    }

    /// Verify the proof and return the rerandomized ciphertext, or `None`.
    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(&self, original: &PyElGamal, gy: &PyGroupElement) -> Option<PyElGamal> {
        self.inner
            .verified_reconstruct(&original.0, &gy.0)
            .map(ToPy::to_py)
    }
}
py_unverified!(PyVerifiableRerandomize: (original: &PyElGamal) -> PyElGamal = [&original.0]);

/// Rerandomize a ciphertext with a proof: the rerandomized ciphertext and the proof.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize")]
fn py_verifiable_rerandomize(
    original: &PyElGamal,
    r: &PyScalarNonZero,
) -> (PyElGamal, PyVerifiableRerandomize) {
    let (result, proof) =
        libpep::elgamal::verifiable::verifiable_rerandomize(&original.0, &r.0, &mut rand::rng());
    (result.to_py(), proof.into())
}

/// Rerandomize a ciphertext under `gy` with a proof: the rerandomized ciphertext and the proof.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize")]
fn py_verifiable_rerandomize(
    original: &PyElGamal,
    gy: &PyGroupElement,
    r: &PyScalarNonZero,
) -> (PyElGamal, PyVerifiableRerandomize) {
    let (result, proof) = libpep::elgamal::verifiable::verifiable_rerandomize(
        &original.0,
        &gy.0,
        &r.0,
        &mut rand::rng(),
    );
    (result.to_py(), proof.into())
}

py_class!(PyVerifiableRekey(VerifiableRekey) as "VerifiableRekey");
#[pymethods]
impl PyVerifiableRekey {
    /// A proof of rekeying `v` with `k`.
    #[staticmethod]
    fn new_proof(v: &PyElGamal, k: &PyScalarNonZero) -> Self {
        VerifiableRekey::new(&v.0, &k.0, &mut rand::rng()).into()
    }
}
py_verify!(PyVerifiableRekey: (original: &PyElGamal, commitment: &PyRekeyCommitment) -> PyElGamal
    = [&original.0, &commitment.inner]);
py_unverified!(PyVerifiableRekey: (original: &PyElGamal) -> PyElGamal = [&original.0]);

py_class!(PyVerifiableRekey2(VerifiableRekey2) as "VerifiableRekey2");
#[pymethods]
impl PyVerifiableRekey2 {
    /// A proof of rekeying `v` from `k_from` to `k_to`.
    #[staticmethod]
    fn new_proof(v: &PyElGamal, k_from: &PyScalarNonZero, k_to: &PyScalarNonZero) -> Self {
        VerifiableRekey2::new(&v.0, &k_from.0, &k_to.0, &mut rand::rng()).into()
    }

    /// Verify the factor sub-proof against the commitments of both sessions.
    fn verify_factor(
        &self,
        from_commitment: &PyRekeyCommitment,
        to_commitment: &PyRekeyCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    /// The commitment to the combined factor `k_from⁻¹·k_to`.
    fn combined_commitment(&self) -> PyRekeyCommitment {
        self.inner.combined_commitment().into()
    }
}
py_verify!(PyVerifiableRekey2: (
    original: &PyElGamal, from_commitment: &PyRekeyCommitment, to_commitment: &PyRekeyCommitment
) -> PyElGamal = [&original.0, &from_commitment.inner, &to_commitment.inner]);
py_unverified!(PyVerifiableRekey2: (original: &PyElGamal) -> PyElGamal = [&original.0]);

py_class!(PyVerifiableReshuffle(VerifiableReshuffle) as "VerifiableReshuffle");
#[pymethods]
impl PyVerifiableReshuffle {
    /// A proof of reshuffling `v` with `s`.
    #[staticmethod]
    fn new_proof(v: &PyElGamal, s: &PyScalarNonZero) -> Self {
        VerifiableReshuffle::new(&v.0, &s.0, &mut rand::rng()).into()
    }
}
py_verify!(PyVerifiableReshuffle: (original: &PyElGamal, commitment: &PyReshuffleCommitment)
    -> PyElGamal = [&original.0, &commitment.inner]);
py_unverified!(PyVerifiableReshuffle: (original: &PyElGamal) -> PyElGamal = [&original.0]);

py_class!(PyVerifiableReshuffle2(VerifiableReshuffle2) as "VerifiableReshuffle2");
#[pymethods]
impl PyVerifiableReshuffle2 {
    /// A proof of reshuffling `v` from `s_from` to `s_to`.
    #[staticmethod]
    fn new_proof(v: &PyElGamal, s_from: &PyScalarNonZero, s_to: &PyScalarNonZero) -> Self {
        VerifiableReshuffle2::new(&v.0, &s_from.0, &s_to.0, &mut rand::rng()).into()
    }

    /// Verify the factor sub-proof against the commitments of both domains.
    fn verify_factor(
        &self,
        from_commitment: &PyReshuffleCommitment,
        to_commitment: &PyReshuffleCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    /// The commitment to the combined factor `s_from⁻¹·s_to`.
    fn combined_commitment(&self) -> PyReshuffleCommitment {
        self.inner.combined_commitment().into()
    }
}
py_verify!(PyVerifiableReshuffle2: (
    original: &PyElGamal,
    from_commitment: &PyReshuffleCommitment,
    to_commitment: &PyReshuffleCommitment
) -> PyElGamal = [&original.0, &from_commitment.inner, &to_commitment.inner]);
py_unverified!(PyVerifiableReshuffle2: (original: &PyElGamal) -> PyElGamal = [&original.0]);

py_class!(
    /// The per-ciphertext part of an RSK proof; verified through the proof that carries it.
    PyVerifiableRSKInner(VerifiableRSKInner) as "VerifiableRSKInner"
);

py_class!(PyVerifiableRSK(VerifiableRSK) as "VerifiableRSK");
#[pymethods]
impl PyVerifiableRSK {
    /// A proof of reshuffling and rekeying `v` with `s` and `k`.
    #[staticmethod]
    fn new_proof(v: &PyElGamal, s: &PyScalarNonZero, k: &PyScalarNonZero) -> Self {
        VerifiableRSK::new(&v.0, &s.0, &k.0, &mut rand::rng()).into()
    }
}
py_verify!(PyVerifiableRSK: (
    original: &PyElGamal,
    reshuffle_commitment: &PyReshuffleCommitment,
    rekey_commitment: &PyRekeyCommitment
) -> PyElGamal = [&original.0, &reshuffle_commitment.inner, &rekey_commitment.inner]);
py_unverified!(PyVerifiableRSK: () -> PyElGamal = []);

py_class!(PyVerifiableRSK2(VerifiableRSK2) as "VerifiableRSK2");
#[pymethods]
impl PyVerifiableRSK2 {
    /// A proof of transitively reshuffling and rekeying `v`.
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        VerifiableRSK2::new(
            &v.0,
            &s_from.0,
            &s_to.0,
            &k_from.0,
            &k_to.0,
            &mut rand::rng(),
        )
        .into()
    }

    /// Verify the factor sub-proofs against the commitments of both domains and sessions.
    fn verify_factor(
        &self,
        s_from_commitment: &PyReshuffleCommitment,
        s_to_commitment: &PyReshuffleCommitment,
        k_from_commitment: &PyRekeyCommitment,
        k_to_commitment: &PyRekeyCommitment,
    ) -> bool {
        self.inner.verify_factor(
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    /// The commitment to the combined reshuffle factor.
    fn combined_reshuffle_commitment(&self) -> PyReshuffleCommitment {
        self.inner.combined_reshuffle_commitment().into()
    }

    /// The commitment to the combined rekey factor.
    fn combined_rekey_commitment(&self) -> PyRekeyCommitment {
        self.inner.combined_rekey_commitment().into()
    }
}
py_verify!(PyVerifiableRSK2: (
    original: &PyElGamal,
    s_from_commitment: &PyReshuffleCommitment,
    s_to_commitment: &PyReshuffleCommitment,
    k_from_commitment: &PyRekeyCommitment,
    k_to_commitment: &PyRekeyCommitment
) -> PyElGamal = [
    &original.0,
    &s_from_commitment.inner,
    &s_to_commitment.inner,
    &k_from_commitment.inner,
    &k_to_commitment.inner
]);
py_unverified!(PyVerifiableRSK2: () -> PyElGamal = []);

py_class!(PyVerifiableRRSK(VerifiableRRSK) as "VerifiableRRSK");
#[pymethods]
impl PyVerifiableRRSK {
    /// A proof of rerandomizing with `r`, then reshuffling and rekeying with `s` and `k`.
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        r: &PyScalarNonZero,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> Self {
        VerifiableRRSK::new(&v.0, &v.0.gy, &r.0, &s.0, &k.0, &mut rand::rng()).into()
    }

    /// A proof of rerandomizing under `gy` with `r`, then reshuffling and rekeying with `s`
    /// and `k`.
    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        gy: &PyGroupElement,
        r: &PyScalarNonZero,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> Self {
        VerifiableRRSK::new(&v.0, &gy.0, &r.0, &s.0, &k.0, &mut rand::rng()).into()
    }
}
py_verify!(#[cfg(feature = "elgamal3")] PyVerifiableRRSK: (
    original: &PyElGamal,
    reshuffle_commitment: &PyReshuffleCommitment,
    rekey_commitment: &PyRekeyCommitment
) -> PyElGamal = [
    &original.0,
    &original.0.gy,
    &reshuffle_commitment.inner,
    &rekey_commitment.inner
]);
py_verify!(#[cfg(not(feature = "elgamal3"))] PyVerifiableRRSK: (
    original: &PyElGamal,
    gy: &PyGroupElement,
    reshuffle_commitment: &PyReshuffleCommitment,
    rekey_commitment: &PyRekeyCommitment
) -> PyElGamal = [&original.0, &gy.0, &reshuffle_commitment.inner, &rekey_commitment.inner]);
py_unverified!(PyVerifiableRRSK: () -> PyElGamal = []);

py_class!(PyVerifiableRRSK2(VerifiableRRSK2) as "VerifiableRRSK2");
#[pymethods]
impl PyVerifiableRRSK2 {
    /// A proof of rerandomizing with `r`, then transitively reshuffling and rekeying.
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
        VerifiableRRSK2::new(
            &v.0,
            &v.0.gy,
            &r.0,
            &s_from.0,
            &s_to.0,
            &k_from.0,
            &k_to.0,
            &mut rand::rng(),
        )
        .into()
    }

    /// A proof of rerandomizing under `gy` with `r`, then transitively reshuffling and
    /// rekeying.
    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    #[staticmethod]
    fn new_proof(
        v: &PyElGamal,
        gy: &PyGroupElement,
        r: &PyScalarNonZero,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        VerifiableRRSK2::new(
            &v.0,
            &gy.0,
            &r.0,
            &s_from.0,
            &s_to.0,
            &k_from.0,
            &k_to.0,
            &mut rand::rng(),
        )
        .into()
    }
}
py_verify!(#[cfg(feature = "elgamal3")] PyVerifiableRRSK2: (
    original: &PyElGamal,
    s_from_commitment: &PyReshuffleCommitment,
    s_to_commitment: &PyReshuffleCommitment,
    k_from_commitment: &PyRekeyCommitment,
    k_to_commitment: &PyRekeyCommitment
) -> PyElGamal = [
    &original.0,
    &original.0.gy,
    &s_from_commitment.inner,
    &s_to_commitment.inner,
    &k_from_commitment.inner,
    &k_to_commitment.inner
]);
py_verify!(#[cfg(not(feature = "elgamal3"))] PyVerifiableRRSK2: (
    original: &PyElGamal,
    gy: &PyGroupElement,
    s_from_commitment: &PyReshuffleCommitment,
    s_to_commitment: &PyReshuffleCommitment,
    k_from_commitment: &PyRekeyCommitment,
    k_to_commitment: &PyRekeyCommitment
) -> PyElGamal = [
    &original.0,
    &gy.0,
    &s_from_commitment.inner,
    &s_to_commitment.inner,
    &k_from_commitment.inner,
    &k_to_commitment.inner
]);
py_unverified!(PyVerifiableRRSK2: () -> PyElGamal = []);

// ---------------------------------------------------------------------------
// Batched proofs
// ---------------------------------------------------------------------------

py_class!(PyVerifiableRerandomizeBatch(VerifiableRerandomizeBatch) as "VerifiableRerandomizeBatch");

#[pymethods]
impl PyVerifiableRerandomizeBatch {
    /// A proof of rerandomizing `n` ciphertexts carrying the key of `gy_source`.
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(n: usize, gy_source: &PyElGamal) -> Self {
        VerifiableRerandomizeBatch::new(n, &gy_source.0.gy, &mut rand::rng()).into()
    }

    /// A proof of rerandomizing `n` ciphertexts under `gy`.
    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(n: usize, gy: &PyGroupElement) -> Self {
        VerifiableRerandomizeBatch::new(n, &gy.0, &mut rand::rng()).into()
    }

    /// Verify the proof against `originals`, which carry one key.
    #[cfg(feature = "elgamal3")]
    fn verify(&self, originals: Vec<PyElGamal>) -> bool {
        common_gy(&originals).is_ok_and(|gy| self.inner.verify(&els(&originals), &gy))
    }

    /// Verify the proof against `originals` and `gy`.
    #[cfg(not(feature = "elgamal3"))]
    fn verify(&self, originals: Vec<PyElGamal>, gy: &PyGroupElement) -> bool {
        self.inner.verify(&els(&originals), &gy.0)
    }

    /// Verify the proof and return the rerandomized ciphertexts, or `None`.
    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(&self, originals: Vec<PyElGamal>) -> Option<Vec<PyElGamal>> {
        let gy = common_gy(&originals).ok()?;
        self.inner
            .verified_reconstruct(&els(&originals), &gy)
            .map(ToPy::to_py)
    }

    /// Verify the proof and return the rerandomized ciphertexts, or `None`.
    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        gy: &PyGroupElement,
    ) -> Option<Vec<PyElGamal>> {
        self.inner
            .verified_reconstruct(&els(&originals), &gy.0)
            .map(ToPy::to_py)
    }
}
py_unverified!(PyVerifiableRerandomizeBatch: (originals: Vec<PyElGamal>) -> Vec<PyElGamal>
    = [&els(&originals)]);

/// Rerandomize ciphertexts with a proof: the rerandomized ciphertexts and the proof.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize_batch")]
fn py_verifiable_rerandomize_batch(
    originals: Vec<PyElGamal>,
) -> PyResult<(Vec<PyElGamal>, PyVerifiableRerandomizeBatch)> {
    let gy = common_gy(&originals)?;
    let (result, proof) = libpep::elgamal::verifiable::verifiable_rerandomize_batch(
        &els(&originals),
        &gy,
        &mut rand::rng(),
    );
    Ok((result.to_py(), proof.into()))
}

/// Rerandomize ciphertexts under `gy` with a proof: the rerandomized ciphertexts and the proof.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[pyfunction]
#[pyo3(name = "verifiable_rerandomize_batch")]
fn py_verifiable_rerandomize_batch(
    originals: Vec<PyElGamal>,
    gy: &PyGroupElement,
) -> (Vec<PyElGamal>, PyVerifiableRerandomizeBatch) {
    let (result, proof) = libpep::elgamal::verifiable::verifiable_rerandomize_batch(
        &els(&originals),
        &gy.0,
        &mut rand::rng(),
    );
    (result.to_py(), proof.into())
}

py_class!(PyVerifiableRekeyBatch(VerifiableRekeyBatch) as "VerifiableRekeyBatch");
#[pymethods]
impl PyVerifiableRekeyBatch {
    /// A proof of rekeying every ciphertext with `k`.
    #[staticmethod]
    fn new_proof(ciphertexts: Vec<PyElGamal>, k: &PyScalarNonZero) -> Self {
        VerifiableRekeyBatch::new(&els(&ciphertexts), &k.0, &mut rand::rng()).into()
    }
}
py_verify!(PyVerifiableRekeyBatch: (originals: Vec<PyElGamal>, commitment: &PyRekeyCommitment)
    -> Vec<PyElGamal> = [&els(&originals), &commitment.inner]);
py_unverified!(PyVerifiableRekeyBatch: (originals: Vec<PyElGamal>) -> Vec<PyElGamal>
    = [&els(&originals)]);

py_class!(PyVerifiableRekey2Batch(VerifiableRekey2Batch) as "VerifiableRekey2Batch");
#[pymethods]
impl PyVerifiableRekey2Batch {
    /// A proof of rekeying every ciphertext from `k_from` to `k_to`.
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        VerifiableRekey2Batch::new(&els(&ciphertexts), &k_from.0, &k_to.0, &mut rand::rng()).into()
    }

    /// Verify the factor sub-proof against the commitments of both sessions.
    fn verify_factor(
        &self,
        from_commitment: &PyRekeyCommitment,
        to_commitment: &PyRekeyCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    /// The commitment to the combined factor `k_from⁻¹·k_to`.
    fn combined_commitment(&self) -> PyRekeyCommitment {
        self.inner.combined_commitment().into()
    }
}
py_verify!(PyVerifiableRekey2Batch: (
    originals: Vec<PyElGamal>,
    from_commitment: &PyRekeyCommitment,
    to_commitment: &PyRekeyCommitment
) -> Vec<PyElGamal> = [&els(&originals), &from_commitment.inner, &to_commitment.inner]);
py_unverified!(PyVerifiableRekey2Batch: (originals: Vec<PyElGamal>) -> Vec<PyElGamal>
    = [&els(&originals)]);

py_class!(PyVerifiableReshuffleBatch(VerifiableReshuffleBatch) as "VerifiableReshuffleBatch");
#[pymethods]
impl PyVerifiableReshuffleBatch {
    /// A proof of reshuffling every ciphertext with `s`.
    #[staticmethod]
    fn new_proof(ciphertexts: Vec<PyElGamal>, s: &PyScalarNonZero) -> Self {
        VerifiableReshuffleBatch::new(&els(&ciphertexts), &s.0, &mut rand::rng()).into()
    }
}
py_verify!(PyVerifiableReshuffleBatch: (
    originals: Vec<PyElGamal>,
    commitment: &PyReshuffleCommitment
) -> Vec<PyElGamal> = [&els(&originals), &commitment.inner]);
py_unverified!(PyVerifiableReshuffleBatch: (originals: Vec<PyElGamal>) -> Vec<PyElGamal>
    = [&els(&originals)]);

py_class!(PyVerifiableReshuffle2Batch(VerifiableReshuffle2Batch) as "VerifiableReshuffle2Batch");
#[pymethods]
impl PyVerifiableReshuffle2Batch {
    /// A proof of reshuffling every ciphertext from `s_from` to `s_to`.
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
    ) -> Self {
        VerifiableReshuffle2Batch::new(&els(&ciphertexts), &s_from.0, &s_to.0, &mut rand::rng())
            .into()
    }

    /// Verify the factor sub-proof against the commitments of both domains.
    fn verify_factor(
        &self,
        from_commitment: &PyReshuffleCommitment,
        to_commitment: &PyReshuffleCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&from_commitment.inner, &to_commitment.inner)
    }

    /// The commitment to the combined factor `s_from⁻¹·s_to`.
    fn combined_commitment(&self) -> PyReshuffleCommitment {
        self.inner.combined_commitment().into()
    }
}
py_verify!(PyVerifiableReshuffle2Batch: (
    originals: Vec<PyElGamal>,
    from_commitment: &PyReshuffleCommitment,
    to_commitment: &PyReshuffleCommitment
) -> Vec<PyElGamal> = [&els(&originals), &from_commitment.inner, &to_commitment.inner]);
py_unverified!(PyVerifiableReshuffle2Batch: (originals: Vec<PyElGamal>) -> Vec<PyElGamal>
    = [&els(&originals)]);

py_class!(PyVerifiableRSKBatch(VerifiableRSKBatch) as "VerifiableRSKBatch");
#[pymethods]
impl PyVerifiableRSKBatch {
    /// A proof of reshuffling and rekeying every ciphertext with `s` and `k`.
    #[staticmethod]
    fn new_proof(ciphertexts: Vec<PyElGamal>, s: &PyScalarNonZero, k: &PyScalarNonZero) -> Self {
        VerifiableRSKBatch::new(&els(&ciphertexts), &s.0, &k.0, &mut rand::rng()).into()
    }

    /// Verify the factor sub-proof against the commitments.
    fn verify_factor(
        &self,
        reshuffle_commitment: &PyReshuffleCommitment,
        rekey_commitment: &PyRekeyCommitment,
    ) -> bool {
        self.inner
            .verify_factor(&reshuffle_commitment.inner, &rekey_commitment.inner)
    }
}
py_verify!(PyVerifiableRSKBatch: (
    originals: Vec<PyElGamal>,
    reshuffle_commitment: &PyReshuffleCommitment,
    rekey_commitment: &PyRekeyCommitment
) -> Vec<PyElGamal> = [&els(&originals), &reshuffle_commitment.inner, &rekey_commitment.inner]);
py_unverified!(PyVerifiableRSKBatch: () -> Vec<PyElGamal> = []);

py_class!(PyVerifiableRSK2Batch(VerifiableRSK2Batch) as "VerifiableRSK2Batch");
#[pymethods]
impl PyVerifiableRSK2Batch {
    /// A proof of transitively reshuffling and rekeying every ciphertext.
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        VerifiableRSK2Batch::new(
            &els(&ciphertexts),
            &s_from.0,
            &s_to.0,
            &k_from.0,
            &k_to.0,
            &mut rand::rng(),
        )
        .into()
    }

    /// Verify the factor sub-proofs against the commitments of both domains and sessions.
    fn verify_factor(
        &self,
        s_from_commitment: &PyReshuffleCommitment,
        s_to_commitment: &PyReshuffleCommitment,
        k_from_commitment: &PyRekeyCommitment,
        k_to_commitment: &PyRekeyCommitment,
    ) -> bool {
        self.inner.verify_factor(
            &s_from_commitment.inner,
            &s_to_commitment.inner,
            &k_from_commitment.inner,
            &k_to_commitment.inner,
        )
    }

    /// The commitment to the combined reshuffle factor.
    fn combined_reshuffle_commitment(&self) -> PyReshuffleCommitment {
        self.inner.combined_reshuffle_commitment().into()
    }

    /// The commitment to the combined rekey factor.
    fn combined_rekey_commitment(&self) -> PyRekeyCommitment {
        self.inner.combined_rekey_commitment().into()
    }
}
py_verify!(PyVerifiableRSK2Batch: (
    originals: Vec<PyElGamal>,
    s_from_commitment: &PyReshuffleCommitment,
    s_to_commitment: &PyReshuffleCommitment,
    k_from_commitment: &PyRekeyCommitment,
    k_to_commitment: &PyRekeyCommitment
) -> Vec<PyElGamal> = [
    &els(&originals),
    &s_from_commitment.inner,
    &s_to_commitment.inner,
    &k_from_commitment.inner,
    &k_to_commitment.inner
]);
py_unverified!(PyVerifiableRSK2Batch: () -> Vec<PyElGamal> = []);

py_class!(PyVerifiableRRSKBatch(VerifiableRRSKBatch) as "VerifiableRRSKBatch");
#[pymethods]
impl PyVerifiableRRSKBatch {
    /// A proof of rerandomizing, reshuffling and rekeying every ciphertext; they must carry one
    /// key.
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> PyResult<Self> {
        let gy = common_gy(&ciphertexts)?;
        Ok(VerifiableRRSKBatch::new(&els(&ciphertexts), &gy, &s.0, &k.0, &mut rand::rng()).into())
    }

    /// A proof of rerandomizing under `gy`, reshuffling and rekeying every ciphertext.
    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        gy: &PyGroupElement,
        s: &PyScalarNonZero,
        k: &PyScalarNonZero,
    ) -> Self {
        VerifiableRRSKBatch::new(&els(&ciphertexts), &gy.0, &s.0, &k.0, &mut rand::rng()).into()
    }

    /// Verify the proof against `originals`, which carry one key, and the commitments.
    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        reshuffle_commitment: &PyReshuffleCommitment,
        rekey_commitment: &PyRekeyCommitment,
    ) -> bool {
        common_gy(&originals).is_ok_and(|gy| {
            self.inner.verify(
                &els(&originals),
                &gy,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
        })
    }

    /// Verify the proof and return the result, or `None` if it does not verify.
    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        reshuffle_commitment: &PyReshuffleCommitment,
        rekey_commitment: &PyRekeyCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let gy = common_gy(&originals).ok()?;
        self.inner
            .verified_reconstruct(
                &els(&originals),
                &gy,
                &reshuffle_commitment.inner,
                &rekey_commitment.inner,
            )
            .map(ToPy::to_py)
    }
}
py_verify!(#[cfg(not(feature = "elgamal3"))] PyVerifiableRRSKBatch: (
    originals: Vec<PyElGamal>,
    gy: &PyGroupElement,
    reshuffle_commitment: &PyReshuffleCommitment,
    rekey_commitment: &PyRekeyCommitment
) -> Vec<PyElGamal> = [
    &els(&originals),
    &gy.0,
    &reshuffle_commitment.inner,
    &rekey_commitment.inner
]);
py_unverified!(PyVerifiableRRSKBatch: () -> Vec<PyElGamal> = []);

py_class!(PyVerifiableRRSK2Batch(VerifiableRRSK2Batch) as "VerifiableRRSK2Batch");
#[pymethods]
impl PyVerifiableRRSK2Batch {
    /// A proof of rerandomizing, then transitively reshuffling and rekeying every ciphertext;
    /// they must carry one key.
    #[cfg(feature = "elgamal3")]
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> PyResult<Self> {
        let gy = common_gy(&ciphertexts)?;
        Ok(VerifiableRRSK2Batch::new(
            &els(&ciphertexts),
            &gy,
            &s_from.0,
            &s_to.0,
            &k_from.0,
            &k_to.0,
            &mut rand::rng(),
        )
        .into())
    }

    /// A proof of rerandomizing under `gy`, then transitively reshuffling and rekeying every
    /// ciphertext.
    #[cfg(not(feature = "elgamal3"))]
    #[staticmethod]
    fn new_proof(
        ciphertexts: Vec<PyElGamal>,
        gy: &PyGroupElement,
        s_from: &PyScalarNonZero,
        s_to: &PyScalarNonZero,
        k_from: &PyScalarNonZero,
        k_to: &PyScalarNonZero,
    ) -> Self {
        VerifiableRRSK2Batch::new(
            &els(&ciphertexts),
            &gy.0,
            &s_from.0,
            &s_to.0,
            &k_from.0,
            &k_to.0,
            &mut rand::rng(),
        )
        .into()
    }

    /// Verify the proof against `originals`, which carry one key, and the commitments.
    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        originals: Vec<PyElGamal>,
        s_from_commitment: &PyReshuffleCommitment,
        s_to_commitment: &PyReshuffleCommitment,
        k_from_commitment: &PyRekeyCommitment,
        k_to_commitment: &PyRekeyCommitment,
    ) -> bool {
        common_gy(&originals).is_ok_and(|gy| {
            self.inner.verify(
                &els(&originals),
                &gy,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
        })
    }

    /// Verify the proof and return the result, or `None` if it does not verify.
    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        originals: Vec<PyElGamal>,
        s_from_commitment: &PyReshuffleCommitment,
        s_to_commitment: &PyReshuffleCommitment,
        k_from_commitment: &PyRekeyCommitment,
        k_to_commitment: &PyRekeyCommitment,
    ) -> Option<Vec<PyElGamal>> {
        let gy = common_gy(&originals).ok()?;
        self.inner
            .verified_reconstruct(
                &els(&originals),
                &gy,
                &s_from_commitment.inner,
                &s_to_commitment.inner,
                &k_from_commitment.inner,
                &k_to_commitment.inner,
            )
            .map(ToPy::to_py)
    }
}
py_verify!(#[cfg(not(feature = "elgamal3"))] PyVerifiableRRSK2Batch: (
    originals: Vec<PyElGamal>,
    gy: &PyGroupElement,
    s_from_commitment: &PyReshuffleCommitment,
    s_to_commitment: &PyReshuffleCommitment,
    k_from_commitment: &PyRekeyCommitment,
    k_to_commitment: &PyRekeyCommitment
) -> Vec<PyElGamal> = [
    &els(&originals),
    &gy.0,
    &s_from_commitment.inner,
    &s_to_commitment.inner,
    &k_from_commitment.inner,
    &k_to_commitment.inner
]);
py_unverified!(PyVerifiableRRSK2Batch: () -> Vec<PyElGamal> = []);

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

pub fn register_module(parent_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(parent_module.py(), "verifiable")?;

    m.add_class::<PyFactorCommitment>()?;
    m.add_class::<PyRekeyFactorCommitment>()?;
    m.add_class::<PyPseudonymizationFactorCommitment>()?;

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
    {
        m.add_function(wrap_pyfunction!(py_verifiable_rerandomize, &m)?)?;
        m.add_function(wrap_pyfunction!(py_verifiable_rerandomize_batch, &m)?)?;
    }

    parent_module.add_submodule(&m)?;
    parent_module
        .py()
        .import("sys")?
        .getattr("modules")?
        .set_item("libpep.elgamal.verifiable", &m)?;
    Ok(())
}
