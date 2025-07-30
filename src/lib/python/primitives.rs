use crate::low_level::primitives::*;
#[cfg(not(feature = "elgamal3"))]
use crate::python::arithmetic::PyGroupElement;
use crate::python::arithmetic::PyScalarNonZero;
use crate::python::elgamal::PyElGamal;
use pyo3::prelude::*;

/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
#[cfg(feature = "elgamal3")]
#[pyfunction]
#[pyo3(name = "rerandomize")]
pub fn py_rerandomize(v: &PyElGamal, r: &PyScalarNonZero) -> PyElGamal {
    rerandomize(&v.0, &r.0).into()
}

/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
/// Requires the public key `gy` that was used to encrypt the message to be provided.
#[cfg(not(feature = "elgamal3"))]
#[pyfunction]
#[pyo3(name = "rerandomize")]
pub fn py_rerandomize(
    v: &PyElGamal,
    public_key: &PyGroupElement,
    r: &PyScalarNonZero,
) -> PyElGamal {
    rerandomize(&v.0, &public_key.0, &r.0).into()
}

/// Make a message encrypted under one key decryptable under another key.
/// If the original message was encrypted under key `Y`, the new message will be encrypted under key
/// `k * Y` such that users with secret key `k * y` can decrypt it.
#[pyfunction]
#[pyo3(name = "rekey")]
pub fn py_rekey(v: &PyElGamal, k: &PyScalarNonZero) -> PyElGamal {
    rekey(&v.0, &k.0).into()
}

/// Change the contents of a ciphertext with factor `s`, i.e. message `M` becomes `s * M`.
/// Can be used to blindly and pseudo-randomly pseudonymize identifiers.
#[pyfunction]
#[pyo3(name = "reshuffle")]
pub fn py_reshuffle(v: &PyElGamal, s: &PyScalarNonZero) -> PyElGamal {
    reshuffle(&v.0, &s.0).into()
}

/// A transitive and reversible n-PEP extension of [`rekey`], rekeying from one key to
/// another.
#[pyfunction]
#[pyo3(name = "rekey2")]
pub fn py_rekey2(v: &PyElGamal, k_from: &PyScalarNonZero, k_to: &PyScalarNonZero) -> PyElGamal {
    rekey2(&v.0, &k_from.0, &k_to.0).into()
}

/// A transitive and reversible n-PEP extension of [`reshuffle`], reshuffling from one pseudonym to
/// another.
#[pyfunction]
#[pyo3(name = "reshuffle2")]
pub fn py_reshuffle2(v: &PyElGamal, n_from: &PyScalarNonZero, n_to: &PyScalarNonZero) -> PyElGamal {
    reshuffle2(&v.0, &n_from.0, &n_to.0).into()
}

/// Combination of  [`reshuffle`] and [`rekey`] (more efficient and secure than applying them
/// separately).
#[pyfunction]
#[pyo3(name = "rsk")]
pub fn py_rsk(v: &PyElGamal, s: &PyScalarNonZero, k: &PyScalarNonZero) -> PyElGamal {
    rsk(&v.0, &s.0, &k.0).into()
}

/// A transitive and reversible n-PEP extension of [`rsk`].
#[pyfunction]
#[pyo3(name = "rsk2")]
pub fn py_rsk2(
    v: &PyElGamal,
    s_from: &PyScalarNonZero,
    s_to: &PyScalarNonZero,
    k_from: &PyScalarNonZero,
    k_to: &PyScalarNonZero,
) -> PyElGamal {
    rsk2(&v.0, &s_from.0, &s_to.0, &k_from.0, &k_to.0).into()
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_rerandomize, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey, m)?)?;
    m.add_function(wrap_pyfunction!(py_reshuffle, m)?)?;
    m.add_function(wrap_pyfunction!(py_rekey2, m)?)?;
    m.add_function(wrap_pyfunction!(py_reshuffle2, m)?)?;
    m.add_function(wrap_pyfunction!(py_rsk, m)?)?;
    m.add_function(wrap_pyfunction!(py_rsk2, m)?)?;
    Ok(())
}
