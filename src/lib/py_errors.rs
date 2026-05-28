//! Typed Python exception classes for libpep errors.
//!
//! This module defines a hierarchy of Python exception types that mirror the
//! various Rust error enums. Each variant of an error enum maps to its own
//! exception subclass so Python callers can write:
//!
//! ```python
//! try:
//!     verifier.register_pseudonymization_commitments(...)
//! except ConflictingValueError:
//!     ...
//! except VerifyError:
//!     ...
//! ```
//!
//! All exceptions inherit from a common base `PEPError(Exception)`.
//!
//! The `From<RustError> for PyErr` impls in this module enable the `?` operator
//! to convert directly into the right Python exception.

#![cfg(all(feature = "python", not(feature = "wasm")))]

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// Base exception
// ---------------------------------------------------------------------------

create_exception!(
    libpep,
    PEPError,
    PyException,
    "Base class for all libpep errors."
);

// ---------------------------------------------------------------------------
// BatchError hierarchy
// ---------------------------------------------------------------------------

create_exception!(libpep, BatchError, PEPError, "A batch operation failed.");
create_exception!(
    libpep,
    InconsistentStructureError,
    BatchError,
    "Items in the batch have inconsistent structures."
);
create_exception!(
    libpep,
    JsonUnifyError,
    BatchError,
    "Failed to unify JSON structures across the batch."
);
create_exception!(
    libpep,
    JsonFormatError,
    BatchError,
    "JSON value is malformed or has an unexpected structure."
);

#[cfg(feature = "batch")]
impl From<crate::data::batch::BatchError> for PyErr {
    fn from(e: crate::data::batch::BatchError) -> PyErr {
        use crate::data::batch::BatchError;
        let msg = e.to_string();
        match e {
            BatchError::InconsistentStructure { .. } => InconsistentStructureError::new_err(msg),
            #[cfg(feature = "json")]
            BatchError::UnifyError(_) => JsonUnifyError::new_err(msg),
            #[cfg(feature = "json")]
            BatchError::JsonError(_) => JsonFormatError::new_err(msg),
        }
    }
}

#[cfg(feature = "json")]
impl From<crate::data::json::UnifyError> for PyErr {
    fn from(e: crate::data::json::UnifyError) -> PyErr {
        JsonUnifyError::new_err(e.to_string())
    }
}

#[cfg(feature = "json")]
impl From<crate::data::json::JsonError> for PyErr {
    fn from(e: crate::data::json::JsonError) -> PyErr {
        JsonFormatError::new_err(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// VerifyError hierarchy
// ---------------------------------------------------------------------------

create_exception!(libpep, VerifyError, PEPError, "A verifier check failed.");
create_exception!(
    libpep,
    ProofRejectedError,
    VerifyError,
    "A zero-knowledge proof did not verify against the supplied statement."
);
create_exception!(
    libpep,
    UnknownCommitmentError,
    VerifyError,
    "No commitments registered for the requested transcryptor/transition."
);
create_exception!(
    libpep,
    WeakCommitmentError,
    VerifyError,
    "A commitment is weak (equal to the identity or generator G) and was rejected."
);
create_exception!(
    libpep,
    MasterKeysNotRegisteredError,
    VerifyError,
    "Master keys are not registered for this transcryptor."
);

#[cfg(feature = "verifiable")]
impl From<crate::verifier::VerifyError> for PyErr {
    fn from(e: crate::verifier::VerifyError) -> PyErr {
        use crate::verifier::VerifyError;
        let msg = e.to_string();
        match e {
            VerifyError::ProofRejected => ProofRejectedError::new_err(msg),
            VerifyError::UnknownCommitment => UnknownCommitmentError::new_err(msg),
            VerifyError::WeakCommitment { .. } => WeakCommitmentError::new_err(msg),
            VerifyError::MasterKeysNotRegistered => MasterKeysNotRegisteredError::new_err(msg),
        }
    }
}

#[cfg(feature = "verifiable")]
impl From<crate::verifier::WeakCommitmentError> for PyErr {
    fn from(e: crate::verifier::WeakCommitmentError) -> PyErr {
        WeakCommitmentError::new_err(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// CacheRegistrationError hierarchy
// ---------------------------------------------------------------------------

create_exception!(
    libpep,
    CacheRegistrationError,
    PEPError,
    "A commitment cache registration failed."
);
create_exception!(
    libpep,
    ConflictingValueError,
    CacheRegistrationError,
    "A different commitment is already registered under this key."
);
create_exception!(
    libpep,
    CacheFullError,
    CacheRegistrationError,
    "The commitment cache has reached its configured maximum size."
);

#[cfg(feature = "verifiable")]
impl From<crate::verifier::CacheRegistrationError> for PyErr {
    fn from(e: crate::verifier::CacheRegistrationError) -> PyErr {
        use crate::verifier::CacheRegistrationError;
        let msg = e.to_string();
        match e {
            CacheRegistrationError::ConflictingValue => ConflictingValueError::new_err(msg),
            CacheRegistrationError::CacheFull => CacheFullError::new_err(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// RegisterCommitmentsError — unwraps to inner Weak or Cache variant.
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
impl From<crate::verifier::RegisterCommitmentsError> for PyErr {
    fn from(e: crate::verifier::RegisterCommitmentsError) -> PyErr {
        use crate::verifier::RegisterCommitmentsError;
        match e {
            RegisterCommitmentsError::Weak(w) => PyErr::from(w),
            RegisterCommitmentsError::Cache(c) => PyErr::from(c),
        }
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // Base.
    m.add("PEPError", py.get_type::<PEPError>())?;

    // BatchError subtree.
    m.add("BatchError", py.get_type::<BatchError>())?;
    m.add(
        "InconsistentStructureError",
        py.get_type::<InconsistentStructureError>(),
    )?;
    m.add("JsonUnifyError", py.get_type::<JsonUnifyError>())?;
    m.add("JsonFormatError", py.get_type::<JsonFormatError>())?;

    // VerifyError subtree.
    m.add("VerifyError", py.get_type::<VerifyError>())?;
    m.add("ProofRejectedError", py.get_type::<ProofRejectedError>())?;
    m.add(
        "UnknownCommitmentError",
        py.get_type::<UnknownCommitmentError>(),
    )?;
    m.add("WeakCommitmentError", py.get_type::<WeakCommitmentError>())?;
    m.add(
        "MasterKeysNotRegisteredError",
        py.get_type::<MasterKeysNotRegisteredError>(),
    )?;

    // CacheRegistrationError subtree.
    m.add(
        "CacheRegistrationError",
        py.get_type::<CacheRegistrationError>(),
    )?;
    m.add(
        "ConflictingValueError",
        py.get_type::<ConflictingValueError>(),
    )?;
    m.add("CacheFullError", py.get_type::<CacheFullError>())?;

    Ok(())
}
