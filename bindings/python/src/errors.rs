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
    DecryptionFailedError,
    BatchError,
    "Decryption failed for an entry in the batch (elgamal3 key mismatch)."
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
pub(crate) fn batch_err_to_py(e: libpep::errors::BatchError) -> PyErr {
    use libpep::errors::BatchError as CoreBatchError;
    let msg = e.to_string();
    match e {
        CoreBatchError::InconsistentStructure { .. } => InconsistentStructureError::new_err(msg),
        #[cfg(feature = "json")]
        CoreBatchError::UnifyError(_) => JsonUnifyError::new_err(msg),
        #[cfg(feature = "json")]
        CoreBatchError::JsonError(_) => JsonFormatError::new_err(msg),
        CoreBatchError::DecryptionFailed { .. } => DecryptionFailedError::new_err(msg),
        _ => BatchError::new_err(msg),
    }
}

#[cfg(feature = "json")]
pub(crate) fn unify_err_to_py(e: libpep::data::json::UnifyError) -> PyErr {
    JsonUnifyError::new_err(e.to_string())
}

#[cfg(feature = "json")]
#[allow(dead_code)]
pub(crate) fn json_err_to_py(e: libpep::data::json::JsonError) -> PyErr {
    JsonFormatError::new_err(e.to_string())
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
pub(crate) fn verify_err_to_py(e: libpep::verifier::VerifyError) -> PyErr {
    use libpep::verifier::VerifyError;
    let msg = e.to_string();
    match e {
        VerifyError::ProofRejected => ProofRejectedError::new_err(msg),
        VerifyError::UnknownCommitment => UnknownCommitmentError::new_err(msg),
        VerifyError::WeakCommitment { .. } => WeakCommitmentError::new_err(msg),
        VerifyError::MasterKeysNotRegistered => MasterKeysNotRegisteredError::new_err(msg),
    }
}

#[cfg(feature = "verifiable")]
pub(crate) fn weak_commitment_err_to_py(e: libpep::verifier::WeakCommitmentError) -> PyErr {
    WeakCommitmentError::new_err(e.to_string())
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
pub(crate) fn cache_registration_err_to_py(e: libpep::verifier::CacheRegistrationError) -> PyErr {
    let msg = e.to_string();
    match e {
        libpep::verifier::CacheRegistrationError::ConflictingValue => {
            ConflictingValueError::new_err(msg)
        }
        libpep::verifier::CacheRegistrationError::CacheFull => CacheFullError::new_err(msg),
    }
}

// ---------------------------------------------------------------------------
// RegisterCommitmentsError — unwraps to inner Weak or Cache variant.
// ---------------------------------------------------------------------------

#[cfg(feature = "verifiable")]
pub(crate) fn register_commitments_err_to_py(
    e: libpep::verifier::RegisterCommitmentsError,
) -> PyErr {
    match e {
        libpep::verifier::RegisterCommitmentsError::Weak(w) => weak_commitment_err_to_py(w),
        libpep::verifier::RegisterCommitmentsError::Cache(c) => cache_registration_err_to_py(c),
    }
}

// ---------------------------------------------------------------------------
// SessionKeyShareError — refusal to generate a session-key share.
// ---------------------------------------------------------------------------

create_exception!(
    libpep,
    SessionKeyShareError,
    PEPError,
    "Refused to generate a session-key share (e.g. weak blinding factor)."
);
create_exception!(
    libpep,
    WeakBlindingError,
    SessionKeyShareError,
    "The supplied blinding factor was 1, which would leak the share scalar."
);

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
pub(crate) fn session_key_share_err_to_py(
    e: libpep::keys::generation::SessionKeyShareError,
) -> PyErr {
    use libpep::keys::generation::SessionKeyShareError;
    match e {
        SessionKeyShareError::WeakBlinding => WeakBlindingError::new_err(e.to_string()),
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

    // SessionKeyShareError subtree.
    m.add(
        "SessionKeyShareError",
        py.get_type::<SessionKeyShareError>(),
    )?;
    m.add("WeakBlindingError", py.get_type::<WeakBlindingError>())?;

    Ok(())
}
