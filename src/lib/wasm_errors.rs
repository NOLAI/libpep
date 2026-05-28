//! Typed-prefix error helpers for WASM bindings.
//!
//! JS doesn't have a great built-in way for wasm-bindgen code to throw typed
//! `Error` subclasses that JS can `instanceof`-check, so instead we throw a
//! `JsError` whose `.message` always starts with a known typed *prefix*.
//! JS callers can then do:
//!
//! ```js
//! try {
//!     verifier.registerPseudonymizationCommitments(...);
//! } catch (e) {
//!     if (e.message.startsWith("ConflictingValue: ")) {
//!         // handle conflict
//!     } else if (e.message.startsWith("CacheFull: ")) {
//!         // handle cache full
//!     }
//! }
//! ```
//!
//! Prefixes:
//! - `"BatchError: ..."` (inconsistent structure variant)
//! - `"JsonError: ..."`, `"UnifyError: ..."`
//! - `"ProofRejected: ..."`, `"UnknownCommitment: ..."`,
//!   `"WeakCommitment: ..."`, `"MasterKeysNotRegistered: ..."`,
//!   `"MalformedProof: ..."`
//! - `"ConflictingValue: ..."`, `"CacheFull: ..."`
//! - `"WeakBlinding: ..."`

#![cfg(all(feature = "wasm", not(feature = "python")))]

use wasm_bindgen::prelude::*;

/// Build a `JsValue` containing a `JsError` whose message is `"{prefix}: {e}"`.
#[allow(dead_code)]
pub(crate) fn js_err(prefix: &str, e: impl std::fmt::Display) -> JsValue {
    JsValue::from(JsError::new(&format!("{}: {}", prefix, e)))
}

// ---------------------------------------------------------------------------
// display_prefix helpers
// ---------------------------------------------------------------------------

/// Trait so each Rust error type can pick its own typed prefix.
#[allow(dead_code)]
pub(crate) trait BatchErrorExt {
    fn display_prefix(&self) -> &'static str;
}

#[allow(dead_code)]
pub(crate) trait VerifyErrorExt {
    fn display_prefix(&self) -> &'static str;
}

#[allow(dead_code)]
pub(crate) trait CacheRegistrationErrorExt {
    fn display_prefix(&self) -> &'static str;
}

#[allow(dead_code)]
pub(crate) trait RegisterCommitmentsErrorExt {
    fn display_prefix(&self) -> &'static str;
}

#[cfg(feature = "batch")]
impl BatchErrorExt for crate::data::batch::BatchError {
    fn display_prefix(&self) -> &'static str {
        use crate::data::batch::BatchError;
        match self {
            BatchError::InconsistentStructure { .. } => "BatchError",
            #[cfg(feature = "json")]
            BatchError::UnifyError(_) => "UnifyError",
            #[cfg(feature = "json")]
            BatchError::JsonError(_) => "JsonError",
        }
    }
}

#[cfg(feature = "verifiable")]
impl VerifyErrorExt for crate::verifier::VerifyError {
    fn display_prefix(&self) -> &'static str {
        use crate::verifier::VerifyError;
        match self {
            VerifyError::ProofRejected => "ProofRejected",
            VerifyError::UnknownCommitment => "UnknownCommitment",
            VerifyError::WeakCommitment { .. } => "WeakCommitment",
            VerifyError::MasterKeysNotRegistered => "MasterKeysNotRegistered",
        }
    }
}

#[cfg(feature = "verifiable")]
impl CacheRegistrationErrorExt for crate::verifier::CacheRegistrationError {
    fn display_prefix(&self) -> &'static str {
        use crate::verifier::CacheRegistrationError;
        match self {
            CacheRegistrationError::ConflictingValue => "ConflictingValue",
            CacheRegistrationError::CacheFull => "CacheFull",
        }
    }
}

#[cfg(feature = "verifiable")]
impl RegisterCommitmentsErrorExt for crate::verifier::RegisterCommitmentsError {
    fn display_prefix(&self) -> &'static str {
        use crate::verifier::RegisterCommitmentsError;
        match self {
            RegisterCommitmentsError::Weak(_) => "WeakCommitment",
            RegisterCommitmentsError::Cache(c) => c.display_prefix(),
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience converters: pick prefix and wrap in `JsValue`.
// ---------------------------------------------------------------------------

#[cfg(feature = "batch")]
#[allow(dead_code)]
pub(crate) fn batch_err_to_js(e: crate::data::batch::BatchError) -> JsValue {
    js_err(e.display_prefix(), &e)
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
pub(crate) fn verify_err_to_js(e: crate::verifier::VerifyError) -> JsValue {
    js_err(e.display_prefix(), &e)
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
pub(crate) fn register_commitments_err_to_js(
    e: crate::verifier::RegisterCommitmentsError,
) -> JsValue {
    js_err(e.display_prefix(), &e)
}

#[cfg(feature = "verifiable")]
#[allow(dead_code)]
pub(crate) fn session_key_share_err_to_js(
    e: crate::keys::generation::SessionKeyShareError,
) -> JsValue {
    use crate::keys::generation::SessionKeyShareError;
    let prefix = match e {
        SessionKeyShareError::WeakBlinding => "WeakBlinding",
    };
    js_err(prefix, e)
}

/// Wrap a deserialization failure for a proof / commitment / other ZKP value
/// as a typed `"MalformedProof: ..."` error so JS can distinguish a bad input
/// from a `"ProofRejected: ..."` cryptographic failure.
#[allow(dead_code)]
pub(crate) fn malformed_proof_err(e: impl std::fmt::Display) -> JsValue {
    js_err("MalformedProof", e)
}
