//! Padding mechanisms for PEP data encoding.
//!
//! This module provides two distinct types of padding for PEP data:
//!
//! - **Internal Padding (PKCS#7)**: See the [`internal`] module for PKCS#7 padding used for single-block encoding.
//! - **External Padding**: See the [`external`] module for padding blocks used for batch unlinkability.
//!
//! Both padding types are completely unambiguous and can encode any possible byte sequence.

pub mod internal;

#[cfg(feature = "long")]
pub mod external;

// Re-export the Padded trait for convenience
pub use internal::Padded;
