//! WebAssembly bindings for libpep using wasm-bindgen.
//!
//! This module provides WebAssembly access to all libpep functionality including:
//! - Basic arithmetic operations on group elements and scalars
//! - ElGamal encryption and decryption  
//! - PEP primitives (rekey, reshuffle, rsk operations)
//! - High-level API for pseudonyms and data points
//! - Distributed n-PEP systems
//!
//! This module is only available when the `wasm` feature is enabled.

pub mod arithmetic;
pub mod distributed;
pub mod elgamal;
pub mod high_level;
pub mod primitives;

use wasm_bindgen::prelude::*;

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn wasm_main() {
    // Module initialization - can be used for setup
}

// Re-export all types from submodules for convenient access
// This allows users to import directly from the main module if they prefer

// Arithmetic types
pub use arithmetic::{WASMGroupElement, WASMScalarCanBeZero, WASMScalarNonZero};

// ElGamal types
pub use elgamal::WASMElGamal;

// Primitives
pub use high_level::{WASMRekeyFactor, WASMReshuffleFactor};

// High-level types and functions
pub use high_level::{
    wasm_make_global_keys as make_global_keys, wasm_make_session_keys as make_session_keys,
    wasm_pseudonymize as pseudonymize, wasm_pseudonymize_batch as pseudonymize_batch,
    wasm_rekey_batch as rekey_batch, wasm_rekey_data as rekey_data,
    wasm_transcrypt_batch as transcrypt_batch, WASMDataPoint, WASMEncryptedDataPoint,
    WASMEncryptedEntityData, WASMEncryptedPseudonym, WASMEncryptionSecret, WASMGlobalKeyPair,
    WASMGlobalPublicKey, WASMGlobalSecretKey, WASMPseudonym, WASMPseudonymizationInfo,
    WASMPseudonymizationSecret, WASMRSKFactors, WASMRekeyInfo, WASMSessionKeyPair,
    WASMSessionPublicKey, WASMSessionSecretKey,
};

// Distributed types
pub use distributed::{
    wasm_make_blinded_global_secret_key as make_blinded_global_secret_key,
    WASMBlindedGlobalSecretKey, WASMBlindingFactor, WASMOfflinePEPClient, WASMPEPClient,
    WASMPEPSystem, WASMSessionKeyShare,
};
