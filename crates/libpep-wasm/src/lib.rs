//! WebAssembly bindings for [libpep], built with wasm-bindgen and distributed on npm as
//! `@nolai/libpep-wasm`.

pub mod arithmetic;
pub mod client;
pub mod core;
pub mod data;
pub mod factors;
pub mod keys;
pub mod transcryptor;

// Re-export functions from client module for backwards compatibility
pub use client::functions::*;
