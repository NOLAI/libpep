//! Python bindings for libpep using PyO3.
//!
//! This module provides Python access to all libpep functionality including:
//! - Basic arithmetic operations on group elements and scalars
//! - ElGamal encryption and decryption
//! - PEP primitives (rekey, reshuffle, rsk operations)
//! - High-level API for pseudonyms and data points
//! - Distributed n-PEP systems
//!
//! This module is only available when the `python` feature is enabled.

// PyO3 code triggers clippy warnings that don't apply to Python bindings:
// - PyResult<T> type aliases appear as "useless conversions" to clippy
// - Methods like to_point(&self) appear to have "wrong self convention" but PyO3 objects can't be moved
#![allow(clippy::useless_conversion, clippy::wrong_self_convention)]

pub mod arithmetic;
pub mod distributed;
pub mod elgamal;
pub mod high_level;
pub mod primitives;

use pyo3::prelude::*;

/// Python module for libpep.
#[pymodule]
pub fn libpep(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // Add arithmetic submodule
    let arithmetic_module = PyModule::new(py, "arithmetic")?;
    arithmetic::register_module(&arithmetic_module)?;
    m.add_submodule(&arithmetic_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.arithmetic", &arithmetic_module)?;

    // Add elgamal submodule
    let elgamal_module = PyModule::new(py, "elgamal")?;
    elgamal::register_module(&elgamal_module)?;
    m.add_submodule(&elgamal_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.elgamal", &elgamal_module)?;

    // Add primitives submodule
    let primitives_module = PyModule::new(py, "primitives")?;
    primitives::register_module(&primitives_module)?;
    m.add_submodule(&primitives_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.primitives", &primitives_module)?;

    // Add high_level submodule
    let high_level_module = PyModule::new(py, "high_level")?;
    high_level::register_module(&high_level_module)?;
    m.add_submodule(&high_level_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.high_level", &high_level_module)?;

    // Add distributed submodule
    let distributed_module = PyModule::new(py, "distributed")?;
    distributed::register_module(&distributed_module)?;
    m.add_submodule(&distributed_module)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("libpep.distributed", &distributed_module)?;

    Ok(())
}
