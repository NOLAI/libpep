use pyo3::prelude::*;

pub(crate) fn create_submodule(py: Python<'_>) -> PyResult<&PyModule> {
    let submod = PyModule::new(py, "arithmetic")?;

    Ok(submod)
}
