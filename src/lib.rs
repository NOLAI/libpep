pub mod internal {
    pub mod arithmetic;
}
pub mod low_level {
    pub mod elgamal;
    pub mod primitives;
}
pub mod high_level {
    pub mod contexts;
    pub mod data_types;
    pub mod keys;
    pub mod ops;
    pub mod utils;
}
pub mod distributed {
    pub mod key_blinding;
    pub mod systems;
}

#[cfg(feature = "wasm")]
mod wasm {
    mod arithmetic;
    mod distributed;
    mod elgamal;
    mod high_level;
    mod primitives;
}

#[cfg(test)]
mod tests {
    mod arithmetic;
    mod distributed;
    mod elgamal;
    mod high_level;
    #[cfg(feature = "legacy-pep-repo-compatible")]
    mod legacy_pep_repo;
    mod primitives;

    #[cfg(feature = "energy-measurements")]
    mod energy {
        mod utils {
            pub(crate) mod ina;
            pub(crate) mod tls;
        }
        mod individual;
        mod network;
    }
}
