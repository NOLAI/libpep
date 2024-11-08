pub mod arithmetic;
pub mod elgamal;
pub mod primitives;
pub mod high_level {
    pub mod keys;
    pub mod data_types;
    pub mod contexts;
    pub mod ops;
    pub mod utils;
}
pub mod distributed;


#[cfg(feature = "wasm")]
mod wasm {
    mod arithmetic;
    mod elgamal;
    mod primitives;
    mod high_level;
    mod distributed;
}

#[cfg(test)]
mod tests {
    mod arithmetic;
    mod elgamal;
    mod primitives;
    mod high_level;
    mod distributed;
    #[cfg(feature = "legacy-pep-repo-compatible")]
    mod legacy_pep_repo;
}
