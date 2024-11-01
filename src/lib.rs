pub mod arithmetic;
pub mod elgamal;
pub mod primitives;
pub mod utils;
pub mod high_level;
pub mod distributed;

pub mod zkps;
pub mod proved;
pub mod high_level_proved;
pub mod verifiers_cache;
pub mod distributed_proved;

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
    mod proved;
    #[cfg(feature = "legacy-pep-repo-compatible")]
    mod legacy_pep_repo;
}
