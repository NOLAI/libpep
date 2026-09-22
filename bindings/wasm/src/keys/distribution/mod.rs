pub mod blinding;

#[cfg(feature = "verifiable-derivation")]
pub mod proofs;
pub mod setup;
pub mod shares;

pub use blinding::{
    WASMBlindedAttributeGlobalSecretKey, WASMBlindedGlobalSecretKeys,
    WASMBlindedPseudonymGlobalSecretKey, WASMBlindingFactor,
};
// Note: Blinding functions are exposed via wasm_bindgen, not as pub fn
pub use setup::{
    wasm_make_distributed_attribute_global_keys, wasm_make_distributed_global_keys,
    wasm_make_distributed_pseudonym_global_keys,
};
pub use shares::{
    wasm_make_attribute_session_key_share, wasm_make_pseudonym_session_key_share,
    wasm_make_session_key_shares, WASMAttributeSessionKeyShare, WASMPseudonymSessionKeyShare,
    WASMSessionKeyShares,
};

#[cfg(feature = "verifiable-derivation")]
pub use proofs::{WASMBlindingCommitment, WASMBlindingCommitments, WASMSessionKeyShareProof};
