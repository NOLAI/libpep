use crate::low_level::primitives::*;
#[cfg(not(feature = "elgamal3"))]
use crate::wasm::arithmetic::WASMGroupElement;
use crate::wasm::arithmetic::WASMScalarNonZero;
use crate::wasm::elgamal::WASMElGamal;
use wasm_bindgen::prelude::wasm_bindgen;

/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = rerandomize)]
pub fn wasm_rerandomize(v: &WASMElGamal, r: &WASMScalarNonZero) -> WASMElGamal {
    rerandomize(v, r).into()
}

/// Change the representation of a ciphertext without changing the contents.
/// Used to make multiple unlinkable copies of the same ciphertext (when disclosing a single
/// stored message multiple times).
/// Requires the public key `gy` that was used to encrypt the message to be provided.
#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = rerandomize)]
pub fn wasm_rerandomize(
    v: &WASMElGamal,
    public_key: &WASMGroupElement,
    r: &WASMScalarNonZero,
) -> WASMElGamal {
    rerandomize(v, public_key, r).into()
}

/// Make a message encrypted under one key decryptable under another key.
/// If the original message was encrypted under key `Y`, the new message will be encrypted under key
/// `k * Y` such that users with secret key `k * y` can decrypt it.
#[wasm_bindgen(js_name = rekey)]
pub fn wasm_rekey(v: &WASMElGamal, k: &WASMScalarNonZero) -> WASMElGamal {
    rekey(v, k).into()
}
/// Change the contents of a ciphertext with factor `s`, i.e. message `M` becomes `s * M`.
/// Can be used to blindly and pseudo-randomly pseudonymize identifiers.
#[wasm_bindgen(js_name = reshuffle)]
pub fn wasm_reshuffle(v: &WASMElGamal, s: &WASMScalarNonZero) -> WASMElGamal {
    reshuffle(v, s).into()
}

/// A transitive and reversible n-PEP extension of [`rekey`], rekeying from one key to
/// another.
#[wasm_bindgen(js_name = rekey2)]
pub fn wasm_rekey2(
    v: &WASMElGamal,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMElGamal {
    rekey2(v, k_from, k_to).into()
}

/// A transitive and reversible n-PEP extension of [`reshuffle`], reshuffling from one pseudonym to
/// another.
#[wasm_bindgen(js_name = reshuffle2)]
pub fn wasm_reshuffle2(
    v: &WASMElGamal,
    n_from: &WASMScalarNonZero,
    n_to: &WASMScalarNonZero,
) -> WASMElGamal {
    reshuffle2(v, n_from, n_to).into()
}

/// Combination of  [`reshuffle`] and [`rekey`] (more efficient and secure than applying them
/// separately).
#[wasm_bindgen(js_name = rsk)]
pub fn wasm_rsk(v: &WASMElGamal, s: &WASMScalarNonZero, k: &WASMScalarNonZero) -> WASMElGamal {
    rsk(v, s, k).into()
}

/// A transitive and reversible n-PEP extension of [`rsk`].
#[wasm_bindgen(js_name = rsk2)]
pub fn wasm_rsk2(
    v: &WASMElGamal,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMElGamal {
    rsk2(v, s_from, s_to, k_from, k_to).into()
}
