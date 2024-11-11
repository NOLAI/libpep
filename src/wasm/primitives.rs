use crate::low_level::primitives::*;
#[cfg(feature = "elgamal2")]
use crate::wasm::arithmetic::WASMGroupElement;
use crate::wasm::arithmetic::WASMScalarNonZero;
use crate::wasm::elgamal::WASMElGamal;
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(not(feature = "elgamal2"))]
#[wasm_bindgen(js_name = rerandomize)]
pub fn wasm_rerandomize(v: &WASMElGamal, r: &WASMScalarNonZero) -> WASMElGamal {
    rerandomize(v, r).into()
}
#[cfg(feature = "elgamal2")]
#[wasm_bindgen(js_name = rerandomize)]
pub fn wasm_rerandomize(
    v: &WASMElGamal,
    public_key: &WASMGroupElement,
    r: &WASMScalarNonZero,
) -> WASMElGamal {
    rerandomize(v, public_key, r).into()
}
#[wasm_bindgen(js_name = rekey)]
pub fn wasm_rekey(v: &WASMElGamal, k: &WASMScalarNonZero) -> WASMElGamal {
    rekey(v, k).into()
}
#[wasm_bindgen(js_name = reshuffle)]
pub fn wasm_reshuffle(v: &WASMElGamal, s: &WASMScalarNonZero) -> WASMElGamal {
    reshuffle(v, s).into()
}
#[wasm_bindgen(js_name = rekey2)]
pub fn wasm_rekey2(
    v: &WASMElGamal,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMElGamal {
    rekey2(v, k_from, k_to).into()
}

#[wasm_bindgen(js_name = reshuffle2)]
pub fn wasm_reshuffle2(
    v: &WASMElGamal,
    n_from: &WASMScalarNonZero,
    n_to: &WASMScalarNonZero,
) -> WASMElGamal {
    reshuffle2(v, n_from, n_to).into()
}
#[wasm_bindgen(js_name = rsk)]
pub fn wasm_rsk(v: &WASMElGamal, s: &WASMScalarNonZero, k: &WASMScalarNonZero) -> WASMElGamal {
    rsk(v, s, k).into()
}
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
