use wasm_bindgen::prelude::wasm_bindgen;
use crate::wasm::arithmetic::WASMScalarNonZero;
use crate::wasm::elgamal::WASMElGamal;
use crate::primitives::*;

#[wasm_bindgen(js_name = rerandomize)]
pub fn rerandomize_wasm(v: &WASMElGamal, r: &WASMScalarNonZero) -> WASMElGamal {
    rerandomize(v, r).into()
}
#[wasm_bindgen(js_name = rekey)]
pub fn rekey_wasm(v: &WASMElGamal, k: &WASMScalarNonZero) -> WASMElGamal {
    rekey(v, k).into()
}
#[wasm_bindgen(js_name = reshuffle)]
pub fn reshuffle_wasm(v: &WASMElGamal, s: &WASMScalarNonZero) -> WASMElGamal {
    reshuffle(v, s).into()
}
#[wasm_bindgen(js_name = rekeyFromTo)]

pub fn rekey_from_to_wasm(v: &WASMElGamal, k_from: &WASMScalarNonZero, k_to: &WASMScalarNonZero) -> WASMElGamal {
    rekey_from_to(v, k_from, k_to).into()
}

#[wasm_bindgen(js_name = reshuffleFromTo)]
pub fn reshuffle_from_to_wasm(v: &WASMElGamal, n_from: &WASMScalarNonZero, n_to: &WASMScalarNonZero) -> WASMElGamal {
    reshuffle_from_to(v, n_from, n_to).into()
}
#[wasm_bindgen(js_name = rsk)]
pub fn rsk_wasm(v: &WASMElGamal, s: &WASMScalarNonZero, k: &WASMScalarNonZero) -> WASMElGamal {
    rsk(v, s, k).into()
}
#[wasm_bindgen(js_name = rskFromTo)]
pub fn rsk_from_to_wasm(v: &WASMElGamal, s_from: &WASMScalarNonZero, s_to: &WASMScalarNonZero, k_from: &WASMScalarNonZero, k_to: &WASMScalarNonZero) -> WASMElGamal {
    rsk_from_to(v, s_from, s_to, k_from, k_to).into()
}

