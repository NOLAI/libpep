//! WASM bindings for zero-knowledge proofs.

use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::core::zkps::{create_proof, verify_proof, Proof};
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

/// A zero-knowledge proof demonstrating knowledge of a discrete logarithm.
///
/// This proof shows that `N = a*M` for some secret scalar `a` without revealing `a`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From, Into, Deref)]
#[wasm_bindgen(js_name = Proof)]
pub struct WASMProof(pub(crate) Proof);

#[wasm_bindgen(js_class = Proof)]
impl WASMProof {
    /// Encodes the proof as a 128-byte array.
    #[wasm_bindgen(js_name = encode)]
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    /// Decodes a proof from a 128-byte array.
    #[wasm_bindgen(js_name = decode)]
    pub fn decode(v: Vec<u8>) -> Option<WASMProof> {
        Proof::decode_from_slice(v.as_slice()).map(WASMProof)
    }

    /// Encodes the proof as a URL-safe base64 string.
    #[wasm_bindgen(js_name = toBase64)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    /// Decodes a proof from a URL-safe base64 string.
    #[wasm_bindgen(js_name = fromBase64)]
    pub fn from_base64(s: &str) -> Option<WASMProof> {
        Proof::from_base64(s).map(WASMProof)
    }
}

/// Pair returned by `createZkpProof`: the public key `A = a*G` and the proof.
#[wasm_bindgen(js_name = ZkpProofResult)]
pub struct WASMZkpProofResult {
    public_key: WASMGroupElement,
    proof: WASMProof,
}

#[wasm_bindgen(js_class = ZkpProofResult)]
impl WASMZkpProofResult {
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> WASMGroupElement {
        self.public_key
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> WASMProof {
        self.proof
    }
}

/// Creates a zero-knowledge proof demonstrating knowledge of a discrete logarithm.
///
/// Given a secret scalar `a` and a public group element `M`, this function creates a proof
/// that `N = a*M` without revealing `a`.
#[wasm_bindgen(js_name = createZkpProof)]
pub fn create_zkp_proof_wasm(a: &WASMScalarNonZero, gm: &WASMGroupElement) -> WASMZkpProofResult {
    let mut rng = rand::rng();
    let (public_key, proof) = create_proof(a, gm, &mut rng);
    WASMZkpProofResult {
        public_key: WASMGroupElement::from(public_key),
        proof: WASMProof(proof),
    }
}

/// Verifies a zero-knowledge proof.
#[wasm_bindgen(js_name = verifyZkpProof)]
pub fn verify_zkp_proof_wasm(
    ga: &WASMGroupElement,
    gm: &WASMGroupElement,
    proof: &WASMProof,
) -> bool {
    verify_proof(ga, gm, &proof.0)
}
