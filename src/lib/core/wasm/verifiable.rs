//! WASM bindings for verifiable transcryption.
//!
//! Mirrors the Rust `core::verifiable` API: factor commitments, per-message
//! proof types, batched proof types, and the corresponding `verifiable_*`
//! free functions.

#[cfg(not(feature = "elgamal3"))]
use crate::arithmetic::wasm::group_elements::WASMGroupElement;
use crate::arithmetic::wasm::scalars::WASMScalarNonZero;
use crate::core::verifiable::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRRSK,
    VerifiableRRSK2, VerifiableRSK, VerifiableRSK2, VerifiableRSKInner, VerifiableRekey,
    VerifiableRekey2, VerifiableRerandomize, VerifiableReshuffle, VerifiableReshuffle2,
};
#[cfg(feature = "batch")]
use crate::core::verifiable::{
    VerifiableRRSK2Batch, VerifiableRRSKBatch, VerifiableRSK2Batch, VerifiableRSKBatch,
    VerifiableRekey2Batch, VerifiableRekeyBatch, VerifiableRerandomizeBatch,
    VerifiableReshuffle2Batch, VerifiableReshuffleBatch,
};
use crate::core::wasm::elgamal::WASMElGamal;
use derive_more::{Deref, From, Into};
use wasm_bindgen::prelude::*;

#[cfg(feature = "batch")]
fn into_elgamal_vec(cts: &[WASMElGamal]) -> Vec<crate::core::elgamal::ElGamal> {
    cts.iter().map(|c| **c).collect()
}

#[cfg(feature = "batch")]
fn into_wasm_elgamal_vec(cts: Vec<crate::core::elgamal::ElGamal>) -> Vec<WASMElGamal> {
    cts.into_iter().map(WASMElGamal::from).collect()
}

// ---------------------------------------------------------------------------
// Factor commitments
// ---------------------------------------------------------------------------

/// Forward commitment `A = a·G` to a factor scalar `a`.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = FactorCommitment)]
pub struct WASMFactorCommitment(pub(crate) FactorCommitment);

#[wasm_bindgen(js_class = FactorCommitment)]
impl WASMFactorCommitment {
    /// Build a commitment to scalar `a`: `A = a · G`.
    #[wasm_bindgen(js_name = fromScalar)]
    pub fn from_scalar(a: &WASMScalarNonZero) -> WASMFactorCommitment {
        WASMFactorCommitment(FactorCommitment::new(a))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMFactorCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMFactorCommitment)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Commitment `K = k·G` to a rekey factor.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = RekeyFactorCommitment)]
pub struct WASMRekeyFactorCommitment(pub(crate) RekeyFactorCommitment);

#[wasm_bindgen(js_class = RekeyFactorCommitment)]
impl WASMRekeyFactorCommitment {
    #[wasm_bindgen(js_name = fromScalar)]
    pub fn from_scalar(a: &WASMScalarNonZero) -> WASMRekeyFactorCommitment {
        WASMRekeyFactorCommitment(RekeyFactorCommitment::new(a))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMRekeyFactorCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMRekeyFactorCommitment)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Commitment `S = s·G` to a pseudonymization (reshuffle) factor.
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = PseudonymizationFactorCommitment)]
pub struct WASMPseudonymizationFactorCommitment(pub(crate) PseudonymizationFactorCommitment);

#[wasm_bindgen(js_class = PseudonymizationFactorCommitment)]
impl WASMPseudonymizationFactorCommitment {
    #[wasm_bindgen(js_name = fromScalar)]
    pub fn from_scalar(a: &WASMScalarNonZero) -> WASMPseudonymizationFactorCommitment {
        WASMPseudonymizationFactorCommitment(PseudonymizationFactorCommitment::new(a))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMPseudonymizationFactorCommitment, JsValue> {
        serde_json::from_str(json)
            .map(WASMPseudonymizationFactorCommitment)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

// ---------------------------------------------------------------------------
// VerifiableRerandomize (per-message)
// ---------------------------------------------------------------------------

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRerandomize)]
pub struct WASMVerifiableRerandomize(pub(crate) VerifiableRerandomize);

#[wasm_bindgen(js_class = VerifiableRerandomize)]
impl WASMVerifiableRerandomize {
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, r: &WASMScalarNonZero) -> WASMVerifiableRerandomize {
        let mut rng = rand::rng();
        WASMVerifiableRerandomize(VerifiableRerandomize::new(&v.gy, r, &mut rng))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(gy: &WASMGroupElement, r: &WASMScalarNonZero) -> WASMVerifiableRerandomize {
        let mut rng = rand::rng();
        WASMVerifiableRerandomize(VerifiableRerandomize::new(gy, r, &mut rng))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verify(&self, v: &WASMElGamal) -> bool {
        self.0.verify(&v.gy)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(&self, gy: &WASMGroupElement) -> bool {
        self.0.verify(gy)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(&self, original: &WASMElGamal) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, &original.gy)
            .map(WASMElGamal::from)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        gy: &WASMGroupElement,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, gy)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, original: &WASMElGamal) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct(original))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRerandomize, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRerandomize)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Pair returned by the insecure `verifiableRerandomize` free function:
/// the rerandomized ciphertext plus the proof.
#[cfg(feature = "insecure")]
#[wasm_bindgen(js_name = VerifiableRerandomizeResult)]
pub struct WASMVerifiableRerandomizeResult {
    result: WASMElGamal,
    proof: WASMVerifiableRerandomize,
}

#[cfg(feature = "insecure")]
#[wasm_bindgen(js_class = VerifiableRerandomizeResult)]
impl WASMVerifiableRerandomizeResult {
    #[wasm_bindgen(getter)]
    pub fn result(&self) -> WASMElGamal {
        self.result
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> WASMVerifiableRerandomize {
        self.proof.clone()
    }
}

#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRerandomize)]
pub fn wasm_verifiable_rerandomize(
    original: &WASMElGamal,
    r: &WASMScalarNonZero,
) -> WASMVerifiableRerandomizeResult {
    let mut rng = rand::rng();
    let (result, proof) = crate::core::verifiable::verifiable_rerandomize(original, r, &mut rng);
    WASMVerifiableRerandomizeResult {
        result: WASMElGamal::from(result),
        proof: WASMVerifiableRerandomize(proof),
    }
}

#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = verifiableRerandomize)]
pub fn wasm_verifiable_rerandomize(
    original: &WASMElGamal,
    gy: &WASMGroupElement,
    r: &WASMScalarNonZero,
) -> WASMVerifiableRerandomizeResult {
    let mut rng = rand::rng();
    let (result, proof) =
        crate::core::verifiable::verifiable_rerandomize(original, gy, r, &mut rng);
    WASMVerifiableRerandomizeResult {
        result: WASMElGamal::from(result),
        proof: WASMVerifiableRerandomize(proof),
    }
}

// ---------------------------------------------------------------------------
// VerifiableRekey / VerifiableRekey2
// ---------------------------------------------------------------------------

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRekey)]
pub struct WASMVerifiableRekey(pub(crate) VerifiableRekey);

#[wasm_bindgen(js_class = VerifiableRekey)]
impl WASMVerifiableRekey {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, k: &WASMScalarNonZero) -> WASMVerifiableRekey {
        let mut rng = rand::rng();
        WASMVerifiableRekey(VerifiableRekey::new(v, k, &mut rng))
    }

    pub fn verify(&self, original: &WASMElGamal, commitment: &WASMRekeyFactorCommitment) -> bool {
        self.0.verify(original, commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, commitment)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, original: &WASMElGamal) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct(original))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRekey, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRekey)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen(js_name = verifiableRekey)]
pub fn wasm_verifiable_rekey(m: &WASMElGamal, k: &WASMScalarNonZero) -> WASMVerifiableRekey {
    let mut rng = rand::rng();
    WASMVerifiableRekey(VerifiableRekey::new(m, k, &mut rng))
}

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRekey2)]
pub struct WASMVerifiableRekey2(pub(crate) VerifiableRekey2);

#[wasm_bindgen(js_class = VerifiableRekey2)]
impl WASMVerifiableRekey2 {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> WASMVerifiableRekey2 {
        let mut rng = rand::rng();
        WASMVerifiableRekey2(VerifiableRekey2::new(v, k_from, k_to, &mut rng))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &WASMRekeyFactorCommitment,
        to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> WASMRekeyFactorCommitment {
        WASMRekeyFactorCommitment(self.0.combined_commitment())
    }

    pub fn verify(
        &self,
        original: &WASMElGamal,
        from_commitment: &WASMRekeyFactorCommitment,
        to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify(original, from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        from_commitment: &WASMRekeyFactorCommitment,
        to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, from_commitment, to_commitment)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, original: &WASMElGamal) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct(original))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRekey2, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRekey2)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen(js_name = verifiableRekey2)]
pub fn wasm_verifiable_rekey2(
    m: &WASMElGamal,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMVerifiableRekey2 {
    let mut rng = rand::rng();
    WASMVerifiableRekey2(VerifiableRekey2::new(m, k_from, k_to, &mut rng))
}

// ---------------------------------------------------------------------------
// VerifiableReshuffle / VerifiableReshuffle2
// ---------------------------------------------------------------------------

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableReshuffle)]
pub struct WASMVerifiableReshuffle(pub(crate) VerifiableReshuffle);

#[wasm_bindgen(js_class = VerifiableReshuffle)]
impl WASMVerifiableReshuffle {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, s: &WASMScalarNonZero) -> WASMVerifiableReshuffle {
        let mut rng = rand::rng();
        WASMVerifiableReshuffle(VerifiableReshuffle::new(v, s, &mut rng))
    }

    pub fn verify(
        &self,
        original: &WASMElGamal,
        commitment: &WASMPseudonymizationFactorCommitment,
    ) -> bool {
        self.0.verify(original, commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        commitment: &WASMPseudonymizationFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, commitment)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, original: &WASMElGamal) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct(original))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableReshuffle, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableReshuffle)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen(js_name = verifiableReshuffle)]
pub fn wasm_verifiable_reshuffle(
    m: &WASMElGamal,
    s: &WASMScalarNonZero,
) -> WASMVerifiableReshuffle {
    let mut rng = rand::rng();
    WASMVerifiableReshuffle(VerifiableReshuffle::new(m, s, &mut rng))
}

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableReshuffle2)]
pub struct WASMVerifiableReshuffle2(pub(crate) VerifiableReshuffle2);

#[wasm_bindgen(js_class = VerifiableReshuffle2)]
impl WASMVerifiableReshuffle2 {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
    ) -> WASMVerifiableReshuffle2 {
        let mut rng = rand::rng();
        WASMVerifiableReshuffle2(VerifiableReshuffle2::new(v, s_from, s_to, &mut rng))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &WASMPseudonymizationFactorCommitment,
        to_commitment: &WASMPseudonymizationFactorCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> WASMPseudonymizationFactorCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_commitment())
    }

    pub fn verify(
        &self,
        original: &WASMElGamal,
        from_commitment: &WASMPseudonymizationFactorCommitment,
        to_commitment: &WASMPseudonymizationFactorCommitment,
    ) -> bool {
        self.0.verify(original, from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        from_commitment: &WASMPseudonymizationFactorCommitment,
        to_commitment: &WASMPseudonymizationFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, from_commitment, to_commitment)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, original: &WASMElGamal) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct(original))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableReshuffle2, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableReshuffle2)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen(js_name = verifiableReshuffle2)]
pub fn wasm_verifiable_reshuffle2(
    m: &WASMElGamal,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
) -> WASMVerifiableReshuffle2 {
    let mut rng = rand::rng();
    WASMVerifiableReshuffle2(VerifiableReshuffle2::new(m, s_from, s_to, &mut rng))
}

// ---------------------------------------------------------------------------
// VerifiableRSKInner / VerifiableRSK / VerifiableRSK2
// ---------------------------------------------------------------------------

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRSKInner)]
pub struct WASMVerifiableRSKInner(pub(crate) VerifiableRSKInner);

#[wasm_bindgen(js_class = VerifiableRSKInner)]
impl WASMVerifiableRSKInner {
    pub fn verify(
        &self,
        original: &WASMElGamal,
        gt: &crate::arithmetic::wasm::group_elements::WASMGroupElement,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0
            .verify(original, gt, reshuffle_commitment, rekey_commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        gt: &crate::arithmetic::wasm::group_elements::WASMGroupElement,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, gt, reshuffle_commitment, rekey_commitment)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRSKInner, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRSKInner)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRSK)]
pub struct WASMVerifiableRSK(pub(crate) VerifiableRSK);

#[wasm_bindgen(js_class = VerifiableRSK)]
impl WASMVerifiableRSK {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        s: &WASMScalarNonZero,
        k: &WASMScalarNonZero,
    ) -> WASMVerifiableRSK {
        let mut rng = rand::rng();
        WASMVerifiableRSK(VerifiableRSK::new(v, s, k, &mut rng))
    }

    pub fn verify(
        &self,
        original: &WASMElGamal,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0
            .verify(original, reshuffle_commitment, rekey_commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, reshuffle_commitment, rekey_commitment)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct())
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRSK, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRSK)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen(js_name = verifiableRsk)]
pub fn wasm_verifiable_rsk(
    m: &WASMElGamal,
    s: &WASMScalarNonZero,
    k: &WASMScalarNonZero,
) -> WASMVerifiableRSK {
    let mut rng = rand::rng();
    WASMVerifiableRSK(VerifiableRSK::new(m, s, k, &mut rng))
}

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRSK2)]
pub struct WASMVerifiableRSK2(pub(crate) VerifiableRSK2);

#[wasm_bindgen(js_class = VerifiableRSK2)]
impl WASMVerifiableRSK2 {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> WASMVerifiableRSK2 {
        let mut rng = rand::rng();
        WASMVerifiableRSK2(VerifiableRSK2::new(v, s_from, s_to, k_from, k_to, &mut rng))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify_factor(
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[wasm_bindgen(js_name = combinedReshuffleCommitment)]
    pub fn combined_reshuffle_commitment(&self) -> WASMPseudonymizationFactorCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_reshuffle_commitment())
    }

    #[wasm_bindgen(js_name = combinedRekeyCommitment)]
    pub fn combined_rekey_commitment(&self) -> WASMRekeyFactorCommitment {
        WASMRekeyFactorCommitment(self.0.combined_rekey_commitment())
    }

    pub fn verify(
        &self,
        original: &WASMElGamal,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify(
            original,
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(
                original,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct())
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRSK2, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRSK2)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[wasm_bindgen(js_name = verifiableRsk2)]
pub fn wasm_verifiable_rsk2(
    m: &WASMElGamal,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMVerifiableRSK2 {
    let mut rng = rand::rng();
    WASMVerifiableRSK2(VerifiableRSK2::new(m, s_from, s_to, k_from, k_to, &mut rng))
}

// ---------------------------------------------------------------------------
// VerifiableRRSK / VerifiableRRSK2
// ---------------------------------------------------------------------------

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRRSK)]
pub struct WASMVerifiableRRSK(pub(crate) VerifiableRRSK);

#[wasm_bindgen(js_class = VerifiableRRSK)]
impl WASMVerifiableRRSK {
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        r: &WASMScalarNonZero,
        s: &WASMScalarNonZero,
        k: &WASMScalarNonZero,
    ) -> WASMVerifiableRRSK {
        let mut rng = rand::rng();
        WASMVerifiableRRSK(VerifiableRRSK::new(v, &v.gy, r, s, k, &mut rng))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        gy: &WASMGroupElement,
        r: &WASMScalarNonZero,
        s: &WASMScalarNonZero,
        k: &WASMScalarNonZero,
    ) -> WASMVerifiableRRSK {
        let mut rng = rand::rng();
        WASMVerifiableRRSK(VerifiableRRSK::new(v, gy, r, s, k, &mut rng))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &WASMElGamal,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify(
            original,
            &original.gy,
            reshuffle_commitment,
            rekey_commitment,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &WASMElGamal,
        gy: &WASMGroupElement,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0
            .verify(original, gy, reshuffle_commitment, rekey_commitment)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(
                original,
                &original.gy,
                reshuffle_commitment,
                rekey_commitment,
            )
            .map(WASMElGamal::from)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        gy: &WASMGroupElement,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, gy, reshuffle_commitment, rekey_commitment)
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct())
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRRSK, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRRSK)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = verifiableRrsk)]
pub fn wasm_verifiable_rrsk(
    m: &WASMElGamal,
    r: &WASMScalarNonZero,
    s: &WASMScalarNonZero,
    k: &WASMScalarNonZero,
) -> WASMVerifiableRRSK {
    let mut rng = rand::rng();
    WASMVerifiableRRSK(VerifiableRRSK::new(m, &m.gy, r, s, k, &mut rng))
}

#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRrsk)]
pub fn wasm_verifiable_rrsk(
    m: &WASMElGamal,
    gy: &WASMGroupElement,
    r: &WASMScalarNonZero,
    s: &WASMScalarNonZero,
    k: &WASMScalarNonZero,
) -> WASMVerifiableRRSK {
    let mut rng = rand::rng();
    WASMVerifiableRRSK(VerifiableRRSK::new(m, gy, r, s, k, &mut rng))
}

#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRRSK2)]
pub struct WASMVerifiableRRSK2(pub(crate) VerifiableRRSK2);

#[wasm_bindgen(js_class = VerifiableRRSK2)]
impl WASMVerifiableRRSK2 {
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        r: &WASMScalarNonZero,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> WASMVerifiableRRSK2 {
        let mut rng = rand::rng();
        WASMVerifiableRRSK2(VerifiableRRSK2::new(
            v, &v.gy, r, s_from, s_to, k_from, k_to, &mut rng,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_proof(
        v: &WASMElGamal,
        gy: &WASMGroupElement,
        r: &WASMScalarNonZero,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> WASMVerifiableRRSK2 {
        let mut rng = rand::rng();
        WASMVerifiableRRSK2(VerifiableRRSK2::new(
            v, gy, r, s_from, s_to, k_from, k_to, &mut rng,
        ))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &WASMElGamal,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify(
            original,
            &original.gy,
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        original: &WASMElGamal,
        gy: &WASMGroupElement,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify(
            original,
            gy,
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(
                original,
                &original.gy,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
            .map(WASMElGamal::from)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        gy: &WASMGroupElement,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(
                original,
                gy,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
            .map(WASMElGamal::from)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self) -> WASMElGamal {
        WASMElGamal::from(self.0.unverified_reconstruct())
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRRSK2, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRRSK2)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "elgamal3")]
#[wasm_bindgen(js_name = verifiableRrsk2)]
pub fn wasm_verifiable_rrsk2(
    m: &WASMElGamal,
    r: &WASMScalarNonZero,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMVerifiableRRSK2 {
    let mut rng = rand::rng();
    WASMVerifiableRRSK2(VerifiableRRSK2::new(
        m, &m.gy, r, s_from, s_to, k_from, k_to, &mut rng,
    ))
}

#[cfg(not(feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRrsk2)]
#[allow(clippy::too_many_arguments)]
pub fn wasm_verifiable_rrsk2(
    m: &WASMElGamal,
    gy: &WASMGroupElement,
    r: &WASMScalarNonZero,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMVerifiableRRSK2 {
    let mut rng = rand::rng();
    WASMVerifiableRRSK2(VerifiableRRSK2::new(
        m, gy, r, s_from, s_to, k_from, k_to, &mut rng,
    ))
}

// ---------------------------------------------------------------------------
// Batched proof types (feature = "batch")
// ---------------------------------------------------------------------------

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRerandomizeBatch)]
pub struct WASMVerifiableRerandomizeBatch(pub(crate) VerifiableRerandomizeBatch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableRerandomizeBatch)]
impl WASMVerifiableRerandomizeBatch {
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(n: usize, gy_source: &WASMElGamal) -> WASMVerifiableRerandomizeBatch {
        let mut rng = rand::rng();
        WASMVerifiableRerandomizeBatch(VerifiableRerandomizeBatch::new(n, &gy_source.gy, &mut rng))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(n: usize, gy: &WASMGroupElement) -> WASMVerifiableRerandomizeBatch {
        let mut rng = rand::rng();
        WASMVerifiableRerandomizeBatch(VerifiableRerandomizeBatch::new(n, gy, &mut rng))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verify(&self, gy_source: &WASMElGamal) -> bool {
        self.0.verify(&gy_source.gy)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(&self, gy: &WASMGroupElement) -> bool {
        self.0.verify(gy)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Option<Vec<WASMElGamal>> {
        if originals.is_empty() {
            return if self.0.inners.is_empty() {
                Some(Vec::new())
            } else {
                None
            };
        }
        let gy = originals[0].gy;
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, &gy)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, gy)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRerandomizeBatch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRerandomizeBatch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

/// Pair returned by the insecure `verifiableRerandomizeBatch` free function:
/// the freshly rerandomized ciphertexts plus the batch proof. Returned as
/// a struct rather than a JS tuple because `wasm-bindgen` cannot expose tuples.
#[cfg(all(feature = "batch", feature = "insecure"))]
#[wasm_bindgen(js_name = VerifiableRerandomizeBatchResult)]
pub struct WASMVerifiableRerandomizeBatchResult {
    results: Vec<WASMElGamal>,
    proof: WASMVerifiableRerandomizeBatch,
}

#[cfg(all(feature = "batch", feature = "insecure"))]
#[wasm_bindgen(js_class = VerifiableRerandomizeBatchResult)]
impl WASMVerifiableRerandomizeBatchResult {
    #[wasm_bindgen(getter)]
    pub fn results(&self) -> Vec<WASMElGamal> {
        self.results.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> WASMVerifiableRerandomizeBatch {
        self.proof.clone()
    }
}

#[cfg(all(feature = "batch", feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRerandomizeBatch)]
pub fn wasm_verifiable_rerandomize_batch(
    originals: Vec<WASMElGamal>,
) -> Result<WASMVerifiableRerandomizeBatchResult, JsValue> {
    if originals.is_empty() {
        return Err(JsValue::from_str(
            "verifiableRerandomizeBatch requires at least one ciphertext",
        ));
    }
    let mut rng = rand::rng();
    let gy = originals[0].gy;
    let cts = into_elgamal_vec(&originals);
    let (results, proof) =
        crate::core::verifiable::verifiable_rerandomize_batch(&cts, &gy, &mut rng);
    Ok(WASMVerifiableRerandomizeBatchResult {
        results: into_wasm_elgamal_vec(results),
        proof: WASMVerifiableRerandomizeBatch(proof),
    })
}

#[cfg(all(feature = "batch", feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = verifiableRerandomizeBatch)]
pub fn wasm_verifiable_rerandomize_batch(
    originals: Vec<WASMElGamal>,
    gy: &WASMGroupElement,
) -> WASMVerifiableRerandomizeBatchResult {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&originals);
    let (results, proof) =
        crate::core::verifiable::verifiable_rerandomize_batch(&cts, gy, &mut rng);
    WASMVerifiableRerandomizeBatchResult {
        results: into_wasm_elgamal_vec(results),
        proof: WASMVerifiableRerandomizeBatch(proof),
    }
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRekeyBatch)]
pub struct WASMVerifiableRekeyBatch(pub(crate) VerifiableRekeyBatch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableRekeyBatch)]
impl WASMVerifiableRekeyBatch {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        k: &WASMScalarNonZero,
    ) -> WASMVerifiableRekeyBatch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableRekeyBatch(VerifiableRekeyBatch::new(&cts, k, &mut rng))
    }

    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0.verify(&cts, commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, commitment)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRekeyBatch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRekeyBatch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = verifiableRekeyBatch)]
pub fn wasm_verifiable_rekey_batch(
    ciphertexts: Vec<WASMElGamal>,
    k: &WASMScalarNonZero,
) -> WASMVerifiableRekeyBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableRekeyBatch(VerifiableRekeyBatch::new(&cts, k, &mut rng))
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRekey2Batch)]
pub struct WASMVerifiableRekey2Batch(pub(crate) VerifiableRekey2Batch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableRekey2Batch)]
impl WASMVerifiableRekey2Batch {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> WASMVerifiableRekey2Batch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableRekey2Batch(VerifiableRekey2Batch::new(&cts, k_from, k_to, &mut rng))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &WASMRekeyFactorCommitment,
        to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> WASMRekeyFactorCommitment {
        WASMRekeyFactorCommitment(self.0.combined_commitment())
    }

    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        from_commitment: &WASMRekeyFactorCommitment,
        to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0.verify(&cts, from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        from_commitment: &WASMRekeyFactorCommitment,
        to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, from_commitment, to_commitment)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRekey2Batch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRekey2Batch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = verifiableRekey2Batch)]
pub fn wasm_verifiable_rekey2_batch(
    ciphertexts: Vec<WASMElGamal>,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMVerifiableRekey2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableRekey2Batch(VerifiableRekey2Batch::new(&cts, k_from, k_to, &mut rng))
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableReshuffleBatch)]
pub struct WASMVerifiableReshuffleBatch(pub(crate) VerifiableReshuffleBatch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableReshuffleBatch)]
impl WASMVerifiableReshuffleBatch {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s: &WASMScalarNonZero,
    ) -> WASMVerifiableReshuffleBatch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableReshuffleBatch(VerifiableReshuffleBatch::new(&cts, s, &mut rng))
    }

    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        commitment: &WASMPseudonymizationFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0.verify(&cts, commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        commitment: &WASMPseudonymizationFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, commitment)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableReshuffleBatch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableReshuffleBatch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = verifiableReshuffleBatch)]
pub fn wasm_verifiable_reshuffle_batch(
    ciphertexts: Vec<WASMElGamal>,
    s: &WASMScalarNonZero,
) -> WASMVerifiableReshuffleBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableReshuffleBatch(VerifiableReshuffleBatch::new(&cts, s, &mut rng))
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableReshuffle2Batch)]
pub struct WASMVerifiableReshuffle2Batch(pub(crate) VerifiableReshuffle2Batch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableReshuffle2Batch)]
impl WASMVerifiableReshuffle2Batch {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
    ) -> WASMVerifiableReshuffle2Batch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableReshuffle2Batch(VerifiableReshuffle2Batch::new(&cts, s_from, s_to, &mut rng))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &WASMPseudonymizationFactorCommitment,
        to_commitment: &WASMPseudonymizationFactorCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> WASMPseudonymizationFactorCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_commitment())
    }

    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        from_commitment: &WASMPseudonymizationFactorCommitment,
        to_commitment: &WASMPseudonymizationFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0.verify(&cts, from_commitment, to_commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        from_commitment: &WASMPseudonymizationFactorCommitment,
        to_commitment: &WASMPseudonymizationFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, from_commitment, to_commitment)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableReshuffle2Batch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableReshuffle2Batch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = verifiableReshuffle2Batch)]
pub fn wasm_verifiable_reshuffle2_batch(
    ciphertexts: Vec<WASMElGamal>,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
) -> WASMVerifiableReshuffle2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableReshuffle2Batch(VerifiableReshuffle2Batch::new(&cts, s_from, s_to, &mut rng))
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRSKBatch)]
pub struct WASMVerifiableRSKBatch(pub(crate) VerifiableRSKBatch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableRSKBatch)]
impl WASMVerifiableRSKBatch {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s: &WASMScalarNonZero,
        k: &WASMScalarNonZero,
    ) -> WASMVerifiableRSKBatch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableRSKBatch(VerifiableRSKBatch::new(&cts, s, k, &mut rng))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify_factor(reshuffle_commitment, rekey_commitment)
    }

    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0.verify(&cts, reshuffle_commitment, rekey_commitment)
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, reshuffle_commitment, rekey_commitment)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRSKBatch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRSKBatch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = verifiableRskBatch)]
pub fn wasm_verifiable_rsk_batch(
    ciphertexts: Vec<WASMElGamal>,
    s: &WASMScalarNonZero,
    k: &WASMScalarNonZero,
) -> WASMVerifiableRSKBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableRSKBatch(VerifiableRSKBatch::new(&cts, s, k, &mut rng))
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRSK2Batch)]
pub struct WASMVerifiableRSK2Batch(pub(crate) VerifiableRSK2Batch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableRSK2Batch)]
impl WASMVerifiableRSK2Batch {
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> WASMVerifiableRSK2Batch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableRSK2Batch(VerifiableRSK2Batch::new(
            &cts, s_from, s_to, k_from, k_to, &mut rng,
        ))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.verify_factor(
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[wasm_bindgen(js_name = combinedReshuffleCommitment)]
    pub fn combined_reshuffle_commitment(&self) -> WASMPseudonymizationFactorCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_reshuffle_commitment())
    }

    #[wasm_bindgen(js_name = combinedRekeyCommitment)]
    pub fn combined_rekey_commitment(&self) -> WASMRekeyFactorCommitment {
        WASMRekeyFactorCommitment(self.0.combined_rekey_commitment())
    }

    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0.verify(
            &cts,
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(
                &cts,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRSK2Batch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRSK2Batch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(feature = "batch")]
#[wasm_bindgen(js_name = verifiableRsk2Batch)]
pub fn wasm_verifiable_rsk2_batch(
    ciphertexts: Vec<WASMElGamal>,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMVerifiableRSK2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableRSK2Batch(VerifiableRSK2Batch::new(
        &cts, s_from, s_to, k_from, k_to, &mut rng,
    ))
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRRSKBatch)]
pub struct WASMVerifiableRRSKBatch(pub(crate) VerifiableRRSKBatch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableRRSKBatch)]
impl WASMVerifiableRRSKBatch {
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s: &WASMScalarNonZero,
        k: &WASMScalarNonZero,
    ) -> Result<WASMVerifiableRRSKBatch, JsValue> {
        if ciphertexts.is_empty() {
            return Err(JsValue::from_str(
                "VerifiableRRSKBatch requires at least one ciphertext",
            ));
        }
        let mut rng = rand::rng();
        let gy = ciphertexts[0].gy;
        let cts = into_elgamal_vec(&ciphertexts);
        Ok(WASMVerifiableRRSKBatch(VerifiableRRSKBatch::new(
            &cts, &gy, s, k, &mut rng,
        )))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        s: &WASMScalarNonZero,
        k: &WASMScalarNonZero,
    ) -> WASMVerifiableRRSKBatch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableRRSKBatch(VerifiableRRSKBatch::new(&cts, gy, s, k, &mut rng))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        if originals.is_empty() {
            return false;
        }
        let gy = originals[0].gy;
        let cts = into_elgamal_vec(&originals);
        self.0
            .verify(&cts, &gy, reshuffle_commitment, rekey_commitment)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verify(&cts, gy, reshuffle_commitment, rekey_commitment)
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        if originals.is_empty() {
            return None;
        }
        let gy = originals[0].gy;
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, &gy, reshuffle_commitment, rekey_commitment)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        reshuffle_commitment: &WASMPseudonymizationFactorCommitment,
        rekey_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(&cts, gy, reshuffle_commitment, rekey_commitment)
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRRSKBatch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRRSKBatch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRrskBatch)]
pub fn wasm_verifiable_rrsk_batch(
    ciphertexts: Vec<WASMElGamal>,
    s: &WASMScalarNonZero,
    k: &WASMScalarNonZero,
) -> Result<WASMVerifiableRRSKBatch, JsValue> {
    if ciphertexts.is_empty() {
        return Err(JsValue::from_str(
            "verifiableRrskBatch requires at least one ciphertext",
        ));
    }
    let mut rng = rand::rng();
    let gy = ciphertexts[0].gy;
    let cts = into_elgamal_vec(&ciphertexts);
    Ok(WASMVerifiableRRSKBatch(VerifiableRRSKBatch::new(
        &cts, &gy, s, k, &mut rng,
    )))
}

#[cfg(all(feature = "batch", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = verifiableRrskBatch)]
pub fn wasm_verifiable_rrsk_batch(
    ciphertexts: Vec<WASMElGamal>,
    gy: &WASMGroupElement,
    s: &WASMScalarNonZero,
    k: &WASMScalarNonZero,
) -> WASMVerifiableRRSKBatch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableRRSKBatch(VerifiableRRSKBatch::new(&cts, gy, s, k, &mut rng))
}

#[cfg(feature = "batch")]
#[derive(Clone, From, Into, Deref)]
#[wasm_bindgen(js_name = VerifiableRRSK2Batch)]
pub struct WASMVerifiableRRSK2Batch(pub(crate) VerifiableRRSK2Batch);

#[cfg(feature = "batch")]
#[wasm_bindgen(js_class = VerifiableRRSK2Batch)]
impl WASMVerifiableRRSK2Batch {
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> Result<WASMVerifiableRRSK2Batch, JsValue> {
        if ciphertexts.is_empty() {
            return Err(JsValue::from_str(
                "VerifiableRRSK2Batch requires at least one ciphertext",
            ));
        }
        let mut rng = rand::rng();
        let gy = ciphertexts[0].gy;
        let cts = into_elgamal_vec(&ciphertexts);
        Ok(WASMVerifiableRRSK2Batch(VerifiableRRSK2Batch::new(
            &cts, &gy, s_from, s_to, k_from, k_to, &mut rng,
        )))
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        s_from: &WASMScalarNonZero,
        s_to: &WASMScalarNonZero,
        k_from: &WASMScalarNonZero,
        k_to: &WASMScalarNonZero,
    ) -> WASMVerifiableRRSK2Batch {
        let mut rng = rand::rng();
        let cts = into_elgamal_vec(&ciphertexts);
        WASMVerifiableRRSK2Batch(VerifiableRRSK2Batch::new(
            &cts, gy, s_from, s_to, k_from, k_to, &mut rng,
        ))
    }

    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        self.0.rsk2.verify_factor(
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        if originals.is_empty() {
            return false;
        }
        let gy = originals[0].gy;
        let cts = into_elgamal_vec(&originals);
        self.0.verify(
            &cts,
            &gy,
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> bool {
        let cts = into_elgamal_vec(&originals);
        self.0.verify(
            &cts,
            gy,
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        if originals.is_empty() {
            return None;
        }
        let gy = originals[0].gy;
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(
                &cts,
                &gy,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    #[allow(clippy::too_many_arguments)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        s_from_commitment: &WASMPseudonymizationFactorCommitment,
        s_to_commitment: &WASMPseudonymizationFactorCommitment,
        k_from_commitment: &WASMRekeyFactorCommitment,
        k_to_commitment: &WASMRekeyFactorCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let cts = into_elgamal_vec(&originals);
        self.0
            .verified_reconstruct(
                &cts,
                gy,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
            .map(into_wasm_elgamal_vec)
    }

    #[cfg(feature = "insecure")]
    #[wasm_bindgen(js_name = unverifiedReconstruct)]
    pub fn unverified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> {
        let cts = into_elgamal_vec(&originals);
        into_wasm_elgamal_vec(self.0.unverified_reconstruct(&cts))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0).map_err(|e| JsValue::from_str(&format!("{}", e)))
    }

    #[cfg(feature = "serde")]
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(json: &str) -> Result<WASMVerifiableRRSK2Batch, JsValue> {
        serde_json::from_str(json)
            .map(WASMVerifiableRRSK2Batch)
            .map_err(|e| JsValue::from_str(&format!("{}", e)))
    }
}

#[cfg(all(feature = "batch", feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRrsk2Batch)]
pub fn wasm_verifiable_rrsk2_batch(
    ciphertexts: Vec<WASMElGamal>,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> Result<WASMVerifiableRRSK2Batch, JsValue> {
    if ciphertexts.is_empty() {
        return Err(JsValue::from_str(
            "verifiableRrsk2Batch requires at least one ciphertext",
        ));
    }
    let mut rng = rand::rng();
    let gy = ciphertexts[0].gy;
    let cts = into_elgamal_vec(&ciphertexts);
    Ok(WASMVerifiableRRSK2Batch(VerifiableRRSK2Batch::new(
        &cts, &gy, s_from, s_to, k_from, k_to, &mut rng,
    )))
}

#[cfg(all(feature = "batch", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = verifiableRrsk2Batch)]
#[allow(clippy::too_many_arguments)]
pub fn wasm_verifiable_rrsk2_batch(
    ciphertexts: Vec<WASMElGamal>,
    gy: &WASMGroupElement,
    s_from: &WASMScalarNonZero,
    s_to: &WASMScalarNonZero,
    k_from: &WASMScalarNonZero,
    k_to: &WASMScalarNonZero,
) -> WASMVerifiableRRSK2Batch {
    let mut rng = rand::rng();
    let cts = into_elgamal_vec(&ciphertexts);
    WASMVerifiableRRSK2Batch(VerifiableRRSK2Batch::new(
        &cts, gy, s_from, s_to, k_from, k_to, &mut rng,
    ))
}
