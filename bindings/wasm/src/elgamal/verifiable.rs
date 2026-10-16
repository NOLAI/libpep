//! WASM bindings for the verifiable primitives.
//!
//! Mirrors `libpep::elgamal::verifiable`: the factor commitments and one class per proof type,
//! single and batched. Every class has `newProof`, `verify`, `verifiedReconstruct` and (with
//! `insecure`) `unverifiedReconstruct`; the two-factor proofs also have `verifyFactor` and their
//! combined commitments. Without `elgamal3` the rerandomizing proofs take the public key `gy`
//! the ciphertexts are encrypted under; with `elgamal3` it is read from the ciphertexts.

#[cfg(not(feature = "elgamal3"))]
use crate::elgamal::arithmetic::group_elements::WASMGroupElement;
use crate::elgamal::arithmetic::scalars::WASMScalarNonZero;
use crate::elgamal::WASMElGamal;
use crate::errors::malformed_proof_err;
use derive_more::{Deref, From, Into};
#[cfg(feature = "elgamal3")]
use libpep::elgamal::arithmetic::group_elements::GroupElement;
use libpep::elgamal::verifiable::{
    FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment, VerifiableRRSK,
    VerifiableRRSK2, VerifiableRRSK2Batch, VerifiableRRSKBatch, VerifiableRSK, VerifiableRSK2,
    VerifiableRSK2Batch, VerifiableRSKBatch, VerifiableRSKInner, VerifiableRekey, VerifiableRekey2,
    VerifiableRekey2Batch, VerifiableRekeyBatch, VerifiableRerandomize, VerifiableRerandomizeBatch,
    VerifiableReshuffle, VerifiableReshuffle2, VerifiableReshuffle2Batch, VerifiableReshuffleBatch,
};
use libpep::elgamal::ElGamal;
use wasm_bindgen::prelude::*;

/// The library ciphertexts of a list of binding ciphertexts.
fn els(ciphertexts: &[WASMElGamal]) -> Vec<ElGamal> {
    ciphertexts.iter().map(|c| c.0).collect()
}

/// A library result as its binding value.
trait ToWasm {
    type Wasm;
    fn to_wasm(self) -> Self::Wasm;
}

impl ToWasm for ElGamal {
    type Wasm = WASMElGamal;
    fn to_wasm(self) -> WASMElGamal {
        WASMElGamal(self)
    }
}

impl ToWasm for Vec<ElGamal> {
    type Wasm = Vec<WASMElGamal>;
    fn to_wasm(self) -> Vec<WASMElGamal> {
        self.into_iter().map(WASMElGamal).collect()
    }
}

/// The key every one of `ciphertexts` carries, which a batch proof is made under.
#[cfg(feature = "elgamal3")]
fn common_gy(ciphertexts: &[WASMElGamal]) -> Result<GroupElement, JsValue> {
    let first = ciphertexts
        .first()
        .ok_or_else(|| JsValue::from_str("the batch has no ciphertexts to read the key from"))?;
    if ciphertexts.iter().any(|c| c.0.gy != first.0.gy) {
        return Err(JsValue::from_str(
            "the ciphertexts of a batch must carry one key",
        ));
    }
    Ok(first.0.gy)
}

/// A class wrapping a library type, with JSON (de)serialization.
macro_rules! wasm_class {
    ($(#[$doc:meta])* $w:ident($inner:ty) as $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, From, Into, Deref)]
        #[wasm_bindgen(js_name = $name)]
        pub struct $w(pub(crate) $inner);

        #[cfg(feature = "serde")]
        #[wasm_bindgen(js_class = $name)]
        impl $w {
            /// Serialize to JSON.
            #[wasm_bindgen(js_name = toJSON)]
            pub fn to_json(&self) -> Result<String, JsValue> {
                serde_json::to_string(&self.0).map_err(malformed_proof_err)
            }

            /// Deserialize from JSON.
            #[wasm_bindgen(js_name = fromJSON)]
            pub fn from_json(json: &str) -> Result<$w, JsValue> {
                serde_json::from_str::<$inner>(json)
                    .map($w)
                    .map_err(malformed_proof_err)
            }
        }
    };
}

/// `verify` and `verifiedReconstruct`, which take the same arguments; `$call` are the library
/// arguments built from them.
macro_rules! wasm_verify {
    ($(#[$cfg:meta])? $w:ident as $name:ident: ($($arg:ident: $ty:ty),*) -> $out:ty = [$($call:expr),*]) => {
        $(#[$cfg])?
        #[wasm_bindgen(js_class = $name)]
        impl $w {
            /// Verify the proof against the original ciphertext(s) and the commitments.
            pub fn verify(&self, $($arg: $ty),*) -> bool {
                self.0.verify($($call),*)
            }

            /// Verify the proof and return the result, or `undefined` if it does not verify.
            #[wasm_bindgen(js_name = verifiedReconstruct)]
            pub fn verified_reconstruct(&self, $($arg: $ty),*) -> Option<$out> {
                self.0.verified_reconstruct($($call),*).map(ToWasm::to_wasm)
            }
        }
    };
}

/// `unverifiedReconstruct` (`insecure` only).
macro_rules! wasm_unverified {
    ($w:ident as $name:ident: ($($arg:ident: $ty:ty),*) -> $out:ty = [$($call:expr),*]) => {
        #[cfg(feature = "insecure")]
        #[wasm_bindgen(js_class = $name)]
        impl $w {
            /// The result of the operation, without verifying the proof.
            #[wasm_bindgen(js_name = unverifiedReconstruct)]
            pub fn unverified_reconstruct(&self, $($arg: $ty),*) -> $out {
                self.0.unverified_reconstruct($($call),*).to_wasm()
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Factor commitments
// ---------------------------------------------------------------------------

macro_rules! wasm_commitment {
    ($(#[$doc:meta])* $w:ident($inner:ty) as $name:ident) => {
        wasm_class!($(#[$doc])* $w($inner) as $name);

        #[wasm_bindgen(js_class = $name)]
        impl $w {
            /// The commitment `a·G` to the scalar `a`.
            #[wasm_bindgen(js_name = fromScalar)]
            pub fn from_scalar(a: &WASMScalarNonZero) -> $w {
                $w(<$inner>::new(a))
            }
        }
    };
}

wasm_commitment!(
    /// Forward commitment `A = a·G` to a factor scalar `a`.
    WASMFactorCommitment(FactorCommitment) as FactorCommitment
);
wasm_commitment!(
    /// Commitment `K = k·G` to a rekey factor.
    WASMRekeyFactorCommitment(RekeyFactorCommitment) as RekeyFactorCommitment
);
wasm_commitment!(
    /// Commitment `S = s·G` to a pseudonymization (reshuffle) factor.
    WASMPseudonymizationFactorCommitment(PseudonymizationFactorCommitment)
        as PseudonymizationFactorCommitment
);

type ReshuffleCommitment = WASMPseudonymizationFactorCommitment;
type RekeyCommitment = WASMRekeyFactorCommitment;
type Scalar = WASMScalarNonZero;

// ---------------------------------------------------------------------------
// Per-message proofs
// ---------------------------------------------------------------------------

wasm_class!(WASMVerifiableRerandomize(VerifiableRerandomize) as VerifiableRerandomize);

#[wasm_bindgen(js_class = VerifiableRerandomize)]
impl WASMVerifiableRerandomize {
    /// A proof of rerandomizing a ciphertext of `v` with `r`.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, r: &Scalar) -> WASMVerifiableRerandomize {
        Self(VerifiableRerandomize::new(&v.0.gy, r, &mut rand::rng()))
    }

    /// A proof of rerandomizing a ciphertext under `gy` with `r`.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(gy: &WASMGroupElement, r: &Scalar) -> WASMVerifiableRerandomize {
        Self(VerifiableRerandomize::new(gy, r, &mut rand::rng()))
    }

    /// Verify the proof against the key of `v`.
    #[cfg(feature = "elgamal3")]
    pub fn verify(&self, v: &WASMElGamal) -> bool {
        self.0.verify(&v.0.gy)
    }

    /// Verify the proof against `gy`.
    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(&self, gy: &WASMGroupElement) -> bool {
        self.0.verify(gy)
    }

    /// Verify the proof and return the rerandomized ciphertext, or `undefined`.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(&self, original: &WASMElGamal) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, &original.0.gy)
            .map(ToWasm::to_wasm)
    }

    /// Verify the proof and return the rerandomized ciphertext, or `undefined`.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        original: &WASMElGamal,
        gy: &WASMGroupElement,
    ) -> Option<WASMElGamal> {
        self.0
            .verified_reconstruct(original, gy)
            .map(ToWasm::to_wasm)
    }
}
wasm_unverified!(WASMVerifiableRerandomize as VerifiableRerandomize:
    (original: &WASMElGamal) -> WASMElGamal = [original]);

/// The result of the insecure `verifiableRerandomize`: the rerandomized ciphertext and the
/// proof.
#[cfg(feature = "insecure")]
#[wasm_bindgen(js_name = VerifiableRerandomizeResult)]
pub struct WASMVerifiableRerandomizeResult {
    result: WASMElGamal,
    proof: WASMVerifiableRerandomize,
}

#[cfg(feature = "insecure")]
#[wasm_bindgen(js_class = VerifiableRerandomizeResult)]
impl WASMVerifiableRerandomizeResult {
    /// The rerandomized ciphertext.
    #[wasm_bindgen(getter)]
    pub fn result(&self) -> WASMElGamal {
        self.result
    }

    /// The proof.
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> WASMVerifiableRerandomize {
        self.proof.clone()
    }
}

/// Rerandomize a ciphertext with a proof.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRerandomize)]
pub fn wasm_verifiable_rerandomize(
    original: &WASMElGamal,
    r: &Scalar,
) -> WASMVerifiableRerandomizeResult {
    let (result, proof) =
        libpep::elgamal::verifiable::verifiable_rerandomize(original, r, &mut rand::rng());
    WASMVerifiableRerandomizeResult {
        result: result.to_wasm(),
        proof: WASMVerifiableRerandomize(proof),
    }
}

/// Rerandomize a ciphertext under `gy` with a proof.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = verifiableRerandomize)]
pub fn wasm_verifiable_rerandomize(
    original: &WASMElGamal,
    gy: &WASMGroupElement,
    r: &Scalar,
) -> WASMVerifiableRerandomizeResult {
    let (result, proof) =
        libpep::elgamal::verifiable::verifiable_rerandomize(original, gy, r, &mut rand::rng());
    WASMVerifiableRerandomizeResult {
        result: result.to_wasm(),
        proof: WASMVerifiableRerandomize(proof),
    }
}

wasm_class!(WASMVerifiableRekey(VerifiableRekey) as VerifiableRekey);
#[wasm_bindgen(js_class = VerifiableRekey)]
impl WASMVerifiableRekey {
    /// A proof of rekeying `v` with `k`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, k: &Scalar) -> WASMVerifiableRekey {
        Self(VerifiableRekey::new(v, k, &mut rand::rng()))
    }
}
wasm_verify!(WASMVerifiableRekey as VerifiableRekey:
    (original: &WASMElGamal, commitment: &RekeyCommitment) -> WASMElGamal = [original, commitment]);
wasm_unverified!(WASMVerifiableRekey as VerifiableRekey:
    (original: &WASMElGamal) -> WASMElGamal = [original]);

wasm_class!(WASMVerifiableRekey2(VerifiableRekey2) as VerifiableRekey2);
#[wasm_bindgen(js_class = VerifiableRekey2)]
impl WASMVerifiableRekey2 {
    /// A proof of rekeying `v` from `k_from` to `k_to`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, k_from: &Scalar, k_to: &Scalar) -> WASMVerifiableRekey2 {
        Self(VerifiableRekey2::new(v, k_from, k_to, &mut rand::rng()))
    }

    /// Verify the factor sub-proof against the commitments of both sessions.
    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &RekeyCommitment,
        to_commitment: &RekeyCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    /// The commitment to the combined factor `k_from⁻¹·k_to`.
    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> RekeyCommitment {
        WASMRekeyFactorCommitment(self.0.combined_commitment())
    }
}
wasm_verify!(WASMVerifiableRekey2 as VerifiableRekey2: (
    original: &WASMElGamal,
    from_commitment: &RekeyCommitment,
    to_commitment: &RekeyCommitment
) -> WASMElGamal = [original, from_commitment, to_commitment]);
wasm_unverified!(WASMVerifiableRekey2 as VerifiableRekey2:
    (original: &WASMElGamal) -> WASMElGamal = [original]);

wasm_class!(WASMVerifiableReshuffle(VerifiableReshuffle) as VerifiableReshuffle);
#[wasm_bindgen(js_class = VerifiableReshuffle)]
impl WASMVerifiableReshuffle {
    /// A proof of reshuffling `v` with `s`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, s: &Scalar) -> WASMVerifiableReshuffle {
        Self(VerifiableReshuffle::new(v, s, &mut rand::rng()))
    }
}
wasm_verify!(WASMVerifiableReshuffle as VerifiableReshuffle:
    (original: &WASMElGamal, commitment: &ReshuffleCommitment) -> WASMElGamal
    = [original, commitment]);
wasm_unverified!(WASMVerifiableReshuffle as VerifiableReshuffle:
    (original: &WASMElGamal) -> WASMElGamal = [original]);

wasm_class!(WASMVerifiableReshuffle2(VerifiableReshuffle2) as VerifiableReshuffle2);
#[wasm_bindgen(js_class = VerifiableReshuffle2)]
impl WASMVerifiableReshuffle2 {
    /// A proof of reshuffling `v` from `s_from` to `s_to`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, s_from: &Scalar, s_to: &Scalar) -> WASMVerifiableReshuffle2 {
        Self(VerifiableReshuffle2::new(v, s_from, s_to, &mut rand::rng()))
    }

    /// Verify the factor sub-proof against the commitments of both domains.
    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &ReshuffleCommitment,
        to_commitment: &ReshuffleCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    /// The commitment to the combined factor `s_from⁻¹·s_to`.
    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> ReshuffleCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_commitment())
    }
}
wasm_verify!(WASMVerifiableReshuffle2 as VerifiableReshuffle2: (
    original: &WASMElGamal,
    from_commitment: &ReshuffleCommitment,
    to_commitment: &ReshuffleCommitment
) -> WASMElGamal = [original, from_commitment, to_commitment]);
wasm_unverified!(WASMVerifiableReshuffle2 as VerifiableReshuffle2:
    (original: &WASMElGamal) -> WASMElGamal = [original]);

wasm_class!(
    /// The per-ciphertext part of an RSK proof; verified through the proof that carries it.
    WASMVerifiableRSKInner(VerifiableRSKInner) as VerifiableRSKInner
);

wasm_class!(WASMVerifiableRSK(VerifiableRSK) as VerifiableRSK);
#[wasm_bindgen(js_class = VerifiableRSK)]
impl WASMVerifiableRSK {
    /// A proof of reshuffling and rekeying `v` with `s` and `k`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, s: &Scalar, k: &Scalar) -> WASMVerifiableRSK {
        Self(VerifiableRSK::new(v, s, k, &mut rand::rng()))
    }
}
wasm_verify!(WASMVerifiableRSK as VerifiableRSK: (
    original: &WASMElGamal,
    reshuffle_commitment: &ReshuffleCommitment,
    rekey_commitment: &RekeyCommitment
) -> WASMElGamal = [original, reshuffle_commitment, rekey_commitment]);
wasm_unverified!(WASMVerifiableRSK as VerifiableRSK: () -> WASMElGamal = []);

wasm_class!(WASMVerifiableRSK2(VerifiableRSK2) as VerifiableRSK2);
#[wasm_bindgen(js_class = VerifiableRSK2)]
impl WASMVerifiableRSK2 {
    /// A proof of transitively reshuffling and rekeying `v`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        s_from: &Scalar,
        s_to: &Scalar,
        k_from: &Scalar,
        k_to: &Scalar,
    ) -> WASMVerifiableRSK2 {
        Self(VerifiableRSK2::new(
            v,
            s_from,
            s_to,
            k_from,
            k_to,
            &mut rand::rng(),
        ))
    }

    /// Verify the factor sub-proofs against the commitments of both domains and sessions.
    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        s_from_commitment: &ReshuffleCommitment,
        s_to_commitment: &ReshuffleCommitment,
        k_from_commitment: &RekeyCommitment,
        k_to_commitment: &RekeyCommitment,
    ) -> bool {
        self.0.verify_factor(
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    /// The commitment to the combined reshuffle factor.
    #[wasm_bindgen(js_name = combinedReshuffleCommitment)]
    pub fn combined_reshuffle_commitment(&self) -> ReshuffleCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_reshuffle_commitment())
    }

    /// The commitment to the combined rekey factor.
    #[wasm_bindgen(js_name = combinedRekeyCommitment)]
    pub fn combined_rekey_commitment(&self) -> RekeyCommitment {
        WASMRekeyFactorCommitment(self.0.combined_rekey_commitment())
    }
}
wasm_verify!(WASMVerifiableRSK2 as VerifiableRSK2: (
    original: &WASMElGamal,
    s_from_commitment: &ReshuffleCommitment,
    s_to_commitment: &ReshuffleCommitment,
    k_from_commitment: &RekeyCommitment,
    k_to_commitment: &RekeyCommitment
) -> WASMElGamal = [
    original,
    s_from_commitment,
    s_to_commitment,
    k_from_commitment,
    k_to_commitment
]);
wasm_unverified!(WASMVerifiableRSK2 as VerifiableRSK2: () -> WASMElGamal = []);

wasm_class!(WASMVerifiableRRSK(VerifiableRRSK) as VerifiableRRSK);
#[wasm_bindgen(js_class = VerifiableRRSK)]
impl WASMVerifiableRRSK {
    /// A proof of rerandomizing with `r`, then reshuffling and rekeying with `s` and `k`.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(v: &WASMElGamal, r: &Scalar, s: &Scalar, k: &Scalar) -> WASMVerifiableRRSK {
        Self(VerifiableRRSK::new(v, &v.0.gy, r, s, k, &mut rand::rng()))
    }

    /// A proof of rerandomizing under `gy` with `r`, then reshuffling and rekeying with `s`
    /// and `k`.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        gy: &WASMGroupElement,
        r: &Scalar,
        s: &Scalar,
        k: &Scalar,
    ) -> WASMVerifiableRRSK {
        Self(VerifiableRRSK::new(v, gy, r, s, k, &mut rand::rng()))
    }
}
wasm_verify!(#[cfg(feature = "elgamal3")] WASMVerifiableRRSK as VerifiableRRSK: (
    original: &WASMElGamal,
    reshuffle_commitment: &ReshuffleCommitment,
    rekey_commitment: &RekeyCommitment
) -> WASMElGamal = [original, &original.0.gy, reshuffle_commitment, rekey_commitment]);
wasm_verify!(#[cfg(not(feature = "elgamal3"))] WASMVerifiableRRSK as VerifiableRRSK: (
    original: &WASMElGamal,
    gy: &WASMGroupElement,
    reshuffle_commitment: &ReshuffleCommitment,
    rekey_commitment: &RekeyCommitment
) -> WASMElGamal = [original, gy, reshuffle_commitment, rekey_commitment]);
wasm_unverified!(WASMVerifiableRRSK as VerifiableRRSK: () -> WASMElGamal = []);

wasm_class!(WASMVerifiableRRSK2(VerifiableRRSK2) as VerifiableRRSK2);
#[wasm_bindgen(js_class = VerifiableRRSK2)]
impl WASMVerifiableRRSK2 {
    /// A proof of rerandomizing with `r`, then transitively reshuffling and rekeying.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        r: &Scalar,
        s_from: &Scalar,
        s_to: &Scalar,
        k_from: &Scalar,
        k_to: &Scalar,
    ) -> WASMVerifiableRRSK2 {
        Self(VerifiableRRSK2::new(
            v,
            &v.0.gy,
            r,
            s_from,
            s_to,
            k_from,
            k_to,
            &mut rand::rng(),
        ))
    }

    /// A proof of rerandomizing under `gy` with `r`, then transitively reshuffling and
    /// rekeying.
    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        v: &WASMElGamal,
        gy: &WASMGroupElement,
        r: &Scalar,
        s_from: &Scalar,
        s_to: &Scalar,
        k_from: &Scalar,
        k_to: &Scalar,
    ) -> WASMVerifiableRRSK2 {
        Self(VerifiableRRSK2::new(
            v,
            gy,
            r,
            s_from,
            s_to,
            k_from,
            k_to,
            &mut rand::rng(),
        ))
    }
}
wasm_verify!(#[cfg(feature = "elgamal3")] WASMVerifiableRRSK2 as VerifiableRRSK2: (
    original: &WASMElGamal,
    s_from_commitment: &ReshuffleCommitment,
    s_to_commitment: &ReshuffleCommitment,
    k_from_commitment: &RekeyCommitment,
    k_to_commitment: &RekeyCommitment
) -> WASMElGamal = [
    original,
    &original.0.gy,
    s_from_commitment,
    s_to_commitment,
    k_from_commitment,
    k_to_commitment
]);
wasm_verify!(#[cfg(not(feature = "elgamal3"))] WASMVerifiableRRSK2 as VerifiableRRSK2: (
    original: &WASMElGamal,
    gy: &WASMGroupElement,
    s_from_commitment: &ReshuffleCommitment,
    s_to_commitment: &ReshuffleCommitment,
    k_from_commitment: &RekeyCommitment,
    k_to_commitment: &RekeyCommitment
) -> WASMElGamal = [
    original,
    gy,
    s_from_commitment,
    s_to_commitment,
    k_from_commitment,
    k_to_commitment
]);
wasm_unverified!(WASMVerifiableRRSK2 as VerifiableRRSK2: () -> WASMElGamal = []);

// ---------------------------------------------------------------------------
// Batched proofs
// ---------------------------------------------------------------------------

wasm_class!(
    WASMVerifiableRerandomizeBatch(VerifiableRerandomizeBatch) as VerifiableRerandomizeBatch
);

#[wasm_bindgen(js_class = VerifiableRerandomizeBatch)]
impl WASMVerifiableRerandomizeBatch {
    /// A proof of rerandomizing `n` ciphertexts carrying the key of `gy_source`.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(n: usize, gy_source: &WASMElGamal) -> WASMVerifiableRerandomizeBatch {
        Self(VerifiableRerandomizeBatch::new(
            n,
            &gy_source.0.gy,
            &mut rand::rng(),
        ))
    }

    /// A proof of rerandomizing `n` ciphertexts under `gy`.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(n: usize, gy: &WASMGroupElement) -> WASMVerifiableRerandomizeBatch {
        Self(VerifiableRerandomizeBatch::new(n, gy, &mut rand::rng()))
    }

    /// Verify the proof against `originals`, which carry one key.
    #[cfg(feature = "elgamal3")]
    pub fn verify(&self, originals: Vec<WASMElGamal>) -> bool {
        common_gy(&originals).is_ok_and(|gy| self.0.verify(&els(&originals), &gy))
    }

    /// Verify the proof against `originals` and `gy`.
    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(&self, originals: Vec<WASMElGamal>, gy: &WASMGroupElement) -> bool {
        self.0.verify(&els(&originals), gy)
    }

    /// Verify the proof and return the rerandomized ciphertexts, or `undefined`.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(&self, originals: Vec<WASMElGamal>) -> Option<Vec<WASMElGamal>> {
        let gy = common_gy(&originals).ok()?;
        self.0
            .verified_reconstruct(&els(&originals), &gy)
            .map(ToWasm::to_wasm)
    }

    /// Verify the proof and return the rerandomized ciphertexts, or `undefined`.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
    ) -> Option<Vec<WASMElGamal>> {
        self.0
            .verified_reconstruct(&els(&originals), gy)
            .map(ToWasm::to_wasm)
    }
}
wasm_unverified!(WASMVerifiableRerandomizeBatch as VerifiableRerandomizeBatch:
    (originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> = [&els(&originals)]);

/// The result of the insecure `verifiableRerandomizeBatch`: the rerandomized ciphertexts and
/// the proof.
#[cfg(feature = "insecure")]
#[wasm_bindgen(js_name = VerifiableRerandomizeBatchResult)]
pub struct WASMVerifiableRerandomizeBatchResult {
    results: Vec<WASMElGamal>,
    proof: WASMVerifiableRerandomizeBatch,
}

#[cfg(feature = "insecure")]
#[wasm_bindgen(js_class = VerifiableRerandomizeBatchResult)]
impl WASMVerifiableRerandomizeBatchResult {
    /// The rerandomized ciphertexts.
    #[wasm_bindgen(getter)]
    pub fn results(&self) -> Vec<WASMElGamal> {
        self.results.clone()
    }

    /// The proof.
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> WASMVerifiableRerandomizeBatch {
        self.proof.clone()
    }
}

/// Rerandomize ciphertexts, which carry one key, with a proof.
#[cfg(all(feature = "insecure", feature = "elgamal3"))]
#[wasm_bindgen(js_name = verifiableRerandomizeBatch)]
pub fn wasm_verifiable_rerandomize_batch(
    originals: Vec<WASMElGamal>,
) -> Result<WASMVerifiableRerandomizeBatchResult, JsValue> {
    let gy = common_gy(&originals)?;
    let (results, proof) = libpep::elgamal::verifiable::verifiable_rerandomize_batch(
        &els(&originals),
        &gy,
        &mut rand::rng(),
    );
    Ok(WASMVerifiableRerandomizeBatchResult {
        results: results.to_wasm(),
        proof: WASMVerifiableRerandomizeBatch(proof),
    })
}

/// Rerandomize ciphertexts under `gy` with a proof.
#[cfg(all(feature = "insecure", not(feature = "elgamal3")))]
#[wasm_bindgen(js_name = verifiableRerandomizeBatch)]
pub fn wasm_verifiable_rerandomize_batch(
    originals: Vec<WASMElGamal>,
    gy: &WASMGroupElement,
) -> WASMVerifiableRerandomizeBatchResult {
    let (results, proof) = libpep::elgamal::verifiable::verifiable_rerandomize_batch(
        &els(&originals),
        gy,
        &mut rand::rng(),
    );
    WASMVerifiableRerandomizeBatchResult {
        results: results.to_wasm(),
        proof: WASMVerifiableRerandomizeBatch(proof),
    }
}

wasm_class!(WASMVerifiableRekeyBatch(VerifiableRekeyBatch) as VerifiableRekeyBatch);
#[wasm_bindgen(js_class = VerifiableRekeyBatch)]
impl WASMVerifiableRekeyBatch {
    /// A proof of rekeying every ciphertext with `k`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(ciphertexts: Vec<WASMElGamal>, k: &Scalar) -> WASMVerifiableRekeyBatch {
        Self(VerifiableRekeyBatch::new(
            &els(&ciphertexts),
            k,
            &mut rand::rng(),
        ))
    }
}
wasm_verify!(WASMVerifiableRekeyBatch as VerifiableRekeyBatch:
    (originals: Vec<WASMElGamal>, commitment: &RekeyCommitment) -> Vec<WASMElGamal>
    = [&els(&originals), commitment]);
wasm_unverified!(WASMVerifiableRekeyBatch as VerifiableRekeyBatch:
    (originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> = [&els(&originals)]);

wasm_class!(WASMVerifiableRekey2Batch(VerifiableRekey2Batch) as VerifiableRekey2Batch);
#[wasm_bindgen(js_class = VerifiableRekey2Batch)]
impl WASMVerifiableRekey2Batch {
    /// A proof of rekeying every ciphertext from `k_from` to `k_to`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        k_from: &Scalar,
        k_to: &Scalar,
    ) -> WASMVerifiableRekey2Batch {
        Self(VerifiableRekey2Batch::new(
            &els(&ciphertexts),
            k_from,
            k_to,
            &mut rand::rng(),
        ))
    }

    /// Verify the factor sub-proof against the commitments of both sessions.
    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &RekeyCommitment,
        to_commitment: &RekeyCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    /// The commitment to the combined factor `k_from⁻¹·k_to`.
    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> RekeyCommitment {
        WASMRekeyFactorCommitment(self.0.combined_commitment())
    }
}
wasm_verify!(WASMVerifiableRekey2Batch as VerifiableRekey2Batch: (
    originals: Vec<WASMElGamal>,
    from_commitment: &RekeyCommitment,
    to_commitment: &RekeyCommitment
) -> Vec<WASMElGamal> = [&els(&originals), from_commitment, to_commitment]);
wasm_unverified!(WASMVerifiableRekey2Batch as VerifiableRekey2Batch:
    (originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> = [&els(&originals)]);

wasm_class!(WASMVerifiableReshuffleBatch(VerifiableReshuffleBatch) as VerifiableReshuffleBatch);
#[wasm_bindgen(js_class = VerifiableReshuffleBatch)]
impl WASMVerifiableReshuffleBatch {
    /// A proof of reshuffling every ciphertext with `s`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(ciphertexts: Vec<WASMElGamal>, s: &Scalar) -> WASMVerifiableReshuffleBatch {
        Self(VerifiableReshuffleBatch::new(
            &els(&ciphertexts),
            s,
            &mut rand::rng(),
        ))
    }
}
wasm_verify!(WASMVerifiableReshuffleBatch as VerifiableReshuffleBatch:
    (originals: Vec<WASMElGamal>, commitment: &ReshuffleCommitment) -> Vec<WASMElGamal>
    = [&els(&originals), commitment]);
wasm_unverified!(WASMVerifiableReshuffleBatch as VerifiableReshuffleBatch:
    (originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> = [&els(&originals)]);

wasm_class!(WASMVerifiableReshuffle2Batch(VerifiableReshuffle2Batch) as VerifiableReshuffle2Batch);
#[wasm_bindgen(js_class = VerifiableReshuffle2Batch)]
impl WASMVerifiableReshuffle2Batch {
    /// A proof of reshuffling every ciphertext from `s_from` to `s_to`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s_from: &Scalar,
        s_to: &Scalar,
    ) -> WASMVerifiableReshuffle2Batch {
        Self(VerifiableReshuffle2Batch::new(
            &els(&ciphertexts),
            s_from,
            s_to,
            &mut rand::rng(),
        ))
    }

    /// Verify the factor sub-proof against the commitments of both domains.
    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        from_commitment: &ReshuffleCommitment,
        to_commitment: &ReshuffleCommitment,
    ) -> bool {
        self.0.verify_factor(from_commitment, to_commitment)
    }

    /// The commitment to the combined factor `s_from⁻¹·s_to`.
    #[wasm_bindgen(js_name = combinedCommitment)]
    pub fn combined_commitment(&self) -> ReshuffleCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_commitment())
    }
}
wasm_verify!(WASMVerifiableReshuffle2Batch as VerifiableReshuffle2Batch: (
    originals: Vec<WASMElGamal>,
    from_commitment: &ReshuffleCommitment,
    to_commitment: &ReshuffleCommitment
) -> Vec<WASMElGamal> = [&els(&originals), from_commitment, to_commitment]);
wasm_unverified!(WASMVerifiableReshuffle2Batch as VerifiableReshuffle2Batch:
    (originals: Vec<WASMElGamal>) -> Vec<WASMElGamal> = [&els(&originals)]);

wasm_class!(WASMVerifiableRSKBatch(VerifiableRSKBatch) as VerifiableRSKBatch);
#[wasm_bindgen(js_class = VerifiableRSKBatch)]
impl WASMVerifiableRSKBatch {
    /// A proof of reshuffling and rekeying every ciphertext with `s` and `k`.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s: &Scalar,
        k: &Scalar,
    ) -> WASMVerifiableRSKBatch {
        Self(VerifiableRSKBatch::new(
            &els(&ciphertexts),
            s,
            k,
            &mut rand::rng(),
        ))
    }

    /// Verify the factor sub-proof against the commitments.
    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        reshuffle_commitment: &ReshuffleCommitment,
        rekey_commitment: &RekeyCommitment,
    ) -> bool {
        self.0.verify_factor(reshuffle_commitment, rekey_commitment)
    }
}
wasm_verify!(WASMVerifiableRSKBatch as VerifiableRSKBatch: (
    originals: Vec<WASMElGamal>,
    reshuffle_commitment: &ReshuffleCommitment,
    rekey_commitment: &RekeyCommitment
) -> Vec<WASMElGamal> = [&els(&originals), reshuffle_commitment, rekey_commitment]);
wasm_unverified!(WASMVerifiableRSKBatch as VerifiableRSKBatch: () -> Vec<WASMElGamal> = []);

wasm_class!(WASMVerifiableRSK2Batch(VerifiableRSK2Batch) as VerifiableRSK2Batch);
#[wasm_bindgen(js_class = VerifiableRSK2Batch)]
impl WASMVerifiableRSK2Batch {
    /// A proof of transitively reshuffling and rekeying every ciphertext.
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s_from: &Scalar,
        s_to: &Scalar,
        k_from: &Scalar,
        k_to: &Scalar,
    ) -> WASMVerifiableRSK2Batch {
        Self(VerifiableRSK2Batch::new(
            &els(&ciphertexts),
            s_from,
            s_to,
            k_from,
            k_to,
            &mut rand::rng(),
        ))
    }

    /// Verify the factor sub-proofs against the commitments of both domains and sessions.
    #[wasm_bindgen(js_name = verifyFactor)]
    pub fn verify_factor(
        &self,
        s_from_commitment: &ReshuffleCommitment,
        s_to_commitment: &ReshuffleCommitment,
        k_from_commitment: &RekeyCommitment,
        k_to_commitment: &RekeyCommitment,
    ) -> bool {
        self.0.verify_factor(
            s_from_commitment,
            s_to_commitment,
            k_from_commitment,
            k_to_commitment,
        )
    }

    /// The commitment to the combined reshuffle factor.
    #[wasm_bindgen(js_name = combinedReshuffleCommitment)]
    pub fn combined_reshuffle_commitment(&self) -> ReshuffleCommitment {
        WASMPseudonymizationFactorCommitment(self.0.combined_reshuffle_commitment())
    }

    /// The commitment to the combined rekey factor.
    #[wasm_bindgen(js_name = combinedRekeyCommitment)]
    pub fn combined_rekey_commitment(&self) -> RekeyCommitment {
        WASMRekeyFactorCommitment(self.0.combined_rekey_commitment())
    }
}
wasm_verify!(WASMVerifiableRSK2Batch as VerifiableRSK2Batch: (
    originals: Vec<WASMElGamal>,
    s_from_commitment: &ReshuffleCommitment,
    s_to_commitment: &ReshuffleCommitment,
    k_from_commitment: &RekeyCommitment,
    k_to_commitment: &RekeyCommitment
) -> Vec<WASMElGamal> = [
    &els(&originals),
    s_from_commitment,
    s_to_commitment,
    k_from_commitment,
    k_to_commitment
]);
wasm_unverified!(WASMVerifiableRSK2Batch as VerifiableRSK2Batch: () -> Vec<WASMElGamal> = []);

wasm_class!(WASMVerifiableRRSKBatch(VerifiableRRSKBatch) as VerifiableRRSKBatch);
#[wasm_bindgen(js_class = VerifiableRRSKBatch)]
impl WASMVerifiableRRSKBatch {
    /// A proof of rerandomizing, reshuffling and rekeying every ciphertext; they must carry one
    /// key.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s: &Scalar,
        k: &Scalar,
    ) -> Result<WASMVerifiableRRSKBatch, JsValue> {
        let gy = common_gy(&ciphertexts)?;
        Ok(Self(VerifiableRRSKBatch::new(
            &els(&ciphertexts),
            &gy,
            s,
            k,
            &mut rand::rng(),
        )))
    }

    /// A proof of rerandomizing under `gy`, reshuffling and rekeying every ciphertext.
    #[cfg(not(feature = "elgamal3"))]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        s: &Scalar,
        k: &Scalar,
    ) -> WASMVerifiableRRSKBatch {
        Self(VerifiableRRSKBatch::new(
            &els(&ciphertexts),
            gy,
            s,
            k,
            &mut rand::rng(),
        ))
    }

    /// Verify the proof against `originals`, which carry one key, and the commitments.
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        reshuffle_commitment: &ReshuffleCommitment,
        rekey_commitment: &RekeyCommitment,
    ) -> bool {
        common_gy(&originals).is_ok_and(|gy| {
            self.0.verify(
                &els(&originals),
                &gy,
                reshuffle_commitment,
                rekey_commitment,
            )
        })
    }

    /// Verify the proof and return the result, or `undefined` if it does not verify.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        reshuffle_commitment: &ReshuffleCommitment,
        rekey_commitment: &RekeyCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let gy = common_gy(&originals).ok()?;
        self.0
            .verified_reconstruct(
                &els(&originals),
                &gy,
                reshuffle_commitment,
                rekey_commitment,
            )
            .map(ToWasm::to_wasm)
    }
}
wasm_verify!(#[cfg(not(feature = "elgamal3"))] WASMVerifiableRRSKBatch as VerifiableRRSKBatch: (
    originals: Vec<WASMElGamal>,
    gy: &WASMGroupElement,
    reshuffle_commitment: &ReshuffleCommitment,
    rekey_commitment: &RekeyCommitment
) -> Vec<WASMElGamal> = [&els(&originals), gy, reshuffle_commitment, rekey_commitment]);
wasm_unverified!(WASMVerifiableRRSKBatch as VerifiableRRSKBatch: () -> Vec<WASMElGamal> = []);

wasm_class!(WASMVerifiableRRSK2Batch(VerifiableRRSK2Batch) as VerifiableRRSK2Batch);
#[wasm_bindgen(js_class = VerifiableRRSK2Batch)]
impl WASMVerifiableRRSK2Batch {
    /// A proof of rerandomizing, then transitively reshuffling and rekeying every ciphertext;
    /// they must carry one key.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        s_from: &Scalar,
        s_to: &Scalar,
        k_from: &Scalar,
        k_to: &Scalar,
    ) -> Result<WASMVerifiableRRSK2Batch, JsValue> {
        let gy = common_gy(&ciphertexts)?;
        Ok(Self(VerifiableRRSK2Batch::new(
            &els(&ciphertexts),
            &gy,
            s_from,
            s_to,
            k_from,
            k_to,
            &mut rand::rng(),
        )))
    }

    /// A proof of rerandomizing under `gy`, then transitively reshuffling and rekeying every
    /// ciphertext.
    #[cfg(not(feature = "elgamal3"))]
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = newProof)]
    pub fn new_proof(
        ciphertexts: Vec<WASMElGamal>,
        gy: &WASMGroupElement,
        s_from: &Scalar,
        s_to: &Scalar,
        k_from: &Scalar,
        k_to: &Scalar,
    ) -> WASMVerifiableRRSK2Batch {
        Self(VerifiableRRSK2Batch::new(
            &els(&ciphertexts),
            gy,
            s_from,
            s_to,
            k_from,
            k_to,
            &mut rand::rng(),
        ))
    }

    /// Verify the proof against `originals`, which carry one key, and the commitments.
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        originals: Vec<WASMElGamal>,
        s_from_commitment: &ReshuffleCommitment,
        s_to_commitment: &ReshuffleCommitment,
        k_from_commitment: &RekeyCommitment,
        k_to_commitment: &RekeyCommitment,
    ) -> bool {
        common_gy(&originals).is_ok_and(|gy| {
            self.0.verify(
                &els(&originals),
                &gy,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
        })
    }

    /// Verify the proof and return the result, or `undefined` if it does not verify.
    #[cfg(feature = "elgamal3")]
    #[wasm_bindgen(js_name = verifiedReconstruct)]
    pub fn verified_reconstruct(
        &self,
        originals: Vec<WASMElGamal>,
        s_from_commitment: &ReshuffleCommitment,
        s_to_commitment: &ReshuffleCommitment,
        k_from_commitment: &RekeyCommitment,
        k_to_commitment: &RekeyCommitment,
    ) -> Option<Vec<WASMElGamal>> {
        let gy = common_gy(&originals).ok()?;
        self.0
            .verified_reconstruct(
                &els(&originals),
                &gy,
                s_from_commitment,
                s_to_commitment,
                k_from_commitment,
                k_to_commitment,
            )
            .map(ToWasm::to_wasm)
    }
}
wasm_verify!(#[cfg(not(feature = "elgamal3"))] WASMVerifiableRRSK2Batch as VerifiableRRSK2Batch: (
    originals: Vec<WASMElGamal>,
    gy: &WASMGroupElement,
    s_from_commitment: &ReshuffleCommitment,
    s_to_commitment: &ReshuffleCommitment,
    k_from_commitment: &RekeyCommitment,
    k_to_commitment: &RekeyCommitment
) -> Vec<WASMElGamal> = [
    &els(&originals),
    gy,
    s_from_commitment,
    s_to_commitment,
    k_from_commitment,
    k_to_commitment
]);
wasm_unverified!(WASMVerifiableRRSK2Batch as VerifiableRRSK2Batch: () -> Vec<WASMElGamal> = []);
