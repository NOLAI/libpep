//! Verifiable variants of the JSON data-layer operations.
//!
//! Mirrors [`crate::data::json::data`].

use crate::data::json::data::EncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::data::simple::{EncryptedAttribute, EncryptedPseudonym};
use crate::data::verifiable::traits::{VerifiableTranscryptable, VerifiableTranscryptionProof};
use crate::factors::TranscryptionInfo;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::SessionKeys;
use rand_core::{CryptoRng, Rng};
use std::collections::HashMap;

/// Proof for verifiable transcryption of a PEP JSON value.
///
/// The structure mirrors the JSON value structure:
/// - `Null` has no proof
/// - Primitives (`Bool`, `Number`, `String`) carry [`AttributeRekeyProof`]
/// - `Pseudonym` carries a [`PseudonymPseudonymizationProof`]
/// - Long variants carry their respective long proofs
/// - Arrays and Objects carry nested proofs
#[cfg(feature = "verifiable")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::large_enum_variant)]
pub enum JSONTranscryptionProof {
    Null,
    Bool(crate::data::verifiable::simple::AttributeRekeyProof),
    Number(crate::data::verifiable::simple::AttributeRekeyProof),
    String(crate::data::verifiable::simple::AttributeRekeyProof),
    LongString(crate::data::verifiable::long::LongAttributeRekeyProof),
    Pseudonym(crate::data::verifiable::simple::PseudonymPseudonymizationProof),
    LongPseudonym(crate::data::verifiable::long::LongPseudonymPseudonymizationProof),
    Array(Vec<Box<JSONTranscryptionProof>>),
    Object(HashMap<String, Box<JSONTranscryptionProof>>),
}

#[cfg(feature = "verifiable")]
impl JSONTranscryptionProof {
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &EncryptedPEPJSONValue,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        match (original, self) {
            (EncryptedPEPJSONValue::Null, JSONTranscryptionProof::Null) => true,
            (EncryptedPEPJSONValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::Number(orig), JSONTranscryptionProof::Number(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::String(orig), JSONTranscryptionProof::String(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => {
                p.verify(orig, &commitments.pseudonym)
            }
            (
                EncryptedPEPJSONValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p.verify(orig, &commitments.pseudonym),
            (EncryptedPEPJSONValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                arr.len() == proofs.len()
                    && arr
                        .iter()
                        .zip(proofs.iter())
                        .all(|(x, p)| p.verify(x, commitments))
            }
            (EncryptedPEPJSONValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                obj.len() == proofs.len()
                    && obj.iter().all(|(k, v)| match proofs.get(k) {
                        Some(p) => p.verify(v, commitments),
                        None => false,
                    })
            }
            _ => false,
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &EncryptedPEPJSONValue,
        keys: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        match (original, self) {
            (EncryptedPEPJSONValue::Null, JSONTranscryptionProof::Null) => true,
            (EncryptedPEPJSONValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::Number(orig), JSONTranscryptionProof::Number(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::String(orig), JSONTranscryptionProof::String(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPEPJSONValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => {
                p.verify(orig, &keys.pseudonym.public, &commitments.pseudonym)
            }
            (
                EncryptedPEPJSONValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p.verify(orig, &keys.pseudonym.public, &commitments.pseudonym),
            (EncryptedPEPJSONValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                arr.len() == proofs.len()
                    && arr
                        .iter()
                        .zip(proofs.iter())
                        .all(|(x, p)| p.verify(x, keys, commitments))
            }
            (EncryptedPEPJSONValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                obj.len() == proofs.len()
                    && obj.iter().all(|(k, v)| match proofs.get(k) {
                        Some(p) => p.verify(v, keys, commitments),
                        None => false,
                    })
            }
            _ => false,
        }
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedPEPJSONValue,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<EncryptedPEPJSONValue> {
        match (original, self) {
            (EncryptedPEPJSONValue::Null, JSONTranscryptionProof::Null) => {
                Some(EncryptedPEPJSONValue::Null)
            }
            (EncryptedPEPJSONValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::Bool),
            (EncryptedPEPJSONValue::Number(orig), JSONTranscryptionProof::Number(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::Number),
            (EncryptedPEPJSONValue::String(orig), JSONTranscryptionProof::String(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::String),
            (EncryptedPEPJSONValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::LongString),
            (EncryptedPEPJSONValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => p
                .verified_reconstruct(orig, &commitments.pseudonym)
                .map(EncryptedPEPJSONValue::Pseudonym),
            (
                EncryptedPEPJSONValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p
                .verified_reconstruct(orig, &commitments.pseudonym)
                .map(EncryptedPEPJSONValue::LongPseudonym),
            (EncryptedPEPJSONValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                if arr.len() != proofs.len() {
                    return None;
                }
                let items: Option<Vec<_>> = arr
                    .iter()
                    .zip(proofs.iter())
                    .map(|(x, p)| p.verified_reconstruct(x, commitments))
                    .collect();
                items.map(EncryptedPEPJSONValue::Array)
            }
            (EncryptedPEPJSONValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                if obj.len() != proofs.len() {
                    return None;
                }
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    let p = proofs.get(k)?;
                    let r = p.verified_reconstruct(v, commitments)?;
                    out.insert(k.clone(), r);
                }
                Some(EncryptedPEPJSONValue::Object(out))
            }
            _ => None,
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedPEPJSONValue,
        keys: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<EncryptedPEPJSONValue> {
        match (original, self) {
            (EncryptedPEPJSONValue::Null, JSONTranscryptionProof::Null) => {
                Some(EncryptedPEPJSONValue::Null)
            }
            (EncryptedPEPJSONValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::Bool),
            (EncryptedPEPJSONValue::Number(orig), JSONTranscryptionProof::Number(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::Number),
            (EncryptedPEPJSONValue::String(orig), JSONTranscryptionProof::String(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::String),
            (EncryptedPEPJSONValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPEPJSONValue::LongString),
            (EncryptedPEPJSONValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => p
                .verified_reconstruct(orig, &keys.pseudonym.public, &commitments.pseudonym)
                .map(EncryptedPEPJSONValue::Pseudonym),
            (
                EncryptedPEPJSONValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p
                .verified_reconstruct(orig, &keys.pseudonym.public, &commitments.pseudonym)
                .map(EncryptedPEPJSONValue::LongPseudonym),
            (EncryptedPEPJSONValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                if arr.len() != proofs.len() {
                    return None;
                }
                let items: Option<Vec<_>> = arr
                    .iter()
                    .zip(proofs.iter())
                    .map(|(x, p)| p.verified_reconstruct(x, keys, commitments))
                    .collect();
                items.map(EncryptedPEPJSONValue::Array)
            }
            (EncryptedPEPJSONValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                if obj.len() != proofs.len() {
                    return None;
                }
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    let p = proofs.get(k)?;
                    let r = p.verified_reconstruct(v, keys, commitments)?;
                    out.insert(k.clone(), r);
                }
                Some(EncryptedPEPJSONValue::Object(out))
            }
            _ => None,
        }
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &EncryptedPEPJSONValue,
    ) -> EncryptedPEPJSONValue {
        match (original, self) {
            (EncryptedPEPJSONValue::Null, JSONTranscryptionProof::Null) => {
                EncryptedPEPJSONValue::Null
            }
            (EncryptedPEPJSONValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => {
                EncryptedPEPJSONValue::Bool(p.unverified_reconstruct(orig))
            }
            (EncryptedPEPJSONValue::Number(orig), JSONTranscryptionProof::Number(p)) => {
                EncryptedPEPJSONValue::Number(p.unverified_reconstruct(orig))
            }
            (EncryptedPEPJSONValue::String(orig), JSONTranscryptionProof::String(p)) => {
                EncryptedPEPJSONValue::String(p.unverified_reconstruct(orig))
            }
            (EncryptedPEPJSONValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => {
                EncryptedPEPJSONValue::LongString(p.unverified_reconstruct(orig))
            }
            (EncryptedPEPJSONValue::Pseudonym(_), JSONTranscryptionProof::Pseudonym(p)) => {
                EncryptedPEPJSONValue::Pseudonym(p.unverified_reconstruct())
            }
            (EncryptedPEPJSONValue::LongPseudonym(_), JSONTranscryptionProof::LongPseudonym(p)) => {
                EncryptedPEPJSONValue::LongPseudonym(p.unverified_reconstruct())
            }
            (EncryptedPEPJSONValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                EncryptedPEPJSONValue::Array(
                    arr.iter()
                        .zip(proofs.iter())
                        .map(|(x, p)| p.unverified_reconstruct(x))
                        .collect(),
                )
            }
            (EncryptedPEPJSONValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    if let Some(p) = proofs.get(k) {
                        out.insert(k.clone(), p.unverified_reconstruct(v));
                    }
                }
                EncryptedPEPJSONValue::Object(out)
            }
            // Shape mismatch — return original unchanged.
            _ => original.clone(),
        }
    }
}

#[cfg(feature = "verifiable")]
impl VerifiableTranscryptionProof for JSONTranscryptionProof {
    type DataType = EncryptedPEPJSONValue;
    type Output = EncryptedPEPJSONValue;

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        self.verify(original, commitments)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        self.verify(original, public_key, commitments)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, commitments)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, public_key, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

#[cfg(feature = "verifiable")]
impl VerifiableTranscryptable for EncryptedPEPJSONValue {
    type TranscryptionProof = JSONTranscryptionProof;

    #[cfg(feature = "elgamal3")]
    fn verifiable_transcrypt<R>(
        &self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Self::TranscryptionProof
    where
        R: Rng + CryptoRng,
    {
        use crate::data::verifiable::traits::{VerifiablePseudonymizable, VerifiableRekeyable};

        match self {
            EncryptedPEPJSONValue::Null => JSONTranscryptionProof::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                JSONTranscryptionProof::Bool(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                JSONTranscryptionProof::Number(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::String(enc) => {
                JSONTranscryptionProof::String(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::LongString(enc) => {
                JSONTranscryptionProof::LongString(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => {
                JSONTranscryptionProof::Pseudonym(enc.verifiable_pseudonymize(&info.pseudonym, rng))
            }
            EncryptedPEPJSONValue::LongPseudonym(enc) => JSONTranscryptionProof::LongPseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, rng),
            ),
            EncryptedPEPJSONValue::Array(arr) => JSONTranscryptionProof::Array(
                arr.iter()
                    .map(|x| Box::new(x.verifiable_transcrypt(info, rng)))
                    .collect(),
            ),
            EncryptedPEPJSONValue::Object(obj) => JSONTranscryptionProof::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), Box::new(v.verifiable_transcrypt(info, rng))))
                    .collect(),
            ),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_transcrypt<R>(
        &self,
        info: &TranscryptionInfo,
        keys: &SessionKeys,
        rng: &mut R,
    ) -> Self::TranscryptionProof
    where
        R: Rng + CryptoRng,
    {
        use crate::data::verifiable::traits::{VerifiablePseudonymizable, VerifiableRekeyable};

        match self {
            EncryptedPEPJSONValue::Null => JSONTranscryptionProof::Null,
            EncryptedPEPJSONValue::Bool(enc) => {
                JSONTranscryptionProof::Bool(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::Number(enc) => {
                JSONTranscryptionProof::Number(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::String(enc) => {
                JSONTranscryptionProof::String(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::LongString(enc) => {
                JSONTranscryptionProof::LongString(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPEPJSONValue::Pseudonym(enc) => JSONTranscryptionProof::Pseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym.public, rng),
            ),
            EncryptedPEPJSONValue::LongPseudonym(enc) => JSONTranscryptionProof::LongPseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym.public, rng),
            ),
            EncryptedPEPJSONValue::Array(arr) => JSONTranscryptionProof::Array(
                arr.iter()
                    .map(|x| Box::new(x.verifiable_transcrypt(info, keys, rng)))
                    .collect(),
            ),
            EncryptedPEPJSONValue::Object(obj) => JSONTranscryptionProof::Object(
                obj.iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            Box::new(v.verifiable_transcrypt(info, keys, rng)),
                        )
                    })
                    .collect(),
            ),
        }
    }
}

/// Hoisted-proof bundle for a batch of [`EncryptedPEPJSONValue`]s.
///
/// All pseudonym blocks (across the whole batch and any nested arrays/
/// objects) collapse into a single
/// [`VerifiableRRSKBatch`](crate::core::verifiable::VerifiableRRSKBatch);
/// all attribute blocks into a single
/// [`VerifiableRekeyBatch`](crate::core::verifiable::VerifiableRekeyBatch).
///
/// No per-item skeleton is needed: the verifier (and the prover) walk the
/// original [`EncryptedPEPJSONValue`] tree in a deterministic order
/// (sorted keys for objects, natural order for arrays) and consume the
/// flat proof entries in lockstep.
#[cfg(all(feature = "batch", feature = "verifiable"))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiableJSONBatch {
    pub pseudonyms: crate::core::verifiable::VerifiableRRSKBatch,
    pub attributes: crate::core::verifiable::VerifiableRekeyBatch,
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl crate::data::batch::EncryptedBatch<EncryptedPEPJSONValue> {
    /// Internal helper: build the JSON transcription proof and reassemble
    /// items from the given `gy`. Does not touch `self.public_key`.
    fn build_verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        gy: crate::arithmetic::group_elements::GroupElement,
        rng: &mut R,
    ) -> VerifiableJSONBatch
    where
        R: Rng + CryptoRng,
    {
        let mut pseudonym_originals: Vec<crate::core::elgamal::ElGamal> = Vec::new();
        let mut attribute_originals: Vec<crate::core::elgamal::ElGamal> = Vec::new();
        for item in &self.items {
            json_flatten(item, &mut pseudonym_originals, &mut attribute_originals);
        }
        let pseudonyms = crate::core::verifiable::VerifiableRRSKBatch::new(
            &pseudonym_originals,
            &gy,
            &info.pseudonym.s.0,
            &info.pseudonym.k.0,
            rng,
        );
        let attributes = crate::core::verifiable::VerifiableRekeyBatch::new(
            &attribute_originals,
            &info.attribute.0,
            rng,
        );
        let pseudonym_results = pseudonyms.result();
        let attribute_results = attributes.result(&attribute_originals);
        let mut p_idx = 0usize;
        let mut a_idx = 0usize;
        let mut new_items = Vec::with_capacity(self.items.len());
        for item in &self.items {
            new_items.push(json_rebuild(
                item,
                &pseudonym_results,
                &attribute_results,
                &mut p_idx,
                &mut a_idx,
            ));
        }
        self.items = new_items;
        VerifiableJSONBatch {
            pseudonyms,
            attributes,
        }
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    not(feature = "elgamal3"),
    feature = "batch-pk"
))]
impl crate::data::batch::EncryptedBatch<EncryptedPEPJSONValue> {
    /// Verifiably transcrypt the batch.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> VerifiableJSONBatch
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let gy = *self.public_key.pseudonym.public.value();
        let proof = self.build_verifiable_transcrypt(info, gy, rng);
        self.public_key = self.public_key.convert(&info.pseudonym.k, &info.attribute);
        proof
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    not(feature = "elgamal3"),
    not(feature = "batch-pk")
))]
impl crate::data::batch::EncryptedBatch<EncryptedPEPJSONValue> {
    /// Verifiably transcrypt the batch using a caller-supplied recipient
    /// key bundle.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::SessionKeys,
        rng: &mut R,
    ) -> VerifiableJSONBatch
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let gy = *public_key.pseudonym.public.value();
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable", feature = "elgamal3"))]
impl crate::data::batch::EncryptedBatch<EncryptedPEPJSONValue> {
    /// Verifiably transcrypt the batch.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> VerifiableJSONBatch
    where
        R: Rng + CryptoRng,
    {
        // gy is carried by each ciphertext; sample from the first available
        // pseudonym leaf.
        let mut pseudonym_originals: Vec<crate::core::elgamal::ElGamal> = Vec::new();
        let mut attribute_originals: Vec<crate::core::elgamal::ElGamal> = Vec::new();
        for item in &self.items {
            json_flatten(item, &mut pseudonym_originals, &mut attribute_originals);
        }
        let gy = pseudonym_originals
            .first()
            .map(|c| c.gy)
            .unwrap_or(crate::arithmetic::group_elements::G);
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}

/// Walk an `EncryptedPEPJSONValue` in canonical traversal order, pushing
/// every pseudonym/attribute leaf ciphertext onto the respective vectors.
/// Objects are walked in sorted-key order for determinism.
#[cfg(all(feature = "batch", feature = "verifiable"))]
fn json_flatten(
    v: &EncryptedPEPJSONValue,
    pseudonym_originals: &mut Vec<crate::core::elgamal::ElGamal>,
    attribute_originals: &mut Vec<crate::core::elgamal::ElGamal>,
) {
    use crate::data::simple::ElGamalEncrypted;
    match v {
        EncryptedPEPJSONValue::Null => {}
        EncryptedPEPJSONValue::Bool(a)
        | EncryptedPEPJSONValue::Number(a)
        | EncryptedPEPJSONValue::String(a) => {
            attribute_originals.push(*a.value());
        }
        EncryptedPEPJSONValue::LongString(la) => {
            for block in &la.0 {
                attribute_originals.push(*block.value());
            }
        }
        EncryptedPEPJSONValue::Pseudonym(p) => {
            pseudonym_originals.push(*p.value());
        }
        EncryptedPEPJSONValue::LongPseudonym(lp) => {
            for block in &lp.0 {
                pseudonym_originals.push(*block.value());
            }
        }
        EncryptedPEPJSONValue::Array(arr) => {
            for x in arr {
                json_flatten(x, pseudonym_originals, attribute_originals);
            }
        }
        EncryptedPEPJSONValue::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for k in keys {
                json_flatten(&obj[k], pseudonym_originals, attribute_originals);
            }
        }
    }
}

/// Rebuild an `EncryptedPEPJSONValue` from the original's shape, consuming
/// reconstructed ciphertexts in the same traversal order [`json_flatten`] used.
#[cfg(all(feature = "batch", feature = "verifiable"))]
fn json_rebuild(
    original: &EncryptedPEPJSONValue,
    pseudonyms: &[crate::core::elgamal::ElGamal],
    attributes: &[crate::core::elgamal::ElGamal],
    p_idx: &mut usize,
    a_idx: &mut usize,
) -> EncryptedPEPJSONValue {
    use crate::data::simple::ElGamalEncrypted;
    match original {
        EncryptedPEPJSONValue::Null => EncryptedPEPJSONValue::Null,
        EncryptedPEPJSONValue::Bool(_) => {
            let ct = attributes[*a_idx];
            *a_idx += 1;
            EncryptedPEPJSONValue::Bool(EncryptedAttribute::from_value(ct))
        }
        EncryptedPEPJSONValue::Number(_) => {
            let ct = attributes[*a_idx];
            *a_idx += 1;
            EncryptedPEPJSONValue::Number(EncryptedAttribute::from_value(ct))
        }
        EncryptedPEPJSONValue::String(_) => {
            let ct = attributes[*a_idx];
            *a_idx += 1;
            EncryptedPEPJSONValue::String(EncryptedAttribute::from_value(ct))
        }
        EncryptedPEPJSONValue::LongString(la) => {
            let blocks_vec: Vec<EncryptedAttribute> = (0..la.0.len())
                .map(|_| {
                    let ct = attributes[*a_idx];
                    *a_idx += 1;
                    EncryptedAttribute::from_value(ct)
                })
                .collect();
            EncryptedPEPJSONValue::LongString(LongEncryptedAttribute(blocks_vec))
        }
        EncryptedPEPJSONValue::Pseudonym(_) => {
            let ct = pseudonyms[*p_idx];
            *p_idx += 1;
            EncryptedPEPJSONValue::Pseudonym(EncryptedPseudonym::from_value(ct))
        }
        EncryptedPEPJSONValue::LongPseudonym(lp) => {
            let blocks_vec: Vec<EncryptedPseudonym> = (0..lp.0.len())
                .map(|_| {
                    let ct = pseudonyms[*p_idx];
                    *p_idx += 1;
                    EncryptedPseudonym::from_value(ct)
                })
                .collect();
            EncryptedPEPJSONValue::LongPseudonym(LongEncryptedPseudonym(blocks_vec))
        }
        EncryptedPEPJSONValue::Array(arr) => EncryptedPEPJSONValue::Array(
            arr.iter()
                .map(|child| json_rebuild(child, pseudonyms, attributes, p_idx, a_idx))
                .collect(),
        ),
        EncryptedPEPJSONValue::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            EncryptedPEPJSONValue::Object(
                keys.into_iter()
                    .map(|k| {
                        (
                            k.clone(),
                            json_rebuild(&obj[k], pseudonyms, attributes, p_idx, a_idx),
                        )
                    })
                    .collect(),
            )
        }
    }
}
