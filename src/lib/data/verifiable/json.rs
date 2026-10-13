//! Verifiable variants of the JSON data-layer operations.
//!
//! Mirrors [`crate::data::json::data`].

use crate::data::json::data::EncryptedPepJsonValue;
#[cfg(all(feature = "long", feature = "batch"))]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::data::simple::{EncryptedAttribute, EncryptedPseudonym};
use crate::data::verifiable::traits::{VerifiableTranscryptable, VerifiableTranscryptionProof};
#[cfg(all(feature = "batch", not(feature = "elgamal3"), feature = "batch-pk"))]
use crate::factors::RekeyPublicKey;
use crate::factors::TranscryptionInfo;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::SessionPublicKeys;
use rand_core::{CryptoRng, Rng};
use std::collections::HashMap;

/// Proof for verifiable transcryption of a PEP JSON value.
///
/// The structure mirrors the JSON value structure:
/// - `Null` has no proof
/// - Primitives (`Bool`, `Number`, `String`) carry [`crate::data::verifiable::simple::AttributeRekeyProof`]
/// - `Pseudonym` carries a [`crate::data::verifiable::simple::PseudonymPseudonymizationProof`]
/// - Long variants carry their respective long proofs
/// - Arrays and Objects carry nested proofs
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::large_enum_variant)]
pub enum JSONTranscryptionProof {
    /// JSON `null`: nothing to prove.
    Null,
    /// The rekey proof of a boolean.
    Bool(crate::data::verifiable::simple::AttributeRekeyProof),
    /// The rekey proof of a number.
    Number(crate::data::verifiable::simple::AttributeRekeyProof),
    /// The rekey proof of a short string.
    String(crate::data::verifiable::simple::AttributeRekeyProof),
    /// The rekey proof of a long string.
    LongString(crate::data::verifiable::long::LongAttributeRekeyProof),
    /// The pseudonymization proof of a short pseudonym.
    Pseudonym(crate::data::verifiable::simple::PseudonymPseudonymizationProof),
    /// The pseudonymization proof of a long pseudonym.
    LongPseudonym(crate::data::verifiable::long::LongPseudonymPseudonymizationProof),
    /// The proofs of the elements of an array.
    Array(Vec<Box<JSONTranscryptionProof>>),
    /// The proofs of the fields of an object.
    Object(HashMap<String, Box<JSONTranscryptionProof>>),
}

impl JSONTranscryptionProof {
    #[cfg(feature = "elgamal3")]
    /// Verify the proof against the original ciphertext and the commitments.
    pub fn verify(
        &self,
        original: &EncryptedPepJsonValue,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JSONTranscryptionProof::Null) => true,
            (EncryptedPepJsonValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::Number(orig), JSONTranscryptionProof::Number(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::String(orig), JSONTranscryptionProof::String(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => {
                p.verify(orig, &commitments.pseudonym)
            }
            (
                EncryptedPepJsonValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p.verify(orig, &commitments.pseudonym),
            (EncryptedPepJsonValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                arr.len() == proofs.len()
                    && arr
                        .iter()
                        .zip(proofs.iter())
                        .all(|(x, p)| p.verify(x, commitments))
            }
            (EncryptedPepJsonValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
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
    /// Verify the proof against the original ciphertext and the commitments; without `elgamal3`,
    /// `public_key` is the key the original was encrypted under.
    pub fn verify(
        &self,
        original: &EncryptedPepJsonValue,
        keys: &SessionPublicKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JSONTranscryptionProof::Null) => true,
            (EncryptedPepJsonValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::Number(orig), JSONTranscryptionProof::Number(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::String(orig), JSONTranscryptionProof::String(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => {
                p.verify(orig, &commitments.attribute)
            }
            (EncryptedPepJsonValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => {
                p.verify(orig, &keys.pseudonym, &commitments.pseudonym)
            }
            (
                EncryptedPepJsonValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p.verify(orig, &keys.pseudonym, &commitments.pseudonym),
            (EncryptedPepJsonValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                arr.len() == proofs.len()
                    && arr
                        .iter()
                        .zip(proofs.iter())
                        .all(|(x, p)| p.verify(x, keys, commitments))
            }
            (EncryptedPepJsonValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
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
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedPepJsonValue,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<EncryptedPepJsonValue> {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JSONTranscryptionProof::Null) => {
                Some(EncryptedPepJsonValue::Null)
            }
            (EncryptedPepJsonValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Bool),
            (EncryptedPepJsonValue::Number(orig), JSONTranscryptionProof::Number(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Number),
            (EncryptedPepJsonValue::String(orig), JSONTranscryptionProof::String(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::String),
            (EncryptedPepJsonValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::LongString),
            (EncryptedPepJsonValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => p
                .verified_reconstruct(orig, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::Pseudonym),
            (
                EncryptedPepJsonValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p
                .verified_reconstruct(orig, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::LongPseudonym),
            (EncryptedPepJsonValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                if arr.len() != proofs.len() {
                    return None;
                }
                let items: Option<Vec<_>> = arr
                    .iter()
                    .zip(proofs.iter())
                    .map(|(x, p)| p.verified_reconstruct(x, commitments))
                    .collect();
                items.map(EncryptedPepJsonValue::Array)
            }
            (EncryptedPepJsonValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                if obj.len() != proofs.len() {
                    return None;
                }
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    let p = proofs.get(k)?;
                    let r = p.verified_reconstruct(v, commitments)?;
                    out.insert(k.clone(), r);
                }
                Some(EncryptedPepJsonValue::Object(out))
            }
            _ => None,
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify; without `elgamal3`, `public_key` is the key the original was encrypted under.
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedPepJsonValue,
        keys: &SessionPublicKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<EncryptedPepJsonValue> {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JSONTranscryptionProof::Null) => {
                Some(EncryptedPepJsonValue::Null)
            }
            (EncryptedPepJsonValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Bool),
            (EncryptedPepJsonValue::Number(orig), JSONTranscryptionProof::Number(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Number),
            (EncryptedPepJsonValue::String(orig), JSONTranscryptionProof::String(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::String),
            (EncryptedPepJsonValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::LongString),
            (EncryptedPepJsonValue::Pseudonym(orig), JSONTranscryptionProof::Pseudonym(p)) => p
                .verified_reconstruct(orig, &keys.pseudonym, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::Pseudonym),
            (
                EncryptedPepJsonValue::LongPseudonym(orig),
                JSONTranscryptionProof::LongPseudonym(p),
            ) => p
                .verified_reconstruct(orig, &keys.pseudonym, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::LongPseudonym),
            (EncryptedPepJsonValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                if arr.len() != proofs.len() {
                    return None;
                }
                let items: Option<Vec<_>> = arr
                    .iter()
                    .zip(proofs.iter())
                    .map(|(x, p)| p.verified_reconstruct(x, keys, commitments))
                    .collect();
                items.map(EncryptedPepJsonValue::Array)
            }
            (EncryptedPepJsonValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                if obj.len() != proofs.len() {
                    return None;
                }
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    let p = proofs.get(k)?;
                    let r = p.verified_reconstruct(v, keys, commitments)?;
                    out.insert(k.clone(), r);
                }
                Some(EncryptedPepJsonValue::Object(out))
            }
            _ => None,
        }
    }

    #[cfg(feature = "insecure")]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    pub fn unverified_reconstruct(
        &self,
        original: &EncryptedPepJsonValue,
    ) -> EncryptedPepJsonValue {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JSONTranscryptionProof::Null) => {
                EncryptedPepJsonValue::Null
            }
            (EncryptedPepJsonValue::Bool(orig), JSONTranscryptionProof::Bool(p)) => {
                EncryptedPepJsonValue::Bool(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::Number(orig), JSONTranscryptionProof::Number(p)) => {
                EncryptedPepJsonValue::Number(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::String(orig), JSONTranscryptionProof::String(p)) => {
                EncryptedPepJsonValue::String(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::LongString(orig), JSONTranscryptionProof::LongString(p)) => {
                EncryptedPepJsonValue::LongString(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::Pseudonym(_), JSONTranscryptionProof::Pseudonym(p)) => {
                EncryptedPepJsonValue::Pseudonym(p.unverified_reconstruct())
            }
            (EncryptedPepJsonValue::LongPseudonym(_), JSONTranscryptionProof::LongPseudonym(p)) => {
                EncryptedPepJsonValue::LongPseudonym(p.unverified_reconstruct())
            }
            (EncryptedPepJsonValue::Array(arr), JSONTranscryptionProof::Array(proofs)) => {
                EncryptedPepJsonValue::Array(
                    arr.iter()
                        .zip(proofs.iter())
                        .map(|(x, p)| p.unverified_reconstruct(x))
                        .collect(),
                )
            }
            (EncryptedPepJsonValue::Object(obj), JSONTranscryptionProof::Object(proofs)) => {
                let mut out = HashMap::with_capacity(obj.len());
                for (k, v) in obj {
                    if let Some(p) = proofs.get(k) {
                        out.insert(k.clone(), p.unverified_reconstruct(v));
                    }
                }
                EncryptedPepJsonValue::Object(out)
            }
            // Shape mismatch — return original unchanged.
            _ => original.clone(),
        }
    }
}

impl VerifiableTranscryptionProof for JSONTranscryptionProof {
    type DataType = EncryptedPepJsonValue;
    type Output = EncryptedPepJsonValue;

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
        public_key: &SessionPublicKeys,
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
        public_key: &SessionPublicKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, public_key, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

impl VerifiableTranscryptable for EncryptedPepJsonValue {
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
            EncryptedPepJsonValue::Null => JSONTranscryptionProof::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                JSONTranscryptionProof::Bool(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Number(enc) => {
                JSONTranscryptionProof::Number(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::String(enc) => {
                JSONTranscryptionProof::String(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                JSONTranscryptionProof::LongString(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                JSONTranscryptionProof::Pseudonym(enc.verifiable_pseudonymize(&info.pseudonym, rng))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => JSONTranscryptionProof::LongPseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, rng),
            ),
            EncryptedPepJsonValue::Array(arr) => JSONTranscryptionProof::Array(
                arr.iter()
                    .map(|x| Box::new(x.verifiable_transcrypt(info, rng)))
                    .collect(),
            ),
            EncryptedPepJsonValue::Object(obj) => JSONTranscryptionProof::Object(
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
        keys: &SessionPublicKeys,
        rng: &mut R,
    ) -> Self::TranscryptionProof
    where
        R: Rng + CryptoRng,
    {
        use crate::data::verifiable::traits::{VerifiablePseudonymizable, VerifiableRekeyable};

        match self {
            EncryptedPepJsonValue::Null => JSONTranscryptionProof::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                JSONTranscryptionProof::Bool(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Number(enc) => {
                JSONTranscryptionProof::Number(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::String(enc) => {
                JSONTranscryptionProof::String(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                JSONTranscryptionProof::LongString(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => JSONTranscryptionProof::Pseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym, rng),
            ),
            EncryptedPepJsonValue::LongPseudonym(enc) => JSONTranscryptionProof::LongPseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym, rng),
            ),
            EncryptedPepJsonValue::Array(arr) => JSONTranscryptionProof::Array(
                arr.iter()
                    .map(|x| Box::new(x.verifiable_transcrypt(info, keys, rng)))
                    .collect(),
            ),
            EncryptedPepJsonValue::Object(obj) => JSONTranscryptionProof::Object(
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

/// Hoisted-proof bundle for a batch of [`EncryptedPepJsonValue`]s.
///
/// All pseudonym blocks (across the whole batch and any nested arrays/
/// objects) collapse into a single
/// [`VerifiableRRSKBatch`](crate::elgamal::verifiable::VerifiableRRSKBatch);
/// all attribute blocks into a single
/// [`VerifiableRekeyBatch`](crate::elgamal::verifiable::VerifiableRekeyBatch).
///
/// No per-item skeleton is needed: the verifier (and the prover) walk the
/// original [`EncryptedPepJsonValue`] tree in a deterministic order
/// (sorted keys for objects, natural order for arrays) and consume the
/// flat proof entries in lockstep.
#[cfg(feature = "batch")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerifiableJSONBatch {
    /// The batch proof over the pseudonyms of every document.
    pub pseudonyms: crate::elgamal::verifiable::VerifiableRRSKBatch,
    /// The batch proof over the attributes of every document.
    pub attributes: crate::elgamal::verifiable::VerifiableRekeyBatch,
}

#[cfg(feature = "batch")]
impl crate::data::batch::EncryptedBatch<EncryptedPepJsonValue> {
    /// Internal helper: build the JSON transcription proof and reassemble
    /// items from the given `gy`. Does not touch `self.public_key`.
    fn build_verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        gy: crate::elgamal::arithmetic::group_elements::GroupElement,
        rng: &mut R,
    ) -> VerifiableJSONBatch
    where
        R: Rng + CryptoRng,
    {
        let mut pseudonym_originals: Vec<crate::elgamal::ElGamal> = Vec::new();
        let mut attribute_originals: Vec<crate::elgamal::ElGamal> = Vec::new();
        for item in &self.items {
            json_flatten(item, &mut pseudonym_originals, &mut attribute_originals);
        }
        let pseudonyms = crate::elgamal::verifiable::VerifiableRRSKBatch::new(
            &pseudonym_originals,
            &gy,
            &info.pseudonym.s.0,
            &info.pseudonym.k.0,
            rng,
        );
        let attributes = crate::elgamal::verifiable::VerifiableRekeyBatch::new(
            &attribute_originals,
            &info.attribute.k.0,
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

#[cfg(all(feature = "batch", not(feature = "elgamal3"), feature = "batch-pk"))]
impl crate::data::batch::EncryptedBatch<EncryptedPepJsonValue> {
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
        let gy = *self.public_key.pseudonym.value();
        let proof = self.build_verifiable_transcrypt(info, gy, rng);
        self.public_key = info.rekey_public_key(&self.public_key);
        proof
    }
}

#[cfg(all(
    feature = "batch",
    not(feature = "elgamal3"),
    not(feature = "batch-pk")
))]
impl crate::data::batch::EncryptedBatch<EncryptedPepJsonValue> {
    /// Verifiably transcrypt the batch using a caller-supplied recipient
    /// key bundle.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::SessionPublicKeys,
        rng: &mut R,
    ) -> VerifiableJSONBatch
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let gy = *public_key.pseudonym.value();
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}

#[cfg(all(feature = "batch", feature = "elgamal3"))]
impl crate::data::batch::EncryptedBatch<EncryptedPepJsonValue> {
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
        let mut pseudonym_originals: Vec<crate::elgamal::ElGamal> = Vec::new();
        let mut attribute_originals: Vec<crate::elgamal::ElGamal> = Vec::new();
        for item in &self.items {
            json_flatten(item, &mut pseudonym_originals, &mut attribute_originals);
        }
        let gy = pseudonym_originals
            .first()
            .map(|c| c.gy)
            .unwrap_or(crate::elgamal::arithmetic::group_elements::G);
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}

/// Walk an `EncryptedPepJsonValue` in canonical traversal order, pushing
/// every pseudonym/attribute leaf ciphertext onto the respective vectors.
/// Objects are walked in sorted-key order for determinism.
#[cfg(feature = "batch")]
fn json_flatten(
    v: &EncryptedPepJsonValue,
    pseudonym_originals: &mut Vec<crate::elgamal::ElGamal>,
    attribute_originals: &mut Vec<crate::elgamal::ElGamal>,
) {
    use crate::data::simple::ElGamalEncrypted;
    match v {
        EncryptedPepJsonValue::Null => {}
        EncryptedPepJsonValue::Bool(a)
        | EncryptedPepJsonValue::Number(a)
        | EncryptedPepJsonValue::String(a) => {
            attribute_originals.push(*a.value());
        }
        EncryptedPepJsonValue::LongString(la) => {
            for block in &la.0 {
                attribute_originals.push(*block.value());
            }
        }
        EncryptedPepJsonValue::Pseudonym(p) => {
            pseudonym_originals.push(*p.value());
        }
        EncryptedPepJsonValue::LongPseudonym(lp) => {
            for block in &lp.0 {
                pseudonym_originals.push(*block.value());
            }
        }
        EncryptedPepJsonValue::Array(arr) => {
            for x in arr {
                json_flatten(x, pseudonym_originals, attribute_originals);
            }
        }
        EncryptedPepJsonValue::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            for k in keys {
                json_flatten(&obj[k], pseudonym_originals, attribute_originals);
            }
        }
    }
}

/// Rebuild an `EncryptedPepJsonValue` from the original's shape, consuming
/// reconstructed ciphertexts in the same traversal order [`json_flatten`] used.
#[cfg(feature = "batch")]
fn json_rebuild(
    original: &EncryptedPepJsonValue,
    pseudonyms: &[crate::elgamal::ElGamal],
    attributes: &[crate::elgamal::ElGamal],
    p_idx: &mut usize,
    a_idx: &mut usize,
) -> EncryptedPepJsonValue {
    use crate::data::simple::ElGamalEncrypted;
    match original {
        EncryptedPepJsonValue::Null => EncryptedPepJsonValue::Null,
        EncryptedPepJsonValue::Bool(_) => {
            let ct = attributes[*a_idx];
            *a_idx += 1;
            EncryptedPepJsonValue::Bool(EncryptedAttribute::from_value(ct))
        }
        EncryptedPepJsonValue::Number(_) => {
            let ct = attributes[*a_idx];
            *a_idx += 1;
            EncryptedPepJsonValue::Number(EncryptedAttribute::from_value(ct))
        }
        EncryptedPepJsonValue::String(_) => {
            let ct = attributes[*a_idx];
            *a_idx += 1;
            EncryptedPepJsonValue::String(EncryptedAttribute::from_value(ct))
        }
        EncryptedPepJsonValue::LongString(la) => {
            let blocks_vec: Vec<EncryptedAttribute> = (0..la.0.len())
                .map(|_| {
                    let ct = attributes[*a_idx];
                    *a_idx += 1;
                    EncryptedAttribute::from_value(ct)
                })
                .collect();
            EncryptedPepJsonValue::LongString(LongEncryptedAttribute(blocks_vec))
        }
        EncryptedPepJsonValue::Pseudonym(_) => {
            let ct = pseudonyms[*p_idx];
            *p_idx += 1;
            EncryptedPepJsonValue::Pseudonym(EncryptedPseudonym::from_value(ct))
        }
        EncryptedPepJsonValue::LongPseudonym(lp) => {
            let blocks_vec: Vec<EncryptedPseudonym> = (0..lp.0.len())
                .map(|_| {
                    let ct = pseudonyms[*p_idx];
                    *p_idx += 1;
                    EncryptedPseudonym::from_value(ct)
                })
                .collect();
            EncryptedPepJsonValue::LongPseudonym(LongEncryptedPseudonym(blocks_vec))
        }
        EncryptedPepJsonValue::Array(arr) => EncryptedPepJsonValue::Array(
            arr.iter()
                .map(|child| json_rebuild(child, pseudonyms, attributes, p_idx, a_idx))
                .collect(),
        ),
        EncryptedPepJsonValue::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            EncryptedPepJsonValue::Object(
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
