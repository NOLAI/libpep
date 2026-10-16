//! Verifiable operations of the JSON data types, generic over the
//! [`Group`](crate::elgamal::arithmetic::Group).

use crate::data::json::data::generic::EncryptedPepJsonValue;
#[cfg(feature = "batch")]
use crate::data::long::generic::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::data::simple::generic::{EncryptedAttribute, EncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::data::verifiable::batch::{BatchTranscryptionProof, VerifiableBatchItem};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable, VerifiableTranscryptable, VerifiableTranscryptionProof,
};
use crate::elgamal::arithmetic::group::InvertibleEncoding;
#[cfg(feature = "batch")]
use crate::elgamal::generic::ElGamal;
use crate::factors::commitments::generic::VerifiableTranscryptionCommitment;
use crate::factors::types::generic::TranscryptionInfo;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::generic::SessionPublicKeys;
use rand_core::{CryptoRng, Rng};
use std::collections::BTreeMap;

/// Proof for verifiable transcryption of a PEP JSON value.
///
/// The structure mirrors the JSON value structure:
/// - `Null` has no proof
/// - Primitives (`Bool`, `Number`, `String`) carry [`crate::data::verifiable::simple::generic::AttributeRekeyProof`]
/// - `Pseudonym` carries a [`crate::data::verifiable::simple::generic::PseudonymPseudonymizationProof`]
/// - Long variants carry their respective long proofs
/// - Arrays and Objects carry nested proofs
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
#[allow(clippy::large_enum_variant)]
pub enum JsonTranscryptionProof<G: InvertibleEncoding> {
    /// JSON `null`: nothing to prove.
    Null,
    /// The rekey proof of a boolean.
    Bool(crate::data::verifiable::simple::generic::AttributeRekeyProof<G>),
    /// The rekey proof of a number.
    Number(crate::data::verifiable::simple::generic::AttributeRekeyProof<G>),
    /// The rekey proof of a short string.
    String(crate::data::verifiable::simple::generic::AttributeRekeyProof<G>),
    /// The rekey proof of a long string.
    LongString(crate::data::verifiable::long::generic::LongAttributeRekeyProof<G>),
    /// The pseudonymization proof of a short pseudonym.
    Pseudonym(crate::data::verifiable::simple::generic::PseudonymPseudonymizationProof<G>),
    /// The pseudonymization proof of a long pseudonym.
    LongPseudonym(crate::data::verifiable::long::generic::LongPseudonymPseudonymizationProof<G>),
    /// The proofs of the elements of an array.
    Array(Vec<Box<JsonTranscryptionProof<G>>>),
    /// The proofs of the fields of an object.
    Object(BTreeMap<String, Box<JsonTranscryptionProof<G>>>),
}

impl<G: InvertibleEncoding> VerifiableTranscryptionProof for JsonTranscryptionProof<G> {
    type Group = G;
    type DataType = EncryptedPepJsonValue<G>;
    type Output = EncryptedPepJsonValue<G>;

    #[cfg(feature = "elgamal3")]
    /// Verify the proof and return the result of the operation, or `None` if the proof does not
    /// verify.
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiableTranscryptionCommitment<G>,
    ) -> Option<Self::Output> {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JsonTranscryptionProof::Null) => {
                Some(EncryptedPepJsonValue::Null)
            }
            (EncryptedPepJsonValue::Bool(orig), JsonTranscryptionProof::Bool(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Bool),
            (EncryptedPepJsonValue::Number(orig), JsonTranscryptionProof::Number(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Number),
            (EncryptedPepJsonValue::String(orig), JsonTranscryptionProof::String(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::String),
            (EncryptedPepJsonValue::LongString(orig), JsonTranscryptionProof::LongString(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::LongString),
            (EncryptedPepJsonValue::Pseudonym(orig), JsonTranscryptionProof::Pseudonym(p)) => p
                .verified_reconstruct(orig, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::Pseudonym),
            (
                EncryptedPepJsonValue::LongPseudonym(orig),
                JsonTranscryptionProof::LongPseudonym(p),
            ) => p
                .verified_reconstruct(orig, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::LongPseudonym),
            (EncryptedPepJsonValue::Array(arr), JsonTranscryptionProof::Array(proofs)) => {
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
            (EncryptedPepJsonValue::Object(obj), JsonTranscryptionProof::Object(proofs)) => {
                if obj.len() != proofs.len() {
                    return None;
                }
                let mut out = BTreeMap::new();
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
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        keys: &SessionPublicKeys<G>,
        commitments: &VerifiableTranscryptionCommitment<G>,
    ) -> Option<Self::Output> {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JsonTranscryptionProof::Null) => {
                Some(EncryptedPepJsonValue::Null)
            }
            (EncryptedPepJsonValue::Bool(orig), JsonTranscryptionProof::Bool(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Bool),
            (EncryptedPepJsonValue::Number(orig), JsonTranscryptionProof::Number(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::Number),
            (EncryptedPepJsonValue::String(orig), JsonTranscryptionProof::String(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::String),
            (EncryptedPepJsonValue::LongString(orig), JsonTranscryptionProof::LongString(p)) => p
                .verified_reconstruct(orig, &commitments.attribute)
                .map(EncryptedPepJsonValue::LongString),
            (EncryptedPepJsonValue::Pseudonym(orig), JsonTranscryptionProof::Pseudonym(p)) => p
                .verified_reconstruct(orig, &keys.pseudonym, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::Pseudonym),
            (
                EncryptedPepJsonValue::LongPseudonym(orig),
                JsonTranscryptionProof::LongPseudonym(p),
            ) => p
                .verified_reconstruct(orig, &keys.pseudonym, &commitments.pseudonym)
                .map(EncryptedPepJsonValue::LongPseudonym),
            (EncryptedPepJsonValue::Array(arr), JsonTranscryptionProof::Array(proofs)) => {
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
            (EncryptedPepJsonValue::Object(obj), JsonTranscryptionProof::Object(proofs)) => {
                if obj.len() != proofs.len() {
                    return None;
                }
                let mut out = BTreeMap::new();
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
    /// The result of the operation, without verifying the proof.
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        match (original, self) {
            (EncryptedPepJsonValue::Null, JsonTranscryptionProof::Null) => {
                EncryptedPepJsonValue::Null
            }
            (EncryptedPepJsonValue::Bool(orig), JsonTranscryptionProof::Bool(p)) => {
                EncryptedPepJsonValue::Bool(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::Number(orig), JsonTranscryptionProof::Number(p)) => {
                EncryptedPepJsonValue::Number(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::String(orig), JsonTranscryptionProof::String(p)) => {
                EncryptedPepJsonValue::String(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::LongString(orig), JsonTranscryptionProof::LongString(p)) => {
                EncryptedPepJsonValue::LongString(p.unverified_reconstruct(orig))
            }
            (EncryptedPepJsonValue::Pseudonym(orig), JsonTranscryptionProof::Pseudonym(p)) => {
                EncryptedPepJsonValue::Pseudonym(p.unverified_reconstruct(orig))
            }
            (
                EncryptedPepJsonValue::LongPseudonym(orig),
                JsonTranscryptionProof::LongPseudonym(p),
            ) => EncryptedPepJsonValue::LongPseudonym(p.unverified_reconstruct(orig)),
            (EncryptedPepJsonValue::Array(arr), JsonTranscryptionProof::Array(proofs)) => {
                EncryptedPepJsonValue::Array(
                    arr.iter()
                        .zip(proofs.iter())
                        .map(|(x, p)| p.unverified_reconstruct(x))
                        .collect(),
                )
            }
            (EncryptedPepJsonValue::Object(obj), JsonTranscryptionProof::Object(proofs)) => {
                let mut out = BTreeMap::new();
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

impl<G: InvertibleEncoding> VerifiableTranscryptable for EncryptedPepJsonValue<G> {
    type TranscryptionProof = JsonTranscryptionProof<G>;

    #[cfg(feature = "elgamal3")]
    fn verifiable_transcrypt<R>(
        &self,
        info: &TranscryptionInfo<G>,
        rng: &mut R,
    ) -> Self::TranscryptionProof
    where
        R: Rng + CryptoRng,
    {
        match self {
            EncryptedPepJsonValue::Null => JsonTranscryptionProof::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                JsonTranscryptionProof::Bool(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Number(enc) => {
                JsonTranscryptionProof::Number(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::String(enc) => {
                JsonTranscryptionProof::String(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                JsonTranscryptionProof::LongString(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => {
                JsonTranscryptionProof::Pseudonym(enc.verifiable_pseudonymize(&info.pseudonym, rng))
            }
            EncryptedPepJsonValue::LongPseudonym(enc) => JsonTranscryptionProof::LongPseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, rng),
            ),
            EncryptedPepJsonValue::Array(arr) => JsonTranscryptionProof::Array(
                arr.iter()
                    .map(|x| Box::new(x.verifiable_transcrypt(info, rng)))
                    .collect(),
            ),
            EncryptedPepJsonValue::Object(obj) => JsonTranscryptionProof::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), Box::new(v.verifiable_transcrypt(info, rng))))
                    .collect(),
            ),
        }
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_transcrypt<R>(
        &self,
        info: &TranscryptionInfo<G>,
        keys: &SessionPublicKeys<G>,
        rng: &mut R,
    ) -> Self::TranscryptionProof
    where
        R: Rng + CryptoRng,
    {
        match self {
            EncryptedPepJsonValue::Null => JsonTranscryptionProof::Null,
            EncryptedPepJsonValue::Bool(enc) => {
                JsonTranscryptionProof::Bool(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Number(enc) => {
                JsonTranscryptionProof::Number(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::String(enc) => {
                JsonTranscryptionProof::String(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::LongString(enc) => {
                JsonTranscryptionProof::LongString(enc.verifiable_rekey(&info.attribute, rng))
            }
            EncryptedPepJsonValue::Pseudonym(enc) => JsonTranscryptionProof::Pseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym, rng),
            ),
            EncryptedPepJsonValue::LongPseudonym(enc) => JsonTranscryptionProof::LongPseudonym(
                enc.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym, rng),
            ),
            EncryptedPepJsonValue::Array(arr) => JsonTranscryptionProof::Array(
                arr.iter()
                    .map(|x| Box::new(x.verifiable_transcrypt(info, keys, rng)))
                    .collect(),
            ),
            EncryptedPepJsonValue::Object(obj) => JsonTranscryptionProof::Object(
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

/// The leaves of a document, in the order of a depth-first walk with object keys sorted, are
/// entries of the two streams of a batch.
#[cfg(feature = "batch")]
impl<G: InvertibleEncoding> VerifiableBatchItem for EncryptedPepJsonValue<G> {
    fn flatten(&self, pseudonyms: &mut Vec<ElGamal<G>>, attributes: &mut Vec<ElGamal<G>>) {
        match self {
            Self::Null => {}
            Self::Bool(a) | Self::Number(a) | Self::String(a) => a.flatten(pseudonyms, attributes),
            Self::LongString(a) => a.flatten(pseudonyms, attributes),
            Self::Pseudonym(p) => p.flatten(pseudonyms, attributes),
            Self::LongPseudonym(p) => p.flatten(pseudonyms, attributes),
            Self::Array(items) => {
                for item in items {
                    item.flatten(pseudonyms, attributes);
                }
            }
            Self::Object(fields) => {
                for value in fields.values() {
                    value.flatten(pseudonyms, attributes);
                }
            }
        }
    }

    fn rebuild(
        template: &Self,
        pseudonyms: &mut impl Iterator<Item = ElGamal<G>>,
        attributes: &mut impl Iterator<Item = ElGamal<G>>,
    ) -> Option<Self> {
        Some(match template {
            Self::Null => Self::Null,
            Self::Bool(t) => Self::Bool(EncryptedAttribute::rebuild(t, pseudonyms, attributes)?),
            Self::Number(t) => {
                Self::Number(EncryptedAttribute::rebuild(t, pseudonyms, attributes)?)
            }
            Self::String(t) => {
                Self::String(EncryptedAttribute::rebuild(t, pseudonyms, attributes)?)
            }
            Self::LongString(t) => {
                Self::LongString(LongEncryptedAttribute::rebuild(t, pseudonyms, attributes)?)
            }
            Self::Pseudonym(t) => {
                Self::Pseudonym(EncryptedPseudonym::rebuild(t, pseudonyms, attributes)?)
            }
            Self::LongPseudonym(t) => {
                Self::LongPseudonym(LongEncryptedPseudonym::rebuild(t, pseudonyms, attributes)?)
            }
            Self::Array(items) => Self::Array(
                items
                    .iter()
                    .map(|t| Self::rebuild(t, pseudonyms, attributes))
                    .collect::<Option<_>>()?,
            ),
            Self::Object(fields) => {
                let mut out = BTreeMap::new();
                for key in fields.keys() {
                    out.insert(
                        key.clone(),
                        Self::rebuild(&fields[key], pseudonyms, attributes)?,
                    );
                }
                Self::Object(out)
            }
        })
    }
}

/// Proof of a verifiable transcryption of a batch of [`EncryptedPepJsonValue`]s.
#[cfg(feature = "batch")]
pub type JsonTranscryptionBatchProof<G> = BatchTranscryptionProof<EncryptedPepJsonValue<G>>;
