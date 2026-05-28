//! Verifiable variants of the records data-layer operations.
//!
//! Mirrors [`crate::data::records`].

#[cfg(feature = "long")]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::data::records::EncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::LongEncryptedRecord;
use crate::data::simple::{ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym};
#[cfg(feature = "long")]
use crate::data::verifiable::long::{LongAttributeRekeyProof, LongPseudonymPseudonymizationProof};
use crate::data::verifiable::simple::{AttributeRekeyProof, PseudonymPseudonymizationProof};
use crate::data::verifiable::traits::{VerifiableTranscryptable, VerifiableTranscryptionProof};
use crate::factors::TranscryptionInfo;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::SessionKeys;
use rand_core::{CryptoRng, Rng};

/// Proof bundle for verifiable transcryption of a simple record.
///
/// Contains proofs for both pseudonymization and attribute rekeying.
#[cfg(feature = "verifiable")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecordTranscryptionProof {
    /// One [`PseudonymPseudonymizationProof`] per pseudonym (RRSK includes
    /// a fresh per-message rerandomize step).
    pub pseudonym_operation_proofs: Vec<PseudonymPseudonymizationProof>,
    /// One [`AttributeRekeyProof`] per attribute, verified against the
    /// combined attribute-rekey commitment published per transition.
    pub attribute_operation_proofs: Vec<AttributeRekeyProof>,
}

#[cfg(feature = "verifiable")]
impl RecordTranscryptionProof {
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &EncryptedRecord,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return false;
        }
        self.pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .all(|(p, orig)| p.verify(orig, &commitments.pseudonym))
            && self
                .attribute_operation_proofs
                .iter()
                .zip(original.attributes.iter())
                .all(|(p, orig)| p.verify(orig, &commitments.attribute))
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &EncryptedRecord,
        keys: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return false;
        }
        self.pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .all(|(p, orig)| p.verify(orig, &keys.pseudonym.public, &commitments.pseudonym))
            && self
                .attribute_operation_proofs
                .iter()
                .zip(original.attributes.iter())
                .all(|(p, orig)| p.verify(orig, &commitments.attribute))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedRecord,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<EncryptedRecord> {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return None;
        }
        let pseudonyms: Option<Vec<_>> = self
            .pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .map(|(p, orig)| p.verified_reconstruct(orig, &commitments.pseudonym))
            .collect();
        let attributes: Option<Vec<_>> = self
            .attribute_operation_proofs
            .iter()
            .zip(original.attributes.iter())
            .map(|(p, orig)| p.verified_reconstruct(orig, &commitments.attribute))
            .collect();
        Some(EncryptedRecord::new(pseudonyms?, attributes?))
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedRecord,
        keys: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<EncryptedRecord> {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return None;
        }
        let pseudonyms: Option<Vec<_>> = self
            .pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .map(|(p, orig)| {
                p.verified_reconstruct(orig, &keys.pseudonym.public, &commitments.pseudonym)
            })
            .collect();
        let attributes: Option<Vec<_>> = self
            .attribute_operation_proofs
            .iter()
            .zip(original.attributes.iter())
            .map(|(p, orig)| p.verified_reconstruct(orig, &commitments.attribute))
            .collect();
        Some(EncryptedRecord::new(pseudonyms?, attributes?))
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &EncryptedRecord) -> EncryptedRecord {
        let pseudonyms: Vec<_> = self
            .pseudonym_operation_proofs
            .iter()
            .map(|p| p.unverified_reconstruct())
            .collect();
        let attributes: Vec<_> = self
            .attribute_operation_proofs
            .iter()
            .zip(original.attributes.iter())
            .map(|(p, orig)| p.unverified_reconstruct(orig))
            .collect();
        EncryptedRecord::new(pseudonyms, attributes)
    }
}

#[cfg(feature = "verifiable")]
impl VerifiableTranscryptionProof for RecordTranscryptionProof {
    type DataType = EncryptedRecord;
    type Output = EncryptedRecord;

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

/// Proof bundle for verifiable transcryption of a long record.
///
/// Contains proofs for both pseudonymization and attribute rekeying,
/// with multiple proofs per long pseudonym/attribute (one per block).
#[cfg(all(feature = "verifiable", feature = "long"))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LongRecordTranscryptionProof {
    /// One [`LongPseudonymPseudonymizationProof`] per long pseudonym.
    pub pseudonym_operation_proofs: Vec<LongPseudonymPseudonymizationProof>,
    /// One [`LongAttributeRekeyProof`] per long attribute.
    pub attribute_operation_proofs: Vec<LongAttributeRekeyProof>,
}

#[cfg(all(feature = "verifiable", feature = "long"))]
impl LongRecordTranscryptionProof {
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &LongEncryptedRecord,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return false;
        }
        self.pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .all(|(p, orig)| p.verify(orig, &commitments.pseudonym))
            && self
                .attribute_operation_proofs
                .iter()
                .zip(original.attributes.iter())
                .all(|(p, orig)| p.verify(orig, &commitments.attribute))
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &LongEncryptedRecord,
        keys: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return false;
        }
        self.pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .all(|(p, orig)| p.verify(orig, &keys.pseudonym.public, &commitments.pseudonym))
            && self
                .attribute_operation_proofs
                .iter()
                .zip(original.attributes.iter())
                .all(|(p, orig)| p.verify(orig, &commitments.attribute))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &LongEncryptedRecord,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<LongEncryptedRecord> {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return None;
        }
        let pseudonyms: Option<Vec<_>> = self
            .pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .map(|(p, orig)| p.verified_reconstruct(orig, &commitments.pseudonym))
            .collect();
        let attributes: Option<Vec<_>> = self
            .attribute_operation_proofs
            .iter()
            .zip(original.attributes.iter())
            .map(|(p, orig)| p.verified_reconstruct(orig, &commitments.attribute))
            .collect();
        Some(LongEncryptedRecord {
            pseudonyms: pseudonyms?,
            attributes: attributes?,
        })
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &LongEncryptedRecord,
        keys: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<LongEncryptedRecord> {
        if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
            || self.attribute_operation_proofs.len() != original.attributes.len()
        {
            return None;
        }
        let pseudonyms: Option<Vec<_>> = self
            .pseudonym_operation_proofs
            .iter()
            .zip(original.pseudonyms.iter())
            .map(|(p, orig)| {
                p.verified_reconstruct(orig, &keys.pseudonym.public, &commitments.pseudonym)
            })
            .collect();
        let attributes: Option<Vec<_>> = self
            .attribute_operation_proofs
            .iter()
            .zip(original.attributes.iter())
            .map(|(p, orig)| p.verified_reconstruct(orig, &commitments.attribute))
            .collect();
        Some(LongEncryptedRecord {
            pseudonyms: pseudonyms?,
            attributes: attributes?,
        })
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &LongEncryptedRecord) -> LongEncryptedRecord {
        let pseudonyms: Vec<_> = self
            .pseudonym_operation_proofs
            .iter()
            .map(|p| p.unverified_reconstruct())
            .collect();
        let attributes: Vec<_> = self
            .attribute_operation_proofs
            .iter()
            .zip(original.attributes.iter())
            .map(|(p, orig)| p.unverified_reconstruct(orig))
            .collect();
        LongEncryptedRecord {
            pseudonyms,
            attributes,
        }
    }
}

#[cfg(all(feature = "verifiable", feature = "long"))]
impl VerifiableTranscryptionProof for LongRecordTranscryptionProof {
    type DataType = LongEncryptedRecord;
    type Output = LongEncryptedRecord;

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
impl VerifiableTranscryptable for EncryptedRecord {
    type TranscryptionProof = RecordTranscryptionProof;

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

        let pseudonym_operation_proofs = self
            .pseudonyms
            .iter()
            .map(|p| p.verifiable_pseudonymize(&info.pseudonym, rng))
            .collect();

        let attribute_operation_proofs = self
            .attributes
            .iter()
            .map(|a| a.verifiable_rekey(&info.attribute, rng))
            .collect();

        RecordTranscryptionProof {
            pseudonym_operation_proofs,
            attribute_operation_proofs,
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

        let pseudonym_operation_proofs = self
            .pseudonyms
            .iter()
            .map(|p| p.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym.public, rng))
            .collect();

        let attribute_operation_proofs = self
            .attributes
            .iter()
            .map(|a| a.verifiable_rekey(&info.attribute, rng))
            .collect();

        RecordTranscryptionProof {
            pseudonym_operation_proofs,
            attribute_operation_proofs,
        }
    }
}

#[cfg(all(feature = "verifiable", feature = "long"))]
impl VerifiableTranscryptable for LongEncryptedRecord {
    type TranscryptionProof = LongRecordTranscryptionProof;

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

        let pseudonym_operation_proofs = self
            .pseudonyms
            .iter()
            .map(|p| p.verifiable_pseudonymize(&info.pseudonym, rng))
            .collect();

        let attribute_operation_proofs = self
            .attributes
            .iter()
            .map(|a| a.verifiable_rekey(&info.attribute, rng))
            .collect();

        LongRecordTranscryptionProof {
            pseudonym_operation_proofs,
            attribute_operation_proofs,
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

        let pseudonym_operation_proofs = self
            .pseudonyms
            .iter()
            .map(|p| p.verifiable_pseudonymize(&info.pseudonym, &keys.pseudonym.public, rng))
            .collect();

        let attribute_operation_proofs = self
            .attributes
            .iter()
            .map(|a| a.verifiable_rekey(&info.attribute, rng))
            .collect();

        LongRecordTranscryptionProof {
            pseudonym_operation_proofs,
            attribute_operation_proofs,
        }
    }
}

/// Hoisted-proof bundle for a batch of [`EncryptedRecord`] values.
///
/// All pseudonym ciphertexts across all records in the batch share one
/// `(s, k_pseudonym)` factor pair, so they collapse into a single
/// [`VerifiableRRSKBatch`](crate::core::verifiable::VerifiableRRSKBatch).
/// All attribute ciphertexts share `k_attribute` and collapse into a single
/// [`VerifiableRekeyBatch`](crate::core::verifiable::VerifiableRekeyBatch).
/// The original per-record structure (how many pseudonyms / attributes per
/// record) is stored alongside so the verifier can align proof entries with
/// the original records.
#[cfg(all(feature = "batch", feature = "verifiable"))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecordTranscryptionBatchProof {
    /// Per-record (#pseudonyms, #attributes), in batch order.
    pub structure: Vec<(usize, usize)>,
    /// One `VerifiableRRSKBatch` covering every pseudonym across the whole
    /// batch (per-record pseudonyms concatenated in batch order).
    pub pseudonyms: crate::core::verifiable::VerifiableRRSKBatch,
    /// One `VerifiableRekeyBatch` covering every attribute across the
    /// whole batch.
    pub attributes: crate::core::verifiable::VerifiableRekeyBatch,
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl RecordTranscryptionBatchProof {
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        use crate::data::simple::ElGamalEncrypted;
        let structure: Vec<(usize, usize)> = original
            .items
            .iter()
            .map(|r| (r.pseudonyms.len(), r.attributes.len()))
            .collect();
        if structure != self.structure {
            return false;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.pseudonyms.iter().map(|p| *p.value()))
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.attributes.iter().map(|a| *a.value()))
            .collect();
        let gy = pseudonym_originals
            .first()
            .map(|c| c.gy)
            .unwrap_or(crate::arithmetic::group_elements::G);
        self.pseudonyms.verify(
            &pseudonym_originals,
            &gy,
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        ) && self
            .attributes
            .verify(&attribute_originals, &commitments.attribute.commitment)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        use crate::data::simple::ElGamalEncrypted;
        use crate::keys::PublicKey as _;
        let structure: Vec<(usize, usize)> = original
            .items
            .iter()
            .map(|r| (r.pseudonyms.len(), r.attributes.len()))
            .collect();
        if structure != self.structure {
            return false;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.pseudonyms.iter().map(|p| *p.value()))
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.attributes.iter().map(|a| *a.value()))
            .collect();
        self.pseudonyms.verify(
            &pseudonym_originals,
            public_key.pseudonym.public.value(),
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        ) && self
            .attributes
            .verify(&attribute_originals, &commitments.attribute.commitment)
    }

    /// Verify and return reconstructed records as a flat `Vec<EncryptedRecord>`.
    /// Under `batch-pk`, use
    /// [`verified_reconstruct_batch`](Self::verified_reconstruct_batch) for
    /// a labelled `EncryptedBatch`.
    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Vec<EncryptedRecord>> {
        use crate::data::simple::ElGamalEncrypted;
        let structure: Vec<(usize, usize)> = original
            .items
            .iter()
            .map(|r| (r.pseudonyms.len(), r.attributes.len()))
            .collect();
        if structure != self.structure {
            return None;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.pseudonyms.iter().map(|p| *p.value()))
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.attributes.iter().map(|a| *a.value()))
            .collect();
        let gy = pseudonym_originals
            .first()
            .map(|c| c.gy)
            .unwrap_or(crate::arithmetic::group_elements::G);
        let pseudo_news = self.pseudonyms.verified_reconstruct(
            &pseudonym_originals,
            &gy,
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        )?;
        let attr_news = self
            .attributes
            .verified_reconstruct(&attribute_originals, &commitments.attribute.commitment)?;
        Some(rebuild_records(&structure, &pseudo_news, &attr_news))
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Vec<EncryptedRecord>> {
        use crate::data::simple::ElGamalEncrypted;
        use crate::keys::PublicKey as _;
        let structure: Vec<(usize, usize)> = original
            .items
            .iter()
            .map(|r| (r.pseudonyms.len(), r.attributes.len()))
            .collect();
        if structure != self.structure {
            return None;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.pseudonyms.iter().map(|p| *p.value()))
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.attributes.iter().map(|a| *a.value()))
            .collect();
        let pseudo_news = self.pseudonyms.verified_reconstruct(
            &pseudonym_originals,
            public_key.pseudonym.public.value(),
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        )?;
        let attr_news = self
            .attributes
            .verified_reconstruct(&attribute_originals, &commitments.attribute.commitment)?;
        Some(rebuild_records(&structure, &pseudo_news, &attr_news))
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
        public_key: &SessionKeys,
        new_public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedRecord>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedRecord>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedRecord>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the records **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedRecord>,
    ) -> Vec<EncryptedRecord> {
        use crate::data::simple::ElGamalEncrypted;
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| r.attributes.iter().map(|a| *a.value()))
            .collect();
        let pseudo_news = self.pseudonyms.result();
        let attr_news = self.attributes.result(&attribute_originals);
        rebuild_records(&self.structure, &pseudo_news, &attr_news)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl VerifiableTranscryptionProof for RecordTranscryptionBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<EncryptedRecord>;
    type Output = Vec<EncryptedRecord>;

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

#[cfg(all(feature = "batch", feature = "verifiable"))]
fn rebuild_records(
    structure: &[(usize, usize)],
    pseudo_news: &[crate::core::elgamal::ElGamal],
    attr_news: &[crate::core::elgamal::ElGamal],
) -> Vec<EncryptedRecord> {
    let mut new_items = Vec::with_capacity(structure.len());
    let mut p_idx = 0;
    let mut a_idx = 0;
    for &(np, na) in structure {
        let record_p: Vec<EncryptedPseudonym> = (0..np)
            .map(|j| EncryptedPseudonym::from_value(pseudo_news[p_idx + j]))
            .collect();
        p_idx += np;
        let record_a: Vec<EncryptedAttribute> = (0..na)
            .map(|j| EncryptedAttribute::from_value(attr_news[a_idx + j]))
            .collect();
        a_idx += na;
        new_items.push(EncryptedRecord::new(record_p, record_a));
    }
    new_items
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl crate::data::batch::EncryptedBatch<EncryptedRecord> {
    /// Internal helper: build the transcription proof and reassemble items
    /// from the given `gy`. Does not touch `self.public_key`.
    fn build_verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        gy: crate::arithmetic::group_elements::GroupElement,
        rng: &mut R,
    ) -> RecordTranscryptionBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::data::simple::ElGamalEncrypted;
        let structure: Vec<(usize, usize)> = self
            .items
            .iter()
            .map(|r| (r.pseudonyms.len(), r.attributes.len()))
            .collect();
        let pseudonym_originals: Vec<_> = self
            .items
            .iter()
            .flat_map(|r| r.pseudonyms.iter().map(|p| *p.value()))
            .collect();
        let attribute_originals: Vec<_> = self
            .items
            .iter()
            .flat_map(|r| r.attributes.iter().map(|a| *a.value()))
            .collect();
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
        let mut new_items = Vec::with_capacity(self.items.len());
        let mut p_idx = 0;
        let mut a_idx = 0;
        for &(np, na) in &structure {
            let record_p: Vec<_> = pseudonym_results[p_idx..p_idx + np]
                .iter()
                .map(|c| EncryptedPseudonym::from_value(*c))
                .collect();
            p_idx += np;
            let record_a: Vec<_> = attribute_results[a_idx..a_idx + na]
                .iter()
                .map(|c| EncryptedAttribute::from_value(*c))
                .collect();
            a_idx += na;
            new_items.push(EncryptedRecord::new(record_p, record_a));
        }
        self.items = new_items;
        RecordTranscryptionBatchProof {
            structure,
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
impl crate::data::batch::EncryptedBatch<EncryptedRecord> {
    /// Verifiably transcrypt the batch.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> RecordTranscryptionBatchProof
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
impl crate::data::batch::EncryptedBatch<EncryptedRecord> {
    /// Verifiably transcrypt the batch using a caller-supplied recipient key
    /// bundle.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::SessionKeys,
        rng: &mut R,
    ) -> RecordTranscryptionBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let gy = *public_key.pseudonym.public.value();
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable", feature = "elgamal3"))]
impl crate::data::batch::EncryptedBatch<EncryptedRecord> {
    /// Verifiably transcrypt the batch.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> RecordTranscryptionBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::data::simple::ElGamalEncrypted;
        let gy = self
            .items
            .iter()
            .find_map(|r| r.pseudonyms.first().map(|p| p.value().gy))
            .or_else(|| {
                self.items
                    .iter()
                    .find_map(|r| r.attributes.first().map(|a| a.value().gy))
            })
            .unwrap_or(crate::arithmetic::group_elements::G);
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}

/// Hoisted-proof bundle for a batch of [`LongEncryptedRecord`] values.
///
/// Like [`RecordTranscryptionBatchProof`] but pseudonyms and attributes
/// have a second-level structure (block counts per long value).
#[cfg(all(feature = "batch", feature = "verifiable", feature = "long"))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LongRecordTranscryptionBatchProof {
    /// Per-record block counts: `(pseudonym_block_counts, attribute_block_counts)`.
    pub structure: Vec<(Vec<usize>, Vec<usize>)>,
    pub pseudonyms: crate::core::verifiable::VerifiableRRSKBatch,
    pub attributes: crate::core::verifiable::VerifiableRekeyBatch,
}

#[cfg(all(feature = "batch", feature = "verifiable", feature = "long"))]
impl LongRecordTranscryptionBatchProof {
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        use crate::data::simple::ElGamalEncrypted;
        let structure = long_record_structure(&original.items);
        if structure != self.structure {
            return false;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.pseudonyms
                    .iter()
                    .flat_map(|lp| lp.0.iter().map(|b| *b.value()))
            })
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.attributes
                    .iter()
                    .flat_map(|la| la.0.iter().map(|b| *b.value()))
            })
            .collect();
        let gy = pseudonym_originals
            .first()
            .map(|c| c.gy)
            .unwrap_or(crate::arithmetic::group_elements::G);
        self.pseudonyms.verify(
            &pseudonym_originals,
            &gy,
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        ) && self
            .attributes
            .verify(&attribute_originals, &commitments.attribute.commitment)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> bool {
        use crate::data::simple::ElGamalEncrypted;
        use crate::keys::PublicKey as _;
        let structure = long_record_structure(&original.items);
        if structure != self.structure {
            return false;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.pseudonyms
                    .iter()
                    .flat_map(|lp| lp.0.iter().map(|b| *b.value()))
            })
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.attributes
                    .iter()
                    .flat_map(|la| la.0.iter().map(|b| *b.value()))
            })
            .collect();
        self.pseudonyms.verify(
            &pseudonym_originals,
            public_key.pseudonym.public.value(),
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        ) && self
            .attributes
            .verify(&attribute_originals, &commitments.attribute.commitment)
    }

    /// Verify and return reconstructed records as a flat `Vec<LongEncryptedRecord>`.
    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Vec<LongEncryptedRecord>> {
        use crate::data::simple::ElGamalEncrypted;
        let structure = long_record_structure(&original.items);
        if structure != self.structure {
            return None;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.pseudonyms
                    .iter()
                    .flat_map(|lp| lp.0.iter().map(|b| *b.value()))
            })
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.attributes
                    .iter()
                    .flat_map(|la| la.0.iter().map(|b| *b.value()))
            })
            .collect();
        let gy = pseudonym_originals
            .first()
            .map(|c| c.gy)
            .unwrap_or(crate::arithmetic::group_elements::G);
        let pseudo_news = self.pseudonyms.verified_reconstruct(
            &pseudonym_originals,
            &gy,
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        )?;
        let attr_news = self
            .attributes
            .verified_reconstruct(&attribute_originals, &commitments.attribute.commitment)?;
        Some(rebuild_long_records(&structure, &pseudo_news, &attr_news))
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<Vec<LongEncryptedRecord>> {
        use crate::data::simple::ElGamalEncrypted;
        use crate::keys::PublicKey as _;
        let structure = long_record_structure(&original.items);
        if structure != self.structure {
            return None;
        }
        let pseudonym_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.pseudonyms
                    .iter()
                    .flat_map(|lp| lp.0.iter().map(|b| *b.value()))
            })
            .collect();
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.attributes
                    .iter()
                    .flat_map(|la| la.0.iter().map(|b| *b.value()))
            })
            .collect();
        let pseudo_news = self.pseudonyms.verified_reconstruct(
            &pseudonym_originals,
            public_key.pseudonym.public.value(),
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        )?;
        let attr_news = self
            .attributes
            .verified_reconstruct(&attribute_originals, &commitments.attribute.commitment)?;
        Some(rebuild_long_records(&structure, &pseudo_news, &attr_news))
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
        public_key: &SessionKeys,
        new_public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedRecord>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedRecord>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
        public_key: &SessionKeys,
        commitments: &crate::factors::VerifiableTranscryptionCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedRecord>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the records **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedRecord>,
    ) -> Vec<LongEncryptedRecord> {
        use crate::data::simple::ElGamalEncrypted;
        let attribute_originals: Vec<_> = original
            .items
            .iter()
            .flat_map(|r| {
                r.attributes
                    .iter()
                    .flat_map(|la| la.0.iter().map(|b| *b.value()))
            })
            .collect();
        let pseudo_news = self.pseudonyms.result();
        let attr_news = self.attributes.result(&attribute_originals);
        rebuild_long_records(&self.structure, &pseudo_news, &attr_news)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable", feature = "long"))]
impl VerifiableTranscryptionProof for LongRecordTranscryptionBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<LongEncryptedRecord>;
    type Output = Vec<LongEncryptedRecord>;

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

#[cfg(all(feature = "batch", feature = "verifiable", feature = "long"))]
fn long_record_structure(items: &[LongEncryptedRecord]) -> Vec<(Vec<usize>, Vec<usize>)> {
    items
        .iter()
        .map(|r| {
            (
                r.pseudonyms.iter().map(|lp| lp.0.len()).collect(),
                r.attributes.iter().map(|la| la.0.len()).collect(),
            )
        })
        .collect()
}

#[cfg(all(feature = "batch", feature = "verifiable", feature = "long"))]
fn rebuild_long_records(
    structure: &[(Vec<usize>, Vec<usize>)],
    pseudo_news: &[crate::core::elgamal::ElGamal],
    attr_news: &[crate::core::elgamal::ElGamal],
) -> Vec<LongEncryptedRecord> {
    let mut new_items = Vec::with_capacity(structure.len());
    let mut p_idx = 0;
    let mut a_idx = 0;
    for (p_blocks_per_long, a_blocks_per_long) in structure {
        let mut record_p: Vec<LongEncryptedPseudonym> = Vec::with_capacity(p_blocks_per_long.len());
        for &n in p_blocks_per_long {
            let blocks: Vec<EncryptedPseudonym> = (0..n)
                .map(|j| EncryptedPseudonym::from_value(pseudo_news[p_idx + j]))
                .collect();
            p_idx += n;
            record_p.push(LongEncryptedPseudonym(blocks));
        }
        let mut record_a: Vec<LongEncryptedAttribute> = Vec::with_capacity(a_blocks_per_long.len());
        for &n in a_blocks_per_long {
            let blocks: Vec<EncryptedAttribute> = (0..n)
                .map(|j| EncryptedAttribute::from_value(attr_news[a_idx + j]))
                .collect();
            a_idx += n;
            record_a.push(LongEncryptedAttribute(blocks));
        }
        new_items.push(LongEncryptedRecord::new(record_p, record_a));
    }
    new_items
}

#[cfg(all(feature = "batch", feature = "verifiable", feature = "long"))]
impl crate::data::batch::EncryptedBatch<LongEncryptedRecord> {
    /// Internal helper: build the long-record transcription proof and
    /// reassemble items from the given `gy`. Does not touch
    /// `self.public_key`.
    fn build_verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        gy: crate::arithmetic::group_elements::GroupElement,
        rng: &mut R,
    ) -> LongRecordTranscryptionBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::data::simple::ElGamalEncrypted;
        let structure: Vec<(Vec<usize>, Vec<usize>)> = self
            .items
            .iter()
            .map(|r| {
                (
                    r.pseudonyms.iter().map(|lp| lp.0.len()).collect(),
                    r.attributes.iter().map(|la| la.0.len()).collect(),
                )
            })
            .collect();
        let pseudonym_originals: Vec<_> = self
            .items
            .iter()
            .flat_map(|r| {
                r.pseudonyms
                    .iter()
                    .flat_map(|lp| lp.0.iter().map(|b| *b.value()))
            })
            .collect();
        let attribute_originals: Vec<_> = self
            .items
            .iter()
            .flat_map(|r| {
                r.attributes
                    .iter()
                    .flat_map(|la| la.0.iter().map(|b| *b.value()))
            })
            .collect();
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
        let mut new_items = Vec::with_capacity(self.items.len());
        let mut p_idx = 0;
        let mut a_idx = 0;
        for (p_blocks_per_long, a_blocks_per_long) in &structure {
            let mut record_p: Vec<LongEncryptedPseudonym> =
                Vec::with_capacity(p_blocks_per_long.len());
            for &n in p_blocks_per_long {
                let blocks: Vec<EncryptedPseudonym> = pseudonym_results[p_idx..p_idx + n]
                    .iter()
                    .map(|c| EncryptedPseudonym::from_value(*c))
                    .collect();
                p_idx += n;
                record_p.push(LongEncryptedPseudonym(blocks));
            }
            let mut record_a: Vec<LongEncryptedAttribute> =
                Vec::with_capacity(a_blocks_per_long.len());
            for &n in a_blocks_per_long {
                let blocks: Vec<EncryptedAttribute> = attribute_results[a_idx..a_idx + n]
                    .iter()
                    .map(|c| EncryptedAttribute::from_value(*c))
                    .collect();
                a_idx += n;
                record_a.push(LongEncryptedAttribute(blocks));
            }
            new_items.push(LongEncryptedRecord::new(record_p, record_a));
        }
        self.items = new_items;
        LongRecordTranscryptionBatchProof {
            structure,
            pseudonyms,
            attributes,
        }
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    feature = "long",
    not(feature = "elgamal3"),
    feature = "batch-pk"
))]
impl crate::data::batch::EncryptedBatch<LongEncryptedRecord> {
    /// Verifiably transcrypt the batch.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> LongRecordTranscryptionBatchProof
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
    feature = "long",
    not(feature = "elgamal3"),
    not(feature = "batch-pk")
))]
impl crate::data::batch::EncryptedBatch<LongEncryptedRecord> {
    /// Verifiably transcrypt the batch using a caller-supplied recipient
    /// key bundle.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::SessionKeys,
        rng: &mut R,
    ) -> LongRecordTranscryptionBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let gy = *public_key.pseudonym.public.value();
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    feature = "long",
    feature = "elgamal3"
))]
impl crate::data::batch::EncryptedBatch<LongEncryptedRecord> {
    /// Verifiably transcrypt the batch.
    pub fn verifiable_transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        rng: &mut R,
    ) -> LongRecordTranscryptionBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::data::simple::ElGamalEncrypted;
        let gy = self
            .items
            .iter()
            .find_map(|r| {
                r.pseudonyms
                    .iter()
                    .find_map(|lp| lp.0.first().map(|b| b.value().gy))
            })
            .unwrap_or(crate::arithmetic::group_elements::G);
        self.build_verifiable_transcrypt(info, gy, rng)
    }
}
