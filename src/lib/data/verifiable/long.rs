//! Verifiable variants of the long data-layer operations.
//!
//! Mirrors [`crate::data::long`].

use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "elgamal3")]
use crate::data::simple::ElGamalEncrypted;
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable,
};
use rand_core::{CryptoRng, Rng};

/// Proof of a verifiable pseudonymization of a [`LongEncryptedPseudonym`].
#[cfg(feature = "verifiable")]
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct LongPseudonymPseudonymizationProof(
    pub Vec<crate::data::verifiable::simple::PseudonymPseudonymizationProof>,
);

#[cfg(feature = "verifiable")]
impl LongPseudonymPseudonymizationProof {
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &LongEncryptedPseudonym,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        if self.0.len() != original.0.len() {
            return false;
        }
        self.0
            .iter()
            .zip(original.0.iter())
            .all(|(p, block)| p.verify(block, commitments))
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &LongEncryptedPseudonym,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        if self.0.len() != original.0.len() {
            return false;
        }
        self.0
            .iter()
            .zip(original.0.iter())
            .all(|(p, block)| p.verify(block, public_key, commitments))
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &LongEncryptedPseudonym,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<LongEncryptedPseudonym> {
        if self.0.len() != original.0.len() {
            return None;
        }
        let blocks: Option<Vec<_>> = self
            .0
            .iter()
            .zip(original.0.iter())
            .map(|(p, block)| p.verified_reconstruct(block, commitments))
            .collect();
        blocks.map(LongEncryptedPseudonym)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &LongEncryptedPseudonym,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<LongEncryptedPseudonym> {
        if self.0.len() != original.0.len() {
            return None;
        }
        let blocks: Option<Vec<_>> = self
            .0
            .iter()
            .zip(original.0.iter())
            .map(|(p, block)| p.verified_reconstruct(block, public_key, commitments))
            .collect();
        blocks.map(LongEncryptedPseudonym)
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self) -> LongEncryptedPseudonym {
        LongEncryptedPseudonym(self.0.iter().map(|p| p.unverified_reconstruct()).collect())
    }
}

#[cfg(feature = "verifiable")]
impl VerifiablePseudonymizationProof for LongPseudonymPseudonymizationProof {
    type DataType = LongEncryptedPseudonym;
    type Output = LongEncryptedPseudonym;

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        self.verify(original, commitments)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        self.verify(original, public_key, commitments)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, commitments)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, public_key, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, _original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct()
    }
}

/// Proof of a verifiable rekey of a [`LongEncryptedPseudonym`].
#[cfg(feature = "verifiable")]
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct LongPseudonymRekeyProof(pub Vec<crate::data::verifiable::simple::PseudonymRekeyProof>);

#[cfg(feature = "verifiable")]
impl LongPseudonymRekeyProof {
    pub fn verify(
        &self,
        original: &LongEncryptedPseudonym,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        if self.0.len() != original.0.len() {
            return false;
        }
        self.0
            .iter()
            .zip(original.0.iter())
            .all(|(p, block)| p.verify(block, commitments))
    }

    pub fn verified_reconstruct(
        &self,
        original: &LongEncryptedPseudonym,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<LongEncryptedPseudonym> {
        if self.0.len() != original.0.len() {
            return None;
        }
        let blocks: Option<Vec<_>> = self
            .0
            .iter()
            .zip(original.0.iter())
            .map(|(p, block)| p.verified_reconstruct(block, commitments))
            .collect();
        blocks.map(LongEncryptedPseudonym)
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &LongEncryptedPseudonym,
    ) -> LongEncryptedPseudonym {
        LongEncryptedPseudonym(
            self.0
                .iter()
                .zip(original.0.iter())
                .map(|(p, block)| p.unverified_reconstruct(block))
                .collect(),
        )
    }
}

#[cfg(feature = "verifiable")]
impl VerifiableRekeyProof for LongPseudonymRekeyProof {
    type DataType = LongEncryptedPseudonym;
    type Output = LongEncryptedPseudonym;

    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        self.verify(original, commitments)
    }

    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

/// Proof of a verifiable rekey of a [`LongEncryptedAttribute`].
#[cfg(feature = "verifiable")]
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct LongAttributeRekeyProof(pub Vec<crate::data::verifiable::simple::AttributeRekeyProof>);

#[cfg(feature = "verifiable")]
impl LongAttributeRekeyProof {
    pub fn verify(
        &self,
        original: &LongEncryptedAttribute,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        if self.0.len() != original.0.len() {
            return false;
        }
        self.0
            .iter()
            .zip(original.0.iter())
            .all(|(p, block)| p.verify(block, commitments))
    }

    pub fn verified_reconstruct(
        &self,
        original: &LongEncryptedAttribute,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<LongEncryptedAttribute> {
        if self.0.len() != original.0.len() {
            return None;
        }
        let blocks: Option<Vec<_>> = self
            .0
            .iter()
            .zip(original.0.iter())
            .map(|(p, block)| p.verified_reconstruct(block, commitments))
            .collect();
        blocks.map(LongEncryptedAttribute)
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &LongEncryptedAttribute,
    ) -> LongEncryptedAttribute {
        LongEncryptedAttribute(
            self.0
                .iter()
                .zip(original.0.iter())
                .map(|(p, block)| p.unverified_reconstruct(block))
                .collect(),
        )
    }
}

#[cfg(feature = "verifiable")]
impl VerifiableRekeyProof for LongAttributeRekeyProof {
    type DataType = LongEncryptedAttribute;
    type Output = LongEncryptedAttribute;

    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        self.verify(original, commitments)
    }

    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

#[cfg(feature = "verifiable")]
impl VerifiablePseudonymizable for LongEncryptedPseudonym {
    type PseudonymizationProof = LongPseudonymPseudonymizationProof;

    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize<R>(
        &self,
        info: &crate::factors::PseudonymizationInfo,
        rng: &mut R,
    ) -> Self::PseudonymizationProof
    where
        R: Rng + CryptoRng,
    {
        LongPseudonymPseudonymizationProof(
            self.0
                .iter()
                .map(|block| block.verifiable_pseudonymize(info, rng))
                .collect(),
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_pseudonymize<R>(
        &self,
        info: &crate::factors::PseudonymizationInfo,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> Self::PseudonymizationProof
    where
        R: Rng + CryptoRng,
    {
        LongPseudonymPseudonymizationProof(
            self.0
                .iter()
                .map(|block| block.verifiable_pseudonymize(info, public_key, rng))
                .collect(),
        )
    }
}

#[cfg(feature = "verifiable")]
impl VerifiableRekeyable for LongEncryptedPseudonym {
    type RekeyProof = LongPseudonymRekeyProof;

    fn verifiable_rekey<R: Rng + CryptoRng>(
        &self,
        info: &Self::RekeyInfo,
        rng: &mut R,
    ) -> Self::RekeyProof {
        LongPseudonymRekeyProof(
            self.0
                .iter()
                .map(|block| block.verifiable_rekey(info, rng))
                .collect(),
        )
    }
}

#[cfg(feature = "verifiable")]
impl VerifiableRekeyable for LongEncryptedAttribute {
    type RekeyProof = LongAttributeRekeyProof;

    fn verifiable_rekey<R: Rng + CryptoRng>(
        &self,
        info: &Self::RekeyInfo,
        rng: &mut R,
    ) -> Self::RekeyProof {
        LongAttributeRekeyProof(
            self.0
                .iter()
                .map(|block| block.verifiable_rekey(info, rng))
                .collect(),
        )
    }
}
/// Proof of a verifiable batch pseudonymization of an
/// `EncryptedBatch<LongEncryptedPseudonym>`.
#[cfg(all(feature = "batch", feature = "verifiable"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct LongPseudonymPseudonymizationBatchProof(
    pub crate::core::verifiable::VerifiableRRSKBatch,
);

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl LongPseudonymPseudonymizationBatchProof {
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        let (_, originals) = flatten_long_pseudonyms(&original.items);
        let Some(gy) = crate::data::verifiable::shared_gy(&originals) else {
            return false;
        };
        self.0.verify(
            &originals,
            &gy,
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        use crate::keys::PublicKey as _;
        let (_, originals) = flatten_long_pseudonyms(&original.items);
        self.0.verify(
            &originals,
            public_key.value(),
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )
    }

    /// Verify and return reconstructed items as a flat `Vec<LongEncryptedPseudonym>`.
    /// Under `batch-pk`, use
    /// [`verified_reconstruct_batch`](Self::verified_reconstruct_batch) for
    /// a labelled `EncryptedBatch`.
    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Vec<LongEncryptedPseudonym>> {
        let (block_counts, originals) = flatten_long_pseudonyms(&original.items);
        let gy = crate::data::verifiable::shared_gy(&originals)?;
        let _ = self.0.verified_reconstruct(
            &originals,
            &gy,
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )?;
        Some(rebuild_long_pseudonyms_from_rrsk(&block_counts, &self.0))
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Vec<LongEncryptedPseudonym>> {
        use crate::keys::PublicKey as _;
        let (block_counts, originals) = flatten_long_pseudonyms(&original.items);
        let _ = self.0.verified_reconstruct(
            &originals,
            public_key.value(),
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )?;
        Some(rebuild_long_pseudonyms_from_rrsk(&block_counts, &self.0))
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        new_public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the items **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
    ) -> Vec<LongEncryptedPseudonym> {
        let (block_counts, _) = flatten_long_pseudonyms(&original.items);
        rebuild_long_pseudonyms_from_rrsk(&block_counts, &self.0)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl VerifiablePseudonymizationProof for LongPseudonymPseudonymizationBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>;
    type Output = Vec<LongEncryptedPseudonym>;

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        self.verify(original, commitments)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        self.verify(original, public_key, commitments)
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, commitments)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, public_key, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

/// Proof of a verifiable batch rekey of an
/// `EncryptedBatch<LongEncryptedPseudonym>`.
#[cfg(all(feature = "batch", feature = "verifiable"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct LongPseudonymRekeyBatchProof(pub crate::core::verifiable::VerifiableRekeyBatch);

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl LongPseudonymRekeyBatchProof {
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        let (_, originals) = flatten_long_pseudonyms(&original.items);
        self.0.verify(&originals, &commitments.commitment)
    }

    /// Verify and return reconstructed items as a flat
    /// `Vec<LongEncryptedPseudonym>`. Under `batch-pk`, use
    /// [`verified_reconstruct_batch`](Self::verified_reconstruct_batch) for
    /// a labelled `EncryptedBatch`.
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Vec<LongEncryptedPseudonym>> {
        let (block_counts, originals) = flatten_long_pseudonyms(&original.items);
        let _ = self
            .0
            .verified_reconstruct(&originals, &commitments.commitment)?;
        Some(rebuild_long_pseudonyms_from_rekey(
            &block_counts,
            &originals,
            &self.0.inners,
        ))
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        new_public_key: &crate::keys::PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the items **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>,
    ) -> Vec<LongEncryptedPseudonym> {
        let (block_counts, originals) = flatten_long_pseudonyms(&original.items);
        rebuild_long_pseudonyms_from_rekey(&block_counts, &originals, &self.0.inners)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl VerifiableRekeyProof for LongPseudonymRekeyBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<LongEncryptedPseudonym>;
    type Output = Vec<LongEncryptedPseudonym>;

    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        self.verify(original, commitments)
    }

    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

/// Proof of a verifiable batch rekey of an
/// `EncryptedBatch<LongEncryptedAttribute>`.
#[cfg(all(feature = "batch", feature = "verifiable"))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct LongAttributeRekeyBatchProof(pub crate::core::verifiable::VerifiableRekeyBatch);

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl LongAttributeRekeyBatchProof {
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedAttribute>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        let (_, originals) = flatten_long_attributes(&original.items);
        self.0.verify(&originals, &commitments.commitment)
    }

    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedAttribute>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Vec<LongEncryptedAttribute>> {
        let (block_counts, originals) = flatten_long_attributes(&original.items);
        let _ = self
            .0
            .verified_reconstruct(&originals, &commitments.commitment)?;
        Some(rebuild_long_attributes_from_rekey(
            &block_counts,
            &originals,
            &self.0.inners,
        ))
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedAttribute>,
        new_public_key: &crate::keys::AttributeSessionPublicKey,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedAttribute>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedAttribute>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<LongEncryptedAttribute>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the items **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<LongEncryptedAttribute>,
    ) -> Vec<LongEncryptedAttribute> {
        let (block_counts, originals) = flatten_long_attributes(&original.items);
        rebuild_long_attributes_from_rekey(&block_counts, &originals, &self.0.inners)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
impl VerifiableRekeyProof for LongAttributeRekeyBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<LongEncryptedAttribute>;
    type Output = Vec<LongEncryptedAttribute>;

    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        self.verify(original, commitments)
    }

    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    not(feature = "elgamal3"),
    feature = "batch-pk"
))]
impl crate::data::batch::EncryptedBatch<LongEncryptedPseudonym> {
    /// Verifiably pseudonymize the batch and return a hoisted
    /// [`LongPseudonymPseudonymizationBatchProof`].
    pub fn verifiable_pseudonymize<R>(
        &mut self,
        info: &crate::factors::PseudonymizationInfo,
        rng: &mut R,
    ) -> LongPseudonymPseudonymizationBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let (block_counts, originals) = flatten_long_pseudonyms(&self.items);
        let gy = *self.public_key.value();
        let proof = crate::core::verifiable::VerifiableRRSKBatch::new(
            &originals, &gy, &info.s.0, &info.k.0, rng,
        );
        self.items = rebuild_long_pseudonyms_from_rrsk(&block_counts, &proof);
        self.public_key = self.public_key.convert(&info.k);
        LongPseudonymPseudonymizationBatchProof(proof)
    }

    /// Verifiably rekey the batch.
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::PseudonymRekeyInfo,
        rng: &mut R,
    ) -> LongPseudonymRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let (block_counts, originals) = flatten_long_pseudonyms(&self.items);
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = rebuild_long_pseudonyms_from_rekey(&block_counts, &originals, &proof.inners);
        self.public_key = self.public_key.convert(info);
        LongPseudonymRekeyBatchProof(proof)
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    not(feature = "elgamal3"),
    not(feature = "batch-pk")
))]
impl crate::data::batch::EncryptedBatch<LongEncryptedPseudonym> {
    /// Verifiably pseudonymize the batch using a caller-supplied recipient
    /// public key.
    pub fn verifiable_pseudonymize<R>(
        &mut self,
        info: &crate::factors::PseudonymizationInfo,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> LongPseudonymPseudonymizationBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let (block_counts, originals) = flatten_long_pseudonyms(&self.items);
        let gy = *public_key.value();
        let proof = crate::core::verifiable::VerifiableRRSKBatch::new(
            &originals, &gy, &info.s.0, &info.k.0, rng,
        );
        self.items = rebuild_long_pseudonyms_from_rrsk(&block_counts, &proof);
        LongPseudonymPseudonymizationBatchProof(proof)
    }

    /// Verifiably rekey the batch.
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::PseudonymRekeyInfo,
        rng: &mut R,
    ) -> LongPseudonymRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let (block_counts, originals) = flatten_long_pseudonyms(&self.items);
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = rebuild_long_pseudonyms_from_rekey(&block_counts, &originals, &proof.inners);
        LongPseudonymRekeyBatchProof(proof)
    }
}

#[cfg(all(feature = "batch", feature = "verifiable", feature = "elgamal3"))]
impl crate::data::batch::EncryptedBatch<LongEncryptedPseudonym> {
    /// Verifiably pseudonymize the batch and return a hoisted
    /// [`LongPseudonymPseudonymizationBatchProof`].
    pub fn verifiable_pseudonymize<R>(
        &mut self,
        info: &crate::factors::PseudonymizationInfo,
        rng: &mut R,
    ) -> LongPseudonymPseudonymizationBatchProof
    where
        R: Rng + CryptoRng,
    {
        let (block_counts, originals) = flatten_long_pseudonyms(&self.items);
        let gy = self
            .items
            .first()
            .and_then(|long| long.0.first())
            .map(|block| block.value().gy)
            .unwrap_or(crate::arithmetic::group_elements::G);
        let proof = crate::core::verifiable::VerifiableRRSKBatch::new(
            &originals, &gy, &info.s.0, &info.k.0, rng,
        );
        self.items = rebuild_long_pseudonyms_from_rrsk(&block_counts, &proof);
        LongPseudonymPseudonymizationBatchProof(proof)
    }

    /// Verifiably rekey the batch.
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::PseudonymRekeyInfo,
        rng: &mut R,
    ) -> LongPseudonymRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let (block_counts, originals) = flatten_long_pseudonyms(&self.items);
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = rebuild_long_pseudonyms_from_rekey(&block_counts, &originals, &proof.inners);
        LongPseudonymRekeyBatchProof(proof)
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    not(feature = "elgamal3"),
    feature = "batch-pk"
))]
impl crate::data::batch::EncryptedBatch<LongEncryptedAttribute> {
    /// Verifiably rekey the batch.
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::AttributeRekeyInfo,
        rng: &mut R,
    ) -> LongAttributeRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let (block_counts, originals) = flatten_long_attributes(&self.items);
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = rebuild_long_attributes_from_rekey(&block_counts, &originals, &proof.inners);
        self.public_key = self.public_key.convert(info);
        LongAttributeRekeyBatchProof(proof)
    }
}

#[cfg(all(
    feature = "batch",
    feature = "verifiable",
    any(feature = "elgamal3", not(feature = "batch-pk"))
))]
impl crate::data::batch::EncryptedBatch<LongEncryptedAttribute> {
    /// Verifiably rekey the batch.
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::AttributeRekeyInfo,
        rng: &mut R,
    ) -> LongAttributeRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let (block_counts, originals) = flatten_long_attributes(&self.items);
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = rebuild_long_attributes_from_rekey(&block_counts, &originals, &proof.inners);
        LongAttributeRekeyBatchProof(proof)
    }
}
#[cfg(all(feature = "batch", feature = "verifiable"))]
pub(crate) fn flatten_long_pseudonyms(
    items: &[LongEncryptedPseudonym],
) -> (Vec<usize>, Vec<crate::core::elgamal::ElGamal>) {
    use crate::data::simple::ElGamalEncrypted;
    let counts = items.iter().map(|x| x.0.len()).collect();
    let flat = items
        .iter()
        .flat_map(|x| x.0.iter().map(|b| *b.value()))
        .collect();
    (counts, flat)
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
pub(crate) fn flatten_long_attributes(
    items: &[LongEncryptedAttribute],
) -> (Vec<usize>, Vec<crate::core::elgamal::ElGamal>) {
    use crate::data::simple::ElGamalEncrypted;
    let counts = items.iter().map(|x| x.0.len()).collect();
    let flat = items
        .iter()
        .flat_map(|x| x.0.iter().map(|b| *b.value()))
        .collect();
    (counts, flat)
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
fn rebuild_long_pseudonyms_from_rrsk(
    counts: &[usize],
    proof: &crate::core::verifiable::VerifiableRRSKBatch,
) -> Vec<LongEncryptedPseudonym> {
    use crate::data::simple::ElGamalEncrypted;
    let flat = proof.result();
    let mut out = Vec::with_capacity(counts.len());
    let mut idx = 0;
    for &n in counts {
        let blocks: Vec<crate::data::simple::EncryptedPseudonym> = flat[idx..idx + n]
            .iter()
            .map(|c| crate::data::simple::EncryptedPseudonym::from_value(*c))
            .collect();
        out.push(LongEncryptedPseudonym(blocks));
        idx += n;
    }
    out
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
fn rebuild_long_pseudonyms_from_rekey(
    counts: &[usize],
    originals: &[crate::core::elgamal::ElGamal],
    inners: &[crate::core::verifiable::VerifiableRekey],
) -> Vec<LongEncryptedPseudonym> {
    use crate::data::simple::ElGamalEncrypted;
    let mut out = Vec::with_capacity(counts.len());
    let mut idx = 0;
    for &n in counts {
        let blocks: Vec<crate::data::simple::EncryptedPseudonym> = (0..n)
            .map(|j| {
                crate::data::simple::EncryptedPseudonym::from_value(
                    inners[idx + j].result(&originals[idx + j]),
                )
            })
            .collect();
        out.push(LongEncryptedPseudonym(blocks));
        idx += n;
    }
    out
}

#[cfg(all(feature = "batch", feature = "verifiable"))]
fn rebuild_long_attributes_from_rekey(
    counts: &[usize],
    originals: &[crate::core::elgamal::ElGamal],
    inners: &[crate::core::verifiable::VerifiableRekey],
) -> Vec<LongEncryptedAttribute> {
    use crate::data::simple::ElGamalEncrypted;
    let mut out = Vec::with_capacity(counts.len());
    let mut idx = 0;
    for &n in counts {
        let blocks: Vec<crate::data::simple::EncryptedAttribute> = (0..n)
            .map(|j| {
                crate::data::simple::EncryptedAttribute::from_value(
                    inners[idx + j].result(&originals[idx + j]),
                )
            })
            .collect();
        out.push(LongEncryptedAttribute(blocks));
        idx += n;
    }
    out
}
