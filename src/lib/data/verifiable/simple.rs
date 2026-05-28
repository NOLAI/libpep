//! Verifiable variants of the simple data-layer operations.
//!
//! Mirrors [`crate::data::simple`]: each non-verifiable operation
//! ([`Pseudonymizable`](crate::data::traits::Pseudonymizable),
//! [`Rekeyable`](crate::data::traits::Rekeyable)) has a verifiable
//! counterpart here that produces a data-layer proof wrapper around the
//! corresponding core ZKP.
//!
//! Each wrapper carries a core ZKP proof along with the data-type identity
//! of the operation it belongs to. Inherent methods (bare verb names)
//! provide the verifier-side API. The wrappers also implement the
//! appropriate `Verifiable*Proof` trait (rekey / pseudonymization) so
//! they work polymorphically with [`Verifier`](crate::verifier::Verifier).

use crate::arithmetic::scalars::ScalarNonZero;
use crate::data::simple::{ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable,
};
#[cfg(all(feature = "batch", not(feature = "elgamal3"), feature = "batch-pk"))]
use crate::keys::AttributeSessionPublicKey;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::PseudonymSessionPublicKey;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Proof of a verifiable pseudonymization of an [`EncryptedPseudonym`].
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymPseudonymizationProof(pub crate::core::verifiable::VerifiableRRSK);

impl PseudonymPseudonymizationProof {
    /// Verify the proof against the original ciphertext and commitments.
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &EncryptedPseudonym,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        self.0.verify(
            original.value(),
            &original.value().gy,
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verify(
        &self,
        original: &EncryptedPseudonym,
        public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        use crate::keys::PublicKey as _;
        self.0.verify(
            original.value(),
            public_key.value(),
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )
    }

    /// Verify the proof and return the reconstructed pseudonymized
    /// ciphertext.
    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedPseudonym,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<EncryptedPseudonym> {
        self.0
            .verified_reconstruct(
                original.value(),
                &original.value().gy,
                &commitments.reshuffle_commitment,
                &commitments.rekey_commitment,
            )
            .map(EncryptedPseudonym::from_value)
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &EncryptedPseudonym,
        public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<EncryptedPseudonym> {
        use crate::keys::PublicKey as _;
        self.0
            .verified_reconstruct(
                original.value(),
                public_key.value(),
                &commitments.reshuffle_commitment,
                &commitments.rekey_commitment,
            )
            .map(EncryptedPseudonym::from_value)
    }

    /// Reconstruct the pseudonymized ciphertext **without** verifying the
    /// proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self) -> EncryptedPseudonym {
        EncryptedPseudonym::from_value(self.0.unverified_reconstruct())
    }
}

impl VerifiablePseudonymizationProof for PseudonymPseudonymizationProof {
    type DataType = EncryptedPseudonym;
    type Output = EncryptedPseudonym;

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
        public_key: &PseudonymSessionPublicKey,
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
        public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, public_key, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, _original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct()
    }
}

/// Proof of a verifiable rekey of an [`EncryptedPseudonym`].
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymRekeyProof(pub crate::core::verifiable::VerifiableRekey);

impl PseudonymRekeyProof {
    pub fn verify(
        &self,
        original: &EncryptedPseudonym,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        self.0.verify(original.value(), &commitments.commitment)
    }

    pub fn verified_reconstruct(
        &self,
        original: &EncryptedPseudonym,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<EncryptedPseudonym> {
        self.0
            .verified_reconstruct(original.value(), &commitments.commitment)
            .map(EncryptedPseudonym::from_value)
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &EncryptedPseudonym) -> EncryptedPseudonym {
        EncryptedPseudonym::from_value(self.0.unverified_reconstruct(original.value()))
    }
}

impl VerifiableRekeyProof for PseudonymRekeyProof {
    type DataType = EncryptedPseudonym;
    type Output = EncryptedPseudonym;

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

/// Proof of a verifiable rekey of an [`EncryptedAttribute`].
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeRekeyProof(pub crate::core::verifiable::VerifiableRekey);

impl AttributeRekeyProof {
    pub fn verify(
        &self,
        original: &EncryptedAttribute,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        self.0.verify(original.value(), &commitments.commitment)
    }

    pub fn verified_reconstruct(
        &self,
        original: &EncryptedAttribute,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<EncryptedAttribute> {
        self.0
            .verified_reconstruct(original.value(), &commitments.commitment)
            .map(EncryptedAttribute::from_value)
    }

    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(&self, original: &EncryptedAttribute) -> EncryptedAttribute {
        EncryptedAttribute::from_value(self.0.unverified_reconstruct(original.value()))
    }
}

impl VerifiableRekeyProof for AttributeRekeyProof {
    type DataType = EncryptedAttribute;
    type Output = EncryptedAttribute;

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

impl VerifiablePseudonymizable for EncryptedPseudonym {
    type PseudonymizationProof = PseudonymPseudonymizationProof;

    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize<R>(
        &self,
        info: &crate::factors::PseudonymizationInfo,
        rng: &mut R,
    ) -> Self::PseudonymizationProof
    where
        R: Rng + CryptoRng,
    {
        let r = ScalarNonZero::random(rng);
        PseudonymPseudonymizationProof(crate::core::verifiable::VerifiableRRSK::new(
            self.value(),
            &self.value().gy,
            &r,
            &info.s.0,
            &info.k.0,
            rng,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_pseudonymize<R>(
        &self,
        info: &crate::factors::PseudonymizationInfo,
        public_key: &PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> Self::PseudonymizationProof
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let r = ScalarNonZero::random(rng);
        PseudonymPseudonymizationProof(crate::core::verifiable::VerifiableRRSK::new(
            self.value(),
            public_key.value(),
            &r,
            &info.s.0,
            &info.k.0,
            rng,
        ))
    }
}

impl VerifiableRekeyable for EncryptedPseudonym {
    type RekeyProof = PseudonymRekeyProof;

    fn verifiable_rekey<R: Rng + CryptoRng>(
        &self,
        info: &Self::RekeyInfo,
        rng: &mut R,
    ) -> Self::RekeyProof {
        PseudonymRekeyProof(crate::core::verifiable::VerifiableRekey::new(
            self.value(),
            &info.0,
            rng,
        ))
    }
}

impl VerifiableRekeyable for EncryptedAttribute {
    type RekeyProof = AttributeRekeyProof;

    fn verifiable_rekey<R: Rng + CryptoRng>(
        &self,
        info: &Self::RekeyInfo,
        rng: &mut R,
    ) -> Self::RekeyProof {
        AttributeRekeyProof(crate::core::verifiable::VerifiableRekey::new(
            self.value(),
            &info.0,
            rng,
        ))
    }
}

/// Proof of a verifiable batch pseudonymization of an
/// `EncryptedBatch<EncryptedPseudonym>`.
#[cfg(feature = "batch")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymPseudonymizationBatchProof(pub crate::core::verifiable::VerifiableRRSKBatch);

#[cfg(feature = "batch")]
impl PseudonymPseudonymizationBatchProof {
    /// Verify the proof against the original batch and commitments.
    #[cfg(feature = "elgamal3")]
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
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
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> bool {
        use crate::keys::PublicKey as _;
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0.verify(
            &originals,
            public_key.value(),
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )
    }

    /// Verify the proof and return the reconstructed items as a raw `Vec`.
    /// Under `(batch-pk, not elgamal3)`, use
    /// [`verified_reconstruct_batch`](Self::verified_reconstruct_batch) if
    /// you want a fully labelled `EncryptedBatch` back.
    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Vec<EncryptedPseudonym>> {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        let gy = crate::data::verifiable::shared_gy(&originals)?;
        self.0
            .verified_reconstruct(
                &originals,
                &gy,
                &commitments.reshuffle_commitment,
                &commitments.rekey_commitment,
            )
            .map(|news| {
                news.into_iter()
                    .map(EncryptedPseudonym::from_value)
                    .collect()
            })
    }

    #[cfg(not(feature = "elgamal3"))]
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Vec<EncryptedPseudonym>> {
        use crate::keys::PublicKey as _;
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0
            .verified_reconstruct(
                &originals,
                public_key.value(),
                &commitments.reshuffle_commitment,
                &commitments.rekey_commitment,
            )
            .map(|news| {
                news.into_iter()
                    .map(EncryptedPseudonym::from_value)
                    .collect()
            })
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        public_key: &PseudonymSessionPublicKey,
        new_public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    /// Verify and return the reconstructed batch. Available under
    /// `elgamal3` and `(not batch-pk, not elgamal3)`.
    #[cfg(feature = "elgamal3")]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, public_key, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the items **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
    ) -> Vec<EncryptedPseudonym> {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0
            .unverified_reconstruct(&originals)
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect()
    }
}

#[cfg(feature = "batch")]
impl VerifiablePseudonymizationProof for PseudonymPseudonymizationBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<EncryptedPseudonym>;
    type Output = Vec<EncryptedPseudonym>;

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
        public_key: &PseudonymSessionPublicKey,
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
        public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiablePseudonymizationCommitment,
    ) -> Option<Self::Output> {
        self.verified_reconstruct(original, public_key, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        self.unverified_reconstruct(original)
    }
}

/// Proof of a verifiable batch rekey of an `EncryptedBatch<EncryptedPseudonym>`.
#[cfg(feature = "batch")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct PseudonymRekeyBatchProof(pub crate::core::verifiable::VerifiableRekeyBatch);

#[cfg(feature = "batch")]
impl PseudonymRekeyBatchProof {
    /// Verify the proof against the original batch and commitments.
    /// Rekey verification doesn't need a recipient pk.
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0.verify(&originals, &commitments.commitment)
    }

    /// Verify the proof and return the reconstructed items as a raw `Vec`.
    /// Use [`verified_reconstruct_batch`](Self::verified_reconstruct_batch)
    /// for a fully labelled `EncryptedBatch`.
    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Vec<EncryptedPseudonym>> {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0
            .verified_reconstruct(&originals, &commitments.commitment)
            .map(|news| {
                news.into_iter()
                    .map(EncryptedPseudonym::from_value)
                    .collect()
            })
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        new_public_key: &PseudonymSessionPublicKey,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    /// Verify and return the reconstructed batch.
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedPseudonym>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the items **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedPseudonym>,
    ) -> Vec<EncryptedPseudonym> {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0
            .unverified_reconstruct(&originals)
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect()
    }
}

#[cfg(feature = "batch")]
impl VerifiableRekeyProof for PseudonymRekeyBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<EncryptedPseudonym>;
    type Output = Vec<EncryptedPseudonym>;

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

/// Proof of a verifiable batch rekey of an `EncryptedBatch<EncryptedAttribute>`.
#[cfg(feature = "batch")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct AttributeRekeyBatchProof(pub crate::core::verifiable::VerifiableRekeyBatch);

#[cfg(feature = "batch")]
impl AttributeRekeyBatchProof {
    pub fn verify(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedAttribute>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> bool {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0.verify(&originals, &commitments.commitment)
    }

    pub fn verified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedAttribute>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<Vec<EncryptedAttribute>> {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0
            .verified_reconstruct(&originals, &commitments.commitment)
            .map(|news| {
                news.into_iter()
                    .map(EncryptedAttribute::from_value)
                    .collect()
            })
    }

    /// Verify and return the reconstructed batch labelled with `new_public_key`.
    /// Available only under `(batch-pk, not elgamal3)`.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedAttribute>,
        new_public_key: &AttributeSessionPublicKey,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedAttribute>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch {
            public_key: *new_public_key,
            items,
        })
    }

    /// Verify and return the reconstructed batch.
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedAttribute>,
        commitments: &crate::factors::VerifiableRekeyCommitment,
    ) -> Option<crate::data::batch::EncryptedBatch<EncryptedAttribute>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(crate::data::batch::EncryptedBatch { items })
    }

    /// Reconstruct the items **without** verifying the proof.
    #[cfg(feature = "insecure")]
    pub fn unverified_reconstruct(
        &self,
        original: &crate::data::batch::EncryptedBatch<EncryptedAttribute>,
    ) -> Vec<EncryptedAttribute> {
        let originals: Vec<_> = original.items.iter().map(|e| *e.value()).collect();
        self.0
            .unverified_reconstruct(&originals)
            .into_iter()
            .map(EncryptedAttribute::from_value)
            .collect()
    }
}

#[cfg(feature = "batch")]
impl VerifiableRekeyProof for AttributeRekeyBatchProof {
    type DataType = crate::data::batch::EncryptedBatch<EncryptedAttribute>;
    type Output = Vec<EncryptedAttribute>;

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

// `verifiable_pseudonymize` builds a VRRSK proof, which needs `gy`. Source:
// `elgamal3` reads it from items; `(batch-pk, not elgamal3)` reads it from
// `self.public_key`; `(not batch-pk, not elgamal3)` takes pk as a parameter.
#[cfg(all(feature = "batch", not(feature = "elgamal3"), feature = "batch-pk"))]
impl crate::data::batch::EncryptedBatch<EncryptedPseudonym> {
    /// Verifiably pseudonymize the batch and return a hoisted
    /// [`PseudonymPseudonymizationBatchProof`].
    ///
    /// Unlike the non-verifiable [`pseudonymize`](Self::pseudonymize), the
    /// order of items is preserved: proof entries are positionally tied to
    /// the input items, so shuffling would invalidate verification.
    pub fn verifiable_pseudonymize<R>(
        &mut self,
        info: &crate::factors::PseudonymizationInfo,
        rng: &mut R,
    ) -> PseudonymPseudonymizationBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let gy = *self.public_key.value();
        let proof = crate::core::verifiable::VerifiableRRSKBatch::new(
            &originals, &gy, &info.s.0, &info.k.0, rng,
        );
        self.items = proof
            .result()
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect();
        self.public_key = self.public_key.convert(&info.k);
        PseudonymPseudonymizationBatchProof(proof)
    }

    /// Verifiably rekey the batch and return a
    /// [`PseudonymRekeyBatchProof`].
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::PseudonymRekeyInfo,
        rng: &mut R,
    ) -> PseudonymRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = proof
            .result(&originals)
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect();
        self.public_key = self.public_key.convert(info);
        PseudonymRekeyBatchProof(proof)
    }
}

#[cfg(all(
    feature = "batch",
    not(feature = "elgamal3"),
    not(feature = "batch-pk")
))]
impl crate::data::batch::EncryptedBatch<EncryptedPseudonym> {
    /// Verifiably pseudonymize the batch using a caller-supplied recipient
    /// public key and return a hoisted
    /// [`PseudonymPseudonymizationBatchProof`].
    pub fn verifiable_pseudonymize<R>(
        &mut self,
        info: &crate::factors::PseudonymizationInfo,
        public_key: &PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> PseudonymPseudonymizationBatchProof
    where
        R: Rng + CryptoRng,
    {
        use crate::keys::PublicKey as _;
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let gy = *public_key.value();
        let proof = crate::core::verifiable::VerifiableRRSKBatch::new(
            &originals, &gy, &info.s.0, &info.k.0, rng,
        );
        self.items = proof
            .result()
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect();
        PseudonymPseudonymizationBatchProof(proof)
    }

    /// Verifiably rekey the batch and return a [`PseudonymRekeyBatchProof`].
    /// No pk is needed for the rekey itself.
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::PseudonymRekeyInfo,
        rng: &mut R,
    ) -> PseudonymRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = proof
            .result(&originals)
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect();
        PseudonymRekeyBatchProof(proof)
    }
}

#[cfg(all(feature = "batch", feature = "elgamal3"))]
impl crate::data::batch::EncryptedBatch<EncryptedPseudonym> {
    /// Verifiably pseudonymize the batch and return a hoisted
    /// [`PseudonymPseudonymizationBatchProof`].
    pub fn verifiable_pseudonymize<R>(
        &mut self,
        info: &crate::factors::PseudonymizationInfo,
        rng: &mut R,
    ) -> PseudonymPseudonymizationBatchProof
    where
        R: Rng + CryptoRng,
    {
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let gy = self
            .items
            .first()
            .map(|e| e.value().gy)
            .unwrap_or(crate::arithmetic::group_elements::G);
        let proof = crate::core::verifiable::VerifiableRRSKBatch::new(
            &originals, &gy, &info.s.0, &info.k.0, rng,
        );
        self.items = proof
            .result()
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect();
        PseudonymPseudonymizationBatchProof(proof)
    }

    /// Verifiably rekey the batch and return a [`PseudonymRekeyBatchProof`].
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::PseudonymRekeyInfo,
        rng: &mut R,
    ) -> PseudonymRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = proof
            .result(&originals)
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect();
        PseudonymRekeyBatchProof(proof)
    }
}

// Attributes: only `verifiable_rekey`, no pk needed for the crypto itself —
// only the pk-update side-effect differs by cfg.

#[cfg(all(feature = "batch", not(feature = "elgamal3"), feature = "batch-pk"))]
impl crate::data::batch::EncryptedBatch<EncryptedAttribute> {
    /// Verifiably rekey the batch and return an [`AttributeRekeyBatchProof`].
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::AttributeRekeyInfo,
        rng: &mut R,
    ) -> AttributeRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = proof
            .result(&originals)
            .into_iter()
            .map(EncryptedAttribute::from_value)
            .collect();
        self.public_key = self.public_key.convert(info);
        AttributeRekeyBatchProof(proof)
    }
}

#[cfg(all(
    feature = "batch",
    any(feature = "elgamal3", not(feature = "batch-pk"))
))]
impl crate::data::batch::EncryptedBatch<EncryptedAttribute> {
    /// Verifiably rekey the batch and return an [`AttributeRekeyBatchProof`].
    pub fn verifiable_rekey<R>(
        &mut self,
        info: &crate::factors::AttributeRekeyInfo,
        rng: &mut R,
    ) -> AttributeRekeyBatchProof
    where
        R: Rng + CryptoRng,
    {
        let originals: Vec<_> = self.items.iter().map(|e| *e.value()).collect();
        let proof = crate::core::verifiable::VerifiableRekeyBatch::new(&originals, &info.0, rng);
        self.items = proof
            .result(&originals)
            .into_iter()
            .map(EncryptedAttribute::from_value)
            .collect();
        AttributeRekeyBatchProof(proof)
    }
}
