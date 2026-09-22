//! Batch operations for pseudonymization, rekeying, and transcryption.
//!
//! The operation methods live on [`EncryptedBatch`] itself, as concrete impls
//! per encrypted type. Each impl shuffles the items, transforms them, and (in
//! `elgamal2` mode) converts the stored recipient public key with the
//! corresponding rekey factor so the batch stays self-describing as it flows
//! downstream.
//!
//! No trait abstraction is used here — the impls are short and the set of
//! encrypted types that participate in batches is fixed (simple/long
//! pseudonyms and attributes, records, JSON).
use crate::data::batch::{shuffle, validate_structure, BatchError, EncryptedBatch};
#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{HasStructure, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::{
    AttributeRekeyInfo, PseudonymRekeyInfo, PseudonymizationInfo, TranscryptionInfo,
};
use rand_core::{CryptoRng, Rng};

#[cfg(feature = "json")]
use crate::data::json::EncryptedPEPJSONValue;
#[cfg(feature = "long")]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::data::records::EncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::LongEncryptedRecord;
use crate::data::simple::{EncryptedAttribute, EncryptedPseudonym};
// `elgamal3` and `(not batch-pk, not elgamal3)` variants both need pk per
// call (in elgamal3 it's carried by each item; in (not batch-pk) it's a
// parameter). The `(batch-pk, not elgamal3)` variant reads it from the batch.

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl EncryptedBatch<EncryptedPseudonym> {
    /// Pseudonymize every item in the batch, shuffling their order to prevent
    /// linking. The batch's recipient public key is converted with the same
    /// rekey factor so the batch stays self-describing.
    pub fn pseudonymize<R>(
        &mut self,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.pseudonymize(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.k);
        Ok(())
    }

    /// Rekey every item in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &PseudonymRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.k);
        Ok(())
    }

    /// Transcrypt every item in the batch and shuffle. For a pseudonym
    /// batch this is equivalent to [`pseudonymize`](Self::pseudonymize)
    /// using the pseudonymization half of `info`.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.pseudonym.k);
        Ok(())
    }
}

#[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl EncryptedBatch<EncryptedPseudonym> {
    /// Pseudonymize every item in the batch using a caller-supplied recipient
    /// public key, shuffling their order to prevent linking.
    pub fn pseudonymize<R>(
        &mut self,
        info: &PseudonymizationInfo,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.pseudonymize(info, public_key, rng))
            .collect();
        Ok(())
    }

    /// Rekey every item in the batch and shuffle. No pk is needed for the
    /// rekey itself.
    pub fn rekey<R>(&mut self, info: &PseudonymRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, public_key, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every item in the batch using a caller-supplied recipient
    /// public key, shuffling their order.
    pub fn transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, public_key, rng))
            .collect();
        Ok(())
    }
}
#[cfg(feature = "elgamal3")]
impl EncryptedBatch<EncryptedPseudonym> {
    /// Pseudonymize every item in the batch, shuffling their order to prevent
    /// linking. Each ciphertext already carries `gy`, so no pk is needed.
    pub fn pseudonymize<R>(
        &mut self,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.pseudonymize(info, rng))
            .collect();
        Ok(())
    }

    /// Rekey every item in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &PseudonymRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every item in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
impl EncryptedBatch<LongEncryptedPseudonym> {
    /// Pseudonymize every long pseudonym in the batch and shuffle. Each block
    /// is pseudonymized independently with a fresh rerandomize factor.
    pub fn pseudonymize<R>(
        &mut self,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.pseudonymize(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.k);
        Ok(())
    }

    /// Rekey every long pseudonym in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &PseudonymRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.k);
        Ok(())
    }

    /// Transcrypt every long pseudonym in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.pseudonym.k);
        Ok(())
    }
}

#[cfg(all(feature = "long", not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl EncryptedBatch<LongEncryptedPseudonym> {
    /// Pseudonymize every long pseudonym in the batch using a caller-supplied
    /// recipient public key, shuffling their order.
    pub fn pseudonymize<R>(
        &mut self,
        info: &PseudonymizationInfo,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.pseudonymize(info, public_key, rng))
            .collect();
        Ok(())
    }

    /// Rekey every long pseudonym in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &PseudonymRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, public_key, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every long pseudonym in the batch using a caller-supplied
    /// recipient public key, shuffling their order.
    pub fn transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::PseudonymSessionPublicKey,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, public_key, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "long", feature = "elgamal3"))]
impl EncryptedBatch<LongEncryptedPseudonym> {
    /// Pseudonymize every long pseudonym in the batch and shuffle.
    pub fn pseudonymize<R>(
        &mut self,
        info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.pseudonymize(info, rng))
            .collect();
        Ok(())
    }

    /// Rekey every long pseudonym in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &PseudonymRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every long pseudonym in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl EncryptedBatch<EncryptedAttribute> {
    /// Rekey every item in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &AttributeRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.k);
        Ok(())
    }

    /// Transcrypt every item in the batch and shuffle. For an attribute
    /// batch this is equivalent to [`rekey`](Self::rekey) using the
    /// attribute half of `info`.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.attribute.k);
        Ok(())
    }
}

#[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl EncryptedBatch<EncryptedAttribute> {
    /// Rekey every item in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &AttributeRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, public_key, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every item in the batch using a caller-supplied recipient
    /// public key, shuffling their order.
    pub fn transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::AttributeSessionPublicKey,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, public_key, rng))
            .collect();
        Ok(())
    }
}

#[cfg(feature = "elgamal3")]
impl EncryptedBatch<EncryptedAttribute> {
    /// Rekey every item in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &AttributeRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every item in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
impl EncryptedBatch<LongEncryptedAttribute> {
    /// Rekey every long attribute in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &AttributeRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.k);
        Ok(())
    }

    /// Transcrypt every long attribute in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, &self.public_key, rng))
            .collect();
        self.public_key = self.public_key.convert(&info.attribute.k);
        Ok(())
    }
}

#[cfg(all(feature = "long", not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl EncryptedBatch<LongEncryptedAttribute> {
    /// Rekey every long attribute in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &AttributeRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, public_key, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every long attribute in the batch using a caller-supplied
    /// recipient public key, shuffling their order.
    pub fn transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::AttributeSessionPublicKey,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, public_key, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "long", feature = "elgamal3"))]
impl EncryptedBatch<LongEncryptedAttribute> {
    /// Rekey every long attribute in the batch and shuffle.
    pub fn rekey<R>(&mut self, info: &AttributeRekeyInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.rekey(info, rng))
            .collect();
        Ok(())
    }

    /// Transcrypt every long attribute in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl EncryptedBatch<EncryptedRecord> {
    /// Transcrypt every record in the batch and shuffle. The batch's recipient
    /// key bundle is converted with both rekey factors so the batch stays
    /// self-describing.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, &self.public_key, rng))
            .collect();
        self.public_key = self
            .public_key
            .convert(&info.pseudonym.k, &info.attribute.k);
        Ok(())
    }
}

#[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl EncryptedBatch<EncryptedRecord> {
    /// Transcrypt every record in the batch using a caller-supplied recipient
    /// key bundle, shuffling their order.
    pub fn transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::SessionKeys,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, public_key, rng))
            .collect();
        Ok(())
    }
}

#[cfg(feature = "elgamal3")]
impl EncryptedBatch<EncryptedRecord> {
    /// Transcrypt every record in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "long", not(feature = "elgamal3"), feature = "batch-pk"))]
impl EncryptedBatch<LongEncryptedRecord> {
    /// Transcrypt every long record in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, &self.public_key, rng))
            .collect();
        self.public_key = self
            .public_key
            .convert(&info.pseudonym.k, &info.attribute.k);
        Ok(())
    }
}

#[cfg(all(feature = "long", not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl EncryptedBatch<LongEncryptedRecord> {
    /// Transcrypt every long record in the batch using a caller-supplied
    /// recipient key bundle, shuffling their order.
    pub fn transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::SessionKeys,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, public_key, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "long", feature = "elgamal3"))]
impl EncryptedBatch<LongEncryptedRecord> {
    /// Transcrypt every long record in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "json", not(feature = "elgamal3"), feature = "batch-pk"))]
impl EncryptedBatch<EncryptedPEPJSONValue> {
    /// Transcrypt every JSON value in the batch and shuffle. The batch's
    /// recipient key bundle is converted with both rekey factors so the batch
    /// stays self-describing.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, &self.public_key, rng))
            .collect();
        self.public_key = self
            .public_key
            .convert(&info.pseudonym.k, &info.attribute.k);
        Ok(())
    }
}

#[cfg(all(feature = "json", not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl EncryptedBatch<EncryptedPEPJSONValue> {
    /// Transcrypt every JSON value in the batch using a caller-supplied
    /// recipient key bundle, shuffling their order.
    pub fn transcrypt<R>(
        &mut self,
        info: &TranscryptionInfo,
        public_key: &crate::keys::SessionKeys,
        rng: &mut R,
    ) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, public_key, rng))
            .collect();
        Ok(())
    }
}

#[cfg(all(feature = "json", feature = "elgamal3"))]
impl EncryptedBatch<EncryptedPEPJSONValue> {
    /// Transcrypt every JSON value in the batch and shuffle.
    pub fn transcrypt<R>(&mut self, info: &TranscryptionInfo, rng: &mut R) -> Result<(), BatchError>
    where
        R: Rng + CryptoRng,
    {
        shuffle(&mut self.items, rng);
        self.items = self
            .items
            .iter()
            .map(|item| item.transcrypt(info, rng))
            .collect();
        Ok(())
    }
}

/// Polymorphic batch pseudonymization with structure validation and shuffling.
///
/// Pseudonymizes a slice of encrypted pseudonyms and shuffles their order to prevent linking.
/// For types implementing `HasStructure`, validates that all items have the same structure.
///
/// # Errors
///
/// Returns an error if the encrypted values do not all have the same structure
/// (for types implementing `HasStructure`).
///
/// # Examples
/// ```rust,ignore
/// let pseudonymized = pseudonymize_batch(&mut encrypted_pseudonyms, &info, &mut rng)?;
/// ```
#[cfg(feature = "elgamal3")]
pub fn pseudonymize_batch<E, R>(
    encrypted: &mut [E],
    info: &crate::factors::PseudonymizationInfo,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.pseudonymize(info, rng))
        .collect())
}

#[cfg(not(feature = "elgamal3"))]
pub fn pseudonymize_batch<E, R>(
    encrypted: &mut [E],
    info: &crate::factors::PseudonymizationInfo,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.pseudonymize(info, public_key, rng))
        .collect())
}

/// Polymorphic batch rekeying with structure validation and shuffling.
///
/// Rekeys a slice of encrypted values and shuffles their order to prevent linking.
/// For types implementing `HasStructure`, validates that all items have the same structure.
///
/// # Errors
///
/// Returns an error if the encrypted values do not all have the same structure
/// (for types implementing `HasStructure`).
///
/// # Examples
/// ```rust,ignore
/// let rekeyed = rekey_batch(&mut encrypted_attributes, &info, &mut rng)?;
/// ```
#[cfg(feature = "elgamal3")]
pub fn rekey_batch<E, R>(
    encrypted: &mut [E],
    info: &E::RekeyInfo,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Rekeyable + HasStructure + Clone,
    E::RekeyInfo: Copy,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|x| x.rekey(info, rng)).collect())
}

#[cfg(not(feature = "elgamal3"))]
pub fn rekey_batch<E, R>(
    encrypted: &mut [E],
    info: &E::RekeyInfo,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Rekeyable + HasStructure + Clone,
    E::RekeyInfo: Copy,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.rekey(info, public_key, rng))
        .collect())
}

/// Polymorphic batch transcryption with structure validation and shuffling.
///
/// Transcrypts a slice of encrypted values and shuffles their order to prevent linking.
/// For types implementing `HasStructure`, validates that all items have the same structure.
///
/// # Errors
///
/// Returns an error if the encrypted values do not all have the same structure
/// (for types implementing `HasStructure`).
///
/// # Examples
/// ```rust,ignore
/// let transcrypted = transcrypt_batch(&mut encrypted_records, &info, &mut rng)?;
/// ```
#[cfg(feature = "elgamal3")]
pub fn transcrypt_batch<E, R>(
    encrypted: &mut [E],
    info: &TranscryptionInfo,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Transcryptable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|x| x.transcrypt(info, rng)).collect())
}

#[cfg(not(feature = "elgamal3"))]
pub fn transcrypt_batch<E, R>(
    encrypted: &mut [E],
    info: &TranscryptionInfo,
    public_key: &<E::UnencryptedType as Encryptable>::PublicKeyType,
    rng: &mut R,
) -> Result<Box<[E]>, BatchError>
where
    E: Transcryptable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted
        .iter()
        .map(|x| x.transcrypt(info, public_key, rng))
        .collect())
}
