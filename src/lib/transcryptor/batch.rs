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

use crate::data::batch::{shuffle, BatchError, EncryptedBatch};
use crate::data::traits::{Pseudonymizable, Rekeyable, Transcryptable};
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
        self.public_key = self.public_key.convert(info);
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
        self.public_key = self.public_key.convert(info);
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
        self.public_key = self.public_key.convert(info);
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
        self.public_key = self.public_key.convert(&info.attribute);
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
        self.public_key = self.public_key.convert(info);
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
        self.public_key = self.public_key.convert(&info.attribute);
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.items = self.items.iter().map(|item| item.rekey(info)).collect();
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
        self.public_key = self.public_key.convert(&info.pseudonym.k, &info.attribute);
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
        self.public_key = self.public_key.convert(&info.pseudonym.k, &info.attribute);
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
        self.public_key = self.public_key.convert(&info.pseudonym.k, &info.attribute);
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
