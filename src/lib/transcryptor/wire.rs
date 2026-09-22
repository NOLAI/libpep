//! Transcryption of a [`BatchRequest`] into a [`BatchResponse`]: the transcryptor's side of the
//! batch protocol of draft-doesburg-cfrg-coprf.

use super::batch::{pseudonymize_batch, rekey_batch};
use super::types::Transcryptor;
use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::data::simple::{ElGamalEncrypted, EncryptedAttribute, EncryptedPseudonym};
use crate::errors::BatchError;
use crate::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey, PublicKey};
use crate::wire::{BatchKind, BatchRequest, BatchResponse};
use rand_core::{CryptoRng, Rng};

impl Transcryptor {
    /// Transcrypt a wire-format batch: derive the factors from the request's identifiers, then
    /// pseudonymize (pseudonym batches) or rekey (attribute batches) the items with fresh
    /// rerandomization and a uniformly random shuffle, as
    /// [`pseudonymize_batch`] and [`rekey_batch`] do.
    ///
    /// The response carries the public key the items are now encrypted under, which is the
    /// request's key with this transcryptor's rekey factor applied, so that the response can be
    /// forwarded to the next transcryptor of a chain as a new request.
    ///
    /// # Errors
    ///
    /// If an identifier is not valid UTF-8 and so cannot name a domain or context.
    pub fn transcrypt_wire<R>(
        &self,
        request: &BatchRequest,
        rng: &mut R,
    ) -> Result<BatchResponse, BatchError>
    where
        R: Rng + CryptoRng,
    {
        let [d_from, d_to, c_from, c_to] = request.identifiers()?;
        let session_from = EncryptionContext::from(c_from);
        let session_to = EncryptionContext::from(c_to);
        let (y_to, items) = match request.kind() {
            BatchKind::Pseudonym => {
                let info = self.pseudonymization_info(
                    &PseudonymizationDomain::from(d_from),
                    &PseudonymizationDomain::from(d_to),
                    &session_from,
                    &session_to,
                );
                let key = PseudonymSessionPublicKey::from_point(*request.y_from());
                let mut encrypted: Vec<EncryptedPseudonym> = request
                    .items()
                    .iter()
                    .copied()
                    .map(EncryptedPseudonym::from_value)
                    .collect();
                #[cfg(feature = "elgamal3")]
                let out = pseudonymize_batch(&mut encrypted, &info, rng)?;
                #[cfg(not(feature = "elgamal3"))]
                let out = pseudonymize_batch(&mut encrypted, &info, &key, rng)?;
                (
                    *info.rekey_public_key(&key).value(),
                    out.iter().map(|e| *e.value()).collect(),
                )
            }
            BatchKind::Attribute => {
                let info = self.attribute_rekey_info(&session_from, &session_to);
                let key = AttributeSessionPublicKey::from_point(*request.y_from());
                let mut encrypted: Vec<EncryptedAttribute> = request
                    .items()
                    .iter()
                    .copied()
                    .map(EncryptedAttribute::from_value)
                    .collect();
                #[cfg(feature = "elgamal3")]
                let out = rekey_batch(&mut encrypted, &info, rng)?;
                #[cfg(not(feature = "elgamal3"))]
                let out = rekey_batch(&mut encrypted, &info, &key, rng)?;
                (
                    *info.rekey_public_key(&key).value(),
                    out.iter().map(|e| *e.value()).collect(),
                )
            }
        };
        Ok(BatchResponse::new(y_to, items)?)
    }
}
