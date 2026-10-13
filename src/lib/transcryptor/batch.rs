//! Batch pseudonymization, rekeying and transcryption with shuffling.
//!
//! A batch is transcrypted item by item after a uniformly random shuffle, so that the order of
//! the output does not reveal the order of the input. The items of a batch must share one
//! structure (see [`HasStructure`]), otherwise they could be linked through it.
//!
//! The operations are methods of [`EncryptedBatch`], whose constructor validates the structure,
//! and free functions over a slice, which validate it themselves. With the `batch-pk` feature
//! (and without `elgamal3`), the batch carries the public key its items are encrypted under and
//! converts it along, so the operations need no key argument.

use crate::data::batch::{shuffle, validate_structure, BatchError, EncryptedBatch};
#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{HasStructure, Pseudonymizable, Rekeyable, Transcryptable};
use crate::factors::types::generic::{PseudonymizationInfo, TranscryptionInfo};
#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
use crate::factors::RekeyPublicKey;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::KeyProvider;
use rand_core::{CryptoRng, Rng};

/// The public key type of the data an encrypted type decrypts to.
#[cfg(not(feature = "elgamal3"))]
type PublicKeyOf<E> =
    <<E as crate::data::traits::Encrypted>::UnencryptedType as Encryptable>::PublicKeyType;

/// Shuffle `items` and replace every item by `f(item, rng)`.
fn shuffle_map<E, R: Rng + CryptoRng>(
    items: &mut Vec<E>,
    rng: &mut R,
    mut f: impl FnMut(&E, &mut R) -> E,
) {
    shuffle(items, rng);
    *items = items.iter().map(|item| f(item, rng)).collect();
}

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl<E: Pseudonymizable + HasStructure> EncryptedBatch<E>
where
    PseudonymizationInfo<E::Group>: RekeyPublicKey<PublicKeyOf<E>>,
{
    /// Pseudonymize every item and shuffle. The batch's public key is converted along.
    pub fn pseudonymize<R: Rng + CryptoRng>(
        &mut self,
        info: &PseudonymizationInfo<E::Group>,
        rng: &mut R,
    ) {
        let key = self.public_key;
        shuffle_map(&mut self.items, rng, |item, rng| {
            item.pseudonymize(info, &key, rng)
        });
        self.public_key = info.rekey_public_key(&key);
    }
}

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl<E: Rekeyable + HasStructure> EncryptedBatch<E>
where
    E::RekeyInfo: RekeyPublicKey<PublicKeyOf<E>>,
{
    /// Rekey every item and shuffle. The batch's public key is converted along.
    pub fn rekey<R: Rng + CryptoRng>(&mut self, info: &E::RekeyInfo, rng: &mut R) {
        let key = self.public_key;
        shuffle_map(&mut self.items, rng, |item, rng| {
            item.rekey(info, &key, rng)
        });
        self.public_key = info.rekey_public_key(&key);
    }
}

#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
impl<E: Transcryptable + HasStructure> EncryptedBatch<E>
where
    TranscryptionInfo<E::Group>: RekeyPublicKey<PublicKeyOf<E>>,
{
    /// Transcrypt every item and shuffle. The batch's public key is converted along.
    pub fn transcrypt<R: Rng + CryptoRng>(
        &mut self,
        info: &TranscryptionInfo<E::Group>,
        rng: &mut R,
    ) {
        let key = self.public_key;
        shuffle_map(&mut self.items, rng, |item, rng| {
            item.transcrypt(info, &key, rng)
        });
        self.public_key = info.rekey_public_key(&key);
    }
}

#[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl<E: Pseudonymizable + HasStructure> EncryptedBatch<E> {
    /// Pseudonymize every item and shuffle. `public_key` is the key the items are currently
    /// encrypted under.
    pub fn pseudonymize<R: Rng + CryptoRng>(
        &mut self,
        info: &PseudonymizationInfo<E::Group>,
        public_key: &PublicKeyOf<E>,
        rng: &mut R,
    ) {
        shuffle_map(&mut self.items, rng, |item, rng| {
            item.pseudonymize(info, public_key, rng)
        });
    }
}

#[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl<E: Rekeyable + HasStructure> EncryptedBatch<E> {
    /// Rekey every item and shuffle. `public_key` is the key the items are currently encrypted
    /// under.
    pub fn rekey<R: Rng + CryptoRng>(
        &mut self,
        info: &E::RekeyInfo,
        public_key: &PublicKeyOf<E>,
        rng: &mut R,
    ) {
        shuffle_map(&mut self.items, rng, |item, rng| {
            item.rekey(info, public_key, rng)
        });
    }
}

#[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
impl<E: Transcryptable + HasStructure> EncryptedBatch<E> {
    /// Transcrypt every item and shuffle. `public_key` is the key the items are currently
    /// encrypted under.
    pub fn transcrypt<R: Rng + CryptoRng>(
        &mut self,
        info: &TranscryptionInfo<E::Group>,
        public_key: &PublicKeyOf<E>,
        rng: &mut R,
    ) {
        shuffle_map(&mut self.items, rng, |item, rng| {
            item.transcrypt(info, public_key, rng)
        });
    }
}

#[cfg(feature = "elgamal3")]
impl<E: Pseudonymizable + HasStructure> EncryptedBatch<E> {
    /// Pseudonymize every item and shuffle.
    pub fn pseudonymize<R: Rng + CryptoRng>(
        &mut self,
        info: &PseudonymizationInfo<E::Group>,
        rng: &mut R,
    ) {
        shuffle_map(&mut self.items, rng, |item, rng| {
            item.pseudonymize(info, rng)
        });
    }
}

#[cfg(feature = "elgamal3")]
impl<E: Rekeyable + HasStructure> EncryptedBatch<E> {
    /// Rekey every item and shuffle.
    pub fn rekey<R: Rng + CryptoRng>(&mut self, info: &E::RekeyInfo, rng: &mut R) {
        shuffle_map(&mut self.items, rng, |item, rng| item.rekey(info, rng));
    }
}

#[cfg(feature = "elgamal3")]
impl<E: Transcryptable + HasStructure> EncryptedBatch<E> {
    /// Transcrypt every item and shuffle.
    pub fn transcrypt<R: Rng + CryptoRng>(
        &mut self,
        info: &TranscryptionInfo<E::Group>,
        rng: &mut R,
    ) {
        shuffle_map(&mut self.items, rng, |item, rng| item.transcrypt(info, rng));
    }
}

/// Validate the structure of `encrypted`, shuffle it, and return `f(item, rng)` for every item.
fn batch<E: HasStructure + Clone, R: Rng + CryptoRng>(
    encrypted: &mut [E],
    rng: &mut R,
    mut f: impl FnMut(&E, &mut R) -> E,
) -> Result<Vec<E>, BatchError> {
    validate_structure(encrypted)?;
    shuffle(encrypted, rng);
    Ok(encrypted.iter().map(|item| f(item, rng)).collect())
}

/// Pseudonymize a slice of encrypted pseudonyms and shuffle them.
///
/// # Errors
///
/// Returns an error if the items do not all have the same structure.
#[cfg(feature = "elgamal3")]
pub fn pseudonymize_batch<E, R>(
    encrypted: &mut [E],
    info: &PseudonymizationInfo<E::Group>,
    rng: &mut R,
) -> Result<Vec<E>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    batch(encrypted, rng, |item, rng| item.pseudonymize(info, rng))
}

/// Pseudonymize a slice of encrypted pseudonyms and shuffle them. `public_key` is the key they
/// are currently encrypted under.
///
/// # Errors
///
/// Returns an error if the items do not all have the same structure.
#[cfg(not(feature = "elgamal3"))]
pub fn pseudonymize_batch<E, R>(
    encrypted: &mut [E],
    info: &PseudonymizationInfo<E::Group>,
    public_key: &impl KeyProvider<PublicKeyOf<E>>,
    rng: &mut R,
) -> Result<Vec<E>, BatchError>
where
    E: Pseudonymizable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    let key = public_key.get_key();
    batch(encrypted, rng, |item, rng| {
        item.pseudonymize(info, &key, rng)
    })
}

/// Rekey a slice of encrypted values and shuffle them.
///
/// # Errors
///
/// Returns an error if the items do not all have the same structure.
#[cfg(feature = "elgamal3")]
pub fn rekey_batch<E, R>(
    encrypted: &mut [E],
    info: &E::RekeyInfo,
    rng: &mut R,
) -> Result<Vec<E>, BatchError>
where
    E: Rekeyable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    batch(encrypted, rng, |item, rng| item.rekey(info, rng))
}

/// Rekey a slice of encrypted values and shuffle them. `public_key` is the key they are
/// currently encrypted under.
///
/// # Errors
///
/// Returns an error if the items do not all have the same structure.
#[cfg(not(feature = "elgamal3"))]
pub fn rekey_batch<E, R>(
    encrypted: &mut [E],
    info: &E::RekeyInfo,
    public_key: &impl KeyProvider<PublicKeyOf<E>>,
    rng: &mut R,
) -> Result<Vec<E>, BatchError>
where
    E: Rekeyable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    let key = public_key.get_key();
    batch(encrypted, rng, |item, rng| item.rekey(info, &key, rng))
}

/// Transcrypt a slice of encrypted values and shuffle them.
///
/// # Errors
///
/// Returns an error if the items do not all have the same structure.
#[cfg(feature = "elgamal3")]
pub fn transcrypt_batch<E, R>(
    encrypted: &mut [E],
    info: &TranscryptionInfo<E::Group>,
    rng: &mut R,
) -> Result<Vec<E>, BatchError>
where
    E: Transcryptable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    batch(encrypted, rng, |item, rng| item.transcrypt(info, rng))
}

/// Transcrypt a slice of encrypted values and shuffle them. `public_key` is the key they are
/// currently encrypted under.
///
/// # Errors
///
/// Returns an error if the items do not all have the same structure.
#[cfg(not(feature = "elgamal3"))]
pub fn transcrypt_batch<E, R>(
    encrypted: &mut [E],
    info: &TranscryptionInfo<E::Group>,
    public_key: &impl KeyProvider<PublicKeyOf<E>>,
    rng: &mut R,
) -> Result<Vec<E>, BatchError>
where
    E: Transcryptable + HasStructure + Clone,
    R: Rng + CryptoRng,
{
    let key = public_key.get_key();
    batch(encrypted, rng, |item, rng| item.transcrypt(info, &key, rng))
}
