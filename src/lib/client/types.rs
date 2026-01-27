//! Client type definitions.

use crate::data::traits::{Encryptable, Encrypted};
use crate::keys::{GlobalPublicKeys, KeyProvider, SessionKeys};
use rand_core::{CryptoRng, RngCore};

/// A PEP client that can encrypt and decrypt data, based on session key pairs for pseudonyms and attributes.
#[derive(Clone)]
pub struct Client {
    pub(crate) keys: SessionKeys,
}

impl Client {
    /// Create a new PEP client from the given session keys.
    pub fn new(keys: SessionKeys) -> Self {
        Self { keys }
    }

    /// Dump the session keys.
    pub fn dump(&self) -> &SessionKeys {
        &self.keys
    }

    /// Restore a PEP client from session keys.
    pub fn restore(keys: SessionKeys) -> Self {
        Self { keys }
    }

    /// Encrypt data with the appropriate session public key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the message type.
    pub fn encrypt<M, R>(&self, message: &M, rng: &mut R) -> M::EncryptedType
    where
        M: Encryptable,
        SessionKeys: KeyProvider<M::PublicKeyType>,
        R: RngCore + CryptoRng,
    {
        message.encrypt(self.keys.get_key(), rng)
    }

    /// Decrypt encrypted data with the appropriate session secret key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the encrypted type.
    /// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
    #[cfg(feature = "elgamal3")]
    pub fn decrypt<E>(&self, encrypted: &E) -> Option<E::UnencryptedType>
    where
        E: Encrypted,
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        encrypted.decrypt(self.keys.get_key())
    }

    /// Decrypt encrypted data with the appropriate session secret key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the encrypted type.
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt<E>(&self, encrypted: &E) -> E::UnencryptedType
    where
        E: Encrypted,
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        encrypted.decrypt(self.keys.get_key())
    }

    /// Encrypt a batch of messages with the appropriate session public key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the message type.
    #[cfg(feature = "batch")]
    pub fn encrypt_batch<M, R>(
        &self,
        messages: &[M],
        rng: &mut R,
    ) -> Result<Vec<M::EncryptedType>, crate::transcryptor::BatchError>
    where
        M: Encryptable,
        SessionKeys: KeyProvider<M::PublicKeyType>,
        R: RngCore + CryptoRng,
    {
        super::batch::encrypt_batch(messages, self.keys.get_key(), rng)
    }

    /// Decrypt a batch of encrypted messages with the appropriate session secret key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the encrypted type.
    /// With the `elgamal3` feature, returns an error if any decryption fails.
    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    pub fn decrypt_batch<E>(
        &self,
        encrypted: &[E],
    ) -> Result<Vec<E::UnencryptedType>, crate::transcryptor::BatchError>
    where
        E: Encrypted,
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        super::batch::decrypt_batch(encrypted, self.keys.get_key())
    }

    /// Decrypt a batch of encrypted messages with the appropriate session secret key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the encrypted type.
    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    pub fn decrypt_batch<E>(
        &self,
        encrypted: &[E],
    ) -> Result<Vec<E::UnencryptedType>, crate::transcryptor::BatchError>
    where
        E: Encrypted,
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        super::batch::decrypt_batch(encrypted, self.keys.get_key())
    }
}

/// An offline PEP client that can encrypt data, based on global public keys for pseudonyms and attributes.
/// This client is used for encryption only, and does not have session key pairs.
/// This can be useful when encryption is done offline and no session key pairs are available,
/// or when using a session key would leak information.
#[cfg(feature = "offline")]
#[derive(Clone)]
pub struct OfflineClient {
    pub global_public_keys: GlobalPublicKeys,
}

#[cfg(feature = "offline")]
impl OfflineClient {
    /// Create a new offline PEP client from the given global public keys.
    pub fn new(global_public_keys: GlobalPublicKeys) -> Self {
        Self { global_public_keys }
    }

    /// Encrypt data with the appropriate global public key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the message type.
    pub fn encrypt<M, R>(&self, message: &M, rng: &mut R) -> M::EncryptedType
    where
        M: Encryptable,
        GlobalPublicKeys: KeyProvider<M::GlobalPublicKeyType>,
        R: RngCore + CryptoRng,
    {
        message.encrypt_global(self.global_public_keys.get_key(), rng)
    }

    /// Encrypt a batch of messages with the appropriate global public key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the message type.
    #[cfg(feature = "batch")]
    pub fn encrypt_batch<M, R>(
        &self,
        messages: &[M],
        rng: &mut R,
    ) -> Result<Vec<M::EncryptedType>, crate::transcryptor::BatchError>
    where
        M: Encryptable,
        GlobalPublicKeys: KeyProvider<M::GlobalPublicKeyType>,
        R: RngCore + CryptoRng,
    {
        super::batch::encrypt_global_batch(messages, self.global_public_keys.get_key(), rng)
    }
}
