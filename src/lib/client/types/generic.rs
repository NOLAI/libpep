//! The client generic over the [`Group`].

use crate::data::traits::{Encryptable, Encrypted};
use crate::elgamal::arithmetic::group::Group;
use crate::keys::traits::KeyProvider;
#[cfg(feature = "offline")]
use crate::keys::types::generic::GlobalPublicKeys;
use crate::keys::types::generic::SessionKeys;
use rand_core::{CryptoRng, Rng};

/// A PEP client that encrypts and decrypts data with its session keys for pseudonyms and
/// attributes.
#[derive(Clone)]
pub struct Client<G: Group> {
    pub(crate) keys: SessionKeys<G>,
}

impl<G: Group> Client<G> {
    /// A client holding the given session keys.
    pub fn new(keys: SessionKeys<G>) -> Self {
        Self { keys }
    }

    /// The session keys of this client.
    pub fn keys(&self) -> &SessionKeys<G> {
        &self.keys
    }

    /// Encrypt a value with the session public key its type requires.
    pub fn encrypt<M, R>(&self, message: &M, rng: &mut R) -> M::EncryptedType
    where
        M: Encryptable<Group = G>,
        SessionKeys<G>: KeyProvider<M::PublicKeyType>,
        R: Rng + CryptoRng,
    {
        message.encrypt(&self.keys.get_key(), rng)
    }

    /// Decrypt a value with the session secret key its type requires.
    /// With the `elgamal3` feature, returns `None` if the secret key does not match.
    #[cfg(feature = "elgamal3")]
    pub fn decrypt<E>(&self, encrypted: &E) -> Option<E::UnencryptedType>
    where
        E: Encrypted<Group = G>,
        SessionKeys<G>: KeyProvider<E::SecretKeyType>,
    {
        encrypted.decrypt(&self.keys.get_key())
    }

    /// Decrypt a value with the session secret key its type requires.
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt<E>(&self, encrypted: &E) -> E::UnencryptedType
    where
        E: Encrypted<Group = G>,
        SessionKeys<G>: KeyProvider<E::SecretKeyType>,
    {
        encrypted.decrypt(&self.keys.get_key())
    }

    /// Encrypt a batch of values with the session public key their type requires; see
    /// [`encrypt_batch`](crate::client::encrypt_batch).
    ///
    /// # Errors
    ///
    /// Returns an error if the values cannot be brought to one structure.
    #[cfg(feature = "batch")]
    pub fn encrypt_batch<M, R>(
        &self,
        messages: &[M],
        rng: &mut R,
    ) -> Result<crate::data::batch::EncryptedBatch<M::EncryptedType>, crate::errors::BatchError>
    where
        M: Encryptable<Group = G> + Clone,
        M::EncryptedType: crate::data::traits::HasStructure,
        SessionKeys<G>: KeyProvider<M::PublicKeyType>,
        R: Rng + CryptoRng,
    {
        crate::client::batch::encrypt_batch(messages, &self.keys.get_key(), rng)
    }

    /// Encrypt a batch of values without bringing them to one structure; see
    /// [`encrypt_batch_raw`](crate::client::batch::encrypt_batch_raw).
    #[cfg(all(feature = "batch", feature = "insecure"))]
    pub fn encrypt_batch_raw<M, R>(&self, messages: &[M], rng: &mut R) -> Vec<M::EncryptedType>
    where
        M: Encryptable<Group = G>,
        SessionKeys<G>: KeyProvider<M::PublicKeyType>,
        R: Rng + CryptoRng,
    {
        crate::client::batch::encrypt_batch_raw(messages, &self.keys.get_key(), rng)
    }

    /// Decrypt a batch of values with the session secret key their type requires.
    ///
    /// # Errors
    ///
    /// With the `elgamal3` feature, returns an error if any decryption fails.
    #[cfg(feature = "batch")]
    pub fn decrypt_batch<E>(
        &self,
        encrypted: &[E],
    ) -> Result<Vec<E::UnencryptedType>, crate::errors::BatchError>
    where
        E: Encrypted<Group = G>,
        SessionKeys<G>: KeyProvider<E::SecretKeyType>,
    {
        crate::client::batch::decrypt_batch(encrypted, &self.keys.get_key())
    }
}

/// A PEP client that encrypts data towards the global public keys, for when no session keys
/// are available or using them would leak information. It holds no secret keys and cannot
/// decrypt.
#[cfg(feature = "offline")]
#[derive(Clone)]
pub struct OfflineClient<G: Group> {
    /// The global public keys encrypted towards.
    pub global_public_keys: GlobalPublicKeys<G>,
}

#[cfg(feature = "offline")]
impl<G: Group> OfflineClient<G> {
    /// An offline client encrypting towards the given global public keys.
    pub fn new(global_public_keys: GlobalPublicKeys<G>) -> Self {
        Self { global_public_keys }
    }

    /// Encrypt a value with the global public key its type requires.
    pub fn encrypt<M, R>(&self, message: &M, rng: &mut R) -> M::EncryptedType
    where
        M: Encryptable<Group = G>,
        GlobalPublicKeys<G>: KeyProvider<M::GlobalPublicKeyType>,
        R: Rng + CryptoRng,
    {
        message.encrypt_global(&self.global_public_keys.get_key(), rng)
    }
}
