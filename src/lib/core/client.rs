//! PEP client for encrypting and decrypting data using session keys or global public keys.

use crate::core::data::traits::{Encryptable, Encrypted};
use crate::core::keys::{GlobalPublicKeys, KeyProvider, SessionKeys};
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

    /// Encrypt a JSON value with the session keys.
    /// JSON values require the full SessionKeys struct, not individual keys.
    #[cfg(feature = "json")]
    pub fn encrypt_json<R>(
        &self,
        message: &crate::core::data::json::data::PEPJSONValue,
        rng: &mut R,
    ) -> crate::core::data::json::data::EncryptedPEPJSONValue
    where
        R: RngCore + CryptoRng,
    {
        message.encrypt(&self.keys, rng)
    }

    /// Decrypt a JSON value with the session keys.
    /// JSON values require the full SessionKeys struct, not individual keys.
    #[cfg(all(feature = "json", feature = "elgamal3"))]
    pub fn decrypt_json(
        &self,
        encrypted: &crate::core::data::json::data::EncryptedPEPJSONValue,
    ) -> Option<crate::core::data::json::data::PEPJSONValue> {
        encrypted.decrypt(&self.keys)
    }

    /// Decrypt a JSON value with the session keys.
    /// JSON values require the full SessionKeys struct, not individual keys.
    #[cfg(all(feature = "json", not(feature = "elgamal3")))]
    pub fn decrypt_json(
        &self,
        encrypted: &crate::core::data::json::data::EncryptedPEPJSONValue,
    ) -> crate::core::data::json::data::PEPJSONValue {
        encrypted.decrypt(&self.keys)
    }

    /// Encrypt a batch of messages with the appropriate session public key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the message type.
    #[cfg(feature = "batch")]
    pub fn encrypt_batch<M, R>(
        &self,
        messages: &[M],
        rng: &mut R,
    ) -> Result<Vec<M::EncryptedType>, crate::core::batch::BatchError>
    where
        M: Encryptable,
        SessionKeys: KeyProvider<M::PublicKeyType>,
        R: RngCore + CryptoRng,
    {
        crate::core::batch::encrypt_batch(messages, self.keys.get_key(), rng)
    }

    /// Decrypt a batch of encrypted messages with the appropriate session secret key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the encrypted type.
    /// With the `elgamal3` feature, returns an error if any decryption fails.
    #[cfg(all(feature = "batch", feature = "elgamal3"))]
    pub fn decrypt_batch<E>(
        &self,
        encrypted: &[E],
    ) -> Result<Vec<E::UnencryptedType>, crate::core::batch::BatchError>
    where
        E: Encrypted,
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        crate::core::batch::decrypt_batch(encrypted, self.keys.get_key())
    }

    /// Decrypt a batch of encrypted messages with the appropriate session secret key.
    /// Automatically selects the correct key (pseudonym or attribute) based on the encrypted type.
    #[cfg(all(feature = "batch", not(feature = "elgamal3")))]
    pub fn decrypt_batch<E>(
        &self,
        encrypted: &[E],
    ) -> Result<Vec<E::UnencryptedType>, crate::core::batch::BatchError>
    where
        E: Encrypted,
        SessionKeys: KeyProvider<E::SecretKeyType>,
    {
        crate::core::batch::decrypt_batch(encrypted, self.keys.get_key())
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
    ) -> Result<Vec<M::EncryptedType>, crate::core::batch::BatchError>
    where
        M: Encryptable,
        GlobalPublicKeys: KeyProvider<M::GlobalPublicKeyType>,
        R: RngCore + CryptoRng,
    {
        crate::core::batch::encrypt_global_batch(messages, self.global_public_keys.get_key(), rng)
    }
}

// Distributed client

/// Trait for session key share types that define their associated key types.
pub trait SessionKeyShare:
    std::ops::Deref<Target = crate::arithmetic::scalars::ScalarNonZero> + Sized
{
    type PublicKeyType: From<crate::arithmetic::group_elements::GroupElement>;
    type SecretKeyType: std::ops::Deref<Target = crate::arithmetic::scalars::ScalarNonZero>
        + From<crate::arithmetic::scalars::ScalarNonZero>;
    type BlindedGlobalSecretKeyType: std::ops::Deref<
        Target = crate::arithmetic::scalars::ScalarNonZero,
    >;
}

impl SessionKeyShare for crate::core::keys::distribution::PseudonymSessionKeyShare {
    type PublicKeyType = crate::core::keys::PseudonymSessionPublicKey;
    type SecretKeyType = crate::core::keys::PseudonymSessionSecretKey;
    type BlindedGlobalSecretKeyType =
        crate::core::keys::distribution::BlindedPseudonymGlobalSecretKey;
}

impl SessionKeyShare for crate::core::keys::distribution::AttributeSessionKeyShare {
    type PublicKeyType = crate::core::keys::AttributeSessionPublicKey;
    type SecretKeyType = crate::core::keys::AttributeSessionSecretKey;
    type BlindedGlobalSecretKeyType =
        crate::core::keys::distribution::BlindedAttributeGlobalSecretKey;
}

/// Polymorphic function to reconstruct a session key from a blinded global secret key and session key shares.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn make_session_key<S>(
    blinded_global_secret_key: S::BlindedGlobalSecretKeyType,
    session_key_shares: &[S],
) -> (S::PublicKeyType, S::SecretKeyType)
where
    S: SessionKeyShare,
{
    let secret = S::SecretKeyType::from(
        session_key_shares
            .iter()
            .fold(*blinded_global_secret_key, |acc, x| acc * **x),
    );
    let public = S::PublicKeyType::from(*secret * crate::arithmetic::group_elements::G);
    (public, secret)
}

/// Reconstruct a pseudonym session key from a blinded global secret key and session key shares.
pub fn make_pseudonym_session_key(
    blinded_global_secret_key: crate::core::keys::distribution::BlindedPseudonymGlobalSecretKey,
    session_key_shares: &[crate::core::keys::distribution::PseudonymSessionKeyShare],
) -> (
    crate::core::keys::PseudonymSessionPublicKey,
    crate::core::keys::PseudonymSessionSecretKey,
) {
    make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct an attribute session key from a blinded global secret key and session key shares.
pub fn make_attribute_session_key(
    blinded_global_secret_key: crate::core::keys::distribution::BlindedAttributeGlobalSecretKey,
    session_key_shares: &[crate::core::keys::distribution::AttributeSessionKeyShare],
) -> (
    crate::core::keys::AttributeSessionPublicKey,
    crate::core::keys::AttributeSessionSecretKey,
) {
    make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct session keys (both pseudonym and attribute) from blinded global secret keys and session key shares.
pub fn make_session_keys_distributed(
    blinded_global_keys: crate::core::keys::distribution::BlindedGlobalKeys,
    session_key_shares: &[crate::core::keys::distribution::SessionKeyShares],
) -> SessionKeys {
    let pseudonym_shares: Vec<crate::core::keys::distribution::PseudonymSessionKeyShare> =
        session_key_shares.iter().map(|s| s.pseudonym).collect();
    let attribute_shares: Vec<crate::core::keys::distribution::AttributeSessionKeyShare> =
        session_key_shares.iter().map(|s| s.attribute).collect();

    let (pseudonym_public, pseudonym_secret) =
        make_session_key(blinded_global_keys.pseudonym, &pseudonym_shares);
    let (attribute_public, attribute_secret) =
        make_session_key(blinded_global_keys.attribute, &attribute_shares);

    SessionKeys {
        pseudonym: crate::core::keys::PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: crate::core::keys::AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Polymorphic function to update a session key with new session key shares.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn update_session_key<S>(
    session_secret_key: S::SecretKeyType,
    old_session_key_share: S,
    new_session_key_share: S,
) -> (S::PublicKeyType, S::SecretKeyType)
where
    S: SessionKeyShare,
{
    let secret = S::SecretKeyType::from(
        *session_secret_key * old_session_key_share.invert() * *new_session_key_share,
    );
    let public = S::PublicKeyType::from(*secret * crate::arithmetic::group_elements::G);
    (public, secret)
}

/// Update a pseudonym session key with new session key shares.
pub fn update_pseudonym_session_key(
    session_secret_key: crate::core::keys::PseudonymSessionSecretKey,
    old_session_key_share: crate::core::keys::distribution::PseudonymSessionKeyShare,
    new_session_key_share: crate::core::keys::distribution::PseudonymSessionKeyShare,
) -> (
    crate::core::keys::PseudonymSessionPublicKey,
    crate::core::keys::PseudonymSessionSecretKey,
) {
    update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update an attribute session key with new session key shares.
pub fn update_attribute_session_key(
    session_secret_key: crate::core::keys::AttributeSessionSecretKey,
    old_session_key_share: crate::core::keys::distribution::AttributeSessionKeyShare,
    new_session_key_share: crate::core::keys::distribution::AttributeSessionKeyShare,
) -> (
    crate::core::keys::AttributeSessionPublicKey,
    crate::core::keys::AttributeSessionSecretKey,
) {
    update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update session keys (both pseudonym and attribute) from old session key shares to new ones.
pub fn update_session_keys(
    current_keys: SessionKeys,
    old_shares: crate::core::keys::distribution::SessionKeyShares,
    new_shares: crate::core::keys::distribution::SessionKeyShares,
) -> SessionKeys {
    let (pseudonym_public, pseudonym_secret) = update_session_key(
        current_keys.pseudonym.secret,
        old_shares.pseudonym,
        new_shares.pseudonym,
    );
    let (attribute_public, attribute_secret) = update_session_key(
        current_keys.attribute.secret,
        old_shares.attribute,
        new_shares.attribute,
    );

    SessionKeys {
        pseudonym: crate::core::keys::PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: crate::core::keys::AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Trait to update and extract session keys from SessionKeys based on the share type.
pub trait SessionKeyUpdater<S: SessionKeyShare> {
    fn get_current_secret(&self) -> S::SecretKeyType;
    fn set_keys(&mut self, public: S::PublicKeyType, secret: S::SecretKeyType);
}

impl SessionKeyUpdater<crate::core::keys::distribution::PseudonymSessionKeyShare> for SessionKeys {
    fn get_current_secret(&self) -> crate::core::keys::PseudonymSessionSecretKey {
        self.pseudonym.secret
    }

    fn set_keys(
        &mut self,
        public: crate::core::keys::PseudonymSessionPublicKey,
        secret: crate::core::keys::PseudonymSessionSecretKey,
    ) {
        self.pseudonym.public = public;
        self.pseudonym.secret = secret;
    }
}

impl SessionKeyUpdater<crate::core::keys::distribution::AttributeSessionKeyShare> for SessionKeys {
    fn get_current_secret(&self) -> crate::core::keys::AttributeSessionSecretKey {
        self.attribute.secret
    }

    fn set_keys(
        &mut self,
        public: crate::core::keys::AttributeSessionPublicKey,
        secret: crate::core::keys::AttributeSessionSecretKey,
    ) {
        self.attribute.public = public;
        self.attribute.secret = secret;
    }
}

/// Extension trait for Client with distributed-specific constructors and methods.
pub trait DistributedClient {
    /// Create a new PEP client from blinded global keys and session key shares.
    fn from_shares(
        blinded_global_keys: crate::core::keys::distribution::BlindedGlobalKeys,
        session_key_shares: &[crate::core::keys::distribution::SessionKeyShares],
    ) -> Self;

    /// Update a session key share from one session to another.
    /// Automatically selects the correct key (pseudonym or attribute) based on the share type.
    fn update_session_secret_key<S>(&mut self, old_key_share: S, new_key_share: S)
    where
        S: SessionKeyShare,
        SessionKeys: SessionKeyUpdater<S>;

    /// Update both pseudonym and attribute session key shares from one session to another.
    /// This is a convenience method that updates both shares together.
    fn update_session_secret_keys(
        &mut self,
        old_key_shares: crate::core::keys::distribution::SessionKeyShares,
        new_key_shares: crate::core::keys::distribution::SessionKeyShares,
    );
}

impl DistributedClient for Client {
    fn from_shares(
        blinded_global_keys: crate::core::keys::distribution::BlindedGlobalKeys,
        session_key_shares: &[crate::core::keys::distribution::SessionKeyShares],
    ) -> Self {
        let keys = make_session_keys_distributed(blinded_global_keys, session_key_shares);
        Self::new(keys)
    }

    fn update_session_secret_key<S>(&mut self, old_key_share: S, new_key_share: S)
    where
        S: SessionKeyShare,
        SessionKeys: SessionKeyUpdater<S>,
    {
        let current_secret = self.keys.get_current_secret();
        let (public, secret) = update_session_key(current_secret, old_key_share, new_key_share);
        self.keys.set_keys(public, secret);
    }

    fn update_session_secret_keys(
        &mut self,
        old_key_shares: crate::core::keys::distribution::SessionKeyShares,
        new_key_shares: crate::core::keys::distribution::SessionKeyShares,
    ) {
        self.keys = update_session_keys(self.keys, old_key_shares, new_key_shares);
    }
}
