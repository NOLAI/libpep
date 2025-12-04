use crate::core::data::{
    decrypt, decrypt_attribute, decrypt_pseudonym, encrypt, encrypt_attribute, encrypt_pseudonym,
    Attribute, Encryptable, Encrypted, EncryptedAttribute, EncryptedPseudonym, HasSessionKeys,
    Pseudonym,
};
use crate::core::keys::SessionKeys;
use crate::distributed::client::keys::{
    make_session_keys_distributed, update_attribute_session_key, update_pseudonym_session_key,
    update_session_keys,
};
use crate::distributed::server::keys::{
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
use crate::distributed::server::setup::BlindedGlobalKeys;
use rand_core::{CryptoRng, RngCore};

/// A PEP client that can encrypt and decrypt data, based on session key pairs for pseudonyms and attributes.
#[derive(Clone)]
pub struct PEPClient {
    pub(crate) keys: SessionKeys,
}
impl PEPClient {
    /// Create a new PEP client from blinded global keys and session key shares.
    pub fn new(
        blinded_global_keys: BlindedGlobalKeys,
        session_key_shares: &[SessionKeyShares],
    ) -> Self {
        let keys = make_session_keys_distributed(blinded_global_keys, session_key_shares);
        Self { keys }
    }

    /// Create a new PEP client from the given session keys.
    pub fn restore(keys: SessionKeys) -> Self {
        Self { keys }
    }

    /// Dump the session keys.
    pub fn dump(&self) -> &SessionKeys {
        &self.keys
    }

    /// Update a pseudonym session key share from one session to the other
    pub fn update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: PseudonymSessionKeyShare,
        new_key_share: PseudonymSessionKeyShare,
    ) {
        let (public, secret) =
            update_pseudonym_session_key(self.keys.pseudonym.secret, old_key_share, new_key_share);
        self.keys.pseudonym.public = public;
        self.keys.pseudonym.secret = secret;
    }

    /// Update an attribute session key share from one session to the other
    pub fn update_attribute_session_secret_key(
        &mut self,
        old_key_share: AttributeSessionKeyShare,
        new_key_share: AttributeSessionKeyShare,
    ) {
        let (public, secret) =
            update_attribute_session_key(self.keys.attribute.secret, old_key_share, new_key_share);
        self.keys.attribute.public = public;
        self.keys.attribute.secret = secret;
    }

    /// Update both pseudonym and attribute session key shares from one session to another.
    /// This is a convenience method that updates both shares together.
    pub fn update_session_secret_keys(
        &mut self,
        old_key_shares: SessionKeyShares,
        new_key_shares: SessionKeyShares,
    ) {
        self.keys = update_session_keys(self.keys, old_key_shares, new_key_shares);
    }

    /// Get the appropriate public key for a given message type (single-block).
    ///
    /// # Safety
    /// Uses unsafe pointer casts for polymorphic dispatch. Safe because:
    /// - TypeId checks ensure the correct concrete type before casting
    /// - All session key types have the same memory layout (GroupElement wrapper)
    #[allow(unsafe_code)]
    fn get_public_key_for<M>(&self) -> &M::SessionPublicKey
    where
        M: HasSessionKeys + 'static,
    {
        use std::any::TypeId;

        if TypeId::of::<M>() == TypeId::of::<Pseudonym>() {
            // SAFETY: TypeId check ensures M is Pseudonym, so M::SessionPublicKey is PseudonymSessionPublicKey
            unsafe { &*(&self.keys.pseudonym.public as *const _ as *const M::SessionPublicKey) }
        } else if TypeId::of::<M>() == TypeId::of::<Attribute>() {
            // SAFETY: TypeId check ensures M is Attribute, so M::SessionPublicKey is AttributeSessionPublicKey
            unsafe { &*(&self.keys.attribute.public as *const _ as *const M::SessionPublicKey) }
        } else {
            panic!("Unsupported message type")
        }
    }

    /// Get the appropriate secret key for a given encrypted message type (single-block).
    ///
    /// # Safety
    /// Uses unsafe pointer casts for polymorphic dispatch. Safe because:
    /// - TypeId checks ensure the correct concrete type before casting
    /// - All session key types have the same memory layout (ScalarNonZero wrapper)
    #[allow(unsafe_code)]
    fn get_secret_key_for<E>(&self) -> &<E::UnencryptedType as HasSessionKeys>::SessionSecretKey
    where
        E: Encrypted,
        E::UnencryptedType: HasSessionKeys + 'static,
    {
        use std::any::TypeId;

        if TypeId::of::<E::UnencryptedType>() == TypeId::of::<Pseudonym>() {
            // SAFETY: TypeId check ensures E::UnencryptedType is Pseudonym
            unsafe {
                &*(&self.keys.pseudonym.secret as *const _
                    as *const <E::UnencryptedType as HasSessionKeys>::SessionSecretKey)
            }
        } else if TypeId::of::<E::UnencryptedType>() == TypeId::of::<Attribute>() {
            // SAFETY: TypeId check ensures E::UnencryptedType is Attribute
            unsafe {
                &*(&self.keys.attribute.secret as *const _
                    as *const <E::UnencryptedType as HasSessionKeys>::SessionSecretKey)
            }
        } else {
            panic!("Unsupported encrypted type")
        }
    }

    /// Polymorphic encrypt that works for both pseudonyms and attributes.
    /// Automatically uses the appropriate session key based on the message type.
    ///
    /// # Example
    /// ```ignore
    /// let encrypted_pseudonym = client.encrypt(&pseudonym, rng);
    /// let encrypted_attribute = client.encrypt(&attribute, rng);
    /// ```
    pub fn encrypt<M, R>(&self, message: &M, rng: &mut R) -> M::EncryptedType
    where
        M: Encryptable + HasSessionKeys + 'static,
        R: RngCore + CryptoRng,
    {
        let public_key = self.get_public_key_for::<M>();
        encrypt(message, public_key, rng)
    }

    /// Polymorphic decrypt that works for both encrypted pseudonyms and attributes.
    /// Automatically uses the appropriate session key based on the encrypted message type.
    /// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
    ///
    /// # Example
    /// ```ignore
    /// let pseudonym = client.decrypt(&encrypted_pseudonym);
    /// let attribute = client.decrypt(&encrypted_attribute);
    /// ```
    #[cfg(feature = "elgamal3")]
    pub fn decrypt<E>(&self, encrypted: &E) -> Option<E::UnencryptedType>
    where
        E: Encrypted,
        E::UnencryptedType: HasSessionKeys + 'static,
    {
        let secret_key = self.get_secret_key_for::<E>();
        decrypt(encrypted, secret_key)
    }

    /// Polymorphic decrypt that works for both encrypted pseudonyms and attributes.
    /// Automatically uses the appropriate session key based on the encrypted message type.
    ///
    /// # Example
    /// ```ignore
    /// let pseudonym = client.decrypt(&encrypted_pseudonym);
    /// let attribute = client.decrypt(&encrypted_attribute);
    /// ```
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt<E>(&self, encrypted: &E) -> E::UnencryptedType
    where
        E: Encrypted,
        E::UnencryptedType: HasSessionKeys + 'static,
    {
        let secret_key = self.get_secret_key_for::<E>();
        decrypt(encrypted, secret_key)
    }

    /// Encrypt a pseudonym with the pseudonym session public key.
    pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
        &self,
        message: &Pseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        encrypt_pseudonym(message, &self.keys.pseudonym.public, rng)
    }

    /// Encrypt an attribute with the attribute session public key.
    pub fn encrypt_attribute<R: RngCore + CryptoRng>(
        &self,
        message: &Attribute,
        rng: &mut R,
    ) -> EncryptedAttribute {
        encrypt_attribute(message, &self.keys.attribute.public, rng)
    }

    /// Decrypt an encrypted pseudonym.
    /// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
    #[cfg(feature = "elgamal3")]
    pub fn decrypt_pseudonym(&self, encrypted: &EncryptedPseudonym) -> Option<Pseudonym> {
        decrypt_pseudonym(encrypted, &self.keys.pseudonym.secret)
    }

    /// Decrypt an encrypted pseudonym.
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt_pseudonym(&self, encrypted: &EncryptedPseudonym) -> Pseudonym {
        decrypt_pseudonym(encrypted, &self.keys.pseudonym.secret)
    }

    /// Decrypt an encrypted attribute.
    /// With the `elgamal3` feature, returns `None` if the secret key doesn't match.
    #[cfg(feature = "elgamal3")]
    pub fn decrypt_attribute(&self, encrypted: &EncryptedAttribute) -> Option<Attribute> {
        decrypt_attribute(encrypted, &self.keys.attribute.secret)
    }

    /// Decrypt an encrypted attribute.
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt_attribute(&self, encrypted: &EncryptedAttribute) -> Attribute {
        decrypt_attribute(encrypted, &self.keys.attribute.secret)
    }
}
