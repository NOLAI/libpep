use crate::core::data::{
    Attribute, EncryptedAttribute, EncryptedPseudonym, HasGlobalKeys, Pseudonym,
};
use crate::core::keys::{GlobalPublicKeys, PublicKey};
use crate::core::offline::{encrypt_attribute_global, encrypt_global, encrypt_pseudonym_global};
use rand_core::{CryptoRng, RngCore};

/// An offline PEP client that can encrypt data, based on global public keys for pseudonyms and attributes.
/// This client is used for encryption only, and does not have session key pairs.
/// This can be useful when encryption is done offline and no session key pairs are available,
/// or when using a session key would leak information.
#[derive(Clone)]
pub struct OfflinePEPClient {
    pub global_public_keys: GlobalPublicKeys,
}

impl OfflinePEPClient {
    /// Create a new offline PEP client from the given global public keys.
    pub fn new(global_public_keys: GlobalPublicKeys) -> Self {
        Self { global_public_keys }
    }
    /// Polymorphic encrypt that works for both pseudonyms and attributes using global keys.
    ///
    /// # Example
    /// ```ignore
    /// let encrypted_pseudonym = client.encrypt(&pseudonym, &client.global_pseudonym_public_key, rng);
    /// let encrypted_attribute = client.encrypt(&attribute, &client.global_attribute_public_key, rng);
    /// ```
    pub fn encrypt<M, R, P>(&self, message: &M, public_key: &P, rng: &mut R) -> M::EncryptedType
    where
        M: HasGlobalKeys<GlobalPublicKey = P>,
        P: PublicKey,
        R: RngCore + CryptoRng,
    {
        encrypt_global(message, public_key, rng)
    }

    /// Encrypt a pseudonym with the global pseudonym public key.
    pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
        &self,
        message: &Pseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        encrypt_pseudonym_global(message, &self.global_public_keys.pseudonym, rng)
    }

    /// Encrypt an attribute with the global attribute public key.
    pub fn encrypt_attribute<R: RngCore + CryptoRng>(
        &self,
        message: &Attribute,
        rng: &mut R,
    ) -> EncryptedAttribute {
        encrypt_attribute_global(message, &self.global_public_keys.attribute, rng)
    }
}
