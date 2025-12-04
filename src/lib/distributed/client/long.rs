use crate::core::data::{Encryptable, Encrypted, HasSessionKeys};
use crate::core::long::data::{
    decrypt_long, decrypt_long_attribute, decrypt_long_pseudonym, encrypt_long,
    encrypt_long_attribute, encrypt_long_pseudonym, LongAttribute, LongEncryptable, LongEncrypted,
    LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use crate::core::long::offline::{
    encrypt_long_attribute_global, encrypt_long_global, encrypt_long_pseudonym_global,
};
use crate::distributed::client::client::PEPClient;
use crate::distributed::client::offline::OfflinePEPClient;
use rand_core::{CryptoRng, RngCore};
use std::any::TypeId;

impl PEPClient {
    /// Get the appropriate public key for a long message type (multi-block).
    ///
    /// # Safety
    /// Uses unsafe pointer casts for polymorphic dispatch. Safe because:
    /// - TypeId checks ensure the correct concrete type before casting
    /// - All session key types have the same memory layout (GroupElement wrapper)
    #[allow(unsafe_code)]
    fn get_public_key_for_long<L>(&self) -> &<L::Block as HasSessionKeys>::SessionPublicKey
    where
        L: LongEncryptable + 'static,
        L::Block: HasSessionKeys,
    {
        if TypeId::of::<L>() == TypeId::of::<LongPseudonym>() {
            // SAFETY: TypeId check ensures L is LongPseudonym, so Block is Pseudonym
            unsafe {
                &*(&self.keys.pseudonym.public as *const _
                    as *const <L::Block as HasSessionKeys>::SessionPublicKey)
            }
        } else if TypeId::of::<L>() == TypeId::of::<LongAttribute>() {
            // SAFETY: TypeId check ensures L is LongAttribute, so Block is Attribute
            unsafe {
                &*(&self.keys.attribute.public as *const _
                    as *const <L::Block as HasSessionKeys>::SessionPublicKey)
            }
        } else {
            panic!("Unsupported long message type")
        }
    }

    /// Get the appropriate secret key for a long encrypted message type (multi-block).
    ///
    /// # Safety
    /// Uses unsafe pointer casts for polymorphic dispatch. Safe because:
    /// - TypeId checks ensure the correct concrete type before casting
    /// - All session key types have the same memory layout (ScalarNonZero wrapper)
    #[allow(unsafe_code)]
    fn get_secret_key_for_long<LE>(
        &self,
    ) -> &<<LE::UnencryptedType as LongEncryptable>::Block as HasSessionKeys>::SessionSecretKey
    where
        LE: LongEncrypted + 'static,
        <LE::UnencryptedType as LongEncryptable>::Block: HasSessionKeys,
    {
        if TypeId::of::<LE>() == TypeId::of::<LongEncryptedPseudonym>() {
            // SAFETY: TypeId check ensures LE is LongEncryptedPseudonym
            unsafe {
                &*(&self.keys.pseudonym.secret as *const _
                    as *const <<LE::UnencryptedType as LongEncryptable>::Block as HasSessionKeys>::SessionSecretKey)
            }
        } else if TypeId::of::<LE>() == TypeId::of::<LongEncryptedAttribute>() {
            // SAFETY: TypeId check ensures LE is LongEncryptedAttribute
            unsafe {
                &*(&self.keys.attribute.secret as *const _
                    as *const <<LE::UnencryptedType as LongEncryptable>::Block as HasSessionKeys>::SessionSecretKey)
            }
        } else {
            panic!("Unsupported long encrypted type")
        }
    }

    /// Polymorphic encrypt for long (multi-block) data types.
    /// Automatically uses the appropriate session key based on the message type.
    ///
    /// # Example
    /// ```ignore
    /// let encrypted_long_pseudonym = client.encrypt_long(&long_pseudonym, rng);
    /// let encrypted_long_attribute = client.encrypt_long(&long_attribute, rng);
    /// ```
    pub fn encrypt_long<L, R>(&self, message: &L, rng: &mut R) -> L::EncryptedType
    where
        L: LongEncryptable + 'static,
        L::Block: HasSessionKeys,
        R: RngCore + CryptoRng,
    {
        let public_key = self.get_public_key_for_long::<L>();
        encrypt_long(message, public_key, rng)
    }

    /// Polymorphic decrypt for long (multi-block) encrypted data types.
    /// Automatically uses the appropriate session key based on the encrypted message type.
    ///
    /// # Example
    /// ```ignore
    /// let long_pseudonym = client.decrypt_long(&encrypted_long_pseudonym);
    /// let long_attribute = client.decrypt_long(&encrypted_long_attribute);
    /// ```
    #[cfg(feature = "elgamal3")]
    pub fn decrypt_long<LE>(&self, encrypted: &LE) -> Option<LE::UnencryptedType>
    where
        LE: LongEncrypted + 'static,
        <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
            Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
        <LE::UnencryptedType as LongEncryptable>::Block: HasSessionKeys,
    {
        let secret_key = self.get_secret_key_for_long::<LE>();
        decrypt_long(encrypted, secret_key)
    }

    /// Polymorphic decrypt for long (multi-block) data types.
    /// Automatically uses the appropriate session key based on the encrypted message type.
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt_long<LE>(&self, encrypted: &LE) -> LE::UnencryptedType
    where
        LE: LongEncrypted + 'static,
        <<LE::UnencryptedType as LongEncryptable>::Block as Encryptable>::EncryptedType:
            Encrypted<UnencryptedType = <LE::UnencryptedType as LongEncryptable>::Block>,
        <LE::UnencryptedType as LongEncryptable>::Block: HasSessionKeys,
    {
        let secret_key = self.get_secret_key_for_long::<LE>();
        decrypt_long(encrypted, secret_key)
    }

    /// Encrypt a long pseudonym with the pseudonym session public key.
    pub fn encrypt_long_pseudonym<R: RngCore + CryptoRng>(
        &self,
        message: &LongPseudonym,
        rng: &mut R,
    ) -> LongEncryptedPseudonym {
        encrypt_long_pseudonym(message, &self.keys.pseudonym.public, rng)
    }

    /// Encrypt a long attribute with the attribute session public key.
    pub fn encrypt_long_attribute<R: RngCore + CryptoRng>(
        &self,
        message: &LongAttribute,
        rng: &mut R,
    ) -> LongEncryptedAttribute {
        encrypt_long_attribute(message, &self.keys.attribute.public, rng)
    }

    /// Decrypt a long encrypted pseudonym.
    #[cfg(feature = "elgamal3")]
    pub fn decrypt_long_pseudonym(
        &self,
        encrypted: &LongEncryptedPseudonym,
    ) -> Option<LongPseudonym> {
        decrypt_long_pseudonym(encrypted, &self.keys.pseudonym.secret)
    }

    /// Decrypt a long encrypted pseudonym.
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt_long_pseudonym(&self, encrypted: &LongEncryptedPseudonym) -> LongPseudonym {
        decrypt_long_pseudonym(encrypted, &self.keys.pseudonym.secret)
    }

    /// Decrypt a long encrypted attribute.
    #[cfg(feature = "elgamal3")]
    pub fn decrypt_long_attribute(
        &self,
        encrypted: &LongEncryptedAttribute,
    ) -> Option<LongAttribute> {
        decrypt_long_attribute(encrypted, &self.keys.attribute.secret)
    }

    /// Decrypt a long encrypted attribute.
    #[cfg(not(feature = "elgamal3"))]
    pub fn decrypt_long_attribute(&self, encrypted: &LongEncryptedAttribute) -> LongAttribute {
        decrypt_long_attribute(encrypted, &self.keys.attribute.secret)
    }
}

#[cfg(feature = "offline")]
impl OfflinePEPClient {
    /// Polymorphic encrypt for long (multi-block) data types using global keys.
    /// Automatically uses the appropriate global key based on the message type.
    ///
    /// # Safety
    /// Uses unsafe pointer casts for polymorphic dispatch. Safe because:
    /// - TypeId checks ensure the correct concrete type before casting
    /// - All global key types have the same memory layout (GroupElement wrapper)
    ///
    /// # Example
    /// ```ignore
    /// let encrypted_long_pseudonym = client.encrypt_long(&long_pseudonym, rng);
    /// let encrypted_long_attribute = client.encrypt_long(&long_attribute, rng);
    /// ```
    #[allow(unsafe_code)]
    pub fn encrypt_long<L, R>(&self, message: &L, rng: &mut R) -> L::EncryptedType
    where
        L: LongEncryptable + 'static,
        L::Block: crate::core::data::HasGlobalKeys,
        R: RngCore + CryptoRng,
    {
        if TypeId::of::<L>() == TypeId::of::<LongPseudonym>() {
            let public_key = &self.global_public_keys.pseudonym;
            // SAFETY: TypeId check ensures L is LongPseudonym, so Block is Pseudonym
            unsafe {
                let public_key_ptr = public_key as *const _
                    as *const <L::Block as crate::core::data::HasGlobalKeys>::GlobalPublicKey;
                encrypt_long_global(message, &*public_key_ptr, rng)
            }
        } else if TypeId::of::<L>() == TypeId::of::<LongAttribute>() {
            let public_key = &self.global_public_keys.attribute;
            // SAFETY: TypeId check ensures L is LongAttribute, so Block is Attribute
            unsafe {
                let public_key_ptr = public_key as *const _
                    as *const <L::Block as crate::core::data::HasGlobalKeys>::GlobalPublicKey;
                encrypt_long_global(message, &*public_key_ptr, rng)
            }
        } else {
            panic!("Unsupported long message type for global encryption")
        }
    }

    /// Encrypt a long pseudonym with the global pseudonym public key.
    pub fn encrypt_long_pseudonym<R: RngCore + CryptoRng>(
        &self,
        message: &LongPseudonym,
        rng: &mut R,
    ) -> LongEncryptedPseudonym {
        encrypt_long_pseudonym_global(message, &self.global_public_keys.pseudonym, rng)
    }

    /// Encrypt a long attribute with the global attribute public key.
    pub fn encrypt_long_attribute<R: RngCore + CryptoRng>(
        &self,
        message: &LongAttribute,
        rng: &mut R,
    ) -> LongEncryptedAttribute {
        encrypt_long_attribute_global(message, &self.global_public_keys.attribute, rng)
    }
}
