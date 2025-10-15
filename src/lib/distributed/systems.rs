//! High-level [`PEPSystem`]s and [`PEPClient`]s.

use crate::distributed::key_blinding::*;
use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::high_level::secrets::{
    make_attribute_rekey_factor, make_pseudonym_rekey_factor, EncryptionSecret,
    PseudonymizationSecret,
};
use rand_core::{CryptoRng, RngCore};

/// A PEP transcryptor system that can [pseudonymize] and [rekey] data, based on
/// a pseudonymisation secret, a rekeying secret and a blinding factor.
#[derive(Clone)]
pub struct PEPSystem {
    pseudonymisation_secret: PseudonymizationSecret,
    rekeying_secret: EncryptionSecret,
    blinding_factor: BlindingFactor,
}
impl PEPSystem {
    /// Create a new PEP system with the given secrets and blinding factor.
    pub fn new(
        pseudonymisation_secret: PseudonymizationSecret,
        rekeying_secret: EncryptionSecret,
        blinding_factor: BlindingFactor,
    ) -> Self {
        Self {
            pseudonymisation_secret,
            rekeying_secret,
            blinding_factor,
        }
    }
    /// Generate a pseudonym session key share for the given session.
    pub fn pseudonym_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> PseudonymSessionKeyShare {
        let k = make_pseudonym_rekey_factor(&self.rekeying_secret, session);
        make_pseudonym_session_key_share(&k.0, &self.blinding_factor)
    }
    /// Generate an attribute session key share for the given session.
    pub fn attribute_session_key_share(
        &self,
        session: &EncryptionContext,
    ) -> AttributeSessionKeyShare {
        let k = make_attribute_rekey_factor(&self.rekeying_secret, session);
        make_attribute_session_key_share(&k.0, &self.blinding_factor)
    }

    /// Generate both pseudonym and attribute session key shares for the given session.
    /// This is a convenience method that returns both shares together.
    pub fn session_key_shares(&self, session: &EncryptionContext) -> SessionKeyShares {
        let pseudonym_rekey_factor = make_pseudonym_rekey_factor(&self.rekeying_secret, session);
        let attribute_rekey_factor = make_attribute_rekey_factor(&self.rekeying_secret, session);
        make_session_key_shares(
            &pseudonym_rekey_factor.0,
            &attribute_rekey_factor.0,
            &self.blinding_factor,
        )
    }
    /// Generate an attribute rekey info to rekey attributes from a given [`EncryptionContext`] to another.
    pub fn attribute_rekey_info(
        &self,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> AttributeRekeyInfo {
        AttributeRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }
    /// Generate a pseudonym rekey info to rekey pseudonyms from a given [`EncryptionContext`] to another.
    pub fn pseudonym_rekey_info(
        &self,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> PseudonymRekeyInfo {
        PseudonymRekeyInfo::new(session_from, session_to, &self.rekeying_secret)
    }
    /// Generate a pseudonymization info to pseudonymize from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    pub fn pseudonymization_info(
        &self,
        domain_form: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> PseudonymizationInfo {
        PseudonymizationInfo::new(
            domain_form,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }
    /// Rekey an [`EncryptedAttribute`] from one session to another, using [`AttributeRekeyInfo`].
    pub fn rekey(
        &self,
        encrypted: &EncryptedAttribute,
        rekey_info: &AttributeRekeyInfo,
    ) -> EncryptedAttribute {
        rekey(encrypted, rekey_info)
    }
    /// Pseudonymize an [`EncryptedPseudonym`] from one pseudonymization domain and session to
    /// another, using [`PseudonymizationInfo`].
    pub fn pseudonymize(
        &self,
        encrypted: &EncryptedPseudonym,
        pseudonymization_info: &PseudonymizationInfo,
    ) -> EncryptedPseudonym {
        pseudonymize(encrypted, pseudonymization_info)
    }

    /// Rekey a batch of [`EncryptedAttribute`]s from one session to another, using
    /// [`AttributeRekeyInfo`].
    pub fn rekey_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [EncryptedAttribute],
        rekey_info: &AttributeRekeyInfo,
        rng: &mut R,
    ) -> Box<[EncryptedAttribute]> {
        rekey_batch(encrypted, rekey_info, rng)
    }

    /// Pseudonymize a batch of [`EncryptedPseudonym`]s from one pseudonymization domain and
    /// session to another, using [`PseudonymizationInfo`].
    pub fn pseudonymize_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [EncryptedPseudonym],
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Box<[EncryptedPseudonym]> {
        pseudonymize_batch(encrypted, pseudonymization_info, rng)
    }

    /// Generate transcryption info to transcrypt from a given [`PseudonymizationDomain`]
    /// and [`EncryptionContext`] to another.
    pub fn transcryption_info(
        &self,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> TranscryptionInfo {
        TranscryptionInfo::new(
            domain_from,
            domain_to,
            session_from,
            session_to,
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }

    /// Transcrypt (rekey or pseudonymize) an encrypted message from one pseudonymization domain and
    /// session to another, using [`TranscryptionInfo`].
    pub fn transcrypt<E: Transcryptable>(
        &self,
        encrypted: &E,
        transcryption_info: &TranscryptionInfo,
    ) -> E {
        transcrypt(encrypted, transcryption_info)
    }

    /// Transcrypt a batch of encrypted messages for one entity (see [`EncryptedData`]),
    /// from one pseudonymization domain and session to another, using [`TranscryptionInfo`].
    pub fn transcrypt_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut Box<[EncryptedData]>,
        transcryption_info: &TranscryptionInfo,
        rng: &mut R,
    ) -> Box<[EncryptedData]> {
        transcrypt_batch(encrypted, transcryption_info, rng)
    }
}

/// A PEP client that can encrypt and decrypt data, based on session key pairs for pseudonyms and attributes.
#[derive(Clone)]
pub struct PEPClient {
    keys: SessionKeys,
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

    /// Get the appropriate public key for a given message type.
    fn get_public_key_for<M>(&self) -> &M::SessionPublicKey
    where
        M: HasSessionKeys + 'static,
    {
        use std::any::TypeId;

        if TypeId::of::<M>() == TypeId::of::<Pseudonym>() {
            // Safe because we've checked the type
            unsafe { &*(&self.keys.pseudonym.public as *const _ as *const M::SessionPublicKey) }
        } else if TypeId::of::<M>() == TypeId::of::<Attribute>() {
            unsafe { &*(&self.keys.attribute.public as *const _ as *const M::SessionPublicKey) }
        } else {
            panic!("Unsupported message type")
        }
    }

    /// Get the appropriate secret key for a given encrypted message type.
    fn get_secret_key_for<E>(&self) -> &<E::UnencryptedType as HasSessionKeys>::SessionSecretKey
    where
        E: Encrypted,
        E::UnencryptedType: HasSessionKeys + 'static,
    {
        use std::any::TypeId;

        if TypeId::of::<E::UnencryptedType>() == TypeId::of::<Pseudonym>() {
            unsafe {
                &*(&self.keys.pseudonym.secret as *const _
                    as *const <E::UnencryptedType as HasSessionKeys>::SessionSecretKey)
            }
        } else if TypeId::of::<E::UnencryptedType>() == TypeId::of::<Attribute>() {
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
        M: HasSessionKeys + 'static,
        R: RngCore + CryptoRng,
    {
        let public_key = self.get_public_key_for::<M>();
        encrypt(message, public_key, rng)
    }

    /// Polymorphic decrypt that works for both encrypted pseudonyms and attributes.
    /// Automatically uses the appropriate session key based on the encrypted message type.
    ///
    /// # Example
    /// ```ignore
    /// let pseudonym = client.decrypt(&encrypted_pseudonym);
    /// let attribute = client.decrypt(&encrypted_attribute);
    /// ```
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
    pub fn decrypt_pseudonym(&self, encrypted: &EncryptedPseudonym) -> Pseudonym {
        decrypt_pseudonym(encrypted, &self.keys.pseudonym.secret)
    }

    /// Decrypt an encrypted attribute.
    pub fn decrypt_attribute(&self, encrypted: &EncryptedAttribute) -> Attribute {
        decrypt_attribute(encrypted, &self.keys.attribute.secret)
    }
}

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
