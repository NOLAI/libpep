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
    pub(crate) pseudonymisation_secret: PseudonymizationSecret,
    pub(crate) rekeying_secret: EncryptionSecret,
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
        SessionKeyShares {
            pseudonym: self.pseudonym_session_key_share(session),
            attribute: self.attribute_session_key_share(session),
        }
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
/// A PEP client that can encrypt and decrypt data, based on separate session key pairs for pseudonyms and attributes.
#[derive(Clone)]
pub struct PEPClient {
    pub pseudonym_session_public_key: PseudonymSessionPublicKey,
    pub(crate) pseudonym_session_secret_key: PseudonymSessionSecretKey,
    pub attribute_session_public_key: AttributeSessionPublicKey,
    pub(crate) attribute_session_secret_key: AttributeSessionSecretKey,
}
impl PEPClient {
    /// Create a new PEP client from the given session key shares for both pseudonyms and attributes.
    pub fn new(
        blinded_global_pseudonym_key: BlindedGlobalSecretKey,
        pseudonym_session_key_shares: &[PseudonymSessionKeyShare],
        blinded_global_attribute_key: BlindedGlobalSecretKey,
        attribute_session_key_shares: &[AttributeSessionKeyShare],
    ) -> Self {
        let (pseudonym_public, pseudonym_secret) =
            make_pseudonym_session_key(blinded_global_pseudonym_key, pseudonym_session_key_shares);
        let (attribute_public, attribute_secret) =
            make_attribute_session_key(blinded_global_attribute_key, attribute_session_key_shares);
        Self {
            pseudonym_session_public_key: pseudonym_public,
            pseudonym_session_secret_key: pseudonym_secret,
            attribute_session_public_key: attribute_public,
            attribute_session_secret_key: attribute_secret,
        }
    }

    /// Create a new PEP client from combined session key shares.
    /// This is a convenience method that accepts a slice of [`SessionKeyShares`].
    pub fn from_session_key_shares(
        blinded_global_pseudonym_key: BlindedGlobalSecretKey,
        blinded_global_attribute_key: BlindedGlobalSecretKey,
        session_key_shares: &[SessionKeyShares],
    ) -> Self {
        let pseudonym_shares: Vec<PseudonymSessionKeyShare> =
            session_key_shares.iter().map(|s| s.pseudonym).collect();
        let attribute_shares: Vec<AttributeSessionKeyShare> =
            session_key_shares.iter().map(|s| s.attribute).collect();
        Self::new(
            blinded_global_pseudonym_key,
            &pseudonym_shares,
            blinded_global_attribute_key,
            &attribute_shares,
        )
    }

    /// Create a new PEP client from the given session key pairs.
    pub fn restore(
        pseudonym_session_public_key: PseudonymSessionPublicKey,
        pseudonym_session_secret_key: PseudonymSessionSecretKey,
        attribute_session_public_key: AttributeSessionPublicKey,
        attribute_session_secret_key: AttributeSessionSecretKey,
    ) -> Self {
        Self {
            pseudonym_session_public_key,
            pseudonym_session_secret_key,
            attribute_session_public_key,
            attribute_session_secret_key,
        }
    }

    /// Dump the session key pairs.
    pub fn dump(
        &self,
    ) -> (
        PseudonymSessionPublicKey,
        PseudonymSessionSecretKey,
        AttributeSessionPublicKey,
        AttributeSessionSecretKey,
    ) {
        (
            self.pseudonym_session_public_key,
            self.pseudonym_session_secret_key,
            self.attribute_session_public_key,
            self.attribute_session_secret_key,
        )
    }

    /// Update a pseudonym session key share from one session to the other
    pub fn update_pseudonym_session_secret_key(
        &mut self,
        old_key_share: PseudonymSessionKeyShare,
        new_key_share: PseudonymSessionKeyShare,
    ) {
        (
            self.pseudonym_session_public_key,
            self.pseudonym_session_secret_key,
        ) = update_pseudonym_session_key(
            self.pseudonym_session_secret_key,
            old_key_share,
            new_key_share,
        )
    }

    /// Update an attribute session key share from one session to the other
    pub fn update_attribute_session_secret_key(
        &mut self,
        old_key_share: AttributeSessionKeyShare,
        new_key_share: AttributeSessionKeyShare,
    ) {
        (
            self.attribute_session_public_key,
            self.attribute_session_secret_key,
        ) = update_attribute_session_key(
            self.attribute_session_secret_key,
            old_key_share,
            new_key_share,
        )
    }

    /// Update both pseudonym and attribute session key shares from one session to another.
    /// This is a convenience method that updates both shares together.
    pub fn update_session_secret_keys(
        &mut self,
        old_key_shares: SessionKeyShares,
        new_key_shares: SessionKeyShares,
    ) {
        self.update_pseudonym_session_secret_key(
            old_key_shares.pseudonym,
            new_key_shares.pseudonym,
        );
        self.update_attribute_session_secret_key(
            old_key_shares.attribute,
            new_key_shares.attribute,
        );
    }

    /// Polymorphic encrypt that works for both pseudonyms and attributes.
    /// Uses the appropriate session key based on the message type.
    ///
    /// # Example
    /// ```ignore
    /// let encrypted_pseudonym = client.encrypt(&pseudonym, &client.pseudonym_session_public_key, rng);
    /// let encrypted_attribute = client.encrypt(&attribute, &client.attribute_session_public_key, rng);
    /// ```
    pub fn encrypt<M, R, P>(&self, message: &M, public_key: &P, rng: &mut R) -> M::EncryptedType
    where
        M: HasSessionKeys<SessionPublicKey = P>,
        P: PublicKey,
        R: RngCore + CryptoRng,
    {
        encrypt(message, public_key, rng)
    }

    /// Polymorphic decrypt that works for both encrypted pseudonyms and attributes.
    /// Uses the appropriate session key based on the encrypted message type.
    ///
    /// # Example
    /// ```ignore
    /// let pseudonym = client.decrypt(&encrypted_pseudonym, &client.pseudonym_session_secret_key);
    /// let attribute = client.decrypt(&encrypted_attribute, &client.attribute_session_secret_key);
    /// ```
    pub fn decrypt<E, S>(&self, encrypted: &E, secret_key: &S) -> E::UnencryptedType
    where
        E: Encrypted,
        E::UnencryptedType: HasSessionKeys<SessionSecretKey = S>,
        S: SecretKey,
    {
        decrypt(encrypted, secret_key)
    }

    /// Encrypt a pseudonym with the pseudonym session public key.
    pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
        &self,
        message: &Pseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        encrypt_pseudonym(message, &self.pseudonym_session_public_key, rng)
    }

    /// Encrypt an attribute with the attribute session public key.
    pub fn encrypt_attribute<R: RngCore + CryptoRng>(
        &self,
        message: &Attribute,
        rng: &mut R,
    ) -> EncryptedAttribute {
        encrypt_attribute(message, &self.attribute_session_public_key, rng)
    }

    /// Decrypt an encrypted pseudonym.
    pub fn decrypt_pseudonym(&self, encrypted: &EncryptedPseudonym) -> Pseudonym {
        decrypt_pseudonym(encrypted, &self.pseudonym_session_secret_key)
    }

    /// Decrypt an encrypted attribute.
    pub fn decrypt_attribute(&self, encrypted: &EncryptedAttribute) -> Attribute {
        decrypt_attribute(encrypted, &self.attribute_session_secret_key)
    }
}

/// An offline PEP client that can encrypt data, based on global public keys for pseudonyms and attributes.
/// This client is used for encryption only, and does not have session key pairs.
/// This can be useful when encryption is done offline and no session key pairs are available,
/// or when using a session key would leak information.
#[derive(Clone)]
pub struct OfflinePEPClient {
    pub global_pseudonym_public_key: PseudonymGlobalPublicKey,
    pub global_attribute_public_key: AttributeGlobalPublicKey,
}
impl OfflinePEPClient {
    /// Create a new offline PEP client from the given global public keys.
    pub fn new(
        global_pseudonym_public_key: PseudonymGlobalPublicKey,
        global_attribute_public_key: AttributeGlobalPublicKey,
    ) -> Self {
        Self {
            global_pseudonym_public_key,
            global_attribute_public_key,
        }
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
        encrypt_pseudonym_global(message, &self.global_pseudonym_public_key, rng)
    }

    /// Encrypt an attribute with the global attribute public key.
    pub fn encrypt_attribute<R: RngCore + CryptoRng>(
        &self,
        message: &Attribute,
        rng: &mut R,
    ) -> EncryptedAttribute {
        encrypt_attribute_global(message, &self.global_attribute_public_key, rng)
    }
}
