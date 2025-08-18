//! High-level [`PEPSystem`]s and [`PEPClient`]s.

use crate::distributed::key_blinding::*;
use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::high_level::utils::make_rekey_factor;
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
    /// Generate a session key share for the given session.
    pub fn session_key_share(&self, session: &EncryptionContext) -> SessionKeyShare {
        let k = make_rekey_factor(&self.rekeying_secret, session);
        make_session_key_share(&k.0, &self.blinding_factor)
    }
    /// Generate a rekey info to rekey from a given [`EncryptionContext`] to another.
    pub fn rekey_info(
        &self,
        session_from: Option<&EncryptionContext>,
        session_to: Option<&EncryptionContext>,
    ) -> RekeyInfo {
        RekeyInfo::new(session_from, session_to, &self.rekeying_secret)
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
    /// Rekey an [`EncryptedDataPoint`] from one session to another, using [`RekeyInfo`].
    pub fn rekey(
        &self,
        encrypted: &EncryptedDataPoint,
        rekey_info: &RekeyInfo,
    ) -> EncryptedDataPoint {
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

    /// Rekey a batch of [`EncryptedDataPoint`]s from one session to another, using
    /// [`RekeyInfo`].
    pub fn rekey_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [EncryptedDataPoint],
        rekey_info: &RekeyInfo,
        rng: &mut R,
    ) -> Box<[EncryptedDataPoint]> {
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

    /// Transcrypt (rekey or pseudonymize) an encrypted message from one pseudonymization domain and
    /// session to another, using [`TranscryptionInfo`].
    pub fn transcrypt<E: Encrypted>(
        &self,
        encrypted: &E,
        transcryption_info: &PseudonymizationInfo,
    ) -> E {
        transcrypt(encrypted, transcryption_info)
    }

    /// Transcrypt a batch of encrypted messages for one entity (see [`EncryptedEntityData`]),
    /// from one pseudonymization domain and session to another, using [`TranscryptionInfo`].
    pub fn transcrypt_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut Box<[EncryptedEntityData]>,
        transcryption_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Box<[EncryptedEntityData]> {
        transcrypt_batch(encrypted, transcryption_info, rng)
    }
}
/// A PEP client that can encrypt and decrypt data, based on a session key pair.
#[derive(Clone)]
pub struct PEPClient {
    pub session_public_key: SessionPublicKey,
    pub(crate) session_secret_key: SessionSecretKey,
}
impl PEPClient {
    /// Create a new PEP client from the given session key shares.
    pub fn new(
        blinded_global_private_key: BlindedGlobalSecretKey,
        session_key_shares: &[SessionKeyShare],
    ) -> Self {
        let (public, secret) = make_session_key(blinded_global_private_key, session_key_shares);
        Self {
            session_public_key: public,
            session_secret_key: secret,
        }
    }

    /// Create a new PEP client from the given session key pair.
    pub fn restore(
        session_public_key: SessionPublicKey,
        session_secret_key: SessionSecretKey,
    ) -> Self {
        Self {
            session_public_key,
            session_secret_key,
        }
    }

    /// Dump the session key pair.
    pub fn dump(&self) -> (SessionPublicKey, SessionSecretKey) {
        (self.session_public_key, self.session_secret_key)
    }

    /// Update a session key share from one session to the other
    pub fn update_session_secret_key(
        &mut self,
        old_key_share: SessionKeyShare,
        new_key_share: SessionKeyShare,
    ) {
        (self.session_public_key, self.session_secret_key) =
            update_session_key(self.session_secret_key, old_key_share, new_key_share)
    }

    /// Decrypt an encrypted message.
    pub fn decrypt<E: Encrypted>(&self, encrypted: &E) -> E::UnencryptedType {
        decrypt(encrypted, &self.session_secret_key)
    }
    /// Encrypt a message with the session public key.
    pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &self,
        message: &E,
        rng: &mut R,
    ) -> E::EncryptedType {
        encrypt(message, &(self.session_public_key), rng)
    }
}

/// An offline PEP client that can encrypt data, based on a global public key.
/// This client is used for encryption only, and does not have a session key pair.
/// This can be useful when encryption is done offline and no session key pair is available,
/// or when using a session key would leak information.
#[derive(Clone)]
pub struct OfflinePEPClient {
    pub global_public_key: GlobalPublicKey,
}
impl OfflinePEPClient {
    /// Create a new offline PEP client from the given global public key.
    pub fn new(global_public_key: GlobalPublicKey) -> Self {
        Self { global_public_key }
    }
    /// Encrypt a message with the global public key.
    pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &self,
        message: &E,
        rng: &mut R,
    ) -> E::EncryptedType {
        encrypt_global(message, &(self.global_public_key), rng)
    }
}
