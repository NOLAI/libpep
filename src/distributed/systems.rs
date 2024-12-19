//! High-level `PEPSystem`s and `PEPClient`s.

use crate::distributed::key_blinding::*;
use crate::high_level::contexts::*;
use crate::high_level::data_types::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::high_level::utils::make_rekey_factor;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct PEPSystem {
    pub(crate) pseudonymisation_secret: PseudonymizationSecret,
    pub(crate) rekeying_secret: EncryptionSecret,
    blinding_factor: BlindingFactor,
}
impl PEPSystem {
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
    pub fn session_key_share(&self, context: &EncryptionContext) -> SessionKeyShare {
        let k = make_rekey_factor(&self.rekeying_secret, context);
        make_session_key_share(&k.0, &self.blinding_factor)
    }
    pub fn rekey_info(
        &self,
        from_enc: &EncryptionContext,
        to_enc: &EncryptionContext,
    ) -> RekeyInfo {
        RekeyInfo::new(from_enc, to_enc, &self.rekeying_secret)
    }
    pub fn pseudonymization_info(
        &self,
        from_pseudo: &PseudonymizationContext,
        to_pseudo: &PseudonymizationContext,
        from_enc: &EncryptionContext,
        to_enc: &EncryptionContext,
    ) -> PseudonymizationInfo {
        PseudonymizationInfo::new(
            from_pseudo,
            to_pseudo,
            from_enc,
            to_enc,
            &self.pseudonymisation_secret,
            &self.rekeying_secret,
        )
    }
    pub fn rekey(
        &self,
        encrypted: &EncryptedDataPoint,
        rekey_info: &RekeyInfo,
    ) -> EncryptedDataPoint {
        rekey(encrypted, rekey_info)
    }
    pub fn pseudonymize(
        &self,
        encrypted: &EncryptedPseudonym,
        pseudonymization_info: &PseudonymizationInfo,
    ) -> EncryptedPseudonym {
        pseudonymize(encrypted, pseudonymization_info)
    }

    pub fn rekey_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [EncryptedDataPoint],
        rekey_info: &RekeyInfo,
        rng: &mut R,
    ) -> Box<[EncryptedDataPoint]> {
        rekey_batch(encrypted, rekey_info, rng)
    }

    pub fn pseudonymize_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut [EncryptedPseudonym],
        pseudonymization_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Box<[EncryptedPseudonym]> {
        pseudonymize_batch(encrypted, pseudonymization_info, rng)
    }

    pub fn transcrypt<E: Encrypted>(
        &self,
        encrypted: &E,
        transcryption_info: &PseudonymizationInfo,
    ) -> E {
        transcrypt(encrypted, transcryption_info)
    }

    pub fn transcrypt_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut Box<[EncryptedEntityDataPair]>,
        transcryption_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Box<[EncryptedEntityDataPair]> {
        transcrypt_batch(encrypted, transcryption_info, rng)
    }
}
#[derive(Clone)]
pub struct PEPClient {
    pub session_public_key: SessionPublicKey,
    pub(crate) session_secret_key: SessionSecretKey,
}
impl PEPClient {
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
    pub fn decrypt<E: Encrypted>(&self, encrypted: &E) -> E::UnencryptedType {
        decrypt(encrypted, &self.session_secret_key)
    }
    pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &self,
        message: &E,
        rng: &mut R,
    ) -> E::EncryptedType {
        encrypt(message, &(self.session_public_key), rng)
    }
}

#[derive(Clone)]
pub struct OfflinePEPClient {
    pub global_public_key: GlobalPublicKey,
}
impl OfflinePEPClient {
    pub fn new(global_public_key: GlobalPublicKey) -> Self {
        Self { global_public_key }
    }
    pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &self,
        message: &E,
        rng: &mut R,
    ) -> E::EncryptedType {
        encrypt_global(message, &(self.global_public_key), rng)
    }
}
