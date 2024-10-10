use crate::arithmetic::*;
use crate::high_level::*;
use crate::utils::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct BlindingFactor(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct BlindedGlobalSecretKey(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct SessionKeyShare(pub ScalarNonZero);
impl BlindingFactor {
    pub fn new(x: ScalarNonZero) -> Self {
        BlindingFactor(x)
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        BlindingFactor(ScalarNonZero::random(rng))
    }
}
pub fn make_blinded_global_secret_key(
    global_secret_key: &GlobalSecretKey,
    blinding_factors: &Vec<BlindingFactor>,
) -> BlindedGlobalSecretKey {
    let y = global_secret_key.clone();
    let x = blinding_factors.iter().fold(*y, |acc, x| acc * x.deref());
    BlindedGlobalSecretKey(x)
}
pub type PEPSystemID = String;

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
        let k = make_decryption_factor(&self.rekeying_secret, &context);
        SessionKeyShare(*k * &self.blinding_factor.invert())
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
    pub fn rekey(&self, p: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
        rekey(p, rekey_info)
    }
    pub fn pseudonymize(
        &self,
        p: &EncryptedPseudonym,
        pseudonymization_info: &PseudonymizationInfo,
    ) -> EncryptedPseudonym {
        pseudonymize(p, pseudonymization_info)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedPseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedDataPoint,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, rng)
    }
}

#[derive(Clone)]
pub struct PEPClient {
    pub(crate) session_secret_key: SessionSecretKey,
    session_public_key: SessionPublicKey,
}
impl PEPClient {
    pub fn new(
        blinded_global_private_key: BlindedGlobalSecretKey,
        session_key_shares: Vec<SessionKeyShare>,
    ) -> Self {
        let secret_key = SessionSecretKey(
            session_key_shares
                .iter()
                .fold(*blinded_global_private_key, |acc, x| acc * x.deref()),
        );
        let public_key = SessionPublicKey(secret_key.deref() * &G);
        Self {
            session_secret_key: secret_key,
            session_public_key: public_key,
        }
    }
    pub fn decrypt_pseudonym(&self, p: &EncryptedPseudonym) -> Pseudonym {
        decrypt_pseudonym(&p, &self.session_secret_key)
    }
    pub fn decrypt_data(&self, data: &EncryptedDataPoint) -> DataPoint {
        decrypt_data(&data, &self.session_secret_key)
    }
    pub fn encrypt_data<R: RngCore + CryptoRng>(
        &self,
        data: &DataPoint,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        encrypt_data(data, &(self.session_public_key), rng)
    }
    pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
        &self,
        p: &Pseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        encrypt_pseudonym(p, &(self.session_public_key), rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedPseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedDataPoint,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, rng)
    }
}
