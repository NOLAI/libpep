use rand_core::OsRng;
use crate::arithmetic::*;
use crate::utils::*;
use crate::high_level::*;

pub struct BlindingFactor(ScalarNonZero);
pub struct BlindedGlobalSecretKey(ScalarNonZero);
pub struct SessionKeyShare(ScalarNonZero);

pub fn make_blinding_factor() -> BlindingFactor {
    let mut rng = OsRng;
    BlindingFactor(ScalarNonZero::random(&mut rng))
}

pub fn make_blinded_global_secret_key(global_secret_key: GlobalSecretKey, blinding_factors: Vec<BlindingFactor>) -> BlindedGlobalSecretKey {
    let x = blinding_factors.iter().fold(global_secret_key.0, |acc, x| acc * x.0);
    BlindedGlobalSecretKey(x)
}


pub struct PEPSystem {
    pseudonymisation_secret: PseudonymizationSecret,
    rekeying_secret: EncryptionSecret,
    blinding_factor: BlindingFactor,
}

impl PEPSystem {
    pub fn new(pseudonymisation_secret: PseudonymizationSecret, rekeying_secret: EncryptionSecret, blinding_factor: BlindingFactor) -> Self {
        Self {
            pseudonymisation_secret,
            rekeying_secret,
            blinding_factor,
        }
    }

    pub fn session_key_share(&self, context: &EncryptionContext) -> SessionKeyShare {
        let k = make_decryption_factor(&self.rekeying_secret.0, &context.0);
        SessionKeyShare(k * &self.blinding_factor.0.invert())
    }

    pub fn rekey(&self, p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext) -> EncryptedDataPoint {
        rekey(&p, from_session, to_session, &self.rekeying_secret)
    }
    pub fn pseudonymize(&self, p: &EncryptedPseudonym, from_context: &PseudonymizationContext, to_context: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext) -> EncryptedPseudonym {
        pseudonymize(&p, from_context, to_context, from_session, to_session, &self.pseudonymisation_secret, &self.rekeying_secret)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: EncryptedPseudonym) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(encrypted)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: EncryptedDataPoint) -> EncryptedDataPoint {
        rerandomize_encrypted(encrypted)
    }
}


pub struct PEPClient {
    session_secret_key: SessionSecretKey,
    session_public_key: SessionPublicKey,
}
impl PEPClient {
    pub fn new(blinded_global_private_key: BlindedGlobalSecretKey, session_key_shares: Vec<SessionKeyShare>) -> Self {
        let secret_key = SessionSecretKey(session_key_shares.iter().fold(blinded_global_private_key.0, |acc, x| acc * x.0));
        let public_key = SessionPublicKey(secret_key.0 * &G);
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

    pub fn encrypt_data(&self, data: &DataPoint) -> EncryptedDataPoint {
        encrypt_data(data, &(self.session_public_key))
    }

    pub fn encrypt_pseudonym(&self, p: &Pseudonym) -> EncryptedPseudonym {
        encrypt_pseudonym(p, &(self.session_public_key))
    }

    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: EncryptedPseudonym) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(encrypted)
    }

    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: EncryptedDataPoint) -> EncryptedDataPoint {
        rerandomize_encrypted(encrypted)
    }
}
