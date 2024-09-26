use std::ops::Deref;
use rand_core::OsRng;
use crate::arithmetic::*;
use crate::utils::*;
use crate::high_level::*;
use crate::high_level_proved::*;
use crate::proved::FactorVerifiersProof;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlindingFactor(pub ScalarNonZero);
impl Deref for BlindingFactor {
    type Target = ScalarNonZero;
    fn deref(&self) -> &Self::Target { &self.0 }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BlindedGlobalSecretKey(pub ScalarNonZero);
impl Deref for BlindedGlobalSecretKey {
    type Target = ScalarNonZero;
    fn deref(&self) -> &Self::Target { &self.0 }
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SessionKeyShare(pub ScalarNonZero);
impl Deref for SessionKeyShare {
    type Target = ScalarNonZero;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl BlindingFactor {
    pub fn new(x: ScalarNonZero) -> Self {
        BlindingFactor(x)
    }
    pub fn random() -> Self {
        BlindingFactor(ScalarNonZero::random(&mut OsRng))
    }
}
pub fn make_blinded_global_secret_key(global_secret_key: &GlobalSecretKey, blinding_factors: &Vec<BlindingFactor>) -> BlindedGlobalSecretKey {
    let y = global_secret_key.clone();
    let x = blinding_factors.iter().fold(*y, |acc, x| acc * x.deref());
    BlindedGlobalSecretKey(x)
}
#[must_use]
pub fn verify_pseudonym_transcryption(messages: &Vec<ProvedEncryptedPseudonym>, original: &EncryptedPseudonym, pseudo_verifiers_from: &Vec<PseudonymizationVerifiers>, pseudo_verifiers_to: &Vec<PseudonymizationVerifiers>, rekey_verifiers_from: &Vec<RekeyVerifiers>, rekey_verifiers_to: &Vec<RekeyVerifiers>) -> Option<EncryptedPseudonym> {
    assert!(messages.len() <= pseudo_verifiers_from.len());
    assert!(messages.len() <= pseudo_verifiers_to.len());
    assert!(messages.len() <= rekey_verifiers_from.len());
    assert!(messages.len() <= rekey_verifiers_to.len());

    let mut previous = original.clone();

    for i in 0..messages.len() {
        let current = &messages[i];
        let pseudo_verifiers_from = &pseudo_verifiers_from[i];
        let pseudo_verifiers_to = &pseudo_verifiers_to[i];
        let rekey_verifiers_from = &rekey_verifiers_from[i];
        let rekey_verifiers_to = &rekey_verifiers_to[i];

        let reconstructed = verify_pseudonymization(current, &previous, pseudo_verifiers_from, pseudo_verifiers_to, rekey_verifiers_from, rekey_verifiers_to);
        if reconstructed.is_none() {
            return None;
        }
        previous = reconstructed.unwrap();
    }
    Some(previous)
}
#[must_use]
pub fn verify_data_transcryption(messages: &Vec<ProvedEncryptedDataPoint>, original: &EncryptedDataPoint, rekey_verifiers_from: &Vec<RekeyVerifiers>, rekey_verifiers_to: &Vec<RekeyVerifiers>) -> Option<EncryptedDataPoint> {
    assert!(messages.len() <= rekey_verifiers_from.len());
    assert!(messages.len() <= rekey_verifiers_to.len());

    let mut previous = original.clone();

    for i in 0..messages.len() {
        let current = &messages[i];
        let rekey_verifiers_from = &rekey_verifiers_from[i];
        let rekey_verifiers_to = &rekey_verifiers_to[i];

        let reconstructed = verify_rekey(current, &previous, rekey_verifiers_from, rekey_verifiers_to);
        if reconstructed.is_none() {
            return None;
        }
        previous = reconstructed.unwrap();
    }
    Some(previous)
}

#[derive(Clone)]
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
        let k = make_decryption_factor(&self.rekeying_secret, &context);
        SessionKeyShare(k * &self.blinding_factor.invert())
    }

    pub fn rekey(&self, p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext) -> EncryptedDataPoint {
        rekey(&p, from_session, to_session, &self.rekeying_secret)
    }
    pub fn pseudonymize(&self, p: &EncryptedPseudonym, from_context: &PseudonymizationContext, to_context: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext) -> EncryptedPseudonym {
        pseudonymize(&p, from_context, to_context, from_session, to_session, &self.pseudonymisation_secret, &self.rekeying_secret)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: EncryptedPseudonym) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: EncryptedDataPoint) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted)
    }
    pub fn pseudo_verifiers(&self, session: &PseudonymizationContext) -> (PseudonymizationVerifiers, FactorVerifiersProof) {
        PseudonymizationVerifiers::new(session, &self.pseudonymisation_secret)
    }
    pub fn rekey_verifiers(&self, session: &EncryptionContext) -> (RekeyVerifiers, FactorVerifiersProof) {
        RekeyVerifiers::new(session, &self.rekeying_secret)
    }
    pub fn proved_pseudonymize(&self, p: &EncryptedPseudonym, from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext) -> ProvedEncryptedPseudonym {
        proved_pseudonymize(&p, from_user, to_user, from_session, to_session, &self.pseudonymisation_secret, &self.rekeying_secret)
    }
    pub fn proved_rekey(&self, p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext) -> ProvedEncryptedDataPoint {
        proved_rekey(&p, from_session, to_session, &self.rekeying_secret)
    }
    pub fn proved_distributed_pseudonymize(&self, messages: &Vec<ProvedEncryptedPseudonym>, original: &EncryptedPseudonym, pseudo_verifiers_from: &Vec<PseudonymizationVerifiers>, pseudo_verifiers_to: &Vec<PseudonymizationVerifiers>, rekey_verifiers_from: &Vec<RekeyVerifiers>, rekey_verifiers_to: &Vec<RekeyVerifiers>, from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext) -> Option<ProvedEncryptedPseudonym> {
        if messages.len() == 0 {
            return Some(self.proved_pseudonymize(original, from_user, to_user, from_session, to_session))
        }
        let result = verify_pseudonym_transcryption(messages, original, pseudo_verifiers_from, pseudo_verifiers_to, rekey_verifiers_from, rekey_verifiers_to);
        result.map(|x| proved_pseudonymize(&x, from_user, to_user, from_session, to_session, &self.pseudonymisation_secret, &self.rekeying_secret))
    }
    pub fn proved_distributed_rekey(&self, messages: &Vec<ProvedEncryptedDataPoint>, original: &EncryptedDataPoint, rekey_verifiers_from: &Vec<RekeyVerifiers>, rekey_verifiers_to: &Vec<RekeyVerifiers>, from_session: &EncryptionContext, to_session: &EncryptionContext) -> Option<ProvedEncryptedDataPoint> {
        if messages.len() == 0 {
            return Some(self.proved_rekey(original, from_session, to_session))
        }
        let result = verify_data_transcryption(messages, original, rekey_verifiers_from, rekey_verifiers_to);
        result.map(|x| proved_rekey(&x, from_session, to_session, &self.rekeying_secret))
    }

}


pub struct PEPClient {
    session_secret_key: SessionSecretKey,
    session_public_key: SessionPublicKey,
}
impl PEPClient {
    pub fn new(blinded_global_private_key: BlindedGlobalSecretKey, session_key_shares: Vec<SessionKeyShare>) -> Self {
        let secret_key = SessionSecretKey(session_key_shares.iter().fold(*blinded_global_private_key, |acc, x| acc * x.deref()));
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

    pub fn encrypt_data(&self, data: &DataPoint) -> EncryptedDataPoint {
        encrypt_data(data, &(self.session_public_key))
    }

    pub fn encrypt_pseudonym(&self, p: &Pseudonym) -> EncryptedPseudonym {
        encrypt_pseudonym(p, &(self.session_public_key))
    }
    pub fn verified_decrypt_pseudonym(&self, messages: &Vec<ProvedEncryptedPseudonym>, original: &EncryptedPseudonym, pseudo_verifiers_from: &Vec<PseudonymizationVerifiers>, pseudo_verifiers_to: &Vec<PseudonymizationVerifiers>, rekey_verifiers_from: &Vec<RekeyVerifiers>, rekey_verifiers_to: &Vec<RekeyVerifiers>) -> Option<Pseudonym> {
        let result = verify_pseudonym_transcryption(messages, original, pseudo_verifiers_from, pseudo_verifiers_to, rekey_verifiers_from, rekey_verifiers_to);
        result.map(|x| decrypt_pseudonym(&x, &self.session_secret_key))
    }
    pub fn verified_decrypt_data(&self, messages: &Vec<ProvedEncryptedDataPoint>, original: &EncryptedDataPoint, rekey_verifiers_from: &Vec<RekeyVerifiers>, rekey_verifiers_to: &Vec<RekeyVerifiers>) -> Option<DataPoint> {
        let result = verify_data_transcryption(messages, original, rekey_verifiers_from, rekey_verifiers_to);
        result.map(|x| decrypt_data(&x, &self.session_secret_key))
    }

    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym(&self, encrypted: EncryptedPseudonym) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted)
    }

    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point(&self, encrypted: EncryptedDataPoint) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted)
    }
}
