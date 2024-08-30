use std::ops::Deref;
use rand_core::OsRng;
use crate::high_level::*;
use crate::proved::*;
use crate::utils::{make_decryption_factor, make_pseudonymisation_factor};

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ProvedEncryptedPseudonym(ProvedRSKFromTo);
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ProvedEncryptedDataPoint(ProvedRekeyFromTo);

impl Deref for ProvedEncryptedPseudonym {
    type Target = ProvedRSKFromTo;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Deref for ProvedEncryptedDataPoint {
    type Target = ProvedRekeyFromTo;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl ProvedEncryptedPseudonym {
    pub fn new(value: ProvedRSKFromTo) -> Self {
        ProvedEncryptedPseudonym(value)
    }

    pub fn reconstruct(&self, original: &EncryptedPseudonym, pseudo_verifiers_from: &FactorVerifiers, pseudo_verifiers_to: &FactorVerifiers, rekey_verifiers_from: &FactorVerifiers, rekey_verifiers_to: &FactorVerifiers,) -> Option<EncryptedPseudonym> {
        let reconstructed = self.verified_reconstruct(&original, pseudo_verifiers_from, pseudo_verifiers_to, rekey_verifiers_from, rekey_verifiers_to);
        if reconstructed.is_none() {
            return None;
        }
        Some(EncryptedPseudonym::new(reconstructed.unwrap()))
    }
}
impl ProvedEncryptedDataPoint {
    pub fn new(value: ProvedRekeyFromTo) -> Self {
        ProvedEncryptedDataPoint(value)
    }
    pub fn reconstruct(&self, original: &EncryptedDataPoint, rekey_verifiers_from: &FactorVerifiers, rekey_verifiers_to: &FactorVerifiers) -> Option<EncryptedDataPoint> {
        let reconstructed = self.verified_reconstruct(&original, rekey_verifiers_from, rekey_verifiers_to);
        if reconstructed.is_none() {
            return None;
        }
        Some(EncryptedDataPoint::new(reconstructed.unwrap()))
    }
}

/// Proved pseudonymize an encrypted pseudonym, from one context to another context
pub fn proved_pseudonymize(p: &EncryptedPseudonym, from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext, pseudonymization_secret: &PseudonymizationSecret, encryption_secret: &EncryptionSecret) -> ProvedEncryptedPseudonym {
    let mut rng = OsRng;

    let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_user);
    let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_user);
    let k_from = make_decryption_factor(&encryption_secret, &from_session);
    let k_to = make_decryption_factor(&encryption_secret, &to_session);

    ProvedEncryptedPseudonym::new(prove_rsk_from_to(&p, &s_from, &s_to, &k_from, &k_to, &mut rng))
}

/// Proved rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn proved_rekey(p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext, encryption_secret: &EncryptionSecret) -> ProvedEncryptedDataPoint {
    let mut rng = OsRng;

    let k_from = make_decryption_factor(&encryption_secret, &from_session);
    let k_to = make_decryption_factor(&encryption_secret, &to_session);

    ProvedEncryptedDataPoint::new(prove_rekey_from_to(&p, &k_from, &k_to, &mut rng))
}

#[derive(Eq, PartialEq, Clone, Copy)]
pub struct RekeyVerifiers(pub FactorVerifiers);
impl Deref for RekeyVerifiers {
    type Target = FactorVerifiers;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl RekeyVerifiers {
    pub fn new(session: &EncryptionContext, encryption_secret: &EncryptionSecret) -> (RekeyVerifiers, FactorVerifiersProof) {
        let mut rng = OsRng;
        let k = make_decryption_factor(&encryption_secret, &session);
        let (v,p) = FactorVerifiers::new(&k, &mut rng);
        (RekeyVerifiers(v), p)
    }
}


#[derive(Eq, PartialEq, Clone, Copy)]
pub struct PseudonymizationVerifiers(pub FactorVerifiers);
impl Deref for PseudonymizationVerifiers {
    type Target = FactorVerifiers;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl PseudonymizationVerifiers {
    pub fn new(session: &PseudonymizationContext, pseudonymization_secret: &PseudonymizationSecret) -> (PseudonymizationVerifiers, FactorVerifiersProof) {
        let mut rng = OsRng;
        let k = make_pseudonymisation_factor(&pseudonymization_secret, &session);
        let (v,p) = FactorVerifiers::new(&k, &mut rng);
        (PseudonymizationVerifiers(v), p)
    }
}

pub fn verify_pseudonymization(msg: &ProvedEncryptedPseudonym, original: &EncryptedPseudonym, pseudo_verifiers_from: &PseudonymizationVerifiers, pseudo_verifiers_to: &PseudonymizationVerifiers, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers) -> Option<EncryptedPseudonym> {
    let reconstructed = msg.verified_reconstruct(&original, &pseudo_verifiers_from, &pseudo_verifiers_to, &rekey_verifiers_from, &rekey_verifiers_to);
    if reconstructed.is_none() {
        return None;
    }
    Some(EncryptedPseudonym::new(reconstructed.unwrap()))
}

pub fn verified_decrypt_pseudonym(x: &ProvedEncryptedPseudonym, original: &EncryptedPseudonym, sk: &SessionSecretKey, pseudo_verifiers_from: &PseudonymizationVerifiers, pseudo_verifiers_to: &PseudonymizationVerifiers, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers) -> Option<Pseudonym> {
    let reconstructed = verify_pseudonymization(x, original, pseudo_verifiers_from, pseudo_verifiers_to, rekey_verifiers_from, rekey_verifiers_to);
    if reconstructed.is_none() {
        return None;
    }
    Some(decrypt_pseudonym(&reconstructed.unwrap(), sk))
}

pub fn verify_rekey(msg: &ProvedEncryptedDataPoint, original: &EncryptedDataPoint, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers) -> Option<EncryptedDataPoint> {
    let reconstructed = msg.verified_reconstruct(&original, &rekey_verifiers_from, &rekey_verifiers_to);
    if reconstructed.is_none() {
        return None;
    }
    Some(EncryptedDataPoint::new(reconstructed.unwrap()))
}

pub fn verified_decrypt_data(x: &ProvedEncryptedDataPoint, original: &EncryptedDataPoint, sk: &SessionSecretKey, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers) -> Option<DataPoint> {
    let reconstructed = verify_rekey(x, original, rekey_verifiers_from, rekey_verifiers_to);
    if reconstructed.is_none() {
        return None;
    }
    Some(decrypt_data(&reconstructed.unwrap(), sk))
}
