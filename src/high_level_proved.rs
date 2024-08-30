use std::ops::Deref;
use rand_core::OsRng;
use crate::high_level::{DataPoint, decrypt_data, decrypt_pseudonym, EncryptedDataPoint, EncryptedPseudonym, EncryptionContext, EncryptionSecret, Pseudonym, PseudonymizationContext, PseudonymizationSecret, SessionSecretKey};
use crate::proved::{FactorVerifiers, FactorVerifiersProof, prove_rekey_from_to, prove_rsk_from_to, ProvedRekeyFromTo, ProvedRSKFromTo};
use crate::utils::{make_decryption_factor, make_pseudonymisation_factor};

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ProvedEncryptedPseudonym{
    pub value: ProvedRSKFromTo
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct ProvedEncryptedDataPoint{
    pub value: ProvedRekeyFromTo
}

impl Deref for ProvedEncryptedPseudonym {
    type Target = ProvedRSKFromTo;
    fn deref(&self) -> &Self::Target { &self.value }
}
impl Deref for ProvedEncryptedDataPoint {
    type Target = ProvedRekeyFromTo;
    fn deref(&self) -> &Self::Target { &self.value }
}

impl ProvedEncryptedPseudonym {
    pub fn new(value: ProvedRSKFromTo) -> Self {
        ProvedEncryptedPseudonym { value }
    }

    pub fn reconstruct(&self, original: &EncryptedPseudonym, pseudo_verifiers_from: &FactorVerifiers, pseudo_verifiers_to: &FactorVerifiers, rekey_verifiers_from: &FactorVerifiers, rekey_verifiers_to: &FactorVerifiers,) -> Option<EncryptedPseudonym> {
        let reconstructed = self.value.verified_reconstruct(&original.value, pseudo_verifiers_from, pseudo_verifiers_to, rekey_verifiers_from, rekey_verifiers_to);
        if reconstructed.is_none() {
            return None;
        }
        Option::from(EncryptedPseudonym::new(reconstructed.unwrap()))
    }
}
impl ProvedEncryptedDataPoint {
    pub fn new(value: ProvedRekeyFromTo) -> Self {
        ProvedEncryptedDataPoint { value }
    }
    pub fn reconstruct(&self, original: &EncryptedDataPoint, rekey_verifiers_from: &FactorVerifiers, rekey_verifiers_to: &FactorVerifiers) -> Option<EncryptedDataPoint> {
        let reconstructed = self.value.verified_reconstruct(&original.value, rekey_verifiers_from, rekey_verifiers_to);
        if reconstructed.is_none() {
            return None;
        }
        Option::from(EncryptedDataPoint::new(reconstructed.unwrap()))
    }
}

/// Proved pseudonymize an encrypted pseudonym, from one context to another context
pub fn proved_pseudonymize(p: &EncryptedPseudonym, from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext, pseudonymization_secret: &PseudonymizationSecret, encryption_secret: &EncryptionSecret) -> ProvedEncryptedPseudonym {
    let mut rng = OsRng;

    let s_from = make_pseudonymisation_factor(&pseudonymization_secret.0, &from_user.0);
    let s_to = make_pseudonymisation_factor(&pseudonymization_secret.0, &to_user.0);
    let k_from = make_decryption_factor(&encryption_secret.0, &from_session.0);
    let k_to = make_decryption_factor(&encryption_secret.0, &to_session.0);

    let original  = p.value;
    ProvedEncryptedPseudonym::new(prove_rsk_from_to(&original, &s_from, &s_to, &k_from, &k_to, &mut rng))
}

/// Proved rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn proved_rekey(p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext, encryption_secret: &EncryptionSecret) -> ProvedEncryptedDataPoint {
    let mut rng = OsRng;

    let k_from = make_decryption_factor(&encryption_secret.0, &from_session.0);
    let k_to = make_decryption_factor(&encryption_secret.0, &to_session.0);
    let original  = p.value;

    ProvedEncryptedDataPoint::new(prove_rekey_from_to(&original, &k_from, &k_to, &mut rng))
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
        let k = make_decryption_factor(&encryption_secret.0, &session.0);
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
        let k = make_pseudonymisation_factor(&pseudonymization_secret.0, &session.0);
        let (v,p) = FactorVerifiers::new(&k, &mut rng);
        (PseudonymizationVerifiers(v), p)
    }
}

pub fn proved_decrypt_pseudonym(x: &ProvedEncryptedPseudonym, original: &EncryptedPseudonym, sk: &SessionSecretKey, pseudo_verifiers_from: &PseudonymizationVerifiers, pseudo_verifiers_to: &PseudonymizationVerifiers, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers,) -> Option<Pseudonym> {
    let encrypted = x.value.verified_reconstruct(&original.value, &pseudo_verifiers_from, &pseudo_verifiers_to, &rekey_verifiers_from, &rekey_verifiers_to);
    if encrypted.is_none() {
        return None;
    }
    Option::from(decrypt_pseudonym(&EncryptedPseudonym::new(encrypted.unwrap()), sk))
}
pub fn proved_decrypt_data(x: &ProvedEncryptedDataPoint, original: &EncryptedDataPoint, sk: &SessionSecretKey, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers) -> Option<DataPoint> {
    let encrypted = x.value.verified_reconstruct(&original.value, &rekey_verifiers_from, &rekey_verifiers_to);
    if encrypted.is_none() {
        return None;
    }
    Option::from(decrypt_data(&EncryptedDataPoint::new(encrypted.unwrap()), sk))
}

/// Proved pseudonymize an encrypted pseudonym, from one context to another context
pub fn proved_re_pseudonymize(x: &ProvedEncryptedPseudonym, original: &EncryptedPseudonym, from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext, pseudonymization_secret: &PseudonymizationSecret, encryption_secret: &EncryptionSecret, pseudo_verifiers_from: &PseudonymizationVerifiers, pseudo_verifiers_to: &PseudonymizationVerifiers, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers) -> Option<ProvedEncryptedPseudonym> {
    let mut rng = OsRng;

    let s_from = make_pseudonymisation_factor(&pseudonymization_secret.0, &from_user.0);
    let s_to = make_pseudonymisation_factor(&pseudonymization_secret.0, &to_user.0);
    let k_from = make_decryption_factor(&encryption_secret.0, &from_session.0);
    let k_to = make_decryption_factor(&encryption_secret.0, &to_session.0);

    let reconstructed = x.value.verified_reconstruct(&original.value, &pseudo_verifiers_from, &pseudo_verifiers_to, &rekey_verifiers_from, &rekey_verifiers_to);
    if reconstructed.is_none() {
        return None;
    }

    Option::from(ProvedEncryptedPseudonym::new(prove_rsk_from_to(&reconstructed.unwrap(), &s_from, &s_to, &k_from, &k_to, &mut rng)))
}

/// Proved rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn proved_re_rekey(x: &ProvedEncryptedDataPoint, original: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext, encryption_secret: &EncryptionSecret, rekey_verifiers_from: &RekeyVerifiers, rekey_verifiers_to: &RekeyVerifiers) -> Option<ProvedEncryptedDataPoint> {
    let mut rng = OsRng;

    let k_from = make_decryption_factor(&encryption_secret.0, &from_session.0);
    let k_to = make_decryption_factor(&encryption_secret.0, &to_session.0);

    let reconstructed = x.value.verified_reconstruct(&original.value, &rekey_verifiers_from, &rekey_verifiers_to);
    if reconstructed.is_none() {
        return None;
    }

    Option::from(ProvedEncryptedDataPoint::new(prove_rekey_from_to(&reconstructed.unwrap(), &k_from, &k_to, &mut rng)))
}