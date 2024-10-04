use crate::arithmetic::{GroupElement, ScalarNonZero, G};
use crate::elgamal::{decrypt, encrypt, ElGamal};
use crate::primitives::*;
use crate::utils::{make_decryption_factor, make_pseudonymisation_factor};
use derive_more::Deref;
use rand_core::{CryptoRng, RngCore};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct SessionSecretKey(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct GlobalSecretKey(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct SessionPublicKey(pub GroupElement);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct GlobalPublicKey(pub GroupElement);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct Pseudonym {
    pub value: GroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct DataPoint {
    pub value: GroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct EncryptedDataPoint {
    pub value: ElGamal,
}
pub type Context = String;
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref)]
pub struct PseudonymizationContext(pub Context);
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref)]
pub struct EncryptionContext(pub Context);
pub type Secret = String;
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref)]
pub struct PseudonymizationSecret(pub Secret);
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref)]
pub struct EncryptionSecret(pub Secret);
impl Pseudonym {
    pub fn new(value: GroupElement) -> Self {
        Pseudonym { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Pseudonym::new(GroupElement::random(rng))
    }
}
impl DataPoint {
    pub fn new(value: GroupElement) -> Self {
        DataPoint { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        DataPoint::new(GroupElement::random(rng))
    }
}
impl EncryptedPseudonym {
    pub fn new(value: ElGamal) -> Self {
        EncryptedPseudonym { value }
    }
}
impl EncryptedDataPoint {
    pub fn new(value: ElGamal) -> Self {
        EncryptedDataPoint { value }
    }
}

/// Generate a new global key pair
pub fn make_global_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (GlobalPublicKey, GlobalSecretKey) {
    let sk = ScalarNonZero::random(rng);
    let pk = sk * G;
    (GlobalPublicKey(pk), GlobalSecretKey(sk))
}

/// Generate a subkey from a global secret key, a context, and an encryption secret
pub fn make_session_keys(global: &GlobalSecretKey, context: &EncryptionContext, encryption_secret: &EncryptionSecret) -> (SessionPublicKey, SessionSecretKey) {
    let k = make_decryption_factor(encryption_secret, context);
    let sk = *k * global.deref();
    let pk = sk * G;
    (SessionPublicKey(pk), SessionSecretKey(sk))
}

/// Encrypt a pseudonym
pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(p: &Pseudonym, pk: &SessionPublicKey, rng: &mut R) -> EncryptedPseudonym {
    EncryptedPseudonym::new(encrypt(p, pk, rng))
}

/// Decrypt an encrypted pseudonym
pub fn decrypt_pseudonym(p: &EncryptedPseudonym, sk: &SessionSecretKey) -> Pseudonym {
    Pseudonym::new(decrypt(p, sk))
}

/// Encrypt a data point
pub fn encrypt_data<R: RngCore + CryptoRng>(data: &DataPoint, pk: &SessionPublicKey, rng: &mut R) -> EncryptedDataPoint {
    EncryptedDataPoint::new(encrypt(data, pk, rng))
}

/// Decrypt an encrypted data point
pub fn decrypt_data(data: &EncryptedDataPoint, sk: &SessionSecretKey) -> DataPoint {
    DataPoint::new(decrypt(&data, &sk))
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct RerandomizeFactor(ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct ReshuffleFactor(ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref)]
pub struct RekeyFactor(ScalarNonZero);
impl From<ScalarNonZero> for RerandomizeFactor {
    fn from(x: ScalarNonZero) -> Self {
        RerandomizeFactor(x)
    }
}
impl From<ScalarNonZero> for ReshuffleFactor {
    fn from(x: ScalarNonZero) -> Self {
        ReshuffleFactor(x)
    }
}
impl From<ScalarNonZero> for RekeyFactor {
    fn from(x: ScalarNonZero) -> Self {
        RekeyFactor(x)
    }
}
#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(encrypted: &EncryptedPseudonym, rng: &mut R) -> EncryptedPseudonym {
    let r = ScalarNonZero::random(rng);
    EncryptedPseudonym::new(rerandomize(&encrypted.value, &r))
}

#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted data point
pub fn rerandomize_encrypted<R: RngCore + CryptoRng>(encrypted: &EncryptedDataPoint, rng: &mut R) -> EncryptedDataPoint {
    let r = ScalarNonZero::random(rng);
    EncryptedDataPoint::new(rerandomize(&encrypted.value, &r))
}

#[derive(Eq, PartialEq, Clone, Copy)]
pub struct Reshuffle2Factors {
    pub from: ReshuffleFactor,
    pub to: ReshuffleFactor,
}
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct Rekey2Factors {
    pub from: RekeyFactor,
    pub to: RekeyFactor,
}
#[derive(Eq, PartialEq, Clone, Copy)]
pub struct RSK2Factors {
    pub s: Reshuffle2Factors,
    pub k: Rekey2Factors,
}

impl Reshuffle2Factors {
    pub fn reverse(self) -> Self {
        Reshuffle2Factors { from: self.to, to: self.from }
    }
}
impl Rekey2Factors {
    pub fn reverse(self) -> Self {
        Rekey2Factors { from: self.to, to: self.from }
    }
}

pub type PseudonymizationInfo = RSK2Factors;
pub type RekeyInfo = Rekey2Factors;
impl PseudonymizationInfo {
    pub fn new(from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext, pseudonymization_secret: &PseudonymizationSecret, encryption_secret: &EncryptionSecret) -> Self {
        let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_user);
        let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_user);
        let reshuffle_factors = Reshuffle2Factors { from: s_from, to: s_to };
        let rekey_factors = RekeyInfo::new(from_session, to_session, encryption_secret);
        RSK2Factors { s: reshuffle_factors, k: rekey_factors }
    }
    pub fn new_from_rekey_info(from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, rekey_info: RekeyInfo, pseudonymization_secret: &PseudonymizationSecret) -> Self {
        let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_user);
        let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_user);
        let reshuffle_factors = Reshuffle2Factors { from: s_from, to: s_to };
        RSK2Factors { s: reshuffle_factors, k: rekey_info }
    }
    pub fn reverse(self) -> Self {
        RSK2Factors { s: self.s.reverse(), k: self.k.reverse() }
    }
}
impl RekeyInfo {
    pub fn new(from_session: &EncryptionContext, to_session: &EncryptionContext, encryption_secret: &EncryptionSecret) -> Self {
        let k_from = make_decryption_factor(&encryption_secret, &from_session);
        let k_to = make_decryption_factor(&encryption_secret, &to_session);
        Rekey2Factors { from: k_from, to: k_to }
    }
}
impl From<PseudonymizationInfo> for RekeyInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        x.k
    }
}

/// Pseudonymize an encrypted pseudonym, from one context to another context
pub fn pseudonymize(p: &EncryptedPseudonym, pseudonymization_info: &PseudonymizationInfo) -> EncryptedPseudonym {
    EncryptedPseudonym::new(rsk2(&p.value, &pseudonymization_info.s.from, &pseudonymization_info.s.to, &pseudonymization_info.k.from, &pseudonymization_info.k.to))
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(p: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::new(rekey2(&p.value, &rekey_info.from, &rekey_info.to))
}


// TODO use deref macro everywhere to make the code more readable