use std::ops::Deref;
use rand_core::OsRng;
use crate::arithmetic::{G, GroupElement, ScalarNonZero};
use crate::elgamal::{ElGamal, encrypt, decrypt};
use crate::primitives::*;
use crate::utils::{make_decryption_factor, make_pseudonymisation_factor};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SessionSecretKey(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GlobalSecretKey(pub ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SessionPublicKey(pub GroupElement);
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GlobalPublicKey(pub GroupElement);
impl Deref for SessionSecretKey {
    type Target = ScalarNonZero;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Deref for GlobalSecretKey {
    type Target = ScalarNonZero;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Deref for SessionPublicKey {
    type Target = GroupElement;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Deref for GlobalPublicKey {
    type Target = GroupElement;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Pseudonym {
    pub value: GroupElement
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct DataPoint{
    pub value: GroupElement
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EncryptedPseudonym{
    pub value: ElGamal
}
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EncryptedDataPoint{
    pub value: ElGamal
}

impl Deref for Pseudonym {
    type Target = GroupElement;
    fn deref(&self) -> &Self::Target { &self.value }
}
impl Deref for DataPoint {
    type Target = GroupElement;
    fn deref(&self) -> &Self::Target { &self.value }
}
impl Deref for EncryptedPseudonym {
    type Target = ElGamal;
    fn deref(&self) -> &Self::Target { &self.value }
}
impl Deref for EncryptedDataPoint {
    type Target = ElGamal;
    fn deref(&self) -> &Self::Target { &self.value }
}

impl Pseudonym {
    pub fn new(value: GroupElement) -> Self {
        Pseudonym { value }
    }
    pub fn random() -> Self {
        let mut rng = OsRng;
        Pseudonym::new(GroupElement::random(&mut rng))
    }
}
impl DataPoint {
    pub fn new(value: GroupElement) -> Self {
        DataPoint { value }
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

pub type Context = String;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PseudonymizationContext(pub Context);
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EncryptionContext(pub Context);

impl Deref for PseudonymizationContext {
    type Target = Context;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Deref for EncryptionContext {
    type Target = Context;
    fn deref(&self) -> &Self::Target { &self.0 }
}


pub type Secret = String;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PseudonymizationSecret(pub Secret);
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EncryptionSecret(pub Secret);

impl Deref for PseudonymizationSecret {
    type Target = Secret;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl Deref for EncryptionSecret {
    type Target = Secret;
    fn deref(&self) -> &Self::Target { &self.0 }
}

/// Generate a new global key pair
pub fn make_global_keys() -> (GlobalPublicKey, GlobalSecretKey) {
    let mut rng = OsRng;
    let sk = ScalarNonZero::random(&mut rng);
    let pk = sk * G;
    (GlobalPublicKey(pk), GlobalSecretKey(sk))
}

/// Generate a subkey from a global secret key, a context, and an encryption secret
pub fn make_session_keys(global: &GlobalSecretKey, context: &EncryptionContext, encryption_secret: &EncryptionSecret) -> (SessionPublicKey, SessionSecretKey) {
    let k = make_decryption_factor(&encryption_secret, &context);
    let sk = k * global.deref();
    let pk = sk * G;
    (SessionPublicKey(pk), SessionSecretKey(sk))
}

/// Encrypt a pseudonym
pub fn encrypt_pseudonym(p: &Pseudonym, pk: &SessionPublicKey) -> EncryptedPseudonym {
    let mut rng = OsRng;
    EncryptedPseudonym::new(encrypt(&p, &pk, &mut rng))
}

/// Decrypt an encrypted pseudonym
pub fn decrypt_pseudonym(p: &EncryptedPseudonym, sk: &SessionSecretKey) -> Pseudonym {
    Pseudonym::new(decrypt(&p, &sk))
}

/// Encrypt a data point
pub fn encrypt_data(data: &DataPoint, pk: &SessionPublicKey) -> EncryptedDataPoint {
    let mut rng = OsRng;
    EncryptedDataPoint::new(encrypt(&data, &pk, &mut rng))
}

/// Decrypt an encrypted data point
pub fn decrypt_data(data: &EncryptedDataPoint, sk: &SessionSecretKey) -> DataPoint {
    DataPoint::new(decrypt(&data, &sk))
}

#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_encrypted_pseudonym(encrypted: &EncryptedPseudonym) -> EncryptedPseudonym {
    let mut rng = OsRng;
    let r = ScalarNonZero::random(&mut rng);
    EncryptedPseudonym::new(rerandomize(&encrypted.value, &r))
}

#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted data point
pub fn rerandomize_encrypted(encrypted: &EncryptedDataPoint) -> EncryptedDataPoint {
    let mut rng = OsRng;
    let r = ScalarNonZero::random(&mut rng);
    EncryptedDataPoint::new(rerandomize(&encrypted.value, &r))
}

/// Pseudonymize an encrypted pseudonym, from one context to another context
pub fn pseudonymize(p: &EncryptedPseudonym, from_user: &PseudonymizationContext, to_user: &PseudonymizationContext, from_session: &EncryptionContext, to_session: &EncryptionContext, pseudonymization_secret: &PseudonymizationSecret, encryption_secret: &EncryptionSecret) -> EncryptedPseudonym {
    let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_user);
    let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_user);
    let k_from = make_decryption_factor(&encryption_secret, &from_session);
    let k_to = make_decryption_factor(&encryption_secret, &to_session);
    EncryptedPseudonym::new(rsk_from_to(&p.value, &s_from, &s_to, &k_from, &k_to))
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(p: &EncryptedDataPoint, from_session: &EncryptionContext, to_session: &EncryptionContext, encryption_secret: &EncryptionSecret) -> EncryptedDataPoint {
    let k_from = make_decryption_factor(&encryption_secret, &from_session);
    let k_to = make_decryption_factor(&encryption_secret, &to_session);
    EncryptedDataPoint::new(rekey_from_to(&p.value, &k_from, &k_to))
}
