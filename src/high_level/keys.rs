use crate::high_level::contexts::{EncryptionContext, PseudonymizationContext};
use crate::high_level::utils::{make_pseudonymisation_factor, make_rekey_factor};
use crate::internal::arithmetic::{GroupElement, ScalarNonZero, G};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct GlobalPublicEncryptionKey(pub GroupElement);
#[derive(Copy, Clone, Debug, From)]
pub struct GlobalSecretEncryptionKey(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct SessionPublicEncryptionKey(pub GroupElement);
#[derive(Copy, Clone, Debug, From)]
pub struct SessionSecretEncryptionKey(pub(crate) ScalarNonZero);


#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct GlobalPublicPseudonymizationKey(pub GroupElement);
#[derive(Copy, Clone, Debug, From)]
pub struct GlobalSecretPseudonymizationKey(pub(crate) ScalarNonZero);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct SessionPublicPseudonymizationKey(pub GroupElement);
#[derive(Copy, Clone, Debug, From)]
pub struct SessionSecretPseudonymizationKey(pub(crate) ScalarNonZero);

pub trait PublicKey {
    fn value(&self) -> &GroupElement;
}
pub trait SecretKey {
    fn value(&self) -> &ScalarNonZero;
}
impl PublicKey for GlobalPublicEncryptionKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
}
impl SecretKey for GlobalSecretEncryptionKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl PublicKey for SessionPublicEncryptionKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
}
impl SecretKey for SessionSecretEncryptionKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

impl PublicKey for GlobalPublicPseudonymizationKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
}
impl SecretKey for GlobalSecretPseudonymizationKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}
impl PublicKey for SessionPublicPseudonymizationKey {
    fn value(&self) -> &GroupElement {
        &self.0
    }
}
impl SecretKey for SessionSecretPseudonymizationKey {
    fn value(&self) -> &ScalarNonZero {
        &self.0
    }
}

/// TRANSCRYPTION SECRETS
pub type Secret = Box<[u8]>; // Secrets are byte arrays of arbitrary length
#[derive(Clone, Debug, From)]
pub struct PseudonymizationSecret(pub(crate) Secret);
#[derive(Clone, Debug, From)]
pub struct EncryptionSecret(pub(crate) Secret);
impl PseudonymizationSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}
impl EncryptionSecret {
    pub fn from(secret: Vec<u8>) -> Self {
        Self(secret.into_boxed_slice())
    }
}

/// Generate a new global key pair
pub fn make_global_encryption_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (GlobalPublicEncryptionKey, GlobalSecretEncryptionKey) {
    let sk = ScalarNonZero::random(rng);
    assert_ne!(sk, ScalarNonZero::one());
    let pk = sk * G;
    (GlobalPublicEncryptionKey(pk), GlobalSecretEncryptionKey(sk))
}

pub fn make_global_pseudonymization_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (GlobalPublicPseudonymizationKey, GlobalSecretPseudonymizationKey) {
    let sk = ScalarNonZero::random(rng);
    assert_ne!(sk, ScalarNonZero::one());
    let pk = sk * G;
    (GlobalPublicPseudonymizationKey(pk), GlobalSecretPseudonymizationKey(sk))
}

/// Generate a subkey from a global secret key, a context, and an encryption secret
pub fn make_session_encryption_keys(
    global: &GlobalSecretEncryptionKey,
    context: &EncryptionContext,
    secret: &EncryptionSecret,
) -> (SessionPublicEncryptionKey, SessionSecretEncryptionKey) {
    let k = make_rekey_factor(secret, context);
    let sk = k.0 * global.0;
    let pk = sk * G;
    (SessionPublicEncryptionKey(pk), SessionSecretEncryptionKey(sk))
}

#[cfg(feature = "insecure-methods")]
pub fn make_session_pseudonymization_keys(
    global: &GlobalSecretPseudonymizationKey,
    context: &PseudonymizationContext,
    secret: &PseudonymizationSecret,
) -> (SessionPublicPseudonymizationKey, SessionSecretPseudonymizationKey) {
    let k = make_pseudonymisation_factor(secret, context);
    let sk = k.0 * global.0;
    let pk = sk * G;
    (SessionPublicPseudonymizationKey(pk), SessionSecretPseudonymizationKey(sk))
}
