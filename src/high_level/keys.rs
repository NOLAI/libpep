use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use crate::arithmetic::{GroupElement, ScalarNonZero, G};
use crate::high_level::contexts::EncryptionContext;
use crate::high_level::utils::make_rekey_factor;

/// GLOBAL KEYS
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct GlobalPublicKey(pub GroupElement);
#[derive(Copy, Clone, Debug, From)]
pub struct GlobalSecretKey(pub(crate) ScalarNonZero);

/// Generate a new global key pair
pub fn make_global_keys<R: RngCore + CryptoRng>(rng: &mut R) -> (GlobalPublicKey, GlobalSecretKey) {
    let sk = ScalarNonZero::random(rng);
    assert_ne!(sk, ScalarNonZero::one());
    let pk = sk * G;
    (GlobalPublicKey(pk), GlobalSecretKey(sk))
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

/// SESSION KEYS
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct SessionPublicKey(pub GroupElement);
#[derive(Copy, Clone, Debug, From)]
pub struct SessionSecretKey(pub(crate) ScalarNonZero);
/// Generate a subkey from a global secret key, a context, and an encryption secret
pub fn make_session_keys(
    global: &GlobalSecretKey,
    context: &EncryptionContext,
    encryption_secret: &EncryptionSecret,
) -> (SessionPublicKey, SessionSecretKey) {
    let k = make_rekey_factor(encryption_secret, context);
    let sk = k.0 * global.0;
    let pk = sk * G;
    (SessionPublicKey(pk), SessionSecretKey(sk))
}