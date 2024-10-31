use crate::arithmetic::{GroupElement, ScalarNonZero, G};
use crate::elgamal::{decrypt, encrypt, ElGamal};
use crate::primitives::*;
use crate::utils::{make_pseudonymisation_factor, make_rekey_factor};
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

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

/// PSEUDONYMS AND DATA
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct Pseudonym {
    pub(crate) value: GroupElement,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct DataPoint {
    pub(crate) value: GroupElement,
}
impl Pseudonym {
    pub fn from_point(value: GroupElement) -> Self {
        Self { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_point(GroupElement::random(rng))
    }
    pub fn encode(&self) -> [u8; 32] {
        self.value.encode()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::decode(bytes).map(|x| Self::from_point(x))
    }
    pub fn from_hash(hash: &[u8; 64]) -> Self {
        Self::from_point(GroupElement::decode_from_hash(hash))
    }
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::decode_from_slice(slice).map(|x| Self::from_point(x))
    }
    pub fn from_hex(hex: &str) -> Option<Self> {
        GroupElement::decode_hex(hex).map(|x| Self::from_point(x))
    }
    pub fn from_bytes(data: &[u8; 16]) -> Option<Self> {
        GroupElement::decode_lizard(data).map(|x| Self::from_point(x))
    }
    pub fn to_hex(&self) -> String {
        self.value.encode_hex()
    }
    pub fn to_bytes(&self) -> Option<[u8; 16]> {
        self.value.encode_lizard()
    }
}
impl DataPoint {
    pub fn from_point(value: GroupElement) -> Self {
        Self { value }
    }
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from_point(GroupElement::random(rng))
    }
    pub fn encode(&self) -> [u8; 32] {
        self.value.encode()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        GroupElement::decode(bytes).map(|x| Self::from_point(x))
    }
    pub fn from_hash(hash: &[u8; 64]) -> Self {
        Self::from_point(GroupElement::decode_from_hash(hash))
    }
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::decode_from_slice(slice).map(|x| Self::from_point(x))
    }
    pub fn from_hex(hex: &str) -> Option<Self> {
        GroupElement::decode_hex(hex).map(|x| Self::from_point(x))
    }
    pub fn from_bytes(data: &[u8; 16]) -> Option<Self> {
        GroupElement::decode_lizard(data).map(|x| Self::from_point(x))
    }
    pub fn to_hex(&self) -> String {
        self.value.encode_hex()
    }
    pub fn to_bytes(&self) -> Option<[u8; 16]> {
        self.value.encode_lizard()
    }
    pub fn from_data_long(data: &[u8]) -> Vec<Self> {
        data.chunks(16)
            .map(|x| Self::from_bytes(x.try_into().unwrap()).unwrap())
            .collect()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedPseudonym {
    pub value: ElGamal,
}
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptedDataPoint {
    pub value: ElGamal,
}

/// Encrypt a pseudonym
pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
    p: &Pseudonym,
    pk: &SessionPublicKey,
    rng: &mut R,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from(encrypt(p, pk, rng))
}

/// Decrypt an encrypted pseudonym
pub fn decrypt_pseudonym(p: &EncryptedPseudonym, sk: &SessionSecretKey) -> Pseudonym {
    Pseudonym::from_point(decrypt(p, &sk.0))
}

/// Encrypt a data point
pub fn encrypt_data<R: RngCore + CryptoRng>(
    data: &DataPoint,
    pk: &SessionPublicKey,
    rng: &mut R,
) -> EncryptedDataPoint {
    EncryptedDataPoint::from(encrypt(data, pk, rng))
}

/// Decrypt an encrypted data point
pub fn decrypt_data(data: &EncryptedDataPoint, sk: &SessionSecretKey) -> DataPoint {
    DataPoint::from_point(decrypt(&data, &sk.0))
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RerandomizeFactor(ScalarNonZero);
#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
    encrypted: &EncryptedPseudonym,
    rng: &mut R,
) -> EncryptedPseudonym {
    let r = ScalarNonZero::random(rng);
    EncryptedPseudonym::from(rerandomize(&encrypted.value, &r))
}

#[cfg(not(feature = "elgamal2"))]
/// Rerandomize the ciphertext of an encrypted data point
pub fn rerandomize_encrypted<R: RngCore + CryptoRng>(
    encrypted: &EncryptedDataPoint,
    rng: &mut R,
) -> EncryptedDataPoint {
    let r = ScalarNonZero::random(rng);
    EncryptedDataPoint::from(rerandomize(&encrypted.value, &r))
}

#[cfg(feature = "elgamal2")]
/// Rerandomize the ciphertext of an encrypted pseudonym
pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
    encrypted: &EncryptedPseudonym,
    public_key: &GroupElement,
    rng: &mut R,
) -> EncryptedPseudonym {
    let r = ScalarNonZero::random(rng);
    EncryptedPseudonym::from(rerandomize(&encrypted.value, public_key, &r))
}

#[cfg(feature = "elgamal2")]
/// Rerandomize the ciphertext of an encrypted data point
pub fn rerandomize_encrypted<R: RngCore + CryptoRng>(
    encrypted: &EncryptedDataPoint,
    public_key: &GroupElement,
    rng: &mut R,
) -> EncryptedDataPoint {
    let r = ScalarNonZero::random(rng);
    EncryptedDataPoint::from(rerandomize(&encrypted.value, public_key, &r))
}

/// CONTEXTS AND FACTORS
pub type Context = String; // Contexts are described by simple strings of arbitrary length
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct PseudonymizationContext(pub Context);
#[cfg(not(feature = "legacy-pep-repo-compatible"))]
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptionContext(pub Context);
#[cfg(feature = "legacy-pep-repo-compatible")]
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct PseudonymizationContext {
    #[deref]
    pub payload: Context,
    pub audience_type: AudienceType,
}
#[cfg(feature = "legacy-pep-repo-compatible")]
#[derive(Clone, Eq, Hash, PartialEq, Debug, Deref, From, Serialize, Deserialize)]
pub struct EncryptionContext {
    #[deref]
    pub payload: Context,
    pub audience_type: AudienceType,
}
#[cfg(feature = "legacy-pep-repo-compatible")]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[repr(u32)]
pub enum AudienceType {
    User = 0x01,
    StorageFacility = 0x02,
    AccessManager = 0x03,
    Transcryptor = 0x04,
    RegistrationServer = 0x05,
    Unknown = 0x00,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct ReshuffleFactor(pub(crate) ScalarNonZero);
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct RekeyFactor(pub(crate) ScalarNonZero);

#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct Reshuffle2Factors {
    pub from: ReshuffleFactor,
    pub to: ReshuffleFactor,
}
#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct Rekey2Factors {
    pub from: RekeyFactor,
    pub to: RekeyFactor,
}
#[derive(Eq, PartialEq, Clone, Copy, Debug, From)]
pub struct RSK2Factors {
    pub s: Reshuffle2Factors,
    pub k: Rekey2Factors,
}

impl Reshuffle2Factors {
    pub fn reverse(self) -> Self {
        Reshuffle2Factors {
            from: self.to,
            to: self.from,
        }
    }
}
impl Rekey2Factors {
    pub fn reverse(self) -> Self {
        Rekey2Factors {
            from: self.to,
            to: self.from,
        }
    }
}

pub type PseudonymizationInfo = RSK2Factors;
pub type RekeyInfo = Rekey2Factors;
impl PseudonymizationInfo {
    pub fn new(
        from_pseudo_context: &PseudonymizationContext,
        to_pseudo_context: &PseudonymizationContext,
        from_enc_context: &EncryptionContext,
        to_enc_context: &EncryptionContext,
        pseudonymization_secret: &PseudonymizationSecret,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let s_from = make_pseudonymisation_factor(&pseudonymization_secret, &from_pseudo_context);
        let s_to = make_pseudonymisation_factor(&pseudonymization_secret, &to_pseudo_context);
        let reshuffle_factors = Reshuffle2Factors {
            from: s_from,
            to: s_to,
        };
        let rekey_factors = RekeyInfo::new(from_enc_context, to_enc_context, encryption_secret);
        RSK2Factors {
            s: reshuffle_factors,
            k: rekey_factors,
        }
    }
    pub fn reverse(self) -> Self {
        RSK2Factors {
            s: self.s.reverse(),
            k: self.k.reverse(),
        }
    }
}
impl RekeyInfo {
    pub fn new(
        from_session: &EncryptionContext,
        to_session: &EncryptionContext,
        encryption_secret: &EncryptionSecret,
    ) -> Self {
        let k_from = make_rekey_factor(&encryption_secret, &from_session);
        let k_to = make_rekey_factor(&encryption_secret, &to_session);
        Rekey2Factors {
            from: k_from,
            to: k_to,
        }
    }
}
impl From<PseudonymizationInfo> for RekeyInfo {
    fn from(x: PseudonymizationInfo) -> Self {
        x.k
    }
}

/// TRANSCRYPTION

/// Pseudonymize an encrypted pseudonym, from one context to another context
pub fn pseudonymize(
    p: &EncryptedPseudonym,
    pseudonymization_info: &PseudonymizationInfo,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from(rsk2(
        &p.value,
        &pseudonymization_info.s.from.0,
        &pseudonymization_info.s.to.0,
        &pseudonymization_info.k.from.0,
        &pseudonymization_info.k.to.0,
    ))
}

/// Pseudonymize an encrypted pseudonym for a global key, from one context to another context, to be decrypted by a session key
pub fn pseudonymize_from_global(
    p: &EncryptedPseudonym,
    reshuffle_factors: Reshuffle2Factors,
    rekey_to: RekeyFactor,
) -> EncryptedPseudonym {
    EncryptedPseudonym::from(rsk2(
        &p.value,
        &reshuffle_factors.from.0,
        &reshuffle_factors.to.0,
        &ScalarNonZero::one(),
        &rekey_to.0,
    ))
}

/// Rekey an encrypted data point, encrypted with one session key, to be decrypted by another session key
pub fn rekey(p: &EncryptedDataPoint, rekey_info: &RekeyInfo) -> EncryptedDataPoint {
    EncryptedDataPoint::from(rekey2(&p.value, &rekey_info.from.0, &rekey_info.to.0))
}

/// Rekey an encrypted data point, encrypted for a global key, to be decrypted by a session key
pub fn rekey_from_global(p: &EncryptedDataPoint, rekey_to: RekeyFactor) -> EncryptedDataPoint {
    EncryptedDataPoint::from(crate::primitives::rekey(&p.value, &rekey_to.0))
}
