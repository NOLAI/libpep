use crate::high_level::utils::make_rekey_factor;
use crate::high_level::contexts::*;
use crate::high_level::keys::*;
use crate::high_level::ops::*;
use crate::high_level::data_types::*;
use crate::arithmetic::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Formatter;

/// GLOBAL KEY BLINDING
#[derive(Copy, Clone, Debug, From)]
pub struct BlindingFactor(pub(crate) ScalarNonZero);
impl BlindingFactor {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let scalar = ScalarNonZero::random(rng);
        assert_ne!(scalar, ScalarNonZero::one());
        BlindingFactor(scalar)
    }
    pub fn from(x: ScalarNonZero) -> Self {
        BlindingFactor(x)
    }
    pub fn encode(&self) -> [u8; 32] {
        self.0.encode()
    }
    pub fn decode(bytes: &[u8; 32]) -> Option<Self> {
        ScalarNonZero::decode(bytes).map(BlindingFactor)
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        hex::decode(s).ok().and_then(|bytes| {
            if bytes.len() == 32 {
                Some(
                    BlindingFactor::decode(<&[u8; 32]>::try_from(bytes.as_slice()).unwrap())
                        .unwrap(),
                )
            } else {
                None
            }
        })
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct BlindedGlobalSecretKey(pub(crate) ScalarNonZero);
impl Serialize for BlindedGlobalSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode_to_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for BlindedGlobalSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlindedGlobalSecretKeyVisitor;
        impl<'de> Visitor<'de> for BlindedGlobalSecretKeyVisitor {
            type Value = BlindedGlobalSecretKey;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a BlindedGlobalSecretKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(&v)
                    .map(BlindedGlobalSecretKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(BlindedGlobalSecretKeyVisitor)
    }
}

pub fn make_blinded_global_secret_key(
    global_secret_key: &GlobalSecretKey,
    blinding_factors: &[BlindingFactor],
) -> Option<BlindedGlobalSecretKey> {
    let y = global_secret_key.clone();
    let k = blinding_factors
        .iter()
        .fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert());
    if k == ScalarNonZero::one() {
        return None;
    }
    Some(BlindedGlobalSecretKey(y.0 * k))
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct SessionKeyShare(pub(crate) ScalarNonZero);
impl Serialize for SessionKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encode_to_hex().as_str())
    }
}
impl<'de> Deserialize<'de> for SessionKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SessionKeyShareVisitor;
        impl<'de> Visitor<'de> for SessionKeyShareVisitor {
            type Value = SessionKeyShare;
            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string representing a SessionKeyShare")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                ScalarNonZero::decode_from_hex(&v)
                    .map(SessionKeyShare)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(SessionKeyShareVisitor)
    }
}

pub fn make_session_key_share(
    key_factor: &ScalarNonZero,
    blinding_factor: &BlindingFactor,
) -> SessionKeyShare {
    SessionKeyShare(key_factor * blinding_factor.0)
}

/// PEP SYSTEM
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
        let k = make_rekey_factor(&self.rekeying_secret, &context);
        make_session_key_share(&k.0, &self.blinding_factor)
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

    pub fn rekey_batch<R: RngCore + CryptoRng>(&self, encrypted: &mut [EncryptedDataPoint], rekey_info: &RekeyInfo, rng: &mut R) -> Box<[EncryptedDataPoint]> {
        rekey_batch(encrypted, rekey_info, rng)
    }

    pub fn pseudonymize_batch<R: RngCore + CryptoRng>(&self, encrypted: &mut [EncryptedPseudonym], pseudonymization_info: &PseudonymizationInfo, rng: &mut R) -> Box<[EncryptedPseudonym]> {
        pseudonymize_batch(encrypted, pseudonymization_info, rng)
    }

    pub fn transcrypt<E: Encrypted>(
        &self,
        encrypted: &E,
        transcryption_info: &PseudonymizationInfo,
    ) -> E {
        transcrypt(encrypted, transcryption_info)
    }

    pub fn transcrypt_batch<R: RngCore + CryptoRng>(
        &self,
        encrypted: &mut Vec<(Vec<EncryptedPseudonym>, Vec<EncryptedDataPoint>)>,
        transcryption_info: &PseudonymizationInfo,
        rng: &mut R,
    ) -> Vec<(Vec<EncryptedPseudonym>, Vec<EncryptedDataPoint>)> {
        transcrypt_batch(encrypted, transcryption_info, rng)
    }

}
pub fn construct_session_key(blinded_global_secret_key: BlindedGlobalSecretKey, session_key_shares: &[SessionKeyShare]) -> (SessionPublicKey, SessionSecretKey) {
    let secret = SessionSecretKey::from(
        session_key_shares
            .iter()
            .fold(*blinded_global_secret_key, |acc, x| acc * x.deref())
    );
    let public = SessionPublicKey::from(secret.0 * &G);
    (public, secret)
}

#[derive(Clone)]
pub struct PEPClient {
    pub session_public_key: SessionPublicKey,
    pub(crate) session_secret_key: SessionSecretKey,
}
impl PEPClient {
    pub fn new(
        blinded_global_private_key: BlindedGlobalSecretKey,
        session_key_shares: &[SessionKeyShare],
    ) -> Self {
        let (public, secret) = construct_session_key(blinded_global_private_key, session_key_shares);
        Self {
            session_public_key: public,
            session_secret_key: secret,
        }
    }
    pub fn decrypt<E: Encrypted>(&self, encrypted: &E) -> E::UnencryptedType {
        decrypt(encrypted, &self.session_secret_key)
    }
    pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &self,
        val: &E,
        rng: &mut R,
    ) -> E::EncryptedType {
        encrypt(val, &(self.session_public_key), rng)
    }
}

pub struct PEPClientOffline {
    pub global_public_key: GlobalPublicKey,
}
impl PEPClientOffline {
    pub fn new(global_public_key: GlobalPublicKey) -> Self {
        Self { global_public_key }
    }
    pub fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &self,
        val: &E,
        rng: &mut R,
    ) -> E::EncryptedType {
        encrypt_global(val, &(self.global_public_key), rng)
    }
}
