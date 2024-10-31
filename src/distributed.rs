use std::fmt::Formatter;
use crate::arithmetic::*;
use crate::high_level::*;
use crate::utils::*;
use derive_more::{Deref, From};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{Error, Visitor};

/// GLOBAL KEY BLINDING
#[derive(Copy, Clone, Debug, From)]
pub struct BlindingFactor(ScalarNonZero);
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
                Some(BlindingFactor::decode(<&[u8; 32]>::try_from(bytes.as_slice()).unwrap()).unwrap())
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
pub struct BlindedGlobalSecretKey(ScalarNonZero);
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
                ScalarNonZero::decode_from_hex(&v).map(BlindedGlobalSecretKey)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(BlindedGlobalSecretKeyVisitor)
    }
}

pub fn make_blinded_global_secret_key(
    global_secret_key: &GlobalSecretKey,
    blinding_factors: &Vec<BlindingFactor>,
) -> Option<BlindedGlobalSecretKey> {
    let y = global_secret_key.clone();
    let k = blinding_factors.iter().fold(ScalarNonZero::one(), |acc, x| acc * x.0.invert());
    if k == ScalarNonZero::one() {
        return None;
    }
    Some(BlindedGlobalSecretKey(y.0 * k))
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deref, From)]
pub struct SessionKeyShare(ScalarNonZero);
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
                ScalarNonZero::decode_from_hex(&v).map(SessionKeyShare)
                    .ok_or(E::custom(format!("invalid hex encoded string: {}", v)))
            }
        }

        deserializer.deserialize_str(SessionKeyShareVisitor)
    }
}

pub fn make_session_key_share(key_factor: &ScalarNonZero, blinding_factor: &BlindingFactor) -> SessionKeyShare {
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
        make_session_key_share(&k, &self.blinding_factor)
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
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedPseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedDataPoint,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, rng)
    }
    #[cfg(feature = "elgamal2")]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedPseudonym,
        public_key: &GroupElement,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, public_key, rng)
    }
    #[cfg(feature = "elgamal2")]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedDataPoint,
        public_key: &GroupElement,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, public_key, rng)
    }
}

#[derive(Clone)]
pub struct PEPClient {
    pub(crate) session_secret_key: SessionSecretKey,
    session_public_key: SessionPublicKey,
}
impl PEPClient {
    pub fn new(
        blinded_global_private_key: BlindedGlobalSecretKey,
        session_key_shares: Vec<SessionKeyShare>,
    ) -> Self {
        let secret_key = SessionSecretKey::from(
            session_key_shares
                .iter()
                .fold(*blinded_global_private_key, |acc, x| acc * x.deref()),
        );
        let public_key = SessionPublicKey::from(secret_key.0 * &G);
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
    pub fn encrypt_data<R: RngCore + CryptoRng>(
        &self,
        data: &DataPoint,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        encrypt_data(data, &(self.session_public_key), rng)
    }
    pub fn encrypt_pseudonym<R: RngCore + CryptoRng>(
        &self,
        p: &Pseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        encrypt_pseudonym(p, &(self.session_public_key), rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedPseudonym,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, rng)
    }
    #[cfg(not(feature = "elgamal2"))]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedDataPoint,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, rng)
    }
    #[cfg(feature = "elgamal2")]
    pub fn rerandomize_encrypted_pseudonym<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedPseudonym,
        public_key: &GroupElement,
        rng: &mut R,
    ) -> EncryptedPseudonym {
        rerandomize_encrypted_pseudonym(&encrypted, public_key, rng)
    }
    #[cfg(feature = "elgamal2")]
    pub fn rerandomize_encrypted_data_point<R: RngCore + CryptoRng>(
        &self,
        encrypted: EncryptedDataPoint,
        public_key: &GroupElement,
        rng: &mut R,
    ) -> EncryptedDataPoint {
        rerandomize_encrypted(&encrypted, public_key, rng)
    }
}
