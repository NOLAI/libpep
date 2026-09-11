//! Role traits for public and secret keys.
//!
//! These traits describe what a key *is for* — which key it pairs with, and how it is encoded for
//! transport — without naming the types of any particular cryptographic scheme. The ElGamal
//! instantiation lives in [`elgamal`](super::elgamal), mirroring how
//! [`Encryptable`](crate::data::traits::Encryptable) is instantiated by
//! [`ElGamalEncryptable`](crate::data::simple::ElGamalEncryptable).
//!
//! They cover *keys* only: the global and session keys that data is actually encrypted towards and
//! decrypted with. Intermediate protocol material from the distributed setup (blinded global
//! secret keys, session key shares, blinding factors) deliberately does **not** implement them —
//! see [`crate::keys::distribution`].

use super::types::*;

/// A public key, which can be encoded to and decoded from byte arrays and hex strings.
pub trait PublicKey: Sized {
    /// Encode as a byte array.
    fn to_bytes(&self) -> [u8; 32];

    /// Encode as a hexadecimal string.
    fn to_hex(&self) -> String;

    /// Decode from a byte array.
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self>;

    /// Decode from a slice of bytes.
    fn from_slice(slice: &[u8]) -> Option<Self>;

    /// Decode from a hexadecimal string.
    fn from_hex(s: &str) -> Option<Self>;
}

/// A secret key, for which we do not allow encoding as secret keys should not be shared.
///
/// Secret material is read through explicit calls rather than `Deref`, so every read of a secret
/// is visible at the call site.
pub trait SecretKey: Sized {
    /// The public key associated with this secret key.
    type PublicKeyType: PublicKey;

    /// Derive the associated public key.
    ///
    /// How the public key is derived is scheme-specific; for ElGamal see
    /// [`ElGamalSecretKey`](super::elgamal::ElGamalSecretKey).
    fn public_key(&self) -> Self::PublicKeyType;
}

/// Trait to provide the correct key from SessionKeys or GlobalPublicKeys based on the key type.
/// This enables polymorphic key access in the Client.
pub trait KeyProvider<K> {
    fn get_key(&self) -> &K;
}
impl KeyProvider<PseudonymSessionPublicKey> for SessionKeys {
    fn get_key(&self) -> &PseudonymSessionPublicKey {
        &self.pseudonym.public
    }
}

impl KeyProvider<AttributeSessionPublicKey> for SessionKeys {
    fn get_key(&self) -> &AttributeSessionPublicKey {
        &self.attribute.public
    }
}

impl KeyProvider<PseudonymSessionSecretKey> for SessionKeys {
    fn get_key(&self) -> &PseudonymSessionSecretKey {
        &self.pseudonym.secret
    }
}

impl KeyProvider<AttributeSessionSecretKey> for SessionKeys {
    fn get_key(&self) -> &AttributeSessionSecretKey {
        &self.attribute.secret
    }
}

impl KeyProvider<SessionKeys> for SessionKeys {
    fn get_key(&self) -> &SessionKeys {
        self
    }
}

impl KeyProvider<PseudonymGlobalPublicKey> for GlobalPublicKeys {
    fn get_key(&self) -> &PseudonymGlobalPublicKey {
        &self.pseudonym
    }
}

impl KeyProvider<AttributeGlobalPublicKey> for GlobalPublicKeys {
    fn get_key(&self) -> &AttributeGlobalPublicKey {
        &self.attribute
    }
}

impl KeyProvider<GlobalPublicKeys> for GlobalPublicKeys {
    fn get_key(&self) -> &GlobalPublicKeys {
        self
    }
}
