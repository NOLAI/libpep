//! Distributed client generic over the [`Group`]: reconstructing session keys from shares.
//!
//! A session secret key is the blinded global secret key multiplied by one session key share
//! per transcryptor: the blinding factors in the shares cancel against those in the blinded
//! key, leaving the global secret key times the rekey factors. Replacing one transcryptor's
//! share (when that transcryptor moves the client to another session) divides out the old share
//! and multiplies in the new one.

use crate::client::types::generic::Client;
use crate::elgamal::arithmetic::group::Group;
use crate::keys::distribution::blinding::generic::{
    BlindedAttributeGlobalSecretKey, BlindedGlobalSecretKey, BlindedGlobalSecretKeys,
    BlindedPseudonymGlobalSecretKey,
};
use crate::keys::distribution::shares::generic::{
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShare, SessionKeyShares,
};
use crate::keys::traits::SecretKey;
use crate::keys::types::generic::{
    AttributeSessionKeys, AttributeSessionPublicKey, AttributeSessionSecretKey,
    PseudonymSessionKeys, PseudonymSessionPublicKey, PseudonymSessionSecretKey, SessionKeys,
};

/// The session public and secret key that a share type reconstructs.
type SessionKeyPair<S> = (
    <<S as SessionKeyShare>::SessionSecretKey as SecretKey>::PublicKeyType,
    <S as SessionKeyShare>::SessionSecretKey,
);

/// Reconstruct a session key from a blinded global secret key and one session key share per
/// transcryptor. Works for both pseudonym and attribute keys based on the share type.
pub fn make_session_key<S: SessionKeyShare>(
    blinded_global_secret_key: S::BlindedGlobalSecretKey,
    session_key_shares: &[S],
) -> SessionKeyPair<S> {
    let secret = S::SessionSecretKey::from_scalar(
        session_key_shares
            .iter()
            .fold(*blinded_global_secret_key.value(), |acc, x| {
                acc * *x.value()
            }),
    );
    (secret.public_key(), secret)
}

/// Reconstruct a pseudonym session key from a blinded global secret key and session key shares.
pub fn make_pseudonym_session_key<G: Group>(
    blinded_global_secret_key: BlindedPseudonymGlobalSecretKey<G>,
    session_key_shares: &[PseudonymSessionKeyShare<G>],
) -> (PseudonymSessionPublicKey<G>, PseudonymSessionSecretKey<G>) {
    make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct an attribute session key from a blinded global secret key and session key shares.
pub fn make_attribute_session_key<G: Group>(
    blinded_global_secret_key: BlindedAttributeGlobalSecretKey<G>,
    session_key_shares: &[AttributeSessionKeyShare<G>],
) -> (AttributeSessionPublicKey<G>, AttributeSessionSecretKey<G>) {
    make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct session keys (both pseudonym and attribute) from blinded global secret keys and session key shares.
pub fn make_session_keys_distributed<G: Group>(
    blinded_global_keys: BlindedGlobalSecretKeys<G>,
    session_key_shares: &[SessionKeyShares<G>],
) -> SessionKeys<G> {
    let pseudonym_shares: Vec<PseudonymSessionKeyShare<G>> =
        session_key_shares.iter().map(|s| s.pseudonym).collect();
    let attribute_shares: Vec<AttributeSessionKeyShare<G>> =
        session_key_shares.iter().map(|s| s.attribute).collect();

    let (pseudonym_public, pseudonym_secret) =
        make_session_key(blinded_global_keys.pseudonym, &pseudonym_shares);
    let (attribute_public, attribute_secret) =
        make_session_key(blinded_global_keys.attribute, &attribute_shares);

    SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Replace one transcryptor's share in a session key with a new one.
/// Works for both pseudonym and attribute keys based on the share type.
pub fn update_session_key<S: SessionKeyShare>(
    session_secret_key: S::SessionSecretKey,
    old_session_key_share: S,
    new_session_key_share: S,
) -> SessionKeyPair<S> {
    let secret = S::SessionSecretKey::from_scalar(
        *session_secret_key.value()
            * S::Group::scalar_inverse(old_session_key_share.value())
            * *new_session_key_share.value(),
    );
    (secret.public_key(), secret)
}

/// Update a pseudonym session key with new session key shares.
pub fn update_pseudonym_session_key<G: Group>(
    session_secret_key: PseudonymSessionSecretKey<G>,
    old_session_key_share: PseudonymSessionKeyShare<G>,
    new_session_key_share: PseudonymSessionKeyShare<G>,
) -> (PseudonymSessionPublicKey<G>, PseudonymSessionSecretKey<G>) {
    update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update an attribute session key with new session key shares.
pub fn update_attribute_session_key<G: Group>(
    session_secret_key: AttributeSessionSecretKey<G>,
    old_session_key_share: AttributeSessionKeyShare<G>,
    new_session_key_share: AttributeSessionKeyShare<G>,
) -> (AttributeSessionPublicKey<G>, AttributeSessionSecretKey<G>) {
    update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update session keys (both pseudonym and attribute) with new session key shares.
pub fn update_session_keys<G: Group>(
    current_keys: SessionKeys<G>,
    old_shares: SessionKeyShares<G>,
    new_shares: SessionKeyShares<G>,
) -> SessionKeys<G> {
    let (pseudonym_public, pseudonym_secret) = update_session_key(
        current_keys.pseudonym.secret,
        old_shares.pseudonym,
        new_shares.pseudonym,
    );
    let (attribute_public, attribute_secret) = update_session_key(
        current_keys.attribute.secret,
        old_shares.attribute,
        new_shares.attribute,
    );

    SessionKeys {
        pseudonym: PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Trait to update and extract session keys from SessionKeys based on the share type.
pub trait SessionKeyUpdater<S: SessionKeyShare> {
    fn get_current_secret(&self) -> S::SessionSecretKey;
    fn set_keys(
        &mut self,
        public: <S::SessionSecretKey as SecretKey>::PublicKeyType,
        secret: S::SessionSecretKey,
    );
}

impl<G: Group> SessionKeyUpdater<PseudonymSessionKeyShare<G>> for SessionKeys<G> {
    fn get_current_secret(&self) -> PseudonymSessionSecretKey<G> {
        self.pseudonym.secret
    }

    fn set_keys(
        &mut self,
        public: PseudonymSessionPublicKey<G>,
        secret: PseudonymSessionSecretKey<G>,
    ) {
        self.pseudonym.public = public;
        self.pseudonym.secret = secret;
    }
}

impl<G: Group> SessionKeyUpdater<AttributeSessionKeyShare<G>> for SessionKeys<G> {
    fn get_current_secret(&self) -> AttributeSessionSecretKey<G> {
        self.attribute.secret
    }

    fn set_keys(
        &mut self,
        public: AttributeSessionPublicKey<G>,
        secret: AttributeSessionSecretKey<G>,
    ) {
        self.attribute.public = public;
        self.attribute.secret = secret;
    }
}

/// Extension trait for Client with distributed-specific constructors and methods.
pub trait Distributed {
    /// The group of the session keys.
    type Group: Group;

    /// Create a new PEP client from blinded global keys and session key shares.
    fn from_shares(
        blinded_global_keys: BlindedGlobalSecretKeys<Self::Group>,
        session_key_shares: &[SessionKeyShares<Self::Group>],
    ) -> Self;

    /// Update a session key share from one session to another.
    /// Automatically selects the correct key (pseudonym or attribute) based on the share type.
    fn update_session_secret_key<S>(&mut self, old_key_share: S, new_key_share: S)
    where
        S: SessionKeyShare<Group = Self::Group>,
        SessionKeys<Self::Group>: SessionKeyUpdater<S>;

    /// Update both pseudonym and attribute session key shares from one session to another.
    /// This is a convenience method that updates both shares together.
    fn update_session_secret_keys(
        &mut self,
        old_key_shares: SessionKeyShares<Self::Group>,
        new_key_shares: SessionKeyShares<Self::Group>,
    );
}

impl<G: Group> Distributed for Client<G> {
    type Group = G;

    fn from_shares(
        blinded_global_keys: BlindedGlobalSecretKeys<G>,
        session_key_shares: &[SessionKeyShares<G>],
    ) -> Self {
        let keys = make_session_keys_distributed(blinded_global_keys, session_key_shares);
        Self::new(keys)
    }

    fn update_session_secret_key<S>(&mut self, old_key_share: S, new_key_share: S)
    where
        S: SessionKeyShare<Group = G>,
        SessionKeys<G>: SessionKeyUpdater<S>,
    {
        let current_secret = self.keys.get_current_secret();
        let (public, secret) = update_session_key(current_secret, old_key_share, new_key_share);
        self.keys.set_keys(public, secret);
    }

    fn update_session_secret_keys(
        &mut self,
        old_key_shares: SessionKeyShares<G>,
        new_key_shares: SessionKeyShares<G>,
    ) {
        self.keys = update_session_keys(self.keys, old_key_shares, new_key_shares);
    }
}
