//! Distributed client for reconstructing session keys from shares.

use crate::keys::SessionKeys;

/// Trait for session key share types that define their associated key types.
pub trait SessionKeyShare:
    std::ops::Deref<Target = crate::arithmetic::scalars::ScalarNonZero> + Sized
{
    type PublicKeyType: From<crate::arithmetic::group_elements::GroupElement>;
    type SecretKeyType: std::ops::Deref<Target = crate::arithmetic::scalars::ScalarNonZero>
        + From<crate::arithmetic::scalars::ScalarNonZero>;
    type BlindedGlobalSecretKeyType: std::ops::Deref<
        Target = crate::arithmetic::scalars::ScalarNonZero,
    >;
}

impl SessionKeyShare for crate::keys::distribution::PseudonymSessionKeyShare {
    type PublicKeyType = crate::keys::PseudonymSessionPublicKey;
    type SecretKeyType = crate::keys::PseudonymSessionSecretKey;
    type BlindedGlobalSecretKeyType = crate::keys::distribution::BlindedPseudonymGlobalSecretKey;
}

impl SessionKeyShare for crate::keys::distribution::AttributeSessionKeyShare {
    type PublicKeyType = crate::keys::AttributeSessionPublicKey;
    type SecretKeyType = crate::keys::AttributeSessionSecretKey;
    type BlindedGlobalSecretKeyType = crate::keys::distribution::BlindedAttributeGlobalSecretKey;
}

/// Polymorphic function to reconstruct a session key from a blinded global secret key and session key shares.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn make_session_key<S>(
    blinded_global_secret_key: S::BlindedGlobalSecretKeyType,
    session_key_shares: &[S],
) -> (S::PublicKeyType, S::SecretKeyType)
where
    S: SessionKeyShare,
{
    let secret = S::SecretKeyType::from(
        session_key_shares
            .iter()
            .fold(*blinded_global_secret_key, |acc, x| acc * **x),
    );
    let public = S::PublicKeyType::from(*secret * crate::arithmetic::group_elements::G);
    (public, secret)
}

/// Reconstruct a pseudonym session key from a blinded global secret key and session key shares.
pub fn make_pseudonym_session_key(
    blinded_global_secret_key: crate::keys::distribution::BlindedPseudonymGlobalSecretKey,
    session_key_shares: &[crate::keys::distribution::PseudonymSessionKeyShare],
) -> (
    crate::keys::PseudonymSessionPublicKey,
    crate::keys::PseudonymSessionSecretKey,
) {
    make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct an attribute session key from a blinded global secret key and session key shares.
pub fn make_attribute_session_key(
    blinded_global_secret_key: crate::keys::distribution::BlindedAttributeGlobalSecretKey,
    session_key_shares: &[crate::keys::distribution::AttributeSessionKeyShare],
) -> (
    crate::keys::AttributeSessionPublicKey,
    crate::keys::AttributeSessionSecretKey,
) {
    make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct session keys (both pseudonym and attribute) from blinded global secret keys and session key shares.
pub fn make_session_keys_distributed(
    blinded_global_keys: crate::keys::distribution::BlindedGlobalKeys,
    session_key_shares: &[crate::keys::distribution::SessionKeyShares],
) -> SessionKeys {
    let pseudonym_shares: Vec<crate::keys::distribution::PseudonymSessionKeyShare> =
        session_key_shares.iter().map(|s| s.pseudonym).collect();
    let attribute_shares: Vec<crate::keys::distribution::AttributeSessionKeyShare> =
        session_key_shares.iter().map(|s| s.attribute).collect();

    let (pseudonym_public, pseudonym_secret) =
        make_session_key(blinded_global_keys.pseudonym, &pseudonym_shares);
    let (attribute_public, attribute_secret) =
        make_session_key(blinded_global_keys.attribute, &attribute_shares);

    SessionKeys {
        pseudonym: crate::keys::PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: crate::keys::AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Polymorphic function to update a session key with new session key shares.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn update_session_key<S>(
    session_secret_key: S::SecretKeyType,
    old_session_key_share: S,
    new_session_key_share: S,
) -> (S::PublicKeyType, S::SecretKeyType)
where
    S: SessionKeyShare,
{
    let secret = S::SecretKeyType::from(
        *session_secret_key * old_session_key_share.invert() * *new_session_key_share,
    );
    let public = S::PublicKeyType::from(*secret * crate::arithmetic::group_elements::G);
    (public, secret)
}

/// Update a pseudonym session key with new session key shares.
pub fn update_pseudonym_session_key(
    session_secret_key: crate::keys::PseudonymSessionSecretKey,
    old_session_key_share: crate::keys::distribution::PseudonymSessionKeyShare,
    new_session_key_share: crate::keys::distribution::PseudonymSessionKeyShare,
) -> (
    crate::keys::PseudonymSessionPublicKey,
    crate::keys::PseudonymSessionSecretKey,
) {
    update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update an attribute session key with new session key shares.
pub fn update_attribute_session_key(
    session_secret_key: crate::keys::AttributeSessionSecretKey,
    old_session_key_share: crate::keys::distribution::AttributeSessionKeyShare,
    new_session_key_share: crate::keys::distribution::AttributeSessionKeyShare,
) -> (
    crate::keys::AttributeSessionPublicKey,
    crate::keys::AttributeSessionSecretKey,
) {
    update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update session keys (both pseudonym and attribute) from old session key shares to new ones.
pub fn update_session_keys(
    current_keys: SessionKeys,
    old_shares: crate::keys::distribution::SessionKeyShares,
    new_shares: crate::keys::distribution::SessionKeyShares,
) -> SessionKeys {
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
        pseudonym: crate::keys::PseudonymSessionKeys {
            public: pseudonym_public,
            secret: pseudonym_secret,
        },
        attribute: crate::keys::AttributeSessionKeys {
            public: attribute_public,
            secret: attribute_secret,
        },
    }
}

/// Trait to update and extract session keys from SessionKeys based on the share type.
pub trait SessionKeyUpdater<S: SessionKeyShare> {
    fn get_current_secret(&self) -> S::SecretKeyType;
    fn set_keys(&mut self, public: S::PublicKeyType, secret: S::SecretKeyType);
}

impl SessionKeyUpdater<crate::keys::distribution::PseudonymSessionKeyShare> for SessionKeys {
    fn get_current_secret(&self) -> crate::keys::PseudonymSessionSecretKey {
        self.pseudonym.secret
    }

    fn set_keys(
        &mut self,
        public: crate::keys::PseudonymSessionPublicKey,
        secret: crate::keys::PseudonymSessionSecretKey,
    ) {
        self.pseudonym.public = public;
        self.pseudonym.secret = secret;
    }
}

impl SessionKeyUpdater<crate::keys::distribution::AttributeSessionKeyShare> for SessionKeys {
    fn get_current_secret(&self) -> crate::keys::AttributeSessionSecretKey {
        self.attribute.secret
    }

    fn set_keys(
        &mut self,
        public: crate::keys::AttributeSessionPublicKey,
        secret: crate::keys::AttributeSessionSecretKey,
    ) {
        self.attribute.public = public;
        self.attribute.secret = secret;
    }
}

/// Extension trait for Client with distributed-specific constructors and methods.
pub trait Distributed {
    /// Create a new PEP client from blinded global keys and session key shares.
    fn from_shares(
        blinded_global_keys: crate::keys::distribution::BlindedGlobalKeys,
        session_key_shares: &[crate::keys::distribution::SessionKeyShares],
    ) -> Self;

    /// Update a session key share from one session to another.
    /// Automatically selects the correct key (pseudonym or attribute) based on the share type.
    fn update_session_secret_key<S>(&mut self, old_key_share: S, new_key_share: S)
    where
        S: SessionKeyShare,
        SessionKeys: SessionKeyUpdater<S>;

    /// Update both pseudonym and attribute session key shares from one session to another.
    /// This is a convenience method that updates both shares together.
    fn update_session_secret_keys(
        &mut self,
        old_key_shares: crate::keys::distribution::SessionKeyShares,
        new_key_shares: crate::keys::distribution::SessionKeyShares,
    );
}

impl Distributed for super::Client {
    fn from_shares(
        blinded_global_keys: crate::keys::distribution::BlindedGlobalKeys,
        session_key_shares: &[crate::keys::distribution::SessionKeyShares],
    ) -> Self {
        let keys = make_session_keys_distributed(blinded_global_keys, session_key_shares);
        Self::new(keys)
    }

    fn update_session_secret_key<S>(&mut self, old_key_share: S, new_key_share: S)
    where
        S: SessionKeyShare,
        SessionKeys: SessionKeyUpdater<S>,
    {
        let current_secret = self.keys.get_current_secret();
        let (public, secret) = update_session_key(current_secret, old_key_share, new_key_share);
        self.keys.set_keys(public, secret);
    }

    fn update_session_secret_keys(
        &mut self,
        old_key_shares: crate::keys::distribution::SessionKeyShares,
        new_key_shares: crate::keys::distribution::SessionKeyShares,
    ) {
        self.keys = update_session_keys(self.keys, old_key_shares, new_key_shares);
    }
}
