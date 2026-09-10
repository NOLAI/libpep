//! Distributed client for reconstructing session keys from shares.

use crate::keys::SessionKeys;

/// How a session key is reconstructed from the material of the distributed setup.
///
/// The *roles* here are independent of the underlying cryptographic scheme: a session key is
/// always rebuilt from one blinded global secret key plus one share per transcryptor, and rotating
/// a single share always yields a new session key. The *rule* by which those parts combine is
/// scheme-specific, and lives in the implementations of this trait.
///
/// For the ElGamal instantiation the rule is multiplicative: shares are `kᵢ·bᵢ`, the blinded
/// global key carries `Π bᵢ⁻¹`, and the blinding factors cancel to leave `y·Π kᵢ`. This
/// cancellation is what allows the global secret key to stay hidden unless every transcryptor
/// cooperates.
pub trait SessionKeyReconstruction {
    /// One transcryptor's contribution to the session key.
    type Share: crate::keys::distribution::SessionKeyShare;
    /// The blinded global secret key the shares are combined with.
    type BlindedGlobal: crate::keys::distribution::BlindedGlobalSecretKey;
    /// The resulting session public key.
    type PublicKeyType: crate::keys::PublicKey;
    /// The resulting session secret key.
    type SecretKeyType: crate::keys::SecretKey<PublicKeyType = Self::PublicKeyType>;

    /// Combine a blinded global secret key with one share per transcryptor.
    fn reconstruct(
        blinded_global_secret_key: &Self::BlindedGlobal,
        shares: &[Self::Share],
    ) -> (Self::PublicKeyType, Self::SecretKeyType);

    /// Replace one share in an existing session key with a new one.
    fn rotate_share(
        session_secret_key: &Self::SecretKeyType,
        old_share: &Self::Share,
        new_share: &Self::Share,
    ) -> (Self::PublicKeyType, Self::SecretKeyType);
}

/// Generates the ElGamal reconstruction rule for one key flavour.
macro_rules! elgamal_reconstruction {
    ($($name:ident { share: $share:ty, blinded: $blinded:ty, public: $pk:ty, secret: $sk:ty })+) => {$(
        /// The ElGamal reconstruction rule, where shares and blinding factors combine
        /// multiplicatively.
        pub enum $name {}

        impl SessionKeyReconstruction for $name {
            type Share = $share;
            type BlindedGlobal = $blinded;
            type PublicKeyType = $pk;
            type SecretKeyType = $sk;

            fn reconstruct(
                blinded_global_secret_key: &Self::BlindedGlobal,
                shares: &[Self::Share],
            ) -> (Self::PublicKeyType, Self::SecretKeyType) {
                use crate::keys::distribution::BlindedGlobalSecretKey;
                use crate::keys::SecretKey;
                let secret = Self::SecretKeyType::from_scalar(
                    shares
                        .iter()
                        .fold(*blinded_global_secret_key.value(), |acc, x| acc * *x.value()),
                );
                (secret.public_key(), secret)
            }

            fn rotate_share(
                session_secret_key: &Self::SecretKeyType,
                old_share: &Self::Share,
                new_share: &Self::Share,
            ) -> (Self::PublicKeyType, Self::SecretKeyType) {
                use crate::keys::SecretKey;
                let secret = Self::SecretKeyType::from_scalar(
                    *session_secret_key.value()
                        * old_share.value().invert()
                        * *new_share.value(),
                );
                (secret.public_key(), secret)
            }
        }
    )+};
}

elgamal_reconstruction! {
    PseudonymSessionKeyReconstruction {
        share: crate::keys::distribution::PseudonymSessionKeyShare,
        blinded: crate::keys::distribution::BlindedPseudonymGlobalSecretKey,
        public: crate::keys::PseudonymSessionPublicKey,
        secret: crate::keys::PseudonymSessionSecretKey
    }
    AttributeSessionKeyReconstruction {
        share: crate::keys::distribution::AttributeSessionKeyShare,
        blinded: crate::keys::distribution::BlindedAttributeGlobalSecretKey,
        public: crate::keys::AttributeSessionPublicKey,
        secret: crate::keys::AttributeSessionSecretKey
    }
}

/// Polymorphic function to reconstruct a session key from a blinded global secret key and session key shares.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn make_session_key<R>(
    blinded_global_secret_key: R::BlindedGlobal,
    session_key_shares: &[R::Share],
) -> (R::PublicKeyType, R::SecretKeyType)
where
    R: SessionKeyReconstruction,
{
    R::reconstruct(&blinded_global_secret_key, session_key_shares)
}

/// Reconstruct a pseudonym session key from a blinded global secret key and session key shares.
pub fn make_pseudonym_session_key(
    blinded_global_secret_key: crate::keys::distribution::BlindedPseudonymGlobalSecretKey,
    session_key_shares: &[crate::keys::distribution::PseudonymSessionKeyShare],
) -> (
    crate::keys::PseudonymSessionPublicKey,
    crate::keys::PseudonymSessionSecretKey,
) {
    make_session_key::<PseudonymSessionKeyReconstruction>(
        blinded_global_secret_key,
        session_key_shares,
    )
}

/// Reconstruct an attribute session key from a blinded global secret key and session key shares.
pub fn make_attribute_session_key(
    blinded_global_secret_key: crate::keys::distribution::BlindedAttributeGlobalSecretKey,
    session_key_shares: &[crate::keys::distribution::AttributeSessionKeyShare],
) -> (
    crate::keys::AttributeSessionPublicKey,
    crate::keys::AttributeSessionSecretKey,
) {
    make_session_key::<AttributeSessionKeyReconstruction>(
        blinded_global_secret_key,
        session_key_shares,
    )
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

    let (pseudonym_public, pseudonym_secret) = make_session_key::<PseudonymSessionKeyReconstruction>(
        blinded_global_keys.pseudonym,
        &pseudonym_shares,
    );
    let (attribute_public, attribute_secret) = make_session_key::<AttributeSessionKeyReconstruction>(
        blinded_global_keys.attribute,
        &attribute_shares,
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

/// Polymorphic function to update a session key with new session key shares.
/// Automatically works for both pseudonym and attribute keys based on the types.
pub fn update_session_key<R>(
    session_secret_key: R::SecretKeyType,
    old_session_key_share: R::Share,
    new_session_key_share: R::Share,
) -> (R::PublicKeyType, R::SecretKeyType)
where
    R: SessionKeyReconstruction,
{
    R::rotate_share(
        &session_secret_key,
        &old_session_key_share,
        &new_session_key_share,
    )
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
    update_session_key::<PseudonymSessionKeyReconstruction>(
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
    update_session_key::<AttributeSessionKeyReconstruction>(
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
    let (pseudonym_public, pseudonym_secret) =
        update_session_key::<PseudonymSessionKeyReconstruction>(
            current_keys.pseudonym.secret,
            old_shares.pseudonym,
            new_shares.pseudonym,
        );
    let (attribute_public, attribute_secret) =
        update_session_key::<AttributeSessionKeyReconstruction>(
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

/// Trait to update and extract session keys from SessionKeys based on the reconstruction rule.
pub trait SessionKeyUpdater<R: SessionKeyReconstruction> {
    fn get_current_secret(&self) -> R::SecretKeyType;
    fn set_keys(&mut self, public: R::PublicKeyType, secret: R::SecretKeyType);
}

impl SessionKeyUpdater<PseudonymSessionKeyReconstruction> for SessionKeys {
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

impl SessionKeyUpdater<AttributeSessionKeyReconstruction> for SessionKeys {
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
        S: crate::keys::distribution::SessionKeyShare,
        SessionKeys: SessionKeyUpdater<S::Reconstruction>;

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
        S: crate::keys::distribution::SessionKeyShare,
        SessionKeys: SessionKeyUpdater<S::Reconstruction>,
    {
        let current_secret = self.keys.get_current_secret();
        let (public, secret) =
            update_session_key::<S::Reconstruction>(current_secret, old_key_share, new_key_share);
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
