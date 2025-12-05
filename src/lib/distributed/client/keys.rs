//! Session key creation and update from session key shares for distributed trust clients.

use crate::arithmetic::group_elements::{GroupElement, G};
use crate::arithmetic::scalars::ScalarNonZero;
use crate::core::keys::{
    AttributeSessionKeys, AttributeSessionPublicKey, AttributeSessionSecretKey,
    PseudonymSessionKeys, PseudonymSessionPublicKey, PseudonymSessionSecretKey, SessionKeys,
};
use crate::distributed::server::keys::{
    AttributeSessionKeyShare, PseudonymSessionKeyShare, SessionKeyShares,
};
use crate::distributed::server::setup::{
    BlindedAttributeGlobalSecretKey, BlindedGlobalKeys, BlindedPseudonymGlobalSecretKey,
};
use std::ops::Deref;

/// Generic function to reconstruct a session key from a blinded global secret key and session key shares.
fn _make_session_key<BGSK, SKS, PK, SK>(
    blinded_global_secret_key: BGSK,
    session_key_shares: &[SKS],
) -> (PK, SK)
where
    BGSK: Deref<Target = ScalarNonZero>,
    SKS: Deref<Target = ScalarNonZero>,
    PK: From<GroupElement>,
    SK: Deref<Target = ScalarNonZero> + From<ScalarNonZero>,
{
    let secret = SK::from(
        session_key_shares
            .iter()
            .fold(*blinded_global_secret_key, |acc, x| acc * **x),
    );
    let public = PK::from(*secret * G);
    (public, secret)
}

/// Reconstruct a pseudonym session key from a [`BlindedPseudonymGlobalSecretKey`] and a list of [`PseudonymSessionKeyShare`]s.
pub fn make_pseudonym_session_key(
    blinded_global_secret_key: BlindedPseudonymGlobalSecretKey,
    session_key_shares: &[PseudonymSessionKeyShare],
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    _make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct an attribute session key from a [`BlindedAttributeGlobalSecretKey`] and a list of [`AttributeSessionKeyShare`]s.
pub fn make_attribute_session_key(
    blinded_global_secret_key: BlindedAttributeGlobalSecretKey,
    session_key_shares: &[AttributeSessionKeyShare],
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    _make_session_key(blinded_global_secret_key, session_key_shares)
}

/// Reconstruct session keys (both pseudonym and attribute) from blinded global secret keys and session key shares.
pub fn make_session_keys_distributed(
    blinded_global_keys: BlindedGlobalKeys,
    session_key_shares: &[SessionKeyShares],
) -> SessionKeys {
    let pseudonym_shares: Vec<PseudonymSessionKeyShare> =
        session_key_shares.iter().map(|s| s.pseudonym).collect();
    let attribute_shares: Vec<AttributeSessionKeyShare> =
        session_key_shares.iter().map(|s| s.attribute).collect();

    let (pseudonym_public, pseudonym_secret) =
        make_pseudonym_session_key(blinded_global_keys.pseudonym, &pseudonym_shares);
    let (attribute_public, attribute_secret) =
        make_attribute_session_key(blinded_global_keys.attribute, &attribute_shares);

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

/// Generic function to update a session key with new session key shares.
fn _update_session_key<SK, SKS, PK>(
    session_secret_key: SK,
    old_session_key_share: SKS,
    new_session_key_share: SKS,
) -> (PK, SK)
where
    SK: Deref<Target = ScalarNonZero> + From<ScalarNonZero>,
    SKS: Deref<Target = ScalarNonZero>,
    PK: From<GroupElement>,
{
    let secret =
        SK::from(*session_secret_key * old_session_key_share.invert() * *new_session_key_share);
    let public = PK::from(*secret * G);
    (public, secret)
}

/// Update a pseudonym session key share from one session to the other
pub fn update_pseudonym_session_key(
    session_secret_key: PseudonymSessionSecretKey,
    old_session_key_share: PseudonymSessionKeyShare,
    new_session_key_share: PseudonymSessionKeyShare,
) -> (PseudonymSessionPublicKey, PseudonymSessionSecretKey) {
    _update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update an attribute session key share from one session to the other
pub fn update_attribute_session_key(
    session_secret_key: AttributeSessionSecretKey,
    old_session_key_share: AttributeSessionKeyShare,
    new_session_key_share: AttributeSessionKeyShare,
) -> (AttributeSessionPublicKey, AttributeSessionSecretKey) {
    _update_session_key(
        session_secret_key,
        old_session_key_share,
        new_session_key_share,
    )
}

/// Update session keys (both pseudonym and attribute) from old session key shares to new ones.
pub fn update_session_keys(
    current_keys: SessionKeys,
    old_shares: SessionKeyShares,
    new_shares: SessionKeyShares,
) -> SessionKeys {
    let (pseudonym_public, pseudonym_secret) = update_pseudonym_session_key(
        current_keys.pseudonym.secret,
        old_shares.pseudonym,
        new_shares.pseudonym,
    );
    let (attribute_public, attribute_secret) = update_attribute_session_key(
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
