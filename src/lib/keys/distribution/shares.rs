//! Session key shares for distributed transcryptors.
//!
//! A session key share is one transcryptor's contribution to a session key. Combining all shares
//! with the corresponding [blinded global secret key](super::blinding) yields the session key;
//! a single share reveals nothing about it on its own.
//!
//! Shares are protocol material, not keys: no data is encrypted towards them and they have no
//! associated public key, so they do not implement [`SecretKey`](crate::keys::SecretKey).
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances. The share functions infer the
//! group from the factors they are given.

pub mod generic;

pub use generic::{
    make_attribute_session_key_share, make_pseudonym_session_key_share, make_session_key_share,
    make_session_key_shares, SessionKeyShare,
};

use crate::elgamal::arithmetic::Ristretto255;

/// The [`PseudonymSessionKeyShare`](generic::PseudonymSessionKeyShare) over ristretto255.
pub type PseudonymSessionKeyShare = generic::PseudonymSessionKeyShare<Ristretto255>;
/// The [`AttributeSessionKeyShare`](generic::AttributeSessionKeyShare) over ristretto255.
pub type AttributeSessionKeyShare = generic::AttributeSessionKeyShare<Ristretto255>;
/// The [`SessionKeyShares`](generic::SessionKeyShares) over ristretto255.
pub type SessionKeyShares = generic::SessionKeyShares<Ristretto255>;
