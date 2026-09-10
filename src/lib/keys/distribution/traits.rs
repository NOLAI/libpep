//! Traits for the intermediate key material of the distributed setup.
//!
//! These types are **not** keys: no data is encrypted towards them and they have no associated
//! public key. They are intermediate values in the distributed protocol, and they deliberately do
//! not implement [`PublicKey`](crate::keys::PublicKey) or [`SecretKey`](crate::keys::SecretKey).
//!
//! A session secret key is reconstructed from a blinded global secret key together with one
//! session key share per transcryptor. That role structure is independent of the underlying
//! scheme; the rule by which the parts combine is not, and lives in
//! [`SessionKeyReconstruction`](crate::client::distributed::SessionKeyReconstruction).

use crate::elgamal::arithmetic::scalars::ScalarNonZero;

/// A global secret key blinded by the blinding factors of all transcryptors.
///
/// Blinding makes the value safe to publish: it hides the global secret key unless all
/// transcryptors cooperate. It is not usable as a decryption key on its own.
pub trait BlindedGlobalSecretKey: Sized {
    /// The scalar value of this blinded key.
    fn value(&self) -> &ScalarNonZero;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: ScalarNonZero) -> Self;
}

/// One transcryptor's contribution to a session key.
///
/// Shares are combined with a [`BlindedGlobalSecretKey`] to reconstruct a session key; a single
/// share reveals nothing about the session key on its own.
pub trait SessionKeyShare: Sized {
    /// The rule by which shares of this kind combine into a session key.
    type Reconstruction: crate::client::distributed::SessionKeyReconstruction<Share = Self>;

    /// The scalar value of this share.
    fn value(&self) -> &ScalarNonZero;

    /// Construct from a raw scalar.
    fn from_scalar(scalar: ScalarNonZero) -> Self;
}
