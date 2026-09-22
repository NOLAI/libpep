//! Key type definitions for global and session keys.
//!
//! Keys are split into separate Attribute and Pseudonym encryption keys to prevent pseudonym values
//! from being leaked by falsely presenting them as attributes.
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

use crate::elgamal::arithmetic::Ristretto255;

/// The [`GlobalPublicKeys`](generic::GlobalPublicKeys) over ristretto255.
pub type GlobalPublicKeys = generic::GlobalPublicKeys<Ristretto255>;
/// The [`GlobalSecretKeys`](generic::GlobalSecretKeys) over ristretto255.
pub type GlobalSecretKeys = generic::GlobalSecretKeys<Ristretto255>;
/// The [`PseudonymGlobalPublicKey`](generic::PseudonymGlobalPublicKey) over ristretto255.
pub type PseudonymGlobalPublicKey = generic::PseudonymGlobalPublicKey<Ristretto255>;
/// The [`PseudonymGlobalSecretKey`](generic::PseudonymGlobalSecretKey) over ristretto255.
pub type PseudonymGlobalSecretKey = generic::PseudonymGlobalSecretKey<Ristretto255>;
/// The [`AttributeGlobalPublicKey`](generic::AttributeGlobalPublicKey) over ristretto255.
pub type AttributeGlobalPublicKey = generic::AttributeGlobalPublicKey<Ristretto255>;
/// The [`AttributeGlobalSecretKey`](generic::AttributeGlobalSecretKey) over ristretto255.
pub type AttributeGlobalSecretKey = generic::AttributeGlobalSecretKey<Ristretto255>;
/// The [`SessionKeys`](generic::SessionKeys) over ristretto255.
pub type SessionKeys = generic::SessionKeys<Ristretto255>;
/// The [`SessionPublicKeys`](generic::SessionPublicKeys) over ristretto255.
pub type SessionPublicKeys = generic::SessionPublicKeys<Ristretto255>;
/// The [`PseudonymSessionKeys`](generic::PseudonymSessionKeys) over ristretto255.
pub type PseudonymSessionKeys = generic::PseudonymSessionKeys<Ristretto255>;
/// The [`AttributeSessionKeys`](generic::AttributeSessionKeys) over ristretto255.
pub type AttributeSessionKeys = generic::AttributeSessionKeys<Ristretto255>;
/// The [`PseudonymSessionPublicKey`](generic::PseudonymSessionPublicKey) over ristretto255.
pub type PseudonymSessionPublicKey = generic::PseudonymSessionPublicKey<Ristretto255>;
/// The [`PseudonymSessionSecretKey`](generic::PseudonymSessionSecretKey) over ristretto255.
pub type PseudonymSessionSecretKey = generic::PseudonymSessionSecretKey<Ristretto255>;
/// The [`AttributeSessionPublicKey`](generic::AttributeSessionPublicKey) over ristretto255.
pub type AttributeSessionPublicKey = generic::AttributeSessionPublicKey<Ristretto255>;
/// The [`AttributeSessionSecretKey`](generic::AttributeSessionSecretKey) over ristretto255.
pub type AttributeSessionSecretKey = generic::AttributeSessionSecretKey<Ristretto255>;
