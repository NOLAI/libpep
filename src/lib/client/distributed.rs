//! Distributed client for reconstructing session keys from shares.
//!
//! A session secret key is the blinded global secret key multiplied by one session key share
//! per transcryptor: the blinding factors in the shares cancel against those in the blinded
//! key, leaving the global secret key times the rekey factors. Replacing one transcryptor's
//! share (when that transcryptor moves the client to another session) divides out the old share
//! and multiplies in the new one.
//!
//! The functions are generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`] and infer it from the key material they are given.

pub mod generic;

pub use generic::{
    make_attribute_session_key, make_pseudonym_session_key, make_session_key,
    make_session_keys_distributed, update_attribute_session_key, update_pseudonym_session_key,
    update_session_key, update_session_keys, Distributed, SessionKeyUpdater,
};
