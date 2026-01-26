//! Prelude module for convenient imports.
//!
//! This module provides two sub-preludes:
//! - [`client`]: For encryption and decryption operations
//! - [`transcryptor`]: For pseudonymization, rekeying, and transcryption operations
//!
//! # Examples
//!
//! ```rust,ignore
//! use libpep::prelude::client::*;
//! use libpep::prelude::transcryptor::*;
//! ```

pub mod client {
    //! Client prelude for encryption and decryption operations.
    pub use crate::client::prelude::*;
}

pub mod transcryptor {
    //! Transcryptor prelude for pseudonymization, rekeying, and transcryption operations.
    pub use crate::transcryptor::prelude::*;
}
