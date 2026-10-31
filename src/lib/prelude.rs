//! Preludes that import what the client and transcryptor roles need.
//!
//! There are two sub-preludes:
//! - [`client`]: encryption and decryption operations
//! - [`transcryptor`]: pseudonymization, rekeying and transcryption operations
//!
//! # Examples
//!
//! ```
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
