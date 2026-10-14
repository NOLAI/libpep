//! The verifiable PEP primitives: every operation of [`primitives`](crate::elgamal::primitives)
//! with a zero-knowledge proof of its correct application, and the commitments to the factors
//! the proofs are verified against.
//!
//! The proof types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]; the names in this module are their ristretto255 instances. [`rfc`](crate::elgamal::verifiable::rfc) holds the
//! wire layouts of the draft's verifiable mode on ristretto255.

mod commitments;
mod rekey;
#[cfg(feature = "batch")]
mod rekey_batch;
mod rerandomize;
#[cfg(feature = "batch")]
mod rerandomize_batch;
mod reshuffle;
#[cfg(feature = "batch")]
mod reshuffle_batch;
pub mod rfc;
mod rrsk;
#[cfg(feature = "batch")]
mod rrsk_batch;
mod rsk;
#[cfg(feature = "batch")]
mod rsk_batch;

/// The proof types generic over the [`Group`](crate::elgamal::arithmetic::Group).
pub mod generic {
    pub use super::commitments::{
        FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
    };
    pub use super::rekey::{VerifiableRekey, VerifiableRekey2};
    #[cfg(feature = "batch")]
    pub use super::rekey_batch::{VerifiableRekey2Batch, VerifiableRekeyBatch};
    #[cfg(feature = "insecure")]
    pub use super::rerandomize::verifiable_rerandomize;
    pub use super::rerandomize::VerifiableRerandomize;
    #[cfg(all(feature = "batch", feature = "insecure"))]
    pub use super::rerandomize_batch::verifiable_rerandomize_batch;
    #[cfg(feature = "batch")]
    pub use super::rerandomize_batch::VerifiableRerandomizeBatch;
    pub use super::reshuffle::{VerifiableReshuffle, VerifiableReshuffle2};
    #[cfg(feature = "batch")]
    pub use super::reshuffle_batch::{VerifiableReshuffle2Batch, VerifiableReshuffleBatch};
    pub use super::rrsk::{VerifiableRRSK, VerifiableRRSK2};
    #[cfg(feature = "batch")]
    pub use super::rrsk_batch::{VerifiableRRSK2Batch, VerifiableRRSKBatch};
    pub use super::rsk::{VerifiableRSK, VerifiableRSK2, VerifiableRSKInner};
    #[cfg(feature = "batch")]
    pub use super::rsk_batch::{VerifiableRSK2Batch, VerifiableRSKBatch};
}

use crate::elgamal::arithmetic::Ristretto255;

#[cfg(feature = "insecure")]
pub use generic::verifiable_rerandomize;
#[cfg(all(feature = "batch", feature = "insecure"))]
pub use generic::verifiable_rerandomize_batch;

macro_rules! ristretto_aliases {
    ($($(#[$cfg:meta])* $name:ident),+ $(,)?) => {$(
        $(#[$cfg])*
        #[doc = concat!("The [`", stringify!($name), "`](generic::", stringify!($name), ") over ristretto255.")]
        pub type $name = generic::$name<Ristretto255>;
    )+};
}

ristretto_aliases!(
    FactorCommitment,
    PseudonymizationFactorCommitment,
    RekeyFactorCommitment,
    VerifiableRerandomize,
    VerifiableReshuffle,
    VerifiableReshuffle2,
    VerifiableRekey,
    VerifiableRekey2,
    VerifiableRSK,
    VerifiableRSK2,
    VerifiableRSKInner,
    VerifiableRRSK,
    VerifiableRRSK2,
    #[cfg(feature = "batch")]
    VerifiableRerandomizeBatch,
    #[cfg(feature = "batch")]
    VerifiableReshuffleBatch,
    #[cfg(feature = "batch")]
    VerifiableReshuffle2Batch,
    #[cfg(feature = "batch")]
    VerifiableRekeyBatch,
    #[cfg(feature = "batch")]
    VerifiableRekey2Batch,
    #[cfg(feature = "batch")]
    VerifiableRSKBatch,
    #[cfg(feature = "batch")]
    VerifiableRSK2Batch,
    #[cfg(feature = "batch")]
    VerifiableRRSKBatch,
    #[cfg(feature = "batch")]
    VerifiableRRSK2Batch,
);
