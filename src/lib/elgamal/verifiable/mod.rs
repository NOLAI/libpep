//! The verifiable PEP primitives: every operation of [`primitives`](crate::elgamal::primitives)
//! with a zero-knowledge proof of its correct application, and the commitments to the factors
//! the proofs are verified against.
//!
//! The proof types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in
//! [`generic`]; the names in this module are their ristretto255 instances.

/// `verified_reconstruct` (the result of the operation if the proof verifies) and, with
/// `insecure`, `unverified_reconstruct` (the result without verifying), from a proof type's
/// `verify` and its crate-private `result`, so that the two can never disagree with `verify`.
macro_rules! reconstruct {
    (
        verified($($va:ident: $vt:ty),*) -> $out:ty = verify($($vv:ident),*);
        unverified($($ua:ident: $ut:ty),*) = result($($rv:ident),*);
    ) => {
        /// Verify the proof and return the result of the operation, or `None` if it does not
        /// verify.
        #[must_use]
        pub fn verified_reconstruct(&self, $($va: $vt),*) -> Option<$out> {
            self.verify($($vv),*).then(|| self.result($($rv),*))
        }

        /// The result of the operation, without verifying the proof.
        #[cfg(feature = "insecure")]
        pub fn unverified_reconstruct(&self, $($ua: $ut),*) -> $out {
            self.result($($rv),*)
        }
    };
}

mod commitments;
mod rekey;
mod rekey_batch;
mod rerandomize;
mod rerandomize_batch;
mod reshuffle;
mod reshuffle_batch;
mod rrsk;
mod rrsk_batch;
mod rsk;
mod rsk_batch;

/// The proof types generic over the [`Group`](crate::elgamal::arithmetic::Group).
pub mod generic {
    pub use super::commitments::{
        FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment,
    };
    pub use super::rekey::{VerifiableRekey, VerifiableRekey2};
    pub use super::rekey_batch::{VerifiableRekey2Batch, VerifiableRekeyBatch};
    #[cfg(feature = "insecure")]
    pub use super::rerandomize::verifiable_rerandomize;
    pub use super::rerandomize::VerifiableRerandomize;
    #[cfg(feature = "insecure")]
    pub use super::rerandomize_batch::verifiable_rerandomize_batch;
    pub use super::rerandomize_batch::VerifiableRerandomizeBatch;
    pub use super::reshuffle::{VerifiableReshuffle, VerifiableReshuffle2};
    pub use super::reshuffle_batch::{VerifiableReshuffle2Batch, VerifiableReshuffleBatch};
    pub use super::rrsk::{VerifiableRRSK, VerifiableRRSK2};
    pub use super::rrsk_batch::{VerifiableRRSK2Batch, VerifiableRRSKBatch};
    pub use super::rsk::{VerifiableRSK, VerifiableRSK2, VerifiableRSKInner};
    pub use super::rsk_batch::{VerifiableRSK2Batch, VerifiableRSKBatch};
}

use crate::elgamal::arithmetic::Ristretto255;

#[cfg(feature = "insecure")]
pub use generic::verifiable_rerandomize;
#[cfg(feature = "insecure")]
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
    VerifiableRerandomizeBatch,
    VerifiableReshuffleBatch,
    VerifiableReshuffle2Batch,
    VerifiableRekeyBatch,
    VerifiableRekey2Batch,
    VerifiableRSKBatch,
    VerifiableRSK2Batch,
    VerifiableRRSKBatch,
    VerifiableRRSK2Batch,
);
