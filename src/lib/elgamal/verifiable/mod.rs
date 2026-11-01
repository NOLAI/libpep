//! The verifiable PEP primitives: every operation of [`primitives`]
//! with a zero-knowledge proof of its correct application, and the commitments to the factors
//! the proofs are verified against.
//!
//! The proof types are generic over the [`Group`](crate::elgamal::arithmetic::Group), which is
//! inferred from the ciphertext. Creating a proof and verifying it hash, so those take the
//! [`Ciphersuite`](crate::elgamal::arithmetic::Ciphersuite) as a type parameter.

#[macro_use]
mod macros;

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

pub use commitments::{FactorCommitment, PseudonymizationFactorCommitment, RekeyFactorCommitment};
pub use rekey::{VerifiableRekey, VerifiableRekey2};
pub use rekey_batch::{VerifiableRekey2Batch, VerifiableRekeyBatch};
pub use rerandomize::VerifiableRerandomize;
#[cfg(feature = "insecure")]
pub use rerandomize::{verifiable_rerandomize, verifiable_rerandomize_generic};
pub use rerandomize_batch::VerifiableRerandomizeBatch;
#[cfg(feature = "insecure")]
pub use rerandomize_batch::{verifiable_rerandomize_batch, verifiable_rerandomize_batch_generic};
pub use reshuffle::{VerifiableReshuffle, VerifiableReshuffle2};
pub use reshuffle_batch::{VerifiableReshuffle2Batch, VerifiableReshuffleBatch};
pub use rrsk::{VerifiableRRSK, VerifiableRRSK2};
pub use rrsk_batch::{VerifiableRRSK2Batch, VerifiableRRSKBatch};
pub use rsk::{VerifiableRSK, VerifiableRSK2, VerifiableRSKInner};
pub use rsk_batch::{VerifiableRSK2Batch, VerifiableRSKBatch};
