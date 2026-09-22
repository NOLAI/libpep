//! Factor types for rerandomization, reshuffling and rekeying, and the info types that bundle
//! the factors needed for one transcryption.
//!
//! A *factor* is a single scalar operand of a PEP [primitive](crate::elgamal::primitives). An
//! *info* is what a transcryptor computes for a transcryption from one domain and session to
//! another: the factor ratios between the two, bundled per data type.
//!
//! The types are generic over the [`Group`](crate::elgamal::arithmetic::Group) in [`generic`];
//! the names in this module are their ristretto255 instances.

pub mod generic;

pub use generic::RekeyFactor;

use crate::elgamal::arithmetic::scalars::ScalarNonZero;
use crate::elgamal::arithmetic::Ristretto255;

/// The [`RerandomizeFactor`](generic::RerandomizeFactor) over ristretto255.
pub type RerandomizeFactor = generic::RerandomizeFactor<Ristretto255>;
/// The [`ReshuffleFactor`](generic::ReshuffleFactor) over ristretto255.
pub type ReshuffleFactor = generic::ReshuffleFactor<Ristretto255>;
/// The [`PseudonymRekeyFactor`](generic::PseudonymRekeyFactor) over ristretto255.
pub type PseudonymRekeyFactor = generic::PseudonymRekeyFactor<Ristretto255>;
/// The [`AttributeRekeyFactor`](generic::AttributeRekeyFactor) over ristretto255.
pub type AttributeRekeyFactor = generic::AttributeRekeyFactor<Ristretto255>;
/// The [`PseudonymizationInfo`](generic::PseudonymizationInfo) over ristretto255.
pub type PseudonymizationInfo = generic::PseudonymizationInfo<Ristretto255>;
/// The [`PseudonymRekeyInfo`](generic::PseudonymRekeyInfo) over ristretto255.
pub type PseudonymRekeyInfo = generic::PseudonymRekeyInfo<Ristretto255>;
/// The [`AttributeRekeyInfo`](generic::AttributeRekeyInfo) over ristretto255.
pub type AttributeRekeyInfo = generic::AttributeRekeyInfo<Ristretto255>;
/// The [`TranscryptionInfo`](generic::TranscryptionInfo) over ristretto255.
pub type TranscryptionInfo = generic::TranscryptionInfo<Ristretto255>;

macro_rules! impl_from_scalar {
    ($($t:ident),+ $(,)?) => {$(
        impl From<ScalarNonZero> for $t {
            fn from(scalar: ScalarNonZero) -> Self {
                generic::$t(scalar)
            }
        }
    )+};
}

impl_from_scalar!(
    RerandomizeFactor,
    ReshuffleFactor,
    PseudonymRekeyFactor,
    AttributeRekeyFactor,
);
