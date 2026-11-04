//! Factor types for rerandomization, reshuffling and rekeying, and the info types that bundle
//! the factors needed for one transcryption.
//!
//! A *factor* is a single scalar operand of a PEP [primitive](crate::elgamal::primitives). An
//! *info* is what a transcryptor computes for a transcryption from one domain and session to
//! another: the factor ratios between the two, bundled per data type. The public key a
//! ciphertext is encrypted under after an info is applied is given by
//! [`keys::RekeyPublicKey`](crate::keys::RekeyPublicKey).

use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::arithmetic::Ristretto255;
use derive_more::From;

/// A factor: a single scalar operand of a PEP [primitive](crate::elgamal::primitives).
pub trait Factor: Copy {
    /// The group the factor is a scalar of.
    type Group: Group;

    /// Wrap a scalar.
    fn from_scalar(scalar: <Self::Group as Group>::Scalar) -> Self;

    /// The scalar value of this factor.
    fn scalar(&self) -> <Self::Group as Group>::Scalar;
}

macro_rules! factor {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Copy, Clone, Eq, PartialEq, zeroize::Zeroize, derive_more::Debug)]
        #[zeroize(bound = "")]
        #[debug("{}([redacted])", stringify!($name))]
        pub struct $name<G: Group = Ristretto255>(pub(crate) G::Scalar);

        impl<G: Group> Factor for $name<G> {
            type Group = G;

            fn from_scalar(scalar: G::Scalar) -> Self {
                Self(scalar)
            }

            fn scalar(&self) -> G::Scalar {
                self.0
            }
        }
    };
}

factor! {
    /// The factor of a [`rerandomize`](crate::elgamal::primitives::rerandomize).
    RerandomizeFactor
}
factor! {
    /// The factor of a [`reshuffle`](crate::elgamal::primitives::reshuffle): the secret `s` of
    /// the Diffie-Hellman function `F_s(M) = s * M`. Specific to a pseudonymization domain.
    ///
    /// Pseudonym unlinkability holds only while reshuffle factors remain secret: anyone who learns
    /// the factors of two domains (or their ratio) can link pseudonyms between those domains.
    /// Unlinkability also needs uniformly random origin identifiers, as reshuffling is a weak PRF;
    /// see [`reshuffle`](crate::elgamal::primitives::reshuffle).
    ReshuffleFactor
}
factor! {
    /// The factor of a [`rekey`](crate::elgamal::primitives::rekey) of pseudonyms. Specific to an
    /// encryption context, and kept separate from the attribute rekey factor, so that an
    /// encrypted pseudonym cannot be presented as an encrypted attribute and rekeyed without
    /// being reshuffled.
    PseudonymRekeyFactor
}
factor! {
    /// The factor of a [`rekey`](crate::elgamal::primitives::rekey) of attributes. Specific to an
    /// encryption context.
    AttributeRekeyFactor
}

/// The information for a pseudonymization from one domain and session to another: a reshuffle
/// factor `s` and a pseudonym rekey factor `k`, each the ratio between the factors of the
/// source and the target.
///
/// The transcryptor applies the ratios with the regular
/// [`rsk`](crate::elgamal::primitives::rsk) operation, which is equivalent to
/// [`rsk2`](crate::elgamal::primitives::rsk2) with the source and target factors but cheaper.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PseudonymizationInfo<G: Group = Ristretto255> {
    /// The reshuffle factor, from the source domain to the target domain.
    pub s: ReshuffleFactor<G>,
    /// The rekey factor, from the source session to the target session.
    pub k: PseudonymRekeyFactor<G>,
}

impl<G: Group> PseudonymizationInfo<G> {
    /// The info for the pseudonymization in the opposite direction.
    pub fn reverse(&self) -> Self {
        Self {
            s: ReshuffleFactor(G::scalar_inverse(&self.s.0)),
            k: PseudonymRekeyFactor(G::scalar_inverse(&self.k.0)),
        }
    }
}

/// The information for a rekeying of pseudonyms from one session to another: the ratio between
/// the pseudonym rekey factors of the source and the target session.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct PseudonymRekeyInfo<G: Group = Ristretto255> {
    /// The rekey factor, from the source session to the target session.
    pub k: PseudonymRekeyFactor<G>,
}

impl<G: Group> PseudonymRekeyInfo<G> {
    /// The info for the rekeying in the opposite direction.
    pub fn reverse(&self) -> Self {
        Self {
            k: PseudonymRekeyFactor(G::scalar_inverse(&self.k.0)),
        }
    }
}

impl<G: Group> From<PseudonymizationInfo<G>> for PseudonymRekeyInfo<G> {
    fn from(x: PseudonymizationInfo<G>) -> Self {
        Self { k: x.k }
    }
}

/// The information for a rekeying of attributes from one session to another: the ratio between
/// the attribute rekey factors of the source and the target session.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct AttributeRekeyInfo<G: Group = Ristretto255> {
    /// The rekey factor, from the source session to the target session.
    pub k: AttributeRekeyFactor<G>,
}

impl<G: Group> AttributeRekeyInfo<G> {
    /// The info for the rekeying in the opposite direction.
    pub fn reverse(&self) -> Self {
        Self {
            k: AttributeRekeyFactor(G::scalar_inverse(&self.k.0)),
        }
    }
}

/// The information for a transcryption from one domain and session to another: the
/// pseudonymization info for the pseudonyms and the rekey info for the attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct TranscryptionInfo<G: Group = Ristretto255> {
    /// The info applied to pseudonyms.
    pub pseudonym: PseudonymizationInfo<G>,
    /// The info applied to attributes.
    pub attribute: AttributeRekeyInfo<G>,
}

impl<G: Group> TranscryptionInfo<G> {
    /// The info for the transcryption in the opposite direction.
    pub fn reverse(&self) -> Self {
        Self {
            pseudonym: self.pseudonym.reverse(),
            attribute: self.attribute.reverse(),
        }
    }
}
