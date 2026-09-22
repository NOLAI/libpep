//! Factor and info types generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use crate::keys::traits::PublicKey;
use crate::keys::types::generic::{
    AttributeSessionPublicKey, PseudonymSessionPublicKey, SessionPublicKeys,
};
use derive_more::From;

/// High-level type for the factor used to [`rerandomize`](crate::elgamal::primitives::rerandomize) an [ElGamal](crate::elgamal::generic::ElGamal) ciphertext.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct RerandomizeFactor<G: Group>(pub(crate) G::Scalar);

impl<G: Group> RerandomizeFactor<G> {
    /// Wrap a scalar.
    pub fn from_scalar(scalar: G::Scalar) -> Self {
        Self(scalar)
    }

    /// The scalar value of this factor.
    pub fn scalar(&self) -> G::Scalar {
        self.0
    }
}

/// High-level type for the factor used to [`reshuffle`](crate::elgamal::primitives::reshuffle) an [ElGamal](crate::elgamal::generic::ElGamal) ciphertext.
///
/// Pseudonym unlinkability holds only while reshuffle factors remain secret: anyone who learns
/// the factors of two domains (or their ratio) can link pseudonyms between those domains.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ReshuffleFactor<G: Group>(pub(crate) G::Scalar);

impl<G: Group> ReshuffleFactor<G> {
    /// Wrap a scalar.
    pub fn from_scalar(scalar: G::Scalar) -> Self {
        Self(scalar)
    }

    /// The scalar value of this factor.
    pub fn scalar(&self) -> G::Scalar {
        self.0
    }
}

/// Trait for rekey factors that can be extracted to a scalar.
pub trait RekeyFactor {
    /// The group the factor is a scalar of.
    type Group: Group;

    /// Wrap a scalar.
    fn from_scalar(scalar: <Self::Group as Group>::Scalar) -> Self;

    /// The scalar value of this factor.
    fn scalar(&self) -> <Self::Group as Group>::Scalar;
}

/// High-level type for the factor used to [`rekey`](crate::elgamal::primitives::rekey) an [ElGamal](crate::elgamal::generic::ElGamal) ciphertext for pseudonyms.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PseudonymRekeyFactor<G: Group>(pub(crate) G::Scalar);

impl<G: Group> RekeyFactor for PseudonymRekeyFactor<G> {
    type Group = G;

    fn from_scalar(scalar: G::Scalar) -> Self {
        Self(scalar)
    }

    fn scalar(&self) -> G::Scalar {
        self.0
    }
}

/// High-level type for the factor used to [`rekey`](crate::elgamal::primitives::rekey) an [ElGamal](crate::elgamal::generic::ElGamal) ciphertext for attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct AttributeRekeyFactor<G: Group>(pub(crate) G::Scalar);

impl<G: Group> RekeyFactor for AttributeRekeyFactor<G> {
    type Group = G;

    fn from_scalar(scalar: G::Scalar) -> Self {
        Self(scalar)
    }

    fn scalar(&self) -> G::Scalar {
        self.0
    }
}

/// The information required to perform n-PEP pseudonymization from one domain and session to another:
/// a reshuffle factor `s` and a pseudonym rekey factor `k`, each the ratio between the factors
/// of the source and target.
///
/// For efficiency, we do not actually use the [`rsk2`](crate::elgamal::primitives::rsk2) operation, but instead use the regular [`rsk`](crate::elgamal::primitives::rsk) operation
/// with precomputed reshuffle and rekey factors, which is equivalent but more efficient.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PseudonymizationInfo<G: Group> {
    /// Reshuffle factor - transforms pseudonyms between different domains
    pub s: ReshuffleFactor<G>,
    /// Rekey factor - transforms pseudonyms between different sessions
    pub k: PseudonymRekeyFactor<G>,
}

impl<G: Group> PseudonymizationInfo<G> {
    /// Reverse the pseudonymization info (i.e., switch the direction of the pseudonymization).
    pub fn reverse(&self) -> Self {
        Self {
            s: ReshuffleFactor(G::scalar_inverse(&self.s.0)),
            k: PseudonymRekeyFactor(G::scalar_inverse(&self.k.0)),
        }
    }
}

/// The information required to perform n-PEP rekeying of pseudonyms from one session to another:
/// the ratio between the pseudonym rekey factors of the source and target session.
///
/// For efficiency, we do not actually use the [`rekey2`](crate::elgamal::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::elgamal::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct PseudonymRekeyInfo<G: Group> {
    /// Rekey factor - transforms pseudonyms between different sessions
    pub k: PseudonymRekeyFactor<G>,
}

impl<G: Group> PseudonymRekeyInfo<G> {
    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
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

/// The information required to perform n-PEP rekeying of attributes from one session to another:
/// the ratio between the attribute rekey factors of the source and target session.
///
/// For efficiency, we do not actually use the [`rekey2`](crate::elgamal::primitives::rekey2) operation, but instead use the regular [`rekey`](crate::elgamal::primitives::rekey) operation
/// with a precomputed rekey factor, which is equivalent but more efficient.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct AttributeRekeyInfo<G: Group> {
    /// Rekey factor - transforms attributes between different sessions
    pub k: AttributeRekeyFactor<G>,
}

impl<G: Group> AttributeRekeyInfo<G> {
    /// Reverse the rekey info (i.e., switch the direction of the rekeying).
    pub fn reverse(&self) -> Self {
        Self {
            k: AttributeRekeyFactor(G::scalar_inverse(&self.k.0)),
        }
    }
}

/// The information required for transcryption, containing both pseudonymization info and attribute rekey info.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct TranscryptionInfo<G: Group> {
    pub pseudonym: PseudonymizationInfo<G>,
    pub attribute: AttributeRekeyInfo<G>,
}

impl<G: Group> TranscryptionInfo<G> {
    /// Reverse the transcryption info (i.e., switch the direction of the transcryption).
    pub fn reverse(&self) -> Self {
        Self {
            pseudonym: self.pseudonym.reverse(),
            attribute: self.attribute.reverse(),
        }
    }
}

// The public key a ciphertext is encrypted under after transcryption. A transcryptor passes this
// on with the ciphertext, so that the next transcryptor (or the storage) can rerandomize it.

impl<G: Group> PseudonymRekeyInfo<G> {
    /// The public key that pseudonyms rekeyed with this info are encrypted under, given the key
    /// they were encrypted under before.
    pub fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        PseudonymSessionPublicKey::from_point(self.k.0 * *before.value())
    }
}

impl<G: Group> AttributeRekeyInfo<G> {
    /// The public key that attributes rekeyed with this info are encrypted under, given the key
    /// they were encrypted under before.
    pub fn rekey_public_key(
        &self,
        before: &AttributeSessionPublicKey<G>,
    ) -> AttributeSessionPublicKey<G> {
        AttributeSessionPublicKey::from_point(self.k.0 * *before.value())
    }
}

impl<G: Group> PseudonymizationInfo<G> {
    /// The public key that pseudonyms pseudonymized with this info are encrypted under, given the
    /// key they were encrypted under before.
    pub fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        PseudonymSessionPublicKey::from_point(self.k.0 * *before.value())
    }
}

impl<G: Group> TranscryptionInfo<G> {
    /// The public keys that data transcrypted with this info is encrypted under, given the keys
    /// it was encrypted under before.
    pub fn rekey_public_keys(&self, before: &SessionPublicKeys<G>) -> SessionPublicKeys<G> {
        SessionPublicKeys {
            pseudonym: self.pseudonym.rekey_public_key(&before.pseudonym),
            attribute: self.attribute.rekey_public_key(&before.attribute),
        }
    }
}
