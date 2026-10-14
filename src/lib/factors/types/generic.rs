//! Factor and info types generic over the [`Group`].

use crate::elgamal::arithmetic::group::Group;
use crate::keys::traits::PublicKey;
use crate::keys::types::generic::{
    AttributeSessionPublicKey, PseudonymSessionPublicKey, SessionPublicKeys,
};
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
        #[derive(Copy, Clone, Eq, PartialEq)]
        pub struct $name<G: Group>(pub(crate) G::Scalar);

        redacted_debug!($name<G>);

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
    /// The factor of a [`reshuffle`](crate::elgamal::primitives::reshuffle).
    ///
    /// Pseudonym unlinkability holds only while reshuffle factors remain secret: anyone who learns
    /// the factors of two domains (or their ratio) can link pseudonyms between those domains.
    ReshuffleFactor
}
factor! {
    /// The factor of a [`rekey`](crate::elgamal::primitives::rekey) of pseudonyms.
    PseudonymRekeyFactor
}
factor! {
    /// The factor of a [`rekey`](crate::elgamal::primitives::rekey) of attributes.
    AttributeRekeyFactor
}

/// The public key a ciphertext is encrypted under after a transcryption with this info, given
/// the key it was encrypted under before.
///
/// A transcryptor passes the key on with the ciphertext, so that the next transcryptor (or the
/// storage) can rerandomize it. Implemented for every info and the key, or key bundle, of the
/// data it transcrypts.
pub trait RekeyPublicKey<K> {
    /// The public key after rekeying `before` with this info: `k * before`.
    fn rekey_public_key(&self, before: &K) -> K;
}

/// The information for a pseudonymization from one domain and session to another: a reshuffle
/// factor `s` and a pseudonym rekey factor `k`, each the ratio between the factors of the
/// source and the target.
///
/// The transcryptor applies the ratios with the regular
/// [`rsk`](crate::elgamal::primitives::rsk) operation, which is equivalent to
/// [`rsk2`](crate::elgamal::primitives::rsk2) with the source and target factors but cheaper.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PseudonymizationInfo<G: Group> {
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

impl<G: Group> RekeyPublicKey<PseudonymSessionPublicKey<G>> for PseudonymizationInfo<G> {
    fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        PseudonymSessionPublicKey::from_point(self.k.0 * *before.value())
    }
}

/// The information for a rekeying of pseudonyms from one session to another: the ratio between
/// the pseudonym rekey factors of the source and the target session.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct PseudonymRekeyInfo<G: Group> {
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

impl<G: Group> RekeyPublicKey<PseudonymSessionPublicKey<G>> for PseudonymRekeyInfo<G> {
    fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        PseudonymSessionPublicKey::from_point(self.k.0 * *before.value())
    }
}

/// The information for a rekeying of attributes from one session to another: the ratio between
/// the attribute rekey factors of the source and the target session.
#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub struct AttributeRekeyInfo<G: Group> {
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

impl<G: Group> RekeyPublicKey<AttributeSessionPublicKey<G>> for AttributeRekeyInfo<G> {
    fn rekey_public_key(
        &self,
        before: &AttributeSessionPublicKey<G>,
    ) -> AttributeSessionPublicKey<G> {
        AttributeSessionPublicKey::from_point(self.k.0 * *before.value())
    }
}

/// The information for a transcryption from one domain and session to another: the
/// pseudonymization info for the pseudonyms and the rekey info for the attributes.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct TranscryptionInfo<G: Group> {
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

impl<G: Group> RekeyPublicKey<SessionPublicKeys<G>> for TranscryptionInfo<G> {
    fn rekey_public_key(&self, before: &SessionPublicKeys<G>) -> SessionPublicKeys<G> {
        SessionPublicKeys {
            pseudonym: self.pseudonym.rekey_public_key(&before.pseudonym),
            attribute: self.attribute.rekey_public_key(&before.attribute),
        }
    }
}

impl<G: Group> RekeyPublicKey<PseudonymSessionPublicKey<G>> for TranscryptionInfo<G> {
    fn rekey_public_key(
        &self,
        before: &PseudonymSessionPublicKey<G>,
    ) -> PseudonymSessionPublicKey<G> {
        self.pseudonym.rekey_public_key(before)
    }
}

impl<G: Group> RekeyPublicKey<AttributeSessionPublicKey<G>> for TranscryptionInfo<G> {
    fn rekey_public_key(
        &self,
        before: &AttributeSessionPublicKey<G>,
    ) -> AttributeSessionPublicKey<G> {
        self.attribute.rekey_public_key(before)
    }
}
