//! Verifiable operations of the simple data types, generic over the [`Group`].

use crate::data::simple::generic::{EncryptedAttribute, EncryptedPseudonym};
use crate::data::simple::ElGamalEncrypted;
#[cfg(feature = "batch")]
use crate::data::verifiable::batch::{
    BatchPseudonymizationProof, BatchRekeyProof, VerifiableBatchItem,
};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable,
};
use crate::elgamal::arithmetic::group::Group;
#[cfg(feature = "batch")]
use crate::elgamal::generic::ElGamal;
use crate::elgamal::verifiable::generic::{VerifiableRRSK, VerifiableRekey};
use crate::factors::commitments::generic::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
};
use crate::factors::types::generic::PseudonymizationInfo;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::traits::PublicKey;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::generic::PseudonymSessionPublicKey;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Proof of a verifiable pseudonymization of an [`EncryptedPseudonym`].
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
pub struct PseudonymPseudonymizationProof<G: Group>(pub VerifiableRRSK<G>);

impl<G: Group> VerifiablePseudonymizationProof for PseudonymPseudonymizationProof<G> {
    type Group = G;
    type DataType = EncryptedPseudonym<G>;
    type Output = EncryptedPseudonym<G>;

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> bool {
        self.0.verify(
            original.value(),
            &original.value().gy,
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<G>,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> bool {
        self.0.verify(
            original.value(),
            public_key.value(),
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> Option<Self::Output> {
        self.0
            .verified_reconstruct(
                original.value(),
                &original.value().gy,
                &commitments.reshuffle_commitment,
                &commitments.rekey_commitment,
            )
            .map(EncryptedPseudonym::from_value)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<G>,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> Option<Self::Output> {
        self.0
            .verified_reconstruct(
                original.value(),
                public_key.value(),
                &commitments.reshuffle_commitment,
                &commitments.rekey_commitment,
            )
            .map(EncryptedPseudonym::from_value)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, _original: &Self::DataType) -> Self::Output {
        EncryptedPseudonym::from_value(self.0.unverified_reconstruct())
    }
}

impl<G: Group> VerifiablePseudonymizable for EncryptedPseudonym<G> {
    type PseudonymizationProof = PseudonymPseudonymizationProof<G>;

    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &self,
        info: &PseudonymizationInfo<G>,
        rng: &mut R,
    ) -> Self::PseudonymizationProof {
        let r = G::random_scalar(rng);
        PseudonymPseudonymizationProof(VerifiableRRSK::new(
            self.value(),
            &self.value().gy,
            &r,
            &info.s.0,
            &info.k.0,
            rng,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &self,
        info: &PseudonymizationInfo<G>,
        public_key: &PseudonymSessionPublicKey<G>,
        rng: &mut R,
    ) -> Self::PseudonymizationProof {
        let r = G::random_scalar(rng);
        PseudonymPseudonymizationProof(VerifiableRRSK::new(
            self.value(),
            public_key.value(),
            &r,
            &info.s.0,
            &info.k.0,
            rng,
        ))
    }
}

/// The rekey proof of a single-ciphertext type, and the rekeying that produces it.
macro_rules! rekey_proof {
    ($(#[$doc:meta])* $proof:ident for $data:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Eq, PartialEq, Debug)]
        #[cfg_attr(
            feature = "serde",
            derive(Serialize, Deserialize),
            serde(bound = "", transparent)
        )]
        pub struct $proof<G: Group>(pub VerifiableRekey<G>);

        impl<G: Group> VerifiableRekeyProof for $proof<G> {
            type Group = G;
            type DataType = $data<G>;
            type Output = $data<G>;

            fn verify(
                &self,
                original: &Self::DataType,
                commitments: &VerifiableRekeyCommitment<G>,
            ) -> bool {
                self.0.verify(original.value(), &commitments.commitment)
            }

            fn verified_reconstruct(
                &self,
                original: &Self::DataType,
                commitments: &VerifiableRekeyCommitment<G>,
            ) -> Option<Self::Output> {
                self.0
                    .verified_reconstruct(original.value(), &commitments.commitment)
                    .map($data::from_value)
            }

            #[cfg(feature = "insecure")]
            fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
                $data::from_value(self.0.unverified_reconstruct(original.value()))
            }
        }

        impl<G: Group> VerifiableRekeyable for $data<G> {
            type RekeyProof = $proof<G>;

            fn verifiable_rekey<R: Rng + CryptoRng>(
                &self,
                info: &Self::RekeyInfo,
                rng: &mut R,
            ) -> Self::RekeyProof {
                $proof(VerifiableRekey::new(self.value(), &info.k.0, rng))
            }
        }
    };
}

rekey_proof! {
    /// Proof of a verifiable rekeying of an [`EncryptedPseudonym`].
    PseudonymRekeyProof for EncryptedPseudonym
}
rekey_proof! {
    /// Proof of a verifiable rekeying of an [`EncryptedAttribute`].
    AttributeRekeyProof for EncryptedAttribute
}

/// A single ciphertext is one entry of the given stream of a batch.
#[cfg(feature = "batch")]
macro_rules! batch_item {
    ($data:ident => $stream:ident of $pseudonyms:ident, $attributes:ident) => {
        impl<G: Group> VerifiableBatchItem for $data<G> {
            fn flatten(
                &self,
                $pseudonyms: &mut Vec<ElGamal<G>>,
                $attributes: &mut Vec<ElGamal<G>>,
            ) {
                $stream.push(*self.value());
            }

            fn rebuild(
                _template: &Self,
                $pseudonyms: &mut impl Iterator<Item = ElGamal<G>>,
                $attributes: &mut impl Iterator<Item = ElGamal<G>>,
            ) -> Option<Self> {
                $stream.next().map(Self::from_value)
            }
        }
    };
}

#[cfg(feature = "batch")]
batch_item!(EncryptedPseudonym => pseudonyms of pseudonyms, _attributes);
#[cfg(feature = "batch")]
batch_item!(EncryptedAttribute => attributes of _pseudonyms, attributes);

/// Proof of a verifiable pseudonymization of a batch of [`EncryptedPseudonym`]s.
#[cfg(feature = "batch")]
pub type PseudonymPseudonymizationBatchProof<G> = BatchPseudonymizationProof<EncryptedPseudonym<G>>;
/// Proof of a verifiable rekeying of a batch of [`EncryptedPseudonym`]s.
#[cfg(feature = "batch")]
pub type PseudonymRekeyBatchProof<G> = BatchRekeyProof<EncryptedPseudonym<G>>;
/// Proof of a verifiable rekeying of a batch of [`EncryptedAttribute`]s.
#[cfg(feature = "batch")]
pub type AttributeRekeyBatchProof<G> = BatchRekeyProof<EncryptedAttribute<G>>;
