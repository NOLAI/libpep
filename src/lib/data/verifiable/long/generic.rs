//! Verifiable operations of the long data types, generic over the [`Group`].
//!
//! A proof of a long value is one proof per block; a batch proof lays all blocks of all values
//! out in one list.

use crate::data::long::generic::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::data::simple::generic::{EncryptedAttribute, EncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::data::simple::ElGamalEncrypted;
#[cfg(feature = "batch")]
use crate::data::verifiable::batch::{
    BatchPseudonymizationProof, BatchRekeyProof, VerifiableBatchItem,
};
use crate::data::verifiable::simple::generic::{
    AttributeRekeyProof, PseudonymPseudonymizationProof, PseudonymRekeyProof,
};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable,
};
use crate::elgamal::arithmetic::group::Group;
#[cfg(feature = "batch")]
use crate::elgamal::generic::ElGamal;
use crate::factors::commitments::generic::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
};
use crate::factors::types::generic::PseudonymizationInfo;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::generic::PseudonymSessionPublicKey;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Proof of a verifiable pseudonymization of a [`LongEncryptedPseudonym`]: one proof per block.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
pub struct LongPseudonymPseudonymizationProof<G: Group>(pub Vec<PseudonymPseudonymizationProof<G>>);

impl<G: Group> VerifiablePseudonymizationProof for LongPseudonymPseudonymizationProof<G> {
    type Group = G;
    type DataType = LongEncryptedPseudonym<G>;
    type Output = LongEncryptedPseudonym<G>;

    #[cfg(feature = "elgamal3")]
    fn verify(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> bool {
        self.0.len() == original.0.len()
            && self
                .0
                .iter()
                .zip(&original.0)
                .all(|(p, block)| p.verify(block, commitments))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verify(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<G>,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> bool {
        self.0.len() == original.0.len()
            && self
                .0
                .iter()
                .zip(&original.0)
                .all(|(p, block)| p.verify(block, public_key, commitments))
    }

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> Option<Self::Output> {
        if self.0.len() != original.0.len() {
            return None;
        }
        self.0
            .iter()
            .zip(&original.0)
            .map(|(p, block)| p.verified_reconstruct(block, commitments))
            .collect::<Option<_>>()
            .map(LongEncryptedPseudonym)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<G>,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> Option<Self::Output> {
        if self.0.len() != original.0.len() {
            return None;
        }
        self.0
            .iter()
            .zip(&original.0)
            .map(|(p, block)| p.verified_reconstruct(block, public_key, commitments))
            .collect::<Option<_>>()
            .map(LongEncryptedPseudonym)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        LongEncryptedPseudonym(
            self.0
                .iter()
                .zip(&original.0)
                .map(|(p, block)| p.unverified_reconstruct(block))
                .collect(),
        )
    }
}

impl<G: Group> VerifiablePseudonymizable for LongEncryptedPseudonym<G> {
    type PseudonymizationProof = LongPseudonymPseudonymizationProof<G>;

    #[cfg(feature = "elgamal3")]
    fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &self,
        info: &PseudonymizationInfo<G>,
        rng: &mut R,
    ) -> Self::PseudonymizationProof {
        LongPseudonymPseudonymizationProof(
            self.0
                .iter()
                .map(|block| block.verifiable_pseudonymize(info, rng))
                .collect(),
        )
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &self,
        info: &PseudonymizationInfo<G>,
        public_key: &PseudonymSessionPublicKey<G>,
        rng: &mut R,
    ) -> Self::PseudonymizationProof {
        LongPseudonymPseudonymizationProof(
            self.0
                .iter()
                .map(|block| block.verifiable_pseudonymize(info, public_key, rng))
                .collect(),
        )
    }
}

/// The rekey proof of a long type: one rekey proof per block.
macro_rules! long_rekey_proof {
    ($(#[$doc:meta])* $proof:ident for $data:ident, block proof $block_proof:ident) => {
        $(#[$doc])*
        #[derive(Clone, Eq, PartialEq, Debug)]
        #[cfg_attr(
            feature = "serde",
            derive(Serialize, Deserialize),
            serde(bound = "", transparent)
        )]
        pub struct $proof<G: Group>(pub Vec<$block_proof<G>>);

        impl<G: Group> VerifiableRekeyProof for $proof<G> {
            type Group = G;
            type DataType = $data<G>;
            type Output = $data<G>;

            fn verify(
                &self,
                original: &Self::DataType,
                commitments: &VerifiableRekeyCommitment<G>,
            ) -> bool {
                self.0.len() == original.0.len()
                    && self
                        .0
                        .iter()
                        .zip(&original.0)
                        .all(|(p, block)| p.verify(block, commitments))
            }

            fn verified_reconstruct(
                &self,
                original: &Self::DataType,
                commitments: &VerifiableRekeyCommitment<G>,
            ) -> Option<Self::Output> {
                if self.0.len() != original.0.len() {
                    return None;
                }
                self.0
                    .iter()
                    .zip(&original.0)
                    .map(|(p, block)| p.verified_reconstruct(block, commitments))
                    .collect::<Option<_>>()
                    .map($data)
            }

            #[cfg(feature = "insecure")]
            fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
                $data(
                    self.0
                        .iter()
                        .zip(&original.0)
                        .map(|(p, block)| p.unverified_reconstruct(block))
                        .collect(),
                )
            }
        }

        impl<G: Group> VerifiableRekeyable for $data<G> {
            type RekeyProof = $proof<G>;

            fn verifiable_rekey<R: Rng + CryptoRng>(
                &self,
                info: &Self::RekeyInfo,
                rng: &mut R,
            ) -> Self::RekeyProof {
                $proof(
                    self.0
                        .iter()
                        .map(|block| block.verifiable_rekey(info, rng))
                        .collect(),
                )
            }
        }
    };
}

long_rekey_proof! {
    /// Proof of a verifiable rekeying of a [`LongEncryptedPseudonym`]: one proof per block.
    LongPseudonymRekeyProof for LongEncryptedPseudonym, block proof PseudonymRekeyProof
}
long_rekey_proof! {
    /// Proof of a verifiable rekeying of a [`LongEncryptedAttribute`]: one proof per block.
    LongAttributeRekeyProof for LongEncryptedAttribute, block proof AttributeRekeyProof
}

/// The blocks of a long value are consecutive entries of the given stream of a batch.
#[cfg(feature = "batch")]
macro_rules! long_batch_item {
    ($data:ident of $block:ident => $stream:ident of $pseudonyms:ident, $attributes:ident) => {
        impl<G: Group> VerifiableBatchItem for $data<G> {
            fn flatten(
                &self,
                $pseudonyms: &mut Vec<ElGamal<G>>,
                $attributes: &mut Vec<ElGamal<G>>,
            ) {
                $stream.extend(self.0.iter().map(|block| *block.value()));
            }

            fn rebuild(
                template: &Self,
                $pseudonyms: &mut impl Iterator<Item = ElGamal<G>>,
                $attributes: &mut impl Iterator<Item = ElGamal<G>>,
            ) -> Option<Self> {
                template
                    .0
                    .iter()
                    .map(|_| $stream.next().map($block::from_value))
                    .collect::<Option<_>>()
                    .map(Self)
            }
        }
    };
}

#[cfg(feature = "batch")]
long_batch_item!(LongEncryptedPseudonym of EncryptedPseudonym => pseudonyms of pseudonyms, _attributes);
#[cfg(feature = "batch")]
long_batch_item!(LongEncryptedAttribute of EncryptedAttribute => attributes of _pseudonyms, attributes);

/// Proof of a verifiable pseudonymization of a batch of [`LongEncryptedPseudonym`]s.
#[cfg(feature = "batch")]
pub type LongPseudonymPseudonymizationBatchProof<G> =
    BatchPseudonymizationProof<LongEncryptedPseudonym<G>>;
/// Proof of a verifiable rekeying of a batch of [`LongEncryptedPseudonym`]s.
#[cfg(feature = "batch")]
pub type LongPseudonymRekeyBatchProof<G> = BatchRekeyProof<LongEncryptedPseudonym<G>>;
/// Proof of a verifiable rekeying of a batch of [`LongEncryptedAttribute`]s.
#[cfg(feature = "batch")]
pub type LongAttributeRekeyBatchProof<G> = BatchRekeyProof<LongEncryptedAttribute<G>>;
