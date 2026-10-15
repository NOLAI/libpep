//! Verifiable operations of the long data types, generic over the [`Group`].
//!
//! The pseudonymization proof of a long pseudonym is one RRSK batch proof over its blocks, which
//! share the factor proofs; a rekey proof is one proof per block. A batch proof lays all blocks
//! of all values out in one list.

use crate::data::long::generic::{LongEncryptedAttribute, LongEncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::data::simple::generic::EncryptedAttribute;
use crate::data::simple::generic::EncryptedPseudonym;
use crate::data::simple::ElGamalEncrypted;
#[cfg(feature = "batch")]
use crate::data::verifiable::batch::{
    BatchPseudonymizationProof, BatchRekeyProof, VerifiableBatchItem,
};
#[cfg(feature = "elgamal3")]
use crate::data::verifiable::common_gy;
use crate::data::verifiable::simple::generic::{AttributeRekeyProof, PseudonymRekeyProof};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable,
};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::verifiable::generic::VerifiableRRSKBatch;
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

/// Proof of a verifiable pseudonymization of a [`LongEncryptedPseudonym`]: one RRSK batch proof
/// over its blocks, so the proofs of the factors (`T`, `S`, `K`) appear once rather than once per
/// block.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
pub struct LongPseudonymPseudonymizationProof<G: Group>(pub VerifiableRRSKBatch<G>);

/// The ciphertexts of the blocks of a long value.
fn blocks<G: Group>(value: &LongEncryptedPseudonym<G>) -> Vec<ElGamal<G>> {
    value.0.iter().map(|block| *block.value()).collect()
}

/// The long value of the given block ciphertexts.
fn from_blocks<G: Group>(blocks: Vec<ElGamal<G>>) -> LongEncryptedPseudonym<G> {
    LongEncryptedPseudonym(
        blocks
            .into_iter()
            .map(EncryptedPseudonym::from_value)
            .collect(),
    )
}

impl<G: Group> LongPseudonymPseudonymizationProof<G> {
    fn reconstruct_under(
        &self,
        original: &LongEncryptedPseudonym<G>,
        gy: &G::Element,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> Option<LongEncryptedPseudonym<G>> {
        self.0
            .verified_reconstruct(
                &blocks(original),
                gy,
                &commitments.reshuffle_commitment,
                &commitments.rekey_commitment,
            )
            .map(from_blocks)
    }
}

impl<G: Group> VerifiablePseudonymizationProof for LongPseudonymPseudonymizationProof<G> {
    type Group = G;
    type DataType = LongEncryptedPseudonym<G>;
    type Output = LongEncryptedPseudonym<G>;

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> Option<Self::Output> {
        let gy = common_gy(&blocks(original))?;
        self.reconstruct_under(original, &gy, commitments)
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<G>,
        commitments: &VerifiablePseudonymizationCommitment<G>,
    ) -> Option<Self::Output> {
        self.reconstruct_under(original, public_key.value(), commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, _original: &Self::DataType) -> Self::Output {
        from_blocks(self.0.result())
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
        let blocks = blocks(self);
        // The blocks of one value carry one key; with mixed keys the proof does not verify.
        let gy = common_gy(&blocks).unwrap_or_else(G::generator);
        LongPseudonymPseudonymizationProof(VerifiableRRSKBatch::new(
            &blocks, &gy, &info.s.0, &info.k.0, rng,
        ))
    }

    #[cfg(not(feature = "elgamal3"))]
    fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &self,
        info: &PseudonymizationInfo<G>,
        public_key: &PseudonymSessionPublicKey<G>,
        rng: &mut R,
    ) -> Self::PseudonymizationProof {
        LongPseudonymPseudonymizationProof(VerifiableRRSKBatch::new(
            &blocks(self),
            public_key.value(),
            &info.s.0,
            &info.k.0,
            rng,
        ))
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
