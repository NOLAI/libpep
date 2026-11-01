//! Verifiable variants of the records data-layer operations.
//!
//! Mirrors [`crate::data::records`].
//!
//! A proof of a record is one proof per pseudonym and per attribute; a batch proof lays all
//! pseudonyms and all attributes of all records out in two lists.

#[cfg(all(feature = "batch", feature = "long"))]
use crate::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use crate::data::records::EncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::LongEncryptedRecord;
#[cfg(feature = "batch")]
use crate::data::simple::{EncryptedAttribute, EncryptedPseudonym};
#[cfg(feature = "batch")]
use crate::data::verifiable::batch::{BatchTranscryptionProof, VerifiableBatchItem};
#[cfg(feature = "long")]
use crate::data::verifiable::long::{LongAttributeRekeyProof, LongPseudonymPseudonymizationProof};
use crate::data::verifiable::simple::{AttributeRekeyProof, PseudonymPseudonymizationProof};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizable, VerifiablePseudonymizationProof, VerifiableRekeyProof,
    VerifiableRekeyable, VerifiableTranscryptable, VerifiableTranscryptionProof,
};
use crate::elgamal::arithmetic::Ristretto255;
use crate::elgamal::arithmetic::{Ciphersuite, Group};
#[cfg(feature = "batch")]
use crate::elgamal::ElGamal;
use crate::factors::commitments::VerifiableTranscryptionCommitment;
use crate::factors::types::TranscryptionInfo;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::SessionPublicKeys;
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The transcryption proof of a record type: one pseudonymization proof per pseudonym and one
/// rekey proof per attribute, and the transcryption that produces it.
macro_rules! record_proof {
    ($(#[$doc:meta])* $proof:ident for $data:ident($p:ident, $a:ident),
     proofs $p_proof:ident, $a_proof:ident $(, $cfg:meta)?) => {
        $(#[$doc])*
        $(#[cfg($cfg)])?
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
        pub struct $proof<G: Group = Ristretto255> {
            /// The pseudonymization proofs, one per pseudonym.
            pub pseudonym_operation_proofs: Vec<$p_proof<G>>,
            /// The rekey proofs, one per attribute.
            pub attribute_operation_proofs: Vec<$a_proof<G>>,
        }

        $(#[cfg($cfg)])?
        impl<G: Group> VerifiableTranscryptionProof for $proof<G> {
            type Group = G;
            type DataType = $data<G>;
            type Output = $data<G>;

            #[cfg(feature = "elgamal3")]
            fn verified_reconstruct<C: Ciphersuite<Group = Self::Group>>(
                &self,
                original: &Self::DataType,
                commitments: &VerifiableTranscryptionCommitment<G>,
            ) -> Option<Self::Output> {
                if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
                    || self.attribute_operation_proofs.len() != original.attributes.len()
                {
                    return None;
                }
                let pseudonyms = self
                    .pseudonym_operation_proofs
                    .iter()
                    .zip(&original.pseudonyms)
                    .map(|(p, orig)| p.verified_reconstruct::<C>(orig, &commitments.pseudonym))
                    .collect::<Option<_>>()?;
                let attributes = self
                    .attribute_operation_proofs
                    .iter()
                    .zip(&original.attributes)
                    .map(|(p, orig)| p.verified_reconstruct::<C>(orig, &commitments.attribute))
                    .collect::<Option<_>>()?;
                Some($data::new(pseudonyms, attributes))
            }

            #[cfg(not(feature = "elgamal3"))]
            fn verified_reconstruct<C: Ciphersuite<Group = Self::Group>>(
                &self,
                original: &Self::DataType,
                keys: &SessionPublicKeys<G>,
                commitments: &VerifiableTranscryptionCommitment<G>,
            ) -> Option<Self::Output> {
                if self.pseudonym_operation_proofs.len() != original.pseudonyms.len()
                    || self.attribute_operation_proofs.len() != original.attributes.len()
                {
                    return None;
                }
                let pseudonyms = self
                    .pseudonym_operation_proofs
                    .iter()
                    .zip(&original.pseudonyms)
                    .map(|(p, orig)| {
                        p.verified_reconstruct::<C>(orig, &keys.pseudonym, &commitments.pseudonym)
                    })
                    .collect::<Option<_>>()?;
                let attributes = self
                    .attribute_operation_proofs
                    .iter()
                    .zip(&original.attributes)
                    .map(|(p, orig)| p.verified_reconstruct::<C>(orig, &commitments.attribute))
                    .collect::<Option<_>>()?;
                Some($data::new(pseudonyms, attributes))
            }

            #[cfg(feature = "insecure")]
            fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
                $data::new(
                    self.pseudonym_operation_proofs
                        .iter()
                        .zip(&original.pseudonyms)
                        .map(|(p, orig)| p.unverified_reconstruct(orig))
                        .collect(),
                    self.attribute_operation_proofs
                        .iter()
                        .zip(&original.attributes)
                        .map(|(p, orig)| p.unverified_reconstruct(orig))
                        .collect(),
                )
            }
        }

        $(#[cfg($cfg)])?
        impl<G: Group> VerifiableTranscryptable for $data<G> {
            type TranscryptionProof = $proof<G>;

            #[cfg(feature = "elgamal3")]
            fn verifiable_transcrypt<C: Ciphersuite<Group = Self::Group>, R: Rng + CryptoRng>(
                &self,
                info: &TranscryptionInfo<G>,
                rng: &mut R,
            ) -> Self::TranscryptionProof {
                $proof {
                    pseudonym_operation_proofs: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.verifiable_pseudonymize::<C, _>(&info.pseudonym, rng))
                        .collect(),
                    attribute_operation_proofs: self
                        .attributes
                        .iter()
                        .map(|a| a.verifiable_rekey::<C, _>(&info.attribute, rng))
                        .collect(),
                }
            }

            #[cfg(not(feature = "elgamal3"))]
            fn verifiable_transcrypt<C: Ciphersuite<Group = Self::Group>, R: Rng + CryptoRng>(
                &self,
                info: &TranscryptionInfo<G>,
                keys: &SessionPublicKeys<G>,
                rng: &mut R,
            ) -> Self::TranscryptionProof {
                $proof {
                    pseudonym_operation_proofs: self
                        .pseudonyms
                        .iter()
                        .map(|p| p.verifiable_pseudonymize::<C, _>(&info.pseudonym, &keys.pseudonym, rng))
                        .collect(),
                    attribute_operation_proofs: self
                        .attributes
                        .iter()
                        .map(|a| a.verifiable_rekey::<C, _>(&info.attribute, rng))
                        .collect(),
                }
            }
        }

        /// The pseudonyms and attributes of a record are consecutive entries of the two
        /// streams of a batch.
        #[cfg(feature = "batch")]
        $(#[cfg($cfg)])?
        impl<G: Group> VerifiableBatchItem for $data<G> {
            fn flatten(
                &self,
                pseudonyms: &mut Vec<ElGamal<G>>,
                attributes: &mut Vec<ElGamal<G>>,
            ) {
                for p in &self.pseudonyms {
                    p.flatten(pseudonyms, attributes);
                }
                for a in &self.attributes {
                    a.flatten(pseudonyms, attributes);
                }
            }

            fn rebuild(
                template: &Self,
                pseudonyms: &mut impl Iterator<Item = ElGamal<G>>,
                attributes: &mut impl Iterator<Item = ElGamal<G>>,
            ) -> Option<Self> {
                let p = template
                    .pseudonyms
                    .iter()
                    .map(|t| $p::rebuild(t, pseudonyms, attributes))
                    .collect::<Option<_>>()?;
                let a = template
                    .attributes
                    .iter()
                    .map(|t| $a::rebuild(t, pseudonyms, attributes))
                    .collect::<Option<_>>()?;
                Some(Self::new(p, a))
            }
        }
    };
}

record_proof! {
    /// Proof of a verifiable transcryption of an [`EncryptedRecord`].
    RecordTranscryptionProof for EncryptedRecord(EncryptedPseudonym, EncryptedAttribute),
    proofs PseudonymPseudonymizationProof, AttributeRekeyProof
}
record_proof! {
    /// Proof of a verifiable transcryption of a [`LongEncryptedRecord`].
    LongRecordTranscryptionProof for LongEncryptedRecord(LongEncryptedPseudonym, LongEncryptedAttribute),
    proofs LongPseudonymPseudonymizationProof, LongAttributeRekeyProof, feature = "long"
}

/// Proof of a verifiable transcryption of a batch of [`EncryptedRecord`]s.
#[cfg(feature = "batch")]
pub type RecordTranscryptionBatchProof<G = Ristretto255> =
    BatchTranscryptionProof<EncryptedRecord<G>>;
/// Proof of a verifiable transcryption of a batch of [`LongEncryptedRecord`]s.
#[cfg(all(feature = "batch", feature = "long"))]
pub type LongRecordTranscryptionBatchProof<G = Ristretto255> =
    BatchTranscryptionProof<LongEncryptedRecord<G>>;
