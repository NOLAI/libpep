//! Verifiable batch operations for every encrypted type.
//!
//! A batch proof is one proof of the primitives over all ciphertexts of all items, laid out in
//! one list ([`VerifiableBatchItem::flatten`]), and the items are rebuilt from the resulting
//! ciphertexts in the shape of the originals ([`VerifiableBatchItem::rebuild`]). The three
//! proof types here cover every item type: [`BatchPseudonymizationProof`] for pseudonyms,
//! [`BatchRekeyProof`] for anything that is rekeyed, and [`BatchTranscryptionProof`] for
//! anything that is transcrypted. The data modules name their instances
//! (`PseudonymPseudonymizationBatchProof`, `RecordTranscryptionBatchProof`, ...).
//!
//! The order of the items is preserved: the proof entries are positionally tied to the items,
//! so, unlike the plain batch operations, the verifiable ones do not shuffle.

use crate::data::batch::EncryptedBatch;
#[cfg(not(feature = "elgamal3"))]
use crate::data::traits::Encryptable;
use crate::data::traits::{Encrypted, Pseudonymizable, Rekeyable, Transcryptable};
use crate::data::verifiable::traits::{
    VerifiablePseudonymizationProof, VerifiableRekeyProof, VerifiableTranscryptionProof,
};
use crate::elgamal::arithmetic::group::Group;
use crate::elgamal::generic::ElGamal;
use crate::elgamal::verifiable::generic::{VerifiableRRSKBatch, VerifiableRekeyBatch};
use crate::factors::commitments::generic::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
use crate::factors::types::generic::{PseudonymizationInfo, TranscryptionInfo};
#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
use crate::factors::RekeyPublicKey;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::traits::PublicKey;
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::generic::{
    AttributeSessionPublicKey, PseudonymSessionPublicKey, SessionPublicKeys,
};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// The public key type of the data an encrypted type decrypts to.
#[cfg(not(feature = "elgamal3"))]
type PublicKeyOf<E> = <<E as Encrypted>::UnencryptedType as Encryptable>::PublicKeyType;

/// An encrypted type whose ciphertexts can be laid out in one list for a batch proof, and
/// rebuilt from such a list. Without `elgamal3`, its public key names the key its pseudonyms
/// are rerandomized under ([`BatchPublicKey`]).
#[cfg(not(feature = "elgamal3"))]
pub trait VerifiableBatchItem:
    Encrypted<UnencryptedType: Encryptable<PublicKeyType: BatchPublicKey<<Self as Encrypted>::Group>>>
{
    /// Append the pseudonym ciphertexts of this item to `pseudonyms` and the attribute
    /// ciphertexts to `attributes`, in the order [`rebuild`](Self::rebuild) takes them.
    fn flatten(
        &self,
        pseudonyms: &mut Vec<ElGamal<Self::Group>>,
        attributes: &mut Vec<ElGamal<Self::Group>>,
    );

    /// Rebuild an item of the shape of `template` from the next ciphertexts of the iterators,
    /// or `None` if they run out.
    fn rebuild(
        template: &Self,
        pseudonyms: &mut impl Iterator<Item = ElGamal<Self::Group>>,
        attributes: &mut impl Iterator<Item = ElGamal<Self::Group>>,
    ) -> Option<Self>;
}

/// An encrypted type whose ciphertexts can be laid out in one list for a batch proof, and
/// rebuilt from such a list.
#[cfg(feature = "elgamal3")]
pub trait VerifiableBatchItem: Encrypted {
    /// Append the pseudonym ciphertexts of this item to `pseudonyms` and the attribute
    /// ciphertexts to `attributes`, in the order [`rebuild`](Self::rebuild) takes them.
    fn flatten(
        &self,
        pseudonyms: &mut Vec<ElGamal<Self::Group>>,
        attributes: &mut Vec<ElGamal<Self::Group>>,
    );

    /// Rebuild an item of the shape of `template` from the next ciphertexts of the iterators,
    /// or `None` if they run out.
    fn rebuild(
        template: &Self,
        pseudonyms: &mut impl Iterator<Item = ElGamal<Self::Group>>,
        attributes: &mut impl Iterator<Item = ElGamal<Self::Group>>,
    ) -> Option<Self>;
}

/// The public key a batch's pseudonyms are encrypted under, for the rerandomization proofs.
#[cfg(not(feature = "elgamal3"))]
pub trait BatchPublicKey<G: Group> {
    /// The public key element of the pseudonyms.
    fn pseudonym_element(&self) -> G::Element;
}

#[cfg(not(feature = "elgamal3"))]
impl<G: Group> BatchPublicKey<G> for PseudonymSessionPublicKey<G> {
    fn pseudonym_element(&self) -> G::Element {
        *self.value()
    }
}

/// A batch of attributes has no pseudonyms; the key only names a base for an empty proof.
#[cfg(not(feature = "elgamal3"))]
impl<G: Group> BatchPublicKey<G> for AttributeSessionPublicKey<G> {
    fn pseudonym_element(&self) -> G::Element {
        *self.value()
    }
}

#[cfg(not(feature = "elgamal3"))]
impl<G: Group> BatchPublicKey<G> for SessionPublicKeys<G> {
    fn pseudonym_element(&self) -> G::Element {
        *self.pseudonym.value()
    }
}

type Flat<G> = (Vec<ElGamal<G>>, Vec<ElGamal<G>>);

/// The pseudonym and attribute ciphertexts of all items.
fn flatten<E: VerifiableBatchItem>(items: &[E]) -> Flat<E::Group> {
    let mut pseudonyms = Vec::new();
    let mut attributes = Vec::new();
    for item in items {
        item.flatten(&mut pseudonyms, &mut attributes);
    }
    (pseudonyms, attributes)
}

/// Rebuild every item of `templates` from the ciphertexts, which must be exactly as many as
/// [`flatten`] produces for the templates.
fn rebuild<E: VerifiableBatchItem>(
    templates: &[E],
    pseudonyms: Vec<ElGamal<E::Group>>,
    attributes: Vec<ElGamal<E::Group>>,
) -> Option<Vec<E>> {
    let mut pseudonyms = pseudonyms.into_iter();
    let mut attributes = attributes.into_iter();
    let items = templates
        .iter()
        .map(|template| E::rebuild(template, &mut pseudonyms, &mut attributes))
        .collect::<Option<Vec<_>>>()?;
    (pseudonyms.next().is_none() && attributes.next().is_none()).then_some(items)
}

/// Rebuild on the prover's side, where the ciphertexts come from the prover's own layout.
fn rebuild_own<E: VerifiableBatchItem>(
    templates: &[E],
    pseudonyms: Vec<ElGamal<E::Group>>,
    attributes: Vec<ElGamal<E::Group>>,
) -> Vec<E> {
    rebuild(templates, pseudonyms, attributes)
        .unwrap_or_else(|| unreachable!("the proof covers every ciphertext of the batch"))
}

#[cfg(feature = "elgamal3")]
use super::common_gy as batch_gy;

/// Proof of a verifiable pseudonymization of a batch of `E`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
pub struct BatchPseudonymizationProof<E: VerifiableBatchItem>(
    /// The proof over the pseudonym ciphertexts of all items.
    pub VerifiableRRSKBatch<E::Group>,
    #[cfg_attr(feature = "serde", serde(skip))] PhantomData<E>,
);

/// Proof of a verifiable rekeying of a batch of `E`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "", transparent)
)]
pub struct BatchRekeyProof<E: VerifiableBatchItem>(
    /// The proof over the ciphertexts of all items.
    pub VerifiableRekeyBatch<E::Group>,
    #[cfg_attr(feature = "serde", serde(skip))] PhantomData<E>,
);

/// Proof of a verifiable transcryption of a batch of `E`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(bound = ""))]
pub struct BatchTranscryptionProof<E: VerifiableBatchItem> {
    /// The proof over the pseudonym ciphertexts of all items.
    pub pseudonyms: VerifiableRRSKBatch<E::Group>,
    /// The proof over the attribute ciphertexts of all items.
    pub attributes: VerifiableRekeyBatch<E::Group>,
    #[cfg_attr(feature = "serde", serde(skip))]
    items: PhantomData<E>,
}

/// The key the pseudonyms of `original` were rerandomized under, given the key the verifier
/// claims. With `batch-pk` the batch carries its key, and a claim that differs from it is
/// refused instead of silently preferred.
#[cfg(not(feature = "elgamal3"))]
fn rerandomization_key<E: VerifiableBatchItem>(
    original: &EncryptedBatch<E>,
    claimed: &<E::Group as Group>::Element,
) -> Option<<E::Group as Group>::Element> {
    #[cfg(feature = "batch-pk")]
    if original.public_key.pseudonym_element() != *claimed {
        return None;
    }
    #[cfg(not(feature = "batch-pk"))]
    let _ = original;
    Some(*claimed)
}

impl<E: VerifiableBatchItem> BatchPseudonymizationProof<E> {
    /// Verify against `items`, rerandomized under `gy`, and rebuild the result.
    fn reconstruct_under(
        &self,
        items: &[E],
        gy: &<E::Group as Group>::Element,
        commitments: &VerifiablePseudonymizationCommitment<E::Group>,
    ) -> Option<Vec<E>> {
        let (pseudonyms, attributes) = flatten(items);
        let news = self.0.verified_reconstruct(
            &pseudonyms,
            gy,
            &commitments.reshuffle_commitment,
            &commitments.rekey_commitment,
        )?;
        rebuild(items, news, attributes)
    }
}

impl<E: VerifiableBatchItem> BatchTranscryptionProof<E> {
    /// Verify against `items`, whose pseudonyms are rerandomized under `gy`, and rebuild the
    /// result.
    fn reconstruct_under(
        &self,
        items: &[E],
        gy: &<E::Group as Group>::Element,
        commitments: &VerifiableTranscryptionCommitment<E::Group>,
    ) -> Option<Vec<E>> {
        let (pseudonyms, attributes) = flatten(items);
        let pseudonyms = self.pseudonyms.verified_reconstruct(
            &pseudonyms,
            gy,
            &commitments.pseudonym.reshuffle_commitment,
            &commitments.pseudonym.rekey_commitment,
        )?;
        let attributes = self
            .attributes
            .verified_reconstruct(&attributes, &commitments.attribute.commitment)?;
        rebuild(items, pseudonyms, attributes)
    }
}

impl<E: VerifiableBatchItem + Pseudonymizable> VerifiablePseudonymizationProof
    for BatchPseudonymizationProof<E>
{
    type Group = E::Group;
    type DataType = EncryptedBatch<E>;
    type Output = Vec<E>;

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiablePseudonymizationCommitment<E::Group>,
    ) -> Option<Self::Output> {
        let gy = batch_gy(&flatten(&original.items).0)?;
        self.reconstruct_under(&original.items, &gy, commitments)
    }

    /// With `batch-pk`, `public_key` must be the key the batch carries.
    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &PseudonymSessionPublicKey<E::Group>,
        commitments: &VerifiablePseudonymizationCommitment<E::Group>,
    ) -> Option<Self::Output> {
        let gy = rerandomization_key(original, public_key.value())?;
        self.reconstruct_under(&original.items, &gy, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        let (_, attributes) = flatten(&original.items);
        rebuild_own(&original.items, self.0.result(), attributes)
    }
}

impl<E: VerifiableBatchItem + Rekeyable> VerifiableRekeyProof for BatchRekeyProof<E> {
    type Group = E::Group;
    type DataType = EncryptedBatch<E>;
    type Output = Vec<E>;

    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiableRekeyCommitment<E::Group>,
    ) -> Option<Self::Output> {
        let (pseudonyms, attributes) = flatten(&original.items);
        let split = pseudonyms.len();
        let mut all = pseudonyms;
        all.extend(attributes);
        let mut news = self.0.verified_reconstruct(&all, &commitments.commitment)?;
        let attributes = news.split_off(split);
        rebuild(&original.items, news, attributes)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        let (pseudonyms, attributes) = flatten(&original.items);
        let split = pseudonyms.len();
        let mut all = pseudonyms;
        all.extend(attributes);
        let mut news = self.0.result(&all);
        let attributes = news.split_off(split);
        rebuild_own(&original.items, news, attributes)
    }
}

impl<E: VerifiableBatchItem + Transcryptable> VerifiableTranscryptionProof
    for BatchTranscryptionProof<E>
{
    type Group = E::Group;
    type DataType = EncryptedBatch<E>;
    type Output = Vec<E>;

    #[cfg(feature = "elgamal3")]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        commitments: &VerifiableTranscryptionCommitment<E::Group>,
    ) -> Option<Self::Output> {
        let gy = batch_gy(&flatten(&original.items).0)?;
        self.reconstruct_under(&original.items, &gy, commitments)
    }

    /// With `batch-pk`, `public_key` must be the key the batch carries.
    #[cfg(not(feature = "elgamal3"))]
    fn verified_reconstruct(
        &self,
        original: &Self::DataType,
        public_key: &SessionPublicKeys<E::Group>,
        commitments: &VerifiableTranscryptionCommitment<E::Group>,
    ) -> Option<Self::Output> {
        let gy = rerandomization_key(original, public_key.pseudonym.value())?;
        self.reconstruct_under(&original.items, &gy, commitments)
    }

    #[cfg(feature = "insecure")]
    fn unverified_reconstruct(&self, original: &Self::DataType) -> Self::Output {
        let (_, attributes) = flatten(&original.items);
        let attributes = self.attributes.result(&attributes);
        rebuild_own(&original.items, self.pseudonyms.result(), attributes)
    }
}

// `verified_reconstruct` as a batch, the form to use for a whole batch: the key the pseudonyms
// were rerandomized under comes from the batch itself (`batch-pk`), from the batch's own key
// type (without `batch-pk`), or from the ciphertexts (`elgamal3`), so it is never given twice.

/// The verified batch with the key it is encrypted under afterwards (`batch-pk`).
#[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
fn with_key<E: VerifiableBatchItem>(
    items: Vec<E>,
    public_key: &PublicKeyOf<E>,
) -> EncryptedBatch<E> {
    EncryptedBatch {
        public_key: *public_key,
        items,
    }
}

macro_rules! verified_reconstruct_batch_rerandomized {
    ($proof:ident, $bound:path, $commitment:ident) => {
        impl<E: VerifiableBatchItem + $bound> $proof<E> {
            /// Verify the batch proof against the batch and the key it carries, and return the
            /// resulting batch, or `None` if it does not verify; `new_public_key` is the key the
            /// batch is encrypted under afterwards.
            #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
            pub fn verified_reconstruct_batch(
                &self,
                original: &EncryptedBatch<E>,
                new_public_key: &PublicKeyOf<E>,
                commitments: &$commitment<E::Group>,
            ) -> Option<EncryptedBatch<E>> {
                let gy = original.public_key.pseudonym_element();
                let items = self.reconstruct_under(&original.items, &gy, commitments)?;
                Some(with_key(items, new_public_key))
            }

            /// Verify the batch proof and return the resulting batch, or `None` if it does not
            /// verify; `public_key` is the key the batch is encrypted under.
            #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
            pub fn verified_reconstruct_batch(
                &self,
                original: &EncryptedBatch<E>,
                public_key: &PublicKeyOf<E>,
                commitments: &$commitment<E::Group>,
            ) -> Option<EncryptedBatch<E>> {
                let gy = public_key.pseudonym_element();
                let items = self.reconstruct_under(&original.items, &gy, commitments)?;
                Some(EncryptedBatch { items })
            }

            /// Verify the batch proof and return the resulting batch, or `None` if it does not
            /// verify.
            #[cfg(feature = "elgamal3")]
            pub fn verified_reconstruct_batch(
                &self,
                original: &EncryptedBatch<E>,
                commitments: &$commitment<E::Group>,
            ) -> Option<EncryptedBatch<E>> {
                let gy = batch_gy(&flatten(&original.items).0)?;
                let items = self.reconstruct_under(&original.items, &gy, commitments)?;
                Some(EncryptedBatch { items })
            }
        }
    };
}

verified_reconstruct_batch_rerandomized!(
    BatchPseudonymizationProof,
    Pseudonymizable,
    VerifiablePseudonymizationCommitment
);
verified_reconstruct_batch_rerandomized!(
    BatchTranscryptionProof,
    Transcryptable,
    VerifiableTranscryptionCommitment
);

impl<E: VerifiableBatchItem + Rekeyable> BatchRekeyProof<E> {
    /// Verify the batch proof and return the resulting batch, or `None` if it does not verify;
    /// `new_public_key` is the key the batch is encrypted under afterwards.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &EncryptedBatch<E>,
        new_public_key: &PublicKeyOf<E>,
        commitments: &VerifiableRekeyCommitment<E::Group>,
    ) -> Option<EncryptedBatch<E>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(with_key(items, new_public_key))
    }

    /// Verify the batch proof and return the resulting batch, or `None` if it does not verify.
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    pub fn verified_reconstruct_batch(
        &self,
        original: &EncryptedBatch<E>,
        commitments: &VerifiableRekeyCommitment<E::Group>,
    ) -> Option<EncryptedBatch<E>> {
        let items = self.verified_reconstruct(original, commitments)?;
        Some(EncryptedBatch { items })
    }
}

// The prover's side: the operations on a batch that produce a proof. Where the batch carries
// its public key (`batch-pk`), the key is converted along; otherwise it is an argument, or
// read from the ciphertexts (`elgamal3`).

impl<E: VerifiableBatchItem + Pseudonymizable> EncryptedBatch<E> {
    fn pseudonymize_under<R: Rng + CryptoRng>(
        &mut self,
        gy: <E::Group as Group>::Element,
        info: &PseudonymizationInfo<E::Group>,
        rng: &mut R,
    ) -> BatchPseudonymizationProof<E> {
        let (pseudonyms, attributes) = flatten(&self.items);
        let proof = VerifiableRRSKBatch::new(&pseudonyms, &gy, &info.s.0, &info.k.0, rng);
        self.items = rebuild_own(&self.items, proof.result(), attributes);
        BatchPseudonymizationProof(proof, PhantomData)
    }

    /// Pseudonymize every item with a proof. The batch's public key is converted along.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &mut self,
        info: &PseudonymizationInfo<E::Group>,
        rng: &mut R,
    ) -> BatchPseudonymizationProof<E>
    where
        PseudonymizationInfo<E::Group>: RekeyPublicKey<PublicKeyOf<E>>,
    {
        let proof = self.pseudonymize_under(self.public_key.pseudonym_element(), info, rng);
        self.public_key = info.rekey_public_key(&self.public_key);
        proof
    }

    /// Pseudonymize every item with a proof. `public_key` is the key the items are currently
    /// encrypted under.
    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    pub fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &mut self,
        info: &PseudonymizationInfo<E::Group>,
        public_key: &PublicKeyOf<E>,
        rng: &mut R,
    ) -> BatchPseudonymizationProof<E> {
        self.pseudonymize_under(public_key.pseudonym_element(), info, rng)
    }

    /// Pseudonymize every item with a proof.
    #[cfg(feature = "elgamal3")]
    pub fn verifiable_pseudonymize<R: Rng + CryptoRng>(
        &mut self,
        info: &PseudonymizationInfo<E::Group>,
        rng: &mut R,
    ) -> BatchPseudonymizationProof<E> {
        let (pseudonyms, _) = flatten(&self.items);
        // Ciphertexts under different keys cannot be in one batch; a proof made with the
        // generator in that case does not verify.
        let gy = batch_gy(&pseudonyms).unwrap_or_else(E::Group::generator);
        self.pseudonymize_under(gy, info, rng)
    }
}

impl<E: VerifiableBatchItem + Rekeyable> EncryptedBatch<E> {
    fn rekey_with<R: Rng + CryptoRng>(
        &mut self,
        k: &<E::Group as Group>::Scalar,
        rng: &mut R,
    ) -> BatchRekeyProof<E> {
        let (pseudonyms, attributes) = flatten(&self.items);
        let split = pseudonyms.len();
        let mut all = pseudonyms;
        all.extend(attributes);
        let proof = VerifiableRekeyBatch::new(&all, k, rng);
        let mut news = proof.result(&all);
        let attributes = news.split_off(split);
        self.items = rebuild_own(&self.items, news, attributes);
        BatchRekeyProof(proof, PhantomData)
    }

    /// Rekey every item with a proof. The batch's public key is converted along.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verifiable_rekey<R: Rng + CryptoRng>(
        &mut self,
        info: &E::RekeyInfo,
        rng: &mut R,
    ) -> BatchRekeyProof<E>
    where
        E::RekeyInfo: RekeyFactorOf<E::Group> + RekeyPublicKey<PublicKeyOf<E>>,
    {
        let proof = self.rekey_with(&info.rekey_factor(), rng);
        self.public_key = info.rekey_public_key(&self.public_key);
        proof
    }

    /// Rekey every item with a proof.
    #[cfg(any(feature = "elgamal3", not(feature = "batch-pk")))]
    pub fn verifiable_rekey<R: Rng + CryptoRng>(
        &mut self,
        info: &E::RekeyInfo,
        rng: &mut R,
    ) -> BatchRekeyProof<E>
    where
        E::RekeyInfo: RekeyFactorOf<E::Group>,
    {
        self.rekey_with(&info.rekey_factor(), rng)
    }
}

/// The rekey factor of a rekey info, for the batch proof over any rekeyable type.
pub trait RekeyFactorOf<G: Group> {
    /// The rekey factor `k`.
    fn rekey_factor(&self) -> G::Scalar;
}

impl<G: Group> RekeyFactorOf<G> for crate::factors::types::generic::PseudonymRekeyInfo<G> {
    fn rekey_factor(&self) -> G::Scalar {
        self.k.0
    }
}

impl<G: Group> RekeyFactorOf<G> for crate::factors::types::generic::AttributeRekeyInfo<G> {
    fn rekey_factor(&self) -> G::Scalar {
        self.k.0
    }
}

impl<E: VerifiableBatchItem + Transcryptable> EncryptedBatch<E> {
    fn transcrypt_under<R: Rng + CryptoRng>(
        &mut self,
        gy: <E::Group as Group>::Element,
        info: &TranscryptionInfo<E::Group>,
        rng: &mut R,
    ) -> BatchTranscryptionProof<E> {
        let (pseudonyms, attributes) = flatten(&self.items);
        let pseudonym_proof = VerifiableRRSKBatch::new(
            &pseudonyms,
            &gy,
            &info.pseudonym.s.0,
            &info.pseudonym.k.0,
            rng,
        );
        let attribute_proof = VerifiableRekeyBatch::new(&attributes, &info.attribute.k.0, rng);
        let attributes = attribute_proof.result(&attributes);
        self.items = rebuild_own(&self.items, pseudonym_proof.result(), attributes);
        BatchTranscryptionProof {
            pseudonyms: pseudonym_proof,
            attributes: attribute_proof,
            items: PhantomData,
        }
    }

    /// Transcrypt every item with a proof. The batch's public key is converted along.
    #[cfg(all(not(feature = "elgamal3"), feature = "batch-pk"))]
    pub fn verifiable_transcrypt<R: Rng + CryptoRng>(
        &mut self,
        info: &TranscryptionInfo<E::Group>,
        rng: &mut R,
    ) -> BatchTranscryptionProof<E>
    where
        TranscryptionInfo<E::Group>: RekeyPublicKey<PublicKeyOf<E>>,
    {
        let proof = self.transcrypt_under(self.public_key.pseudonym_element(), info, rng);
        self.public_key = info.rekey_public_key(&self.public_key);
        proof
    }

    /// Transcrypt every item with a proof. `public_key` is the key the items are currently
    /// encrypted under.
    #[cfg(all(not(feature = "elgamal3"), not(feature = "batch-pk")))]
    pub fn verifiable_transcrypt<R: Rng + CryptoRng>(
        &mut self,
        info: &TranscryptionInfo<E::Group>,
        public_key: &PublicKeyOf<E>,
        rng: &mut R,
    ) -> BatchTranscryptionProof<E> {
        self.transcrypt_under(public_key.pseudonym_element(), info, rng)
    }

    /// Transcrypt every item with a proof.
    #[cfg(feature = "elgamal3")]
    pub fn verifiable_transcrypt<R: Rng + CryptoRng>(
        &mut self,
        info: &TranscryptionInfo<E::Group>,
        rng: &mut R,
    ) -> BatchTranscryptionProof<E> {
        let (pseudonyms, _) = flatten(&self.items);
        // Ciphertexts under different keys cannot be in one batch; a proof made with the
        // generator in that case does not verify.
        let gy = batch_gy(&pseudonyms).unwrap_or_else(E::Group::generator);
        self.transcrypt_under(gy, info, rng)
    }
}
