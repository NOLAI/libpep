//! Verifiable transcryptor operations.
//!
//! The methods of the [`Transcryptor`] that perform transcryption operations and generate
//! zero-knowledge proofs of them.

use crate::contexts::{EncryptionContext, PseudonymizationDomain};
use crate::data::traits::Encrypted;
use crate::elgamal::arithmetic::Ciphersuite;
use crate::factors::commitments::{
    VerifiablePseudonymizationCommitment, VerifiableRekeyCommitment,
    VerifiableTranscryptionCommitment,
};
use crate::factors::types::{PseudonymizationInfo, TranscryptionInfo};
use rand_core::{CryptoRng, Rng};

use super::types::Transcryptor;

impl<C: Ciphersuite> Transcryptor<C> {
    /// Build the public commitments for a pseudonymization transition:
    /// forward commitments `S = s·G` and `K = k·G` to the reshuffle and rekey
    /// factors. The commitments are bound to the same `(domain_from,
    /// domain_to, session_from, session_to)` tuple the prover passes to
    /// [`pseudonymization_info`](Self::pseudonymization_info), so the verifier
    /// and prover commit to the same secrets.
    pub fn pseudonymization_commitment(
        &self,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> VerifiablePseudonymizationCommitment<C::Group> {
        self.pseudonymization_info(domain_from, domain_to, session_from, session_to)
            .into()
    }

    /// Build the public commitment for a pseudonym rekey transition: `K = k·G`.
    pub fn pseudonym_rekey_commitment(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> VerifiableRekeyCommitment<C::Group> {
        self.pseudonym_rekey_info(session_from, session_to).into()
    }

    /// Build the public commitment for an attribute rekey transition: `K = k·G`.
    pub fn attribute_rekey_commitment(
        &self,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> VerifiableRekeyCommitment<C::Group> {
        self.attribute_rekey_info(session_from, session_to).into()
    }

    /// Build the combined public commitments for a transcryption transition:
    /// pseudonymization (`S`, `K_pseudo`) and attribute rekey (`K_attr`).
    pub fn transcryption_commitment(
        &self,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
        session_from: &EncryptionContext,
        session_to: &EncryptionContext,
    ) -> VerifiableTranscryptionCommitment<C::Group> {
        self.transcryption_info(domain_from, domain_to, session_from, session_to)
            .into()
    }

    /// Perform a verifiable pseudonymization operation.
    ///
    /// Uses RRSK with a freshly sampled rerandomize factor. The verifier
    /// recovers the result by calling
    /// [`Verifier::verified_reconstruct_pseudonymization`](crate::verifier::Verifier::verified_reconstruct_pseudonymization)
    /// (or its `_cached` variant) on the returned proof.
    #[cfg(feature = "elgamal3")]
    pub fn verifiable_pseudonymize<E, R>(
        &self,
        encrypted: &E,
        info: &PseudonymizationInfo<C::Group>,
        rng: &mut R,
    ) -> E::PseudonymizationProof
    where
        E: crate::data::verifiable::traits::VerifiablePseudonymizable<Group = C::Group>
            + Encrypted<Group = C::Group>,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_pseudonymize::<C, R>(info, rng)
    }

    #[cfg(not(feature = "elgamal3"))]
    /// Pseudonymize with a proof; `public_key` is the key the ciphertext is currently encrypted
    /// under.
    pub fn verifiable_pseudonymize<E, R>(
        &self,
        encrypted: &E,
        info: &PseudonymizationInfo<C::Group>,
        public_key: &<E::UnencryptedType as crate::data::traits::Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E::PseudonymizationProof
    where
        E: crate::data::verifiable::traits::VerifiablePseudonymizable<Group = C::Group>
            + Encrypted<Group = C::Group>,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_pseudonymize::<C, R>(info, public_key, rng)
    }

    /// Perform a verifiable rekey operation (VRK), without rerandomization (see
    /// [`VerifiableRekeyable`](crate::data::verifiable::traits::VerifiableRekeyable)).
    ///
    /// The verifier recovers the result by calling
    /// [`Verifier::verify_rekey`](crate::verifier::Verifier::verify_rekey)
    /// on the returned proof.
    pub fn verifiable_rekey<E, R>(
        &self,
        encrypted: &E,
        info: &E::RekeyInfo,
        rng: &mut R,
    ) -> E::RekeyProof
    where
        E: crate::data::verifiable::traits::VerifiableRekeyable<Group = C::Group>
            + Encrypted<Group = C::Group>,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_rekey::<C, R>(info, rng)
    }

    /// Perform a verifiable transcryption operation on composite values
    /// (records, JSON). Pseudonym fields get verifiable RRSK; attribute
    /// fields get verifiable rekey. The returned proof bundles both.
    #[cfg(feature = "elgamal3")]
    pub fn verifiable_transcrypt<E, R>(
        &self,
        encrypted: &E,
        info: &TranscryptionInfo<C::Group>,
        rng: &mut R,
    ) -> E::TranscryptionProof
    where
        E: crate::data::verifiable::traits::VerifiableTranscryptable<Group = C::Group>
            + Encrypted<Group = C::Group>,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_transcrypt::<C, R>(info, rng)
    }

    /// Perform a verifiable transcryption operation on composite values
    /// (records, JSON). `public_key` is the public key the
    /// pseudonym ciphertexts are currently encrypted under.
    #[cfg(not(feature = "elgamal3"))]
    pub fn verifiable_transcrypt<E, R>(
        &self,
        encrypted: &E,
        info: &TranscryptionInfo<C::Group>,
        public_key: &<E::UnencryptedType as crate::data::traits::Encryptable>::PublicKeyType,
        rng: &mut R,
    ) -> E::TranscryptionProof
    where
        E: crate::data::verifiable::traits::VerifiableTranscryptable<Group = C::Group>
            + Encrypted<Group = C::Group>,
        R: Rng + CryptoRng,
    {
        encrypted.verifiable_transcrypt::<C, R>(info, public_key, rng)
    }
}
