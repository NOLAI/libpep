//! Python bindings for verifiable transcryptor operations.

use super::types::PyTranscryptor;
use crate::contexts::{PyEncryptionContext, PyPseudonymizationDomain};
#[cfg(feature = "long")]
use crate::data::long::{
    PyLongAttributeRekeyProof, PyLongEncryptedAttribute, PyLongEncryptedPseudonym,
    PyLongPseudonymPseudonymizationProof, PyLongPseudonymRekeyProof,
};
use crate::data::records::PyEncryptedRecord;
#[cfg(feature = "long")]
use crate::data::records::PyLongEncryptedRecord;
use crate::data::simple::{PyEncryptedAttribute, PyEncryptedPseudonym};
use crate::factors::types::{PyAttributeRekeyInfo, PyPseudonymizationInfo, PyTranscryptionInfo};
#[cfg(not(feature = "elgamal3"))]
use crate::keys::types::PyPseudonymSessionPublicKey;
use libpep::ciphersuite::Ristretto255Sha512;
use libpep::data::verifiable::traits::{VerifiablePseudonymizable, VerifiableRekeyable};
use libpep::factors::{AttributeRekeyInfo, PseudonymizationInfo, TranscryptionInfo};
#[cfg(not(feature = "elgamal3"))]
use libpep::keys::PublicKey;
use pyo3::prelude::*;

#[pymethods]
impl PyTranscryptor {
    /// The public commitments for a pseudonymization transition (`S`, `K`).
    #[cfg(feature = "verifiable")]
    fn pseudonymization_commitment(
        &self,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::factors::commitments::PyVerifiablePseudonymizationCommitment {
        crate::factors::commitments::PyVerifiablePseudonymizationCommitment {
            inner: self.0.pseudonymization_commitment(
                &domain_from.0,
                &domain_to.0,
                &session_from.0,
                &session_to.0,
            ),
        }
    }

    /// The public commitment for an attribute rekey transition (`K'`).
    #[cfg(feature = "verifiable")]
    fn attribute_rekey_commitment(
        &self,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::factors::commitments::PyVerifiableRekeyCommitment {
        crate::factors::commitments::PyVerifiableRekeyCommitment {
            inner: self
                .0
                .attribute_rekey_commitment(&session_from.0, &session_to.0),
        }
    }

    /// The public commitment for a pseudonym rekey transition (`K`).
    #[cfg(feature = "verifiable")]
    fn pseudonym_rekey_commitment(
        &self,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::factors::commitments::PyVerifiableRekeyCommitment {
        crate::factors::commitments::PyVerifiableRekeyCommitment {
            inner: self
                .0
                .pseudonym_rekey_commitment(&session_from.0, &session_to.0),
        }
    }

    /// The combined public commitments for a transcryption transition:
    /// pseudonymization (`S`, `K`) plus attribute rekey (`K'`).
    #[cfg(feature = "verifiable")]
    fn transcryption_commitment(
        &self,
        domain_from: &PyPseudonymizationDomain,
        domain_to: &PyPseudonymizationDomain,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::factors::commitments::PyVerifiableTranscryptionCommitment {
        crate::factors::commitments::PyVerifiableTranscryptionCommitment {
            inner: self.0.transcryption_commitment(
                &domain_from.0,
                &domain_to.0,
                &session_from.0,
                &session_to.0,
            ),
        }
    }

    /// Perform verifiable pseudonymization.
    ///
    /// Returns the operation proof. It is self-contained: the forward-direction
    /// construction needs no separate factors proof.
    #[cfg(all(feature = "verifiable", feature = "elgamal3"))]
    fn verifiable_pseudonymize(
        &self,
        encrypted: &PyEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
    ) -> crate::data::simple::PyPseudonymPseudonymizationProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(pseudo_info);
        let operation_proof = encrypted
            .0
            .verifiable_pseudonymize::<Ristretto255Sha512, _>(&info, &mut rng);

        operation_proof.into()
    }

    #[cfg(all(feature = "verifiable", not(feature = "elgamal3")))]
    fn verifiable_pseudonymize(
        &self,
        encrypted: &PyEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
        public_key: &PyPseudonymSessionPublicKey,
    ) -> crate::data::simple::PyPseudonymPseudonymizationProof {
        let mut rng = rand::rng();
        let info = PseudonymizationInfo::from(pseudo_info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        let operation_proof = encrypted
            .0
            .verifiable_pseudonymize::<Ristretto255Sha512, _>(&info, &pk, &mut rng);

        operation_proof.into()
    }

    /// Perform verifiable attribute rekey.
    ///
    /// Returns the operation proof.
    #[cfg(feature = "verifiable")]
    fn verifiable_attribute_rekey(
        &self,
        encrypted: &PyEncryptedAttribute,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> crate::data::simple::PyAttributeRekeyProof {
        let mut rng = rand::rng();
        let info = AttributeRekeyInfo::from(rekey_info);
        let operation_proof = encrypted
            .0
            .verifiable_rekey::<Ristretto255Sha512, _>(&info, &mut rng);

        operation_proof.into()
    }

    /// Perform verifiable pseudonym rekey.
    ///
    /// Returns the operation proof.
    #[cfg(feature = "verifiable")]
    fn verifiable_pseudonym_rekey(
        &self,
        encrypted: &PyEncryptedPseudonym,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> crate::data::simple::PyPseudonymRekeyProof {
        let mut rng = rand::rng();
        let info = self.pseudonym_rekey_info(&session_from.0, &session_to.0);
        let operation_proof = encrypted
            .0
            .verifiable_rekey::<Ristretto255Sha512, _>(&info, &mut rng);

        operation_proof.into()
    }

    /// Verifiable pseudonymization of a long pseudonym: one batch proof over its blocks.
    #[cfg(all(feature = "verifiable", feature = "long", feature = "elgamal3"))]
    fn verifiable_long_pseudonymize(
        &self,
        encrypted: &PyLongEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
    ) -> PyLongPseudonymPseudonymizationProof {
        let info = PseudonymizationInfo::from(pseudo_info);
        encrypted
            .0
            .verifiable_pseudonymize::<Ristretto255Sha512, _>(&info, &mut rand::rng())
            .into()
    }

    /// Verifiable pseudonymization of a long pseudonym: one batch proof over its blocks.
    /// `public_key` is the key the value is encrypted under.
    #[cfg(all(feature = "verifiable", feature = "long", not(feature = "elgamal3")))]
    fn verifiable_long_pseudonymize(
        &self,
        encrypted: &PyLongEncryptedPseudonym,
        pseudo_info: &PyPseudonymizationInfo,
        public_key: &PyPseudonymSessionPublicKey,
    ) -> PyLongPseudonymPseudonymizationProof {
        let info = PseudonymizationInfo::from(pseudo_info);
        let pk = libpep::keys::PseudonymSessionPublicKey::from_point(public_key.0 .0);
        encrypted
            .0
            .verifiable_pseudonymize::<Ristretto255Sha512, _>(&info, &pk, &mut rand::rng())
            .into()
    }

    /// Verifiable rekeying of a long attribute: one proof per block.
    #[cfg(all(feature = "verifiable", feature = "long"))]
    fn verifiable_long_attribute_rekey(
        &self,
        encrypted: &PyLongEncryptedAttribute,
        rekey_info: &PyAttributeRekeyInfo,
    ) -> PyLongAttributeRekeyProof {
        let info = AttributeRekeyInfo::from(rekey_info);
        encrypted
            .0
            .verifiable_rekey::<Ristretto255Sha512, _>(&info, &mut rand::rng())
            .into()
    }

    /// Verifiable rekeying of a long pseudonym: one proof per block.
    #[cfg(all(feature = "verifiable", feature = "long"))]
    fn verifiable_long_pseudonym_rekey(
        &self,
        encrypted: &PyLongEncryptedPseudonym,
        session_from: &PyEncryptionContext,
        session_to: &PyEncryptionContext,
    ) -> PyLongPseudonymRekeyProof {
        let info = self.pseudonym_rekey_info(&session_from.0, &session_to.0);
        encrypted
            .0
            .verifiable_rekey::<Ristretto255Sha512, _>(&info, &mut rand::rng())
            .into()
    }

    /// Perform verifiable transcryption of a simple record (pseudonyms +
    /// attributes). Returns a [`RecordTranscryptionProof`] containing per-item
    /// proofs that the verifier can check against the commitments published
    /// for this transition.
    #[cfg(all(feature = "verifiable", feature = "elgamal3"))]
    fn verifiable_record_transcrypt(
        &self,
        encrypted: &PyEncryptedRecord,
        transcryption_info: &PyTranscryptionInfo,
    ) -> crate::data::records::PyRecordTranscryptionProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(transcryption_info);
        let proof = self.0.verifiable_transcrypt(&encrypted.0, &info, &mut rng);
        crate::data::records::PyRecordTranscryptionProof { inner: proof }
    }

    /// Non-`elgamal3` variant: the session keys the pseudonym /
    /// attribute ciphertexts were encrypted under must be supplied so the
    /// inner rerandomize step's binding can be proven.
    #[cfg(all(feature = "verifiable", not(feature = "elgamal3")))]
    fn verifiable_record_transcrypt(
        &self,
        encrypted: &PyEncryptedRecord,
        transcryption_info: &PyTranscryptionInfo,
        session_keys: &crate::keys::PySessionKeys,
    ) -> crate::data::records::PyRecordTranscryptionProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(transcryption_info);
        let sk = libpep::keys::SessionKeys::from(session_keys.clone());
        let proof = self
            .0
            .verifiable_transcrypt(&encrypted.0, &info, &sk.public(), &mut rng);
        crate::data::records::PyRecordTranscryptionProof { inner: proof }
    }

    /// Verifiable transcryption of a long record.
    #[cfg(all(feature = "verifiable", feature = "long", feature = "elgamal3"))]
    fn verifiable_long_record_transcrypt(
        &self,
        encrypted: &PyLongEncryptedRecord,
        transcryption_info: &PyTranscryptionInfo,
    ) -> crate::data::records::PyLongRecordTranscryptionProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(transcryption_info);
        let proof = self.0.verifiable_transcrypt(&encrypted.0, &info, &mut rng);
        crate::data::records::PyLongRecordTranscryptionProof { inner: proof }
    }

    #[cfg(all(feature = "verifiable", feature = "long", not(feature = "elgamal3")))]
    fn verifiable_long_record_transcrypt(
        &self,
        encrypted: &PyLongEncryptedRecord,
        transcryption_info: &PyTranscryptionInfo,
        session_keys: &crate::keys::PySessionKeys,
    ) -> crate::data::records::PyLongRecordTranscryptionProof {
        let mut rng = rand::rng();
        let info = TranscryptionInfo::from(transcryption_info);
        let sk = libpep::keys::SessionKeys::from(session_keys.clone());
        let proof = self
            .0
            .verifiable_transcrypt(&encrypted.0, &info, &sk.public(), &mut rng);
        crate::data::records::PyLongRecordTranscryptionProof { inner: proof }
    }
}
