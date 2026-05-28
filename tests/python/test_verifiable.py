#!/usr/bin/env python3
"""
Python integration tests for verifiable transcryption.

Mirrors the Rust integration tests in `tests/verifiable.rs` 1:1 so the Python
and Rust APIs read the same; each test below corresponds to a same-named
Rust test. The transcryptor produces commitments + per-operation ZK proofs;
a separate `Verifier` checks each proof against the published commitments
and recovers the transformed ciphertext, which the recipient then decrypts.
"""

import json
import unittest

from libpep.data import (
    Attribute,
    Pseudonym,
    Record,
    EncryptedRecord,
    encrypt_record,
)
from libpep.keys import (
    make_pseudonym_global_keys,
    make_attribute_global_keys,
    make_pseudonym_session_keys,
    make_attribute_session_keys,
    make_distributed_global_keys,
    PseudonymSessionKeys,
    AttributeSessionKeys,
    SessionKeys,
)
from libpep.factors import (
    PseudonymizationSecret,
    EncryptionSecret,
    PseudonymizationDomain,
    EncryptionContext,
)
from libpep.client import Client, encrypt, decrypt
from libpep.transcryptor import DistributedTranscryptor, Transcryptor
from libpep.verifier import Verifier

try:
    from libpep.data import (
        EncryptedPseudonymBatch,
        PseudonymPseudonymizationBatchProof,
    )
    _BATCH_AVAILABLE = True
except ImportError:  # build without `batch`/`verifiable`
    _BATCH_AVAILABLE = False


def _detect_batch_pk():
    """Return True if the build enabled `batch-pk` (the no-pk batch constructor
    will be rejected) — needed to choose the right per-call signatures."""
    if not _BATCH_AVAILABLE:
        return False
    try:
        EncryptedPseudonymBatch([])  # type: ignore[call-arg]
        return False
    except TypeError:
        return True
    except Exception:
        return True


_BATCH_PK = _detect_batch_pk()


SECRET = b"secret"


def _verifiable_pseudonymize(transcryptor, enc_pseudo, info, session_pub):
    """Cross-feature wrapper: elgamal3 takes (enc, info); non-elgamal3 also needs the pseudonym session pk."""
    try:
        return transcryptor.verifiable_pseudonymize(enc_pseudo, info)
    except TypeError:
        return transcryptor.verifiable_pseudonymize(enc_pseudo, info, session_pub)


def _verify_pseudonymization(verifier, enc_pseudo, proof, session_pub, commitments):
    try:
        return verifier.verify_pseudonymization(enc_pseudo, proof, commitments)
    except TypeError:
        return verifier.verify_pseudonymization(enc_pseudo, proof, session_pub, commitments)


def _verify_pseudonymization_cached(
    verifier, t_id, enc_pseudo, proof, session_pub, d_from, d_to, s_from, s_to,
):
    try:
        return verifier.verify_pseudonymization_cached(
            t_id, enc_pseudo, proof, d_from, d_to, s_from, s_to,
        )
    except TypeError:
        return verifier.verify_pseudonymization_cached(
            t_id, enc_pseudo, proof, session_pub, d_from, d_to, s_from, s_to,
        )


class TestVerifiable(unittest.TestCase):
    """Mirrors tests/verifiable.rs."""

    def test_verifiable_pseudonymization_simple(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        domain1 = PseudonymizationDomain("domain1")
        domain2 = PseudonymizationDomain("domain2")
        session1 = EncryptionContext("session1")
        session2 = EncryptionContext("session2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, session1, enc_secret,
        )
        pseudonym_session2_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, session2, enc_secret,
        )

        pseudo = Pseudonym.random()
        enc_pseudo = encrypt(pseudo, pseudonym_session1_keys.public)

        transcryptor = Transcryptor("secret", "secret")
        info = transcryptor.pseudonymization_info(domain1, domain2, session1, session2)
        commitments = transcryptor.pseudonymization_commitment(
            domain1, domain2, session1, session2,
        )

        operation_proof = _verifiable_pseudonymize(
            transcryptor, enc_pseudo, info, pseudonym_session1_keys.public,
        )

        verifier = Verifier()
        result = _verify_pseudonymization(
            verifier, enc_pseudo, operation_proof, pseudonym_session1_keys.public, commitments,
        )

        # Decrypting under the target session must succeed.
        decrypted = decrypt(result, pseudonym_session2_keys.secret)
        self.assertIsNotNone(decrypted)

    def test_verifiable_pseudonym_rekey(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        session1 = EncryptionContext("session1")
        session2 = EncryptionContext("session2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, session1, enc_secret,
        )
        pseudonym_session2_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, session2, enc_secret,
        )

        pseudo = Pseudonym.random()
        enc_pseudo = encrypt(pseudo, pseudonym_session1_keys.public)

        transcryptor = Transcryptor("secret", "secret")
        commitments = transcryptor.pseudonym_rekey_commitment(session1, session2)
        operation_proof = transcryptor.verifiable_pseudonym_rekey(enc_pseudo, session1, session2)

        verifier = Verifier()
        result = verifier.verify_pseudonym_rekey(enc_pseudo, operation_proof, commitments)

        # Pseudonym rekey preserves the underlying value across sessions.
        decrypted = decrypt(result, pseudonym_session2_keys.secret)
        original_decrypted = decrypt(enc_pseudo, pseudonym_session1_keys.secret)
        self.assertEqual(decrypted.to_hex(), original_decrypted.to_hex())

    def test_verifiable_attribute_rekey(self):
        attribute_global_keys = make_attribute_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        session1 = EncryptionContext("session1")
        session2 = EncryptionContext("session2")

        attribute_session1_keys = make_attribute_session_keys(
            attribute_global_keys.secret, session1, enc_secret,
        )
        attribute_session2_keys = make_attribute_session_keys(
            attribute_global_keys.secret, session2, enc_secret,
        )

        attr = Attribute.random()
        enc_attr = encrypt(attr, attribute_session1_keys.public)

        transcryptor = Transcryptor("secret", "secret")
        rekey_info = transcryptor.attribute_rekey_info(session1, session2)
        commitments = transcryptor.attribute_rekey_commitment(session1, session2)

        operation_proof = transcryptor.verifiable_attribute_rekey(enc_attr, rekey_info)

        verifier = Verifier()
        result = verifier.verify_attribute_rekey(enc_attr, operation_proof, commitments)

        decrypted = decrypt(result, attribute_session2_keys.secret)
        original_decrypted = decrypt(enc_attr, attribute_session1_keys.secret)
        self.assertEqual(decrypted.to_hex(), original_decrypted.to_hex())

    def test_verifiable_record_transcryption(self):
        # End-to-end: prove + verify a transcryption on a composite (record)
        # value. Exercises `Transcryptor.verifiable_record_transcrypt` (prover)
        # and `Verifier.verify_record_transcryption` (verifier).
        global_pseudonym_keys = make_pseudonym_global_keys()
        global_attribute_keys = make_attribute_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        domain_a = PseudonymizationDomain("a")
        domain_b = PseudonymizationDomain("b")
        session_a = EncryptionContext("sa")
        session_b = EncryptionContext("sb")

        pseudonym_session_a = make_pseudonym_session_keys(
            global_pseudonym_keys.secret, session_a, enc_secret,
        )
        attribute_session_a = make_attribute_session_keys(
            global_attribute_keys.secret, session_a, enc_secret,
        )
        session_a_keys = SessionKeys(
            PseudonymSessionKeys(
                pseudonym_session_a.public, pseudonym_session_a.secret,
            ),
            AttributeSessionKeys(
                attribute_session_a.public, attribute_session_a.secret,
            ),
        )

        # Build a record and encrypt it.
        record = Record(
            [Pseudonym.random(), Pseudonym.random()],
            [Attribute.random(), Attribute.random(), Attribute.random()],
        )
        enc_record = encrypt_record(record, session_a_keys)

        transcryptor = Transcryptor("secret", "secret")
        info = transcryptor.transcryption_info(domain_a, domain_b, session_a, session_b)
        commitments = transcryptor.transcryption_commitment(
            domain_a, domain_b, session_a, session_b,
        )

        # The verifiable_record_transcrypt elgamal2 variant needs the session
        # keys the record was encrypted under so the inner rerandomize steps
        # can be proven; elgamal3 doesn't.
        try:
            proof = transcryptor.verifiable_record_transcrypt(enc_record, info)
        except TypeError:
            proof = transcryptor.verifiable_record_transcrypt(enc_record, info, session_a_keys)

        verifier = Verifier()
        try:
            reconstructed = verifier.verify_record_transcryption(
                enc_record, proof, commitments,
            )
        except TypeError:
            reconstructed = verifier.verify_record_transcryption(
                enc_record, proof, session_a_keys, commitments,
            )

        self.assertEqual(len(reconstructed.pseudonyms), len(record.pseudonyms))
        self.assertEqual(len(reconstructed.attributes), len(record.attributes))

    def test_verifier_cache_pseudonymization(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        domain1 = PseudonymizationDomain("domain1")
        domain2 = PseudonymizationDomain("domain2")
        domain3 = PseudonymizationDomain("domain3")
        session1 = EncryptionContext("session1")
        session2 = EncryptionContext("session2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, session1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        info = transcryptor.pseudonymization_info(domain1, domain2, session1, session2)
        commitments = transcryptor.pseudonymization_commitment(
            domain1, domain2, session1, session2,
        )

        verifier = Verifier()
        transcryptor_id = "transcryptor1"
        verifier.register_pseudonymization_commitments(
            transcryptor_id, domain1, domain2, session1, session2, commitments,
        )

        pseudo = Pseudonym.random()
        enc_pseudo = encrypt(pseudo, pseudonym_session1_keys.public)
        operation_proof = _verifiable_pseudonymize(
            transcryptor, enc_pseudo, info, pseudonym_session1_keys.public,
        )

        # Cached lookup against the registered transition succeeds.
        result = _verify_pseudonymization_cached(
            verifier, transcryptor_id, enc_pseudo, operation_proof,
            pseudonym_session1_keys.public, domain1, domain2, session1, session2,
        )
        self.assertIsNotNone(result)

        # Wrong transition (different target domain) is not in the cache.
        with self.assertRaises(Exception):
            _verify_pseudonymization_cached(
                verifier, transcryptor_id, enc_pseudo, operation_proof,
                pseudonym_session1_keys.public, domain1, domain3, session1, session2,
            )

        verifier.clear_cache()
        self.assertEqual(verifier.cache_size(), 0)

    @unittest.skipUnless(_BATCH_AVAILABLE, "requires `batch` + `verifiable` features")
    def test_n_pep_batch_distributed_verifiable(self):
        """Distributed verifiable batch transcryption: client A -> 3 transcryptors -> client B.

        Mirrors the Rust `n_pep_batch_distributed_verifiable` test: each
        transcryptor produces a hoisted batch proof and *the next transcryptor
        verifies the previous one's proof* before applying its own
        transcryption. The final client verifies the last proof, then decrypts.
        """
        n = 3
        _global_public_keys, blinded_global_keys, blinding_factors = (
            make_distributed_global_keys(n)
        )

        systems = [
            DistributedTranscryptor(f"ps-{i}", f"es-{i}", blinding_factors[i])
            for i in range(n)
        ]

        domain_a = PseudonymizationDomain("a")
        domain_b = PseudonymizationDomain("b")
        session_a = EncryptionContext("sa")
        session_b = EncryptionContext("sb")

        sks_a = [s.session_key_shares(session_a) for s in systems]
        sks_b = [s.session_key_shares(session_b) for s in systems]

        client_a = Client(blinded_global_keys, sks_a)
        client_b = Client(blinded_global_keys, sks_b)

        # Client A encrypts a batch of pseudonyms.
        pseudonyms = [Pseudonym.random() for _ in range(5)]
        encrypted_items = client_a.encrypt_batch(pseudonyms)
        client_a_pk = client_a.session_public_keys().pseudonym

        if _BATCH_PK:
            current = EncryptedPseudonymBatch(encrypted_items, client_a_pk)
        else:
            current = EncryptedPseudonymBatch(encrypted_items)

        def _current_pk():
            return current.public_key() if _BATCH_PK else client_a_pk

        # Chain: each step records (pre-batch, pre-pk, proof, commitments) so
        # the *next* step can verify it before doing its own transcryption.
        prev = None

        for system in systems:
            # Step 1: verify the previous step (if any). The verification
            # reconstructs the post-batch from the previous step's pre-batch
            # and proof; that reconstruction must match what this transcryptor
            # actually received.
            if prev is not None:
                pre_batch, pre_pk, proof, commitments = prev
                if _BATCH_PK:
                    reconstructed = proof.verified_reconstruct_batch(
                        pre_batch, pre_pk, _current_pk(), commitments,
                    )
                else:
                    reconstructed = proof.verified_reconstruct_batch(
                        pre_batch, pre_pk, commitments,
                    )
                self.assertEqual(reconstructed.items(), current.items())

            # Step 2: this transcryptor builds and applies its own verifiable
            # batch transcryption. We save a clone of the pre-batch + its pk
            # so the next iteration can verify against them.
            pre_pk = _current_pk()
            if _BATCH_PK:
                pre_batch_clone = EncryptedPseudonymBatch(current.items(), pre_pk)
            else:
                pre_batch_clone = EncryptedPseudonymBatch(current.items())

            info = system.pseudonymization_info(
                domain_a, domain_b, session_a, session_b,
            )
            commitments = system.pseudonymization_commitment(
                domain_a, domain_b, session_a, session_b,
            )
            if _BATCH_PK:
                proof = current.verifiable_pseudonymize(info)
            else:
                proof = current.verifiable_pseudonymize(info, pre_pk)
            prev = (pre_batch_clone, pre_pk, proof, commitments)

        # Final: client B verifies the last transcryptor's proof, then decrypts.
        self.assertIsNotNone(prev)
        pre_batch, pre_pk, proof, commitments = prev
        if _BATCH_PK:
            verified_batch = proof.verified_reconstruct_batch(
                pre_batch, pre_pk, _current_pk(), commitments,
            )
        else:
            verified_batch = proof.verified_reconstruct_batch(
                pre_batch, pre_pk, commitments,
            )
        self.assertEqual(verified_batch.items(), current.items())

        decrypted = client_b.decrypt_batch(verified_batch.items())
        self.assertEqual(len(decrypted), len(pseudonyms))
        # Domains differ, so pseudonyms are remapped and should NOT equal the originals.
        self.assertNotEqual(
            [p.to_hex() for p in decrypted],
            [p.to_hex() for p in pseudonyms],
        )


class TestVerifiableNegative(unittest.TestCase):
    """Negative tests: tampered proofs / wrong inputs must be rejected."""

    def test_tampered_proof_rejected_pseudonymization(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        d1 = PseudonymizationDomain("d1")
        d2 = PseudonymizationDomain("d2")
        s1 = EncryptionContext("s1")
        s2 = EncryptionContext("s2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, s1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        info = transcryptor.pseudonymization_info(d1, d2, s1, s2)
        commitments = transcryptor.pseudonymization_commitment(d1, d2, s1, s2)

        enc_pseudo = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)
        proof = _verifiable_pseudonymize(
            transcryptor, enc_pseudo, info, pseudonym_session1_keys.public,
        )

        # Build a second valid proof to donate one of its components. Every
        # Ristretto/scalar in the proof JSON is a fixed-length hex string;
        # flipping a character blindly would yield an undecodable point, so we
        # cross-graft from another *valid* proof — every individual element
        # still decodes, but the per-statement binding no longer matches.
        donor_enc = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)
        donor_proof = _verifiable_pseudonymize(
            transcryptor, donor_enc, info, pseudonym_session1_keys.public,
        )
        tampered = _swap_first_string_proof(proof, donor_proof)
        self.assertNotEqual(_proof_to_json(tampered), _proof_to_json(proof))

        verifier = Verifier()
        with self.assertRaises(Exception):
            _verify_pseudonymization(
                verifier, enc_pseudo, tampered, pseudonym_session1_keys.public, commitments,
            )

    def test_wrong_original_rejected_pseudonymization(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        d1 = PseudonymizationDomain("d1")
        d2 = PseudonymizationDomain("d2")
        s1 = EncryptionContext("s1")
        s2 = EncryptionContext("s2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, s1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        info = transcryptor.pseudonymization_info(d1, d2, s1, s2)
        commitments = transcryptor.pseudonymization_commitment(d1, d2, s1, s2)

        enc_pseudo = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)
        proof = _verifiable_pseudonymize(
            transcryptor, enc_pseudo, info, pseudonym_session1_keys.public,
        )

        # Verify the proof against a *different* ciphertext.
        other_enc = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)

        verifier = Verifier()
        with self.assertRaises(Exception):
            _verify_pseudonymization(
                verifier, other_enc, proof, pseudonym_session1_keys.public, commitments,
            )

    def test_wrong_commitments_rejected_pseudonymization(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        d1 = PseudonymizationDomain("d1")
        d2 = PseudonymizationDomain("d2")
        d3 = PseudonymizationDomain("d3")
        s1 = EncryptionContext("s1")
        s2 = EncryptionContext("s2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, s1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        info = transcryptor.pseudonymization_info(d1, d2, s1, s2)
        # Commitments for a *different* target domain than the proof.
        wrong_commitments = transcryptor.pseudonymization_commitment(d1, d3, s1, s2)

        enc_pseudo = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)
        proof = _verifiable_pseudonymize(
            transcryptor, enc_pseudo, info, pseudonym_session1_keys.public,
        )

        verifier = Verifier()
        with self.assertRaises(Exception):
            _verify_pseudonymization(
                verifier, enc_pseudo, proof, pseudonym_session1_keys.public, wrong_commitments,
            )

    def test_tampered_proof_rejected_pseudonym_rekey(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        s1 = EncryptionContext("s1")
        s2 = EncryptionContext("s2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, s1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        commitments = transcryptor.pseudonym_rekey_commitment(s1, s2)

        enc_pseudo = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)
        proof = transcryptor.verifiable_pseudonym_rekey(enc_pseudo, s1, s2)

        donor_enc = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)
        donor_proof = transcryptor.verifiable_pseudonym_rekey(donor_enc, s1, s2)
        tampered = _swap_first_string_proof(proof, donor_proof)
        self.assertNotEqual(_proof_to_json(tampered), _proof_to_json(proof))

        verifier = Verifier()
        with self.assertRaises(Exception):
            verifier.verify_pseudonym_rekey(enc_pseudo, tampered, commitments)

    def test_wrong_original_rejected_pseudonym_rekey(self):
        pseudonym_global_keys = make_pseudonym_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        s1 = EncryptionContext("s1")
        s2 = EncryptionContext("s2")

        pseudonym_session1_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, s1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        commitments = transcryptor.pseudonym_rekey_commitment(s1, s2)

        enc_pseudo = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)
        proof = transcryptor.verifiable_pseudonym_rekey(enc_pseudo, s1, s2)

        other_enc = encrypt(Pseudonym.random(), pseudonym_session1_keys.public)

        verifier = Verifier()
        with self.assertRaises(Exception):
            verifier.verify_pseudonym_rekey(other_enc, proof, commitments)

    def test_tampered_proof_rejected_attribute_rekey(self):
        attribute_global_keys = make_attribute_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        s1 = EncryptionContext("s1")
        s2 = EncryptionContext("s2")

        attribute_session1_keys = make_attribute_session_keys(
            attribute_global_keys.secret, s1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        rekey_info = transcryptor.attribute_rekey_info(s1, s2)
        commitments = transcryptor.attribute_rekey_commitment(s1, s2)

        enc_attr = encrypt(Attribute.random(), attribute_session1_keys.public)
        proof = transcryptor.verifiable_attribute_rekey(enc_attr, rekey_info)

        donor_enc = encrypt(Attribute.random(), attribute_session1_keys.public)
        donor_proof = transcryptor.verifiable_attribute_rekey(donor_enc, rekey_info)
        tampered = _swap_first_string_proof(proof, donor_proof)
        self.assertNotEqual(_proof_to_json(tampered), _proof_to_json(proof))

        verifier = Verifier()
        with self.assertRaises(Exception):
            verifier.verify_attribute_rekey(enc_attr, tampered, commitments)

    def test_tampered_proof_rejected_record_transcryption(self):
        global_pseudonym_keys = make_pseudonym_global_keys()
        global_attribute_keys = make_attribute_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        d1 = PseudonymizationDomain("a")
        d2 = PseudonymizationDomain("b")
        s1 = EncryptionContext("sa")
        s2 = EncryptionContext("sb")

        pseudonym_session_a = make_pseudonym_session_keys(
            global_pseudonym_keys.secret, s1, enc_secret,
        )
        attribute_session_a = make_attribute_session_keys(
            global_attribute_keys.secret, s1, enc_secret,
        )
        session_a_keys = SessionKeys(
            PseudonymSessionKeys(
                pseudonym_session_a.public, pseudonym_session_a.secret,
            ),
            AttributeSessionKeys(
                attribute_session_a.public, attribute_session_a.secret,
            ),
        )

        record = Record(
            [Pseudonym.random()],
            [Attribute.random(), Attribute.random()],
        )
        enc_record = encrypt_record(record, session_a_keys)

        transcryptor = Transcryptor("secret", "secret")
        info = transcryptor.transcryption_info(d1, d2, s1, s2)
        commitments = transcryptor.transcryption_commitment(d1, d2, s1, s2)

        try:
            proof = transcryptor.verifiable_record_transcrypt(enc_record, info)
        except TypeError:
            proof = transcryptor.verifiable_record_transcrypt(enc_record, info, session_a_keys)

        # Donor: independently re-encrypt the same record and prove again.
        donor_enc = encrypt_record(record, session_a_keys)
        try:
            donor_proof = transcryptor.verifiable_record_transcrypt(donor_enc, info)
        except TypeError:
            donor_proof = transcryptor.verifiable_record_transcrypt(donor_enc, info, session_a_keys)

        tampered = _swap_first_string_proof(proof, donor_proof)
        self.assertNotEqual(_proof_to_json(tampered), _proof_to_json(proof))

        verifier = Verifier()
        with self.assertRaises(Exception):
            try:
                verifier.verify_record_transcryption(enc_record, tampered, commitments)
            except TypeError:
                verifier.verify_record_transcryption(
                    enc_record, tampered, session_a_keys, commitments,
                )

    def test_wrong_original_rejected_attribute_rekey(self):
        attribute_global_keys = make_attribute_global_keys()
        pseudo_secret = PseudonymizationSecret(SECRET)
        enc_secret = EncryptionSecret(SECRET)

        s1 = EncryptionContext("s1")
        s2 = EncryptionContext("s2")

        attribute_session1_keys = make_attribute_session_keys(
            attribute_global_keys.secret, s1, enc_secret,
        )

        transcryptor = Transcryptor("secret", "secret")
        rekey_info = transcryptor.attribute_rekey_info(s1, s2)
        commitments = transcryptor.attribute_rekey_commitment(s1, s2)

        enc_attr = encrypt(Attribute.random(), attribute_session1_keys.public)
        proof = transcryptor.verifiable_attribute_rekey(enc_attr, rekey_info)

        other_enc = encrypt(Attribute.random(), attribute_session1_keys.public)

        verifier = Verifier()
        with self.assertRaises(Exception):
            verifier.verify_attribute_rekey(other_enc, proof, commitments)


# ---------------------------------------------------------------------------
# Helpers for the negative ("tampered proof") tests.
# ---------------------------------------------------------------------------

def _proof_to_json(proof):
    """Best-effort JSON view of an opaque proof object for diff/comparison."""
    if hasattr(proof, "to_json"):
        return proof.to_json()
    return json.dumps(proof, sort_keys=True)


def _proof_from_json(proof_class, json_str):
    return proof_class.from_json(json_str)


def _swap_first_string_proof(proof, donor):
    """Swap the first differing leaf string value between two proofs.

    Returns a new proof object (same class as `proof`) that is well-formed JSON
    — every Ristretto point still decodes — but no longer matches the
    statement `proof` was generated for. We do this by parsing both proofs
    as JSON, finding the first leaf string in `proof` that differs from the
    corresponding leaf in `donor`, swapping it in, and round-tripping back
    through the proof class's `from_json`.
    """
    target = json.loads(_proof_to_json(proof))
    donor_v = json.loads(_proof_to_json(donor))
    if not _swap_first_string_value(target, donor_v):
        raise RuntimeError("no swappable string leaf found")
    return type(proof).from_json(json.dumps(target))


def _swap_first_string_value(target, donor):
    if isinstance(target, list) and isinstance(donor, list):
        for i in range(min(len(target), len(donor))):
            t, d = target[i], donor[i]
            if isinstance(t, str) and isinstance(d, str):
                if t != d:
                    target[i] = d
                    return True
            elif _swap_first_string_value(t, d):
                return True
        return False
    if isinstance(target, dict) and isinstance(donor, dict):
        for k in target:
            if k not in donor:
                continue
            t, d = target[k], donor[k]
            if isinstance(t, str) and isinstance(d, str):
                if t != d:
                    target[k] = d
                    return True
            elif _swap_first_string_value(t, d):
                return True
        return False
    return False


if __name__ == "__main__":
    unittest.main()
