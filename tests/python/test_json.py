#!/usr/bin/env python3
"""
Python integration tests for JSON module.
Tests JSON encryption, decryption, and transcryption with structured data.
"""

import unittest
from libpep.keys import (
    make_global_keys,
    make_session_keys,
)
from libpep.factors import (
    EncryptionSecret,
    PseudonymizationSecret,
    TranscryptionInfo,
    PseudonymizationInfo,
    PseudonymizationDomain,
    EncryptionContext,
)
from libpep.client import (
    encrypt,
    encrypt_batch,
    decrypt,
)
from libpep.data import json as pepjson
from libpep.data.json import transcrypt_json_batch, PEPJSONBuilder


class TestJSONTranscryption(unittest.TestCase):
    def test_json_transcryption_with_builder(self):
        """Test JSON encryption/decryption/transcryption with existing JSON data"""
        # Setup keys and secrets
        global_keys = make_global_keys()
        pseudo_secret = PseudonymizationSecret(b"pseudo-secret")
        enc_secret = EncryptionSecret(b"encryption-secret")

        domain_a = PseudonymizationDomain("clinic-a")
        domain_b = PseudonymizationDomain("clinic-b")
        session = EncryptionContext("session-1")

        session_keys = make_session_keys(global_keys[1], session, enc_secret)

        # Create JSON with existing data
        patient_data = {
            "user_id": "user-67890",
            "name": "Alice",
            "age": 30,
            "active": True,
        }

        # Convert to PEP JSON, specifying which fields are pseudonyms
        patient_record = PEPJSONBuilder.from_json(patient_data, ["user_id"]).build()

        # Encrypt
        encrypted = encrypt(patient_record, session_keys)

        # Decrypt to verify original
        decrypted_original = decrypt(encrypted, session_keys)
        json_original = decrypted_original.to_json()
        self.assertEqual(json_original["user_id"], "user-67890")
        self.assertEqual(json_original["name"], "Alice")
        self.assertEqual(json_original["age"], 30)
        self.assertEqual(json_original["active"], True)

        # Transcrypt from clinic A to clinic B
        transcrypted = encrypted.transcrypt(
            domain_a, domain_b, session, session, pseudo_secret, enc_secret
        )

        # Verify that the encrypted structures are different after transcryption
        self.assertNotEqual(
            str(encrypted),
            str(transcrypted),
            "Encrypted values should be different after transcryption",
        )

        # Decrypt transcrypted data
        decrypted_transcrypted = decrypt(transcrypted, session_keys)
        json_transcrypted = decrypted_transcrypted.to_json()

        # Attributes should remain the same, but pseudonym should be different
        self.assertEqual(json_transcrypted["name"], "Alice")
        self.assertEqual(json_transcrypted["age"], 30)
        self.assertEqual(json_transcrypted["active"], True)
        self.assertNotEqual(
            json_transcrypted["user_id"],
            "user-67890",
            "Pseudonym should be different after cross-domain transcryption",
        )


class TestJSONBatchTranscryption(unittest.TestCase):
    def test_json_batch_transcryption_same_structure(self):
        """Test batch transcryption of JSON values with the same structure"""
        # Setup keys and secrets
        global_keys = make_global_keys()
        pseudo_secret = PseudonymizationSecret(b"pseudo-secret")
        enc_secret = EncryptionSecret(b"encryption-secret")

        domain_a = PseudonymizationDomain("domain-a")
        domain_b = PseudonymizationDomain("domain-b")
        session = EncryptionContext("session-1")

        session_keys = make_session_keys(global_keys[1], session, enc_secret)

        # Create two JSON values with the SAME structure using Python dicts
        data1 = {"patient_id": "patient-001", "diagnosis": "Flu", "temperature": 38.5}

        data2 = {"patient_id": "patient-002", "diagnosis": "Cold", "temperature": 37.2}

        # Convert to PEP JSON, specifying "patient_id" as pseudonym field
        record1 = PEPJSONBuilder.from_json(data1, ["patient_id"]).build()
        record2 = PEPJSONBuilder.from_json(data2, ["patient_id"]).build()

        # Encrypt both records
        encrypted1 = encrypt(record1, session_keys)
        encrypted2 = encrypt(record2, session_keys)

        # Verify they have the same structure
        structure1 = encrypted1.structure()
        structure2 = encrypted2.structure()
        self.assertEqual(structure1, structure2, "Records should have same structure")

        # Batch transcrypt (this should succeed because structures match)
        transcryption_info = TranscryptionInfo(
            domain_a,
            domain_b,
            session,
            session,
            pseudo_secret,
            enc_secret,
        )

        transcrypted_batch = transcrypt_json_batch(
            [encrypted1, encrypted2], transcryption_info
        )

        # Verify we got 2 records back
        self.assertEqual(len(transcrypted_batch), 2)

        # Verify that batch transcryption succeeded and values changed
        self.assertNotEqual(
            str([encrypted1, encrypted2]),
            str(transcrypted_batch),
            "Batch transcryption should transform the values",
        )

        # Decrypt all transcrypted values
        decrypted_batch = [
            decrypt(v, session_keys).to_json() for v in transcrypted_batch
        ]

        # Sort by temperature to have a consistent order (Cold=37.2, Flu=38.5)
        decrypted_batch.sort(key=lambda x: x["temperature"])

        # Verify the Cold patient data (lower temperature)
        self.assertEqual(decrypted_batch[0]["diagnosis"], "Cold")
        self.assertEqual(decrypted_batch[0]["temperature"], 37.2)
        self.assertNotEqual(
            decrypted_batch[0]["patient_id"],
            "patient-002",
            "Patient ID should be different after cross-domain transcryption",
        )

        # Verify the Flu patient data (higher temperature)
        self.assertEqual(decrypted_batch[1]["diagnosis"], "Flu")
        self.assertEqual(decrypted_batch[1]["temperature"], 38.5)
        self.assertNotEqual(
            decrypted_batch[1]["patient_id"],
            "patient-001",
            "Patient ID should be different after cross-domain transcryption",
        )

    def test_json_batch_transcryption_different_structures(self):
        """Test batch transcryption fails with different structures"""
        # Setup keys and secrets
        global_keys = make_global_keys()
        pseudo_secret = PseudonymizationSecret(b"pseudo-secret")
        enc_secret = EncryptionSecret(b"encryption-secret")

        domain_a = PseudonymizationDomain("domain-a")
        domain_b = PseudonymizationDomain("domain-b")
        session = EncryptionContext("session-1")

        session_keys = make_session_keys(global_keys[1], session, enc_secret)

        # Create two JSON values with DIFFERENT structures using Python dicts
        data1 = {"patient_id": "patient-001", "diagnosis": "Flu", "temperature": 38.5}

        data2 = {"user_id": "user-002", "name": "Bob", "age": 25, "active": True}

        # Convert to PEP JSON with different pseudonym fields
        record1 = PEPJSONBuilder.from_json(data1, ["patient_id"]).build()
        record2 = PEPJSONBuilder.from_json(data2, ["user_id"]).build()

        # Encrypt both records
        encrypted1 = encrypt(record1, session_keys)
        encrypted2 = encrypt(record2, session_keys)

        # Verify they have different structures
        structure1 = encrypted1.structure()
        structure2 = encrypted2.structure()
        self.assertNotEqual(
            structure1, structure2, "Records should have different structures"
        )

        # Attempt batch transcryption (this should raise an error because structures don't match)
        transcryption_info = TranscryptionInfo(
            domain_a,
            domain_b,
            session,
            session,
            pseudo_secret,
            enc_secret,
        )

        # Verify we get an error about structure mismatch
        with self.assertRaises(Exception) as context:
            transcrypt_json_batch([encrypted1, encrypted2], transcryption_info)

        # Error message may vary, just check that it mentions structure or inconsistency
        error_msg = str(context.exception).lower()
        self.assertTrue(
            "structure" in error_msg or "inconsistent" in error_msg,
            f"Error should mention structure mismatch, got: {context.exception}",
        )

    def test_json_batch_transcryption_same_structure_different_lengths(self):
            """
            Test JSON batch transcryption where structures differ in length.
            Individual encryptions will fail in a batch, but encrypt_json_batch
            should succeed by normalizing/padding the structures.
            """
            # Setup keys and secrets
            global_keys = make_global_keys()
            pseudo_secret = PseudonymizationSecret(b"pseudo-secret")
            enc_secret = EncryptionSecret(b"encryption-secret")

            domain_a = PseudonymizationDomain("domain-a")
            domain_b = PseudonymizationDomain("domain-b")
            session = EncryptionContext("session-1")

            # global_keys[1] is the Public Key
            session_keys = make_session_keys(global_keys[1], session, enc_secret)

            # Create two JSON values with same keys but different string lengths
            data1 = {
                "patient_id": "p1",
                "diagnosis": "Flu",
                "temperature": 38.5
            }

            data2 = {
                "patient_id": "patient-002-with-a-very-long-id-that-changes-length",
                "diagnosis": "Flu with a very long description to ensure structure length differs",
                "temperature": 38.5
            }

            # Convert to PEP JSON
            record1 = PEPJSONBuilder.from_json(data1, ["patient_id"]).build()
            record2 = PEPJSONBuilder.from_json(data2, ["patient_id"]).build()

            # 1. Encrypt separately
            encrypted1 = encrypt(record1, session_keys)
            encrypted2 = encrypt(record2, session_keys)

            # Verify they have different structures due to length
            self.assertNotEqual(encrypted1.structure(), encrypted2.structure())

            transcryption_info = TranscryptionInfo(
                domain_a, domain_b, session, session, pseudo_secret, enc_secret
            )

            # 2. Attempt batch transcryption (should fail because structures are not identical)
            with self.assertRaises(Exception) as cm:
                transcrypt_json_batch([encrypted1, encrypted2], transcryption_info)

            self.assertIn("structure", str(cm.exception).lower())

            # 3. Use encrypt_json_batch (this automatically pads both to the same structure)
            # Note: Depending on your specific pyo3 mapping, this might be in pepjson or client
            encrypted_batch = encrypt_batch([record1, record2], session_keys)

            # Verify that the padded structures are now identical
            self.assertEqual(
                encrypted_batch[0].structure(),
                encrypted_batch[1].structure(),
                "encrypt_json_batch should have unified the structures via padding"
            )

            # 4. Batch transcrypt the normalized records (should succeed)
            transcrypted_batch = transcrypt_json_batch(encrypted_batch, transcryption_info)

            # Verify output
            self.assertEqual(len(transcrypted_batch), 2)

            # Decrypt and check data integrity
            dec_json1 = decrypt(transcrypted_batch[0], session_keys).to_json()
            dec_json2 = decrypt(transcrypted_batch[1], session_keys).to_json()

            self.assertEqual(dec_json1["diagnosis"], "Flu")
            self.assertEqual(dec_json2["diagnosis"], "Flu with a very long description to ensure structure length differs")


if __name__ == "__main__":
    unittest.main()
