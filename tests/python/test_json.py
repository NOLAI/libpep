#!/usr/bin/env python3
"""
Python integration tests for JSON module.
Tests JSON encryption, decryption, and transcryption with structured data.
"""

import unittest
from libpep.core.keys import (
    make_global_keys,
    make_session_keys,
    SessionKeys,
    EncryptionSecret,
    PseudonymizationSecret,
)
from libpep.core.transcryption.contexts import (
    TranscryptionInfo,
    PseudonymizationInfo,
    PseudonymizationDomain,
    EncryptionContext,
)
from libpep.core.json.builder import PEPJSONBuilder
from libpep.core.json import encrypt_json, decrypt_json


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
        encrypted = encrypt_json(patient_record, session_keys)

        # Decrypt to verify original
        decrypted_original = decrypt_json(encrypted, session_keys)
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
        decrypted_transcrypted = decrypt_json(transcrypted, session_keys)
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
        from libpep.core.json import transcrypt_json_batch
        from libpep.core.transcryption.contexts import TranscryptionInfo

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
        encrypted1 = encrypt_json(record1, session_keys)
        encrypted2 = encrypt_json(record2, session_keys)

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
            decrypt_json(v, session_keys).to_json() for v in transcrypted_batch
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
        from libpep.core.json import transcrypt_json_batch
        from libpep.core.transcryption.contexts import TranscryptionInfo

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
        encrypted1 = encrypt_json(record1, session_keys)
        encrypted2 = encrypt_json(record2, session_keys)

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

        self.assertIn(
            "All values must have the same structure",
            str(context.exception),
            "Error should mention structure mismatch",
        )


if __name__ == "__main__":
    unittest.main()
