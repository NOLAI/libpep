#!/usr/bin/env python3
"""
Python integration tests for offline (global-key) encryption and decryption.

decrypt_global and decrypt_global_batch require the `insecure` feature; these
tests are skipped when the extension was built without it.
"""

import unittest

import libpep.client
from libpep.data import Pseudonym, Attribute
from libpep.data.json import PEPJSONBuilder
from libpep.keys import (
    make_global_keys,
    make_pseudonym_global_keys,
    make_attribute_global_keys,
)
from libpep.client import encrypt_global

INSECURE_BUILD = hasattr(libpep.client, "decrypt_global")


@unittest.skipUnless(
    INSECURE_BUILD, "extension built without the `insecure` feature"
)
class TestOfflineDecryption(unittest.TestCase):
    def test_encrypt_decrypt_global_pseudonym(self):
        """Round-trip a pseudonym through global-key encryption"""
        keys = make_pseudonym_global_keys()
        public, secret = keys.public, keys.secret

        pseudo = Pseudonym.random()
        encrypted = encrypt_global(pseudo, public)
        decrypted = libpep.client.decrypt_global(encrypted, secret)
        self.assertEqual(pseudo.to_hex(), decrypted.to_hex())

    def test_encrypt_decrypt_global_attribute(self):
        """Round-trip an attribute through global-key encryption"""
        keys = make_attribute_global_keys()
        public, secret = keys.public, keys.secret

        attribute = Attribute.random()
        encrypted = encrypt_global(attribute, public)
        decrypted = libpep.client.decrypt_global(encrypted, secret)
        self.assertEqual(attribute.to_hex(), decrypted.to_hex())

    def test_encrypt_decrypt_global_json(self):
        """Round-trip a JSON value through global-key encryption.

        Regression test: decrypt_global on EncryptedPEPJSONValue used to
        require the wrong key type (SessionKeys instead of GlobalSecretKeys).
        """
        global_public, global_secret = make_global_keys()

        record = PEPJSONBuilder.from_json(
            {"patient_id": "patient-12345", "diagnosis": "Flu"}, ["patient_id"]
        ).build()

        encrypted = libpep.client.encrypt_global(record, global_public)
        decrypted = libpep.client.decrypt_global(encrypted, global_secret)

        json = decrypted.to_json()
        self.assertEqual(json["patient_id"], "patient-12345")
        self.assertEqual(json["diagnosis"], "Flu")

    def test_encrypt_decrypt_global_batch_pseudonyms(self):
        """Round-trip a batch of pseudonyms through global-key encryption"""
        keys = make_pseudonym_global_keys()
        public, secret = keys.public, keys.secret

        pseudonyms = [Pseudonym.random() for _ in range(5)]
        encrypted = libpep.client.encrypt_global_batch(pseudonyms, public)
        decrypted = libpep.client.decrypt_global_batch(encrypted, secret)
        self.assertEqual(
            [p.to_hex() for p in pseudonyms], [p.to_hex() for p in decrypted]
        )

    def test_encrypt_decrypt_global_batch_json(self):
        """Round-trip a batch of JSON values through global-key encryption.

        Regression test: decrypt_global_batch on EncryptedPEPJSONValue used to
        require TranscryptionInfo instead of GlobalSecretKeys.
        """
        global_public, global_secret = make_global_keys()

        records = [
            PEPJSONBuilder.from_json(
                {"patient_id": f"patient-{i}", "diagnosis": "Flu"}, ["patient_id"]
            ).build()
            for i in range(3)
        ]

        encrypted = libpep.client.encrypt_global_batch(records, global_public)
        decrypted = libpep.client.decrypt_global_batch(encrypted, global_secret)

        self.assertEqual(len(records), len(decrypted))
        for original, roundtripped in zip(records, decrypted):
            self.assertEqual(original.to_json(), roundtripped.to_json())

    def test_decrypt_global_wrong_key_type_raises(self):
        """Passing a non-key where a global secret key is expected raises"""
        public = make_pseudonym_global_keys().public

        pseudo = Pseudonym.random()
        encrypted = encrypt_global(pseudo, public)
        with self.assertRaises(TypeError):
            libpep.client.decrypt_global(encrypted, "not a key")


if __name__ == "__main__":
    unittest.main()
