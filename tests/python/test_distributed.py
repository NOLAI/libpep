#!/usr/bin/env python3
"""
Python integration tests for distributed module.
Tests distributed n-PEP systems, PEP clients, and key blinding functionality.
"""

import unittest
from libpep.data import (
    Pseudonym,
    Attribute,
    EncryptedPseudonym,
    EncryptedAttribute,
)
from libpep.keys import (
    make_global_keys,
    make_session_keys,
    BlindingFactor,
    BlindedGlobalKeys,
    make_blinded_global_keys,
    make_pseudonym_global_keys,
    make_attribute_global_keys,
)
from libpep.factors import (
    PseudonymizationSecret,
    EncryptionSecret,
    TranscryptionInfo,
    PseudonymizationInfo,
    AttributeRekeyInfo,
    PseudonymizationDomain,
    EncryptionContext,
)
from libpep.client import (
    Client,
    OfflineClient,
    encrypt,
    decrypt,
)
from libpep.transcryptor import (
    DistributedTranscryptor,
)


class TestDistributed(unittest.TestCase):
    def setUp(self):
        """Setup common test data"""
        # Generate global keys using the new combined API
        self.global_public_keys, self.global_secret_keys = make_global_keys()

        # Create secrets
        self.secret = b"test_secret"
        self.pseudo_secret = PseudonymizationSecret(self.secret)
        self.enc_secret = EncryptionSecret(self.secret)

        # Create blinding factors (simulate 3 transcryptors)
        self.blinding_factors = [
            BlindingFactor.random(),
            BlindingFactor.random(),
            BlindingFactor.random(),
        ]

        # Create blinded global secret keys using the new combined API
        self.blinded_global_keys = make_blinded_global_keys(
            self.global_secret_keys, self.blinding_factors
        )

    def test_blinding_factor_operations(self):
        """Test blinding factor creation and operations"""
        # Test random generation
        bf1 = BlindingFactor.random()
        bf2 = BlindingFactor.random()
        self.assertNotEqual(bf1.to_hex(), bf2.to_hex())

        # Test encoding/decoding
        encoded = bf1.to_bytes()
        decoded = BlindingFactor.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(bf1.to_hex(), decoded.to_hex())

        # Test hex encoding/decoding
        hex_str = bf1.to_hex()
        decoded_hex = BlindingFactor.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.to_hex())

    def test_blinded_global_secret_key(self):
        """Test blinded global secret key operations"""
        # Just verify that blinded keys were created successfully
        self.assertIsNotNone(self.blinded_global_keys)
        self.assertIsNotNone(self.blinded_global_keys.pseudonym)
        self.assertIsNotNone(self.blinded_global_keys.attribute)

    def test_pseudonymization_rekey_info(self):
        """Test standalone pseudonymization and rekey info creation"""
        # Test TranscryptionInfo creation
        transcryption_info = TranscryptionInfo(
            PseudonymizationDomain("domain1"),
            PseudonymizationDomain("domain2"),
            EncryptionContext("session1"),
            EncryptionContext("session2"),
            self.pseudo_secret,
            self.enc_secret,
        )

        # Test reverse operation
        transcryption_rev = transcryption_info.rev()
        self.assertIsNotNone(transcryption_rev)


if __name__ == "__main__":
    unittest.main()
