#!/usr/bin/env python3
"""
Python integration tests for core module.
Tests high-level API for pseudonyms, data points, and session management.
"""

import unittest
from libpep.data import (
    Pseudonym,
    Attribute,
    EncryptedPseudonym,
    EncryptedAttribute,
)
from libpep.keys import (
    PseudonymGlobalPublicKey,
    AttributeGlobalPublicKey,
    make_pseudonym_global_keys,
    make_attribute_global_keys,
    make_pseudonym_session_keys,
    make_attribute_session_keys,
)
from libpep.factors import (
    PseudonymizationSecret,
    EncryptionSecret,
    PseudonymizationInfo,
    AttributeRekeyInfo,
    TranscryptionInfo,
    PseudonymizationDomain,
    EncryptionContext,
)
from libpep.client import (
    encrypt,
    decrypt,
)


class TestHighLevel(unittest.TestCase):
    def test_core_operations(self):
        """Test high-level pseudonym and data operations"""
        # Generate global keys
        pseudonym_global_keys = make_pseudonym_global_keys()
        attribute_global_keys = make_attribute_global_keys()
        enc_secret = EncryptionSecret(b"test_secret")

        # Create session keys
        session = EncryptionContext("test_session")
        pseudonym_session_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, session, enc_secret
        )
        attribute_session_keys = make_attribute_session_keys(
            attribute_global_keys.secret, session, enc_secret
        )

        # Create and encrypt pseudonym
        pseudo = Pseudonym.random()
        enc_pseudo = encrypt(pseudo, pseudonym_session_keys.public)

        # Create and encrypt data point
        data = Attribute.random()
        enc_data = encrypt(data, attribute_session_keys.public)

        # Verify encryption and decryption
        dec_pseudo = decrypt(enc_pseudo, pseudonym_session_keys.secret)
        dec_data = decrypt(enc_data, attribute_session_keys.secret)

        self.assertEqual(pseudo.to_hex(), dec_pseudo.to_hex())
        self.assertEqual(data.to_hex(), dec_data.to_hex())

    def test_pseudonym_operations(self):
        """Test pseudonym creation and manipulation"""
        # Test random pseudonym
        pseudo1 = Pseudonym.random()
        pseudo2 = Pseudonym.random()
        self.assertNotEqual(pseudo1.to_hex(), pseudo2.to_hex())

        # Test encoding/decoding
        encoded = pseudo1.to_bytes()
        decoded = Pseudonym.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(pseudo1.to_hex(), decoded.to_hex())

        # Test hex encoding/decoding
        hex_str = pseudo1.to_hex()
        decoded_hex = Pseudonym.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(pseudo1.to_hex(), decoded_hex.to_hex())

    def test_attribute_operations(self):
        """Test data point creation and manipulation"""
        # Test random data point
        data1 = Attribute.random()
        data2 = Attribute.random()
        self.assertNotEqual(data1.to_hex(), data2.to_hex())

        # Test encoding/decoding
        encoded = data1.to_bytes()
        decoded = Attribute.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(data1.to_hex(), decoded.to_hex())

    def test_string_padding_operations(self):
        """Test string padding for pseudonyms and data points"""
        test_string = "Hello!"  # Max 15 bytes for single block

        # Test pseudonym string padding
        pseudo = Pseudonym.from_string_padded(test_string)
        reconstructed = pseudo.to_string_padded()
        self.assertEqual(test_string, reconstructed)

        # Test data point string padding
        attr = Attribute.from_string_padded(test_string)
        reconstructed_data = attr.to_string_padded()
        self.assertEqual(test_string, reconstructed_data)

    def test_bytes_padding_operations(self):
        """Test bytes padding for pseudonyms and data points"""
        test_bytes = b"Hello!"  # Max 15 bytes for single block

        # Test pseudonym bytes padding
        pseudo = Pseudonym.from_bytes_padded(test_bytes)
        reconstructed = pseudo.to_bytes_padded()
        self.assertEqual(test_bytes, reconstructed)

        # Test data point bytes padding
        attr = Attribute.from_bytes_padded(test_bytes)
        reconstructed_data = attr.to_bytes_padded()
        self.assertEqual(test_bytes, reconstructed_data)

    def test_fixed_size_bytes_operations(self):
        """Test 16-byte fixed size operations using lizard encoding"""
        # Create 16-byte test data
        test_bytes = b"1234567890abcdef"  # Exactly 16 bytes

        # Test pseudonym from/to lizard
        pseudo = Pseudonym.from_lizard(test_bytes)
        reconstructed = pseudo.to_lizard()
        self.assertIsNotNone(reconstructed)
        self.assertEqual(test_bytes, reconstructed)

        # Test data point from/to lizard
        data = Attribute.from_lizard(test_bytes)
        reconstructed_data = data.to_lizard()
        self.assertIsNotNone(reconstructed_data)
        self.assertEqual(test_bytes, reconstructed_data)

    def test_encrypted_types_encoding(self):
        """Test encoding/decoding of encrypted types"""
        # Setup
        pseudonym_global_keys = make_pseudonym_global_keys()
        attribute_global_keys = make_attribute_global_keys()
        enc_secret = EncryptionSecret(b"test_secret")
        session = EncryptionContext("test_session")

        pseudonym_session_keys = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, session, enc_secret
        )
        attribute_session_keys = make_attribute_session_keys(
            attribute_global_keys.secret, session, enc_secret
        )

        # Create encrypted pseudonym
        pseudo = Pseudonym.random()
        enc_pseudo = encrypt(pseudo, pseudonym_session_keys.public)

        # Test byte encoding/decoding
        encoded = enc_pseudo.to_bytes()
        decoded = EncryptedPseudonym.from_bytes(encoded)
        self.assertIsNotNone(decoded)

        # Test base64 encoding/decoding
        b64_str = enc_pseudo.to_base64()
        decoded_b64 = EncryptedPseudonym.from_base64(b64_str)
        self.assertIsNotNone(decoded_b64)

        # Verify decryption works
        dec1 = decrypt(decoded, pseudonym_session_keys.secret)
        dec2 = decrypt(decoded_b64, pseudonym_session_keys.secret)
        self.assertEqual(pseudo.to_hex(), dec1.to_hex())
        self.assertEqual(pseudo.to_hex(), dec2.to_hex())

        # Test same for encrypted data point
        data = Attribute.random()
        enc_data = encrypt(data, attribute_session_keys.public)

        encoded_data = enc_data.to_bytes()
        decoded_data = EncryptedAttribute.from_bytes(encoded_data)
        self.assertIsNotNone(decoded_data)

        dec_data = decrypt(decoded_data, attribute_session_keys.secret)
        self.assertEqual(data.to_hex(), dec_data.to_hex())

    def test_key_generation_consistency(self):
        """Test that key generation is consistent"""
        secret = b"consistent_secret"
        enc_secret = EncryptionSecret(secret)

        # Generate same global keys multiple times (they should be random)
        pseudo_keys1 = make_pseudonym_global_keys()
        pseudo_keys2 = make_pseudonym_global_keys()
        self.assertNotEqual(pseudo_keys1.public.to_hex(), pseudo_keys2.public.to_hex())

        attr_keys1 = make_attribute_global_keys()
        attr_keys2 = make_attribute_global_keys()
        self.assertNotEqual(attr_keys1.public.to_hex(), attr_keys2.public.to_hex())

        # Generate same session keys with same inputs (should be deterministic)
        pseudonym_global_keys = make_pseudonym_global_keys()
        session1a = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, EncryptionContext("session1"), enc_secret
        )
        session1b = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, EncryptionContext("session1"), enc_secret
        )

        self.assertEqual(
            session1a.public.to_point().to_hex(), session1b.public.to_point().to_hex()
        )

        # Different session names should give different keys
        session2 = make_pseudonym_session_keys(
            pseudonym_global_keys.secret, EncryptionContext("session2"), enc_secret
        )
        self.assertNotEqual(
            session1a.public.to_point().to_hex(), session2.public.to_point().to_hex()
        )

    def test_global_public_key_operations(self):
        """Test global public key specific operations"""
        # Test PseudonymGlobalPublicKey
        pseudo_keys = make_pseudonym_global_keys()
        pseudo_pub_key = pseudo_keys.public

        # Test hex operations
        hex_str = pseudo_pub_key.to_hex()
        decoded = PseudonymGlobalPublicKey.from_hex(hex_str)
        self.assertIsNotNone(decoded)
        self.assertEqual(hex_str, decoded.to_hex())

        # Test AttributeGlobalPublicKey
        attr_keys = make_attribute_global_keys()
        attr_pub_key = attr_keys.public

        # Test hex operations
        hex_str2 = attr_pub_key.to_hex()
        decoded2 = AttributeGlobalPublicKey.from_hex(hex_str2)
        self.assertIsNotNone(decoded2)
        self.assertEqual(hex_str2, decoded2.to_hex())



if __name__ == "__main__":
    unittest.main()
