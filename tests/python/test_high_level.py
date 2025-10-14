#!/usr/bin/env python3
"""
Python integration tests for high_level module.
Tests high-level API for pseudonyms, data points, and session management.
"""

import unittest
from libpep.arithmetic import GroupElement
from libpep.high_level import (
    Pseudonym, Attribute, LongPseudonym, LongAttribute,
    PseudonymizationSecret, EncryptionSecret,
    EncryptedPseudonym, EncryptedAttribute,
    PseudonymGlobalPublicKey, AttributeGlobalPublicKey,
    make_pseudonym_global_keys, make_attribute_global_keys,
    make_pseudonym_session_keys, make_attribute_session_keys,
    encrypt_pseudonym, decrypt_pseudonym, encrypt_data, decrypt_data
)


class TestHighLevel(unittest.TestCase):
    
    def test_high_level_operations(self):
        """Test high-level pseudonym and data operations"""
        # Generate global keys
        pseudonym_global_keys = make_pseudonym_global_keys()
        attribute_global_keys = make_attribute_global_keys()

        # Create secrets
        secret = b"secret"
        pseudo_secret = PseudonymizationSecret(secret)
        enc_secret = EncryptionSecret(secret)

        # Define domains and sessions
        domain1 = "domain1"
        session1 = "session1"
        domain2 = "domain2"
        session2 = "session2"

        # Generate session keys
        pseudonym_session1_keys = make_pseudonym_session_keys(pseudonym_global_keys.secret, session1, enc_secret)
        pseudonym_session2_keys = make_pseudonym_session_keys(pseudonym_global_keys.secret, session2, enc_secret)
        attribute_session1_keys = make_attribute_session_keys(attribute_global_keys.secret, session1, enc_secret)
        attribute_session2_keys = make_attribute_session_keys(attribute_global_keys.secret, session2, enc_secret)

        # Create and encrypt pseudonym
        pseudo = Pseudonym.random()
        enc_pseudo = encrypt_pseudonym(pseudo, pseudonym_session1_keys.public)

        # Create and encrypt data point
        random_point = GroupElement.random()
        data = Attribute(random_point)
        enc_data = encrypt_data(data, attribute_session1_keys.public)

        # Decrypt and verify
        dec_pseudo = decrypt_pseudonym(enc_pseudo, pseudonym_session1_keys.secret)
        dec_data = decrypt_data(enc_data, attribute_session1_keys.secret)

        self.assertEqual(pseudo.as_hex(), dec_pseudo.as_hex())
        self.assertEqual(data.as_hex(), dec_data.as_hex())
    
    def test_pseudonym_operations(self):
        """Test pseudonym creation and manipulation"""
        # Test random pseudonym
        pseudo1 = Pseudonym.random()
        pseudo2 = Pseudonym.random()
        self.assertNotEqual(pseudo1.as_hex(), pseudo2.as_hex())
        
        # Test from group element
        g = GroupElement.random()
        pseudo3 = Pseudonym(g)
        self.assertEqual(g.as_hex(), pseudo3.to_point().as_hex())
        
        # Test encoding/decoding
        encoded = pseudo1.encode()
        decoded = Pseudonym.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(pseudo1.as_hex(), decoded.as_hex())
        
        # Test hex encoding/decoding
        hex_str = pseudo1.as_hex()
        decoded_hex = Pseudonym.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(pseudo1.as_hex(), decoded_hex.as_hex())
    
    def test_attribute_operations(self):
        """Test data point creation and manipulation"""
        # Test random data point
        data1 = Attribute.random()
        data2 = Attribute.random()
        self.assertNotEqual(data1.as_hex(), data2.as_hex())
        
        # Test from group element
        g = GroupElement.random()
        data3 = Attribute(g)
        self.assertEqual(g.as_hex(), data3.to_point().as_hex())
        
        # Test encoding/decoding
        encoded = data1.encode()
        decoded = Attribute.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(data1.as_hex(), decoded.as_hex())
    
    def test_string_padding_operations(self):
        """Test string padding for pseudonyms and data points"""
        test_string = "Hello, World! This is a test string for padding."

        # Test pseudonym string padding
        long_pseudo = LongPseudonym.from_string_padded(test_string)
        self.assertGreater(len(long_pseudo), 0)

        # Reconstruct string
        reconstructed = long_pseudo.to_string_padded()
        self.assertEqual(test_string, reconstructed)

        # Test data point string padding
        long_attr = LongAttribute.from_string_padded(test_string)
        self.assertGreater(len(long_attr), 0)

        # Reconstruct string
        reconstructed_data = long_attr.to_string_padded()
        self.assertEqual(test_string, reconstructed_data)
    
    def test_bytes_padding_operations(self):
        """Test bytes padding for pseudonyms and data points"""
        test_bytes = b"Hello, World! This is a test byte array for padding."

        # Test pseudonym bytes padding
        long_pseudo = LongPseudonym.from_bytes_padded(test_bytes)
        self.assertGreater(len(long_pseudo), 0)

        # Reconstruct bytes
        reconstructed = long_pseudo.to_bytes_padded()
        self.assertEqual(test_bytes, reconstructed)

        # Test data point bytes padding
        long_attr = LongAttribute.from_bytes_padded(test_bytes)
        self.assertGreater(len(long_attr), 0)

        # Reconstruct bytes
        reconstructed_data = long_attr.to_bytes_padded()
        self.assertEqual(test_bytes, reconstructed_data)
    
    def test_fixed_size_bytes_operations(self):
        """Test 16-byte fixed size operations"""
        # Create 16-byte test data
        test_bytes = b"1234567890abcdef"  # Exactly 16 bytes
        
        # Test pseudonym from/as bytes
        pseudo = Pseudonym.from_bytes(test_bytes)
        reconstructed = pseudo.as_bytes()
        self.assertIsNotNone(reconstructed)
        self.assertEqual(test_bytes, reconstructed)
        
        # Test data point from/as bytes
        data = Attribute.from_bytes(test_bytes)
        reconstructed_data = data.as_bytes()
        self.assertIsNotNone(reconstructed_data)
        self.assertEqual(test_bytes, reconstructed_data)
    
    def test_encrypted_types_encoding(self):
        """Test encoding/decoding of encrypted types"""
        # Setup
        pseudonym_global_keys = make_pseudonym_global_keys()
        attribute_global_keys = make_attribute_global_keys()
        secret = b"secret"
        enc_secret = EncryptionSecret(secret)
        pseudonym_session_keys = make_pseudonym_session_keys(pseudonym_global_keys.secret, "session", enc_secret)
        attribute_session_keys = make_attribute_session_keys(attribute_global_keys.secret, "session", enc_secret)

        # Create encrypted pseudonym
        pseudo = Pseudonym.random()
        enc_pseudo = encrypt_pseudonym(pseudo, pseudonym_session_keys.public)

        # Test byte encoding/decoding
        encoded = enc_pseudo.encode()
        decoded = EncryptedPseudonym.decode(encoded)
        self.assertIsNotNone(decoded)

        # Test base64 encoding/decoding
        b64_str = enc_pseudo.as_base64()
        decoded_b64 = EncryptedPseudonym.from_base64(b64_str)
        self.assertIsNotNone(decoded_b64)

        # Verify both decode to same plaintext
        dec1 = decrypt_pseudonym(decoded, pseudonym_session_keys.secret)
        dec2 = decrypt_pseudonym(decoded_b64, pseudonym_session_keys.secret)
        self.assertEqual(pseudo.as_hex(), dec1.as_hex())
        self.assertEqual(pseudo.as_hex(), dec2.as_hex())

        # Test same for encrypted data point
        data = Attribute.random()
        enc_data = encrypt_data(data, attribute_session_keys.public)

        encoded_data = enc_data.encode()
        decoded_data = EncryptedAttribute.decode(encoded_data)
        self.assertIsNotNone(decoded_data)

        dec_data = decrypt_data(decoded_data, attribute_session_keys.secret)
        self.assertEqual(data.as_hex(), dec_data.as_hex())
    
    def test_key_generation_consistency(self):
        """Test that key generation is consistent"""
        secret = b"consistent_secret"
        enc_secret = EncryptionSecret(secret)

        # Generate same global keys multiple times (they should be random)
        pseudo_keys1 = make_pseudonym_global_keys()
        pseudo_keys2 = make_pseudonym_global_keys()
        self.assertNotEqual(pseudo_keys1.public.as_hex(), pseudo_keys2.public.as_hex())

        attr_keys1 = make_attribute_global_keys()
        attr_keys2 = make_attribute_global_keys()
        self.assertNotEqual(attr_keys1.public.as_hex(), attr_keys2.public.as_hex())

        # Generate same session keys with same inputs (should be deterministic)
        pseudonym_global_keys = make_pseudonym_global_keys()
        session1a = make_pseudonym_session_keys(pseudonym_global_keys.secret, "session1", enc_secret)
        session1b = make_pseudonym_session_keys(pseudonym_global_keys.secret, "session1", enc_secret)

        self.assertEqual(session1a.public.to_point().as_hex(), session1b.public.to_point().as_hex())

        # Different session names should give different keys
        session2 = make_pseudonym_session_keys(pseudonym_global_keys.secret, "session2", enc_secret)
        self.assertNotEqual(session1a.public.to_point().as_hex(), session2.public.to_point().as_hex())
    
    def test_global_public_key_operations(self):
        """Test global public key specific operations"""
        # Test PseudonymGlobalPublicKey
        g1 = GroupElement.random()
        pseudo_pub_key = PseudonymGlobalPublicKey(g1)

        # Test point conversion
        self.assertEqual(g1.as_hex(), pseudo_pub_key.to_point().as_hex())

        # Test hex operations
        hex_str = pseudo_pub_key.as_hex()
        decoded = PseudonymGlobalPublicKey.from_hex(hex_str)
        self.assertIsNotNone(decoded)
        self.assertEqual(hex_str, decoded.as_hex())

        # Test AttributeGlobalPublicKey
        g2 = GroupElement.random()
        attr_pub_key = AttributeGlobalPublicKey(g2)

        # Test point conversion
        self.assertEqual(g2.as_hex(), attr_pub_key.to_point().as_hex())

        # Test hex operations
        hex_str2 = attr_pub_key.as_hex()
        decoded2 = AttributeGlobalPublicKey.from_hex(hex_str2)
        self.assertIsNotNone(decoded2)
        self.assertEqual(hex_str2, decoded2.as_hex())


if __name__ == '__main__':
    unittest.main()