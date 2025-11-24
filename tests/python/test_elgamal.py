#!/usr/bin/env python3
"""
Python integration tests for elgamal module.
Tests ElGamal encryption and decryption functionality.
"""

import unittest
import libpep
arithmetic = libpep.arithmetic
elgamal = libpep.low_level


class TestElGamal(unittest.TestCase):
    
    def test_encryption_decryption(self):
        """Test basic ElGamal encryption/decryption"""
        # Generate key pair
        G = arithmetic.GroupElement.generator()
        y = arithmetic.ScalarNonZero.random()
        Y = G.mul(y)  # Public key
        
        # Generate random message
        m = arithmetic.GroupElement.random()
        
        # Encrypt and decrypt
        encrypted = elgamal.encrypt(m, Y)
        decrypted = elgamal.decrypt(encrypted, y)
        
        # Verify message integrity
        self.assertEqual(m.to_hex(), decrypted.to_hex())
    
    def test_multiple_encryptions(self):
        """Test that multiple encryptions of same message are different (due to randomness)"""
        G = arithmetic.GroupElement.generator()
        y = arithmetic.ScalarNonZero.random()
        Y = G.mul(y)
        m = arithmetic.GroupElement.random()
        
        # Encrypt same message multiple times
        enc1 = elgamal.encrypt(m, Y)
        enc2 = elgamal.encrypt(m, Y)
        
        # Ciphertexts should be different (due to randomness)
        self.assertNotEqual(enc1.to_base64(), enc2.to_base64())
        
        # But both should decrypt to same message
        dec1 = elgamal.decrypt(enc1, y)
        dec2 = elgamal.decrypt(enc2, y)
        
        self.assertEqual(m.to_hex(), dec1.to_hex())
        self.assertEqual(m.to_hex(), dec2.to_hex())
        self.assertEqual(dec1.to_hex(), dec2.to_hex())
    
    def test_elgamal_encoding(self):
        """Test ElGamal ciphertext encoding/decoding"""
        G = arithmetic.GroupElement.generator()
        y = arithmetic.ScalarNonZero.random()
        Y = G.mul(y)
        m = arithmetic.GroupElement.random()
        
        # Create ciphertext
        encrypted = elgamal.encrypt(m, Y)
        
        # Test byte encoding/decoding
        encoded_bytes = encrypted.to_bytes()
        decoded = elgamal.ElGamal.from_bytes(encoded_bytes)
        self.assertIsNotNone(decoded)
        
        # Verify decryption still works
        decrypted_original = elgamal.decrypt(encrypted, y)
        decrypted_decoded = elgamal.decrypt(decoded, y)
        self.assertEqual(decrypted_original.to_hex(), decrypted_decoded.to_hex())
        
        # Test base64 encoding/decoding
        base64_str = encrypted.to_base64()
        decoded_b64 = elgamal.ElGamal.from_base64(base64_str)
        self.assertIsNotNone(decoded_b64)
        
        # Verify decryption still works
        decrypted_b64 = elgamal.decrypt(decoded_b64, y)
        self.assertEqual(decrypted_original.to_hex(), decrypted_b64.to_hex())
    
    def test_elgamal_representation(self):
        """Test ElGamal string representations"""
        G = arithmetic.GroupElement.generator()
        y = arithmetic.ScalarNonZero.random()
        Y = G.mul(y)
        m = arithmetic.GroupElement.random()
        
        encrypted = elgamal.encrypt(m, Y)
        
        # Test string representations
        str_repr = str(encrypted)
        repr_repr = repr(encrypted)
        
        self.assertIsInstance(str_repr, str)
        self.assertIsInstance(repr_repr, str)
        self.assertIn("ElGamal", repr_repr)
        
        # str should be same as base64
        self.assertEqual(str_repr, encrypted.to_base64())
    
    def test_deterministic_values(self):
        """Test with known deterministic values for consistency"""
        # Use known values for reproducible test
        y_hex = "044214715d782745a36ededee498b31d882f5e6239db9f9443f6bfef04944906"
        y = arithmetic.ScalarNonZero.from_hex(y_hex)
        self.assertIsNotNone(y)
        
        # Use generator as both message and base for public key
        generator = arithmetic.GroupElement.generator()
        Y = generator.mul(y)  # Public key
        
        # Encrypt generator with this key setup
        encrypted = elgamal.encrypt(generator, Y)
        decrypted = elgamal.decrypt(encrypted, y)
        
        # Should decrypt back to original message
        self.assertEqual(generator.to_hex(), decrypted.to_hex())


if __name__ == '__main__':
    unittest.main()