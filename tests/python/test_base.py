#!/usr/bin/env python3
"""
Python integration tests for base module.
Tests ElGamal encryption/decryption and PEP primitive operations.
"""

import unittest
import libpep
arithmetic = libpep.arithmetic
base = libpep.base


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
        encrypted = base.encrypt(m, Y)
        decrypted = base.decrypt(encrypted, y)

        # Verify message integrity
        self.assertEqual(m.to_hex(), decrypted.to_hex())

    def test_multiple_encryptions(self):
        """Test that multiple encryptions of same message are different (due to randomness)"""
        G = arithmetic.GroupElement.generator()
        y = arithmetic.ScalarNonZero.random()
        Y = G.mul(y)
        m = arithmetic.GroupElement.random()

        # Encrypt same message multiple times
        enc1 = base.encrypt(m, Y)
        enc2 = base.encrypt(m, Y)

        # Ciphertexts should be different (due to randomness)
        self.assertNotEqual(enc1.to_base64(), enc2.to_base64())

        # But both should decrypt to same message
        dec1 = base.decrypt(enc1, y)
        dec2 = base.decrypt(enc2, y)

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
        encrypted = base.encrypt(m, Y)

        # Test byte encoding/decoding
        encoded_bytes = encrypted.to_bytes()
        decoded = base.ElGamal.from_bytes(encoded_bytes)
        self.assertIsNotNone(decoded)

        # Verify decryption still works
        decrypted_original = base.decrypt(encrypted, y)
        decrypted_decoded = base.decrypt(decoded, y)
        self.assertEqual(decrypted_original.to_hex(), decrypted_decoded.to_hex())

        # Test base64 encoding/decoding
        base64_str = encrypted.to_base64()
        decoded_b64 = base.ElGamal.from_base64(base64_str)
        self.assertIsNotNone(decoded_b64)

        # Verify decryption still works
        decrypted_b64 = base.decrypt(decoded_b64, y)
        self.assertEqual(decrypted_original.to_hex(), decrypted_b64.to_hex())

    def test_elgamal_representation(self):
        """Test ElGamal string representations"""
        G = arithmetic.GroupElement.generator()
        y = arithmetic.ScalarNonZero.random()
        Y = G.mul(y)
        m = arithmetic.GroupElement.random()

        encrypted = base.encrypt(m, Y)

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
        encrypted = base.encrypt(generator, Y)
        decrypted = base.decrypt(encrypted, y)

        # Should decrypt back to original message
        self.assertEqual(generator.to_hex(), decrypted.to_hex())


class TestPrimitives(unittest.TestCase):

    def setUp(self):
        """Setup common test data"""
        # Generate key pair
        self.G = arithmetic.GroupElement.generator()
        self.y = arithmetic.ScalarNonZero.random()
        self.Y = self.G.mul(self.y)  # Public key

        # Generate message and encrypt it
        self.m = arithmetic.GroupElement.random()
        self.encrypted = base.encrypt(self.m, self.Y)

    def test_rerandomize(self):
        """Test rerandomization primitive"""
        # Generate rerandomization factor
        r = arithmetic.ScalarNonZero.random()

        # Rerandomize the ciphertext
        if hasattr(base, 'rerandomize'):
            # Check if we need public key (non-elgamal3 version)
            try:
                rerandomized = base.rerandomize(self.encrypted, self.Y, r)
            except TypeError:
                # elgamal3 version - doesn't need public key
                rerandomized = base.rerandomize(self.encrypted, r)
        else:
            self.skipTest("rerandomize not available")

        # Both should decrypt to same message
        dec_original = base.decrypt(self.encrypted, self.y)
        dec_rerandomized = base.decrypt(rerandomized, self.y)

        self.assertEqual(dec_original.to_hex(), dec_rerandomized.to_hex())
        self.assertEqual(self.m.to_hex(), dec_rerandomized.to_hex())

        # But ciphertexts should be different
        self.assertNotEqual(self.encrypted.to_base64(), rerandomized.to_base64())

    def test_rekey(self):
        """Test rekeying primitive"""
        # Generate rekeying factor
        k = arithmetic.ScalarNonZero.random()

        # Rekey the ciphertext
        rekeyed = base.rekey(self.encrypted, k)

        # New secret key should be k * y
        new_secret = self.y.mul(k)

        # Decrypt with new key
        decrypted = base.decrypt(rekeyed, new_secret)

        # Should decrypt to same message
        self.assertEqual(self.m.to_hex(), decrypted.to_hex())

    def test_reshuffle(self):
        """Test reshuffling primitive"""
        # Generate shuffle factor
        s = arithmetic.ScalarNonZero.random()

        # Reshuffle the ciphertext
        reshuffled = base.reshuffle(self.encrypted, s)

        # Decrypt and verify the message is multiplied by s
        decrypted = base.decrypt(reshuffled, self.y)
        expected = self.m.mul(s)

        self.assertEqual(expected.to_hex(), decrypted.to_hex())

    def test_rsk_combined(self):
        """Test combined reshuffle and rekey (rsk) operation"""
        # Generate factors
        s = arithmetic.ScalarNonZero.random()
        k = arithmetic.ScalarNonZero.random()

        # Apply rsk
        rsk_result = base.rsk(self.encrypted, s, k)

        # Apply operations separately
        reshuffled = base.reshuffle(self.encrypted, s)
        rsk_separate = base.rekey(reshuffled, k)

        # New secret key
        new_secret = self.y.mul(k)

        # Both should decrypt to same result
        dec_combined = base.decrypt(rsk_result, new_secret)
        dec_separate = base.decrypt(rsk_separate, new_secret)

        self.assertEqual(dec_combined.to_hex(), dec_separate.to_hex())

        # Should be original message multiplied by s
        expected = self.m.mul(s)
        self.assertEqual(expected.to_hex(), dec_combined.to_hex())

    def test_rekey2_transitivity(self):
        """Test transitive rekeying (rekey2)"""
        # Generate key factors
        k_from = arithmetic.ScalarNonZero.random()
        k_to = arithmetic.ScalarNonZero.random()

        # First, rekey with k_from
        rekeyed_from = base.rekey(self.encrypted, k_from)

        # Then use rekey2 to go from k_from to k_to
        rekeyed_to = base.rekey2(rekeyed_from, k_from, k_to)

        # This should be equivalent to direct rekey with k_to
        direct_rekey = base.rekey(self.encrypted, k_to)

        # Both should decrypt to same message with k_to * y
        new_secret = self.y.mul(k_to)

        dec_transitive = base.decrypt(rekeyed_to, new_secret)
        dec_direct = base.decrypt(direct_rekey, new_secret)

        self.assertEqual(dec_transitive.to_hex(), dec_direct.to_hex())
        self.assertEqual(self.m.to_hex(), dec_transitive.to_hex())

    def test_reshuffle2_transitivity(self):
        """Test transitive reshuffling (reshuffle2)"""
        # Generate shuffle factors
        n_from = arithmetic.ScalarNonZero.random()
        n_to = arithmetic.ScalarNonZero.random()

        # First, reshuffle with n_from
        reshuffled_from = base.reshuffle(self.encrypted, n_from)

        # Then use reshuffle2 to go from n_from to n_to
        reshuffled_to = base.reshuffle2(reshuffled_from, n_from, n_to)

        # This should be equivalent to direct reshuffle with n_to
        direct_reshuffle = base.reshuffle(self.encrypted, n_to)

        # Both should decrypt to same result
        dec_transitive = base.decrypt(reshuffled_to, self.y)
        dec_direct = base.decrypt(direct_reshuffle, self.y)

        self.assertEqual(dec_transitive.to_hex(), dec_direct.to_hex())

        # Should be original message multiplied by n_to
        expected = self.m.mul(n_to)
        self.assertEqual(expected.to_hex(), dec_transitive.to_hex())

    def test_rsk2_transitivity(self):
        """Test transitive combined operation (rsk2)"""
        # Generate factors
        s_from = arithmetic.ScalarNonZero.random()
        s_to = arithmetic.ScalarNonZero.random()
        k_from = arithmetic.ScalarNonZero.random()
        k_to = arithmetic.ScalarNonZero.random()

        # First, apply rsk with from factors
        rsk_from = base.rsk(self.encrypted, s_from, k_from)

        # Then use rsk2 to transition
        rsk_to = base.rsk2(rsk_from, s_from, s_to, k_from, k_to)

        # This should be equivalent to direct rsk with to factors
        direct_rsk = base.rsk(self.encrypted, s_to, k_to)

        # Both should decrypt to same result
        new_secret = self.y.mul(k_to)

        dec_transitive = base.decrypt(rsk_to, new_secret)
        dec_direct = base.decrypt(direct_rsk, new_secret)

        self.assertEqual(dec_transitive.to_hex(), dec_direct.to_hex())

        # Should be original message multiplied by s_to
        expected = self.m.mul(s_to)
        self.assertEqual(expected.to_hex(), dec_transitive.to_hex())

    def test_identity_operations(self):
        """Test operations with identity elements"""
        # Test with scalar one (identity for multiplication)
        one = arithmetic.ScalarNonZero.one()

        # Rekey with one should not change decryption
        rekeyed_one = base.rekey(self.encrypted, one)
        dec_rekeyed = base.decrypt(rekeyed_one, self.y)
        self.assertEqual(self.m.to_hex(), dec_rekeyed.to_hex())

        # Reshuffle with one should not change message
        reshuffled_one = base.reshuffle(self.encrypted, one)
        dec_reshuffled = base.decrypt(reshuffled_one, self.y)
        self.assertEqual(self.m.to_hex(), dec_reshuffled.to_hex())

        # rsk with ones should not change anything
        rsk_ones = base.rsk(self.encrypted, one, one)
        dec_rsk = base.decrypt(rsk_ones, self.y)
        self.assertEqual(self.m.to_hex(), dec_rsk.to_hex())


if __name__ == '__main__':
    unittest.main()
