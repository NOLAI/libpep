#!/usr/bin/env python3
"""
Python integration tests for base module.
Tests ElGamal encryption/decryption and PEP primitive operations.
"""

import unittest
from libpep.arithmetic.group_elements import GroupElement
from libpep.arithmetic.scalars import ScalarNonZero
import libpep.base as base
from libpep.base.elgamal import encrypt, decrypt, ElGamal
from libpep.base.primitives import (
    rekey,
    rekey2,
    rerandomize,
    reshuffle,
    reshuffle2,
    rsk,
    rsk2,
    rrsk,
    rrsk2,
)


class TestElGamal(unittest.TestCase):
    def test_encryption_decryption(self):
        """Test basic ElGamal encryption/decryption"""
        # Generate key pair
        G = GroupElement.generator()
        y = ScalarNonZero.random()
        Y = G.mul(y)  # Public key

        # Generate random message
        m = GroupElement.random()

        # Encrypt and decrypt
        encrypted = encrypt(m, Y)
        decrypted = decrypt(encrypted, y)

        # Verify message integrity
        self.assertEqual(m.to_hex(), decrypted.to_hex())

    def test_multiple_encryptions(self):
        """Test that multiple encryptions of same message are different (due to randomness)"""
        G = GroupElement.generator()
        y = ScalarNonZero.random()
        Y = G.mul(y)
        m = GroupElement.random()

        # Encrypt same message multiple times
        enc1 = encrypt(m, Y)
        enc2 = encrypt(m, Y)

        # Ciphertexts should be different (due to randomness)
        self.assertNotEqual(enc1.to_base64(), enc2.to_base64())

        # But both should decrypt to same message
        dec1 = decrypt(enc1, y)
        dec2 = decrypt(enc2, y)

        self.assertEqual(m.to_hex(), dec1.to_hex())
        self.assertEqual(m.to_hex(), dec2.to_hex())
        self.assertEqual(dec1.to_hex(), dec2.to_hex())

    def test_elgamal_encoding(self):
        """Test ElGamal ciphertext encoding/decoding"""
        G = GroupElement.generator()
        y = ScalarNonZero.random()
        Y = G.mul(y)
        m = GroupElement.random()

        # Create ciphertext
        encrypted = encrypt(m, Y)

        # Test byte encoding/decoding
        encoded_bytes = encrypted.to_bytes()
        decoded = ElGamal.from_bytes(encoded_bytes)
        self.assertIsNotNone(decoded)

        # Verify decryption still works
        decrypted_original = decrypt(encrypted, y)
        decrypted_decoded = decrypt(decoded, y)
        self.assertEqual(decrypted_original.to_hex(), decrypted_decoded.to_hex())

        # Test base64 encoding/decoding
        base64_str = encrypted.to_base64()
        decoded_b64 = ElGamal.from_base64(base64_str)
        self.assertIsNotNone(decoded_b64)

        # Verify decryption still works
        decrypted_b64 = decrypt(decoded_b64, y)
        self.assertEqual(decrypted_original.to_hex(), decrypted_b64.to_hex())

    def test_elgamal_representation(self):
        """Test ElGamal string representations"""
        G = GroupElement.generator()
        y = ScalarNonZero.random()
        Y = G.mul(y)
        m = GroupElement.random()

        encrypted = encrypt(m, Y)

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
        y = ScalarNonZero.from_hex(y_hex)
        self.assertIsNotNone(y)

        # Use generator as both message and base for public key
        generator = GroupElement.generator()
        Y = generator.mul(y)  # Public key

        # Encrypt generator with this key setup
        encrypted = encrypt(generator, Y)
        decrypted = decrypt(encrypted, y)

        # Should decrypt back to original message
        self.assertEqual(generator.to_hex(), decrypted.to_hex())


class TestPrimitives(unittest.TestCase):
    def setUp(self):
        """Setup common test data"""
        # Generate key pair
        self.G = GroupElement.generator()
        self.y = ScalarNonZero.random()
        self.Y = self.G.mul(self.y)  # Public key

        # Generate message and encrypt it
        self.m = GroupElement.random()
        self.encrypted = encrypt(self.m, self.Y)

    def test_rerandomize(self):
        """Test rerandomization primitive"""
        # Generate rerandomization factor
        r = ScalarNonZero.random()

        # Rerandomize the ciphertext
        if hasattr(base, "rerandomize"):
            # Check if we need public key (non-elgamal3 version)
            try:
                rerandomized = rerandomize(self.encrypted, self.Y, r)
            except TypeError:
                # elgamal3 version - doesn't need public key
                rerandomized = rerandomize(self.encrypted, r)
        else:
            self.skipTest("rerandomize not available")

        # Both should decrypt to same message
        dec_original = decrypt(self.encrypted, self.y)
        dec_rerandomized = decrypt(rerandomized, self.y)

        self.assertEqual(dec_original.to_hex(), dec_rerandomized.to_hex())
        self.assertEqual(self.m.to_hex(), dec_rerandomized.to_hex())

        # But ciphertexts should be different
        self.assertNotEqual(self.encrypted.to_base64(), rerandomized.to_base64())

    def test_rekey(self):
        """Test rekeying primitive"""
        # Generate rekeying factor
        k = ScalarNonZero.random()

        # Rekey the ciphertext
        rekeyed = rekey(self.encrypted, k)

        # New secret key should be k * y
        new_secret = self.y.mul(k)

        # Decrypt with new key
        decrypted = decrypt(rekeyed, new_secret)

        # Should decrypt to same message
        self.assertEqual(self.m.to_hex(), decrypted.to_hex())

    def test_reshuffle(self):
        """Test reshuffling primitive"""
        # Generate shuffle factor
        s = ScalarNonZero.random()

        # Reshuffle the ciphertext
        reshuffled = reshuffle(self.encrypted, s)

        # Decrypt and verify the message is multiplied by s
        decrypted = decrypt(reshuffled, self.y)
        expected = self.m.mul(s)

        self.assertEqual(expected.to_hex(), decrypted.to_hex())

    def test_rsk_combined(self):
        """Test combined reshuffle and rekey (rsk) operation"""
        # Generate factors
        s = ScalarNonZero.random()
        k = ScalarNonZero.random()

        # Apply rsk
        rsk_result = rsk(self.encrypted, s, k)

        # Apply operations separately
        reshuffled = reshuffle(self.encrypted, s)
        rsk_separate = rekey(reshuffled, k)

        # New secret key
        new_secret = self.y.mul(k)

        # Both should decrypt to same result
        dec_combined = decrypt(rsk_result, new_secret)
        dec_separate = decrypt(rsk_separate, new_secret)

        self.assertEqual(dec_combined.to_hex(), dec_separate.to_hex())

        # Should be original message multiplied by s
        expected = self.m.mul(s)
        self.assertEqual(expected.to_hex(), dec_combined.to_hex())

    def test_rekey2_transitivity(self):
        """Test transitive rekeying (rekey2)"""
        # Generate key factors
        k_from = ScalarNonZero.random()
        k_to = ScalarNonZero.random()

        # First, rekey with k_from
        rekeyed_from = rekey(self.encrypted, k_from)

        # Then use rekey2 to go from k_from to k_to
        rekeyed_to = rekey2(rekeyed_from, k_from, k_to)

        # This should be equivalent to direct rekey with k_to
        direct_rekey = rekey(self.encrypted, k_to)

        # Both should decrypt to same message with k_to * y
        new_secret = self.y.mul(k_to)

        dec_transitive = decrypt(rekeyed_to, new_secret)
        dec_direct = decrypt(direct_rekey, new_secret)

        self.assertEqual(dec_transitive.to_hex(), dec_direct.to_hex())
        self.assertEqual(self.m.to_hex(), dec_transitive.to_hex())

    def test_reshuffle2_transitivity(self):
        """Test transitive reshuffling (reshuffle2)"""
        # Generate shuffle factors
        n_from = ScalarNonZero.random()
        n_to = ScalarNonZero.random()

        # First, reshuffle with n_from
        reshuffled_from = reshuffle(self.encrypted, n_from)

        # Then use reshuffle2 to go from n_from to n_to
        reshuffled_to = reshuffle2(reshuffled_from, n_from, n_to)

        # This should be equivalent to direct reshuffle with n_to
        direct_reshuffle = reshuffle(self.encrypted, n_to)

        # Both should decrypt to same result
        dec_transitive = decrypt(reshuffled_to, self.y)
        dec_direct = decrypt(direct_reshuffle, self.y)

        self.assertEqual(dec_transitive.to_hex(), dec_direct.to_hex())

        # Should be original message multiplied by n_to
        expected = self.m.mul(n_to)
        self.assertEqual(expected.to_hex(), dec_transitive.to_hex())

    def test_rsk2_transitivity(self):
        """Test transitive combined operation (rsk2)"""
        # Generate factors
        s_from = ScalarNonZero.random()
        s_to = ScalarNonZero.random()
        k_from = ScalarNonZero.random()
        k_to = ScalarNonZero.random()

        # First, apply rsk with from factors
        rsk_from = rsk(self.encrypted, s_from, k_from)

        # Then use rsk2 to transition
        rsk_to = rsk2(rsk_from, s_from, s_to, k_from, k_to)

        # This should be equivalent to direct rsk with to factors
        direct_rsk = rsk(self.encrypted, s_to, k_to)

        # Both should decrypt to same result
        new_secret = self.y.mul(k_to)

        dec_transitive = decrypt(rsk_to, new_secret)
        dec_direct = decrypt(direct_rsk, new_secret)

        self.assertEqual(dec_transitive.to_hex(), dec_direct.to_hex())

        # Should be original message multiplied by s_to
        expected = self.m.mul(s_to)
        self.assertEqual(expected.to_hex(), dec_transitive.to_hex())

    def test_identity_operations(self):
        """Test operations with identity elements"""
        # Test with scalar one (identity for multiplication)
        one = ScalarNonZero.one()

        # Rekey with one should not change decryption
        rekeyed_one = rekey(self.encrypted, one)
        dec_rekeyed = decrypt(rekeyed_one, self.y)
        self.assertEqual(self.m.to_hex(), dec_rekeyed.to_hex())

        # Reshuffle with one should not change message
        reshuffled_one = reshuffle(self.encrypted, one)
        dec_reshuffled = decrypt(reshuffled_one, self.y)
        self.assertEqual(self.m.to_hex(), dec_reshuffled.to_hex())

        # rsk with ones should not change anything
        rsk_ones = rsk(self.encrypted, one, one)
        dec_rsk = decrypt(rsk_ones, self.y)
        self.assertEqual(self.m.to_hex(), dec_rsk.to_hex())


if __name__ == "__main__":
    unittest.main()
