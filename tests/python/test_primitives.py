#!/usr/bin/env python3
"""
Python integration tests for primitives module.
Tests PEP primitive operations like rekey, reshuffle, and rsk.
"""

import unittest
import libpep
arithmetic = libpep.arithmetic
elgamal = libpep.elgamal
primitives = libpep.primitives


class TestPrimitives(unittest.TestCase):
    
    def setUp(self):
        """Setup common test data"""
        # Generate key pair
        self.G = arithmetic.GroupElement.generator()
        self.y = arithmetic.ScalarNonZero.random()
        self.Y = self.G.mul(self.y)  # Public key
        
        # Generate message and encrypt it
        self.m = arithmetic.GroupElement.random()
        self.encrypted = elgamal.encrypt(self.m, self.Y)
    
    def test_rerandomize(self):
        """Test rerandomization primitive"""
        # Generate rerandomization factor
        r = arithmetic.ScalarNonZero.random()
        
        # Rerandomize the ciphertext
        if hasattr(primitives, 'rerandomize'):
            # Check if we need public key (non-elgamal3 version)
            try:
                rerandomized = primitives.rerandomize(self.encrypted, self.Y, r)
            except TypeError:
                # elgamal3 version - doesn't need public key
                rerandomized = primitives.rerandomize(self.encrypted, r)
        else:
            self.skipTest("rerandomize not available")
        
        # Both should decrypt to same message
        dec_original = elgamal.decrypt(self.encrypted, self.y)
        dec_rerandomized = elgamal.decrypt(rerandomized, self.y)
        
        self.assertEqual(dec_original.as_hex(), dec_rerandomized.as_hex())
        self.assertEqual(self.m.as_hex(), dec_rerandomized.as_hex())
        
        # But ciphertexts should be different
        self.assertNotEqual(self.encrypted.as_base64(), rerandomized.as_base64())
    
    def test_rekey(self):
        """Test rekeying primitive"""
        # Generate rekeying factor
        k = arithmetic.ScalarNonZero.random()
        
        # Rekey the ciphertext
        rekeyed = primitives.rekey(self.encrypted, k)
        
        # New secret key should be k * y
        new_secret = self.y.mul(k)
        
        # Decrypt with new key
        decrypted = elgamal.decrypt(rekeyed, new_secret)
        
        # Should decrypt to same message
        self.assertEqual(self.m.as_hex(), decrypted.as_hex())
    
    def test_reshuffle(self):
        """Test reshuffling primitive"""
        # Generate shuffle factor
        s = arithmetic.ScalarNonZero.random()
        
        # Reshuffle the ciphertext
        reshuffled = primitives.reshuffle(self.encrypted, s)
        
        # Decrypt and verify the message is multiplied by s
        decrypted = elgamal.decrypt(reshuffled, self.y)
        expected = self.m.mul(s)
        
        self.assertEqual(expected.as_hex(), decrypted.as_hex())
    
    def test_rsk_combined(self):
        """Test combined reshuffle and rekey (rsk) operation"""
        # Generate factors
        s = arithmetic.ScalarNonZero.random()
        k = arithmetic.ScalarNonZero.random()
        
        # Apply rsk
        rsk_result = primitives.rsk(self.encrypted, s, k)
        
        # Apply operations separately
        reshuffled = primitives.reshuffle(self.encrypted, s)
        rsk_separate = primitives.rekey(reshuffled, k)
        
        # New secret key
        new_secret = self.y.mul(k)
        
        # Both should decrypt to same result
        dec_combined = elgamal.decrypt(rsk_result, new_secret)
        dec_separate = elgamal.decrypt(rsk_separate, new_secret)
        
        self.assertEqual(dec_combined.as_hex(), dec_separate.as_hex())
        
        # Should be original message multiplied by s
        expected = self.m.mul(s)
        self.assertEqual(expected.as_hex(), dec_combined.as_hex())
    
    def test_rekey2_transitivity(self):
        """Test transitive rekeying (rekey2)"""
        # Generate key factors
        k_from = arithmetic.ScalarNonZero.random()
        k_to = arithmetic.ScalarNonZero.random()
        
        # First, rekey with k_from
        rekeyed_from = primitives.rekey(self.encrypted, k_from)
        
        # Then use rekey2 to go from k_from to k_to
        rekeyed_to = primitives.rekey2(rekeyed_from, k_from, k_to)
        
        # This should be equivalent to direct rekey with k_to
        direct_rekey = primitives.rekey(self.encrypted, k_to)
        
        # Both should decrypt to same message with k_to * y
        new_secret = self.y.mul(k_to)
        
        dec_transitive = elgamal.decrypt(rekeyed_to, new_secret)
        dec_direct = elgamal.decrypt(direct_rekey, new_secret)
        
        self.assertEqual(dec_transitive.as_hex(), dec_direct.as_hex())
        self.assertEqual(self.m.as_hex(), dec_transitive.as_hex())
    
    def test_reshuffle2_transitivity(self):
        """Test transitive reshuffling (reshuffle2)"""
        # Generate shuffle factors
        n_from = arithmetic.ScalarNonZero.random()
        n_to = arithmetic.ScalarNonZero.random()
        
        # First, reshuffle with n_from
        reshuffled_from = primitives.reshuffle(self.encrypted, n_from)
        
        # Then use reshuffle2 to go from n_from to n_to
        reshuffled_to = primitives.reshuffle2(reshuffled_from, n_from, n_to)
        
        # This should be equivalent to direct reshuffle with n_to
        direct_reshuffle = primitives.reshuffle(self.encrypted, n_to)
        
        # Both should decrypt to same result
        dec_transitive = elgamal.decrypt(reshuffled_to, self.y)
        dec_direct = elgamal.decrypt(direct_reshuffle, self.y)
        
        self.assertEqual(dec_transitive.as_hex(), dec_direct.as_hex())
        
        # Should be original message multiplied by n_to
        expected = self.m.mul(n_to)
        self.assertEqual(expected.as_hex(), dec_transitive.as_hex())
    
    def test_rsk2_transitivity(self):
        """Test transitive combined operation (rsk2)"""
        # Generate factors
        s_from = arithmetic.ScalarNonZero.random()
        s_to = arithmetic.ScalarNonZero.random()
        k_from = arithmetic.ScalarNonZero.random()
        k_to = arithmetic.ScalarNonZero.random()
        
        # First, apply rsk with from factors
        rsk_from = primitives.rsk(self.encrypted, s_from, k_from)
        
        # Then use rsk2 to transition
        rsk_to = primitives.rsk2(rsk_from, s_from, s_to, k_from, k_to)
        
        # This should be equivalent to direct rsk with to factors
        direct_rsk = primitives.rsk(self.encrypted, s_to, k_to)
        
        # Both should decrypt to same result
        new_secret = self.y.mul(k_to)
        
        dec_transitive = elgamal.decrypt(rsk_to, new_secret)
        dec_direct = elgamal.decrypt(direct_rsk, new_secret)
        
        self.assertEqual(dec_transitive.as_hex(), dec_direct.as_hex())
        
        # Should be original message multiplied by s_to
        expected = self.m.mul(s_to)
        self.assertEqual(expected.as_hex(), dec_transitive.as_hex())
    
    def test_identity_operations(self):
        """Test operations with identity elements"""
        # Test with scalar one (identity for multiplication)
        one = arithmetic.ScalarNonZero.one()
        
        # Rekey with one should not change decryption
        rekeyed_one = primitives.rekey(self.encrypted, one)
        dec_rekeyed = elgamal.decrypt(rekeyed_one, self.y)
        self.assertEqual(self.m.as_hex(), dec_rekeyed.as_hex())
        
        # Reshuffle with one should not change message
        reshuffled_one = primitives.reshuffle(self.encrypted, one)
        dec_reshuffled = elgamal.decrypt(reshuffled_one, self.y)
        self.assertEqual(self.m.as_hex(), dec_reshuffled.as_hex())
        
        # rsk with ones should not change anything
        rsk_ones = primitives.rsk(self.encrypted, one, one)
        dec_rsk = elgamal.decrypt(rsk_ones, self.y)
        self.assertEqual(self.m.as_hex(), dec_rsk.as_hex())


if __name__ == '__main__':
    unittest.main()