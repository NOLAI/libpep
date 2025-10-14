#!/usr/bin/env python3
"""
Python integration tests for distributed module.
Tests distributed n-PEP systems, PEP clients, and key blinding functionality.
"""

import unittest
import libpep
arithmetic = libpep.arithmetic
high_level = libpep.high_level
distributed = libpep.distributed


class TestDistributed(unittest.TestCase):
    
    def setUp(self):
        """Setup common test data"""
        # Generate global keys using the new combined API
        self.global_public_keys, self.global_secret_keys = high_level.make_global_keys()

        # Create secrets
        self.secret = b"test_secret"
        self.pseudo_secret = high_level.PseudonymizationSecret(self.secret)
        self.enc_secret = high_level.EncryptionSecret(self.secret)

        # Create blinding factors (simulate 3 transcryptors)
        self.blinding_factors = [
            distributed.BlindingFactor.random(),
            distributed.BlindingFactor.random(),
            distributed.BlindingFactor.random()
        ]

        # Create blinded global secret keys using the new combined API
        self.blinded_global_keys = distributed.make_blinded_global_keys(
            self.global_secret_keys,
            self.blinding_factors
        )
    
    def test_blinding_factor_operations(self):
        """Test blinding factor creation and operations"""
        # Test random generation
        bf1 = distributed.BlindingFactor.random()
        bf2 = distributed.BlindingFactor.random()
        self.assertNotEqual(bf1.as_hex(), bf2.as_hex())
        
        # Test from scalar
        scalar = arithmetic.ScalarNonZero.random()
        bf3 = distributed.BlindingFactor(scalar)
        
        # Test encoding/decoding
        encoded = bf1.encode()
        decoded = distributed.BlindingFactor.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(bf1.as_hex(), decoded.as_hex())
        
        # Test hex encoding/decoding
        hex_str = bf1.as_hex()
        decoded_hex = distributed.BlindingFactor.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.as_hex())
    
    def test_blinded_global_secret_key(self):
        """Test blinded global secret key operations"""
        # Test encoding/decoding for pseudonym key
        encoded = self.blinded_global_keys.pseudonym.encode()
        decoded = distributed.BlindedPseudonymGlobalSecretKey.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(self.blinded_global_keys.pseudonym.as_hex(), decoded.as_hex())

        # Test hex operations for pseudonym key
        hex_str = self.blinded_global_keys.pseudonym.as_hex()
        decoded_hex = distributed.BlindedPseudonymGlobalSecretKey.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.as_hex())

        # Test encoding/decoding for attribute key
        encoded_attr = self.blinded_global_keys.attribute.encode()
        decoded_attr = distributed.BlindedAttributeGlobalSecretKey.decode(encoded_attr)
        self.assertIsNotNone(decoded_attr)
        self.assertEqual(self.blinded_global_keys.attribute.as_hex(), decoded_attr.as_hex())

        # Test hex operations for attribute key
        hex_str_attr = self.blinded_global_keys.attribute.as_hex()
        decoded_hex_attr = distributed.BlindedAttributeGlobalSecretKey.from_hex(hex_str_attr)
        self.assertIsNotNone(decoded_hex_attr)
        self.assertEqual(hex_str_attr, decoded_hex_attr.as_hex())
    
    def test_pep_system_creation(self):
        """Test PEP system creation and basic operations"""
        # Create PEP system
        pep_system = distributed.PEPSystem(
            "pseudonymization_secret",
            "rekeying_secret", 
            self.blinding_factors[0]
        )
        
        # Test pseudonym session key share generation
        session = "test_session"
        key_share = pep_system.pseudonym_session_key_share(session)

        # Should be deterministic for same inputs
        key_share2 = pep_system.pseudonym_session_key_share(session)
        self.assertEqual(key_share.as_hex(), key_share2.as_hex())

        # Different sessions should give different shares
        key_share3 = pep_system.pseudonym_session_key_share("different_session")
        self.assertNotEqual(key_share.as_hex(), key_share3.as_hex())
    
    def test_pep_system_info_generation(self):
        """Test PEP system info generation"""
        pep_system = distributed.PEPSystem(
            "pseudonymization_secret",
            "rekeying_secret",
            self.blinding_factors[0]
        )
        
        # Test attribute rekey info generation
        attr_rekey_info = pep_system.attribute_rekey_info("session1", "session2")
        self.assertIsNotNone(attr_rekey_info)

        # Test pseudonymization info generation
        pseudo_info = pep_system.pseudonymization_info(
            "domain1", "domain2", "session1", "session2"
        )
        self.assertIsNotNone(pseudo_info)

        # Test reverse operations
        rekey_rev = attr_rekey_info.rev()
        pseudo_rev = pseudo_info.rev()
        
        self.assertIsNotNone(rekey_rev)
        self.assertIsNotNone(pseudo_rev)
    
    def test_pep_client_creation(self):
        """Test PEP client creation and session management"""
        # Create multiple PEP systems (simulating multiple transcryptors)
        systems = []
        session_key_shares = []

        for i in range(3):
            system = distributed.PEPSystem(
                f"pseudo_secret_{i}",
                f"enc_secret_{i}",
                self.blinding_factors[i]
            )
            systems.append(system)

            # Generate session key shares using the convenience method
            shares = system.session_key_shares("test_session")
            session_key_shares.append(shares)

        # Create PEP client using the standard constructor
        client = distributed.PEPClient(
            self.blinded_global_keys,
            session_key_shares
        )
        
        # Test session key dumping
        keys = client.dump()

        # Keys should be valid
        self.assertIsNotNone(keys)
        self.assertIsNotNone(keys.public)
        self.assertIsNotNone(keys.secret)
        self.assertIsNotNone(keys.public.pseudonym)
        self.assertIsNotNone(keys.public.attribute)
    
    def test_encryption_decryption_flow(self):
        """Test full encryption/decryption flow with distributed system"""
        # Setup multiple systems
        systems = []
        session_key_shares = []

        for i in range(3):
            system = distributed.PEPSystem(
                f"pseudo_secret_{i}",
                f"enc_secret_{i}",
                self.blinding_factors[i]
            )
            systems.append(system)
            session_key_shares.append(system.session_key_shares("test_session"))

        # Create client using the standard constructor
        client = distributed.PEPClient(
            self.blinded_global_keys,
            session_key_shares
        )
        
        # Test pseudonym encryption/decryption
        pseudo = high_level.Pseudonym.random()
        enc_pseudo = client.encrypt_pseudonym(pseudo)
        dec_pseudo = client.decrypt_pseudonym(enc_pseudo)
        
        self.assertEqual(pseudo.as_hex(), dec_pseudo.as_hex())
        
        # Test data encryption/decryption
        data = high_level.Attribute.random()
        enc_data = client.encrypt_data(data)
        dec_data = client.decrypt_data(enc_data)
        
        self.assertEqual(data.as_hex(), dec_data.as_hex())
    
    def test_offline_pep_client(self):
        """Test offline PEP client for encryption-only operations"""
        # Create offline client using the combined global public keys
        offline_client = distributed.OfflinePEPClient(self.global_public_keys)
        
        # Test encryption (but can't decrypt without private key)
        pseudo = high_level.Pseudonym.random()
        enc_pseudo = offline_client.encrypt_pseudonym(pseudo)
        
        data = high_level.Attribute.random()
        enc_data = offline_client.encrypt_data(data)
        
        # These should be valid encrypted values
        self.assertIsNotNone(enc_pseudo)
        self.assertIsNotNone(enc_data)
        
        # Note: Global encryption can't be easily decrypted without proper key setup
        # This test verifies the encryption works
        # The offline client is meant for encryption-only scenarios
    
    def test_session_key_share_operations(self):
        """Test session key share encoding and operations"""
        scalar = arithmetic.ScalarNonZero.random()

        # Test PseudonymSessionKeyShare
        pseudo_share = distributed.PseudonymSessionKeyShare(scalar)

        # Test encoding/decoding
        encoded = pseudo_share.encode()
        decoded = distributed.PseudonymSessionKeyShare.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(pseudo_share.as_hex(), decoded.as_hex())

        # Test hex operations
        hex_str = pseudo_share.as_hex()
        decoded_hex = distributed.PseudonymSessionKeyShare.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.as_hex())

        # Test AttributeSessionKeyShare
        attr_share = distributed.AttributeSessionKeyShare(scalar)
        encoded_attr = attr_share.encode()
        decoded_attr = distributed.AttributeSessionKeyShare.decode(encoded_attr)
        self.assertIsNotNone(decoded_attr)
        self.assertEqual(attr_share.as_hex(), decoded_attr.as_hex())

        # Test SessionKeyShares wrapper
        session_shares = distributed.SessionKeyShares(pseudo_share, attr_share)
        self.assertEqual(session_shares.pseudonym.as_hex(), pseudo_share.as_hex())
        self.assertEqual(session_shares.attribute.as_hex(), attr_share.as_hex())
    
    def test_pseudonymization_rekey_info(self):
        """Test standalone pseudonymization and rekey info creation"""
        # Test PseudonymizationInfo creation
        pseudo_info = distributed.PseudonymizationInfo(
            "domain1", "domain2", "session1", "session2",
            self.pseudo_secret, self.enc_secret
        )
        
        # Test reverse operation
        pseudo_rev = pseudo_info.rev()
        self.assertIsNotNone(pseudo_rev)
        
        # Test AttributeRekeyInfo creation
        attr_rekey_info = distributed.AttributeRekeyInfo("session1", "session2", self.enc_secret)
        rekey_rev = attr_rekey_info.rev()
        self.assertIsNotNone(rekey_rev)
    
    def test_session_key_update(self):
        """Test session key share update functionality"""
        # Create initial client
        systems = []
        initial_shares = []

        for i in range(3):
            system = distributed.PEPSystem(
                f"pseudo_secret_{i}",
                f"enc_secret_{i}",
                self.blinding_factors[i]
            )
            systems.append(system)
            initial_shares.append(system.session_key_shares("session1"))

        client = distributed.PEPClient(
            self.blinded_global_keys,
            initial_shares
        )

        # Generate new shares for session2
        new_shares = []
        for system in systems:
            new_shares.append(system.session_key_shares("session2"))

        # Update session keys one by one using the convenience method
        for i in range(3):
            client.update_session_secret_keys(initial_shares[i], new_shares[i])
        
        # Client should now work with session2 keys
        pseudo = high_level.Pseudonym.random()
        enc_pseudo = client.encrypt_pseudonym(pseudo)
        dec_pseudo = client.decrypt_pseudonym(enc_pseudo)
        
        self.assertEqual(pseudo.as_hex(), dec_pseudo.as_hex())


if __name__ == '__main__':
    unittest.main()