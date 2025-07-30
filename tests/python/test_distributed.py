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
        # Generate global keys
        self.global_keys = high_level.make_global_keys()
        
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
        
        # Create blinded global secret key
        self.blinded_global_key = distributed.make_blinded_global_secret_key(
            self.global_keys.secret, 
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
        # Test encoding/decoding
        encoded = self.blinded_global_key.encode()
        decoded = distributed.BlindedGlobalSecretKey.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(self.blinded_global_key.as_hex(), decoded.as_hex())
        
        # Test hex operations
        hex_str = self.blinded_global_key.as_hex()
        decoded_hex = distributed.BlindedGlobalSecretKey.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.as_hex())
    
    def test_pep_system_creation(self):
        """Test PEP system creation and basic operations"""
        # Create PEP system
        pep_system = distributed.PEPSystem(
            "pseudonymization_secret",
            "rekeying_secret", 
            self.blinding_factors[0]
        )
        
        # Test session key share generation
        session = "test_session"
        key_share = pep_system.session_key_share(session)
        
        # Should be deterministic for same inputs
        key_share2 = pep_system.session_key_share(session)
        self.assertEqual(key_share.as_hex(), key_share2.as_hex())
        
        # Different sessions should give different shares
        key_share3 = pep_system.session_key_share("different_session")
        self.assertNotEqual(key_share.as_hex(), key_share3.as_hex())
    
    def test_pep_system_info_generation(self):
        """Test PEP system info generation"""
        pep_system = distributed.PEPSystem(
            "pseudonymization_secret",
            "rekeying_secret",
            self.blinding_factors[0]
        )
        
        # Test rekey info generation
        rekey_info = pep_system.rekey_info("session1", "session2")
        self.assertIsNotNone(rekey_info)
        
        # Test pseudonymization info generation
        pseudo_info = pep_system.pseudonymization_info(
            "domain1", "domain2", "session1", "session2"
        )
        self.assertIsNotNone(pseudo_info)
        
        # Test reverse operations
        rekey_rev = rekey_info.rev()
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
            
            # Generate session key share
            share = system.session_key_share("test_session")
            session_key_shares.append(share)
        
        # Create PEP client
        client = distributed.PEPClient(self.blinded_global_key, session_key_shares)
        
        # Test session key dumping/restoration
        session_keys = client.dump()
        restored_client = distributed.PEPClient.restore(session_keys)
        
        # Both clients should have same session keys
        original_keys = client.dump()
        restored_keys = restored_client.dump()
        
        self.assertEqual(
            original_keys.public.to_point().as_hex(),
            restored_keys.public.to_point().as_hex()
        )
    
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
            session_key_shares.append(system.session_key_share("test_session"))
        
        # Create client
        client = distributed.PEPClient(self.blinded_global_key, session_key_shares)
        
        # Test pseudonym encryption/decryption
        pseudo = high_level.Pseudonym.random()
        enc_pseudo = client.encrypt_pseudonym(pseudo)
        dec_pseudo = client.decrypt_pseudonym(enc_pseudo)
        
        self.assertEqual(pseudo.as_hex(), dec_pseudo.as_hex())
        
        # Test data encryption/decryption
        data = high_level.DataPoint.random()
        enc_data = client.encrypt_data(data)
        dec_data = client.decrypt_data(enc_data)
        
        self.assertEqual(data.as_hex(), dec_data.as_hex())
    
    def test_offline_pep_client(self):
        """Test offline PEP client for encryption-only operations"""
        # Create offline client
        offline_client = distributed.OfflinePEPClient(self.global_keys.public)
        
        # Test encryption (but can't decrypt without private key)
        pseudo = high_level.Pseudonym.random()
        enc_pseudo = offline_client.encrypt_pseudonym(pseudo)
        
        data = high_level.DataPoint.random()
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
        share = distributed.SessionKeyShare(scalar)
        
        # Test encoding/decoding
        encoded = share.encode()
        decoded = distributed.SessionKeyShare.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(share.as_hex(), decoded.as_hex())
        
        # Test hex operations
        hex_str = share.as_hex()
        decoded_hex = distributed.SessionKeyShare.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.as_hex())
    
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
        
        # Test RekeyInfo creation
        rekey_info = distributed.RekeyInfo("session1", "session2", self.enc_secret)
        rekey_rev = rekey_info.rev()
        self.assertIsNotNone(rekey_rev)
        
        # Test conversion from pseudonymization info
        rekey_from_pseudo = distributed.RekeyInfo.from_pseudo_info(pseudo_info)
        self.assertIsNotNone(rekey_from_pseudo)
    
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
            initial_shares.append(system.session_key_share("session1"))
        
        client = distributed.PEPClient(self.blinded_global_key, initial_shares)
        
        # Generate new shares for session2
        new_shares = []
        for system in systems:
            new_shares.append(system.session_key_share("session2"))
        
        # Update session keys one by one
        for i in range(3):
            client.update_session_secret_key(initial_shares[i], new_shares[i])
        
        # Client should now work with session2 keys
        pseudo = high_level.Pseudonym.random()
        enc_pseudo = client.encrypt_pseudonym(pseudo)
        dec_pseudo = client.decrypt_pseudonym(enc_pseudo)
        
        self.assertEqual(pseudo.as_hex(), dec_pseudo.as_hex())


if __name__ == '__main__':
    unittest.main()