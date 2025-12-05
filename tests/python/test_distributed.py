#!/usr/bin/env python3
"""
Python integration tests for distributed module.
Tests distributed n-PEP systems, PEP clients, and key blinding functionality.
"""

import unittest
from libpep.arithmetic.group_elements import GroupElement
from libpep.arithmetic.scalars import ScalarNonZero
from libpep.core.data import (
    Pseudonym,
    Attribute,
    EncryptedPseudonym,
    EncryptedAttribute,
)
from libpep.core.keys import (
    make_global_keys,
    make_session_keys,
    SessionKeys,
    EncryptionSecret,
    PseudonymizationSecret,
)
from libpep.core.transcryption.contexts import (
    TranscryptionInfo,
    PseudonymizationInfo,
    AttributeRekeyInfo,
    PseudonymizationDomain,
    EncryptionContext,
)
from libpep.distributed.server.setup import (
    BlindingFactor,
    BlindedPseudonymGlobalSecretKey,
    BlindedAttributeGlobalSecretKey,
    make_blinded_global_keys,
)
from libpep.distributed.client.keys import (
    PseudonymSessionKeyShare,
    AttributeSessionKeyShare,
    SessionKeyShares,
)
from libpep.distributed.server.core import (
    PEPSystem,
)
from libpep.distributed.client.core import (
    PEPClient,
)
from libpep.distributed.client.offline import (
    OfflinePEPClient,
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

        # Test from scalar
        scalar = ScalarNonZero.random()
        bf3 = BlindingFactor(scalar)

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
        # Test encoding/decoding for pseudonym key
        encoded = self.blinded_global_keys.pseudonym.to_bytes()
        decoded = BlindedPseudonymGlobalSecretKey.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(self.blinded_global_keys.pseudonym.to_hex(), decoded.to_hex())

        # Test hex operations for pseudonym key
        hex_str = self.blinded_global_keys.pseudonym.to_hex()
        decoded_hex = BlindedPseudonymGlobalSecretKey.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.to_hex())

        # Test encoding/decoding for attribute key
        encoded_attr = self.blinded_global_keys.attribute.to_bytes()
        decoded_attr = BlindedAttributeGlobalSecretKey.from_bytes(encoded_attr)
        self.assertIsNotNone(decoded_attr)
        self.assertEqual(
            self.blinded_global_keys.attribute.to_hex(), decoded_attr.to_hex()
        )

        # Test hex operations for attribute key
        hex_str_attr = self.blinded_global_keys.attribute.to_hex()
        decoded_hex_attr = BlindedAttributeGlobalSecretKey.from_hex(hex_str_attr)
        self.assertIsNotNone(decoded_hex_attr)
        self.assertEqual(hex_str_attr, decoded_hex_attr.to_hex())

    def test_pep_system_creation(self):
        """Test PEP system creation and basic operations"""
        # Create PEP system
        pep_system = PEPSystem(
            "pseudonymization_secret", "rekeying_secret", self.blinding_factors[0]
        )

        # Test pseudonym session key share generation
        session = EncryptionContext("test_session")
        key_share = pep_system.pseudonym_session_key_share(session)

        # Should be deterministic for same inputs
        key_share2 = pep_system.pseudonym_session_key_share(session)
        self.assertEqual(key_share.to_hex(), key_share2.to_hex())

        # Different sessions should give different shares
        key_share3 = pep_system.pseudonym_session_key_share(EncryptionContext("different_session"))
        self.assertNotEqual(key_share.to_hex(), key_share3.to_hex())

    def test_pep_system_info_generation(self):
        """Test PEP system info generation"""
        pep_system = PEPSystem(
            "pseudonymization_secret", "rekeying_secret", self.blinding_factors[0]
        )

        # Test attribute rekey info generation
        attr_rekey_info = pep_system.attribute_rekey_info(
            EncryptionContext("session1"),
            EncryptionContext("session2")
        )
        self.assertIsNotNone(attr_rekey_info)

        # Test pseudonymization info generation
        pseudo_info = pep_system.pseudonymization_info(
            PseudonymizationDomain("domain1"),
            PseudonymizationDomain("domain2"),
            EncryptionContext("session1"),
            EncryptionContext("session2")
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
            system = PEPSystem(
                f"pseudo_secret_{i}", f"enc_secret_{i}", self.blinding_factors[i]
            )
            systems.append(system)

            # Generate session key shares using the convenience method
            shares = system.session_key_shares(EncryptionContext("test_session"))
            session_key_shares.append(shares)

        # Create PEP client using the standard constructor
        client = PEPClient(self.blinded_global_keys, session_key_shares)

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
            system = PEPSystem(
                f"pseudo_secret_{i}", f"enc_secret_{i}", self.blinding_factors[i]
            )
            systems.append(system)
            session_key_shares.append(system.session_key_shares(EncryptionContext("test_session")))

        # Create client using the standard constructor
        client = PEPClient(self.blinded_global_keys, session_key_shares)

        # Test pseudonym encryption/decryption
        pseudo = Pseudonym.random()
        enc_pseudo = client.encrypt_pseudonym(pseudo)
        dec_pseudo = client.decrypt_pseudonym(enc_pseudo)

        self.assertEqual(pseudo.to_hex(), dec_pseudo.to_hex())

        # Test data encryption/decryption
        data = Attribute.random()
        enc_data = client.encrypt_data(data)
        dec_data = client.decrypt_data(enc_data)

        self.assertEqual(data.to_hex(), dec_data.to_hex())

    def test_offline_pep_client(self):
        """Test offline PEP client for encryption-only operations"""
        # Create offline client using the combined global public keys
        offline_client = OfflinePEPClient(self.global_public_keys)

        # Test encryption (but can't decrypt without private key)
        pseudo = Pseudonym.random()
        enc_pseudo = offline_client.encrypt_pseudonym(pseudo)

        data = Attribute.random()
        enc_data = offline_client.encrypt_data(data)

        # These should be valid encrypted values
        self.assertIsNotNone(enc_pseudo)
        self.assertIsNotNone(enc_data)

        # Note: Global encryption can't be easily decrypted without proper key setup
        # This test verifies the encryption works
        # The offline client is meant for encryption-only scenarios

    def test_session_key_share_operations(self):
        """Test session key share encoding and operations"""
        scalar = ScalarNonZero.random()

        # Test PseudonymSessionKeyShare
        pseudo_share = PseudonymSessionKeyShare(scalar)

        # Test encoding/decoding
        encoded = pseudo_share.to_bytes()
        decoded = PseudonymSessionKeyShare.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(pseudo_share.to_hex(), decoded.to_hex())

        # Test hex operations
        hex_str = pseudo_share.to_hex()
        decoded_hex = PseudonymSessionKeyShare.from_hex(hex_str)
        self.assertIsNotNone(decoded_hex)
        self.assertEqual(hex_str, decoded_hex.to_hex())

        # Test AttributeSessionKeyShare
        attr_share = AttributeSessionKeyShare(scalar)
        encoded_attr = attr_share.to_bytes()
        decoded_attr = AttributeSessionKeyShare.from_bytes(encoded_attr)
        self.assertIsNotNone(decoded_attr)
        self.assertEqual(attr_share.to_hex(), decoded_attr.to_hex())

        # Test SessionKeyShares wrapper
        session_shares = SessionKeyShares(pseudo_share, attr_share)
        self.assertEqual(session_shares.pseudonym.to_hex(), pseudo_share.to_hex())
        self.assertEqual(session_shares.attribute.to_hex(), attr_share.to_hex())

    def test_pseudonymization_rekey_info(self):
        """Test standalone pseudonymization and rekey info creation"""
        # Test PseudonymizationInfo creation
        pseudo_info = PseudonymizationInfo(
            PseudonymizationDomain("domain1"),
            PseudonymizationDomain("domain2"),
            EncryptionContext("session1"),
            EncryptionContext("session2"),
            self.pseudo_secret,
            self.enc_secret,
        )

        # Test reverse operation
        pseudo_rev = pseudo_info.rev()
        self.assertIsNotNone(pseudo_rev)

        # Test AttributeRekeyInfo creation
        attr_rekey_info = AttributeRekeyInfo(
            EncryptionContext("session1"),
            EncryptionContext("session2"),
            self.enc_secret
        )
        rekey_rev = attr_rekey_info.rev()
        self.assertIsNotNone(rekey_rev)

    def test_session_key_update(self):
        """Test session key share update functionality"""
        # Create initial client
        systems = []
        initial_shares = []

        for i in range(3):
            system = PEPSystem(
                f"pseudo_secret_{i}", f"enc_secret_{i}", self.blinding_factors[i]
            )
            systems.append(system)
            initial_shares.append(system.session_key_shares(EncryptionContext("session1")))

        client = PEPClient(self.blinded_global_keys, initial_shares)

        # Generate new shares for session2
        new_shares = []
        for system in systems:
            new_shares.append(system.session_key_shares(EncryptionContext("session2")))

        # Update session keys one by one using the convenience method
        for i in range(3):
            client.update_session_secret_keys(initial_shares[i], new_shares[i])

        # Client should now work with session2 keys
        pseudo = Pseudonym.random()
        enc_pseudo = client.encrypt_pseudonym(pseudo)
        dec_pseudo = client.decrypt_pseudonym(enc_pseudo)

        self.assertEqual(pseudo.to_hex(), dec_pseudo.to_hex())


if __name__ == "__main__":
    unittest.main()
