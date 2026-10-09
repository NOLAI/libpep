#!/usr/bin/env python3
"""A key operation accepts the one key it needs or a bundle to take it from.

The *data's* type selects which half of the bundle is used, so a pseudonym is never encrypted,
decrypted or transcrypted under the attribute key. These tests pin that: the bundle form must
agree with the specific-key form, and the wrong specific key must still be rejected.
"""

import unittest

from libpep.client import decrypt, encrypt
from libpep.contexts import EncryptionContext, PseudonymizationDomain
from libpep.data import Attribute, Pseudonym
from libpep.factors import (
    EncryptionSecret,
    PseudonymizationInfo,
    PseudonymizationSecret,
)
from libpep.keys import make_global_keys, make_session_keys
from libpep.transcryptor import pseudonymize


class TestKeyBundles(unittest.TestCase):
    def setUp(self):
        global_keys = make_global_keys()
        self.pseudo_secret = PseudonymizationSecret(b"pseudo-secret")
        self.enc_secret = EncryptionSecret(b"encryption-secret")
        self.session = EncryptionContext("session-a")
        self.keys = make_session_keys(global_keys[1], self.session, self.enc_secret)

    def test_the_two_halves_are_different_keys(self):
        """The premise: selecting the wrong half would be observable."""
        self.assertNotEqual(
            self.keys.pseudonym.public.to_bytes(),
            self.keys.attribute.public.to_bytes(),
        )

    def test_pseudonym_round_trip_through_the_bundle(self):
        pseudonym = Pseudonym.random()
        encrypted = encrypt(pseudonym, self.keys.public())
        self.assertEqual(decrypt(encrypted, self.keys), pseudonym)

    def test_attribute_round_trip_through_the_bundle(self):
        attribute = Attribute.random()
        encrypted = encrypt(attribute, self.keys.public())
        self.assertEqual(decrypt(encrypted, self.keys), attribute)

    def test_the_specific_key_still_works(self):
        pseudonym = Pseudonym.random()
        encrypted = encrypt(pseudonym, self.keys.pseudonym.public)
        self.assertEqual(decrypt(encrypted, self.keys.pseudonym.secret), pseudonym)

    def test_session_keys_also_accepted_where_a_public_key_is_wanted(self):
        """Matching the existing `session()` precedent, which ignores the secret halves."""
        pseudonym = Pseudonym.random()
        encrypted = encrypt(pseudonym, self.keys)
        self.assertEqual(decrypt(encrypted, self.keys), pseudonym)

    def test_the_wrong_specific_key_is_rejected_for_encryption(self):
        pseudonym = Pseudonym.random()
        with self.assertRaises(TypeError):
            encrypt(pseudonym, self.keys.attribute.public)

    def test_the_wrong_specific_key_is_rejected_for_decryption(self):
        pseudonym = Pseudonym.random()
        encrypted = encrypt(pseudonym, self.keys.public())
        with self.assertRaises(TypeError):
            decrypt(encrypted, self.keys.attribute.secret)

    def test_transcryption_accepts_the_bundle(self):
        pseudonym = Pseudonym.random()
        encrypted = encrypt(pseudonym, self.keys.public())
        session_b = EncryptionContext("session-b")
        info = PseudonymizationInfo(
            PseudonymizationDomain("clinic-a"),
            PseudonymizationDomain("clinic-b"),
            self.session,
            session_b,
            self.pseudo_secret,
            self.enc_secret,
        )
        # Both forms are accepted where the current public key is needed, and both yield a
        # ciphertext that still decrypts to A's pseudonym when converted straight back.
        reverse = info.reverse()
        # The key B's ciphertext is under, which the reverse step needs.
        key_b = info.rekey_public_key(self.keys.pseudonym.public)
        for key in (self.keys.pseudonym.public, self.keys.public(), self.keys):
            transcrypted = pseudonymize(encrypted, info, key)
            back = pseudonymize(transcrypted, reverse, key_b)
            self.assertEqual(decrypt(back, self.keys), pseudonym)

    def test_transcryption_rejects_the_wrong_specific_key(self):
        pseudonym = Pseudonym.random()
        encrypted = encrypt(pseudonym, self.keys.public())
        session_b = EncryptionContext("session-b")
        info = PseudonymizationInfo(
            PseudonymizationDomain("clinic-a"),
            PseudonymizationDomain("clinic-b"),
            self.session,
            session_b,
            self.pseudo_secret,
            self.enc_secret,
        )
        with self.assertRaises(TypeError):
            pseudonymize(encrypted, info, self.keys.attribute.public)


if __name__ == "__main__":
    unittest.main()
