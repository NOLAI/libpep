#!/usr/bin/env python3
"""
Python integration tests for the protocol context, hashing and encodings.
"""

import unittest

from libpep.contexts import EncryptionContext, PseudonymizationDomain
from libpep.elgamal.arithmetic.group_elements import GroupElement
from libpep.elgamal.arithmetic.hashing import (
    expand_message_xmd_sha512,
    hash_to_group as hash_to_group_with_dst,
    hash_to_scalar,
)
from libpep.encodings import decode_lizard, encode_lizard, hash_to_group
from libpep.factors import EncryptionSecret, PseudonymizationSecret, TranscryptionInfo
from libpep.keys import make_global_keys, make_session_keys
from libpep.protocol import Context, Mode
from libpep.transcryptor import Transcryptor


class TestContext(unittest.TestCase):
    def test_default_context_string(self):
        ctx = Context()
        self.assertEqual(ctx, Context.default())
        self.assertEqual(ctx.mode, Mode.CoPRF)
        self.assertEqual(ctx.identifier, b"ristretto255-SHA512")
        self.assertEqual(ctx.context_string(), b"coPRFV1-\x00-ristretto255-SHA512")

    def test_custom_context(self):
        ctx = Context("my-deployment", Mode.VcoPRF)
        self.assertEqual(ctx.context_string(), b"coPRFV1-\x01-my-deployment")
        self.assertEqual(Context(b"my-deployment", Mode.VcoPRF), ctx)
        self.assertNotEqual(Context("my-deployment"), ctx)
        self.assertEqual(len({ctx, Context("my-deployment", Mode.VcoPRF)}), 1)

    def test_transcryptor_takes_no_context(self):
        # The protocol context is a property of the ciphersuite, so a transcryptor is built
        # from its secrets alone.
        session_a, session_b = EncryptionContext("session-a"), EncryptionContext("session-b")
        self.assertEqual(
            Transcryptor("p", "e").pseudonym_rekey_info(session_a, session_b).k.scalar().to_hex(),
            Transcryptor("p", "e").pseudonym_rekey_info(session_a, session_b).k.scalar().to_hex(),
        )


class TestHashing(unittest.TestCase):
    def test_expand_message_xmd_rfc9380_vector(self):
        dst = b"QUUX-V01-CS02-with-expander-SHA512-256"
        self.assertEqual(
            expand_message_xmd_sha512(b"", dst, 32).hex(),
            "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba",
        )
        self.assertEqual(
            expand_message_xmd_sha512(b"abc", dst, 32).hex(),
            "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc",
        )
        with self.assertRaises(ValueError):
            expand_message_xmd_sha512(b"", dst, 65536)

    def test_hash_to_group_uses_context_dst(self):
        ctx = Context("my-deployment")
        dst = b"HashToGroup-" + ctx.context_string()
        self.assertEqual(hash_to_group(b"patient-1", ctx), hash_to_group_with_dst(b"patient-1", dst))
        self.assertEqual(hash_to_group(b"patient-1"), hash_to_group(b"patient-1", Context()))
        self.assertNotEqual(hash_to_group(b"patient-1"), hash_to_group(b"patient-1", ctx))
        self.assertNotEqual(hash_to_group(b"patient-1"), hash_to_group(b"patient-2"))
        self.assertIsInstance(hash_to_group(b"patient-1"), GroupElement)

    def test_hash_to_scalar_is_deterministic_and_separated(self):
        a = hash_to_scalar(b"msg", b"dst-a")
        self.assertEqual(a, hash_to_scalar(b"msg", b"dst-a"))
        self.assertNotEqual(a, hash_to_scalar(b"msg", b"dst-b"))


class TestEncodings(unittest.TestCase):
    def test_lizard_round_trip(self):
        data = bytes(range(16))
        element = encode_lizard(data)
        self.assertEqual(decode_lizard(element), data)
        self.assertEqual(element, GroupElement.from_lizard(data))
        self.assertIsNone(decode_lizard(GroupElement.random()))
        with self.assertRaises(ValueError):
            encode_lizard(b"too short")


class TestSeparation(unittest.TestCase):
    def test_secrets_domains_and_sessions_separate_factors_and_keys(self):
        # Factor derivation takes no protocol context: the secret is part of its hash input,
        # so different secrets already give unrelated factors, and the domain and the session
        # separate within a deployment.
        _, global_secret = make_global_keys()
        enc_secret = EncryptionSecret(b"encryption secret")
        pseudo_secret = PseudonymizationSecret(b"pseudonymization secret")
        other_enc = EncryptionSecret(b"other encryption secret")
        other_pseudo = PseudonymizationSecret(b"other pseudonymization secret")
        session_a = EncryptionContext("session-a")
        session_b = EncryptionContext("session-b")
        domain_a = PseudonymizationDomain("hospital")
        domain_b = PseudonymizationDomain("research")

        keys = make_session_keys(global_secret, session_a, enc_secret)
        info = TranscryptionInfo(domain_a, domain_b, session_a, session_b, pseudo_secret, enc_secret)

        # Deterministic in the secrets, the domains and the sessions.
        self.assertEqual(
            keys.pseudonym.public.to_hex(),
            make_session_keys(global_secret, session_a, enc_secret).pseudonym.public.to_hex(),
        )
        self.assertEqual(
            info.pseudonym.s.scalar().to_hex(),
            TranscryptionInfo(domain_a, domain_b, session_a, session_b, pseudo_secret, enc_secret).pseudonym.s.scalar().to_hex(),
        )

        # A different secret separates.
        self.assertNotEqual(
            keys.pseudonym.public.to_hex(),
            make_session_keys(global_secret, session_a, other_enc).pseudonym.public.to_hex(),
        )
        self.assertNotEqual(
            info.pseudonym.s.scalar().to_hex(),
            TranscryptionInfo(domain_a, domain_b, session_a, session_b, other_pseudo, other_enc).pseudonym.s.scalar().to_hex(),
        )

        # A different session or domain separates.
        self.assertNotEqual(
            keys.pseudonym.public.to_hex(),
            make_session_keys(global_secret, session_b, enc_secret).pseudonym.public.to_hex(),
        )
        self.assertNotEqual(
            info.pseudonym.s.scalar().to_hex(),
            TranscryptionInfo(domain_a, PseudonymizationDomain("other"), session_a, session_b, pseudo_secret, enc_secret).pseudonym.s.scalar().to_hex(),
        )


if __name__ == "__main__":
    unittest.main()
