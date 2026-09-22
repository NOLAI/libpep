"""The wire formats of draft-doesburg-cfrg-coprf: batch requests and responses as bytes."""

import unittest

from libpep.client import Client
from libpep.contexts import EncryptionContext, PseudonymizationDomain
from libpep.data import Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym
from libpep.elgamal import ElGamal
from libpep.elgamal.arithmetic.group_elements import GroupElement
from libpep.keys import SessionKeyShares, make_distributed_global_keys
from libpep.transcryptor import DistributedTranscryptor, Transcryptor
from libpep.wire import BatchKind, BatchRequest, BatchResponse


class TestWire(unittest.TestCase):
    def setUp(self):
        n = 3
        _, self.blinded, factors = make_distributed_global_keys(n)
        self.systems = [
            DistributedTranscryptor(f"ps-{i}", f"es-{i}", factors[i]) for i in range(n)
        ]
        self.session_a = EncryptionContext("session-a")
        self.session_b = EncryptionContext("session-b")

        def shares(session):
            # Shares travel to the clients as bytes.
            return [
                SessionKeyShares.from_bytes(s.session_key_shares(session).to_bytes())
                for s in self.systems
            ]

        self.sender = Client(self.blinded, shares(self.session_a))
        self.receiver = Client(self.blinded, shares(self.session_b))

    def chain(self, request):
        data = request.to_bytes()
        response = None
        for system in self.systems:
            req = BatchRequest.from_bytes(data)
            response = BatchResponse.from_bytes(system.transcrypt_wire(req).to_bytes())
            data = BatchRequest(
                req.kind, req.d_from, req.d_to, req.c_from, req.c_to, response.y_to, response.items
            ).to_bytes()
        return response

    def test_pseudonym_batch_through_three_transcryptors(self):
        pseudonyms = [Pseudonym.random() for _ in range(4)]
        encrypted = [self.sender.encrypt(p) for p in pseudonyms]
        request = BatchRequest(
            BatchKind.Pseudonym,
            "domain-a",
            b"domain-b",
            "session-a",
            "session-b",
            self.sender.dump().pseudonym.public.to_point(),
            [ElGamal.from_bytes(e.to_bytes()) for e in encrypted],
        )
        self.assertEqual(request.d_from, b"domain-a")
        self.assertEqual(request.d_to, b"domain-b")
        self.assertEqual(len(request), 4)

        response = self.chain(request)
        self.assertEqual(response.y_to, self.receiver.dump().pseudonym.public.to_point())

        got = {
            self.receiver.decrypt(EncryptedPseudonym(item)).to_hex() for item in response.items
        }
        expected = set()
        for e in encrypted:
            acc, key = e, self.sender.dump().pseudonym.public
            for system in self.systems:
                info = system.pseudonymization_info(
                    PseudonymizationDomain("domain-a"),
                    PseudonymizationDomain("domain-b"),
                    self.session_a,
                    self.session_b,
                )
                acc, key = system.pseudonymize(acc, info, key), info.rekey_public_key(key)
            expected.add(self.receiver.decrypt(acc).to_hex())
        self.assertEqual(got, expected)
        self.assertTrue(got.isdisjoint({p.to_hex() for p in pseudonyms}))

    def test_attribute_batch_through_three_transcryptors(self):
        attributes = [Attribute.random() for _ in range(3)]
        encrypted = [self.sender.encrypt(a) for a in attributes]
        request = BatchRequest(
            BatchKind.Attribute,
            b"",
            b"",
            b"session-a",
            b"session-b",
            self.sender.dump().attribute.public.to_point(),
            [ElGamal.from_bytes(e.to_bytes()) for e in encrypted],
        )
        response = self.chain(request)
        self.assertEqual(response.y_to, self.receiver.dump().attribute.public.to_point())
        got = {
            self.receiver.decrypt(EncryptedAttribute(item)).to_hex() for item in response.items
        }
        self.assertEqual(got, {a.to_hex() for a in attributes})
        self.assertNotEqual(
            [i.to_bytes() for i in response.items], [e.to_bytes() for e in encrypted]
        )

    def test_round_trip_and_layout(self):
        key = GroupElement.random()
        items = [ElGamal.from_bytes(self.sender.encrypt(Pseudonym.random()).to_bytes())]
        request = BatchRequest(BatchKind.Pseudonym, "a", "b", "c", "d", key, items)
        data = request.to_bytes()
        self.assertEqual(len(data), 1 + 4 * 3 + 32 + 4 + 64)
        self.assertEqual(data[0], 0x01)
        self.assertEqual(data[1:4], b"\x00\x01a")
        self.assertEqual(BatchRequest.from_bytes(data), request)

        response = BatchResponse(key, items)
        data = response.to_bytes()
        self.assertEqual(len(data), 32 + 4 + 64)
        self.assertEqual(BatchResponse.from_bytes(data), response)
        self.assertEqual(response.items, items)

    def test_rejections(self):
        key = GroupElement.random()
        items = [ElGamal.from_bytes(self.sender.encrypt(Pseudonym.random()).to_bytes())]
        data = BatchRequest(BatchKind.Attribute, "a", "b", "c", "d", key, items).to_bytes()
        with self.assertRaises(ValueError):
            BatchRequest.from_bytes(b"\x03" + data[1:])
        with self.assertRaises(ValueError):
            BatchRequest.from_bytes(data[:-1])
        with self.assertRaises(ValueError):
            BatchRequest.from_bytes(data + b"\x00")
        with self.assertRaises(ValueError):
            BatchRequest.from_bytes(data[:-68] + b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError):
            BatchRequest.from_bytes(data[:-32] + bytes(32))
        with self.assertRaises(ValueError):
            BatchRequest(BatchKind.Attribute, "a", "b", "c", "d", key, [])
        with self.assertRaises(ValueError):
            BatchResponse(key, [])
        with self.assertRaises(ValueError):
            BatchResponse.from_bytes(data[-32 - 4 - 64 :] + b"\x00")
        with self.assertRaises(TypeError):
            BatchRequest(BatchKind.Attribute, 1, "b", "c", "d", key, items)

    def test_non_utf8_identifier_is_rejected_by_the_transcryptor(self):
        key = GroupElement.random()
        items = [ElGamal.from_bytes(self.sender.encrypt(Pseudonym.random()).to_bytes())]
        request = BatchRequest(BatchKind.Pseudonym, b"\xff", "b", "c", "d", key, items)
        self.assertEqual(BatchRequest.from_bytes(request.to_bytes()).d_from, b"\xff")
        with self.assertRaises(ValueError):
            Transcryptor("ps", "es").transcrypt_wire(request)

    def test_session_key_shares_bytes(self):
        shares = self.systems[0].session_key_shares(self.session_a)
        data = shares.to_bytes()
        self.assertEqual(len(data), 64)
        self.assertEqual(data[:32], shares.pseudonym.to_bytes())
        self.assertEqual(data[32:], shares.attribute.to_bytes())
        self.assertEqual(SessionKeyShares.from_bytes(data), shares)
        with self.assertRaises(ValueError):
            SessionKeyShares.from_bytes(data[:63])
        with self.assertRaises(ValueError):
            SessionKeyShares.from_bytes(bytes(32) + data[32:])


if __name__ == "__main__":
    unittest.main()
