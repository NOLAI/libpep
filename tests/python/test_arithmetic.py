#!/usr/bin/env python3
"""
Python integration tests for arithmetic module.
Tests basic arithmetic operations on group elements and scalars.
"""

import unittest
from libpep.arithmetic.group_elements import GroupElement
from libpep.arithmetic.scalars import ScalarNonZero, ScalarCanBeZero


class TestArithmetic(unittest.TestCase):
    def test_group_element_arithmetic(self):
        """Test GroupElement arithmetic operations"""
        a = GroupElement.from_hex(
            "503f0bbed01007ad413d665131c48c4f92ad506704305873a2128f29430c2674"
        )
        b = GroupElement.from_hex(
            "ceab6438bae4a0b5662afa5776029d60f1f2aa5440cf966bc4592fae088c5639"
        )

        self.assertIsNotNone(a)
        self.assertIsNotNone(b)

        c = a.add(b)
        d = a.sub(b)

        self.assertEqual(
            c.to_hex(),
            "d4d8ae736b598e2e22754f5ef7a8c26dba41a7e934ad76170d5a1419bd42730a",
        )
        self.assertEqual(
            d.to_hex(),
            "c008e64b609452d0a314365f76ff0b68d634f094ce3fa0a9f309e80696ab6f67",
        )

    def test_group_element_operators(self):
        """Test GroupElement Python operator overloads"""
        a = GroupElement.random()
        b = GroupElement.random()

        # Test __add__ and __sub__
        c = a + b
        d = a - b

        # Should be same as explicit method calls
        self.assertEqual(c.to_hex(), a.add(b).to_hex())
        self.assertEqual(d.to_hex(), a.sub(b).to_hex())

        # Test identity
        identity = GroupElement.identity()
        self.assertEqual((a + identity).to_hex(), a.to_hex())
        self.assertEqual((a - identity).to_hex(), a.to_hex())

    def test_scalar_arithmetic(self):
        """Test ScalarNonZero arithmetic operations"""
        a = ScalarNonZero.from_hex(
            "044214715d782745a36ededee498b31d882f5e6239db9f9443f6bfef04944906"
        )
        b = ScalarNonZero.from_hex(
            "d8efcc0acb2b9cd29c698ab4a77d5139e3ce3c61ad5dc060db0820ab0c90470b"
        )
        c = GroupElement.from_hex(
            "1818ef438e7856d71c46f6a486f3b6dbb67b6d0573c897bcdb9c8fe662928754"
        )

        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertIsNotNone(c)

        d = a.mul(b)
        e = a.invert()
        f = c.mul(a)  # Group element * scalar

        self.assertEqual(
            d.to_hex(),
            "70b1f2f67d2da167185b133cc1d5157d23bf43741aced485d42e0c791e1d3305",
        )
        self.assertEqual(
            e.to_hex(),
            "6690b6c6f8571e72fe98fa368923c23f090d720419562451d20fa1e4ab556c01",
        )
        self.assertEqual(
            f.to_hex(),
            "56bf55ebfd2fcb7bfc7cbe1208a95d6f5aa3f4842c5b2828375a75c4b78b3126",
        )

    def test_scalar_can_be_zero(self):
        """Test ScalarCanBeZero operations"""
        g = ScalarCanBeZero.zero()
        self.assertIsNone(g.to_non_zero())

        # Test that zero hex returns None for ScalarNonZero
        h = ScalarNonZero.from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        self.assertIsNone(h)

        i = ScalarCanBeZero.from_hex(
            "ca1f7e593ba0c53440e3c6437784e5fbe7306d9686013e5978c4c2d89bc0b109"
        )
        j = ScalarCanBeZero.from_hex(
            "d921b0febd39e59148ca5c35d157227667a7e8cd6d3b0fbbc973e0e54cb4390c"
        )

        self.assertIsNotNone(i)
        self.assertIsNotNone(j)

        k = i.add(j)
        l = i.sub(j)

        self.assertEqual(
            k.to_hex(),
            "b66d38fbde76986eb2102cd669e2285d4fd85564f43c4d144238a3bee874eb05",
        )
        self.assertEqual(
            l.to_hex(),
            "ded1c3b797c9f2facdb561b18426a29a808984c818c62e9eae50e2f24e0c780d",
        )

    def test_scalar_can_be_zero_operators(self):
        """Test ScalarCanBeZero Python operator overloads"""
        a = ScalarCanBeZero.one()
        b = ScalarCanBeZero.zero()

        # Test __add__ and __sub__
        c = a + b
        d = a - b

        self.assertEqual(c.to_hex(), a.add(b).to_hex())
        self.assertEqual(d.to_hex(), a.sub(b).to_hex())

        # Test that adding zero doesn't change value
        self.assertEqual((a + b).to_hex(), a.to_hex())
        self.assertEqual((a - b).to_hex(), a.to_hex())

    def test_encoding_decoding(self):
        """Test encode/decode operations"""
        # Test GroupElement
        g = GroupElement.random()
        encoded = g.to_bytes()
        decoded = GroupElement.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(g.to_hex(), decoded.to_hex())

        # Test ScalarNonZero
        s = ScalarNonZero.random()
        encoded = s.to_bytes()
        decoded = ScalarNonZero.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(s.to_hex(), decoded.to_hex())

        # Test ScalarCanBeZero
        sc = ScalarCanBeZero.one()
        encoded = sc.to_bytes()
        decoded = ScalarCanBeZero.from_bytes(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(sc.to_hex(), decoded.to_hex())

    def test_conversions(self):
        """Test type conversions"""
        # ScalarNonZero to ScalarCanBeZero
        s_nz = ScalarNonZero.random()
        s_cbz = s_nz.to_can_be_zero()
        self.assertEqual(s_nz.to_hex(), s_cbz.to_hex())

        # ScalarCanBeZero to ScalarNonZero (non-zero case)
        s_cbz_one = ScalarCanBeZero.one()
        s_nz_converted = s_cbz_one.to_non_zero()
        self.assertIsNotNone(s_nz_converted)
        self.assertEqual(s_cbz_one.to_hex(), s_nz_converted.to_hex())

        # ScalarCanBeZero to ScalarNonZero (zero case)
        s_cbz_zero = ScalarCanBeZero.zero()
        s_nz_none = s_cbz_zero.to_non_zero()
        self.assertIsNone(s_nz_none)

    def test_generators_and_constants(self):
        """Test generator and constant values"""
        g = GroupElement.generator()
        g2 = GroupElement.generator()
        self.assertEqual(g.to_hex(), g2.to_hex())

        identity = GroupElement.identity()
        one = ScalarNonZero.one()

        # G * 1 should equal G
        result = g.mul(one)
        self.assertEqual(g.to_hex(), result.to_hex())

        # G + identity should equal G
        result2 = g.add(identity)
        self.assertEqual(g.to_hex(), result2.to_hex())


if __name__ == "__main__":
    unittest.main()
