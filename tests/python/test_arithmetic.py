#!/usr/bin/env python3
"""
Python integration tests for arithmetic module.
Tests basic arithmetic operations on group elements and scalars.
"""

import unittest
import libpep
arithmetic = libpep.arithmetic


class TestArithmetic(unittest.TestCase):
    
    def test_group_element_arithmetic(self):
        """Test GroupElement arithmetic operations"""
        a = arithmetic.GroupElement.from_hex("503f0bbed01007ad413d665131c48c4f92ad506704305873a2128f29430c2674")
        b = arithmetic.GroupElement.from_hex("ceab6438bae4a0b5662afa5776029d60f1f2aa5440cf966bc4592fae088c5639")
        
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        
        c = a.add(b)
        d = a.sub(b)
        
        self.assertEqual(c.as_hex(), "d4d8ae736b598e2e22754f5ef7a8c26dba41a7e934ad76170d5a1419bd42730a")
        self.assertEqual(d.as_hex(), "c008e64b609452d0a314365f76ff0b68d634f094ce3fa0a9f309e80696ab6f67")
    
    def test_group_element_operators(self):
        """Test GroupElement Python operator overloads"""
        a = arithmetic.GroupElement.random()
        b = arithmetic.GroupElement.random()
        
        # Test __add__ and __sub__
        c = a + b
        d = a - b
        
        # Should be same as explicit method calls
        self.assertEqual(c.as_hex(), a.add(b).as_hex())
        self.assertEqual(d.as_hex(), a.sub(b).as_hex())
        
        # Test identity
        identity = arithmetic.GroupElement.identity()
        self.assertEqual((a + identity).as_hex(), a.as_hex())
        self.assertEqual((a - identity).as_hex(), a.as_hex())
    
    def test_scalar_arithmetic(self):
        """Test ScalarNonZero arithmetic operations"""
        a = arithmetic.ScalarNonZero.from_hex("044214715d782745a36ededee498b31d882f5e6239db9f9443f6bfef04944906")
        b = arithmetic.ScalarNonZero.from_hex("d8efcc0acb2b9cd29c698ab4a77d5139e3ce3c61ad5dc060db0820ab0c90470b")
        c = arithmetic.GroupElement.from_hex("1818ef438e7856d71c46f6a486f3b6dbb67b6d0573c897bcdb9c8fe662928754")
        
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertIsNotNone(c)
        
        d = a.mul(b)
        e = a.invert()
        f = c.mul(a)  # Group element * scalar
        
        self.assertEqual(d.as_hex(), "70b1f2f67d2da167185b133cc1d5157d23bf43741aced485d42e0c791e1d3305")
        self.assertEqual(e.as_hex(), "6690b6c6f8571e72fe98fa368923c23f090d720419562451d20fa1e4ab556c01")
        self.assertEqual(f.as_hex(), "56bf55ebfd2fcb7bfc7cbe1208a95d6f5aa3f4842c5b2828375a75c4b78b3126")
    
    def test_scalar_can_be_zero(self):
        """Test ScalarCanBeZero operations"""
        g = arithmetic.ScalarCanBeZero.zero()
        self.assertIsNone(g.to_non_zero())
        
        # Test that zero hex returns None for ScalarNonZero
        h = arithmetic.ScalarNonZero.from_hex("0000000000000000000000000000000000000000000000000000000000000000")
        self.assertIsNone(h)
        
        i = arithmetic.ScalarCanBeZero.from_hex("ca1f7e593ba0c53440e3c6437784e5fbe7306d9686013e5978c4c2d89bc0b109")
        j = arithmetic.ScalarCanBeZero.from_hex("d921b0febd39e59148ca5c35d157227667a7e8cd6d3b0fbbc973e0e54cb4390c")
        
        self.assertIsNotNone(i)
        self.assertIsNotNone(j)
        
        k = i.add(j)
        l = i.sub(j)
        
        self.assertEqual(k.as_hex(), "b66d38fbde76986eb2102cd669e2285d4fd85564f43c4d144238a3bee874eb05")
        self.assertEqual(l.as_hex(), "ded1c3b797c9f2facdb561b18426a29a808984c818c62e9eae50e2f24e0c780d")
    
    def test_scalar_can_be_zero_operators(self):
        """Test ScalarCanBeZero Python operator overloads"""
        a = arithmetic.ScalarCanBeZero.one()
        b = arithmetic.ScalarCanBeZero.zero()
        
        # Test __add__ and __sub__
        c = a + b
        d = a - b
        
        self.assertEqual(c.as_hex(), a.add(b).as_hex())
        self.assertEqual(d.as_hex(), a.sub(b).as_hex())
        
        # Test that adding zero doesn't change value
        self.assertEqual((a + b).as_hex(), a.as_hex())
        self.assertEqual((a - b).as_hex(), a.as_hex())
    
    def test_encoding_decoding(self):
        """Test encode/decode operations"""
        # Test GroupElement
        g = arithmetic.GroupElement.random()
        encoded = g.encode()
        decoded = arithmetic.GroupElement.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(g.as_hex(), decoded.as_hex())
        
        # Test ScalarNonZero
        s = arithmetic.ScalarNonZero.random()
        encoded = s.encode()
        decoded = arithmetic.ScalarNonZero.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(s.as_hex(), decoded.as_hex())
        
        # Test ScalarCanBeZero
        sc = arithmetic.ScalarCanBeZero.one()
        encoded = sc.encode()
        decoded = arithmetic.ScalarCanBeZero.decode(encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(sc.as_hex(), decoded.as_hex())
    
    def test_conversions(self):
        """Test type conversions"""
        # ScalarNonZero to ScalarCanBeZero
        s_nz = arithmetic.ScalarNonZero.random()
        s_cbz = s_nz.to_can_be_zero()
        self.assertEqual(s_nz.as_hex(), s_cbz.as_hex())
        
        # ScalarCanBeZero to ScalarNonZero (non-zero case)
        s_cbz_one = arithmetic.ScalarCanBeZero.one()
        s_nz_converted = s_cbz_one.to_non_zero()
        self.assertIsNotNone(s_nz_converted)
        self.assertEqual(s_cbz_one.as_hex(), s_nz_converted.as_hex())
        
        # ScalarCanBeZero to ScalarNonZero (zero case)
        s_cbz_zero = arithmetic.ScalarCanBeZero.zero()
        s_nz_none = s_cbz_zero.to_non_zero()
        self.assertIsNone(s_nz_none)
    
    def test_generators_and_constants(self):
        """Test generator and constant values"""
        g = arithmetic.GroupElement.generator()
        g2 = arithmetic.GroupElement.generator()
        self.assertEqual(g.as_hex(), g2.as_hex())
        
        identity = arithmetic.GroupElement.identity()
        one = arithmetic.ScalarNonZero.one()
        
        # G * 1 should equal G
        result = g.mul(one)
        self.assertEqual(g.as_hex(), result.as_hex())
        
        # G + identity should equal G
        result2 = g.add(identity)
        self.assertEqual(g.as_hex(), result2.as_hex())


if __name__ == '__main__':
    unittest.main()