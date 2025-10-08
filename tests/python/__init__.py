"""
Python integration tests for libpep.

This package contains comprehensive integration tests for the Python bindings
of libpep, covering all modules:

- test_arithmetic: Basic arithmetic operations (GroupElement, ScalarNonZero, ScalarCanBeZero)
- test_elgamal: ElGamal encryption and decryption
- test_primitives: PEP primitives (rekey, reshuffle, rsk operations)
- test_high_level: High-level API (Pseudonym, Attribute, session management)
- test_distributed: Distributed n-PEP systems (PEPSystem, PEPClient, key blinding)

Run all tests with:
    python -m unittest discover tests/python/ -v

Or with poetry:
    poetry run python -m unittest discover tests/python/ -v
"""