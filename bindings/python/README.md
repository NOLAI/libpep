# libpep-py: Python bindings for libpep

Python bindings for [libpep](https://github.com/NOLAI/libpep), a library for polymorphic encryption and pseudonymization implementing the *n-PEP* scheme: end-to-end encrypted, pseudonymized data sharing where semi-trusted *transcryptors* blindly re-encrypt data and convert pseudonyms between domains, with distributed trust over `n` transcryptors.

## Installation

```bash
pip install libpep-py
```

The module is importable as `libpep`:

```python
from libpep.data import Pseudonym
from libpep.keys import make_global_keys, make_session_keys
from libpep.client import encrypt, decrypt
```

See the [repository README](https://github.com/NOLAI/libpep) for the full documentation, the cryptographic background, and the papers describing the scheme.

## Development

Build and test from the repository root:

```bash
cd bindings/python
maturin develop
python -m unittest discover tests -v
python generate_stubs.py   # regenerate the type stubs after an API change
```
