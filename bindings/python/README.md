# libpep-py: Python bindings for libpep

Python bindings for [libpep](https://github.com/NOLAI/libpep), a library for polymorphic encryption and pseudonymization implementing the *n-PEP* scheme: end-to-end encrypted, pseudonymized data sharing where semi-trusted *transcryptors* blindly re-encrypt data and convert pseudonyms between domains, with distributed trust over `n` transcryptors.

## Installation

```bash
pip install libpep-py
```

The module is importable as `libpep`. The API mirrors the Rust crate, fixed to ristretto255 with SHA-512, the default of the crate's generic types, so there are no group or ciphersuite type parameters. A complete round trip, from one party's pseudonym to another party's pseudonym for the same subject:

```python
from libpep.client import decrypt, encrypt
from libpep.contexts import EncryptionContext, PseudonymizationDomain
from libpep.data import Pseudonym
from libpep.factors import EncryptionSecret
from libpep.keys import make_global_keys, make_session_keys
from libpep.transcryptor import Transcryptor

# System setup: global keys and the secrets of the transcryptor.
global_public, global_secret = make_global_keys()
transcryptor = Transcryptor("pseudonymization secret", "encryption secret")

# Parties A and B each have a pseudonymization domain, an encryption context and session keys.
domain_a, session_a = PseudonymizationDomain("hospital"), EncryptionContext("session-a")
domain_b, session_b = PseudonymizationDomain("research"), EncryptionContext("session-b")
keys_a = make_session_keys(global_secret, session_a, EncryptionSecret(b"encryption secret"))
keys_b = make_session_keys(global_secret, session_b, EncryptionSecret(b"encryption secret"))

# A encrypts one of its pseudonyms for its own session.
pseudonym_a = Pseudonym.random()
encrypted = encrypt(pseudonym_a, keys_a.public())

# The transcryptor converts it to B's domain and session, without decrypting it.
info = transcryptor.transcryption_info(domain_a, domain_b, session_a, session_b)
transcrypted = transcryptor.transcrypt(encrypted, info, keys_a.public())

# B decrypts its own pseudonym for the same subject, which is unlinkable to A's.
pseudonym_b = decrypt(transcrypted, keys_b)
assert pseudonym_a.to_hex() != pseudonym_b.to_hex()

# Transcryption is reversible.
back = transcryptor.transcrypt(transcrypted, info.reverse(), keys_b.public())
assert decrypt(back, keys_a).to_hex() == pseudonym_a.to_hex()
```

Keys are passed either as the one key an operation needs or as a bundle: `keys_a.public()` for the session's public keys, `keys_a` itself where a secret key is needed. The type of the data selects the right half of the bundle.

See the [repository README](https://github.com/NOLAI/libpep) for the cryptographic background and the papers describing the scheme.

## Development

Build and test from the repository root:

```bash
cd bindings/python
maturin develop
python -m unittest discover tests -v
python generate_stubs.py   # regenerate the type stubs after an API change
```
