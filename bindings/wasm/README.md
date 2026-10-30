# @nolai/libpep-wasm: WebAssembly bindings for libpep

WebAssembly bindings for [libpep](https://github.com/NOLAI/libpep), a library for polymorphic encryption and pseudonymization implementing the *n-PEP* scheme: end-to-end encrypted, pseudonymized data sharing where semi-trusted *transcryptors* blindly re-encrypt data and convert pseudonyms between domains, with distributed trust over `n` transcryptors.

## Installation

```bash
npm install @nolai/libpep-wasm
```

The package ships both a Node.js and a browser build, selected automatically through the `exports` field. The API mirrors the Rust crate, instantiated for ristretto255, so there are no group type parameters. A complete round trip, from one party's pseudonym to another party's pseudonym for the same subject:

```javascript
import {
  EncryptionContext,
  EncryptionSecret,
  Pseudonym,
  PseudonymizationDomain,
  Transcryptor,
  decryptPseudonym,
  encryptPseudonym,
  makeGlobalKeys,
  makeSessionKeys,
  transcryptPseudonym,
} from "@nolai/libpep-wasm";

// System setup: global keys and the secrets of the transcryptor.
const globalKeys = makeGlobalKeys();
const transcryptor = new Transcryptor("pseudonymization secret", "encryption secret");
const encryptionSecret = new EncryptionSecret(new TextEncoder().encode("encryption secret"));

// Parties A and B each have a pseudonymization domain, an encryption context and session keys.
const domainA = new PseudonymizationDomain("hospital");
const sessionA = new EncryptionContext("session-a");
const domainB = new PseudonymizationDomain("research");
const sessionB = new EncryptionContext("session-b");
const keysA = makeSessionKeys(globalKeys.secret, sessionA, encryptionSecret);
const keysB = makeSessionKeys(globalKeys.secret, sessionB, encryptionSecret);

// A encrypts one of its pseudonyms for its own session.
const pseudonymA = Pseudonym.random();
const encrypted = encryptPseudonym(pseudonymA, keysA.pseudonym.public);

// The transcryptor converts it to B's domain and session, without decrypting it.
const info = transcryptor.transcryptionInfo(domainA, domainB, sessionA, sessionB);
const transcrypted = transcryptPseudonym(encrypted, info, keysA.pseudonym.public);

// B decrypts its own pseudonym for the same subject, which is unlinkable to A's.
const pseudonymB = decryptPseudonym(transcrypted, keysB.pseudonym.secret);
if (pseudonymA.toHex() === pseudonymB.toHex()) throw new Error("pseudonyms should differ");

// Transcryption is reversible.
const back = transcryptPseudonym(transcrypted, info.reverse(), keysB.pseudonym.public);
if (decryptPseudonym(back, keysA.pseudonym.secret).toHex() !== pseudonymA.toHex()) throw new Error("not reversible");
```

See the [repository README](https://github.com/NOLAI/libpep) for the full documentation, the cryptographic background, and the papers describing the scheme.

## Development

Build and test from this crate directory:

```bash
cd bindings/wasm
npm install
npm test
```

To build for a specific target:

```bash
npm run build:nodejs  # Node.js, into pkg/
npm run build:web     # browsers, into pkg-web/
npm run build         # bundler + web, for publishing
```

## License
- Authors: Bernard van Gastel and Job Doesburg
- License: Apache License 2.0
