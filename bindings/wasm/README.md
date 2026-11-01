# @nolai/libpep-wasm: WebAssembly bindings for libpep

WebAssembly bindings for [libpep](https://github.com/NOLAI/libpep), a library for polymorphic encryption and pseudonymization implementing the *n-PEP* scheme: end-to-end encrypted, asynchronous, pseudonymized data sharing between users, where semi-trusted *transcryptors* (no single one can read data or link pseudonyms) blindly re-encrypt data and convert pseudonyms between pseudonymization domains, with distributed trust over `n` transcryptors.

## Installation

```bash
npm install @nolai/libpep-wasm
```

The package has a Node.js and a browser build, selected through the `exports` field. The API mirrors the Rust crate with its defaults, ristretto255 and SHA-512, so there are no group or ciphersuite type parameters. This round trip converts the pseudonym of one user, a sender, into the pseudonym of another user, a receiver, for the same subject:

```javascript
import {
  EncryptionContext,
  RekeyingSecret,
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
const transcryptor = new Transcryptor("pseudonymization secret", "rekeying secret");
const rekeyingSecret = new RekeyingSecret(new TextEncoder().encode("rekeying secret"));

// User A (a sender) and user B (a receiver) each work in their own pseudonymization domain and
// encryption context, with session keys for it.
const domainA = new PseudonymizationDomain("hospital");
const sessionA = new EncryptionContext("session-a");
const domainB = new PseudonymizationDomain("research");
const sessionB = new EncryptionContext("session-b");
const keysA = makeSessionKeys(globalKeys.secret, sessionA, rekeyingSecret);
const keysB = makeSessionKeys(globalKeys.secret, sessionB, rekeyingSecret);

// A encrypts one of its pseudonyms for its own encryption context.
const pseudonymA = Pseudonym.random();
const encrypted = encryptPseudonym(pseudonymA, keysA.pseudonym.public);

// The transcryptor converts it to B's domain and encryption context, without decrypting it.
const info = transcryptor.transcryptionInfo(domainA, domainB, sessionA, sessionB);
const transcrypted = transcryptPseudonym(encrypted, info, keysA.pseudonym.public);

// B decrypts its own pseudonym for the same subject, which is unlinkable to A's.
const pseudonymB = decryptPseudonym(transcrypted, keysB.pseudonym.secret);
if (pseudonymA.toHex() === pseudonymB.toHex()) throw new Error("pseudonyms should differ");

// Transcryption is reversible.
const back = transcryptPseudonym(transcrypted, info.reverse(), keysB.pseudonym.public);
if (decryptPseudonym(back, keysA.pseudonym.secret).toHex() !== pseudonymA.toHex()) throw new Error("not reversible");
```

See the [repository README](https://github.com/NOLAI/libpep) for the cryptographic background and the references.

## Development

Build and test:

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

Apache License 2.0. Authors: Bernard van Gastel and Job Doesburg.
