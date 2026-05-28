// JS integration tests for verifiable transcryption.
//
// Mirrors the Rust integration tests in `tests/verifiable.rs` 1:1 so the JS
// and Rust APIs read the same; each test below corresponds to a same-named
// Rust test. Proofs are passed as JSON strings on the WASM boundary (the
// `verifiable*` methods on `Transcryptor` return JSON, the `verify*` methods
// on `Verifier` accept JSON).

const {
    Attribute,
    Pseudonym,
    PseudonymizationDomain,
    EncryptionContext,
    PseudonymizationSecret,
    EncryptionSecret,
    Transcryptor,
    Verifier,
    encryptPseudonym,
    encryptAttribute,
    decryptPseudonym,
    decryptAttribute,
    makePseudonymGlobalKeys,
    makeAttributeGlobalKeys,
    makePseudonymSessionKeys,
    makeAttributeSessionKeys,
    Client,
    DistributedTranscryptor,
    EncryptedPseudonymBatch,
    PseudonymPseudonymizationBatchProof,
    makeDistributedGlobalKeys,
} = require("../../pkg/libpep.js");

// Detect whether the WASM build was compiled with `batch-pk`. With `batch-pk`,
// `new EncryptedPseudonymBatch(items, pk)` requires a public key argument and
// `verifiable_pseudonymize` takes only `info`. Without `batch-pk`, the
// constructor takes only items, and `verifiable_pseudonymize`/
// `verifiedReconstructBatch`/`verifyPseudonymizationBatch` need an extra
// public-key argument.
function _detectBatchPk() {
    if (typeof EncryptedPseudonymBatch === "undefined") return false;
    try {
        // eslint-disable-next-line no-new
        new EncryptedPseudonymBatch([]);
        return false;
    } catch (e) {
        return true;
    }
}
const BATCH_PK = _detectBatchPk();

const SECRET = Uint8Array.from(Buffer.from("secret"));

test('test_verifiable_pseudonymization_simple', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const domain1 = new PseudonymizationDomain("domain1");
    const domain2 = new PseudonymizationDomain("domain2");
    const session1 = new EncryptionContext("session1");
    const session2 = new EncryptionContext("session2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const pseudonymSession2Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session2, encSecret);

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, pseudonymSession1Keys.public);

    const transcryptor = new Transcryptor("secret", "secret");
    const info = transcryptor.pseudonymizationInfo(domain1, domain2, session1, session2);
    const commitments =
        transcryptor.pseudonymizationCommitment(domain1, domain2, session1, session2);

    const operationProof =
        transcryptor.verifiablePseudonymize(encPseudo, info, pseudonymSession1Keys.public);

    const verifier = new Verifier();
    const result = verifier.verifyPseudonymization(
        encPseudo, operationProof, pseudonymSession1Keys.public, commitments,
    );

    // Decrypting under the target session must succeed.
    const decrypted = decryptPseudonym(result, pseudonymSession2Keys.secret);
    expect(decrypted).toBeDefined();
});

test('test_verifiable_pseudonym_rekey', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const session1 = new EncryptionContext("session1");
    const session2 = new EncryptionContext("session2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const pseudonymSession2Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session2, encSecret);

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, pseudonymSession1Keys.public);

    const transcryptor = new Transcryptor("secret", "secret");
    const commitments = transcryptor.pseudonymRekeyCommitment(session1, session2);
    const operationProof =
        transcryptor.verifiablePseudonymRekey(encPseudo, session1, session2);

    const verifier = new Verifier();
    const result = verifier.verifyPseudonymRekey(encPseudo, operationProof, commitments);

    // Pseudonym rekey preserves the underlying value across sessions.
    const decrypted = decryptPseudonym(result, pseudonymSession2Keys.secret);
    const originalDecrypted = decryptPseudonym(encPseudo, pseudonymSession1Keys.secret);
    expect(decrypted.toHex()).toEqual(originalDecrypted.toHex());
});

test('test_verifiable_attribute_rekey', () => {
    const attributeGlobalKeys = makeAttributeGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const session1 = new EncryptionContext("session1");
    const session2 = new EncryptionContext("session2");

    const attributeSession1Keys =
        makeAttributeSessionKeys(attributeGlobalKeys.secret, session1, encSecret);
    const attributeSession2Keys =
        makeAttributeSessionKeys(attributeGlobalKeys.secret, session2, encSecret);

    const attr = Attribute.random();
    const encAttr = encryptAttribute(attr, attributeSession1Keys.public);

    const transcryptor = new Transcryptor("secret", "secret");
    const rekeyInfo = transcryptor.attributeRekeyInfo(session1, session2);
    const commitments = transcryptor.attributeRekeyCommitment(session1, session2);

    const operationProof = transcryptor.verifiableAttributeRekey(encAttr, rekeyInfo);

    const verifier = new Verifier();
    const result = verifier.verifyAttributeRekey(encAttr, operationProof, commitments);

    const decrypted = decryptAttribute(result, attributeSession2Keys.secret);
    const originalDecrypted = decryptAttribute(encAttr, attributeSession1Keys.secret);
    expect(decrypted.toHex()).toEqual(originalDecrypted.toHex());
});

test('test_verifier_cache_pseudonymization', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const domain1 = new PseudonymizationDomain("domain1");
    const domain2 = new PseudonymizationDomain("domain2");
    const domain3 = new PseudonymizationDomain("domain3");
    const session1 = new EncryptionContext("session1");
    const session2 = new EncryptionContext("session2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const info = transcryptor.pseudonymizationInfo(domain1, domain2, session1, session2);
    const commitments =
        transcryptor.pseudonymizationCommitment(domain1, domain2, session1, session2);

    const verifier = new Verifier();
    const transcryptorId = "transcryptor1";
    verifier.registerPseudonymizationCommitments(
        transcryptorId, domain1, domain2, session1, session2, commitments,
    );

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, pseudonymSession1Keys.public);
    const operationProof =
        transcryptor.verifiablePseudonymize(encPseudo, info, pseudonymSession1Keys.public);

    // Cached lookup against the registered transition succeeds.
    const result = verifier.verifyPseudonymizationCached(
        transcryptorId, encPseudo, operationProof, pseudonymSession1Keys.public,
        domain1, domain2, session1, session2,
    );
    expect(result).toBeDefined();

    // Wrong transition (different target domain) is not in the cache: throws.
    expect(() => {
        verifier.verifyPseudonymizationCached(
            transcryptorId, encPseudo, operationProof, pseudonymSession1Keys.public,
            domain1, domain3, session1, session2,
        );
    }).toThrow();

    verifier.clearCache();
    expect(verifier.cacheSize()).toBe(0);
});

test('tampered_proof_rejected_pseudonymization', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const d1 = new PseudonymizationDomain("d1");
    const d2 = new PseudonymizationDomain("d2");
    const s1 = new EncryptionContext("s1");
    const s2 = new EncryptionContext("s2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, s1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const info = transcryptor.pseudonymizationInfo(d1, d2, s1, s2);
    const commitments = transcryptor.pseudonymizationCommitment(d1, d2, s1, s2);

    const encPseudo = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);
    const proof = transcryptor.verifiablePseudonymize(encPseudo, info, pseudonymSession1Keys.public);

    // Build a second valid proof and graft one of its proof components into
    // the first proof: the result is still well-formed JSON (every Ristretto
    // point still decodes) but the per-statement binding no longer matches.
    const donorEnc = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);
    const donorProof = transcryptor.verifiablePseudonymize(
        donorEnc, info, pseudonymSession1Keys.public,
    );
    const tampered = swapFirstString(proof, donorProof);
    expect(tampered).not.toEqual(proof);

    const verifier = new Verifier();
    expect(() => {
        verifier.verifyPseudonymization(
            encPseudo, tampered, pseudonymSession1Keys.public, commitments,
        );
    }).toThrow();
});

test('wrong_original_rejected_pseudonymization', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const d1 = new PseudonymizationDomain("d1");
    const d2 = new PseudonymizationDomain("d2");
    const s1 = new EncryptionContext("s1");
    const s2 = new EncryptionContext("s2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, s1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const info = transcryptor.pseudonymizationInfo(d1, d2, s1, s2);
    const commitments = transcryptor.pseudonymizationCommitment(d1, d2, s1, s2);

    const encPseudo = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);
    const proof = transcryptor.verifiablePseudonymize(encPseudo, info, pseudonymSession1Keys.public);

    // Verify the proof against a *different* ciphertext.
    const otherEnc = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);

    const verifier = new Verifier();
    expect(() => {
        verifier.verifyPseudonymization(
            otherEnc, proof, pseudonymSession1Keys.public, commitments,
        );
    }).toThrow();
});

test('wrong_commitments_rejected_pseudonymization', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const d1 = new PseudonymizationDomain("d1");
    const d2 = new PseudonymizationDomain("d2");
    const d3 = new PseudonymizationDomain("d3");
    const s1 = new EncryptionContext("s1");
    const s2 = new EncryptionContext("s2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, s1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const info = transcryptor.pseudonymizationInfo(d1, d2, s1, s2);
    // Commitments for a *different* target domain than the proof.
    const wrongCommitments = transcryptor.pseudonymizationCommitment(d1, d3, s1, s2);

    const encPseudo = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);
    const proof = transcryptor.verifiablePseudonymize(encPseudo, info, pseudonymSession1Keys.public);

    const verifier = new Verifier();
    expect(() => {
        verifier.verifyPseudonymization(
            encPseudo, proof, pseudonymSession1Keys.public, wrongCommitments,
        );
    }).toThrow();
});

test('tampered_proof_rejected_pseudonym_rekey', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const s1 = new EncryptionContext("s1");
    const s2 = new EncryptionContext("s2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, s1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const commitments = transcryptor.pseudonymRekeyCommitment(s1, s2);

    const encPseudo = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);
    const proof = transcryptor.verifiablePseudonymRekey(encPseudo, s1, s2);

    const donorEnc = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);
    const donorProof = transcryptor.verifiablePseudonymRekey(donorEnc, s1, s2);
    const tampered = swapFirstString(proof, donorProof);
    expect(tampered).not.toEqual(proof);

    const verifier = new Verifier();
    expect(() => {
        verifier.verifyPseudonymRekey(encPseudo, tampered, commitments);
    }).toThrow();
});

test('wrong_original_rejected_pseudonym_rekey', () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const s1 = new EncryptionContext("s1");
    const s2 = new EncryptionContext("s2");

    const pseudonymSession1Keys =
        makePseudonymSessionKeys(pseudonymGlobalKeys.secret, s1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const commitments = transcryptor.pseudonymRekeyCommitment(s1, s2);

    const encPseudo = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);
    const proof = transcryptor.verifiablePseudonymRekey(encPseudo, s1, s2);

    const otherEnc = encryptPseudonym(Pseudonym.random(), pseudonymSession1Keys.public);

    const verifier = new Verifier();
    expect(() => {
        verifier.verifyPseudonymRekey(otherEnc, proof, commitments);
    }).toThrow();
});

test('tampered_proof_rejected_attribute_rekey', () => {
    const attributeGlobalKeys = makeAttributeGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const s1 = new EncryptionContext("s1");
    const s2 = new EncryptionContext("s2");

    const attributeSession1Keys =
        makeAttributeSessionKeys(attributeGlobalKeys.secret, s1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const rekeyInfo = transcryptor.attributeRekeyInfo(s1, s2);
    const commitments = transcryptor.attributeRekeyCommitment(s1, s2);

    const encAttr = encryptAttribute(Attribute.random(), attributeSession1Keys.public);
    const proof = transcryptor.verifiableAttributeRekey(encAttr, rekeyInfo);

    const donorEnc = encryptAttribute(Attribute.random(), attributeSession1Keys.public);
    const donorProof = transcryptor.verifiableAttributeRekey(donorEnc, rekeyInfo);
    const tampered = swapFirstString(proof, donorProof);
    expect(tampered).not.toEqual(proof);

    const verifier = new Verifier();
    expect(() => {
        verifier.verifyAttributeRekey(encAttr, tampered, commitments);
    }).toThrow();
});

test('wrong_original_rejected_attribute_rekey', () => {
    const attributeGlobalKeys = makeAttributeGlobalKeys();
    const pseudoSecret = new PseudonymizationSecret(SECRET);
    const encSecret = new EncryptionSecret(SECRET);

    const s1 = new EncryptionContext("s1");
    const s2 = new EncryptionContext("s2");

    const attributeSession1Keys =
        makeAttributeSessionKeys(attributeGlobalKeys.secret, s1, encSecret);

    const transcryptor = new Transcryptor("secret", "secret");
    const rekeyInfo = transcryptor.attributeRekeyInfo(s1, s2);
    const commitments = transcryptor.attributeRekeyCommitment(s1, s2);

    const encAttr = encryptAttribute(Attribute.random(), attributeSession1Keys.public);
    const proof = transcryptor.verifiableAttributeRekey(encAttr, rekeyInfo);

    const otherEnc = encryptAttribute(Attribute.random(), attributeSession1Keys.public);

    const verifier = new Verifier();
    expect(() => {
        verifier.verifyAttributeRekey(otherEnc, proof, commitments);
    }).toThrow();
});

test('n_pep_batch_distributed_verifiable', () => {
    // Distributed verifiable batch transcryption: client A -> 3 transcryptors -> client B.
    //
    // Mirrors the Rust `n_pep_batch_distributed_verifiable` test 1:1. Each
    // transcryptor produces a hoisted batch proof, and the *next* transcryptor
    // verifies the previous one's proof before applying its own transcryption.
    // The final client B verifies the last proof, then decrypts.
    if (typeof EncryptedPseudonymBatch === "undefined"
        || typeof DistributedTranscryptor === "undefined"
        || typeof makeDistributedGlobalKeys === "undefined") {
        // Build without `batch`/`verifiable`/distributed: nothing to test.
        return;
    }

    const n = 3;
    const [_globalPublicKeys, blindedGlobalKeys, blindingFactors] =
        makeDistributedGlobalKeys(n);

    const systems = [];
    for (let i = 0; i < n; i++) {
        systems.push(new DistributedTranscryptor(`ps-${i}`, `es-${i}`, blindingFactors[i]));
    }

    const domainA = new PseudonymizationDomain("a");
    const domainB = new PseudonymizationDomain("b");
    const sessionA = new EncryptionContext("sa");
    const sessionB = new EncryptionContext("sb");

    const sksA = systems.map((s) => s.sessionKeyShares(sessionA));
    const sksB = systems.map((s) => s.sessionKeyShares(sessionB));

    const clientA = new Client(blindedGlobalKeys, sksA);
    const clientB = new Client(blindedGlobalKeys, sksB);

    // Client A encrypts a batch of pseudonyms. wasm-bindgen consumes the
    // input array by value, so capture the original hex representations
    // *before* the call for the post-decryption comparison below.
    const pseudonyms = [];
    for (let i = 0; i < 5; i++) pseudonyms.push(Pseudonym.random());
    const originalHex = pseudonyms.map((p) => p.toHex());
    const encryptedItems = clientA.encryptPseudonymBatch(pseudonyms);
    const clientAPk = clientA.sessionKeys.pseudonym.public;

    const makeBatch = (items) =>
        BATCH_PK
            ? new EncryptedPseudonymBatch(items, clientAPk)
            : new EncryptedPseudonymBatch(items);

    let current = makeBatch(encryptedItems);
    const currentPk = () => (BATCH_PK ? current.publicKey : clientAPk);

    // Chain: each step records (pre-batch, pre-pk, proof, commitments) so the
    // next step can verify it before doing its own transcryption.
    let prev = null;

    for (const system of systems) {
        // Step 1: verify the previous step (if any). The verification
        // reconstructs the post-batch from the previous step's pre-batch and
        // proof; that reconstruction must match what this transcryptor
        // actually received.
        if (prev !== null) {
            const { preBatch, prePk, proof, commitments } = prev;
            const reconstructed = BATCH_PK
                ? proof.verifiedReconstructBatch(preBatch, prePk, currentPk(), commitments)
                : proof.verifiedReconstructBatch(preBatch, prePk, commitments);
            // Compare items by base64 serialization to avoid object identity.
            const recItems = reconstructed.items.map((p) => p.toBase64());
            const curItems = current.items.map((p) => p.toBase64());
            expect(recItems).toEqual(curItems);
        }

        // Step 2: this transcryptor builds and applies its own verifiable
        // batch transcryption. We save a clone of the pre-batch + its pk so
        // the next iteration can verify against them.
        const prePk = currentPk();
        const preBatch = BATCH_PK
            ? new EncryptedPseudonymBatch(current.items, prePk)
            : new EncryptedPseudonymBatch(current.items);

        const info = system.pseudonymizationInfo(domainA, domainB, sessionA, sessionB);
        const commitments = system.pseudonymizationCommitment(
            domainA, domainB, sessionA, sessionB,
        );
        const proof = BATCH_PK
            ? current.verifiablePseudonymize(info)
            : current.verifiablePseudonymize(info, prePk);
        prev = { preBatch, prePk, proof, commitments };
    }

    // Final step: client B verifies the last transcryptor's proof, then
    // decrypts.
    expect(prev).not.toBeNull();
    const { preBatch, prePk, proof, commitments } = prev;
    const verifiedBatch = BATCH_PK
        ? proof.verifiedReconstructBatch(preBatch, prePk, currentPk(), commitments)
        : proof.verifiedReconstructBatch(preBatch, prePk, commitments);
    const verItems = verifiedBatch.items.map((p) => p.toBase64());
    const curItems = current.items.map((p) => p.toBase64());
    expect(verItems).toEqual(curItems);

    const decrypted = clientB.decryptPseudonymBatch(verifiedBatch.items);
    expect(decrypted.length).toBe(originalHex.length);

    // Domains differ, so pseudonyms are remapped and should NOT equal the originals.
    const decHex = decrypted.map((p) => p.toHex());
    expect(decHex).not.toEqual(originalHex);
});

// Swap the first leaf string value in `target` with the corresponding value
// in `donor` and return the resulting JSON. Both `target` and `donor` are
// serialized proofs of the same shape (produced by two independent
// `verifiable*` calls). Every Ristretto/scalar point in the proof JSON is a
// fixed-length hex string; blindly flipping a character would yield an
// undecodable point, so we cross-graft from another *valid* proof — that
// keeps every individual element decodable while breaking proof relations.
function swapFirstString(targetJson, donorJson) {
    const target = JSON.parse(targetJson);
    const donor = JSON.parse(donorJson);
    if (!swapFirstStringValue(target, donor)) {
        throw new Error("swapFirstString: no swappable string leaf found");
    }
    return JSON.stringify(target);
}

function swapFirstStringValue(target, donor) {
    if (Array.isArray(target) && Array.isArray(donor)) {
        const n = Math.min(target.length, donor.length);
        for (let i = 0; i < n; i++) {
            if (typeof target[i] === 'string' && typeof donor[i] === 'string') {
                if (target[i] !== donor[i]) {
                    target[i] = donor[i];
                    return true;
                }
            } else if (swapFirstStringValue(target[i], donor[i])) {
                return true;
            }
        }
        return false;
    }
    if (target && donor && typeof target === 'object' && typeof donor === 'object') {
        for (const k of Object.keys(target)) {
            if (!(k in donor)) continue;
            if (typeof target[k] === 'string' && typeof donor[k] === 'string') {
                if (target[k] !== donor[k]) {
                    target[k] = donor[k];
                    return true;
                }
            } else if (swapFirstStringValue(target[k], donor[k])) {
                return true;
            }
        }
        return false;
    }
    return false;
}
