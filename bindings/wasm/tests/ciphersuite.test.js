const {
    Context,
    Mode,
    Transcryptor,
    GroupElement,
    EncryptionContext,
    PseudonymizationDomain,
    EncryptionSecret,
    PseudonymizationSecret,
    TranscryptionInfo,
    makeGlobalKeys,
    makeSessionKeys,
    hashToGroup,
    hashToGroupWithDst,
    hashToScalarWithDst,
    expandMessageXmdSha512,
    encodeLizard,
    decodeLizard,
} = require("../pkg/libpep.js");

const utf8 = (s) => new TextEncoder().encode(s);
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const concat = (a, b) => new Uint8Array([...a, ...b]);

test('Context string', () => {
    const ctx = Context.default();
    expect(ctx.mode).toBe(Mode.CoPRF);
    expect(Buffer.from(ctx.identifier).toString()).toBe("ristretto255-SHA512");
    expect(Buffer.from(ctx.contextString())).toEqual(Buffer.from("coPRFV1-\x00-ristretto255-SHA512", "latin1"));
    expect(ctx.equals(new Context("ristretto255-SHA512"))).toBe(true);

    const custom = Context.withMode(Mode.VcoPRF, "my-deployment");
    expect(Buffer.from(custom.contextString())).toEqual(Buffer.from("coPRFV1-\x01-my-deployment", "latin1"));
    expect(custom.equals(new Context("my-deployment"))).toBe(false);
    expect(custom.toString()).toBe("coPRFV1-01-my-deployment");
});

test('Transcryptor takes no context', () => {
    // The protocol context is a property of the ciphersuite, so a transcryptor is constructed
    // from its secrets alone and derives the same factors as the free functions.
    const t = new Transcryptor("p", "e");
    const sessionA = new EncryptionContext("session-a");
    const sessionB = new EncryptionContext("session-b");
    expect(t.pseudonymRekeyInfo(sessionA, sessionB).k.scalar().toHex())
        .toBe(new Transcryptor("p", "e").pseudonymRekeyInfo(sessionA, sessionB).k.scalar().toHex());
});

test('expand_message_xmd RFC 9380 vector', () => {
    const dst = utf8("QUUX-V01-CS02-with-expander-SHA512-256");
    expect(hex(expandMessageXmdSha512(utf8(""), dst, 32)))
        .toBe("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba");
    expect(hex(expandMessageXmdSha512(utf8("abc"), dst, 32)))
        .toBe("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc");
    expect(() => expandMessageXmdSha512(utf8(""), dst, 65536)).toThrow();
});

test('hashToGroup uses the context DST', () => {
    const ctx = new Context("my-deployment");
    const dst = concat(utf8("HashToGroup-"), ctx.contextString());
    expect(hashToGroup(utf8("patient-1"), ctx).toHex()).toBe(hashToGroupWithDst(utf8("patient-1"), dst).toHex());
    expect(hashToGroup(utf8("patient-1")).toHex()).toBe(hashToGroup(utf8("patient-1"), Context.default()).toHex());
    expect(hashToGroup(utf8("patient-1")).toHex()).not.toBe(hashToGroup(utf8("patient-1"), ctx).toHex());
    expect(hashToGroup(utf8("patient-1")).toHex()).not.toBe(hashToGroup(utf8("patient-2")).toHex());

    const a = hashToScalarWithDst(utf8("msg"), utf8("dst-a"));
    expect(a.toHex()).toBe(hashToScalarWithDst(utf8("msg"), utf8("dst-a")).toHex());
    expect(a.toHex()).not.toBe(hashToScalarWithDst(utf8("msg"), utf8("dst-b")).toHex());
});

test('lizard round trip', () => {
    const data = new Uint8Array(16).map((_, i) => i);
    const element = encodeLizard(data);
    expect(Buffer.from(decodeLizard(element))).toEqual(Buffer.from(data));
    expect(decodeLizard(GroupElement.random())).toBeUndefined();
    expect(() => encodeLizard(new Uint8Array(3))).toThrow();
});

test('Secrets, domains and sessions separate factors and session keys', () => {
    // Factor derivation takes no protocol context: the secret is part of its hash input, so
    // different secrets already give unrelated factors, and the domain and session separate
    // within a deployment.
    const globalKeys = makeGlobalKeys();
    const encSecret = new EncryptionSecret(utf8("encryption secret"));
    const pseudoSecret = new PseudonymizationSecret(utf8("pseudonymization secret"));
    const otherEnc = new EncryptionSecret(utf8("other encryption secret"));
    const otherPseudo = new PseudonymizationSecret(utf8("other pseudonymization secret"));
    const sessionA = new EncryptionContext("session-a");
    const sessionB = new EncryptionContext("session-b");
    const domainA = new PseudonymizationDomain("hospital");
    const domainB = new PseudonymizationDomain("research");

    const keys = makeSessionKeys(globalKeys.secret, sessionA, encSecret);
    const info = new TranscryptionInfo(domainA, domainB, sessionA, sessionB, pseudoSecret, encSecret);

    // Deterministic in the secrets, the domains and the sessions.
    expect(keys.pseudonym.secret[0].toHex())
        .toBe(makeSessionKeys(globalKeys.secret, sessionA, encSecret).pseudonym.secret[0].toHex());
    expect(info.pseudonym.s.scalar().toHex())
        .toBe(new TranscryptionInfo(domainA, domainB, sessionA, sessionB, pseudoSecret, encSecret).pseudonym.s.scalar().toHex());

    // A different secret separates.
    expect(makeSessionKeys(globalKeys.secret, sessionA, otherEnc).pseudonym.secret[0].toHex())
        .not.toBe(keys.pseudonym.secret[0].toHex());
    expect(new TranscryptionInfo(domainA, domainB, sessionA, sessionB, otherPseudo, otherEnc).pseudonym.s.scalar().toHex())
        .not.toBe(info.pseudonym.s.scalar().toHex());

    // A different session or domain separates.
    expect(makeSessionKeys(globalKeys.secret, sessionB, encSecret).pseudonym.secret[0].toHex())
        .not.toBe(keys.pseudonym.secret[0].toHex());
    expect(new TranscryptionInfo(domainA, new PseudonymizationDomain("other"), sessionA, sessionB, pseudoSecret, encSecret).pseudonym.s.scalar().toHex())
        .not.toBe(info.pseudonym.s.scalar().toHex());
});
