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

test('Transcryptor context', () => {
    const ctx = new Context("my-deployment");
    expect(new Transcryptor("p", "e").context.equals(Context.default())).toBe(true);
    expect(new Transcryptor("p", "e", ctx).context.equals(ctx)).toBe(true);
    // A plain object with the same properties is accepted as a context too.
    expect(new Transcryptor("p", "e", {mode: 0, identifier: "my-deployment"}).context.equals(ctx)).toBe(true);
    expect(() => new Transcryptor("p", "e", {mode: 7, identifier: "x"})).toThrow();
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

test('Contexts separate factors and session keys', () => {
    const globalKeys = makeGlobalKeys();
    const encSecret = new EncryptionSecret(utf8("encryption secret"));
    const pseudoSecret = new PseudonymizationSecret(utf8("pseudonymization secret"));
    const sessionA = new EncryptionContext("session-a");
    const sessionB = new EncryptionContext("session-b");
    const domainA = new PseudonymizationDomain("hospital");
    const domainB = new PseudonymizationDomain("research");

    const contexts = [Context.default(), new Context("another-deployment"), Context.withMode(Mode.VcoPRF, "ristretto255-SHA512")];
    const keys = contexts.map((ctx) => makeSessionKeys(globalKeys.secret, sessionA, encSecret, ctx));
    const infos = contexts.map((ctx) => new TranscryptionInfo(domainA, domainB, sessionA, sessionB, pseudoSecret, encSecret, ctx));

    expect(keys[0].pseudonym.secret[0].toHex())
        .toBe(makeSessionKeys(globalKeys.secret, sessionA, encSecret).pseudonym.secret[0].toHex());
    expect(infos[0].pseudonym.s.scalar().toHex())
        .toBe(new TranscryptionInfo(domainA, domainB, sessionA, sessionB, pseudoSecret, encSecret).pseudonym.s.scalar().toHex());

    for (let i = 0; i < contexts.length; i++) {
        for (let j = 0; j < i; j++) {
            expect(keys[i].pseudonym.secret[0].toHex()).not.toBe(keys[j].pseudonym.secret[0].toHex());
            expect(keys[i].attribute.secret[0].toHex()).not.toBe(keys[j].attribute.secret[0].toHex());
            expect(infos[i].pseudonym.s.scalar().toHex()).not.toBe(infos[j].pseudonym.s.scalar().toHex());
            expect(infos[i].pseudonym.k.scalar().toHex()).not.toBe(infos[j].pseudonym.k.scalar().toHex());
            expect(infos[i].attribute.k.scalar().toHex()).not.toBe(infos[j].attribute.k.scalar().toHex());
        }
    }
});
