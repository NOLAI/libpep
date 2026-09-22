// The wire formats of draft-doesburg-cfrg-coprf: batch requests and responses as bytes.
const {
    Attribute,
    BatchKind,
    BatchRequest,
    BatchResponse,
    Client,
    DistributedTranscryptor,
    ElGamal,
    EncryptedAttribute,
    EncryptedPseudonym,
    EncryptionContext,
    GroupElement,
    makeDistributedGlobalKeys,
    Pseudonym,
    PseudonymizationDomain,
    SessionKeyShares,
    Transcryptor,
} = require("../pkg/libpep.js");

const SESSION_A = new EncryptionContext("session-a");
const SESSION_B = new EncryptionContext("session-b");

function setup(n = 3) {
    const [, blinded, factors] = makeDistributedGlobalKeys(n);
    const systems = factors.map((f, i) => new DistributedTranscryptor(`ps-${i}`, `es-${i}`, f));
    // Shares travel to the clients as bytes.
    const shares = (session) =>
        systems.map((s) => SessionKeyShares.fromBytes(s.sessionKeyShares(session).toBytes()));
    return {
        systems,
        sender: new Client(blinded, shares(SESSION_A)),
        receiver: new Client(blinded, shares(SESSION_B)),
    };
}

function chain(systems, request) {
    let data = request.toBytes();
    let response = null;
    for (const system of systems) {
        const req = BatchRequest.fromBytes(data);
        response = BatchResponse.fromBytes(system.transcryptWire(req).toBytes());
        data = new BatchRequest(req.kind, req.dFrom, req.dTo, req.cFrom, req.cTo, response.yTo, response.items).toBytes();
    }
    return response;
}

const toElGamal = (encrypted) => ElGamal.fromBytes(encrypted.toBytes());
// Arrays of ElGamal values are moved into the WASM constructors, so build a fresh one per call.
const oneItem = (sender) => [toElGamal(sender.encryptPseudonym(Pseudonym.random()))];

test("pseudonym batch through three transcryptors", () => {
    const { systems, sender, receiver } = setup();
    const pseudonyms = Array.from({ length: 4 }, () => Pseudonym.random());
    const encrypted = pseudonyms.map((p) => sender.encryptPseudonym(p));
    const request = new BatchRequest(
        BatchKind.Pseudonym,
        "domain-a",
        new TextEncoder().encode("domain-b"),
        "session-a",
        "session-b",
        sender.dump().pseudonym.public[0],
        encrypted.map(toElGamal),
    );
    expect(Buffer.from(request.dFrom).toString()).toBe("domain-a");
    expect(Buffer.from(request.dTo).toString()).toBe("domain-b");
    expect(request.length).toBe(4);

    const response = chain(systems, request);
    expect(response.yTo.toHex()).toBe(receiver.dump().pseudonym.public[0].toHex());

    const got = new Set(response.items.map((c) => receiver.decryptPseudonym(new EncryptedPseudonym(c)).toHex()));
    const expected = new Set(
        encrypted.map((e) => {
            const [out] = systems.reduce(
                ([acc, key], system) => {
                    const info = system.pseudonymizationInfo(
                        new PseudonymizationDomain("domain-a"),
                        new PseudonymizationDomain("domain-b"),
                        SESSION_A,
                        SESSION_B,
                    );
                    return [system.pseudonymize(acc, info, key), info.rekeyPublicKey(key)];
                },
                [e, sender.dump().pseudonym.public],
            );
            return receiver.decryptPseudonym(out).toHex();
        }),
    );
    expect(got).toEqual(expected);
    for (const p of pseudonyms) expect(got.has(p.toHex())).toBe(false);
});

test("attribute batch through three transcryptors", () => {
    const { systems, sender, receiver } = setup();
    const attributes = Array.from({ length: 3 }, () => new Attribute(GroupElement.random()));
    const encrypted = attributes.map((a) => sender.encryptData(a));
    const request = new BatchRequest(
        BatchKind.Attribute,
        "",
        "",
        "session-a",
        "session-b",
        sender.dump().attribute.public[0],
        encrypted.map(toElGamal),
    );
    const response = chain(systems, request);
    expect(response.yTo.toHex()).toBe(receiver.dump().attribute.public[0].toHex());
    const got = new Set(response.items.map((c) => receiver.decryptData(new EncryptedAttribute(c)).toHex()));
    expect(got).toEqual(new Set(attributes.map((a) => a.toHex())));
    expect(response.items.map((i) => i.toBase64())).not.toEqual(encrypted.map((e) => e.toBase64()));
});

test("round trip and layout", () => {
    const { sender } = setup(1);
    const key = GroupElement.random();
    const item = oneItem(sender)[0].toBase64();
    const request = new BatchRequest(BatchKind.Pseudonym, "a", "b", "c", "d", key, [ElGamal.fromBase64(item)]);
    const data = request.toBytes();
    expect(data.length).toBe(1 + 4 * 3 + 32 + 4 + 64);
    expect(data[0]).toBe(1);
    expect(Array.from(data.slice(1, 4))).toEqual([0, 1, 97]);
    expect(BatchRequest.fromBytes(data).toBytes()).toEqual(data);

    const response = new BatchResponse(key, [ElGamal.fromBase64(item)]);
    const bytes = response.toBytes();
    expect(bytes.length).toBe(32 + 4 + 64);
    expect(BatchResponse.fromBytes(bytes).toBytes()).toEqual(bytes);
    expect(response.items[0].toBase64()).toBe(item);
});

test("rejections", () => {
    const { sender } = setup(1);
    const key = GroupElement.random();
    const data = new BatchRequest(BatchKind.Attribute, "a", "b", "c", "d", key, oneItem(sender)).toBytes();
    const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
    expect(() => BatchRequest.fromBytes(concat([3], data.slice(1)))).toThrow(/unknown batch type/);
    expect(() => BatchRequest.fromBytes(data.slice(0, -1))).toThrow(/truncated/);
    expect(() => BatchRequest.fromBytes(concat(data, [0]))).toThrow(/trailing/);
    expect(() => BatchRequest.fromBytes(concat(data.slice(0, -68), [0, 0, 0, 0]))).toThrow(/at least one item/);
    expect(() => BatchRequest.fromBytes(concat(data.slice(0, -32), new Uint8Array(32)))).toThrow(/invalid group element/);
    expect(() => new BatchRequest(BatchKind.Attribute, "a", "b", "c", "d", key, [])).toThrow(/at least one item/);
    expect(() => new BatchResponse(key, [])).toThrow(/at least one item/);
    expect(() => BatchResponse.fromBytes(concat(data.slice(-100), [0]))).toThrow(/trailing/);
    expect(() => new BatchRequest(BatchKind.Attribute, 1, "b", "c", "d", key, oneItem(sender))).toThrow(/Uint8Array or a string/);
});

test("non-UTF-8 identifier is rejected by the transcryptor", () => {
    const { sender } = setup(1);
    const key = GroupElement.random();
    const request = new BatchRequest(BatchKind.Pseudonym, new Uint8Array([0xff]), "b", "c", "d", key, oneItem(sender));
    expect(Array.from(BatchRequest.fromBytes(request.toBytes()).dFrom)).toEqual([0xff]);
    expect(() => new Transcryptor("ps", "es").transcryptWire(request)).toThrow(/UTF-8/);
});

test("session key shares as bytes", () => {
    const { systems } = setup(1);
    const shares = systems[0].sessionKeyShares(SESSION_A);
    const data = shares.toBytes();
    expect(data.length).toBe(64);
    expect(Array.from(data.slice(0, 32))).toEqual(Array.from(shares.pseudonym.toBytes()));
    expect(Array.from(data.slice(32))).toEqual(Array.from(shares.attribute.toBytes()));
    expect(SessionKeyShares.fromBytes(data).pseudonym.toHex()).toBe(shares.pseudonym.toHex());
    expect(() => SessionKeyShares.fromBytes(data.slice(0, 63))).toThrow(/truncated/);
    const zero = Uint8Array.from(data);
    zero.fill(0, 0, 32);
    expect(() => SessionKeyShares.fromBytes(zero)).toThrow(/invalid scalar/);
});
