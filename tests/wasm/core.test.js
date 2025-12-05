const {
    Attribute,
    LongAttribute,
    decryptAttribute,
    decryptPseudonym,
    encryptAttribute,
    encryptPseudonym,
    GroupElement,
    makePseudonymGlobalKeys,
    makeAttributeGlobalKeys,
    makePseudonymSessionKeys,
    makeAttributeSessionKeys,
    pseudonymize,
    rekeyAttribute,
    Pseudonym,
    LongPseudonym,
    PseudonymizationInfo,
    AttributeRekeyInfo,
    TranscryptionInfo,
    PseudonymizationSecret,
    EncryptionSecret,
    transcryptBatch,
    PseudonymGlobalPublicKey,
    AttributeGlobalPublicKey,
    EncryptedPseudonym,
    EncryptedAttribute,
    PseudonymizationDomain,
    EncryptionContext,
} = require("../../pkg/libpep.js");

test('test high level', async () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const attributeGlobalKeys = makeAttributeGlobalKeys();

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = new PseudonymizationDomain("domain1");
    const session1 = new EncryptionContext("session1");
    const domain2 = new PseudonymizationDomain("domain2");
    const session2 = new EncryptionContext("session2");

    const pseudonymSession1Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const pseudonymSession2Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session2, encSecret);
    const attributeSession1Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session1, encSecret);
    const attributeSession2Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session2, encSecret);

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, pseudonymSession1Keys.public);

    const random = GroupElement.random();
    const data = new Attribute(random);
    const encData = encryptAttribute(data, attributeSession1Keys.public);

    const decPseudo = decryptPseudonym(encPseudo, pseudonymSession1Keys.secret);
    const decData = decryptAttribute(encData, attributeSession1Keys.secret);

    expect(pseudo.toHex()).toEqual(decPseudo.toHex());
    expect(data.toHex()).toEqual(decData.toHex());

    const pseudoInfo = new PseudonymizationInfo(domain1, domain2, session1, session2, pseudoSecret, encSecret);
    const rekeyInfo = new AttributeRekeyInfo(session1, session2, encSecret);

    const rekeyed = rekeyAttribute(encData, rekeyInfo);
    const rekeyedDec = decryptAttribute(rekeyed, attributeSession2Keys.secret);

    expect(data.toHex()).toEqual(rekeyedDec.toHex());

    const pseudonymized = pseudonymize(encPseudo, pseudoInfo);
    const pseudonymizedDec = decryptPseudonym(pseudonymized, pseudonymSession2Keys.secret);

    expect(pseudo.toHex()).not.toEqual(pseudonymizedDec.toHex());

    const revPseudonymized = pseudonymize(pseudonymized, pseudoInfo.reverse());
    const revPseudonymizedDec = decryptPseudonym(revPseudonymized, pseudonymSession1Keys.secret);

    expect(pseudo.toHex()).toEqual(revPseudonymizedDec.toHex());
})

test('test pseudonym operations', async () => {
    // Test random pseudonym
    const pseudo1 = Pseudonym.random();
    const pseudo2 = Pseudonym.random();
    expect(pseudo1.toHex()).not.toEqual(pseudo2.toHex());
    
    // Test encoding/decoding
    const encoded = pseudo1.toBytes();
    const decoded = Pseudonym.fromBytes(encoded);
    expect(decoded).not.toBeNull();
    expect(pseudo1.toHex()).toEqual(decoded.toHex());
    
    // Test hex encoding/decoding
    const hexStr = pseudo1.toHex();
    const decodedHex = Pseudonym.fromHex(hexStr);
    expect(decodedHex).not.toBeNull();
    expect(pseudo1.toHex()).toEqual(decodedHex.toHex());
});

test('test data point operations', async () => {
    // Test random data point
    const data1 = Attribute.random();
    const data2 = Attribute.random();
    expect(data1.toHex()).not.toEqual(data2.toHex());
    
    // Test encoding/decoding
    const encoded = data1.toBytes();
    const decoded = Attribute.fromBytes(encoded);
    expect(decoded).not.toBeNull();
    expect(data1.toHex()).toEqual(decoded.toHex());
});

test('test string padding operations', async () => {
    const testString = "Hello, World! This is a test string for padding.";

    // Test pseudonym string padding
    const longPseudo = LongPseudonym.fromStringPadded(testString);
    expect(longPseudo.length).toBeGreaterThan(0);

    // Reconstruct string
    const reconstructed = longPseudo.toStringPadded();
    expect(testString).toEqual(reconstructed);

    // Test data point string padding
    const longAttr = LongAttribute.fromStringPadded(testString);
    expect(longAttr.length).toBeGreaterThan(0);

    // Reconstruct string
    const reconstructedData = longAttr.toStringPadded();
    expect(testString).toEqual(reconstructedData);
});

test('test bytes padding operations', async () => {
    const testBytes = new Uint8Array(Buffer.from("Hello, World! This is a test byte array for padding."));

    // Test pseudonym bytes padding
    const longPseudo = LongPseudonym.fromBytesPadded(testBytes);
    expect(longPseudo.length).toBeGreaterThan(0);

    // Reconstruct bytes
    const reconstructed = longPseudo.toBytesPadded();
    expect(new Uint8Array(reconstructed)).toEqual(testBytes);

    // Test data point bytes padding
    const longAttr = LongAttribute.fromBytesPadded(testBytes);
    expect(longAttr.length).toBeGreaterThan(0);

    // Reconstruct bytes
    const reconstructedData = longAttr.toBytesPadded();
    expect(new Uint8Array(reconstructedData)).toEqual(testBytes);
});

test('test fixed size bytes operations', async () => {
    // Create 16-byte test data
    const testBytes = new Uint8Array(Buffer.from("1234567890abcdef")); // Exactly 16 bytes
    
    // Test pseudonym from/as bytes
    const pseudo = Pseudonym.fromLizard(testBytes);
    const reconstructed = pseudo.toLizard();
    expect(reconstructed).not.toBeNull();
    expect(new Uint8Array(reconstructed)).toEqual(testBytes);
    
    // Test data point from/as bytes
    const data = Attribute.fromLizard(testBytes);
    const reconstructedData = data.toLizard();
    expect(reconstructedData).not.toBeNull();
    expect(new Uint8Array(reconstructedData)).toEqual(testBytes);
});

test('test encrypted types encoding', async () => {
    // Setup
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const attributeGlobalKeys = makeAttributeGlobalKeys();
    const secret = new Uint8Array(Buffer.from("secret"));
    const encSecret = new EncryptionSecret(secret);
    const session = new EncryptionContext("session");
    const pseudonymSessionKeys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session, encSecret);
    const attributeSessionKeys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session, encSecret);

    // Create encrypted pseudonym
    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, pseudonymSessionKeys.public);

    // Test byte encoding/decoding
    const encoded = encPseudo.toBytes();
    const decoded = EncryptedPseudonym.fromBytes(encoded);
    expect(decoded).not.toBeNull();

    // Test base64 encoding/decoding
    const b64Str = encPseudo.toBase64();
    const decodedB64 = EncryptedPseudonym.fromBase64(b64Str);
    expect(decodedB64).not.toBeNull();

    // Verify both decode to same plaintext
    const dec1 = decryptPseudonym(decoded, pseudonymSessionKeys.secret);
    const dec2 = decryptPseudonym(decodedB64, pseudonymSessionKeys.secret);
    expect(pseudo.toHex()).toEqual(dec1.toHex());
    expect(pseudo.toHex()).toEqual(dec2.toHex());

    // Test same for encrypted data point
    const data = Attribute.random();
    const encData = encryptAttribute(data, attributeSessionKeys.public);

    const encodedData = encData.toBytes();
    const decodedData = EncryptedAttribute.fromBytes(encodedData);
    expect(decodedData).not.toBeNull();

    const decData = decryptAttribute(decodedData, attributeSessionKeys.secret);
    expect(data.toHex()).toEqual(decData.toHex());
});

test('test key generation consistency', async () => {
    const secret = new Uint8Array(Buffer.from("consistent_secret"));
    const encSecret = new EncryptionSecret(secret);

    // Generate same global keys multiple times (they should be random)
    const pseudoKeys1 = makePseudonymGlobalKeys();
    const pseudoKeys2 = makePseudonymGlobalKeys();
    expect(pseudoKeys1.public.toHex()).not.toEqual(pseudoKeys2.public.toHex());

    const attrKeys1 = makeAttributeGlobalKeys();
    const attrKeys2 = makeAttributeGlobalKeys();
    expect(attrKeys1.public.toHex()).not.toEqual(attrKeys2.public.toHex());

    // Generate same session keys with same inputs (should be deterministic)
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const session1 = new EncryptionContext("session1");
    const session1a = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const session1b = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);

    // Access GroupElement directly from SessionPublicKey (it has property '0')
    expect(session1a.public[0].toHex()).toEqual(session1b.public[0].toHex());

    // Different session names should give different keys
    const session2 = new EncryptionContext("session2");
    const session2Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session2, encSecret);
    expect(session1a.public[0].toHex()).not.toEqual(session2Keys.public[0].toHex());
});

test('test global public key operations', async () => {
    // Test pseudonym global public key
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoPubKey = pseudonymGlobalKeys.public;

    const pseudoHexStr = pseudoPubKey.toHex();
    const decodedPseudo = PseudonymGlobalPublicKey.fromHex(pseudoHexStr);
    expect(decodedPseudo).not.toBeNull();
    expect(pseudoHexStr).toEqual(decodedPseudo.toHex());

    // Test attribute global public key
    const attributeGlobalKeys = makeAttributeGlobalKeys();
    const attrPubKey = attributeGlobalKeys.public;

    const attrHexStr = attrPubKey.toHex();
    const decodedAttr = AttributeGlobalPublicKey.fromHex(attrHexStr);
    expect(decodedAttr).not.toBeNull();
    expect(attrHexStr).toEqual(decodedAttr.toHex());
});

test('test batch long operations', async () => {
    const {
        LongPseudonym,
        LongAttribute,
        LongEncryptedPseudonym,
        LongEncryptedAttribute,
        encryptLongPseudonym,
        encryptLongAttribute,
        decryptLongPseudonym,
        decryptLongAttribute,
        makePseudonymGlobalKeys,
        makeAttributeGlobalKeys,
        makePseudonymSessionKeys,
        makeAttributeSessionKeys,
        PseudonymizationSecret,
        EncryptionSecret,
        TranscryptionInfo,
        pseudonymizeLongBatch,
        rekeyLongPseudonymBatch,
        rekeyLongAttributeBatch,
        transcryptLongBatch,
        LongEncryptedDataPair,
    } = require("../../pkg/libpep.js");

    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const attributeGlobalKeys = makeAttributeGlobalKeys();

    const secret = Uint8Array.from(Buffer.from("secret"));
    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = new PseudonymizationDomain("domain1");
    const session1 = new EncryptionContext("session1");
    const domain2 = new PseudonymizationDomain("domain2");
    const session2 = new EncryptionContext("session2");

    const pseudonymSession1Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const pseudonymSession2Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session2, encSecret);
    const attributeSession1Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session1, encSecret);
    const attributeSession2Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session2, encSecret);

    // Create long pseudonyms and attributes with padding
    const testStrings = [
        "User 1 identifier string that spans multiple blocks",
        "User 2 identifier string that spans multiple blocks",
        "User 3 identifier string that spans multiple blocks",
    ];

    const longPseudonyms = testStrings.map(s =>
        encryptLongPseudonym(LongPseudonym.fromStringPadded(s), pseudonymSession1Keys.public)
    );

    const longAttributes = testStrings.map(s =>
        encryptLongAttribute(LongAttribute.fromStringPadded(s), attributeSession1Keys.public)
    );

    const transcryptionInfo = new TranscryptionInfo(
        domain1, domain2, session1, session2, pseudoSecret, encSecret
    );

    // Test batch rekeying of long pseudonyms
    const rekeyedPseudonyms = rekeyLongPseudonymBatch(
        longPseudonyms.map(p => p.clone()),
        transcryptionInfo.pseudonym.k
    );
    expect(rekeyedPseudonyms.length).toEqual(3);

    // Test batch rekeying of long attributes
    const rekeyedAttributes = rekeyLongAttributeBatch(
        longAttributes.map(a => a.clone()),
        transcryptionInfo.attribute
    );
    expect(rekeyedAttributes.length).toEqual(3);

    // Verify decryption works after rekeying
    for (const rekeyedAttr of rekeyedAttributes) {
        const decrypted = decryptLongAttribute(rekeyedAttr, attributeSession2Keys.secret);
        const decryptedString = decrypted.toStringPadded();
        expect(testStrings).toContain(decryptedString);
    }

    // Test batch pseudonymization of long pseudonyms
    const pseudonymized = pseudonymizeLongBatch(
        longPseudonyms.map(p => p.clone()),
        transcryptionInfo.pseudonym
    );
    expect(pseudonymized.length).toEqual(3);

    // Verify decryption works after pseudonymization
    for (const pseudonymizedPseudo of pseudonymized) {
        const decrypted = decryptLongPseudonym(pseudonymizedPseudo, pseudonymSession2Keys.secret);
        // After pseudonymization, the value changes but we can verify it decrypts
        expect(decrypted.length).toEqual(4); // String padded to 4 blocks
    }

    // Test batch transcryption of long data
    const data = [];
    for (let i = 0; i < 3; i++) {
        const pseudonyms = [encryptLongPseudonym(
            LongPseudonym.fromStringPadded(`Entity ${i} pseudonym data`),
            pseudonymSession1Keys.public
        )];
        const attributes = [encryptLongAttribute(
            LongAttribute.fromStringPadded(`Entity ${i} attribute data`),
            attributeSession1Keys.public
        )];
        data.push(new LongEncryptedDataPair(pseudonyms, attributes));
    }

    const transcrypted = transcryptLongBatch(data, transcryptionInfo);
    expect(transcrypted.length).toEqual(3);

    // Verify each entity has one pseudonym and one attribute
    for (const pair of transcrypted) {
        expect(pair.pseudonyms.length).toEqual(1);
        expect(pair.attributes.length).toEqual(1);

        // Verify attributes decrypt correctly
        const decryptedAttr = decryptLongAttribute(pair.attributes[0], attributeSession2Keys.secret);
        const attrStr = decryptedAttr.toStringPadded();
        expect(attrStr.startsWith("Entity ") && attrStr.endsWith(" attribute data")).toBe(true);
    }
});

test.skip('test batch transcrypt', async () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const attributeGlobalKeys = makeAttributeGlobalKeys();

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = new PseudonymizationDomain("domain1");
    const session1 = new EncryptionContext("session1");
    const domain2 = new PseudonymizationDomain("domain2");
    const session2 = new EncryptionContext("session2");

    const transcryptionInfo = new TranscryptionInfo(domain1, domain2, session1, session2, pseudoSecret, encSecret);

    const pseudonymSession1Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const attributeSession1Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session1, encSecret);

    const messages = [];

    for (let i = 0; i < 10; i++) {
        const dataPoints = [];
        const pseudonyms = [];

        for (let j = 0; j < 3; j++) {
            dataPoints.push(encryptAttribute(
                new Attribute(GroupElement.random()),
                attributeSession1Keys.public,
            ));

            pseudonyms.push(encryptPseudonym(
                new Pseudonym(GroupElement.random()),
                pseudonymSession1Keys.public,
            ));
        }

        const entityData = new EncryptedData(pseudonyms, dataPoints);
        messages.push(entityData);
    }
    const transcrypted = transcryptBatch(messages, transcryptionInfo);
    expect(transcrypted.length).toEqual(messages.length);

    // Verify structure is maintained
    for (let i = 0; i < transcrypted.length; i++) {
        expect(transcrypted[i].pseudonyms.length).toEqual(3);
        expect(transcrypted[i].attributes.length).toEqual(3);
    }
})