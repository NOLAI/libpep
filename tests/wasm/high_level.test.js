const {
    Attribute,
    LongAttribute,
    decryptData,
    decryptPseudonym,
    encryptData,
    encryptPseudonym,
    GroupElement,
    makePseudonymGlobalKeys,
    makeAttributeGlobalKeys,
    makePseudonymSessionKeys,
    makeAttributeSessionKeys,
    pseudonymize,
    rekeyData,
    Pseudonym,
    LongPseudonym,
    PseudonymizationInfo,
    AttributeRekeyInfo,
    TranscryptionInfo,
    PseudonymizationSecret,
    EncryptionSecret,
    transcryptBatch,
    EncryptedData,
    PseudonymGlobalPublicKey,
    AttributeGlobalPublicKey,
    EncryptedPseudonym,
    EncryptedAttribute
} = require("../../pkg/libpep.js");

test('test high level', async () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const attributeGlobalKeys = makeAttributeGlobalKeys();

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = "domain1";
    const session1 = "session1";
    const domain2 = "domain2";
    const session2 = "session2";

    const pseudonymSession1Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const pseudonymSession2Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session2, encSecret);
    const attributeSession1Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session1, encSecret);
    const attributeSession2Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session2, encSecret);

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, pseudonymSession1Keys.public);

    const random = GroupElement.random();
    const data = new Attribute(random);
    const encData = encryptData(data, attributeSession1Keys.public);

    const decPseudo = decryptPseudonym(encPseudo, pseudonymSession1Keys.secret);
    const decData = decryptData(encData, attributeSession1Keys.secret);

    expect(pseudo.asHex()).toEqual(decPseudo.asHex());
    expect(data.asHex()).toEqual(decData.asHex());

    const pseudoInfo = new PseudonymizationInfo(domain1, domain2, session1, session2, pseudoSecret, encSecret);
    const rekeyInfo = new AttributeRekeyInfo(session1, session2, encSecret);

    const rekeyed = rekeyData(encData, rekeyInfo);
    const rekeyedDec = decryptData(rekeyed, attributeSession2Keys.secret);

    expect(data.asHex()).toEqual(rekeyedDec.asHex());

    const pseudonymized = pseudonymize(encPseudo, pseudoInfo);
    const pseudonymizedDec = decryptPseudonym(pseudonymized, pseudonymSession2Keys.secret);

    expect(pseudo.asHex()).not.toEqual(pseudonymizedDec.asHex());

    const revPseudonymized = pseudonymize(pseudonymized, pseudoInfo.rev());
    const revPseudonymizedDec = decryptPseudonym(revPseudonymized, pseudonymSession1Keys.secret);

    expect(pseudo.asHex()).toEqual(revPseudonymizedDec.asHex());
})

test('test pseudonym operations', async () => {
    // Test random pseudonym
    const pseudo1 = Pseudonym.random();
    const pseudo2 = Pseudonym.random();
    expect(pseudo1.asHex()).not.toEqual(pseudo2.asHex());
    
    // Test encoding/decoding
    const encoded = pseudo1.encode();
    const decoded = Pseudonym.decode(encoded);
    expect(decoded).not.toBeNull();
    expect(pseudo1.asHex()).toEqual(decoded.asHex());
    
    // Test hex encoding/decoding
    const hexStr = pseudo1.asHex();
    const decodedHex = Pseudonym.fromHex(hexStr);
    expect(decodedHex).not.toBeNull();
    expect(pseudo1.asHex()).toEqual(decodedHex.asHex());
});

test('test data point operations', async () => {
    // Test random data point
    const data1 = Attribute.random();
    const data2 = Attribute.random();
    expect(data1.asHex()).not.toEqual(data2.asHex());
    
    // Test encoding/decoding
    const encoded = data1.encode();
    const decoded = Attribute.decode(encoded);
    expect(decoded).not.toBeNull();
    expect(data1.asHex()).toEqual(decoded.asHex());
});

test('test string padding operations', async () => {
    const testString = "Hello, World! This is a test string for padding.";

    // Test pseudonym string padding
    const longPseudo = LongPseudonym.fromStringPadded(testString);
    expect(longPseudo.length()).toBeGreaterThan(0);

    // Reconstruct string
    const reconstructed = longPseudo.toStringPadded();
    expect(testString).toEqual(reconstructed);

    // Test data point string padding
    const longAttr = LongAttribute.fromStringPadded(testString);
    expect(longAttr.length()).toBeGreaterThan(0);

    // Reconstruct string
    const reconstructedData = longAttr.toStringPadded();
    expect(testString).toEqual(reconstructedData);
});

test('test bytes padding operations', async () => {
    const testBytes = new Uint8Array(Buffer.from("Hello, World! This is a test byte array for padding."));

    // Test pseudonym bytes padding
    const longPseudo = LongPseudonym.fromBytesPadded(testBytes);
    expect(longPseudo.length()).toBeGreaterThan(0);

    // Reconstruct bytes
    const reconstructed = longPseudo.toBytesPadded();
    expect(new Uint8Array(reconstructed)).toEqual(testBytes);

    // Test data point bytes padding
    const longAttr = LongAttribute.fromBytesPadded(testBytes);
    expect(longAttr.length()).toBeGreaterThan(0);

    // Reconstruct bytes
    const reconstructedData = longAttr.toBytesPadded();
    expect(new Uint8Array(reconstructedData)).toEqual(testBytes);
});

test('test fixed size bytes operations', async () => {
    // Create 16-byte test data
    const testBytes = new Uint8Array(Buffer.from("1234567890abcdef")); // Exactly 16 bytes
    
    // Test pseudonym from/as bytes
    const pseudo = Pseudonym.fromBytes(testBytes);
    const reconstructed = pseudo.asBytes();
    expect(reconstructed).not.toBeNull();
    expect(new Uint8Array(reconstructed)).toEqual(testBytes);
    
    // Test data point from/as bytes
    const data = Attribute.fromBytes(testBytes);
    const reconstructedData = data.asBytes();
    expect(reconstructedData).not.toBeNull();
    expect(new Uint8Array(reconstructedData)).toEqual(testBytes);
});

test('test encrypted types encoding', async () => {
    // Setup
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const attributeGlobalKeys = makeAttributeGlobalKeys();
    const secret = new Uint8Array(Buffer.from("secret"));
    const encSecret = new EncryptionSecret(secret);
    const pseudonymSessionKeys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, "session", encSecret);
    const attributeSessionKeys = makeAttributeSessionKeys(attributeGlobalKeys.secret, "session", encSecret);

    // Create encrypted pseudonym
    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, pseudonymSessionKeys.public);

    // Test byte encoding/decoding
    const encoded = encPseudo.encode();
    const decoded = EncryptedPseudonym.decode(encoded);
    expect(decoded).not.toBeNull();

    // Test base64 encoding/decoding
    const b64Str = encPseudo.asBase64();
    const decodedB64 = EncryptedPseudonym.fromBase64(b64Str);
    expect(decodedB64).not.toBeNull();

    // Verify both decode to same plaintext
    const dec1 = decryptPseudonym(decoded, pseudonymSessionKeys.secret);
    const dec2 = decryptPseudonym(decodedB64, pseudonymSessionKeys.secret);
    expect(pseudo.asHex()).toEqual(dec1.asHex());
    expect(pseudo.asHex()).toEqual(dec2.asHex());

    // Test same for encrypted data point
    const data = Attribute.random();
    const encData = encryptData(data, attributeSessionKeys.public);

    const encodedData = encData.encode();
    const decodedData = EncryptedAttribute.decode(encodedData);
    expect(decodedData).not.toBeNull();

    const decData = decryptData(decodedData, attributeSessionKeys.secret);
    expect(data.asHex()).toEqual(decData.asHex());
});

test('test key generation consistency', async () => {
    const secret = new Uint8Array(Buffer.from("consistent_secret"));
    const encSecret = new EncryptionSecret(secret);

    // Generate same global keys multiple times (they should be random)
    const pseudoKeys1 = makePseudonymGlobalKeys();
    const pseudoKeys2 = makePseudonymGlobalKeys();
    expect(pseudoKeys1.public.asHex()).not.toEqual(pseudoKeys2.public.asHex());

    const attrKeys1 = makeAttributeGlobalKeys();
    const attrKeys2 = makeAttributeGlobalKeys();
    expect(attrKeys1.public.asHex()).not.toEqual(attrKeys2.public.asHex());

    // Generate same session keys with same inputs (should be deterministic)
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const session1a = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, "session1", encSecret);
    const session1b = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, "session1", encSecret);

    // Access GroupElement directly from SessionPublicKey (it has property '0')
    expect(session1a.public[0].asHex()).toEqual(session1b.public[0].asHex());

    // Different session names should give different keys
    const session2 = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, "session2", encSecret);
    expect(session1a.public[0].asHex()).not.toEqual(session2.public[0].asHex());
});

test('test global public key operations', async () => {
    // Test pseudonym global public key
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const pseudoPubKey = pseudonymGlobalKeys.public;

    const pseudoHexStr = pseudoPubKey.asHex();
    const decodedPseudo = PseudonymGlobalPublicKey.fromHex(pseudoHexStr);
    expect(decodedPseudo).not.toBeNull();
    expect(pseudoHexStr).toEqual(decodedPseudo.asHex());

    // Test attribute global public key
    const attributeGlobalKeys = makeAttributeGlobalKeys();
    const attrPubKey = attributeGlobalKeys.public;

    const attrHexStr = attrPubKey.asHex();
    const decodedAttr = AttributeGlobalPublicKey.fromHex(attrHexStr);
    expect(decodedAttr).not.toBeNull();
    expect(attrHexStr).toEqual(decodedAttr.asHex());
});

test('test batch transcrypt', async () => {
    const pseudonymGlobalKeys = makePseudonymGlobalKeys();
    const attributeGlobalKeys = makeAttributeGlobalKeys();

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = "domain1";
    const session1 = "session1";
    const domain2 = "domain2";
    const session2 = "session2";

    const transcryptionInfo = new TranscryptionInfo(domain1, domain2, session1, session2, pseudoSecret, encSecret);

    const pseudonymSession1Keys = makePseudonymSessionKeys(pseudonymGlobalKeys.secret, session1, encSecret);
    const attributeSession1Keys = makeAttributeSessionKeys(attributeGlobalKeys.secret, session1, encSecret);

    const messages = [];

    for (let i = 0; i < 10; i++) {
        const dataPoints = [];
        const pseudonyms = [];

        for (let j = 0; j < 3; j++) {
            dataPoints.push(encryptData(
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