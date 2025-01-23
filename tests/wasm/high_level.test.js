const {
    DataPoint, decryptData, decryptPseudonym, encryptData,
    encryptPseudonym,
    GroupElement,
    makeGlobalKeys,
    makeSessionKeys,
    pseudonymize, rekeyData, Pseudonym, PseudonymizationInfo, RekeyInfo, PseudonymizationSecret, EncryptionSecret
} = require("../../pkg/libpep.js");

test('test high level', async () => {
    const globalKeys = makeGlobalKeys();
    const globalPublicKey = globalKeys.public;
    const globalPrivateKey = globalKeys.secret;

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const domain1 = "domain1";
    const session1 = "session1";
    const domain2 = "domain2";
    const session2 = "session2";

    const session1Keys = makeSessionKeys(globalPrivateKey, session1, encSecret);
    const session2Keys = makeSessionKeys(globalPrivateKey, session2, encSecret);

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, session1Keys.public);

    const random = GroupElement.random();
    const data = new DataPoint(random);
    const encData = encryptData(data, session1Keys.public);

    const decPseudo = decryptPseudonym(encPseudo, session1Keys.secret);
    const decData = decryptData(encData, session1Keys.secret);

    expect(pseudo.asHex()).toEqual(decPseudo.asHex());
    expect(data.asHex()).toEqual(decData.asHex());

    const pseudoInfo = new PseudonymizationInfo(domain1, domain2, session1, session2, pseudoSecret, encSecret);
    const rekeyInfo = new RekeyInfo(session1, session2, encSecret);

    const rekeyed = rekeyData(encData, rekeyInfo);
    const rekeyedDec = decryptData(rekeyed, session2Keys.secret);

    expect(data.asHex()).toEqual(rekeyedDec.asHex());

    const pseudonymized = pseudonymize(encPseudo, pseudoInfo);
    const pseudonymizedDec = decryptPseudonym(pseudonymized, session2Keys.secret);

    expect(pseudo.asHex()).not.toEqual(pseudonymizedDec.asHex());

    const revPseudonymized = pseudonymize(pseudonymized, pseudoInfo.rev());
    const revPseudonymizedDec = decryptPseudonym(revPseudonymized, session1Keys.secret);

    expect(pseudo.asHex()).toEqual(revPseudonymizedDec.asHex());
})