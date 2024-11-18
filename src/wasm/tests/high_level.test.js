const {
    DataPoint, decryptData, decryptPseudonym, encryptData,
    encryptPseudonym,
    GroupElement,
    makeGlobalKeys,
    makeSessionKeys,
    pseudonymize, rekeyData, Pseudonym, PseudonymizationInfo, RekeyInfo, PseudonymizationSecret, EncryptionSecret
} = require("../../../pkg");

test('test high level', async () => {
    const globalKeys = makeGlobalKeys();
    const globalPublicKey = globalKeys.public;
    const globalPrivateKey = globalKeys.secret;

    const secret = Uint8Array.from(Buffer.from("secret"))

    const pseudoSecret = new PseudonymizationSecret(secret);
    const encSecret = new EncryptionSecret(secret);

    const pseudoContext1 = "context1";
    const encContext1 = "session1";
    const pseudoContext2 = "context2";
    const encContext2 = "session2";

    const session1Keys = makeSessionKeys(globalPrivateKey, encContext1, encSecret);
    const session2Keys = makeSessionKeys(globalPrivateKey, encContext2, encSecret);

    const pseudo = Pseudonym.random();
    const encPseudo = encryptPseudonym(pseudo, session1Keys.public);

    const random = GroupElement.random();
    const data = new DataPoint(random);
    const encData = encryptData(data, session1Keys.public);

    const decPseudo = decryptPseudonym(encPseudo, session1Keys.secret);
    const decData = decryptData(encData, session1Keys.secret);

    expect(pseudo.toHex()).toEqual(decPseudo.toHex());
    expect(data.toHex()).toEqual(decData.toHex());

    const pseudoInfo = new PseudonymizationInfo(pseudoContext1, pseudoContext2, encContext1, encContext2, pseudoSecret, encSecret);
    const rekeyInfo = new RekeyInfo(encContext1, encContext2, encSecret);

    const rekeyed = rekeyData(encData, rekeyInfo);
    const rekeyedDec = decryptData(rekeyed, session2Keys.secret);

    expect(data.toHex()).toEqual(rekeyedDec.toHex());

    const pseudonymized = pseudonymize(encPseudo, pseudoInfo);
    const pseudonymizedDec = decryptPseudonym(pseudonymized, session2Keys.secret);

    expect(pseudo.toHex()).not.toEqual(pseudonymizedDec.toHex());

    const revPseudonymized = pseudonymize(pseudonymized, pseudoInfo.rev());
    const revPseudonymizedDec = decryptPseudonym(revPseudonymized, session1Keys.secret);

    expect(pseudo.toHex()).toEqual(revPseudonymizedDec.toHex());
})