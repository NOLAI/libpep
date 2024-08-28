const {
    DataPoint, decryptData, decryptPseudonym, encryptData,
    encryptPseudonym,
    GroupElement,
    makeGlobalKeys,
    makeSessionKeys,
    newRandomPseudonym, pseudonymize, rekeyData
} = require("../../pkg");

test('test high level', async () => {
    const globalKeys = makeGlobalKeys();
    const _globalPublicKey = globalKeys.public;
    const globalPrivateKey = globalKeys.secret;

    const pseudoSecret = "secret";
    const encSecret = "secret";

    const pseudoContext1 = "context1";
    const encContext1 = "session1";
    const pseudoContext2 = "context2";
    const encContext2 = "session2";

    const session1Keys = makeSessionKeys(globalPrivateKey, encContext1, encSecret);
    const session2Keys = makeSessionKeys(globalPrivateKey, encContext2, encSecret);

    const pseudo = newRandomPseudonym();
    const encPseudo = encryptPseudonym(pseudo, session1Keys.public);

    const random = GroupElement.random();
    const data = new DataPoint(random);
    const encData = encryptData(data, session1Keys.public);

    const decPseudo = decryptPseudonym(encPseudo, session1Keys.secret);
    const decData = decryptData(encData, session1Keys.secret);

    expect(pseudo["0"].toHex()).toEqual(decPseudo["0"].toHex());
    expect(data["0"].toHex()).toEqual(decData["0"].toHex());

    const rekeyed = rekeyData(encData, encContext1, encContext2, encSecret);
    const rekeyedDec = decryptData(rekeyed, session2Keys.secret);

    expect(data["0"].toHex()).toEqual(rekeyedDec["0"].toHex());

    const pseudonymized = pseudonymize(encPseudo, pseudoContext1, pseudoContext2, encContext1, encContext2, pseudoSecret, encSecret);
    const pseudonymizedDec = decryptPseudonym(pseudonymized, session2Keys.secret);

    expect(pseudo["0"].toHex()).not.toEqual(pseudonymizedDec["0"].toHex());

    const revPseudonymized = pseudonymize(pseudonymized, pseudoContext2, pseudoContext1, encContext2, encContext1, pseudoSecret, encSecret);
    const revPseudonymizedDec = decryptPseudonym(revPseudonymized, session1Keys.secret);

    expect(pseudo["0"].toHex()).toEqual(revPseudonymizedDec["0"].toHex());

})