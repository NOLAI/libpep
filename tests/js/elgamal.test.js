const {GroupElement, ScalarNonZero, encrypt, decrypt} = require("../../pkg");

test('encryption decryption', async () => {
    const G = GroupElement.G();
    const y = ScalarNonZero.random();
    const Y = G.mul(y);
    const m = GroupElement.random();
    const encrypted = encrypt(m, Y);
    const decrypted = decrypt(encrypted, y);
    expect(m.toHex()).toEqual(decrypted.toHex());
})