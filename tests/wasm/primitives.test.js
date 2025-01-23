const {GroupElement, ScalarNonZero, encrypt, decrypt, rekey} = require("../../pkg/libpep.js");

test('rekey', async () => {
    const G = GroupElement.G();
    const y = ScalarNonZero.random();
    const Y = G.mul(y);

    const k = ScalarNonZero.random();
    const m = GroupElement.random();
    const encrypted = encrypt(m, Y);
    const rekeyed = rekey(encrypted, k);
    expect(rekeyed).not.toBeNull();
    expect(rekeyed).not.toEqual(encrypted);

    const ky = k.mul(y);
    const decrypted = decrypt(rekeyed, ky);

    expect(m.asHex()).toEqual(decrypted.asHex());
})