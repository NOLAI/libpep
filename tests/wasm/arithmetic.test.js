const {GroupElement, ScalarNonZero, ScalarCanBeZero} = require("../../pkg/libpep.js");

test('GroupElement arithmetic', async () => {
    const a = GroupElement.fromHex("503f0bbed01007ad413d665131c48c4f92ad506704305873a2128f29430c2674");
    const b = GroupElement.fromHex("ceab6438bae4a0b5662afa5776029d60f1f2aa5440cf966bc4592fae088c5639");

    const c = a.add(b);
    const d = a.sub(b);

    expect(c.asHex()).toEqual("d4d8ae736b598e2e22754f5ef7a8c26dba41a7e934ad76170d5a1419bd42730a");
    expect(d.asHex()).toEqual("c008e64b609452d0a314365f76ff0b68d634f094ce3fa0a9f309e80696ab6f67");
});

test('Scalar arithmetic', async () => {
    const a = ScalarNonZero.fromHex("044214715d782745a36ededee498b31d882f5e6239db9f9443f6bfef04944906");
    const b = ScalarNonZero.fromHex("d8efcc0acb2b9cd29c698ab4a77d5139e3ce3c61ad5dc060db0820ab0c90470b");
    const c = GroupElement.fromHex("1818ef438e7856d71c46f6a486f3b6dbb67b6d0573c897bcdb9c8fe662928754");

    const d = a.mul(b);
    const e = a.invert();
    const f = c.mul(a);

    expect(d.asHex()).toEqual("70b1f2f67d2da167185b133cc1d5157d23bf43741aced485d42e0c791e1d3305");
    expect(e.asHex()).toEqual("6690b6c6f8571e72fe98fa368923c23f090d720419562451d20fa1e4ab556c01");
    expect(f.asHex()).toEqual("56bf55ebfd2fcb7bfc7cbe1208a95d6f5aa3f4842c5b2828375a75c4b78b3126");

    const g = ScalarCanBeZero.zero();
    expect(g.toNonZero()).toBeUndefined();
    const h = ScalarNonZero.fromHex("0000000000000000000000000000000000000000000000000000000000000000");
    expect(h).toBeUndefined();

    const i = ScalarCanBeZero.fromHex("ca1f7e593ba0c53440e3c6437784e5fbe7306d9686013e5978c4c2d89bc0b109");
    const j = ScalarCanBeZero.fromHex("d921b0febd39e59148ca5c35d157227667a7e8cd6d3b0fbbc973e0e54cb4390c");
    const k = i.add(j);
    const l = i.sub(j);
    expect(k.asHex()).toEqual("b66d38fbde76986eb2102cd669e2285d4fd85564f43c4d144238a3bee874eb05");
    expect(l.asHex()).toEqual("ded1c3b797c9f2facdb561b18426a29a808984c818c62e9eae50e2f24e0c780d");

});

