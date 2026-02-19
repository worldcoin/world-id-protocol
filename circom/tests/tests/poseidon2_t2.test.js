const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("Poseidon2 t=2 kats", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/poseidon2_t2_test.circom"),
      { include: [path.join(__dirname, "../../poseidon2")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness({ in: [0, 1] }, true);
    await circuit.assertOut(witness, {
      out: [
        0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878bn,
        0x0d189ec589c41b8cffa88cfc523618a055abe8192c70f75aa72fc514560f6c61n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat1", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x2f1df4234732c49ac7567c29d2e066308f807e1bbf0951136b7fccba2602ea9en,
          0x04a23083267080ae4ee1a3cb4173dbce507c86edcfdd02853b0399cdab611517n,
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x0d6e20ac92800c7b08438805fe94a871c5f756ec07a919923c4e007cf01fa87en,
        0x0d0e60f1acb65d948e7ff874e255c2c07a0f0ecc15e4d14209bc5d5715951ccbn,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat2", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x106babe89343a47ce296eed78129b6f7af056b46ad808b2cabb66f371180dd17n,
          0x2f01d999b6e58284d87640c08c49e96d538ba3ffba0c544090fe858dbb5bc28en,
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x08d523548b9f396c877536b5f96fdfd1826ecdc0c806e24ae328586e8a405d8fn,
        0x1c1c5eeb613b596dd524fe59264ae5ef173cbd271e7f476a5f15d56175cb7478n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat3", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x299c0a40411ed9d7de7792fa299b262937b21fabfa386fa761e3f079c1d9045fn,
          0x2ace2e81e39d97a8e6d83c9e50a8643f4bf01a1465177518558305e7ab254c62n,
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x2c62b5c08ee75aa967809de58131cb38e953fdbdccb9140ed92ea89adebcda85n,
        0x2c507b864995a399f7c1143f8c9dc67b7aca63419a2443a879715404a16ec6b8n,
      ],
    });
    await circuit.checkConstraints(witness);
  });
});
