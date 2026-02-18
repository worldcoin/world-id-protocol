const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

const fr =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

describe("BabyJubJub is in Fr ", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/baby_jubjub_is_in_fr_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("Fr(0)", async () => {
    const witness = await circuit.calculateWitness({ in: 0 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Fr(1)", async () => {
    const witness = await circuit.calculateWitness({ in: 1 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("Fr(fr-1)", async () => {
    var fr_minus_one = fr - 1n;
    const witness = await circuit.calculateWitness({ in: fr_minus_one }, true);
    await circuit.assertOut(witness, {
      out: fr_minus_one,
    });
    await circuit.checkConstraints(witness);
  });

  it("Fr(fr) fails", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ in: fr }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("Fr(-1) fails", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ in: -1 }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });
});
