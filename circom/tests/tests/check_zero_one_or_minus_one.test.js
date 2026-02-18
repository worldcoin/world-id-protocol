const { wasm } = require("circom_tester");
const path = require("path");
const { expect } = require("chai");

describe("check x in {0,1,-1}", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/check_zero_one_or_minus_one.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("Check 0 passes constraints", async () => {
    const witness = await circuit.calculateWitness({ in: 0 }, true);
    await circuit.checkConstraints(witness);
  });

  it("Check 1 passes constraints", async () => {
    const witness = await circuit.calculateWitness({ in: 1 }, true);
    await circuit.checkConstraints(witness);
  });

  it("Check -1 passes constraints", async () => {
    const witness = await circuit.calculateWitness({ in: -1 }, true);
    await circuit.checkConstraints(witness);
  });

  it("Check 2 fails constraints", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ in: 2 }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("Check -2 fails constraints", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ in: -2 }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("Check 0x42 fails constraints", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ in: 0x42 }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });
});
