const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("sgn0", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/sgn0_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("sgn0(0) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: 0 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(1) == 1", async () => {
    const witness = await circuit.calculateWitness({ in: 1 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(2) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: 2 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(3) == 1", async () => {
    const witness = await circuit.calculateWitness({ in: 3 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(4) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: 4 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(-1) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: -1 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(-2) == 1", async () => {
    const witness = await circuit.calculateWitness({ in: -2 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(-3) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: -3 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(-4) == 1", async () => {
    const witness = await circuit.calculateWitness({ in: -4 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(-5) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: -5 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(0x42) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: 0x42 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("sgn0(0x348598972154312) == 0", async () => {
    const witness = await circuit.calculateWitness({ in: 0x348598972154312 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });


});
