const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("is quadratic residue or zero", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/quadratic_residue_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("Check 0 should return true", async () => {
    const witness = await circuit.calculateWitness({ a: 0 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 1 should return true", async () => {
    const witness = await circuit.calculateWitness({ a: 1 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });


  it("Check 2 should return true", async () => {
    const witness = await circuit.calculateWitness({ a: 2 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 3 should return true", async () => {
    const witness = await circuit.calculateWitness({ a: 3 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 4 should return true", async () => {
    const witness = await circuit.calculateWitness({ a: 4 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });



  it("Check 5 should return false", async () => {
    const witness = await circuit.calculateWitness({ a: 5 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 5*5 should return true", async () => {
    const witness = await circuit.calculateWitness({ a: 5*5 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 5*5*5 should return false", async () => {
    const witness = await circuit.calculateWitness({ a: 5*5*5 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check -5 should return false", async () => {
    const witness = await circuit.calculateWitness({ a: -5 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 7 should return false", async () => {
    const witness = await circuit.calculateWitness({ a: 7 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 11 should return false", async () => {
    const witness = await circuit.calculateWitness({ a: 11 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 42 should return false", async () => {
    const witness = await circuit.calculateWitness({ a: 42 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check -1 should return true", async () => {
    const witness = await circuit.calculateWitness({ a: -1 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });
});
