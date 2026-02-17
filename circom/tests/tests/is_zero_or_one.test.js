const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("is zero or one", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/is_zero_or_one_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("Check 0 should return true", async () => {
    const witness = await circuit.calculateWitness({ in: 0 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 1 should return true", async () => {
    const witness = await circuit.calculateWitness({ in: 1 }, true);
    await circuit.assertOut(witness, {
      out: 1,
    });
    await circuit.checkConstraints(witness);
  });


  it("Check 2 should return false", async () => {
    const witness = await circuit.calculateWitness({ in: 2 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check -1 should return false", async () => {
    const witness = await circuit.calculateWitness({ in: -1 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

  it("Check 42 should return false", async () => {
    const witness = await circuit.calculateWitness({ in: 42 }, true);
    await circuit.assertOut(witness, {
      out: 0,
    });
    await circuit.checkConstraints(witness);
  });

});
