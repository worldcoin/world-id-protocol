const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("hash to field Poseidon2 t=3", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/hash_to_field_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness({ in: [42] }, true);
    await circuit.assertOut(witness, {
      out: 7897415424385838084099011472024798078244437790378445018734308668354447223317n,
    });
    await circuit.checkConstraints(witness);
  });
});
