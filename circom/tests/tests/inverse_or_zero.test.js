const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("inverse or zero", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/inverse_or_zero_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("InverseOrZero(0)", async () => {
    const witness = await circuit.calculateWitness({ in: 0 }, true);
    await circuit.assertOut(witness, {
      inv: 0
    });
    await circuit.checkConstraints(witness);
  });

  it("InverseOrZero(1)", async () => {
    const witness = await circuit.calculateWitness({ in: 1 }, true);
    await circuit.assertOut(witness, {
      inv: 1
    });
    await circuit.checkConstraints(witness);
  });

  it("InverseOrZero(2)", async () => {
    const witness = await circuit.calculateWitness({ in: 2 }, true);
    await circuit.assertOut(witness, {
      inv: 10944121435919637611123202872628637544274182200208017171849102093287904247809n
    });
    await circuit.checkConstraints(witness);
  });

  it("InverseOrZero(-1)", async () => {
    const witness = await circuit.calculateWitness({ in: -1 }, true);
    await circuit.assertOut(witness, {
      inv: 21888242871839275222246405745257275088548364400416034343698204186575808495616n
    });
    await circuit.checkConstraints(witness);
  });

  it("InverseOrZero(0x42)", async () => {
    const witness = await circuit.calculateWitness({ in: 0x42 }, true);
    await circuit.assertOut(witness, {
      inv: 19566762567250261183523302105608776215520507570068879186033243136484434867294n
    });
    await circuit.checkConstraints(witness);
  });
});
