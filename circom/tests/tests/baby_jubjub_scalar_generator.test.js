const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

const x_fr = 974702657547524289083458286093415891087722395818179653312912891021790281865n;
const y_fr = 1349391061432402225851424785187822365392125343576213258463045158875877862010n;

const fr = 2736030358979909402780800718157159386076813972158567259200215660948447373041n

describe("BabyJubJub Scalar Mul Generator", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/baby_jubjub_scalar_mul_generator_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("x*G", async () => {
    const witness = await circuit.calculateWitness(
      { e: x_fr },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        3322943142755818391083786311633865732275013709080773055448402582760648214744n,
        20636111337785873250338096741390126578174799478070997272759585020554374802955n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("y*G", async () => {
    const witness = await circuit.calculateWitness(
      { e: y_fr },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        2870379625012351628593970124156118223833415856138494526831180956452972122422n,
        10589417929847398204500845794414071982235286009994639476859311756874555325987n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("0*G", async () => {
    const witness = await circuit.calculateWitness(
      { e: 0 },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0,
        1,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("1*G", async () => {
    const witness = await circuit.calculateWitness(
      { e: 1 },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        5299619240641551281634865583518297030282874472190772894086521144482721001553n,
        16950150798460657717958625567821834550301663161624707787222815936182638968203n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("(Fr-1)*G", async () => {
    const witness = await circuit.calculateWitness(
      { e: fr - 1n },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        16588623631197723940611540161738978058265489928225261449611683042093087494064n,
        16950150798460657717958625567821834550301663161624707787222815936182638968203n,
      ],
    });
    await circuit.checkConstraints(witness);
  });
});
