const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("encode to curve babyjubjub", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/encode_to_curve_babyjubjub_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("encode 0", async () => {
    const witness = await circuit.calculateWitness({ in: 0 }, true);
    await circuit.assertOut(witness, {
      out: [
        16605852874433019712683889710166313607515083375138125349412270828059484170936n,
        12075050546928691602283582412953179086742727007172364313655633055645374686589n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("encode 1", async () => {
    const witness = await circuit.calculateWitness({ in: 1 }, true);
    await circuit.assertOut(witness, {
      out: [
        11002900464198096423817765773353706001288532015233140864760905190252874214917n,
        7016440448871558243167195007792676864601939532400400318353119539635085686238n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("encode -1", async () => {
    const witness = await circuit.calculateWitness({ in: -1 }, true);
    const result = [
      3782842576138717538438883176712136907445115601566119479256805132436077088519n,
      3010305986415855129763133575752930058033131498892936791891502969519197518977n,
    ];
    await circuit.assertOut(witness, {
      out: result,
    });
    await circuit.checkConstraints(witness);
  });

  it("encode 0x42", async () => {
    const witness = await circuit.calculateWitness({ in: 0x42 }, true);
    const result = [
      16453178030699411958341692808730701741568100876455568813278163225032347056514n,
      5447922750205248208490261749483809853022174346498064122782172531486866662376n,
    ];
    await circuit.assertOut(witness, {
      out: result,
    });
    await circuit.checkConstraints(witness);
  });
});
