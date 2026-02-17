const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

const a_x =
  17198511433894968793465431674681704063214539090234231940658916129372939658280n;
const a_y =
  7096022295031894750538718201677443509070855497286293707399348308180894474126n;
const b_x =
  1370195182723755180330139957608574837756381581331631262925562351487402786675n;
const b_y =
  4914841023884182990424920031862777928930597684365442051411609356476877989803n;

describe("BabyJubJub On Curve Check", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/baby_jubjub_on_curve_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("check A on curve", async () => {
    const witness = await circuit.calculateWitness({ p: [a_x, a_y] }, true);
    await circuit.assertOut(witness, {
      out: [a_x, a_y],
    });
    await circuit.checkConstraints(witness);
  });

  it("check B on curve", async () => {
    const witness = await circuit.calculateWitness({ p: [b_x, b_y] }, true);
    await circuit.assertOut(witness, {
      out: [b_x, b_y],
    });
    await circuit.checkConstraints(witness);
  });

  it("check identity on curve", async () => {
    const witness = await circuit.calculateWitness({ p: [0, 1] }, true);
    await circuit.assertOut(witness, {
      out: [0, 1],
    });
    await circuit.checkConstraints(witness);
  });

  it("check (0,0) not on curve", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ p: [0, 0] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("check (Ax,By) not on curve", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ p: [a_x, b_y] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("check (Ax,Ax) not on curve", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ p: [a_x, a_x] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });
});
