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

describe("BabyJubJub Identity Check", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/baby_jubjub_identity_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("Find identity", async () => {
    const witness = await circuit.calculateWitness({ p: [0, 1] }, true);
    await circuit.checkConstraints(witness);
  });

  it("Identity(A) fails", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ p: [a_x, a_y] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("Identity(B) fails", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ p: [b_x, b_y] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("Identity(0, a_y) fails", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ p: [0, a_y] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

  it("Identity(b_x, 1) fails", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ p: [b_x, 1] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });

});
