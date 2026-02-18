const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

const a_x = 17198511433894968793465431674681704063214539090234231940658916129372939658280n;
const a_y = 7096022295031894750538718201677443509070855497286293707399348308180894474126n;
const b_x = 1370195182723755180330139957608574837756381581331631262925562351487402786675n;
const b_y = 4914841023884182990424920031862777928930597684365442051411609356476877989803n;

describe("BabyJubJub Sub", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/baby_jubjub_sub_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("A-B", async () => {
    const witness = await circuit.calculateWitness(
      { lhs: [a_x,a_y], rhs: [b_x, b_y] },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        13400200893630892187031549597377549332518924039038491829675818487460013008688n,
        17980483594907442009132964055924958470283850998225911884057066193996295304747n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("B-A", async () => {
    const witness = await circuit.calculateWitness(
      { lhs: [b_x,b_y], rhs: [a_x, a_y] },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        8488041978208383035214856147879725756029440361377542514022385699115795486929n,
        17980483594907442009132964055924958470283850998225911884057066193996295304747n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("A-0", async () => {
    const witness = await circuit.calculateWitness(
      { lhs: [a_x,a_y], rhs: [0, 1] },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        a_x,
        a_y,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("0-A", async () => {
    const witness = await circuit.calculateWitness(
      { lhs: [0,1], rhs: [a_x, a_y] },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        4689731437944306428780974070575571025333825310181802403039288057202868837337n, // -a_x
        a_y,
      ],
    });
    await circuit.checkConstraints(witness);
  });

});
