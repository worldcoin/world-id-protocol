const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("clear cofactor baby jubjub", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/clear_cofactor_babyjubjub_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          19749237763777877504811025958859187282736077178612498967835952987338546424382n,
          9825651499528233657748386613879383508828535951494059213535798845190111515722n,
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [19639628802331067714920142964194687338561819679258049812441592321105943536842n, 11346329236507494865585709204927959305406795872019529850625216399990666158973n],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat1", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [19639628802331067714920142964194687338561819679258049812441592321105943536842n, 11346329236507494865585709204927959305406795872019529850625216399990666158973n],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [8209398687764479338874622630135315686212707031708372733707065788681004290804n, 7952524503094846254003139028504820220835142329118525005533786297154183575893n],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat2", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [8209398687764479338874622630135315686212707031708372733707065788681004290804n, 7952524503094846254003139028504820220835142329118525005533786297154183575893n],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [10873729373466187168732787656725114046976746925851753192500476549919102027549n, 12798037779934295567578517080349860047505013996760633587201983316944729077251n],
    });
    await circuit.checkConstraints(witness);
  });

  it("clear cofactor identity", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [0,1],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [0,1],
    });
    await circuit.checkConstraints(witness);
  });

});
