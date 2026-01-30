const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("rational map mont -> twisted edwards baby jubjub", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(
        __dirname,
        "circuits/rational_map_mont_to_twisted_edwards_babyjubjub_test.circom",
      ),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          175237875522834448155549773453859181418677905226545111199128371026771239667n,
          794533486396999852797929440893762925440898645703216930553108654213575115931n,
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        19749237763777877504811025958859187282736077178612498967835952987338546424382n,
        9825651499528233657748386613879383508828535951494059213535798845190111515722n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat1", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          10648445053055756208483835589904638676661988556514516239690237683734442125505n,
          4802517896840021410932810118091198914414923462543984062792492592398104141457n,
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        9466255069464382829376229720059203306026642282376731717118956633769641656470n,
        12172554837077650910888073060921814542100819213660500362167557566341089258409n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("map identity", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [0, 1],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0,
        21888242871839275222246405745257275088548364400416034343698204186575808495616n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("map P(0,0)", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [0, 0],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [0, 1],
    });
    await circuit.checkConstraints(witness);
  });

  it("map P(1,1)", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [1, 0],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [0, 1],
    });
    await circuit.checkConstraints(witness);
  });

  it("map P(-1,-1)", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [-1, -1],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [0, 1],
    });
    await circuit.checkConstraints(witness);
  });
});
