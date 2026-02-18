const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("map to curve elligator 2", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/map_to_curve_elligator2_test.circom"),
      {
        include: [
          path.join(__dirname, "../../"),
        ],
      },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x2e5c8c8ff53da47080c341f261d1a10c1d54f6650b90bbed9dd30198ca1256b3n,
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        175237875522834448155549773453859181418677905226545111199128371026771239667n,
        21093709385442275369448476304363512163107465754712817413145095532362233379686n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("encode zero", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [0],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [0, 0],
    });
    await circuit.checkConstraints(witness);
  });

  it("encode 1 and -1 and check for equality", async () => {
    const witness_1 = await circuit.calculateWitness(
      {
        in: [1],
      },
      true,
    );
    const witness_neg1 = await circuit.calculateWitness(
      {
        in: [-1],
      },
      true,
    );
    const result = [
        14592161914559516814830937163504850059032242933610689562465469457717205523163n,
        19295415032761905889642384658646365873112747456829196877313925589830351592100n,
      ];
    await circuit.assertOut(witness_1, {
      out: result,
    });
    await circuit.checkConstraints(witness_1);
    await circuit.assertOut(witness_neg1, {
      out: result,
    });
    await circuit.checkConstraints(witness_neg1);
  });

  it("encode 2 and -2 and check for equality", async () => {
    const witness_2 = await circuit.calculateWitness(
      {
        in: [2],
      },
      true,
    );
    const witness_neg2 = await circuit.calculateWitness(
      {
        in: [-2],
      },
      true,
    );
    const result = [
        19803648312616487105841986150470867937258043981328792977631708549759064668703n,
        13727573273142503991283543845260329070609971662849521911601331219358639896120n,
      ];
    await circuit.assertOut(witness_2, {
      out: result,
    });
    await circuit.checkConstraints(witness_2);
    await circuit.assertOut(witness_neg2, {
      out: result,
    });
    await circuit.checkConstraints(witness_neg2);
  });

});
