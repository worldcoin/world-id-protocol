const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("Poseidon2 t=4 kats", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/poseidon2_t4_test.circom"),
      { include: [path.join(__dirname, "../../poseidon2")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness({ in: [0, 1, 2, 3] }, true);
    await circuit.assertOut(witness, {
      out: [
        0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737n,
        0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662n,
        0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cbn,
        0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847an
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat1", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x0c8c9889597488008e2e96985b843092fa78004ac3406c9df51ed2b6cf1165cdn,
          0x20519dc2e54103607f781cb4c3e0728db3c0183b0d8e32b7a18b3ee7226d1866n,
          0x17f6e0269a9439e0cbafb92fb6a33448460becc662da31786bf22935ca8734edn,
          0x18bd21d391158c54dd641afa11a9020a2bc49948f16864fbaf161d746d49b3a8n
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x17853a421466990a70c8df0ca883fc9580968a8ff381c573ccdb2a17b4717f1an,
        0x16c5b3481f48b51a628fc4595f30198f9c7eef5315e126d668a555076d6b77b3n,
        0x06c6ff5c992138c00e99c9daa6a4eeb86cce3b1b8cc9fa8b30c3a9350dedd1cbn,
        0x0fb18430a0e66a85bdf65c38f2d23be9005c48fae709f297268d13bff5076b1cn
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat2", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x1854b7992ec5a1349e9ed40970bbae67373bf98cac98055c7baf28d664384085n,
          0x12d3bf93b4c656e57eb1f4e1fe74f4dc5dacd2b95f27a12f0cc51c8aad9b4cebn,
          0x26c5ff636e75996c5d4953e2f44fc31403710c59e017cc0c68d7f7b547e5e12dn,
          0x1c29859e1768d3def45f2a97f7f96fd13149e50bd809fe6f49ee960e9d625f3en
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x17d01a086c63a77d6315cd7a1cdbac3ca89534c1a1da4e778f5ce60bdc77b28fn,
        0x0c64c46dbae63fb3e07037ae5d732c5cdf0da73971b940dbd32b2aa5c0bd7a5fn,
        0x2bcdcd400e2f052facc52233728cea88f9088313746a0f44fc286c5b6fef5f8cn,
        0x0fb03a8ea938397d9aaacde31fd4510d89ad5a11d353603448d19bcd4bdcda8cn
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat3", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x24ad6b688e5398429ffb1e3ba8ab3cd798f9909155b45812325cba5a16d2d220n,
          0x300687b9652aa54e7cae4137d9408e3ddf88a869428998d30b86f788ce92e1d1n,
          0x2aaff3037bd20cd938462fbf41dac988afe9104d7794016c017a29aa411912d0n,
          0x195cf02bd9aeebd4482b3f72dc509221de8c2ebf37361f8766f600bc748de617n
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x143d9fb2ffcec25c75977edf8ffa3d3007cdd38e1bd4d64b0a6603b7e38380a7n,
        0x1d2b015c19154421416a0204b88da26fbb74fa545116bea2c1c252d8cc43f284n,
        0x25bcf030113a4e13e812ebefc4b2af53687c21729bc197462b1f52b9d38820ben,
        0x0758b5e5e91eadf63054e205c4239ad12b950fe183800db6e2673408a4ef2600n
      ],
    });
    await circuit.checkConstraints(witness);
  });
});
