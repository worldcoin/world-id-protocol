const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("Poseidon2 t=8 kats", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/poseidon2_t8_test.circom"),
      { include: [path.join(__dirname, "../../poseidon2")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness({ in: [0, 1, 2, 3, 4, 5, 6, 7] }, true);
    await circuit.assertOut(witness, {
      out: [
        0x1d1a50bcde871247856df135d56a4ca61af575f1140ed9b1503c77528cf345dfn,
        0x2d3943cf476ed49fd8a636660d8a76c83b55f07d06bc082005ad7eb1a21791c5n,
        0x2fcda2dd846fadfde8104b1d05175dcf3cf8bd698ed8ea3ad2fbcf9c06e00310n,
        0x28811ac7e0829171f9d3d81f1c0ff8f34b360d407a16b331a1cb6b5d992de094n,
        0x2c07c1817cfccb67c1297935514885c07abad5a0e15477f6c076c0b0fb1ad6f3n,
        0x1b6114397199bc44e37437dd3ba1754dff007d3315bfcdcdc14ec27d02452f52n,
        0x1431250baf36fb61a07618caee4dd2f500da339a05c553e8f529a3349e617aa2n,
        0x0b19bfa00c8f1d505074130e7f8b49a8624b1905e280ceca5ba11099b081b265n
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat1", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x11e027e38a43d36a72be06d524c0856d027363f604c347937fd91acdd47e04f7n,
          0x28b51285afdea43557ffd2b5ad3ec85c08e1f718e263bf9e8709889d6bb9a745n,
          0x290a6954438d96f11db1a59092c454379c233b5a07bd0b70f29ea12c03a3b729n,
          0x06869a7aa196418515672ba3e3de0124866d8448d387e33d69de16cd0a0cd9d8n,
          0x2aa9acb0cfdabf42c8254db2fe4980c757daaffa7429e87bbbd5756334a01b86n,
          0x10356d863c177d1a97fd1a908b89a6ff0bccda3eae346c96ae8a72f3b44d59een,
          0x09b24b777e6352b7908cc4961942624f2725412f84c75ed93238ccd42b2efd49n,
          0x241fd4790bab98a9185d5b11d083ffe5360b3e2094bf1123142bcea4eadf6012n
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x301e58def5ed2e1a5dcaa44a9cd47919246011f39575de8212cd631da771686an,
        0x23d5d952e536aea304ebc4c83d206a8f1dff4c1480334ac954bb24e273ba2120n,
        0x12386a450b5c89202ee12619ff486c1c2ba39ae969b24f7b850afe0a7f0db2ean,
        0x1100f7e0935587cc6e3d2a59b69045e12c1e1ca3c442365c5769ea2df8c370a7n,
        0x20bc910a6ec6aacc4007e5dfc7bd7b51adfa1dae2516aa3060e15e5a42106b5en,
        0x0550bb9366d5da5470ac98c4e97fb12cb04e70fb1e47d17d365e9444a9860761n,
        0x1049903ff3d9d6a8286508e3e7b8e3f3d254228aa00c322ef9d305d3248b8754n,
        0x076dc291e1cdc9f48efeaf713a161de6d43e407133f38b82d56df9279d723de9n
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat2", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x25776de965f9e74ee70f66a4aa501b2e5bdd7f1dc2910bf1a060cc5fd746ed1en,
          0x2b5b27c3c2f2f6991ce700ba074c7cb8bad876e2a8f09e712310c50f77af22b0n,
          0x2f43305136fcb3ef1d0fa9347702dbcdddd8475ebb01d617a598add5b0d62acan,
          0x16812fd128edf911aa4f7e27568814a208023bc9ffa8183117efa78ff356734bn,
          0x0811490d27c169cc8a8a774c686cd25dfcebdbfdf9865152728f10b02f416a8an,
          0x04955c2c8ad3bab330220fb515cd610fd14f3a20d4c8939846580f46cf23b6afn,
          0x048ba851a27072d279d88094f1f3871974d645e1dbd9226fa35f81731ecea4e0n,
          0x065be967a2d16752761af356145ed461a2056ad0a7e9166940623e4d140b76a0n
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x01fdac4b572d213e5b5438a33af928caa48a2325ac8cc30239ceea2f45819e0en,
        0x1dd13703749821c20ece4e35213b89da18b635672d791e520196a00c6885f575n,
        0x0df6f1389b8d70c99487871540ca5e0cf4607cf5e4556bd2d039a14916bbdc17n,
        0x10d97ee74863b8809387176212ea8d7458d2fb89e5216e6e7fa80fba63c0af7an,
        0x1384c276930a90e80c8669d30a72706ff550e66e4b5becefa4a4a9f434419d9an,
        0x27848d26ca176da553cb66917754c38f234c00b0b0d28c2a48e1d5d15a8d8bd6n,
        0x108255dd7381e3b8af4bd33974092e732e5a1bc6be7e6974a9e7d3c4a77f4005n,
        0x2b95ca49b2b7e7316bd7832d29e3235bc3769ffd04b98671af8d116a2ac565een
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat3", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x03cab88b5d93ab657ab738c39575c2812e61f87d188d787ec9c920da592c2243n,
          0x1657057a76dc5a0846c28c33fbfcdfed94a3baea5daf495df4aa61ed4bad34d5n,
          0x050fc77fea82eb8ae11537eeeeee6cb66ad4f77810df293cb0ceb614fa86328an,
          0x0f5574ad89685ce5ae2beab6db16631d32b16789fc9a1d4178bc1b73ad83be17n,
          0x282d72510f9ca1e6fbc868d709137e17e516cc26654ec034fee1cf5bce179bc5n,
          0x1d84329514de9a7030a7ad080cc7683ba63de7b2b14c71611f0cb3565340e223n,
          0x2605438a072c04502ef613759e28d86b51dac43671182ce62250e7a806e4bf9cn,
          0x2aea2975994ffd70c4ff8b6c75840cca6736fde04f03aa784c1cc5b7a27b006fn
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x295df3c1a93aaf9c6e852d06fc490c2811646eb73143f55eb86e679b1ca7354dn,
        0x1ad9d7447e57f1c6ae9a8b2300349e2c9332e5edb6813e12e428922bb66630c6n,
        0x2697581dcc42d3162ea222c0b5a47b3ea975824909a707d0af1431a2a2932c87n,
        0x22829b572f388ea29335c16f079d9e1ea8081a1709e45b9be089932fa70b5e58n,
        0x0398a6b47097a23a0afba8d9b76e126befdf2fcd7742c3136600b751ed18c106n,
        0x203aaf9774c8d558d14c52085d9a4c2406394d0000e640f3372d0084ecc84aa1n,
        0x14be6fa6b09e9b03b603e75baa6a80764e170941fe782879d02988d0428a115dn,
        0x01579c9185a70c3885e75ad94de88c2b6237d7be5fb8f84ebd7c3f2733a04f3fn
      ],
    });
    await circuit.checkConstraints(witness);
  });
});
