const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("Poseidon2 t=3 kats", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/poseidon2_t3_test.circom"),
      { include: [path.join(__dirname, "../../poseidon2")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness({ in: [0, 1, 2] }, true);
    await circuit.assertOut(witness, {
      out: [
        0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033n,
        0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570n,
        0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8n
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat1", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
        0x2c6422c33190d036a17bd4281738ad60a6b4544c1020da1c0c84880a0ddc71c4n,
        0x245cd98e5af9a6ebb35945b092c7e877ab9549c8919940250956a0bfedb457abn,
        0x0b43c424171231016dfe2072518b825a18c759383dba4e09a47bcd8b1a55da21n
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x0b6f503d74ca8c80934b48d8d9e41c239ea6bcee17f658d416a0b72fd7daf1b8n,
        0x2845997bb81ad9d29f0b7ba57550cb7160b6930c70c92287207c7b5f65b2814bn,
        0x0a97e625f336a7c5e51bb2881e3b4e224f6e2e01ae5d698fa19446dbc407ac3fn
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat2", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
        0x124ce2326b4a95fe09743697c1e5c9ac9f6940cab7221decfd0162a8873c63ean,
        0x167148c1014f9f1ae03bb93892ec0164c6f65f779b526c3499d7ac374e84af86n,
        0x18c0badc1c5aa472c434c254786f8e1aa8b519a7ec017dfd20bc1e5dfb820caan
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x2791fa7cca97f87cc3de6ce004bccf28e3cb631e4fd31d50b38fc79b7e43dbbfn,
        0x22e42774e15a97e78d378b0225379ecbcb76060beef46e10e4b630bbd256003bn,
        0x2e56288af3d63be34692074d7db4ce2f9eda91f7a55ba60d7661d8c2bfca9580n
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat3", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
        0x034f5155557b5e85db4fba5c254882f8658baa03376a38d37ff03fef1f850cfdn,
        0x23975b943c4070c2bc98ec66b4a9e1f0ca1c812b38317bdbfac98aa748b5b059n,
        0x03f9ef0d827a433a679060b654b556daa963c9658f628a3522dee7e839ab3615n
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x0014a5e7728d210b90ef439df76561371be410051332852cea084ef73271ccbdn,
        0x05c0808fa8657cb6091ee49fd5a0b32de2affeab6bed761043044982b3d7e3f5n,
        0x2f6cc98fa05d79737a559115be171d2863e65080353c281b2104bb17b01f9c49n
      ],
    });
    await circuit.checkConstraints(witness);
  });
});
