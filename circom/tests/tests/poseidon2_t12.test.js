const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("Poseidon2 t=12 kats", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/poseidon2_t12_test.circom"),
      { include: [path.join(__dirname, "../../poseidon2")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness({ in: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] }, true);
    await circuit.assertOut(witness, {
      out: [
        0x3014e0ec17029f7e4f5cfe8c7c54fc3df6a5f7539f6aa304b2f3c747a9105618n,
        0x2f90753e7aaf46c158cd12346da7dd37c3136353ec51525cabbaaf2b2350f9b2n,
        0x2e28bdc8b2c68b09da0cb653ee7e54eca909cf2ae010784554aa3e165b1a105fn,
        0x1d6a97ef87dbd3476a848af45beebe6b5d79cb047b37212e3e5839f1e80b397an,
        0x24e23df24b19b75f44218a08d107709d35561bc1b982cfc317d54568cd496519n,
        0x185a08e623b85e797844191a1f184f7b8fc486253919eb20f1186a8331757018n,
        0x069ed78df853a105c8949dae5b4e81cbe370e8f6e25735a688aa8ff3df9659ebn,
        0x284395d79b64123211a4a59b81a90f9cfa8d8314dccde4cef22ec1e31431efd3n,
        0x0f24be5a8c95e3504ead0da9e792b77d7056f94461d69b04b33ea5d239f8e444n,
        0x022469ccfef0ce5a237518c38dec31fc2804e633b3b365c23a9f703ca31ef393n,
        0x1fcdcee218d5a0101bd233d572f184964854d445ca08d2bd6df6ceba5651e322n,
        0x0905469a776b7d5a3f18841edb90fa0d8c6de479c2789c042dafefb367ad1a2bn
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat1", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x2954cb9ff6347d5c499f1fc52db830ea8fa29f01e77c979c5611ae2aaae0e3den,
          0x2e12b253c9034b6cc304cb4420dd4bf63c9216a8db85b157b55f45570fafbaa5n,
          0x2de62fca9606e83d76d60bd222c14d4413e9fff2d15f8864a18586b76b32a632n,
          0x053aa142100d013792bbd568174ebef586796425b95544a3f6a206a634be52cbn,
          0x22e8c7cd6ced3be1e324aa7ec1f6c7347c849792e943af4a6d20c962df7a8e00n,
          0x13a81629feaef1e972cb07eb6d159532540d824adc6447dc68ddd3d87f57d767n,
          0x2e28fe5682677d8cf856dac08146a2be10967e4a4e4f4566997862b2e6d05b2an,
          0x01d5081e49390999b33ea02ab069f0b8855d3fa8bbfd43f9121b4cf28783369bn,
          0x105dba4ad50f65b112ba7114004c8e78acdb8d82e503eff0bbdce42ae5ec7b31n,
          0x141fad864e665d79d8db92eda98782ffb2b2c2f9a3614b3fb777c52415e7d8ebn,
          0x222b0b923438c6a043369e9aa8eca0bbca03c6a27043cd522093da00e0f74967n,
          0x29a6fd647be4d6cd66d9a1113b7360370a4c6709218470c593429b96af7dabban
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x0257f0ad69a35000c0f2098903aca10697d8b0909bd7e95f54602daddfec71ffn,
        0x2d9ef8a8b201f129cf9ee4778dc349d8f07fef770b637c599869d38b210079a7n,
        0x28f7af08ebbd432d38e754beed5388259415787336308d3368afb59a7afaf483n,
        0x05ff1f845ae26942c954561231bbcbe486d11910dffb70b79eb4623ba0fc6ef0n,
        0x040e1059dbe09077cbfc249c44a14c15bd76d593223daeb3bb96d2c103e867f9n,
        0x0aa8fe67e12b6fd4bc4f43aabf21d3e2c0527a0d708fc15537e49b8138fb14ben,
        0x1c79772645dad9c4b23063d6af5caa9265477748de8d1cd6f09d8e8e7f0bfa3cn,
        0x1da93a274000eb66d6f0745165382a3ce35f8a6984f4f013913e05294113d80en,
        0x230a40b2e0b5c7f1421896cbadca811b6ab7bd7d550c009048a9a3f1b5102aa4n,
        0x19ba5c10d702746c2a91c418c7da7529fc7739ecc8b9ebb9930cf3882c734161n,
        0x20fb88db1e84b64a269d166dab1b4fb41eea93fc70e8ac70fba15c41ed94440an,
        0x026a4a32f3788bf37504e335a6565b53554c80f61dd4affa003d399a704a8916n
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat2", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x2668dc335384b37562764a5a19c9e518210e99df10eaadfd8234582773424edcn,
          0x1547f370a3afc9e04397c85b7a3c4fcb4a1a9a82c496f97a24586ddb2899991en,
          0x301401729a06d886a0e6994e5eeb05df0f132f1e296c7c27ede1ae6e635badb8n,
          0x1f3baa6f3437051086ca888b5bfdf4fd52c0d7dd0530e7ac7da2e28f18a3f8a9n,
          0x274c0f2fe96c00f0b5a429330c5d353f11df9be99d647de5ba2f304c93c16a0en,
          0x0fb1c188d5e118878c27d579087530bd62fac3244567a97eba7f894fbc769d44n,
          0x25954b4a8b7715fdba97363ab8eae609ffb4f8c4e21a95d0c5e33fbcd44b8e4en,
          0x27cb4b4b9dd72782a603042e9055c323528979f9e7cc20b9e9732c4a893b0240n,
          0x19945581bc40d43994ec03b221b67bc066c0acad440b8e088e053a0c48bdbb57n,
          0x1871e044e029613b440f0e4c42f7016f2d5996afba39803537cd43d231bed230n,
          0x2cc3e85d2fa143ec0d4360f4b9e818177aed14aa1729abda9fa599895b255b06n,
          0x263692e752e88ca26f0a11f287bc6e34ee9293960a3272317306cedcae431daan
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x2761fccbeda551f0c04e8b2ff444c1069d9f6b1ffbd27a6cdfada182ba8dcca0n,
        0x12229ab4e7120c8d3b6ce91a8dd6cbfab56b47c0a83f975c1a6e02f9e3d66ef2n,
        0x2f21544af0290c7c29df3aa46d799a0c0e90d1643598b45d6c5372699fcca267n,
        0x26e3da009605d1bba4a63c81b74274a52c61d0700084c8ea08bfd74fdac2d65dn,
        0x17de00cb801527c11534a372fcfabf0f671172b6e868b8d5be1c513065f3a11cn,
        0x1047b435887e2641c56bb84203a54971509ea420628366fa567588e66fd968c8n,
        0x165d2fb6addc9d82bf44c478ccbf2ab3f60d07eee609a4840367accb3ae309bbn,
        0x23fc43f57315da64e45970d84a4200312b65d7ec8c6778831e5f0bb03748bfb1n,
        0x2fce79cba7d35f3b7ded143dffd7f63ced3310a240fa9f8b87b3ad209cdcd999n,
        0x02f7c02befa262f3ee29bd5b7090500636c85bde0de0279166dd0fd9a4235aban,
        0x0ca46b5a35de6bba8669fbeac600724eea86fa910dfa5e7aea6644cd874bf6c1n,
        0x01eb392b97282a8841f0aee92cfecab3ce141aaf895e011dec35c41ff483a3c7n
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("kat3", async () => {
    const witness = await circuit.calculateWitness(
      {
        in: [
          0x12b0aa3d80398d5a38e8bd25d2e0deafd716d06d5b81226951fb503441fd05b0n,
          0x1b9dffbb066e42c5e5fe85e5850f542afb97ff19d0d9e336e13c342b1d856b00n,
          0x2feda7e3978df56ba8ff3b2f922c1dc14b1eeec68c5b4439c48fcb588dab04d4n,
          0x2412a693e4bb430dfe125d42dd27ef6796aa5243325c2da78de0f67387e6666cn,
          0x02173d9ff42d29fb20ac917034ca2b71ebe1c3fe601155505e5506f248a7b4e0n,
          0x0e4e6b1d12b4f45c77e827c9d3456a06f8e072549f5ad6fa306e9a43a803a605n,
          0x2150a663f9e09a48f2ebddae69702f805f876c4857e339312fccb02ee6ad7b21n,
          0x2e35e0cc3cef89f252e864a60c17a99a33992ea8dbb9c99c8d45d8a515499d09n,
          0x0ca9ed526f7bf21c7b1c94cc628da0bb5195a0219663dfb6205d3f6e58a64123n,
          0x283102b3b664803689b7455d3ac787e983718440d1629ab68099f844613bf82bn,
          0x113416a1d8301bacfdc5b45e533a93f7d00ea8882d1dc8a9f0dfd1ac13f8b138n,
          0x107b2566c5b160848eabecfa4b917f7a1ebb03e9593a57b7dd964fdd0263f221n
        ],
      },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0x16a931fb7416d55742ae30f51abaac8b2d50374461b45bd7c0d3944325cd892en,
        0x10ecf93f67f0a304cd49bc0701a89a649a22d407e7172e0d588e8efe39b9fc70n,
        0x1ef1c158ae71004e37af4e204fe4e8de4e09a6eda70526f8de2497a43a43aadfn,
        0x1d1d8ccf693996a2e6ee6911a46afddcfa21eaf13bdbd595b95da72de5cbb0f3n,
        0x0aa36ee23897734da0727d13d55a08708aa02b34e831d46351f2ddc697f90969n,
        0x0aca8aea0e6f9407a7e505bd4bbd17b236d960bde0de04ec8fc780b85db2c4d4n,
        0x15b91aade12b7ef464f05f0f2d1bb28e5351aae1b69b23459102fa8c749e8b59n,
        0x2d446ff7f6e277dadf83f087de11f06845edc688248fdafbde1d003fb67afb57n,
        0x21e2cdd361f7000d443656eee38424e84e6b8ea759f6166223104f5c1ae4145dn,
        0x0786373dd287cb1d1af2e54a065efd1ab958069279a0a42e2e902fb59c136e41n,
        0x20f80e49d40a3100f0e47d677efce1a5754aabbbe942a268f09435bff7fae158n,
        0x0de42ffbe0e04712b1d7d0f921567de60274c5889cb26ea4a843b3e8ff0ac7f6n
      ],
    });
    await circuit.checkConstraints(witness);
  });
});
