const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

const x_fq = 7635940231166461559743911368068085893223435965227444771661666474118272601539n;
const y_fq = 14410948882403828236940551690863828050999097843481586328909715729172535448142n;
const z_fq = 10116753512442813513341465614699062870687867030491728121605599588948473856102n;

const a_x = 13852210342980036242488216946117211826283486560286321713191426447557617672848n;
const a_y = 16619927274608990088320429324634738785056223501341385107818435812328029872233n;
const b_x = 11815925977257892037720315523139995537974726661448698895296473143293248776265n;
const b_y = 15672883364677039803777980168632673365350941870077356968171203160380631157209n;
const c_x = 18278048663260200973855255675276196898882350525216070151141140641897268569238n;
const c_y = 5813169746239956734894173676142183017479392820977892383701532143734147064073n;

describe("BabyJubJub Scalar Mul Base Field", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/baby_jubjub_scalar_mul_base_field_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("x*A", async () => {
    const witness = await circuit.calculateWitness(
      { e: x_fq, x: a_x, y: a_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        7331811952161354833759632466300792047971267791171092060693626004621688595462n,
        5664735800565765576027417760862991456206023655163487791029870349791491257049n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("y*A", async () => {
    const witness = await circuit.calculateWitness(
      { e: y_fq, x: a_x, y: a_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        12008956823787348271168946274019310253199160617201003646165755512453147106010n,
        20288474237081155321243134592591004810238835444910404958321897464835957722220n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("z*A", async () => {
    const witness = await circuit.calculateWitness(
      { e: z_fq, x: a_x, y: a_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        11344025440567798950084619308436425738898974976822886221698573349772381774843n,
        7660920130498268727246685075798179453665477623968188463703205807149810775106n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("x*B", async () => {
    const witness = await circuit.calculateWitness(
      { e: x_fq, x: b_x, y: b_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        11975952874758856689202098503678374903334918458907859623478663320733652022558n,
        21701989191654418172766581204730845179594605845822205409485284378276031534753n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("y*B", async () => {
    const witness = await circuit.calculateWitness(
      { e: y_fq, x: b_x, y: b_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        14535901858882786524525586646151931857777195908798910056140001825706076826155n,
        21059472500960235149700276248422425145807409244112954140801591549161213353546n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("z*B", async () => {
    const witness = await circuit.calculateWitness(
      { e: z_fq, x: b_x, y: b_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        13691758297345296020398810946947220872948081765672248594642486598154078831835n,
        12092527492015466207375283094997062840115857228825457794179266561345756046n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("0*A", async () => {
    const witness = await circuit.calculateWitness(
      { e: 0, x: a_x, y: a_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        0,
        1,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("1*B", async () => {
    const witness = await circuit.calculateWitness(
      { e: 1, x: b_x, y: b_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        b_x,
        b_y,
      ],
    });
    await circuit.checkConstraints(witness);
  });
});
