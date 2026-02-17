const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

const x_fr = 974702657547524289083458286093415891087722395818179653312912891021790281865n;
const y_fr = 1349391061432402225851424785187822365392125343576213258463045158875877862010n;
const z_fr = 871327393485062856402920825038263058036569291482410961997174114099742208541n;

const a_x = 13852210342980036242488216946117211826283486560286321713191426447557617672848n;
const a_y = 16619927274608990088320429324634738785056223501341385107818435812328029872233n;
const b_x = 11815925977257892037720315523139995537974726661448698895296473143293248776265n;
const b_y = 15672883364677039803777980168632673365350941870077356968171203160380631157209n;
const c_x = 18278048663260200973855255675276196898882350525216070151141140641897268569238n;
const c_y = 5813169746239956734894173676142183017479392820977892383701532143734147064073n;

describe("BabyJubJub Scalar Mul", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/baby_jubjub_scalar_mul_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("x*A", async () => {
    const witness = await circuit.calculateWitness(
      { e: x_fr, x: a_x, y: a_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        8292168176599860036511313613086027608747613736967317894164668067301391989488n,
        14674236266082220100504201132673914726468524306290982654246184829622186531100n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("y*A", async () => {
    const witness = await circuit.calculateWitness(
      { e: y_fr, x: a_x, y: a_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        3448708339107175569635418677073863151360233938259595542706574019059228685795n,
        16502773804919056165006670757902657023983894592063706974197836117580162623540n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("z*A", async () => {
    const witness = await circuit.calculateWitness(
      { e: z_fr, x: a_x, y: a_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        11458114319089649497326903349697534971508172399640224023252589155711459883997n,
        8493383852066662203755167469227350534670723797789946493409226246333499340425n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("x*B", async () => {
    const witness = await circuit.calculateWitness(
      { e: x_fr, x: b_x, y: b_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        15446422568964186620462611899149379627064374963512605191644629544286006979626n,
        21389825699933786158101001040322501217739241891143897753149653134132766738677n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("y*B", async () => {
    const witness = await circuit.calculateWitness(
      { e: y_fr, x: b_x, y: b_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        7500655952075762766696880386567893301280686794344898300996439511359284765693n,
        1224007352433545158148351001508025160105244785704753725161108424312129872618n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("z*B", async () => {
    const witness = await circuit.calculateWitness(
      { e: z_fr, x: b_x, y: b_y },
      true,
    );
    await circuit.assertOut(witness, {
      out: [
        11022182374752428543244794640227296513207169075820780830224397034212120311087n,
        785863979921821253955515955372993427757581452797407760667255245110799432486n,
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
