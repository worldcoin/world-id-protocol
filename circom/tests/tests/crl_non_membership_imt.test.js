const { wasm } = require("circom_tester");
const path = require("path");

// CRL holding four revoked credential ids, as an indexed Merkle tree of depth 20.
// Fixtures generated with taceo-poseidon2 (the crate the Rust side uses).
const CRL_ROOT =
    12097942214609829388685118057841084351999056154894183207750185805233777735055n;
const SIBLINGS = [
    9372719887031541198108091235758150371719549160393302887860947811248444522870n,
    1880039561619461064187878579465655207003051782534268597158967457067321768083n,
    5878617723720496186231161591013638732239712167591971584790793783701439699046n,
    20846426933296943402289409165716903143674406371782261099735847433924593192150n,
    19570709311100149041770094415303300085749902031216638721752284824736726831172n,
    11737142173000203701607979434185548337265641794352013537668027209469132654026n,
    11865865012735342650993929214218361747705569437250152833912362711743119784159n,
    1493463551715988755902230605042557878234810673525086316376178495918903796315n,
    18746103596419850001763894956142528089435746267438407061601783590659355049966n,
    21234194473503024590374857258930930634542887619436018385581872843343250130100n,
    14681119568252857310414189897145410009875739166689283501408363922419813627484n,
    13243470632183094581890559006623686685113540193867211988709619438324105679244n,
    19463898140191333844443019106944343282402694318119383727674782613189581590092n,
    10565902370220049529800497209344287504121041033501189980624875736992201671117n,
    5560307625408070902174028041423028597194394554482880015024167821933869023078n,
    20576730574720116265513866548855226316241518026808984067485384181494744706390n,
    11166760821615661136366651998133963805984915741187325490784169611245269155689n,
    13692603500396323648417392244466291089928913430742736835590182936663435788822n,
    11129674755567463025028188404867541558752927519269975708924528737249823830641n,
    6673535049007525806710184801639542254440636510496168661971704157154828514023n,
];
// Low leaf at index 2: the gap (12176925761186149000, 15000000000000000000).
const LOW_LEAF = {
    crl_low_value: 12176925761186149000n,
    crl_low_next_index: 3n,
    crl_low_next_value: 15000000000000000000n,
    crl_low_index: 2n,
};

function witness(key, overrides = {}) {
    return {
        crl_root: CRL_ROOT,
        crl_depth: 20n,
        key,
        low_value: LOW_LEAF.crl_low_value,
        low_next_index: LOW_LEAF.crl_low_next_index,
        low_next_value: LOW_LEAF.crl_low_next_value,
        low_index: LOW_LEAF.crl_low_index,
        crl_siblings: SIBLINGS,
        ...overrides,
    };
}

async function expectReject(circuit, input, what) {
    let failed = false;
    try {
        await circuit.calculateWitness(input, true);
    } catch (e) {
        failed = true;
    }
    if (!failed) {
        throw new Error(`expected rejection: ${what}`);
    }
}

describe("CRL non-membership (indexed Merkle tree, d=20)", function () {
    this.timeout(20000);

    let circuit;
    before(async () => {
        circuit = await wasm(
            path.join(__dirname, "circuits/crl_non_membership_imt_test.circom"),
            { include: [path.join(__dirname, "../../")] },
        );
        await circuit.loadConstraints();
    });

    it("accepts a key inside a gap", async () => {
        const w = await circuit.calculateWitness(witness(12176925761186149284n), true);
        await circuit.checkConstraints(w);
    });

    it("rejects a revoked key at the upper bound of the gap", async () => {
        // 15000000000000000000 is revoked. Its own leaf cannot serve as a low
        // leaf, so the closest forgery is the leaf whose gap ends at it.
        await expectReject(circuit, witness(15000000000000000000n), "revoked key");
    });

    it("rejects a revoked key at the lower bound of the gap", async () => {
        await expectReject(circuit, witness(12176925761186149000n), "revoked key");
    });

    it("rejects a key below the low leaf", async () => {
        await expectReject(circuit, witness(5000000000000000000n), "key below gap");
    });

    it("rejects a tampered low leaf", async () => {
        await expectReject(
            circuit,
            witness(12176925761186149284n, { low_next_value: 16000000000000000000n }),
            "leaf not in tree",
        );
    });

    it("rejects a wrong root", async () => {
        await expectReject(
            circuit,
            witness(12176925761186149284n, { crl_root: CRL_ROOT + 1n }),
            "root mismatch",
        );
    });
});
