const { wasm } = require("circom_tester");
const path = require("path");

// CRL holding four revoked credential ids, as a compressed sparse Merkle tree
// (Iden3 layout) with the Poseidon2 hashes from smt_hash_poseidon2.circom.
// The tree needs 20 levels for these keys; nLevels is 32.
// Fixtures generated with taceo-poseidon2.
const CRL_ROOT =
    9894853241070312559826468648221758705354266811117924818603644919943744122917n;

const ZEROS = new Array(32).fill(0n);
const sibs = (entries) => {
    const s = [...ZEROS];
    for (const [i, v] of entries) s[i] = v;
    return s;
};

// Path for an unrevoked key that terminates on an empty node.
const EMPTY_TERM = {
    key: 12176925761186149284n,
    old_key: 0n,
    old_value: 0n,
    is_old_0: 1n,
    crl_siblings: sibs([
        [
            2,
            19274922329925398520731754395183265830783456209449642478773788638090700085239n,
        ],
    ]),
};

// Path for an unrevoked key that terminates on a *different* leaf. This is the
// case that only exists in a compressed tree — a full fixed-depth tree always
// terminates on an empty node.
const LEAF_TERM = {
    key: 12176926860697776776n,
    old_key: 12176925761186149000n,
    old_value: 1n,
    is_old_0: 0n,
    crl_siblings: sibs([
        [
            3,
            6151720557088603710612623358072583076102554265920929133785974860364829561746n,
        ],
    ]),
};

// A revoked key. Its path reaches its own leaf, so old_key == key, which
// SMTVerifier rejects for a non-inclusion check.
const REVOKED = {
    key: 12176925761186149000n,
    old_key: 12176925761186149000n,
    old_value: 1n,
    is_old_0: 0n,
    crl_siblings: LEAF_TERM.crl_siblings,
};

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

describe("CRL non-membership (compressed SMT, nLevels=32)", function () {
    this.timeout(20000);

    let circuit;
    before(async () => {
        circuit = await wasm(
            path.join(
                __dirname,
                "circuits/crl_non_membership_smt_compressed_test.circom",
            ),
            { include: [path.join(__dirname, "../../")] },
        );
        await circuit.loadConstraints();
    });

    it("accepts a key whose path ends on an empty node", async () => {
        const w = await circuit.calculateWitness(
            { crl_root: CRL_ROOT, ...EMPTY_TERM },
            true,
        );
        await circuit.checkConstraints(w);
    });

    it("accepts a key whose path ends on a different leaf", async () => {
        const w = await circuit.calculateWitness(
            { crl_root: CRL_ROOT, ...LEAF_TERM },
            true,
        );
        await circuit.checkConstraints(w);
    });

    it("rejects a revoked key", async () => {
        await expectReject(circuit, { crl_root: CRL_ROOT, ...REVOKED }, "revoked key");
    });

    it("rejects claiming an empty terminal node on an occupied path", async () => {
        await expectReject(
            circuit,
            { crl_root: CRL_ROOT, ...LEAF_TERM, is_old_0: 1n, old_key: 0n, old_value: 0n },
            "forged isOld0",
        );
    });

    it("rejects a wrong root", async () => {
        await expectReject(
            circuit,
            { crl_root: CRL_ROOT + 1n, ...EMPTY_TERM },
            "root mismatch",
        );
    });

    it("rejects a tampered sibling", async () => {
        await expectReject(
            circuit,
            {
                crl_root: CRL_ROOT,
                ...EMPTY_TERM,
                crl_siblings: sibs([[2, 12345n]]),
            },
            "sibling mismatch",
        );
    });
});
