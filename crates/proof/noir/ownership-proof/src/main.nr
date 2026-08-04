pub(crate) mod constants;
pub(crate) mod types;
pub(crate) mod commitment;
pub(crate) mod merkle_proof;

use commitment::{generate_commitment, generate_message};
use constants::{MAX_DEPTH, NUM_KEYS};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use merkle_proof::{compute_merkle_root_poseidon2, merkle_leaf};
use std::field::bn254::assert_lt;
use types::OwnershipProofInputs;

pub fn main(
    merkle_root: pub Field,
    depth: pub Field,
    nonce: pub Field,
    expected_commitment: pub Field,
    context: pub Field,
    inputs: OwnershipProofInputs<MAX_DEPTH, NUM_KEYS>,
) {
    // 1. Generate query commitment and verify
    let commitment = generate_commitment(inputs.merkle_proof.leaf_index, inputs.commitment_blinder);
    assert(commitment == expected_commitment, "commitment mismatch");

    // 2. Verify authenticator signature to the expected message
    assert_lt(inputs.pk_index, NUM_KEYS as Field);
    let message = generate_message(commitment, nonce, context);
    let chosen_pk = inputs.user_pk[inputs.pk_index as u32];

    let is_valid = verify_eddsa_poseidon2(
        chosen_pk.x,
        chosen_pk.y,
        inputs.query_s,
        inputs.query_r,
        message,
    );
    assert(is_valid, "invalid signature");

    // 3. Compute and verify merkle inclusion proof
    let merkle_leaf = merkle_leaf(inputs.user_pk);
    let computed_root = compute_merkle_root_poseidon2(
        merkle_leaf,
        depth,
        inputs.merkle_proof.leaf_index,
        inputs.merkle_proof.siblings,
    );
    assert(computed_root == merkle_root, "merkle proof verification failed");
}

mod tests {
    use super::commitment::{generate_commitment, generate_message};
    use super::constants::{MAX_DEPTH, NUM_KEYS};
    use super::main;
    use super::merkle_proof::{compute_merkle_root_poseidon2, merkle_leaf};
    use super::types::{MerkleProof, OwnershipProofInputs, PublicKey};
    use eddsa_poseidon2::verify_eddsa_poseidon2;

    // A signature cannot be produced inside the circuit, so the key and signature below are taken
    // from `Prover.toml`
    global LEAF_INDEX: Field = 1;
    global COMMITMENT_BLINDER: Field = 999;
    global NONCE: Field = 1234567890;
    global CONTEXT: Field = 42;
    global DEPTH: Field = MAX_DEPTH as Field;

    global PK: PublicKey = PublicKey {
        x: 9230889302806843410427776577603967869139681576051679463468697945589251186930,
        y: 13340734779535463242937595182271680716556898913154048933923051173366500594068,
    };
    global QUERY_S: Field =
        910017447433905092614337544258235277431716510412736141199530925241413000074;
    global QUERY_R: [Field; 2] = [
        11748463473175932415456174210595149973052339513602937745261141508498295651118,
        11968271147063664615069879152051076702654398559067659777925074746865468544338,
    ];
    global SIBLINGS: [Field; MAX_DEPTH] = [
        0,
        15621590199821056450610068202457788725601603091791048810523422053872049975191,
        15180302612178352054084191513289999058431498575847349863917170755410077436260,
        20846426933296943402289409165716903143674406371782261099735847433924593192150,
        19570709311100149041770094415303300085749902031216638721752284824736726831172,
        11737142173000203701607979434185548337265641794352013537668027209469132654026,
        11865865012735342650993929214218361747705569437250152833912362711743119784159,
        1493463551715988755902230605042557878234810673525086316376178495918903796315,
        18746103596419850001763894956142528089435746267438407061601783590659355049966,
        21234194473503024590374857258930930634542887619436018385581872843343250130100,
        14681119568252857310414189897145410009875739166689283501408363922419813627484,
        13243470632183094581890559006623686685113540193867211988709619438324105679244,
        19463898140191333844443019106944343282402694318119383727674782613189581590092,
        10565902370220049529800497209344287504121041033501189980624875736992201671117,
        5560307625408070902174028041423028597194394554482880015024167821933869023078,
        20576730574720116265513866548855226316241518026808984067485384181494744706390,
        11166760821615661136366651998133963805984915741187325490784169611245269155689,
        13692603500396323648417392244466291089928913430742736835590182936663435788822,
        11129674755567463025028188404867541558752927519269975708924528737249823830641,
        6673535049007525806710184801639542254440636510496168661971704157154828514023,
        7958154589163466663626421142270206662020519181323839780192984613274682930816,
        3739156991379607404516753076057250171966250101655747790592556040569841550790,
        1334107297020502384420211493664486465203492095766400031330900935069700302301,
        20357028769054354174264046872903423695314313082869184437966002491602414517674,
        19392290367394672558538719012722289280213395590510602524366987685302929990731,
        7360502715619830055199267117332475946442427205382059394111067387016428818088,
        9629177338475347225553791169746168712988898028547587350296027054067573957412,
        21877160135037839571797468541807904053886800340144060811298025652177410263004,
        7105691694342706282901391345307729036900705570482804586768449537652208350743,
        15888057581779748293164452094398990053773731478520540058125130669204703869637,
    ];

    /// The order of the BabyJubJub scalar field, i.e. the modulus a signature's `s` is reduced by.
    global BABYJUBJUB_FR: Field =
        2736030358979909402780800718157159386076813972158567259200215660948447373041;

    /// The neutral point of BabyJubJub, the value unused authenticator key slots hold.
    //
    // O = (0,1). Reference: <https://docs.iden3.io/publications/pdfs/Baby-Jubjub.pdf> section 4.3.1
    global UNUSED_KEY: PublicKey = PublicKey { x: 0, y: 1 };

    /// `-PK`, a valid key in the same subgroup that the fixture signature was *not* made with.
    /// Negation in twisted Edwards form is `(-x, y)`.
    global OTHER_KEY: PublicKey = PublicKey { x: 0 - PK.x, y: PK.y };

    fn fixture_inputs() -> OwnershipProofInputs<MAX_DEPTH, NUM_KEYS> {
        let mut user_pk = [UNUSED_KEY; NUM_KEYS];
        user_pk[0] = PK;

        OwnershipProofInputs {
            user_pk,
            pk_index: 0,
            query_s: QUERY_S,
            query_r: QUERY_R,
            merkle_proof: MerkleProof { leaf_index: LEAF_INDEX, siblings: SIBLINGS },
            commitment_blinder: COMMITMENT_BLINDER,
        }
    }

    fn fixture_commitment() -> Field {
        generate_commitment(LEAF_INDEX, COMMITMENT_BLINDER)
    }

    /// The root the fixture's key set and sibling path hash up to at the full tree depth.
    fn merkle_root_of(inputs: OwnershipProofInputs<MAX_DEPTH, NUM_KEYS>) -> Field {
        compute_merkle_root_poseidon2(
            merkle_leaf(inputs.user_pk),
            DEPTH,
            inputs.merkle_proof.leaf_index,
            inputs.merkle_proof.siblings,
        )
    }

    #[test]
    fn test_main_accepts_valid_fixture() {
        let inputs = fixture_inputs();
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    // SECTION: commitment binding

    #[test(should_fail_with = "commitment mismatch")]
    fn test_main_rejects_wrong_expected_commitment() {
        let inputs = fixture_inputs();
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment() + 1,
            CONTEXT,
            inputs,
        );
    }

    /// A prover who does not know the blinder behind `expected_commitment` cannot substitute one.
    #[test(should_fail_with = "commitment mismatch")]
    fn test_main_rejects_tampered_commitment_blinder() {
        let mut inputs = fixture_inputs();
        inputs.commitment_blinder = COMMITMENT_BLINDER + 1;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// The commitment is bound to the leaf index, so it cannot be claimed for another leaf.
    #[test(should_fail_with = "commitment mismatch")]
    fn test_main_rejects_commitment_for_another_leaf_index() {
        let mut inputs = fixture_inputs();
        inputs.merkle_proof.leaf_index = LEAF_INDEX + 1;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    // SECTION: signature binding

    /// The nonce is bound into the signed message: replaying a proof under a fresh nonce fails.
    #[test(should_fail_with = "invalid signature")]
    fn test_main_rejects_wrong_nonce() {
        let inputs = fixture_inputs();
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE + 1,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// The context is bound into the signed message: a proof cannot be reused in another context.
    #[test(should_fail_with = "invalid signature")]
    fn test_main_rejects_wrong_context() {
        let inputs = fixture_inputs();
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT + 1,
            inputs,
        );
    }

    #[test(should_fail_with = "invalid signature")]
    fn test_main_rejects_tampered_signature_s() {
        let mut inputs = fixture_inputs();
        inputs.query_s = QUERY_S + 1;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// A different on-curve point for `R` does not satisfy the verification equation.
    #[test(should_fail_with = "invalid signature")]
    fn test_main_rejects_wrong_signature_r() {
        let mut inputs = fixture_inputs();
        inputs.query_r = [PK.x, PK.y];
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// Swapping `R`'s coordinates puts it off the curve, which the verifier rejects outright.
    #[test(should_fail_with = "R must be on curve")]
    fn test_main_rejects_off_curve_signature_r() {
        let mut inputs = fixture_inputs();
        inputs.query_r = [QUERY_R[1], QUERY_R[0]];
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// `s` must be canonical. `s + Fr` reduces to the same scalar, so accepting it would make
    /// signatures malleable. uses assert_lt so we can't check for a specific error
    #[test(should_fail)]
    fn test_main_rejects_non_canonical_signature_s() {
        let mut inputs = fixture_inputs();
        inputs.query_s = QUERY_S + BABYJUBJUB_FR;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// An all-zero signature over the neutral point must not pass as a valid one.
    #[test(should_fail_with = "invalid signature")]
    fn test_main_rejects_empty_signature() {
        let mut inputs = fixture_inputs();
        inputs.query_s = 0;
        inputs.query_r = [UNUSED_KEY.x, UNUSED_KEY.y];
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    // SECTION: key selection

    /// `pk_index` must select the key that produced the signature, not any registered key. The
    /// merkle root is re-derived from the same key set, so only the signature check can fail.
    #[test(should_fail_with = "invalid signature")]
    fn test_main_rejects_key_index_that_did_not_sign() {
        let mut inputs = fixture_inputs();
        inputs.user_pk[1] = OTHER_KEY;
        inputs.pk_index = 1;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// A key the signer does not hold cannot be swapped in, even with a matching merkle root.
    #[test(should_fail_with = "invalid signature")]
    fn test_main_rejects_substituted_public_key() {
        let mut inputs = fixture_inputs();
        inputs.user_pk[0] = OTHER_KEY;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// Unused key slots hold the neutral point, which the EdDSA verifier refuses as a public key.
    /// Selecting an empty slot therefore cannot produce a proof.
    #[test(should_fail_with = "Public key cannot be identity")]
    fn test_main_rejects_key_index_pointing_at_unused_slot() {
        let mut inputs = fixture_inputs();
        inputs.pk_index = 1;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    /// `pk_index` is constrained below `NUM_KEYS`, so it cannot read past the key set. The
    /// rejection comes from `assert_lt`.
    #[test(should_fail)]
    fn test_main_rejects_pk_index_at_num_keys() {
        let mut inputs = fixture_inputs();
        inputs.pk_index = NUM_KEYS as Field;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    #[test(should_fail)]
    fn test_main_rejects_pk_index_beyond_key_set() {
        let mut inputs = fixture_inputs();
        inputs.pk_index = 12345;
        main(
            merkle_root_of(inputs),
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    // SECTION: registry inclusion

    #[test(should_fail_with = "merkle proof verification failed")]
    fn test_main_rejects_wrong_merkle_root() {
        let inputs = fixture_inputs();
        main(
            merkle_root_of(inputs) + 1,
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    #[test(should_fail_with = "merkle proof verification failed")]
    fn test_main_rejects_tampered_sibling() {
        let inputs = fixture_inputs();
        let merkle_root = merkle_root_of(inputs);

        let mut tampered = inputs;
        tampered.merkle_proof.siblings[MAX_DEPTH - 1] += 1;
        main(
            merkle_root,
            DEPTH,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            tampered,
        );
    }

    #[test(should_fail_with = "merkle proof verification failed")]
    fn test_main_rejects_wrong_depth() {
        let inputs = fixture_inputs();
        main(
            merkle_root_of(inputs),
            DEPTH - 1,
            NONCE,
            fixture_commitment(),
            CONTEXT,
            inputs,
        );
    }

    // SECTION: EdDSA verification behaviour `main` relies on

    #[test]
    fn test_eddsa_accepts_fixture_signature() {
        let message = generate_message(fixture_commitment(), NONCE, CONTEXT);
        assert(verify_eddsa_poseidon2(PK.x, PK.y, QUERY_S, QUERY_R, message));
    }

    #[test]
    fn test_eddsa_rejects_signature_over_another_message() {
        let message = generate_message(fixture_commitment(), NONCE, CONTEXT) + 1;
        assert(!verify_eddsa_poseidon2(PK.x, PK.y, QUERY_S, QUERY_R, message));
    }

    #[test]
    fn test_eddsa_rejects_signature_under_another_key() {
        let message = generate_message(fixture_commitment(), NONCE, CONTEXT);
        assert(!verify_eddsa_poseidon2(OTHER_KEY.x, OTHER_KEY.y, QUERY_S, QUERY_R, message));
    }

    #[test(should_fail_with = "Public key cannot be identity")]
    fn test_eddsa_rejects_identity_public_key() {
        let message = generate_message(fixture_commitment(), NONCE, CONTEXT);
        let _ = verify_eddsa_poseidon2(UNUSED_KEY.x, UNUSED_KEY.y, QUERY_S, QUERY_R, message);
    }
}
