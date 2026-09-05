//! Known-answer test vectors for WIP-100 ("Cryptographic Primitives for World ID Protocol").
//!
//! Every value asserted here is published in the "Test Vectors" section of
//! `docs/WIPs/wip-100.md`. The two MUST be changed together: if a constant here
//! moves, the specification is wrong or the implementation broke interoperability.
//!
//! Vectors are grouped to mirror the spec's section order.

use std::str::FromStr;

use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::EdDSAPrivateKey;
use ruint::aliases::U256;
use taceo_oprf::core::{
    dlog_equality::DLogEqualityProof,
    oprf::{BlindingFactor, client::blind_query},
};
use world_id_primitives::{TREE_DEPTH, sponge::hash_bytes_to_field_element};

/// Parses a decimal string as an $F_q$ element.
fn fq(decimal: &str) -> Fq {
    Fq::from_str(decimal).expect("valid F_q decimal")
}

/// Parses a decimal string as an $F_r$ element.
fn fr(decimal: &str) -> Fr {
    Fr::from_str(decimal).expect("valid F_r decimal")
}

/// Derives a domain separator from an ASCII label, per spec "Domain separators".
fn ds(label: &[u8]) -> Fq {
    assert!(label.len() <= 31, "labels are bounded at 31 bytes");
    Fq::from_be_bytes_mod_order(label)
}

/// $H_3$: `ds` in the capacity at index 0, inputs at 1.., digest at index 1.
fn h3(separator: Fq, inputs: &[Fq]) -> Fq {
    let mut state = [Fq::ZERO; 3];
    state[0] = separator;
    state[1..=inputs.len()].copy_from_slice(inputs);
    poseidon2::bn254::t3::permutation(&state)[1]
}

/// $H_8$, same construction at width 8.
fn h8(separator: Fq, inputs: &[Fq]) -> Fq {
    let mut state = [Fq::ZERO; 8];
    state[0] = separator;
    state[1..=inputs.len()].copy_from_slice(inputs);
    poseidon2::bn254::t8::permutation(&state)[1]
}

/// $H_{16}$, same construction at width 16.
fn h16(separator: Fq, inputs: &[Fq]) -> Fq {
    let mut state = [Fq::ZERO; 16];
    state[0] = separator;
    state[1..=inputs.len()].copy_from_slice(inputs);
    poseidon2::bn254::t16::permutation(&state)[1]
}

/// Davies-Meyer node compression: $P_2([x_L, x_R])[0] + x_L$.
fn compress(left: Fq, right: Fq) -> Fq {
    let mut state = poseidon2::bn254::t2::permutation(&[left, right]);
    state[0] += left;
    state[0]
}

/// Reduces an $F_q$ challenge into $F_r$ for use as a scalar.
fn to_scalar(value: Fq) -> Fr {
    Fr::from_le_bytes_mod_order(&value.into_bigint().to_bytes_le())
}

/// Ascending byte string `00 01 02 ..`, wrapping below 251 to stay non-repeating.
fn ascending(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).expect("bounded by 251"))
        .collect()
}

fn hex_compressed<T: CanonicalSerialize>(value: &T) -> String {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .expect("serialization into a Vec cannot fail");
    hex::encode(buf)
}

const DS_EDDSA: &[u8] = b"EdDSA Signature";
const DS_HASH_TO_FIELD: &[u8] = b"OPRF_HashToField_BabyJubJub";
const DS_DLOG: &[u8] = b"DLOG Equality Proof";
const DS_CLAIMS: &[u8] = b"CLAIMS_HASH_V1";

// --- Field and Curve -------------------------------------------------------

#[test]
fn curve_order_factors_as_cofactor_times_subgroup_order() {
    let n = U256::from_str_radix(
        "21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
    .expect("valid decimal");
    let r = U256::from_str_radix(
        "2736030358979909402780800718157159386076813972158567259200215660948447373041",
        10,
    )
    .expect("valid decimal");
    assert_eq!(r * U256::from(8u8), n, "n = h * r with h = 8");
}

#[test]
fn generator_matches_eip_2494_base_point() {
    let g = EdwardsAffine::generator();
    assert_eq!(
        g.x,
        fq("5299619240641551281634865583518297030282874472190772894086521144482721001553")
    );
    assert_eq!(
        g.y,
        fq("16950150798460657717958625567821834550301663161624707787222815936182638968203")
    );
    assert!(g.is_on_curve() && g.is_in_correct_subgroup_assuming_on_curve());
}

// --- Domain separators -----------------------------------------------------

#[test]
fn domain_separators_match_their_labels() {
    assert_eq!(ds(DS_EDDSA), fq("360302137480307891234917541314130533"));
    assert_eq!(
        ds(DS_HASH_TO_FIELD),
        fq("32627786498498119128812045057993354633158048678109587794777765218")
    );
    assert_eq!(
        ds(DS_DLOG),
        fq("1523098184080632582082867317389990410064981862")
    );
    assert_eq!(ds(DS_CLAIMS), fq("1364962988938129392107510493566513"));
}

// --- Poseidon2 permutation P_t ---------------------------------------------

#[test]
fn permutation_vectors_on_ascending_state() {
    let p2 = poseidon2::bn254::t2::permutation(&[Fq::from(0), Fq::from(1)]);
    assert_eq!(
        p2,
        [
            fq("13120422956170837922441672802975889424559262309139960702680326932494325745547"),
            fq("5923567162677888564808904842769941181302763723060647224839027357562627386465"),
        ]
    );

    let p3 = poseidon2::bn254::t3::permutation(&[Fq::from(0), Fq::from(1), Fq::from(2)]);
    assert_eq!(
        p3,
        [
            fq("5297208644449048816064511434384511824916970985131888684874823260532015509555"),
            fq("21816030159894113985964609355246484851575571273661473159848781012394295965040"),
            fq("13940986381491601233448981668101586453321811870310341844570924906201623195336"),
        ]
    );

    let p4 = poseidon2::bn254::t4::permutation(&ascending_state::<4>());
    assert_eq!(
        p4,
        [
            fq("786823568102245344938517132468097745676732687098822989626730198331658606391"),
            fq("16105493617470833344375945651585194737369509580406730765188791202038211593826"),
            fq("2169165722086073256768101917994796590773204847633762971322389403847680713675"),
            fq("20837792685223053096472825292260687493226094382304778455120670180090619921530"),
        ]
    );

    let p8 = poseidon2::bn254::t8::permutation(&ascending_state::<8>());
    assert_eq!(
        p8[0],
        fq("13163567864211573827878829467860137302577760599598440387954761704438999762399")
    );
    assert_eq!(
        p8[1],
        fq("20455256474176316209572707628365862887207812418465031548192789068192434065861")
    );

    let p16 = poseidon2::bn254::t16::permutation(&ascending_state::<16>());
    assert_eq!(
        p16[0],
        fq("7129053404014098913941583447102076532611276040718594073862066403012892177215")
    );
    assert_eq!(
        p16[1],
        fq("5458683216916715697310099658604278457911373519210593239261146303695981710820")
    );
}

/// State `[0, 1, .., T-1]`.
fn ascending_state<const T: usize>() -> [Fq; T] {
    core::array::from_fn(|i| Fq::from(u64::try_from(i).expect("width fits in u64")))
}

// --- Fixed-arity hash H_t --------------------------------------------------

#[test]
fn fixed_arity_hash_vector() {
    assert_eq!(
        h3(ds(DS_HASH_TO_FIELD), &[Fq::from(1)]),
        fq("10409509318069101293316722480711595867625349071847922195261332397736272636435")
    );
}

#[test]
fn zero_padding_collides_across_arities() {
    // The failure mode the spec's CAUTION box describes: k=1 and k=2 with a
    // trailing zero are the same permutation input, so they are the same digest.
    // This is why k MUST be fixed per domain separator.
    let separator = ds(DS_HASH_TO_FIELD);
    assert_eq!(
        h3(separator, &[Fq::from(1)]),
        h3(separator, &[Fq::from(1), Fq::ZERO]),
    );
}

// --- Variable-length hash H_var --------------------------------------------

#[test]
fn variable_length_hash_vectors() {
    // 5 bytes: a single partial chunk.
    assert_eq!(
        *hash_bytes_to_field_element(DS_CLAIMS, &ascending(5)).expect("non-empty"),
        fq("10211288575303974548876522708704799813789152253072508541903122365688547522837")
    );
    // 31 bytes: exactly one full chunk.
    assert_eq!(
        *hash_bytes_to_field_element(DS_CLAIMS, &ascending(31)).expect("non-empty"),
        fq("12658306072862357948815044357476041793480954961275831694284480429814652585452")
    );
    // 32 bytes: one full chunk plus a 1-byte tail, which is NOT zero-padded to 31.
    assert_eq!(
        *hash_bytes_to_field_element(DS_CLAIMS, &ascending(32)).expect("non-empty"),
        fq("7105501883046959224351664232028428089815911608118705425730076057190813037341")
    );
    // 466 bytes: 15 full chunks plus a tail, forcing a second permutation.
    assert_eq!(
        *hash_bytes_to_field_element(DS_CLAIMS, &ascending(466)).expect("non-empty"),
        fq("15525893232164838192982873493581731321396161293199355856124601873305423262450")
    );
}

#[test]
fn variable_length_hash_binds_length() {
    let a = hash_bytes_to_field_element(DS_CLAIMS, &ascending(31)).expect("non-empty");
    let b = hash_bytes_to_field_element(DS_CLAIMS, &ascending(32)).expect("non-empty");
    assert_ne!(a, b, "length is bound into the capacity tag");
}

// --- Merkle tree -----------------------------------------------------------

#[test]
fn node_compression_vectors() {
    assert_eq!(
        compress(Fq::ZERO, Fq::ZERO),
        fq("15621590199821056450610068202457788725601603091791048810523422053872049975191")
    );
    assert_eq!(
        compress(Fq::from(1), Fq::from(2)),
        fq("6588139247708940112588203339651261153905233202198520634825199962343944922547")
    );
}

/// Empty-subtree roots: `z_0 = 0`, `z_{j+1} = Compress(z_j, z_j)`.
fn zero_nodes() -> Vec<Fq> {
    let mut node = Fq::ZERO;
    let mut nodes = vec![node];
    for _ in 0..TREE_DEPTH {
        node = compress(node, node);
        nodes.push(node);
    }
    nodes
}

#[test]
fn empty_tree_zero_nodes() {
    let nodes = zero_nodes();
    assert_eq!(
        nodes[1],
        fq("15621590199821056450610068202457788725601603091791048810523422053872049975191")
    );
    assert_eq!(
        nodes[2],
        fq("15180302612178352054084191513289999058431498575847349863917170755410077436260")
    );
    assert_eq!(
        nodes[TREE_DEPTH],
        fq("15633048765234690365876053958277790002681834789256406938121001738966131111330"),
        "root of a wholly empty depth-30 tree"
    );
}

#[test]
fn inclusion_proof_root_at_depth_30() {
    let nodes = zero_nodes();
    let leaf = Fq::from(42);
    let index: u64 = 1;

    let mut node = leaf;
    for (j, sibling) in nodes.iter().take(TREE_DEPTH).enumerate() {
        node = if (index >> j) & 1 == 0 {
            compress(node, *sibling)
        } else {
            compress(*sibling, node)
        };
    }

    assert_eq!(
        node,
        fq("21449849969959258301263701183300082902700436494585373070244441970359881620262")
    );
}

// --- Public key representation ---------------------------------------------

#[test]
fn compressed_point_encodings() {
    assert_eq!(
        hex_compressed(&EdwardsAffine::generator()),
        "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
    );

    let identity = EdwardsAffine::zero();
    assert_eq!(identity.x, Fq::ZERO);
    assert_eq!(identity.y, Fq::ONE);
    assert_eq!(
        hex_compressed(&identity),
        "0100000000000000000000000000000000000000000000000000000000000000"
    );
}

// --- Signatures ------------------------------------------------------------

/// Seed `00 01 .. 1f`, the private key for the signature vectors.
fn signing_seed() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i).expect("index below 32"))
}

#[test]
fn eddsa_signature_vector() {
    let sk = EdDSAPrivateKey::from_bytes(signing_seed());
    let pk = sk.public();
    let message = Fq::from(42);
    let signature = sk.sign(message);

    assert_eq!(
        hex::encode(signing_seed()),
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    assert_eq!(
        pk.pk.x,
        fq("5743127613665812714027674485677763488557233128677239431720756512332055304469")
    );
    assert_eq!(
        pk.pk.y,
        fq("6713952740716875958406247477052754272136198788949552789678520356076812341435")
    );
    assert_eq!(
        hex::encode(pk.to_compressed_bytes().expect("valid point")),
        "bb9015f1309156fdfddcda5e5922f1ae565f6e5b2e78d4e35f884e036cf6d70e"
    );

    assert_eq!(
        signature.r.x,
        fq("4471796480099078564607791866308147318722757043758328908648489482326053658209")
    );
    assert_eq!(
        signature.r.y,
        fq("16743942090139358314901240752948685648557595749372215854958283055038688657910")
    );
    assert_eq!(
        signature.s,
        fr("1707871037059365895665483114747551425359126542652147321192782334073340268810")
    );
    assert_eq!(
        hex::encode(signature.to_compressed_bytes().expect("valid signature")),
        "f601e481eec3c9fac20942eed731b5c815194fd1416a3f0c7948ffdf41bc0425\
         0a91c15ded66fde2ecec499b86fd56a7aad62d409391584a9c126b8de99ec603"
    );

    assert!(pk.verify(message, &signature));
}

#[test]
fn eddsa_challenge_and_cofactored_equation_follow_the_spec() {
    let sk = EdDSAPrivateKey::from_bytes(signing_seed());
    let pk = sk.public();
    let message = Fq::from(42);
    let signature = sk.sign(message);

    // e = H_8(ds; R_x, R_y, pk_x, pk_y, M)
    let challenge = h8(
        ds(DS_EDDSA),
        &[signature.r.x, signature.r.y, pk.pk.x, pk.pk.y, message],
    );
    assert_eq!(
        challenge,
        fq("14790550837438996768258768677587167620081417436968300740169708289833632123084")
    );

    // h * (sG - R - e*pk) = O, with h = 8.
    let mut residue =
        (EdwardsAffine::generator() * signature.s) - signature.r - (pk.pk * to_scalar(challenge));
    residue.double_in_place();
    residue.double_in_place();
    residue.double_in_place();
    assert!(
        residue.is_zero(),
        "spec challenge reproduces a signature the implementation accepts"
    );
}

// --- Hash to curve ---------------------------------------------------------

/// `EncodeToCurve` is reachable through `blind_query` with a blinding factor of 1.
fn encode_to_curve(input: Fq) -> EdwardsAffine {
    let identity_blinding = BlindingFactor::from_scalar(Fr::ONE).expect("non-zero");
    blind_query(input, identity_blinding).blinded_query()
}

#[test]
fn encode_to_curve_vectors() {
    let p1 = encode_to_curve(Fq::from(1));
    assert_eq!(
        p1.x,
        fq("11002900464198096423817765773353706001288532015233140864760905190252874214917")
    );
    assert_eq!(
        p1.y,
        fq("7016440448871558243167195007792676864601939532400400318353119539635085686238")
    );

    let p42 = encode_to_curve(Fq::from(42));
    assert_eq!(
        p42.x,
        fq("1368536874988764403285491466492470225763829673979223271328990939656695174872")
    );
    assert_eq!(
        p42.y,
        fq("5918944744409897789209151589310931911112404737084812644826989226820698253694")
    );

    for point in [p1, p42] {
        assert!(point.is_on_curve());
        assert!(point.is_in_correct_subgroup_assuming_on_curve());
        assert!(!point.is_zero(), "callers must reject the identity");
    }
}

#[test]
fn hash_to_field_is_h3_over_the_allocated_separator() {
    // HashToField(x) = H_3(ds_H2F; x), the first step of EncodeToCurve.
    assert_eq!(
        h3(ds(DS_HASH_TO_FIELD), &[Fq::from(1)]),
        fq("10409509318069101293316722480711595867625349071847922195261332397736272636435")
    );
}

// --- Discrete logarithm equality proof -------------------------------------

#[test]
fn dlog_equality_proof_vector() {
    let base_b = encode_to_curve(Fq::from(42));
    let witness = fr("12345");
    let nonce = fr("67890");

    let base_d = EdwardsAffine::generator();
    let point_a = (base_d * witness).into_affine();
    let point_c = (base_b * witness).into_affine();
    let commit_1 = (base_d * nonce).into_affine();
    let commit_2 = (base_b * nonce).into_affine();

    assert_eq!(
        point_a.x,
        fq("19099552327547260981542886231210125691902505931204088720746463491300185142606")
    );
    assert_eq!(
        point_a.y,
        fq("13276557205153692030187527501273228448057533426731746626187331221465573305487")
    );
    assert_eq!(
        point_c.x,
        fq("1704386023042037258303736539892861539707201163487540094949081990693465165451")
    );
    assert_eq!(
        point_c.y,
        fq("8768369809996482248064559070370438612828016885307150244744623529899299197157")
    );
    assert_eq!(
        commit_1.x,
        fq("7560514331452906482367540963526316341247740678202978210835422163029445477658")
    );
    assert_eq!(
        commit_1.y,
        fq("11610694160704858701950599566691828874575930603037515361903555914794501850944")
    );
    assert_eq!(
        commit_2.x,
        fq("3490405731880058419043956475882448859018810273867088182397477099060627470353")
    );
    assert_eq!(
        commit_2.y,
        fq("11594420891490965176904143623534974685648090668464922826887222168496451873187")
    );

    // e = H_16(ds; A, B, C, D, R1, R2), each point as x then y.
    let challenge = h16(
        ds(DS_DLOG),
        &[
            point_a.x, point_a.y, base_b.x, base_b.y, point_c.x, point_c.y, base_d.x, base_d.y,
            commit_1.x, commit_1.y, commit_2.x, commit_2.y,
        ],
    );
    assert_eq!(
        challenge,
        fq("16671088874615503773909688665365363469394641783242006990890243365077833605068")
    );

    let response = nonce + to_scalar(challenge) * witness;
    assert_eq!(
        response,
        fr("388554659608811743276554153883008978905828355147065499832325343644454488330")
    );

    // The operand order above is normative: a proof built from it must verify.
    assert!(
        DLogEqualityProof::new(challenge, response)
            .verify(point_a, base_b, point_c, base_d)
            .is_ok()
    );
}

#[test]
fn dlog_equality_proof_rejects_a_permuted_statement() {
    let base_b = encode_to_curve(Fq::from(42));
    let witness = fr("12345");
    let base_d = EdwardsAffine::generator();
    let point_a = (base_d * witness).into_affine();
    let point_c = (base_b * witness).into_affine();

    let challenge =
        fq("16671088874615503773909688665365363469394641783242006990890243365077833605068");
    let response =
        fr("388554659608811743276554153883008978905828355147065499832325343644454488330");

    // Swapping A and C moves the statement; the challenge no longer recomputes.
    assert!(
        DLogEqualityProof::new(challenge, response)
            .verify(point_c, base_b, point_a, base_d)
            .is_err()
    );
}
