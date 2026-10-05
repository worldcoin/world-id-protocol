//! Known tests for the vectors in **WIP-100**.

use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AdditiveGroup, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, MontFp, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use taceo_oprf::core::{
    dlog_equality::DLogEqualityProof,
    oprf::{BlindingFactor, client::blind_query},
};
use world_id_primitives::{
    FieldElement, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    poseidon::{self, DomainSeparator, ds::CLAIMS_HASH_V1},
    sponge::hash_bytes_to_field_element,
};

const DS_EDDSA: &[u8] = b"EdDSA Signature";
const DS_HASH_TO_FIELD: &[u8] = b"OPRF_HashToField_BabyJubJub";
const DS_DLOG: &[u8] = b"DLOG Equality Proof";

#[test]
fn generator_matches_eip_2494_base_point() {
    let g = EdwardsAffine::generator();
    assert_eq!(
        g.x,
        MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553")
    );
    assert_eq!(
        g.y,
        MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203")
    );
    assert!(g.is_on_curve() && g.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn domain_separators_match_their_labels() {
    assert_eq!(
        ds(DS_EDDSA),
        MontFp!("360302137480307891234917541314130533")
    );
    assert_eq!(
        ds(DS_HASH_TO_FIELD),
        MontFp!("32627786498498119128812045057993354633158048678109587794777765218")
    );
    assert_eq!(
        ds(DS_DLOG),
        MontFp!("1523098184080632582082867317389990410064981862")
    );
    assert_eq!(
        ds(CLAIMS_HASH_V1.as_bytes()),
        MontFp!("1364962988938129392107510493566513")
    );
}

#[test]
fn permutation_t2() {
    let output = poseidon2::bn254::t2::permutation(&ascending_state::<2>());
    assert_eq!(
        output,
        [
            MontFp!(
                "13120422956170837922441672802975889424559262309139960702680326932494325745547"
            ),
            MontFp!("5923567162677888564808904842769941181302763723060647224839027357562627386465"),
        ]
    );
}

#[test]
fn permutation_t3() {
    let output = poseidon2::bn254::t3::permutation(&ascending_state::<3>());
    assert_eq!(
        output,
        [
            MontFp!("5297208644449048816064511434384511824916970985131888684874823260532015509555"),
            MontFp!(
                "21816030159894113985964609355246484851575571273661473159848781012394295965040"
            ),
            MontFp!(
                "13940986381491601233448981668101586453321811870310341844570924906201623195336"
            ),
        ]
    );
}

#[test]
fn permutation_t4() {
    let output = poseidon2::bn254::t4::permutation(&ascending_state::<4>());
    assert_eq!(
        output,
        [
            MontFp!("786823568102245344938517132468097745676732687098822989626730198331658606391"),
            MontFp!(
                "16105493617470833344375945651585194737369509580406730765188791202038211593826"
            ),
            MontFp!("2169165722086073256768101917994796590773204847633762971322389403847680713675"),
            MontFp!(
                "20837792685223053096472825292260687493226094382304778455120670180090619921530"
            ),
        ]
    );
}

#[test]
fn permutation_t8() {
    assert_eq!(
        poseidon2::bn254::t8::permutation(&ascending_state::<8>()),
        [
            MontFp!(
                "13163567864211573827878829467860137302577760599598440387954761704438999762399"
            ),
            MontFp!(
                "20455256474176316209572707628365862887207812418465031548192789068192434065861"
            ),
            MontFp!(
                "21622031586696647398529562584873094656572287904668581566093346191656615936784"
            ),
            MontFp!(
                "18320622048765136384409419776996464874987888500923344182439589703061890523284"
            ),
            MontFp!(
                "19915468795157938233689963601267136400922725821760118753901600546477081024243"
            ),
            MontFp!(
                "12383970660639123649548441396659012498414420037083153473614822644813849243474"
            ),
            MontFp!("9133088157465982496917058916696585316057943251337470087079495488316110895778"),
            MontFp!("5020935059501715015422969097649999023750915432550677386523662686145648636517"),
        ]
    );
}

#[test]
fn permutation_t16() {
    assert_eq!(
        poseidon2::bn254::t16::permutation(&ascending_state::<16>()),
        [
            MontFp!("7129053404014098913941583447102076532611276040718594073862066403012892177215"),
            MontFp!("5458683216916715697310099658604278457911373519210593239261146303695981710820"),
            MontFp!(
                "11764907654416682971926471140388165312909351793032868507449176373009888376893"
            ),
            MontFp!(
                "17363012907147515824232626923071954964539976031233523938322583063167173991942"
            ),
            MontFp!(
                "16754602647566413012759386310550362661092317428428132757066277153406453157400"
            ),
            MontFp!(
                "10442131742273378767812305849732860137449534508695657144865044457198204305243"
            ),
            MontFp!(
                "13315916208806700309353847107954103794241355430909228633658159683794835480566"
            ),
            MontFp!(
                "14675611827802190925530581036356245293764500457751312643178429199155385431971"
            ),
            MontFp!("3800671750689110886099899395588427301982955036566905831860793275457528754896"),
            MontFp!("863058427093450397617252284543198432424871511785791089866952153042503171268"),
            MontFp!(
                "16110421480974327191214802248220528120081914075253666769021797524181818259452"
            ),
            MontFp!("3050248777345249982082587219460801555485024010345812479213241978893548171998"),
            MontFp!("8005144369031495385854140476761376792991595443174132540148616210767138457404"),
            MontFp!("193712991007063517677674367979478243863141973963118958643316643360558925992"),
            MontFp!("6765341258738133397733055933640609905610288576122407133007925535267189590216"),
            MontFp!("6411743912316957490668095751870764077217660758836562678571866082387292213586"),
        ]
    );
}

#[test]
fn hash_to_field_vector() {
    assert_eq!(
        poseidon2::bn254::t3::permutation(&[ds(DS_HASH_TO_FIELD), Fq::ONE, Fq::ZERO])[1],
        MontFp!("10409509318069101293316722480711595867625349071847922195261332397736272636435")
    );
}

#[test]
fn variable_length_hash_vectors() {
    assert!(hash_bytes_to_field_element(CLAIMS_HASH_V1, &[]).is_err());
    assert_eq!(
        *hash_bytes_to_field_element(CLAIMS_HASH_V1, &ascending(31)).expect("non-empty"),
        MontFp!("12658306072862357948815044357476041793480954961275831694284480429814652585452")
    );
    assert_eq!(
        *hash_bytes_to_field_element(CLAIMS_HASH_V1, &ascending(32)).expect("non-empty"),
        MontFp!("7105501883046959224351664232028428089815911608118705425730076057190813037341")
    );
    assert_eq!(
        *hash_bytes_to_field_element(CLAIMS_HASH_V1, &ascending(465)).expect("non-empty"),
        MontFp!("13435504409435728907439603956434602577345452839959452028063546759536561347478")
    );
    assert_eq!(
        *hash_bytes_to_field_element(CLAIMS_HASH_V1, &ascending(466)).expect("non-empty"),
        MontFp!("15525893232164838192982873493581731321396161293199355856124601873305423262450")
    );
}

#[test]
fn node_compression_vectors() {
    assert_eq!(
        *poseidon::compress(FieldElement::ZERO, FieldElement::ZERO),
        MontFp!("15621590199821056450610068202457788725601603091791048810523422053872049975191")
    );
    assert_eq!(
        *poseidon::compress(1u64.into(), 2u64.into()),
        MontFp!("6588139247708940112588203339651261153905233202198520634825199962343944922547")
    );
}

#[test]
fn empty_tree_zero_nodes() {
    let nodes = zero_nodes();
    assert_eq!(
        nodes[1],
        MontFp!("15621590199821056450610068202457788725601603091791048810523422053872049975191")
    );
    assert_eq!(
        nodes[2],
        MontFp!("15180302612178352054084191513289999058431498575847349863917170755410077436260")
    );
    assert_eq!(
        nodes[TREE_DEPTH],
        MontFp!("15633048765234690365876053958277790002681834789256406938121001738966131111330"),
        "root of a wholly empty depth-30 tree"
    );
}

#[test]
fn inclusion_proof_root_at_depth_30() {
    assert_eq!(TREE_DEPTH, 30);
    let nodes = zero_nodes();
    let root: Fq =
        MontFp!("21449849969959258301263701183300082902700436494585373070244441970359881620262");
    let proof = MerkleInclusionProof::new(
        root.into(),
        1,
        core::array::from_fn::<_, TREE_DEPTH, _>(|i| nodes[i].into()),
    );
    assert!(proof.is_valid(42u64.into()));
    assert!(!proof.is_valid(43u64.into()));
}

#[test]
fn compressed_point_encodings() {
    assert_eq!(
        hex_compressed(&EdwardsAffine::generator()),
        "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
    );

    assert_eq!(
        hex_compressed(&-EdwardsAffine::generator()),
        "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f7037279a5"
    );

    let identity = EdwardsAffine::zero();
    assert_eq!(identity.x, Fq::ZERO);
    assert_eq!(identity.y, Fq::ONE);
    assert_eq!(
        hex_compressed(&identity),
        "0100000000000000000000000000000000000000000000000000000000000000"
    );
}
#[test]
fn eddsa_signature_vector() {
    let sk = EdDSAPrivateKey::from_bytes(
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let pk = sk.public();
    let message = Fq::from(42);
    let signature = sk.sign(message);

    assert_eq!(
        pk.pk.x,
        MontFp!("5743127613665812714027674485677763488557233128677239431720756512332055304469")
    );
    assert_eq!(
        pk.pk.y,
        MontFp!("6713952740716875958406247477052754272136198788949552789678520356076812341435")
    );
    assert_eq!(
        hex::encode(pk.to_compressed_bytes().expect("valid point")),
        "bb9015f1309156fdfddcda5e5922f1ae565f6e5b2e78d4e35f884e036cf6d70e"
    );

    assert_eq!(
        signature.r.x,
        MontFp!("4471796480099078564607791866308147318722757043758328908648489482326053658209")
    );
    assert_eq!(
        signature.r.y,
        MontFp!("16743942090139358314901240752948685648557595749372215854958283055038688657910")
    );
    assert_eq!(
        signature.s,
        MontFp!("1707871037059365895665483114747551425359126542652147321192782334073340268810")
    );
    assert_eq!(
        hex::encode(signature.to_compressed_bytes().expect("valid signature")),
        "f601e481eec3c9fac20942eed731b5c815194fd1416a3f0c7948ffdf41bc0425\
         0a91c15ded66fde2ecec499b86fd56a7aad62d409391584a9c126b8de99ec603"
    );

    let challenge = *poseidon::hash(
        DomainSeparator::<5>::new(DS_EDDSA),
        [signature.r.x, signature.r.y, pk.pk.x, pk.pk.y, message].map(FieldElement::from),
    );
    assert_eq!(
        challenge,
        MontFp!("14790550837438996768258768677587167620081417436968300740169708289833632123084")
    );
    assert!(pk.verify(message, &signature));
    assert!(!pk.verify(message + Fq::ONE, &signature));
}

#[test]
fn cofactored_signature_accepts_torsion_in_r() {
    let pk = EdDSAPublicKey {
        pk: EdwardsAffine::generator(),
    };
    let torsion = EdwardsAffine::new_unchecked(Fq::ZERO, -Fq::ONE);
    let signature = EdDSASignature {
        r: (pk.pk + torsion).into_affine(),
        s: MontFp!("427326129406822435681373102365063578330480770223021153266919590076109569430"),
    };
    let challenge = *poseidon::hash(
        DomainSeparator::<5>::new(DS_EDDSA),
        [signature.r.x, signature.r.y, pk.pk.x, pk.pk.y, Fq::from(42)].map(FieldElement::from),
    );
    assert_eq!(
        challenge,
        MontFp!("14107477924306369449585376693150860508714550631015857449267997894818346434634")
    );
    assert_eq!(signature.s, Fr::ONE + to_scalar(challenge));
    let residue = pk.pk * signature.s - signature.r - pk.pk * to_scalar(challenge);
    assert!(!residue.is_zero());
    assert!(pk.verify(Fq::from(42), &signature));
}

#[test]
fn encode_to_curve_vectors() {
    let p2 = encode_to_curve(Fq::from(2));
    assert_eq!(
        p2.x,
        MontFp!("20419487629862769727627645368371427138888560013459229812372534124769971005828")
    );
    assert_eq!(
        p2.y,
        MontFp!("7631771008065059170045692780763031490103103796767657363493053446444837523289")
    );

    let p42 = encode_to_curve(Fq::from(42));
    assert_eq!(
        p42.x,
        MontFp!("1368536874988764403285491466492470225763829673979223271328990939656695174872")
    );
    assert_eq!(
        p42.y,
        MontFp!("5918944744409897789209151589310931911112404737084812644826989226820698253694")
    );

    for point in [p2, p42] {
        assert!(point.is_on_curve());
        assert!(point.is_in_correct_subgroup_assuming_on_curve());
        assert!(!point.is_zero(), "callers must reject the identity");
    }
}

#[test]
fn dlog_equality_proof_vector() {
    let base_b = encode_to_curve(Fq::from(42));
    let witness = Fr::from(12345);
    let nonce = Fr::from(67890);

    let base_d = EdwardsAffine::generator();
    let point_a = (base_d * witness).into_affine();
    let point_c = (base_b * witness).into_affine();
    let commit_1 = (base_d * nonce).into_affine();
    let commit_2 = (base_b * nonce).into_affine();

    assert_eq!(
        point_a.x,
        MontFp!("19099552327547260981542886231210125691902505931204088720746463491300185142606")
    );
    assert_eq!(
        point_a.y,
        MontFp!("13276557205153692030187527501273228448057533426731746626187331221465573305487")
    );
    assert_eq!(
        point_c.x,
        MontFp!("1704386023042037258303736539892861539707201163487540094949081990693465165451")
    );
    assert_eq!(
        point_c.y,
        MontFp!("8768369809996482248064559070370438612828016885307150244744623529899299197157")
    );
    assert_eq!(
        commit_1.x,
        MontFp!("7560514331452906482367540963526316341247740678202978210835422163029445477658")
    );
    assert_eq!(
        commit_1.y,
        MontFp!("11610694160704858701950599566691828874575930603037515361903555914794501850944")
    );
    assert_eq!(
        commit_2.x,
        MontFp!("3490405731880058419043956475882448859018810273867088182397477099060627470353")
    );
    assert_eq!(
        commit_2.y,
        MontFp!("11594420891490965176904143623534974685648090668464922826887222168496451873187")
    );
    let challenge = *poseidon::hash(
        DomainSeparator::<12>::new(DS_DLOG),
        [
            point_a.x, point_a.y, base_b.x, base_b.y, point_c.x, point_c.y, base_d.x, base_d.y,
            commit_1.x, commit_1.y, commit_2.x, commit_2.y,
        ]
        .map(FieldElement::from),
    );
    assert_eq!(
        challenge,
        MontFp!("16671088874615503773909688665365363469394641783242006990890243365077833605068")
    );

    let response = nonce + to_scalar(challenge) * witness;
    assert_eq!(
        response,
        MontFp!("388554659608811743276554153883008978905828355147065499832325343644454488330")
    );
    let proof = DLogEqualityProof::new(challenge, response);
    assert!(proof.verify(point_a, base_b, point_c, base_d).is_ok());
    assert!(proof.verify(point_c, base_b, point_a, base_d).is_err());
}

fn ds(label: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(label)
}

fn to_scalar(value: Fq) -> Fr {
    Fr::from_le_bytes_mod_order(&value.into_bigint().to_bytes_le())
}

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

fn ascending_state<const T: usize>() -> [Fq; T] {
    core::array::from_fn(|i| Fq::from(u64::try_from(i).expect("width fits in u64")))
}

fn zero_nodes() -> Vec<Fq> {
    let mut node = Fq::ZERO;
    let mut nodes = vec![node];
    for _ in 0..TREE_DEPTH {
        node = *poseidon::compress(node.into(), node.into());
        nodes.push(node);
    }
    nodes
}

fn encode_to_curve(input: Fq) -> EdwardsAffine {
    // Blinding by one exposes EncodeToCurve through the public OPRF API.
    let identity_blinding = BlindingFactor::from_scalar(Fr::ONE).expect("non-zero");
    blind_query(input, identity_blinding).blinded_query()
}
