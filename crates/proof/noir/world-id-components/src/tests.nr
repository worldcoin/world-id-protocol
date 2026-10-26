// Known-answer vectors for WIP-100 Appendix A1.10. Authentication reuses the WIP-103 Appendix A.1
// witness, Credential Verification and Session Commitment the WIP-202 fixture.
use super::{
    authentication,
    constants::{MAX_CLAIMS, MERKLE_DEPTH, NUM_KEYS},
    credential::{self, CredentialPublic},
    session,
    types::{AccountInputs, CredentialInputs, PublicKey, Signature},
};
use poseidon2::bn254::permutation;

/// `z[0] = 0`, `z[j + 1] = Compress(z[j], z[j])`: the empty-subtree sibling path.
fn empty_subtree_siblings() -> [Field; MERKLE_DEPTH] {
    let mut siblings: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
    for i in 1..MERKLE_DEPTH {
        let z = siblings[i - 1];
        siblings[i] = permutation::t2([z, z])[0] + z;
    }
    siblings
}

// SECTION: World ID Authentication (WIP-103 Appendix A.1)

global PK: PublicKey = PublicKey {
    x: 9230889302806843410427776577603967869139681576051679463468697945589251186930,
    y: 13340734779535463242937595182271680716556898913154048933923051173366500594068,
};
global AUTH_SIG: Signature = Signature {
    s: 910017447433905092614337544258235277431716510412736141199530925241413000074,
    r: [
        11748463473175932415456174210595149973052339513602937745261141508498295651118,
        11968271147063664615069879152051076702654398559067659777925074746865468544338,
    ],
};
global AUTH_MESSAGE: Field =
    10907257490204364861298213021646911497433160997351053623048368726659330366356;
global MERKLE_ROOT: Field =
    14215929515479009984751917935014344082150835663566579083007945264825305524498;

fn account() -> AccountInputs {
    let mut user_pk = [PublicKey { x: 0, y: 1 }; NUM_KEYS];
    user_pk[0] = PK;
    AccountInputs {
        user_pk,
        pk_index: 0,
        auth: AUTH_SIG,
        leaf_index: 1,
        siblings: empty_subtree_siblings(),
    }
}

#[test]
fn test_authentication_vector() {
    assert_eq(authentication::verify(MERKLE_ROOT, AUTH_MESSAGE, account()), 1);
}

#[test(should_fail_with = "invalid authorization signature")]
fn test_authentication_vector_rejects_other_message() {
    let _ = authentication::verify(MERKLE_ROOT, AUTH_MESSAGE + 1, account());
}

// SECTION: Credential Verification (WIP-202 fixture)

global NOW: u32 = 1783446000;
global CLAIM_0: Field =
    18221512155588497305747704225993744070660555059966222885154001906335959616602;

fn credential_public() -> CredentialPublic {
    CredentialPublic {
        cred_pk: PublicKey {
            x: 14798749425381380862307680523394443046889593920036401427304811477586694233049,
            y: 12968755499483333796470904991791972225213732697010974473747270661164777138792,
        },
        issuer_schema_id: 4242,
        issuer_version: 1,
        genesis_issued_at_min: 1500000000,
    }
}

fn credential_inputs() -> CredentialInputs {
    let mut claims: [Field; MAX_CLAIMS] = [0; MAX_CLAIMS];
    claims[0] = CLAIM_0;
    CredentialInputs {
        claims,
        associated_data_hash: 0,
        genesis_issued_at: 1600000000,
        expires_at: 1900000000,
        sub_blinding_factor: 777,
        id: 7,
        sig: Signature {
            s: 1525279079686285952558356098062551513368745174754899682158656069073151036299,
            r: [
                6181857795842669202945168662266359162524942635619480994480440699125152080861,
                19111743504371222395629924073909689069020645764122585978758137706674714991498,
            ],
        },
    }
}

#[test]
fn test_credential_sub_vector() {
    assert_eq(
        credential::compute_sub(1, 777),
        17013727709299444456449714748930165627683430121261365452639579493880092063629,
    );
}

#[test]
fn test_credential_vector() {
    let claims = credential::verify(credential_public(), NOW, 1, credential_inputs());
    assert_eq(claims[0], CLAIM_0);
}

#[test(should_fail_with = "invalid credential signature")]
fn test_credential_vector_rejects_other_leaf_index() {
    let _ = credential::verify(credential_public(), NOW, 2, credential_inputs());
}

// SECTION: Session Commitment (WIP-202 fixture)

global SESSION_ID: Field =
    6697484268586176009119486561889585674186999134622438745286630469585729473719;

#[test]
fn test_session_vector() {
    session::verify(SESSION_ID, 1, 555);
    session::verify(0, 1, 555);
}

#[test(should_fail_with = "session_id must be nil or the session commitment")]
fn test_session_vector_rejects_other_leaf_index() {
    session::verify(SESSION_ID, 2, 555);
}
