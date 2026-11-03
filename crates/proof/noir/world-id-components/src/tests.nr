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
        sig: AUTH_SIG,
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

global NOW: Field = 1783446000;
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

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_credential_rejects_a_now_beyond_32_bits() {
    let _ = credential::verify(
        credential_public(),
        NOW + 0x100000000,
        1,
        credential_inputs(),
    );
}

// SECTION: World ID Authentication with the signing key in slot 3 of four registered keys

global SLOT_3_KEYS: [PublicKey; 4] = [
    PublicKey {
        x: 16403486683365168807410678668809953762244404106701258314670180797996653734428,
        y: 19889159345992055602614121295645113409337174535619030639158974512253806339,
    },
    PublicKey {
        x: 11001311774205851531114529321070231114614866085049674923628939064211988942423,
        y: 14470868678190347154585818421406763940185986390732919656502624314866579666526,
    },
    PublicKey {
        x: 1351475003155051577328796124157742341640180717260181083384001762704920710914,
        y: 546546516207329725641553443374532649612903126778446857061082668887569244892,
    },
    PublicKey {
        x: 3957518881285075985312824119417898257658695886958661273608975350001063452342,
        y: 57234495657912877717408109326583671350222980264881239973357079469712962662,
    },
];
global SLOT_3_SIG: Signature = Signature {
    s: 977398903115752930138364578060293689830390286354464231442371233051912463028,
    r: [
        12786572570126389649482623509750299896489528172617623680652398156672524010035,
        10923304075774932191957652773022250363837013335963080461012459151227619883945,
    ],
};
global SLOT_3_MESSAGE: Field = 0x05107303;
global SLOT_3_ROOT: Field =
    4711733747136252782523402458390808128582138054005898430522429112448313640253;

fn slot_3_account(pk_index: Field) -> AccountInputs {
    let mut user_pk = [PublicKey { x: 0, y: 1 }; NUM_KEYS];
    for i in 0..4 {
        user_pk[i] = SLOT_3_KEYS[i];
    }
    AccountInputs {
        user_pk,
        pk_index,
        sig: SLOT_3_SIG,
        leaf_index: 1,
        siblings: empty_subtree_siblings(),
    }
}

#[test]
fn test_authentication_vector_with_the_key_in_slot_3() {
    assert_eq(authentication::verify(SLOT_3_ROOT, SLOT_3_MESSAGE, slot_3_account(3)), 1);
}

#[test(should_fail_with = "invalid authorization signature")]
fn test_authentication_rejects_another_registered_slot() {
    let _ = authentication::verify(SLOT_3_ROOT, SLOT_3_MESSAGE, slot_3_account(2));
}

// SECTION: Credential validity bounds

#[test]
fn test_credential_is_valid_until_just_before_expiry() {
    let _ = credential::verify(credential_public(), 1899999999, 1, credential_inputs());
}

#[test(should_fail_with = "credential expired")]
fn test_credential_rejects_now_at_expiry() {
    let _ = credential::verify(credential_public(), 1900000000, 1, credential_inputs());
}

#[test]
fn test_credential_accepts_a_minimum_equal_to_genesis() {
    let mut public = credential_public();
    public.genesis_issued_at_min = 1600000000;
    let _ = credential::verify(public, NOW, 1, credential_inputs());
}

#[test(should_fail_with = "credential too recent")]
fn test_credential_rejects_a_minimum_after_genesis() {
    let mut public = credential_public();
    public.genesis_issued_at_min = 1600000001;
    let _ = credential::verify(public, NOW, 1, credential_inputs());
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_credential_rejects_an_issuer_version_beyond_8_bits() {
    let mut public = credential_public();
    public.issuer_version += 0x100;
    let _ = credential::verify(public, NOW, 1, credential_inputs());
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_credential_rejects_an_id_beyond_64_bits() {
    let mut inputs = credential_inputs();
    inputs.id += 0x10000000000000000;
    let _ = credential::verify(credential_public(), NOW, 1, inputs);
}
