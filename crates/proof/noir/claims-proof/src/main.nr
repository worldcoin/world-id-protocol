use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;
use std::field::bn254::assert_lt;

global NUM_CLAIMS: u32 = 15;
global MAX_U64_PLUS_ONE: Field = 18446744073709551616;

// Protocol domain separators, represented as capacity field elements.
global DS_CREDENTIAL_SUB: Field = 87492525752134038588518953; // b"H_CS(id, r)"
global DS_CREDENTIAL: Field = 1790969822004668215611014194230797064349043274; // b"POSEIDON2+EDDSA-BJJ"
global DS_OPRF_QUERY: Field = 1773399373884719043551600379785849; // b"World ID Query"
global DS_NULLIFIER: Field = 1773399373884719043551596035141478; // b"World ID Proof"

/// A public predicate over the claim in the corresponding fixed credential slot.
///
/// `checks[0]` enables the strict lower bound and `checks[1]` enables the strict
/// upper bound. The claim itself remains private.
pub struct ClaimsStatement {
    pub checks: [Field; 2],
    pub range_check_min: Field,
    pub range_check_max: Field,
}

pub struct ClaimsStatementInputs {
    pub statements: [ClaimsStatement; NUM_CLAIMS],
}

pub struct CredentialPublicInputs {
    pub issuer_schema_id: Field,
    pub cred_pk: [Field; 2],
    pub current_timestamp: Field,
    pub cred_genesis_issued_at_min: Field,
}

pub struct NullifierPublicInputs {
    pub value: Field,
    pub rp_id: Field,
    pub action: Field,
}

pub struct ClaimsProofPublicInputs {
    pub claims: ClaimsStatementInputs,
    pub credential: CredentialPublicInputs,
    pub nullifier: NullifierPublicInputs,
}

pub struct CredentialPrivateInputs {
    pub cred_genesis_issued_at: Field,
    pub cred_expires_at: Field,
    pub associated_data_hash: Field,
    pub cred_id: Field,
    pub cred_user_id_r: Field,
    pub cred_s: Field,
    pub cred_r: [Field; 2],
}

pub struct NullifierPrivateInputs {
    pub leaf_index: Field,
    pub oprf_response: [Field; 2],
}

/// Private values which connect the issuer-attested claims to the nullifier.
pub struct ClaimsProofPrivateInputs {
    pub claims: [Field; NUM_CLAIMS],
    pub credential: CredentialPrivateInputs,
    pub nullifier: NullifierPrivateInputs,
}

fn calculate_claims_hash(claims: [Field; NUM_CLAIMS]) -> Field {
    // Credential V1 puts the 15 claims in the rate and zero in the capacity.
    let mut state: [Field; 16] = [0; 16];
    for i in 0..NUM_CLAIMS {
        state[i] = claims[i];
    }
    perm::x5_16(state)[1]
}

fn calculate_credential_subject(leaf_index: Field, blinder: Field) -> Field {
    perm::x5_3([DS_CREDENTIAL_SUB, leaf_index, blinder])[1]
}

fn calculate_credential_message(
    issuer_schema_id: Field,
    subject: Field,
    genesis_issued_at: Field,
    expires_at: Field,
    claims_hash: Field,
    associated_data_hash: Field,
    cred_id: Field,
) -> Field {
    perm::x5_8([
        DS_CREDENTIAL,
        issuer_schema_id,
        subject,
        genesis_issued_at,
        expires_at,
        claims_hash,
        associated_data_hash,
        cred_id,
    ])[1]
}

fn calculate_nullifier(
    leaf_index: Field,
    rp_id: Field,
    action: Field,
    oprf_response: [Field; 2],
) -> Field {
    let query = perm::x5_4([DS_OPRF_QUERY, leaf_index, rp_id, action])[1];
    perm::x5_4([DS_NULLIFIER, query, oprf_response[0], oprf_response[1]])[1]
}

fn check_claim_statements(claims: [Field; NUM_CLAIMS], statements: [ClaimsStatement; NUM_CLAIMS]) {
    for i in 0..NUM_CLAIMS {
        let check_min = statements[i].checks[0];
        let check_max = statements[i].checks[1];

        // Do not allow an arbitrary field value to silently disable a check.
        assert(check_min * (check_min - 1) == 0, "minimum check must be boolean");
        assert(check_max * (check_max - 1) == 0, "maximum check must be boolean");

        if check_min == 1 {
            assert_lt(statements[i].range_check_min, claims[i]);
        }
        if check_max == 1 {
            assert_lt(claims[i], statements[i].range_check_max);
        }
    }
}

/// PROTOTYPE: proves public predicates about private issuer-attested claims and
/// binds them to the same hidden leaf index used to derive `nullifier`.
///
/// This deliberately does not re-prove the authenticator/Merkle/DLog/unblinding
/// parts of the companion Circom nullifier proof. The verifier must verify both
/// proofs against the same `nullifier`, `issuer_schema_id`, `cred_pk`, `rp_id`,
/// `action`, and time policy.
fn main(public_inputs: pub ClaimsProofPublicInputs, private_inputs: ClaimsProofPrivateInputs) {
    let claims_hash = calculate_claims_hash(private_inputs.claims);

    let subject = calculate_credential_subject(
        private_inputs.nullifier.leaf_index,
        private_inputs.credential.cred_user_id_r,
    );
    let credential_message = calculate_credential_message(
        public_inputs.credential.issuer_schema_id,
        subject,
        private_inputs.credential.cred_genesis_issued_at,
        private_inputs.credential.cred_expires_at,
        claims_hash,
        private_inputs.credential.associated_data_hash,
        private_inputs.credential.cred_id,
    );
    assert(
        verify_eddsa_poseidon2(
            public_inputs.credential.cred_pk[0],
            public_inputs.credential.cred_pk[1],
            private_inputs.credential.cred_s,
            private_inputs.credential.cred_r,
            credential_message,
        ),
        "invalid credential signature",
    );

    // Mirror the credential timestamp semantics from `CheckCredentialSignature`.
    assert_lt(
        private_inputs.credential.cred_genesis_issued_at,
        MAX_U64_PLUS_ONE,
    );
    assert_lt(private_inputs.credential.cred_expires_at, MAX_U64_PLUS_ONE);
    assert_lt(public_inputs.credential.current_timestamp, MAX_U64_PLUS_ONE);
    assert_lt(
        public_inputs.credential.cred_genesis_issued_at_min,
        MAX_U64_PLUS_ONE,
    );
    assert_lt(
        public_inputs.credential.current_timestamp,
        private_inputs.credential.cred_expires_at,
    );
    assert_lt(
        public_inputs.credential.cred_genesis_issued_at_min,
        private_inputs.credential.cred_genesis_issued_at + 1,
    );

    check_claim_statements(private_inputs.claims, public_inputs.claims.statements);

    assert(
        calculate_nullifier(
            private_inputs.nullifier.leaf_index,
            public_inputs.nullifier.rp_id,
            public_inputs.nullifier.action,
            private_inputs.nullifier.oprf_response,
        )
            == public_inputs.nullifier.value,
        "nullifier mismatch",
    );
}

mod tests {
    use super::{
        calculate_claims_hash, calculate_nullifier, check_claim_statements,
        ClaimsProofPrivateInputs, ClaimsProofPublicInputs, ClaimsStatement, ClaimsStatementInputs,
        CredentialPrivateInputs, CredentialPublicInputs, main, NullifierPrivateInputs,
        NullifierPublicInputs, NUM_CLAIMS,
    };

    global ISSUER_SCHEMA_ID: Field = 1;
    global CRED_PK: [Field; 2] = [
        21825204959029483311433036009853709113262520481918849765727459753607131160346,
        8339486770249821464793634710648189540136988043780169655155172519121840615364,
    ];
    global RP_ID: Field = 950325648507560155068233096743093215539447660945;
    global ACTION: Field =
        84721944028150696728472418813119358007006361082259892623669024918011698311;
    global CURRENT_TIMESTAMP: Field = 1767868101;
    global GENESIS_ISSUED_AT_MIN: Field = 0;
    global EXPECTED_NULLIFIER: Field =
        21342856517406476000190785734870568200315738457615815351702849709270076362125;
    global EXPECTED_CLAIMS_HASH: Field =
        14272087287699568472569351444185311392108883722570788958733484799744115401870;

    fn no_statements() -> [ClaimsStatement; NUM_CLAIMS] {
        [ClaimsStatement { checks: [0, 0], range_check_min: 0, range_check_max: 0 }; NUM_CLAIMS]
    }

    fn fixture_inputs() -> ClaimsProofPrivateInputs {
        ClaimsProofPrivateInputs {
            claims: [0; NUM_CLAIMS],
            credential: CredentialPrivateInputs {
                cred_genesis_issued_at: 1767868120,
                cred_expires_at: 1767868180,
                associated_data_hash: 0,
                cred_id: 12176925761186149284,
                cred_user_id_r: 19016519542686775328775746932795543103858066763212549618980890183285781521458,
                cred_s: 1785197794318390548654263507521729446174585997835004080357493002880021427752,
                cred_r: [
                    9716162517813998269973089361571651784159199085806289463178774674474552458864,
                    6858161934880479087336794169055762635352680692798466775715085760374212641424,
                ],
            },
            nullifier: NullifierPrivateInputs {
                leaf_index: 1,
                oprf_response: [
                    11771927497930831763844779626723106344742708040976110136703486119568919340013,
                    19299702061490581533153169629464406607119112637706400365988657399831357218309,
                ],
            },
        }
    }

    fn fixture_public_inputs() -> ClaimsProofPublicInputs {
        ClaimsProofPublicInputs {
            claims: ClaimsStatementInputs { statements: no_statements() },
            credential: CredentialPublicInputs {
                issuer_schema_id: ISSUER_SCHEMA_ID,
                cred_pk: CRED_PK,
                current_timestamp: CURRENT_TIMESTAMP,
                cred_genesis_issued_at_min: GENESIS_ISSUED_AT_MIN,
            },
            nullifier: NullifierPublicInputs {
                value: EXPECTED_NULLIFIER,
                rp_id: RP_ID,
                action: ACTION,
            },
        }
    }

    #[test]
    fn test_circom_fixture_claims_hash() {
        assert_eq(calculate_claims_hash([0; NUM_CLAIMS]), EXPECTED_CLAIMS_HASH);
    }

    #[test]
    fn test_circom_fixture_nullifier() {
        let inputs = fixture_inputs();
        assert_eq(
            calculate_nullifier(
                inputs.nullifier.leaf_index,
                RP_ID,
                ACTION,
                inputs.nullifier.oprf_response,
            ),
            EXPECTED_NULLIFIER,
        );
    }

    #[test]
    fn test_full_attested_claims_flow() {
        let inputs = fixture_inputs();
        main(fixture_public_inputs(), inputs);
    }

    #[test]
    fn test_numeric_claim_statement() {
        let mut claims = [0; NUM_CLAIMS];
        claims[3] = 21;
        let mut statements = no_statements();
        statements[3] =
            ClaimsStatement { checks: [1, 1], range_check_min: 18, range_check_max: 65 };
        check_claim_statements(claims, statements);
    }

    #[test(should_fail_with = "invalid credential signature")]
    fn test_tampered_claim_is_not_attested() {
        let mut inputs = fixture_inputs();
        inputs.claims[0] = 1;
        main(fixture_public_inputs(), inputs);
    }

    #[test(should_fail_with = "minimum check must be boolean")]
    fn test_statement_flags_must_be_boolean() {
        let claims = [0; NUM_CLAIMS];
        let mut statements = no_statements();
        statements[0].checks[0] = 2;
        check_claim_statements(claims, statements);
    }
}
