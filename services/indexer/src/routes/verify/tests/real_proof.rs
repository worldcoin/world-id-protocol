use super::*;
use alloy::{network::EthereumWallet, primitives::keccak256, sol};
use world_id_primitives::{SessionNullifier, ZeroKnowledgeProof};
use world_id_test_utils::anvil::TestAnvil;

sol!(
    #[sol(rpc)]
    RegistryFixture,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/WorldIDVerifierTest.t.sol/WorldIDRegistryMock.json"
    )
);
sol!(
    #[sol(rpc)]
    IssuerFixture,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/WorldIDVerifierTest.t.sol/CredentialSchemaIssuerRegistryMock.json"
    )
);
sol!(
    #[sol(rpc)]
    OprfFixture,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/WorldIDVerifierTest.t.sol/OprfKeyRegistryMock.json"
    )
);

// Public inputs and proofs from contracts/test/core/WorldIDVerifierTest.t.sol.
// Registry reads use its mocks; Groth16 verification runs the real verifier on Anvil.
fn fixture_request(session: bool) -> IndexerVerifyRequest {
    let proof = if session {
        [
            "4930872a26a12446d943042e1958e65d4b3eecca9bf2b80c6bdba2dd24f37467",
            "15bba2773377d7ef96c76ede7d8d12bc5725441961de9f1b330484e1f24a19a8",
            "86dc81c5fccb1de6766036f308db3b6e1e6eb0fa7d780096d701cc97fb4a20f1",
            "3d4279efe1806d0c7747915b9852ade3738e8ffd87604e01034ca78e8cb81c54",
        ]
    } else {
        [
            "2a184f5930f2b6a0f367f649a80757e081b3fb28b76fffcfe325d82df87395b3",
            "f6849ab589365a7537beeb70014958ae261fe2dd7fdbf5c4823c6b527aefa34",
            "ac5ee090f2ee180619c5c9825f22cee8873fc0d4764b7b0c5ffd7802d8f2e0f9",
            "4a221ef1d3b5522ac95f38db43afda6863d34836f7a8cff0b50aa9c8ca52e727",
        ]
    };
    let mut encoded = [U256::ZERO; 5];
    for (target, value) in encoded.iter_mut().zip(proof) {
        *target = U256::from_str_radix(value, 16).unwrap();
    }
    encoded[4] = U256::from_str_radix(
        "af727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853",
        16,
    )
    .unwrap();
    let mut req = request(json!({"proof_type": "uniqueness", "nullifier": "7", "action": "8"}));
    req.rp_id = 0x387df34f862cd4e;
    req.expires_at_min = 0x6a54cd68;
    req.issuer_schema_id = 1;
    req.credential_genesis_issued_at_min = U256::ZERO;
    req.signal_hash = U256::from_str_radix(
        "1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f",
        16,
    )
    .unwrap();
    req.proof = ZeroKnowledgeProof::from_ethereum_representation(encoded);
    if session {
        req.nonce = U256::from_str_radix(
            "a138dc568a2548155f3991625ddec3b466d2a49b19d6ff26a94ba0310cdf5ba",
            16,
        )
        .unwrap();
        req.verification = IndexerVerifyInputs::Session {
            session_id: U256::from_str_radix(
                "2018a266d26fbc1cd41743cc3126321302b8f0af39c367fe5718eeafb341d494",
                16,
            )
            .unwrap(),
            session_nullifier: SessionNullifier::from_ethereum_representation([
                U256::from_str_radix(
                    "8ce710377b04b2605fd6c5545f15f638527bd0315f223b8c2c070a4ac0a62d0",
                    16,
                )
                .unwrap(),
                U256::from_str_radix(
                    "2b6b35cb561c84d7a137fbc715c9df67152fa28c1b81042a4c0e80d1ba01b00",
                    16,
                )
                .unwrap(),
            ])
            .unwrap(),
        };
    } else {
        req.nonce = U256::from_str_radix(
            "38ed3d4d95deac6e369dde48890d5b14b49a2d26a0b2e8854d429ff7c52cf99",
            16,
        )
        .unwrap();
        req.verification = IndexerVerifyInputs::Uniqueness {
            nullifier: U256::from_str_radix(
                "5968cd4d3c50bfd2305671d1092bee10ccb679b93db3ca779b6477e4885e476",
                16,
            )
            .unwrap(),
            action: U256::from_str_radix(
                "978cc65f06353d8543971b65da8751833ff1253a192f58bed14f2739c0a345",
                16,
            )
            .unwrap(),
        };
    }
    // Exercise the same JSON encoding/decoding used at the API boundary.
    serde_json::from_value(serde_json::to_value(req).unwrap()).unwrap()
}

#[tokio::test]
async fn verifies_real_proofs_and_validates_startup_configuration() {
    let anvil = TestAnvil::spawn_auto_mine().unwrap();
    let signer = anvil.signer(0).unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer.clone()))
        .connect_http(anvil.endpoint().parse().unwrap())
        .erased();
    let registry = RegistryFixture::deploy(provider.clone()).await.unwrap();
    let issuer = IssuerFixture::deploy(provider.clone()).await.unwrap();
    let oprf = OprfFixture::deploy(provider.clone()).await.unwrap();
    let address = anvil
        .deploy_world_id_verifier(
            signer,
            *issuer.address(),
            *registry.address(),
            *oprf.address(),
        )
        .await
        .unwrap();
    let verifier = crate::initialize_verifier(provider.clone(), address, *registry.address(), 10)
        .await
        .unwrap();

    let slot = U256::from_be_bytes(keccak256("eip1967.proxy.implementation").0) - U256::from(1);
    let implementation =
        Address::from_word(provider.get_storage_at(address, slot).await.unwrap().into());
    for (target, expected_registry) in [
        (Address::ZERO, *registry.address()),
        (*registry.address(), *registry.address()),
        (implementation, *registry.address()),
        (address, *issuer.address()),
    ] {
        assert!(
            crate::initialize_verifier(provider.clone(), target, expected_registry, 10)
                .await
                .is_err()
        );
    }

    // Pin time so this checked-in proof remains valid independently of the wall clock.
    let _: Value = provider
        .client()
        .request("evm_setTime", (0x6a54cd68u64,))
        .await
        .unwrap();
    let _: Value = provider.client().request("evm_mine", ()).await.unwrap();
    for session in [false, true] {
        assert!(
            verify(&verifier, fixture_request(session))
                .await
                .unwrap()
                .0
                .valid
        );
        let mut tampered = fixture_request(session);
        tampered.nonce += U256::from(1);
        assert_eq!(
            verify(&verifier, tampered)
                .await
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut overflow = fixture_request(false);
    overflow.expires_at_min = u64::MAX;
    assert_eq!(
        verify(&verifier, overflow)
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let mut zero_session = fixture_request(true);
    if let IndexerVerifyInputs::Session { session_id, .. } = &mut zero_session.verification {
        *session_id = U256::ZERO;
    }
    assert_eq!(
        verify(&verifier, zero_session)
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
}
