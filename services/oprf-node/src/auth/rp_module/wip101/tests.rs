use world_id_test_utils::anvil::TestAnvil;

use crate::auth::{self, rp_module::RpAccountType};

alloy::sol!(
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    interface IERC165 {
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
    }

    struct RpRequestIntent {
        uint8 requestVersion;
        uint64 rpId;
        uint160 oprfKeyId;
        uint256 nonce;
        uint64 createdAt;
        uint64 expiresAt;
        uint8 proofType;
        uint8 sessionMode;
        uint8 actionKind;
        uint256 action;
        bytes32 existingSessionSeedAuthorization;
        bytes32 detailsHash;
    }

    interface IWIP101 is IERC165 {
        error RpInvalidRequest(uint256 code);

        function verifyRpRequest(
            RpRequestIntent calldata intent,
            uint256 oprfAction,
            bytes calldata data
        ) external view returns (bytes4 magicValue);
    }

    bytes4 constant WIP101_MAGIC_VALUE = IWIP101.verifyRpRequest.selector;
    bytes4 constant ERC165_INTERFACE_ID = type(IERC165).interfaceId;
    bytes4 constant IWIP101_INTERFACE_ID = type(IWIP101).interfaceId;

    #[sol(rpc, bytecode="60808060405234601557610192908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100d6575063d7e3f32c14610032575f80fd5b346100d2577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126100d257610180136100d2576101a43567ffffffffffffffff81116100d257366023820112156100d257806004013567ffffffffffffffff81116100d257369101602401116100d25760206040517fd7e3f32c000000000000000000000000000000000000000000000000000000008152f35b5f80fd5b346100d25760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100d257600435907fffffffff0000000000000000000000000000000000000000000000000000000082168092036100d257817fd7e3f32c0000000000000000000000000000000000000000000000000000000060209314908115610168575b5015158152f35b7f01ffc9a7000000000000000000000000000000000000000000000000000000009150148361016156")]
    contract WIP101Correct is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata)
            external
            pure
            override
            returns (bytes4)
        {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="608080604052346015576101fc908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100e7575063d7e3f32c14610032575f80fd5b346100e3577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126100e357610180136100e3576101a43567ffffffffffffffff81116100e357366023820112156100e35780600401359067ffffffffffffffff82116100e35736602483830101116100e35760209160246100b992016101a3565b7fffffffff0000000000000000000000000000000000000000000000000000000060405191168152f35b5f80fd5b346100e35760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100e357600435907fffffffff0000000000000000000000000000000000000000000000000000000082168092036100e357817fd7e3f32c0000000000000000000000000000000000000000000000000000000060209314908115610179575b5015158152f35b7f01ffc9a70000000000000000000000000000000000000000000000000000000091501483610172565b506003146101d8577f5927c5d1000000000000000000000000000000000000000000000000000000005f52600160045260245ffd5b7fd7e3f32c000000000000000000000000000000000000000000000000000000009056")]
    contract WIP101CorrectWhenAuxData is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata data)
            external pure override returns (bytes4) {
            if (data.length == 3) {
               return WIP101_MAGIC_VALUE;
            }
            revert IWIP101.RpInvalidRequest(1);
        }
    }

    #[sol(rpc, bytecode="60808060405234601557610192908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100d6575063d7e3f32c14610032575f80fd5b346100d2577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126100d257610180136100d2576101a43567ffffffffffffffff81116100d257366023820112156100d257806004013567ffffffffffffffff81116100d257369101602401116100d25760206040517fdeadbeef000000000000000000000000000000000000000000000000000000008152f35b5f80fd5b346100d25760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100d257600435907fffffffff0000000000000000000000000000000000000000000000000000000082168092036100d257817fd7e3f32c0000000000000000000000000000000000000000000000000000000060209314908115610168575b5015158152f35b7f01ffc9a7000000000000000000000000000000000000000000000000000000009150148361016156")]
    contract WIP101WrongMagic is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }


        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata)
            external pure override returns (bytes4) {
            return 0xdeadbeef;
        }
    }

    #[sol(rpc, bytecode="60808060405234601557610195908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100d9575063d7e3f32c14610032575f80fd5b346100d5577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126100d557610180136100d5576101a43567ffffffffffffffff81116100d557366023820112156100d557806004013567ffffffffffffffff81116100d557369101602401116100d5577f5927c5d1000000000000000000000000000000000000000000000000000000005f52602a60045260245ffd5b5f80fd5b346100d55760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100d557600435907fffffffff0000000000000000000000000000000000000000000000000000000082168092036100d557817fd7e3f32c000000000000000000000000000000000000000000000000000000006020931490811561016b575b5015158152f35b7f01ffc9a7000000000000000000000000000000000000000000000000000000009150148361016456")]
    contract WIP101RevertsWithCode is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }


        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata)
            external pure override returns (bytes4) {
            revert RpInvalidRequest(42);
        }
    }

    #[sol(rpc, bytecode="608080604052346015576101c6908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a71461010a575063d7e3f32c14610032575f80fd5b34610106577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126101065761018013610106576101a43567ffffffffffffffff8111610106573660238201121561010657806004013567ffffffffffffffff811161010657369101602401116101065760646040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152600960248201527f6e6f20726561736f6e00000000000000000000000000000000000000000000006044820152fd5b5f80fd5b346101065760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261010657600435907fffffffff00000000000000000000000000000000000000000000000000000000821680920361010657817fd7e3f32c000000000000000000000000000000000000000000000000000000006020931490811561019c575b5015158152f35b7f01ffc9a7000000000000000000000000000000000000000000000000000000009150148361019556")]
    contract WIP101PlainRevert is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }


        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata)
            external pure override returns (bytes4) {
            revert("no reason");
        }
    }

    #[sol(rpc, bytecode="60808060405234601557610138908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100d6575063d7e3f32c14610032575f80fd5b346100d2577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126100d257610180136100d2576101a43567ffffffffffffffff81116100d257366023820112156100d257806004013567ffffffffffffffff81116100d257369101602401116100d25760206040517fd7e3f32c000000000000000000000000000000000000000000000000000000008152f35b5f80fd5b346100d25760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100d2576004357fffffffff000000000000000000000000000000000000000000000000000000008116036100d257805f60209252f3")]
    contract WIP101BrokenERC165 is IWIP101 {
        function supportsInterface(bytes4) external pure override returns (bool) {
            return false;
        }

        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata)
            external pure override returns (bytes4) {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="608080604052346013576003908160188239f35b5f80fdfe5f80fd")]
    contract NoERC165 {}

    #[sol(rpc, bytecode="6080806040523460135760de908160188239f35b5f80fdfe60808060405260043610156011575f80fd5b5f3560e01c6301ffc9a7146023575f80fd5b3460da5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011260da57600435907fffffffff00000000000000000000000000000000000000000000000000000000821680920360da57817fd7e3f32c000000000000000000000000000000000000000000000000000000006020931490811560b1575b5015158152f35b7f01ffc9a7000000000000000000000000000000000000000000000000000000009150145f60aa565b5f80fd")]
    contract NoWIP101 {
        // no verifyRpRequest
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

    }

    #[sol(rpc, bytecode="60808060405234601557610187908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100cb575063dfafdcdf14610032575f80fd5b346100c75760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100c75760443567ffffffffffffffff81116100c757366023820112156100c757806004013567ffffffffffffffff81116100c757369101602401116100c75760206040517fd7e3f32c000000000000000000000000000000000000000000000000000000008152f35b5f80fd5b346100c75760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100c757600435907fffffffff0000000000000000000000000000000000000000000000000000000082168092036100c757817fd7e3f32c000000000000000000000000000000000000000000000000000000006020931490811561015d575b5015158152f35b7f01ffc9a7000000000000000000000000000000000000000000000000000000009150148361015656")]
    contract WrongSignature {
        function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

        function verifyRpRequest(uint256, uint256, bytes calldata)
            external pure returns (bytes4) {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="60808060405234601557610298908161001a8239f35b5f80fdfe60806040526004361015610011575f80fd5b5f3560e01c806301ffc9a714610122578063c6c2ea17146100de5763d7e3f32c1461003a575f80fd5b346100da577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126100da57610180136100da576101a43567ffffffffffffffff81116100da57366023820112156100da57806004013567ffffffffffffffff81116100da57369101602401116100da5760206040517fd7e3f32c000000000000000000000000000000000000000000000000000000008152f35b5f80fd5b346100da5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100da57602061011a6004356101ec565b604051908152f35b346100da5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100da576004357fffffffff0000000000000000000000000000000000000000000000000000000081168091036100da5760209061018b60326101ec565b507fd7e3f32c0000000000000000000000000000000000000000000000000000000081149081156101c2575b506040519015158152f35b7f01ffc9a700000000000000000000000000000000000000000000000000000000915014826101b7565b6001811115610295577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff810181811161026857610228906101ec565b907ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe81019081116102685761025c906101ec565b81018091116102685790565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b9056")]
    contract WIP101TimeoutERC165 is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            fib(50);
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

        function fib(uint256 n) public pure returns (uint256) {
            if (n <= 1) {
                return n;
            }
            return fib(n - 1) + fib(n - 2);
        }

        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata)
            external
            pure
            override
            returns (bytes4)
        {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="60808060405234601557610298908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a71461013057508063c6c2ea17146100ec5763d7e3f32c1461003d575f80fd5b346100e8577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36016101c081126100e857610180136100e8576101a43567ffffffffffffffff81116100e857366023820112156100e857806004013567ffffffffffffffff81116100e857369101602401116100e8576100bd60326101ec565b5060206040517fd7e3f32c000000000000000000000000000000000000000000000000000000008152f35b5f80fd5b346100e85760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100e85760206101286004356101ec565b604051908152f35b346100e85760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126100e857600435907fffffffff0000000000000000000000000000000000000000000000000000000082168092036100e857817fd7e3f32c00000000000000000000000000000000000000000000000000000000602093149081156101c2575b5015158152f35b7f01ffc9a700000000000000000000000000000000000000000000000000000000915014836101bb565b6001811115610295577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff810181811161026857610228906101ec565b907ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe81019081116102685761025c906101ec565b81018091116102685790565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b9056")]
    contract WIP101TimeoutVerify is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

        function fib(uint256 n) public pure returns (uint256) {
            if (n <= 1) {
                return n;
            }
            return fib(n - 1) + fib(n - 2);
        }

        function verifyRpRequest(RpRequestIntent calldata, uint256, bytes calldata)
            external
            pure
            override
            returns (bytes4)
        {
            fib(50);
            return WIP101_MAGIC_VALUE;
        }
    }
);

#[tokio::test]
async fn test_confirm_success() {
    let anvil = TestAnvil::spawn_auto_mine().expect("Should spawn anvil");
    let rpc_provider = auth::tests::build_http_provider(&anvil.instance);
    let wip101_instance = WIP101Correct::deploy(rpc_provider.inner())
        .await
        .expect("Should be able to deploy contract");
    let rp_type = super::account_check(*wip101_instance.address(), &rpc_provider)
        .await
        .expect("Should successfully get rp type");

    assert_eq!(rp_type, RpAccountType::Contract);
}

#[tokio::test]
async fn test_no_contract() {
    let anvil = TestAnvil::spawn_auto_mine().expect("Should spawn anvil");
    let rpc_provider = auth::tests::build_http_provider(&anvil.instance);
    let zero_address = alloy::primitives::address!("0x0000000000000000000000000000000000000000");

    let rp_type = super::account_check(zero_address, &rpc_provider)
        .await
        .expect("Should successfully get rp type");

    assert_eq!(rp_type, RpAccountType::Eoa);
}

#[tokio::test]
async fn test_contract_broken_erc165() {
    let anvil = TestAnvil::spawn_auto_mine().expect("Should spawn anvil");
    let rpc_provider = auth::tests::build_http_provider(&anvil.instance);
    let wip101_instance = WIP101BrokenERC165::deploy(rpc_provider.inner())
        .await
        .expect("Should be able to deploy contract");

    let rp_type = super::account_check(*wip101_instance.address(), &rpc_provider)
        .await
        .expect("Should successfully get rp type");

    assert_eq!(rp_type, RpAccountType::IncompatibleWip101);
}

#[tokio::test]
async fn test_contract_no_method() {
    let anvil = TestAnvil::spawn_auto_mine().expect("Should spawn anvil");
    let rpc_provider = auth::tests::build_http_provider(&anvil.instance);
    let wip101_instance = NoERC165::deploy(rpc_provider.inner())
        .await
        .expect("Should be able to deploy contract");

    let rp_type = super::account_check(*wip101_instance.address(), &rpc_provider)
        .await
        .expect("Should successfully get rp type");

    assert_eq!(rp_type, RpAccountType::IncompatibleWip101);
}
