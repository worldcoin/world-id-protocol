use alloy::node_bindings::Anvil;

use crate::auth::{self, rp_module::RpAccountType};

alloy::sol!(
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    interface IERC165 {
        function supportsInterface(bytes4 interfaceId) external view returns (bool);
    }

    interface IWIP101 is IERC165 {
        error RpInvalidRequest(uint256 code);

        function verifyRpRequest(
            uint8 version,
            uint256 nonce,
            uint64 createdAt,
            uint64 expiresAt,
            uint256 action,
            bytes calldata data
        ) external view returns (bytes4 magicValue);
    }

    bytes4 constant WIP101_MAGIC_VALUE = 0x35dbc8de;
    bytes4 constant ERC165_INTERFACE_ID = type(IERC165).interfaceId;
    bytes4 constant IWIP101_INTERFACE_ID = type(IWIP101).interfaceId;

    #[sol(rpc, bytecode="6080806040523460155761016a908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100b357506335dbc8de14610032575f80fd5b346100af5760c03660031901126100af5760043560ff8116036100af57610057610106565b5061006061011d565b5060a43567ffffffffffffffff81116100af57366023820112156100af57806004013567ffffffffffffffff81116100af57369101602401116100af57604051631aede46f60e11b8152602090f35b5f80fd5b346100af5760203660031901126100af576004359063ffffffff60e01b82168092036100af57602091631aede46f60e11b81149081156100f5575b5015158152f35b6301ffc9a760e01b149050836100ee565b6044359067ffffffffffffffff821682036100af57565b6064359067ffffffffffffffff821682036100af5756fea264697066735822122096e7f4484e9ba9d2d42b676a61e28dadc5f2048086cf1e7b9c64dfccc0274c6c64736f6c634300081e0033")]
    contract WIP101Correct is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

        function verifyRpRequest(
            uint8,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes calldata
        ) external pure override returns (bytes4) {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="608080604052346015576101a3908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100c557506335dbc8de14610032575f80fd5b346100c15760c03660031901126100c15760043560ff8116036100c157610057610118565b5061006061012f565b5060a43567ffffffffffffffff81116100c157366023820112156100c15780600401359067ffffffffffffffff82116100c15736602483830101116100c15760209160246100ae9201610146565b6040516001600160e01b03199091168152f35b5f80fd5b346100c15760203660031901126100c1576004359063ffffffff60e01b82168092036100c157602091631aede46f60e11b8114908115610107575b5015158152f35b6301ffc9a760e01b14905083610100565b6044359067ffffffffffffffff821682036100c157565b6064359067ffffffffffffffff821682036100c157565b5060031461016257635927c5d160e01b5f52600160045260245ffd5b631aede46f60e11b9056fea26469706673582212202ec4c3e4ff79412b4e94dd6ea5ff2e51bde2683825eaa3c15bf734f931208f2264736f6c634300081e0033")]
    contract WIP101CorrectWhenAuxData is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

        function verifyRpRequest(
            uint8,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes calldata
        ) external pure override returns (bytes4) {
            if (data.length == 3) {
               return WIP101_MAGIC_VALUE;
            }
            revert IWIP101.RpInvalidRequest(1);
        }
    }

    #[sol(rpc, bytecode="6080806040523460155761016a908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100b357506335dbc8de14610032575f80fd5b346100af5760c03660031901126100af5760043560ff8116036100af57610057610106565b5061006061011d565b5060a43567ffffffffffffffff81116100af57366023820112156100af57806004013567ffffffffffffffff81116100af57369101602401116100af5760405163deadbeef60e01b8152602090f35b5f80fd5b346100af5760203660031901126100af576004359063ffffffff60e01b82168092036100af57602091631aede46f60e11b81149081156100f5575b5015158152f35b6301ffc9a760e01b149050836100ee565b6044359067ffffffffffffffff821682036100af57565b6064359067ffffffffffffffff821682036100af5756fea2646970667358221220f7c7208153417dd46507ef4a041fef59c2c425a8631039c5b4f337b953fed05764736f6c634300081e0033")]
    contract WIP101WrongMagic is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }


        function verifyRpRequest(
            uint8,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes calldata
        ) external pure override returns (bytes4) {
            return 0xdeadbeef;
        }
    }

    #[sol(rpc, bytecode="6080806040523460155761016c908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100b557506335dbc8de14610032575f80fd5b346100b15760c03660031901126100b15760043560ff8116036100b157610057610108565b5061006061011f565b5060a43567ffffffffffffffff81116100b157366023820112156100b157806004013567ffffffffffffffff81116100b157369101602401116100b157635927c5d160e01b5f52602a60045260245ffd5b5f80fd5b346100b15760203660031901126100b1576004359063ffffffff60e01b82168092036100b157602091631aede46f60e11b81149081156100f7575b5015158152f35b6301ffc9a760e01b149050836100f0565b6044359067ffffffffffffffff821682036100b157565b6064359067ffffffffffffffff821682036100b15756fea2646970667358221220c81b460a3819625bcc08bad6422cc277be32d99f104eef939c0f00fcd54b4ee864736f6c634300081e0033")]
    contract WIP101RevertsWithCode is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }


        function verifyRpRequest(
            uint8,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes calldata
        ) external pure override returns (bytes4) {
            revert RpInvalidRequest(42);
        }
    }

    #[sol(rpc, bytecode="60808060405234601557610189908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100d257506335dbc8de14610032575f80fd5b346100ce5760c03660031901126100ce5760043560ff8116036100ce57610057610125565b5061006061013c565b5060a43567ffffffffffffffff81116100ce57366023820112156100ce57806004013567ffffffffffffffff81116100ce57369101602401116100ce5760405162461bcd60e51b81526020600482015260096024820152683737903932b0b9b7b760b91b6044820152606490fd5b5f80fd5b346100ce5760203660031901126100ce576004359063ffffffff60e01b82168092036100ce57602091631aede46f60e11b8114908115610114575b5015158152f35b6301ffc9a760e01b1490508361010d565b6044359067ffffffffffffffff821682036100ce57565b6064359067ffffffffffffffff821682036100ce5756fea26469706673582212205c4ef5aba17cc550ec6b340e754c4b5d15729ced451a33ba12341c5dcd4be36564736f6c634300081e0033")]
    contract WIP101PlainRevert is IWIP101 {
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }


        function verifyRpRequest(
            uint8,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes calldata
        ) external pure override returns (bytes4) {
            revert("no reason");
        }
    }

    #[sol(rpc, bytecode="60808060405234601557610130908161001a8239f35b5f80fdfe60808060405260043610156011575f80fd5b5f3560e01c90816301ffc9a71460a557506335dbc8de14602f575f80fd5b3460a15760c036600319011260a15760043560ff81160360a157604f60ce565b50605660e4565b5060a43567ffffffffffffffff811160a1573660238201121560a157806004013567ffffffffffffffff811160a1573691016024011160a157604051631aede46f60e11b8152602090f35b5f80fd5b3460a157602036600319011260a1576004356001600160e01b031981160360a157805f60209252f35b6044359067ffffffffffffffff8216820360a157565b6064359067ffffffffffffffff8216820360a15756fea264697066735822122003aa2a0e23947cd3d95c3891ebbfcb1772c1ae500f2843389fe3ec00f5a299a464736f6c634300081e0033")]
    contract WIP101BrokenERC165 is IWIP101 {
        function supportsInterface(bytes4) external pure override returns (bool) {
            return false;
        }

        function verifyRpRequest(
            uint8,
            uint256,
            uint64,
            uint64,
            uint256,
            bytes calldata
        ) external pure override returns (bytes4) {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="608080604052346013576039908160188239f35b5f80fdfe5f80fdfea2646970667358221220e03fd1a6f18d8d70e90e3f71f6f062c99b0d5de32b1fca4e07e66e7046c39a7364736f6c634300081e0033")]
    contract NoERC165 {}

    #[sol(rpc, bytecode="6080806040523460135760ab908160188239f35b5f80fdfe60808060405260043610156011575f80fd5b5f3560e01c6301ffc9a7146023575f80fd5b3460715760203660031901126071576004359063ffffffff60e01b8216809203607157602091631aede46f60e11b81149081156061575b5015158152f35b6301ffc9a760e01b1490505f605a565b5f80fdfea2646970667358221220c7658d68732fdcaedf4bc4c0aac8766a338e41135d9905ebfdc6e91f432e53dc64736f6c634300081e0033")]
    contract NoWIP101 {
        // no verifyRpRequest
        function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == ERC165_INTERFACE_ID;
        }

    }

    #[sol(rpc, bytecode="6080806040523460155761015e908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100a7575063ec36b9e314610032575f80fd5b346100a35760c03660031901126100a35761004b6100fa565b50610054610111565b5060a43567ffffffffffffffff81116100a357366023820112156100a357806004013567ffffffffffffffff81116100a357369101602401116100a357604051631aede46f60e11b8152602090f35b5f80fd5b346100a35760203660031901126100a3576004359063ffffffff60e01b82168092036100a357602091631aede46f60e11b81149081156100e9575b5015158152f35b6301ffc9a760e01b149050836100e2565b6044359067ffffffffffffffff821682036100a357565b6064359067ffffffffffffffff821682036100a35756fea2646970667358221220e6d7fbcfb6c410c1a87c460029baebaf75e33dffda537316856910b8cedce8e864736f6c634300081e0033")]
    contract WrongSignature {
        function supportsInterface(bytes4) external pure override returns (bool) {
            return interfaceId == IWIP101_INTERFACE_ID || interfaceId == IWI;
        }

        function verifyRpRequest(
            uint256, // wrong type!
            uint256,
            uint64,
            uint64,
            uint256,
            bytes calldata
        ) external pure returns (bytes4) {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="608080604052346015576101fc908161001a8239f35b5f80fdfe60806040526004361015610011575f80fd5b5f3560e01c806301ffc9a7146100e157806335dbc8de146100645763c6c2ea171461003a575f80fd5b34610060576020366003190112610060576020610058600435610170565b604051908152f35b5f80fd5b346100605760c03660031901126100605760043560ff81160361006057610089610142565b50610092610159565b5060a43567ffffffffffffffff8111610060573660238201121561006057806004013567ffffffffffffffff8111610060573691016024011161006057604051631aede46f60e11b8152602090f35b346100605760203660031901126100605760043563ffffffff60e01b8116809103610060576020906101136032610170565b50631aede46f60e11b8114908115610131575b506040519015158152f35b6301ffc9a760e01b14905082610126565b6044359067ffffffffffffffff8216820361006057565b6064359067ffffffffffffffff8216820361006057565b60018111156101c3575f1981018181116101af5761018d90610170565b9060011981019081116101af576101a390610170565b81018091116101af5790565b634e487b7160e01b5f52601160045260245ffd5b9056fea2646970667358221220ee84e83eb72f50ef3356b7aae0e2b89f93f40dc5d5274efb24d0a1a1d29facc664736f6c634300081e0033")]
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

        function verifyRpRequest(uint8, uint256, uint64, uint64, uint256, bytes calldata)
            external
            pure
            override
            returns (bytes4)
        {
            return WIP101_MAGIC_VALUE;
        }
    }

    #[sol(rpc, bytecode="608080604052346015576101fc908161001a8239f35b5f80fdfe6080806040526004361015610012575f80fd5b5f3560e01c90816301ffc9a7146100ef5750806335dbc8de146100675763c6c2ea171461003d575f80fd5b3461006357602036600319011261006357602061005b600435610170565b604051908152f35b5f80fd5b346100635760c03660031901126100635760043560ff8116036100635761008c610142565b50610095610159565b5060a43567ffffffffffffffff8111610063573660238201121561006357806004013567ffffffffffffffff81116100635736910160240111610063576100dc6032610170565b50604051631aede46f60e11b8152602090f35b34610063576020366003190112610063576004359063ffffffff60e01b821680920361006357602091631aede46f60e11b8114908115610131575b5015158152f35b6301ffc9a760e01b1490508361012a565b6044359067ffffffffffffffff8216820361006357565b6064359067ffffffffffffffff8216820361006357565b60018111156101c3575f1981018181116101af5761018d90610170565b9060011981019081116101af576101a390610170565b81018091116101af5790565b634e487b7160e01b5f52601160045260245ffd5b9056fea26469706673582212202c8ca8ed0deefc859e1cdbfc5c1168c92dc32ce6d3bfe958b51dd3fd9d4e0b3c64736f6c634300081e0033")]
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

        function verifyRpRequest(uint8, uint256, uint64, uint64, uint256, bytes calldata)
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
    let anvil = Anvil::new().spawn();
    let rpc_provider = auth::tests::build_http_provider(&anvil);
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
    let anvil = Anvil::new().spawn();
    let rpc_provider = auth::tests::build_http_provider(&anvil);
    let zero_address = alloy::primitives::address!("0x0000000000000000000000000000000000000000");

    let rp_type = super::account_check(zero_address, &rpc_provider)
        .await
        .expect("Should successfully get rp type");

    assert_eq!(rp_type, RpAccountType::Eoa);
}

#[tokio::test]
async fn test_contract_broken_erc165() {
    let anvil = Anvil::new().spawn();
    let rpc_provider = auth::tests::build_http_provider(&anvil);
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
    let anvil = Anvil::new().spawn();
    let rpc_provider = auth::tests::build_http_provider(&anvil);
    let wip101_instance = NoERC165::deploy(rpc_provider.inner())
        .await
        .expect("Should be able to deploy contract");

    let rp_type = super::account_check(*wip101_instance.address(), &rpc_provider)
        .await
        .expect("Should successfully get rp type");

    assert_eq!(rp_type, RpAccountType::IncompatibleWip101);
}
