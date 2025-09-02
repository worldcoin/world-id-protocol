// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AuthenticatorRegistry} from "../src/AuthenticatorRegistry.sol";
import {TreeHelper} from "../src/TreeHelper.sol";
import {BinaryIMT, BinaryIMTData} from "../src/tree/BinaryIMT.sol";

contract AuthenticatorRegistryTest is Test {
    using BinaryIMT for BinaryIMTData;

    AuthenticatorRegistry public authenticatorRegistry;

    address public constant DEFAULT_RECOVERY_ADDRESS = address(0xDEADBEEF);
    address public constant RECOVERY_ADDRESS = address(0xDEADBEEF);
    uint256 public constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;
    address public AUTHENTICATOR_ADDRESS1;
    address public AUTHENTICATOR_ADDRESS2;
    address public AUTHENTICATOR_ADDRESS3;
    uint256 public constant AUTH1_PRIVATE_KEY = 0x01;
    uint256 public constant AUTH2_PRIVATE_KEY = 0x02;
    uint256 public constant AUTH3_PRIVATE_KEY = 0x03;

    function setUp() public {
        authenticatorRegistry = new AuthenticatorRegistry(DEFAULT_RECOVERY_ADDRESS);
        AUTHENTICATOR_ADDRESS1 = vm.addr(AUTH1_PRIVATE_KEY);
        AUTHENTICATOR_ADDRESS2 = vm.addr(AUTH2_PRIVATE_KEY);
        AUTHENTICATOR_ADDRESS3 = vm.addr(AUTH3_PRIVATE_KEY);
    }

    ////////////////////////////////////////////////////////////
    //                        Helpers                         //
    ////////////////////////////////////////////////////////////

    function eip712Sign(bytes32 typeHash, bytes memory data, uint256 privateKey) private returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, data));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", authenticatorRegistry.domainSeparatorV4(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function emptyProof() private pure returns (uint256[] memory) {
        uint256 depth = 30;
        uint256[] memory proof = new uint256[](depth);
        for (uint256 i = 0; i < depth; i++) {
            proof[i] = BinaryIMT.defaultZero(i);
        }
        return proof;
    }

    function updateAuthenticatorProofAndSignature(uint256 accountIndex, uint256 newLeaf, uint256 nonce)
        private
        returns (bytes memory, uint256[] memory)
    {
        bytes memory signature = eip712Sign(
            authenticatorRegistry.UPDATE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS1, AUTHENTICATOR_ADDRESS2, newLeaf, nonce),
            AUTH1_PRIVATE_KEY
        );

        return (signature, emptyProof());
    }

    ////////////////////////////////////////////////////////////
    //                        Tests                           //
    ////////////////////////////////////////////////////////////

    function test_CreateAccount() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        address[] memory authenticatorAddresses2 = new address[](1);
        authenticatorAddresses2[0] = AUTHENTICATOR_ADDRESS2;
        authenticatorRegistry.createAccount(address(0), authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);
        uint256 size = authenticatorRegistry.nextAccountIndex();
        uint256 startGas = gasleft();
        authenticatorRegistry.createAccount(address(0), authenticatorAddresses2, OFFCHAIN_SIGNER_COMMITMENT);
        uint256 endGas = gasleft();
        console.log("Gas used per create account:", (startGas - endGas));
        assertEq(authenticatorRegistry.nextAccountIndex(), size + 1);
    }

    function test_CreateManyAccounts() public {
        uint256 size = authenticatorRegistry.nextAccountIndex();
        uint256 numAccounts = 100;
        address[] memory recoveryAddresses = new address[](numAccounts);
        address[][] memory authenticatorAddresses = new address[][](numAccounts);
        uint256[] memory offchainSignerCommitments = new uint256[](numAccounts);

        for (uint256 i = 0; i < numAccounts; i++) {
            authenticatorAddresses[i] = new address[](1);
            authenticatorAddresses[i][0] = address(uint160(i + 1));
            offchainSignerCommitments[i] = OFFCHAIN_SIGNER_COMMITMENT;
        }

        uint256 startGas = gasleft();
        authenticatorRegistry.createManyAccounts(recoveryAddresses, authenticatorAddresses, offchainSignerCommitments);
        uint256 endGas = gasleft();
        console.log("Gas used per account:", (startGas - endGas) / numAccounts);
        assertEq(authenticatorRegistry.nextAccountIndex(), size + numAccounts);
    }

    function test_UpdateAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 0;
        uint256 accountIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // AUTHENTICATOR_ADDRESS1 is assigned to account 1
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, newCommitment, nonce);

        uint256 startGas = gasleft();
        authenticatorRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            proof,
            nonce
        );
        uint256 endGas = gasleft();
        console.log("Gas used per update:", (startGas - endGas));

        // AUTHENTICATOR_ADDRESS1 has been removed
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1), 0);
        // AUTHENTICATOR_ADDRESS2 has been added
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS2), 1);
    }

    function test_UpdateAuthenticatorInvalidAccountIndex() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 0;
        uint256 accountIndex = 2;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, newCommitment, nonce);

        vm.expectRevert("Invalid account index");

        authenticatorRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            proof,
            nonce
        );
    }

    function test_UpdateAuthenticatorInvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 1;
        uint256 accountIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // AUTHENTICATOR_ADDRESS1 is assigned to account 1
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, newCommitment, nonce);

        vm.expectRevert("Invalid nonce");

        authenticatorRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            proof,
            nonce
        );
    }

    function test_InsertAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            authenticatorRegistry.INSERT_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS2, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        uint256 startGas = gasleft();
        authenticatorRegistry.insertAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );
        uint256 endGas = gasleft();
        console.log("Gas used per insert:", (startGas - endGas));

        // Both authenticators should now belong to the same account
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS2), accountIndex);
    }

    function test_RemoveAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorAddresses[1] = AUTHENTICATOR_ADDRESS2;
        authenticatorRegistry.createAccount(RECOVERY_ADDRESS, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            authenticatorRegistry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS2, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        authenticatorRegistry.removeAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS2,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );

        // AUTHENTICATOR_ADDRESS2 should be removed; AUTHENTICATOR_ADDRESS1 remains
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS2), 0);
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1), accountIndex);
    }

    function test_RecoverAccountSuccess() public {
        // Use a recovery address we control via a known private key
        uint256 RECOVERY_PRIVATE_KEY = 0xA11CE;
        address recoverySigner = vm.addr(RECOVERY_PRIVATE_KEY);

        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorAddresses[1] = AUTHENTICATOR_ADDRESS2;
        authenticatorRegistry.createAccount(recoverySigner, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        address NEW_AUTHENTICATOR = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            authenticatorRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(accountIndex, NEW_AUTHENTICATOR, newCommitment, nonce),
            RECOVERY_PRIVATE_KEY
        );

        authenticatorRegistry.recoverAccount(
            accountIndex, NEW_AUTHENTICATOR, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, signature, emptyProof(), nonce
        );

        // Old authenticator still exists but with lower recovery counter
        assertEq(
            uint128(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1)),
            uint128(accountIndex)
        );
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1) >> 128, 0);
        // New authenticator added with higher recovery counter
        assertEq(
            uint128(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(NEW_AUTHENTICATOR)),
            uint128(accountIndex)
        );
        assertEq(authenticatorRegistry.authenticatorAddressToPackedAccountIndex(NEW_AUTHENTICATOR) >> 128, 1);
    }
}
