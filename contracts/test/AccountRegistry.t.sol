// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";
import {TreeHelper} from "../src/TreeHelper.sol";
import {BinaryIMT, BinaryIMTData} from "../src/tree/BinaryIMT.sol";

contract AccountRegistryTest is Test {
    using BinaryIMT for BinaryIMTData;

    AccountRegistry public accountRegistry;

    uint256 public constant RECOVERY_PRIVATE_KEY = 0xA11CE;
    uint256 public constant RECOVERY_PRIVATE_KEY_ALT = 0xB11CE;
    uint256 public constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;
    address public recoveryAddress;
    address public alternateRecoveryAddress;
    address public AUTHENTICATOR_ADDRESS1;
    address public AUTHENTICATOR_ADDRESS2;
    address public AUTHENTICATOR_ADDRESS3;
    uint256 public constant AUTH1_PRIVATE_KEY = 0x01;
    uint256 public constant AUTH2_PRIVATE_KEY = 0x02;
    uint256 public constant AUTH3_PRIVATE_KEY = 0x03;

    function setUp() public {
        recoveryAddress = vm.addr(RECOVERY_PRIVATE_KEY);
        accountRegistry = new AccountRegistry();
        alternateRecoveryAddress = vm.addr(RECOVERY_PRIVATE_KEY_ALT);
        AUTHENTICATOR_ADDRESS1 = vm.addr(AUTH1_PRIVATE_KEY);
        AUTHENTICATOR_ADDRESS2 = vm.addr(AUTH2_PRIVATE_KEY);
        AUTHENTICATOR_ADDRESS3 = vm.addr(AUTH3_PRIVATE_KEY);
    }

    ////////////////////////////////////////////////////////////
    //                        Helpers                         //
    ////////////////////////////////////////////////////////////

    function eip712Sign(bytes32 typeHash, bytes memory data, uint256 privateKey) private view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encodePacked(typeHash, data));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", accountRegistry.domainSeparatorV4(), structHash));
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

    function updateAuthenticatorProofAndSignature(
        uint256 accountIndex,
        uint256 pubkeyId,
        uint256 newLeaf,
        uint256 nonce
    ) private returns (bytes memory, uint256[] memory) {
        bytes memory signature = eip712Sign(
            accountRegistry.UPDATE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS1, AUTHENTICATOR_ADDRESS2, pubkeyId, newLeaf, nonce),
            AUTH1_PRIVATE_KEY
        );

        return (signature, emptyProof());
    }

    function updateRecoveryAddressSignature(uint256 accountIndex, address newRecoveryAddress, uint256 nonce)
        private
        returns (bytes memory)
    {
        return eip712Sign(
            accountRegistry.UPDATE_RECOVERY_ADDRESS_TYPEHASH(),
            abi.encode(accountIndex, newRecoveryAddress, nonce),
            AUTH1_PRIVATE_KEY
        );
    }

    ////////////////////////////////////////////////////////////
    //                        Tests                           //
    ////////////////////////////////////////////////////////////

    function test_CreateAccount() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        address[] memory authenticatorAddresses2 = new address[](1);
        authenticatorAddresses2[0] = AUTHENTICATOR_ADDRESS2;
        uint256 size = accountRegistry.nextAccountIndex();
        uint256 startGas = gasleft();
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses2, OFFCHAIN_SIGNER_COMMITMENT);
        uint256 endGas = gasleft();
        console.log("Gas used per create account:", (startGas - endGas));
        assertEq(accountRegistry.nextAccountIndex(), size + 1);
    }

    function test_CreateManyAccounts() public {
        uint256 size = accountRegistry.nextAccountIndex();
        uint256 numAccounts = 100;
        address[] memory recoveryAddresses = new address[](numAccounts);
        address[][] memory authenticatorAddresses = new address[][](numAccounts);
        uint256[] memory offchainSignerCommitments = new uint256[](numAccounts);

        for (uint256 i = 0; i < numAccounts; i++) {
            recoveryAddresses[i] = address(uint160(0x1000 + i));
            authenticatorAddresses[i] = new address[](1);
            authenticatorAddresses[i][0] = address(uint160(i + 1));
            offchainSignerCommitments[i] = OFFCHAIN_SIGNER_COMMITMENT;
        }

        uint256 startGas = gasleft();
        accountRegistry.createManyAccounts(recoveryAddresses, authenticatorAddresses, offchainSignerCommitments);
        uint256 endGas = gasleft();
        console.log("Gas used per account:", (startGas - endGas) / numAccounts);
        assertEq(accountRegistry.nextAccountIndex(), size + numAccounts);
    }

    function test_UpdateAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 0;
        uint256 accountIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // AUTHENTICATOR_ADDRESS1 is assigned to account 1
        uint256 packed1 = accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1);
        assertEq(uint192(packed1), accountIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, 0, newCommitment, nonce);

        uint256 startGas = gasleft();
        accountRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            0,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            proof,
            nonce
        );
        uint256 endGas = gasleft();
        console.log("Gas used per update:", (startGas - endGas));

        // AUTHENTICATOR_ADDRESS1 has been removed
        assertEq(accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1), 0);
        // AUTHENTICATOR_ADDRESS2 has been added
        uint256 packed2 = accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS2);
        assertEq(uint192(packed2), 1);
    }

    function test_UpdateAuthenticatorInvalidAccountIndex() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 0;
        uint256 accountIndex = 2;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, 0, newCommitment, nonce);

        vm.expectRevert("Invalid account index");

        accountRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            0,
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
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 nonce = 1;
        uint256 accountIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // AUTHENTICATOR_ADDRESS1 is assigned to account 1
        uint256 packed = accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1);
        assertEq(uint192(packed), accountIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, 0, newCommitment, nonce);

        vm.expectRevert("Invalid nonce");

        accountRegistry.updateAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS1,
            AUTHENTICATOR_ADDRESS2,
            0,
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
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            accountRegistry.INSERT_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS2, uint256(1), newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        uint256 startGas = gasleft();
        accountRegistry.insertAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS2,
            1,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );
        uint256 endGas = gasleft();
        console.log("Gas used per insert:", (startGas - endGas));

        // Both authenticators should now belong to the same account
        assertEq(
            uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1)), accountIndex
        );
        assertEq(
            uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS2)), accountIndex
        );
    }

    function test_RemoveAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorAddresses[1] = AUTHENTICATOR_ADDRESS2;
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            accountRegistry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, AUTHENTICATOR_ADDRESS2, uint256(1), newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        accountRegistry.removeAuthenticator(
            accountIndex,
            AUTHENTICATOR_ADDRESS2,
            1,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );

        // AUTHENTICATOR_ADDRESS2 should be removed; AUTHENTICATOR_ADDRESS1 remains
        assertEq(accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS2), 0);
        assertEq(
            uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1)), accountIndex
        );
    }

    function test_UpdateRecoveryAddress_SetNewAddress() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        address newRecovery = recoveryAddress;

        bytes memory signature = updateRecoveryAddressSignature(accountIndex, newRecovery, nonce);

        vm.prank(AUTHENTICATOR_ADDRESS1);
        accountRegistry.updateRecoveryAddress(accountIndex, newRecovery, signature, nonce);

        assertEq(accountRegistry.accountIndexToRecoveryAddress(accountIndex), newRecovery);
        assertEq(accountRegistry.signatureNonces(accountIndex), 1);
    }

    function test_UpdateRecoveryAddress_RevertInvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        accountRegistry.createAccount(recoveryAddress, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 1;
        address newRecovery = recoveryAddress;

        bytes memory signature = updateRecoveryAddressSignature(accountIndex, newRecovery, nonce);

        vm.prank(AUTHENTICATOR_ADDRESS1);
        vm.expectRevert("Invalid nonce");
        accountRegistry.updateRecoveryAddress(accountIndex, newRecovery, signature, nonce);
    }

    function test_RecoverAccountSuccess() public {
        // Use a recovery address we control via a known private key
        uint256 recoveryPrivateKey = RECOVERY_PRIVATE_KEY;
        address recoverySigner = vm.addr(recoveryPrivateKey);

        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = AUTHENTICATOR_ADDRESS1;
        authenticatorAddresses[1] = AUTHENTICATOR_ADDRESS2;
        accountRegistry.createAccount(recoverySigner, authenticatorAddresses, OFFCHAIN_SIGNER_COMMITMENT);

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        address NEW_AUTHENTICATOR = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            accountRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(accountIndex, NEW_AUTHENTICATOR, newCommitment, nonce),
            recoveryPrivateKey
        );

        accountRegistry.recoverAccount(
            accountIndex, NEW_AUTHENTICATOR, OFFCHAIN_SIGNER_COMMITMENT, newCommitment, signature, emptyProof(), nonce
        );

        // Old authenticator still exists but with lower recovery counter
        assertEq(
            uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1)),
            uint192(accountIndex)
        );
        assertEq(accountRegistry.authenticatorAddressToPackedAccountIndex(AUTHENTICATOR_ADDRESS1) >> 224, 0);
        // New authenticator added with higher recovery counter
        assertEq(
            uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(NEW_AUTHENTICATOR)), uint192(accountIndex)
        );
        assertEq(accountRegistry.authenticatorAddressToPackedAccountIndex(NEW_AUTHENTICATOR) >> 224, 1);
    }
}
