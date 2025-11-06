// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";
import {BinaryIMT, BinaryIMTData} from "../src/tree/BinaryIMT.sol";
import {PackedAccountIndex} from "../src/lib/PackedAccountIndex.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract AccountRegistryTest is Test {
    using BinaryIMT for BinaryIMTData;

    AccountRegistry public accountRegistry;

    uint256 public constant RECOVERY_PRIVATE_KEY = 0xA11CE;
    uint256 public constant RECOVERY_PRIVATE_KEY_ALT = 0xB11CE;
    uint256 public constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;
    address public recoveryAddress;
    address public alternateRecoveryAddress;
    address public authenticatorAddress1;
    address public authenticatorAddress2;
    address public authenticatorAddress3;
    uint256 public constant AUTH1_PRIVATE_KEY = 0x01;
    uint256 public constant AUTH2_PRIVATE_KEY = 0x02;
    uint256 public constant AUTH3_PRIVATE_KEY = 0x03;

    function setUp() public {
        recoveryAddress = vm.addr(RECOVERY_PRIVATE_KEY);

        // Deploy implementation
        AccountRegistry implementation = new AccountRegistry();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(AccountRegistry.initialize.selector, 30);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        accountRegistry = AccountRegistry(address(proxy));

        alternateRecoveryAddress = vm.addr(RECOVERY_PRIVATE_KEY_ALT);
        authenticatorAddress1 = vm.addr(AUTH1_PRIVATE_KEY);
        authenticatorAddress2 = vm.addr(AUTH2_PRIVATE_KEY);
        authenticatorAddress3 = vm.addr(AUTH3_PRIVATE_KEY);
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
    ) private view returns (bytes memory, uint256[] memory) {
        bytes memory signature = eip712Sign(
            accountRegistry.UPDATE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, authenticatorAddress1, authenticatorAddress2, pubkeyId, newLeaf, newLeaf, nonce),
            AUTH1_PRIVATE_KEY
        );

        return (signature, emptyProof());
    }

    function updateRecoveryAddressSignature(uint256 accountIndex, address newRecoveryAddress, uint256 nonce)
        private
        view
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
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        uint256 size = accountRegistry.nextAccountIndex();
        uint256 startGas = gasleft();
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        uint256 endGas = gasleft();
        console.log("Gas used per create account:", (startGas - endGas));
        assertEq(accountRegistry.nextAccountIndex(), size + 1);
    }

    function test_CreateManyAccounts() public {
        uint256 size = accountRegistry.nextAccountIndex();
        uint256 numAccounts = 100;
        address[] memory recoveryAddresses = new address[](numAccounts);
        address[][] memory authenticatorAddresses = new address[][](numAccounts);
        uint256[][] memory authenticatorPubkeys = new uint256[][](numAccounts);
        uint256[] memory offchainSignerCommitments = new uint256[](numAccounts);

        for (uint256 i = 0; i < numAccounts; i++) {
            recoveryAddresses[i] = address(uint160(0x1000 + i));
            authenticatorAddresses[i] = new address[](1);
            authenticatorAddresses[i][0] = address(uint160(i + 1));
            authenticatorPubkeys[i] = new uint256[](1);
            authenticatorPubkeys[i][0] = 0;
            offchainSignerCommitments[i] = OFFCHAIN_SIGNER_COMMITMENT;
        }

        uint256 startGas = gasleft();
        accountRegistry.createManyAccounts(
            recoveryAddresses, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitments
        );
        uint256 endGas = gasleft();
        console.log("Gas used per account:", (startGas - endGas) / numAccounts);
        assertEq(accountRegistry.nextAccountIndex(), size + numAccounts);
    }

    function test_UpdateAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 nonce = 0;
        uint256 accountIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // authenticatorAddress1 is assigned to account 1
        uint256 packed1 = accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1);
        assertEq(uint192(packed1), accountIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, 0, newCommitment, nonce);

        uint256 startGas = gasleft();
        accountRegistry.updateAuthenticator(
            accountIndex,
            authenticatorAddress1,
            authenticatorAddress2,
            0,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            proof,
            nonce
        );
        uint256 endGas = gasleft();
        console.log("Gas used per update:", (startGas - endGas));

        // authenticatorAddress1 has been removed
        assertEq(accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1), 0);
        // authenticatorAddress2 has been added
        uint256 packed2 = accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress2);
        assertEq(uint192(packed2), 1);
    }

    function test_UpdateAuthenticatorInvalidAccountIndex() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 nonce = 0;
        uint256 accountIndex = 2;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, 0, newCommitment, nonce);

        vm.expectRevert("Invalid account index");

        accountRegistry.updateAuthenticator(
            accountIndex,
            authenticatorAddress1,
            authenticatorAddress2,
            0,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            proof,
            nonce
        );
    }

    function test_UpdateAuthenticatorInvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 nonce = 1;
        uint256 accountIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // authenticatorAddress1 is assigned to account 1
        uint256 packed = accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1);
        assertEq(uint192(packed), accountIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(accountIndex, 0, newCommitment, nonce);

        vm.expectRevert("Invalid nonce");

        accountRegistry.updateAuthenticator(
            accountIndex,
            authenticatorAddress1,
            authenticatorAddress2,
            0,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            proof,
            nonce
        );
    }

    function test_InsertAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            accountRegistry.INSERT_AUTHENTICATOR_TYPEHASH(),
            abi.encode(accountIndex, authenticatorAddress2, uint256(1), newCommitment, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        uint256 startGas = gasleft();
        accountRegistry.insertAuthenticator(
            accountIndex,
            authenticatorAddress2,
            1,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );
        uint256 endGas = gasleft();
        console.log("Gas used per insert:", (startGas - endGas));

        // Both authenticators should now belong to the same account
        assertEq(uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1)), accountIndex);
        assertEq(uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress2)), accountIndex);
    }

    function test_RemoveAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = authenticatorAddress1;
        authenticatorAddresses[1] = authenticatorAddress2;
        uint256[] memory authenticatorPubkeys = new uint256[](2);
        authenticatorPubkeys[0] = 0;
        authenticatorPubkeys[1] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            accountRegistry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(
                accountIndex, authenticatorAddress2, uint256(1), OFFCHAIN_SIGNER_COMMITMENT, newCommitment, nonce
            ),
            AUTH1_PRIVATE_KEY
        );

        accountRegistry.removeAuthenticator(
            accountIndex,
            authenticatorAddress2,
            1,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );

        // authenticatorAddress2 should be removed; authenticatorAddress1 remains
        assertEq(accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress2), 0);
        assertEq(uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1)), accountIndex);
    }

    function test_UpdateRecoveryAddress_SetNewAddress() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        address newRecovery = recoveryAddress;

        bytes memory signature = updateRecoveryAddressSignature(accountIndex, newRecovery, nonce);

        vm.prank(authenticatorAddress1);
        accountRegistry.updateRecoveryAddress(accountIndex, newRecovery, signature, nonce);

        assertEq(accountRegistry.accountIndexToRecoveryAddress(accountIndex), newRecovery);
        assertEq(accountRegistry.signatureNonces(accountIndex), 1);
    }

    function test_UpdateRecoveryAddress_RevertInvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 accountIndex = 1;
        uint256 nonce = 1;
        address newRecovery = recoveryAddress;

        bytes memory signature = updateRecoveryAddressSignature(accountIndex, newRecovery, nonce);

        vm.prank(authenticatorAddress1);
        vm.expectRevert("Invalid nonce");
        accountRegistry.updateRecoveryAddress(accountIndex, newRecovery, signature, nonce);
    }

    function test_RecoverAccountSuccess() public {
        // Use a recovery address we control via a known private key
        uint256 recoveryPrivateKey = RECOVERY_PRIVATE_KEY;
        address recoverySigner = vm.addr(recoveryPrivateKey);

        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = authenticatorAddress1;
        authenticatorAddresses[1] = authenticatorAddress2;
        uint256[] memory authenticatorPubkeys = new uint256[](2);
        authenticatorPubkeys[0] = 0;
        authenticatorPubkeys[1] = 0;
        accountRegistry.createAccount(
            recoverySigner, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 accountIndex = 1;
        uint256 nonce = 0;
        address newAuthenticatorAddress = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            accountRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(accountIndex, newAuthenticatorAddress, newCommitment, newCommitment, nonce),
            recoveryPrivateKey
        );

        accountRegistry.recoverAccount(
            accountIndex,
            newAuthenticatorAddress,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );

        // authenticatorAddress1 still associated with accountIndex = 1
        assertEq(
            uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1)),
            uint192(accountIndex)
        );
        // Recovery counter is 0 as it will only be incremented on the NEW_AUTHENTICATOR
        assertEq(
            PackedAccountIndex.recoveryCounter(
                accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1)
            ),
            0
        );

        // New authenticator added with higher recovery counter
        assertEq(
            uint192(accountRegistry.authenticatorAddressToPackedAccountIndex(newAuthenticatorAddress)),
            uint192(accountIndex)
        );
        assertEq(
            PackedAccountIndex.recoveryCounter(
                accountRegistry.authenticatorAddressToPackedAccountIndex(newAuthenticatorAddress)
            ),
            1
        );

        // Check that we can create a new account with authenticatorAddress1 after recovery
        address[] memory authenticatorAddressesNew = new address[](1);
        authenticatorAddressesNew[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeysNew = new uint256[](1);
        authenticatorPubkeysNew[0] = 0;

        accountRegistry.createAccount(
            recoverySigner, authenticatorAddressesNew, authenticatorPubkeysNew, OFFCHAIN_SIGNER_COMMITMENT
        );

        // authenticatorAddress1 now associated with accountIndex = 2
        assertEq(
            PackedAccountIndex.accountIndex(
                accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1)
            ),
            2
        );
        // Recovery counter is 0 for accountIndex = 2
        assertEq(
            PackedAccountIndex.recoveryCounter(
                accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1)
            ),
            0
        );
    }

    function test_CannotRegisterAuthenticatorAddressThatIsAlreadyInUse() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        vm.expectRevert(
            abi.encodeWithSelector(AccountRegistry.AuthenticatorAddressAlreadyInUse.selector, authenticatorAddress1)
        );
        authenticatorPubkeys[0] = 2;
        accountRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        assertEq(accountRegistry.authenticatorAddressToPackedAccountIndex(authenticatorAddress1), 1);
    }
}
