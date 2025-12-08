// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {WorldIDRegistry} from "../src/WorldIDRegistry.sol";
import {BinaryIMT, BinaryIMTData} from "../src/tree/BinaryIMT.sol";
import {PackedAccountData} from "../src/lib/PackedAccountData.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MockERC1271Wallet} from "./Mock1271Wallet.t.sol";

contract WorldIDRegistryTest is Test {
    using BinaryIMT for BinaryIMTData;

    WorldIDRegistry public worldIDRegistry;

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
        WorldIDRegistry implementation = new WorldIDRegistry();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        worldIDRegistry = WorldIDRegistry(address(proxy));

        // Ensure the initial root is recorded as valid
        uint256 root = worldIDRegistry.currentRoot();
        assertTrue(worldIDRegistry.isValidRoot(root));
        assertEq(worldIDRegistry.rootToTimestamp(root), block.timestamp);

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
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", worldIDRegistry.domainSeparatorV4(), structHash));
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

    function updateAuthenticatorProofAndSignature(uint256 leafIndex, uint32 pubkeyId, uint256 newLeaf, uint256 nonce)
        private
        view
        returns (bytes memory, uint256[] memory)
    {
        bytes memory signature = eip712Sign(
            worldIDRegistry.UPDATE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, authenticatorAddress1, authenticatorAddress2, pubkeyId, newLeaf, newLeaf, nonce),
            AUTH1_PRIVATE_KEY
        );

        return (signature, emptyProof());
    }

    function updateRecoveryAddressSignature(uint256 leafIndex, address newRecoveryAddress, uint256 nonce)
        private
        view
        returns (bytes memory)
    {
        return eip712Sign(
            worldIDRegistry.UPDATE_RECOVERY_ADDRESS_TYPEHASH(),
            abi.encode(leafIndex, newRecoveryAddress, nonce),
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
        uint256 size = worldIDRegistry.nextLeafIndex();
        uint256 startGas = gasleft();
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        uint256 endGas = gasleft();
        console.log("Gas used per create account:", (startGas - endGas));
        assertEq(worldIDRegistry.nextLeafIndex(), size + 1);
    }

    function test_CreateManyAccounts() public {
        uint256 size = worldIDRegistry.nextLeafIndex();
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
        worldIDRegistry.createManyAccounts(
            recoveryAddresses, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitments
        );
        uint256 endGas = gasleft();
        console.log("Gas used per account:", (startGas - endGas) / numAccounts);
        assertEq(worldIDRegistry.nextLeafIndex(), size + numAccounts);
    }

    function test_UpdateAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 nonce = 0;
        uint256 leafIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // authenticatorAddress1 is assigned to account 1
        uint256 packed1 = worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1);
        assertEq(uint192(packed1), leafIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(leafIndex, 0, newCommitment, nonce);

        uint256 startGas = gasleft();
        worldIDRegistry.updateAuthenticator(
            leafIndex,
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
        assertEq(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1), 0);
        // authenticatorAddress2 has been added
        uint256 packed2 = worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress2);
        assertEq(uint192(packed2), 1);
    }

    function test_UpdateAuthenticatorInvalidLeafIndex() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 nonce = 0;
        uint256 leafIndex = 2;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(leafIndex, 0, newCommitment, nonce);

        vm.expectRevert(abi.encodeWithSelector(WorldIDRegistry.AccountDoesNotExist.selector, leafIndex));

        worldIDRegistry.updateAuthenticator(
            leafIndex,
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
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 nonce = 1;
        uint256 leafIndex = 1;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // authenticatorAddress1 is assigned to account 1
        uint256 packed = worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1);
        assertEq(uint192(packed), leafIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(leafIndex, 0, newCommitment, nonce);

        vm.expectRevert(abi.encodeWithSelector(WorldIDRegistry.MismatchedSignatureNonce.selector, leafIndex, 0, 1));

        worldIDRegistry.updateAuthenticator(
            leafIndex,
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
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            worldIDRegistry.INSERT_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, authenticatorAddress2, uint256(1), newCommitment, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        uint256 startGas = gasleft();
        worldIDRegistry.insertAuthenticator(
            leafIndex,
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
        assertEq(uint192(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1)), leafIndex);
        assertEq(uint192(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress2)), leafIndex);
    }

    function test_InsertAuthenticatorDuplicatePubkeyId() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;

        uint256[] memory siblingNodes = new uint256[](30);

        vm.expectRevert(abi.encodeWithSelector(WorldIDRegistry.PubkeyIdInUse.selector));
        worldIDRegistry.insertAuthenticator(
            leafIndex,
            authenticatorAddress3,
            0, // same pubkeyId as authenticatorAddress1
            2, // pubkey
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT + 1,
            bytes(""), // we don't get to the signature verification
            siblingNodes,
            nonce
        );
    }

    function test_InsertAuthenticatorDuplicatePubkeyIdNonZeroIndex() public {
        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = authenticatorAddress1;
        authenticatorAddresses[1] = authenticatorAddress3;
        uint256[] memory authenticatorPubkeys = new uint256[](2);
        authenticatorPubkeys[0] = 0;
        authenticatorPubkeys[1] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        address newAuthenticatorAddress = address(0x4);

        uint256[] memory siblingNodes = new uint256[](30);

        vm.expectRevert(abi.encodeWithSelector(WorldIDRegistry.PubkeyIdInUse.selector));
        worldIDRegistry.insertAuthenticator(
            leafIndex,
            newAuthenticatorAddress,
            1, // same pubkeyId as authenticatorAddress3
            4, // pubkey
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT + 1,
            bytes(""), // we don't get to the signature verification
            siblingNodes,
            nonce
        );
    }

    function test_RemoveAuthenticatorSuccess() public {
        address[] memory authenticatorAddresses = new address[](2);
        authenticatorAddresses[0] = authenticatorAddress1;
        authenticatorAddresses[1] = authenticatorAddress2;
        uint256[] memory authenticatorPubkeys = new uint256[](2);
        authenticatorPubkeys[0] = 0;
        authenticatorPubkeys[1] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            worldIDRegistry.REMOVE_AUTHENTICATOR_TYPEHASH(),
            abi.encode(leafIndex, authenticatorAddress2, uint256(1), OFFCHAIN_SIGNER_COMMITMENT, newCommitment, nonce),
            AUTH1_PRIVATE_KEY
        );

        worldIDRegistry.removeAuthenticator(
            leafIndex,
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
        assertEq(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress2), 0);
        assertEq(uint192(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1)), leafIndex);
    }

    function test_UpdateRecoveryAddress_SetNewAddress() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        address newRecovery = recoveryAddress;

        bytes memory signature = updateRecoveryAddressSignature(leafIndex, newRecovery, nonce);

        vm.prank(authenticatorAddress1);
        worldIDRegistry.updateRecoveryAddress(leafIndex, newRecovery, signature, nonce);

        assertEq(worldIDRegistry.getRecoveryAddress(leafIndex), newRecovery);
        assertEq(worldIDRegistry.leafIndexToSignatureNonce(leafIndex), 1);
    }

    function test_UpdateRecoveryAddress_RevertInvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 1;
        address newRecovery = recoveryAddress;

        bytes memory signature = updateRecoveryAddressSignature(leafIndex, newRecovery, nonce);

        vm.prank(authenticatorAddress1);
        vm.expectRevert(abi.encodeWithSelector(WorldIDRegistry.MismatchedSignatureNonce.selector, leafIndex, 0, 1));
        worldIDRegistry.updateRecoveryAddress(leafIndex, newRecovery, signature, nonce);
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
        worldIDRegistry.createAccount(
            recoverySigner, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        address newAuthenticatorAddress = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory signature = eip712Sign(
            worldIDRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(leafIndex, newAuthenticatorAddress, newCommitment, newCommitment, nonce),
            recoveryPrivateKey
        );

        worldIDRegistry.recoverAccount(
            leafIndex,
            newAuthenticatorAddress,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );

        // authenticatorAddress1 still associated with leafIndex = 1
        assertEq(
            uint192(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1)), uint192(leafIndex)
        );
        // Recovery counter is 0 as it will only be incremented on the NEW_AUTHENTICATOR
        assertEq(
            PackedAccountData.recoveryCounter(
                worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1)
            ),
            0
        );

        // New authenticator added with higher recovery counter
        assertEq(
            uint192(worldIDRegistry.authenticatorAddressToPackedAccountData(newAuthenticatorAddress)),
            uint192(leafIndex)
        );
        assertEq(
            PackedAccountData.recoveryCounter(
                worldIDRegistry.authenticatorAddressToPackedAccountData(newAuthenticatorAddress)
            ),
            1
        );

        // Check that we can create a new account with authenticatorAddress1 after recovery
        address[] memory authenticatorAddressesNew = new address[](1);
        authenticatorAddressesNew[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeysNew = new uint256[](1);
        authenticatorPubkeysNew[0] = 0;

        worldIDRegistry.createAccount(
            recoverySigner, authenticatorAddressesNew, authenticatorPubkeysNew, OFFCHAIN_SIGNER_COMMITMENT
        );

        // authenticatorAddress1 now associated with leafIndex = 2
        assertEq(
            PackedAccountData.leafIndex(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1)),
            2
        );
        // Recovery counter is 0 for leafIndex = 2
        assertEq(
            PackedAccountData.recoveryCounter(
                worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1)
            ),
            0
        );
    }

    function test_CannotRegisterAuthenticatorAddressThatIsAlreadyInUse() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        vm.expectRevert(
            abi.encodeWithSelector(WorldIDRegistry.AuthenticatorAddressAlreadyInUse.selector, authenticatorAddress1)
        );
        authenticatorPubkeys[0] = 2;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        assertEq(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1), 1);
    }

    function test_TreeDepth() public view {
        assertEq(worldIDRegistry.treeDepth(), 30);
    }

    function test_RecoverAccountWithERC1271Wallet() public {
        // Create a mock ERC-1271 wallet controlled by recoveryAddress
        MockERC1271Wallet wallet = new MockERC1271Wallet(recoveryAddress);

        // Create an account with the smart contract wallet as the recovery signer
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            address(wallet), authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        address newAuthenticatorAddress = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // Sign with the wallet owner's private key
        bytes memory signature = eip712Sign(
            worldIDRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(leafIndex, newAuthenticatorAddress, newCommitment, newCommitment, nonce),
            RECOVERY_PRIVATE_KEY
        );

        uint256 startGas = gasleft();
        worldIDRegistry.recoverAccount(
            leafIndex,
            newAuthenticatorAddress,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            signature,
            emptyProof(),
            nonce
        );
        uint256 endGas = gasleft();
        console.log("Gas used for ERC-1271 recovery:", (startGas - endGas));

        // Verify recovery was successful
        assertEq(
            uint192(worldIDRegistry.authenticatorAddressToPackedAccountData(newAuthenticatorAddress)),
            uint192(leafIndex)
        );
        assertEq(
            PackedAccountData.recoveryCounter(
                worldIDRegistry.authenticatorAddressToPackedAccountData(newAuthenticatorAddress)
            ),
            1
        );
        assertEq(worldIDRegistry.leafIndexToRecoveryCounter(leafIndex), 1);
    }

    function test_MockERC1271Wallet_Validation() public {
        // Test the mock wallet directly
        MockERC1271Wallet wallet = new MockERC1271Wallet(recoveryAddress);

        bytes32 testHash = keccak256("test");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(RECOVERY_PRIVATE_KEY, testHash);
        bytes memory validSig = abi.encodePacked(r, s, v);

        // Valid signature should return magic value
        bytes4 result = wallet.isValidSignature(testHash, validSig);
        assertEq(result, bytes4(0x1626ba7e));

        // Invalid signature (signed by different key) should return 0xffffffff
        (v, r, s) = vm.sign(RECOVERY_PRIVATE_KEY_ALT, testHash);
        bytes memory invalidSig = abi.encodePacked(r, s, v);
        result = wallet.isValidSignature(testHash, invalidSig);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_GetRecoveryAddress() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        address retrievedRecoveryAddress = worldIDRegistry.getRecoveryAddress(1);
        assertEq(retrievedRecoveryAddress, recoveryAddress);
    }

    function test_CreateAccountWithNoRecoveryAgent() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            address(0), authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        assertEq(worldIDRegistry.authenticatorAddressToPackedAccountData(authenticatorAddress1), 1);
        assertEq(worldIDRegistry.getRecoveryAddress(1), address(0));

        // Now test that we can update the recovery address to a non-zero address
        uint256 nonce = 0;
        bytes memory signature = updateRecoveryAddressSignature(1, alternateRecoveryAddress, nonce);
        worldIDRegistry.updateRecoveryAddress(1, alternateRecoveryAddress, signature, nonce);
        assertEq(worldIDRegistry.getRecoveryAddress(1), alternateRecoveryAddress);
    }

    /**
     * @dev Tests that we can update the recovery address to the zero address, i.e. unsetting/disabling the Recovery Agent.
     */
    function test_UpdateRecoveryAddressToZeroAddress() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        uint256 nonce = 0;
        bytes memory signature = updateRecoveryAddressSignature(1, address(0), nonce);
        worldIDRegistry.updateRecoveryAddress(1, address(0), signature, nonce);
    }

    function test_CannotRecoverAccountWhichHasNoRecoveryAgent() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            address(0), authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256[] memory siblingNodes = new uint256[](30);

        vm.expectRevert(abi.encodeWithSelector(WorldIDRegistry.RecoveryNotEnabled.selector));
        worldIDRegistry.recoverAccount(
            1,
            authenticatorAddress1,
            0,
            OFFCHAIN_SIGNER_COMMITMENT,
            OFFCHAIN_SIGNER_COMMITMENT,
            bytes(""),
            siblingNodes,
            0
        );
    }

    function test_SetMaxAuthenticators() public {
        // Set max authenticators to 1
        worldIDRegistry.setMaxAuthenticators(1);
        assertEq(worldIDRegistry.maxAuthenticators(), 1);

        // Create account with 1 authenticator should succeed
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        // Trying to create account with 2 authenticators should fail
        address[] memory twoAuthenticators = new address[](2);
        twoAuthenticators[0] = authenticatorAddress2;
        twoAuthenticators[1] = authenticatorAddress3;
        uint256[] memory twoAuthenticatorPubkeys = new uint256[](2);
        twoAuthenticatorPubkeys[0] = 0;
        twoAuthenticatorPubkeys[1] = 0;

        vm.expectRevert(abi.encodeWithSelector(WorldIDRegistry.PubkeyIdOutOfBounds.selector));
        worldIDRegistry.createAccount(
            alternateRecoveryAddress, twoAuthenticators, twoAuthenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
    }
}
