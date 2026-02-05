// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {WorldIDRegistry} from "../src/WorldIDRegistry.sol";
import {IWorldIDRegistry} from "../src/interfaces/IWorldIDRegistry.sol";
import {WorldIDBase} from "../src/abstract/WorldIDBase.sol";
import {BinaryIMT, BinaryIMTData} from "../src/libraries/BinaryIMT.sol";
import {PackedAccountData} from "../src/libraries/PackedAccountData.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MockERC1271Wallet} from "./Mock1271Wallet.t.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

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

        // Deploy proxy with no fees
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, address(0xAAA), feeToken, 0);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        worldIDRegistry = WorldIDRegistry(address(proxy));

        // Ensure the initial root is recorded as valid
        uint256 root = worldIDRegistry.currentRoot();
        assertTrue(worldIDRegistry.isValidRoot(root));
        assertEq(worldIDRegistry.getRootTimestamp(root), block.timestamp);

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

    function initiateRecoveryAgentUpdateSignature(uint256 leafIndex, address newRecoveryAgent, uint256 nonce)
        private
        view
        returns (bytes memory)
    {
        return eip712Sign(
            worldIDRegistry.INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, newRecoveryAgent, nonce),
            AUTH1_PRIVATE_KEY
        );
    }

    function cancelRecoveryAgentUpdateSignature(uint256 leafIndex, uint256 nonce) private view returns (bytes memory) {
        return eip712Sign(
            worldIDRegistry.CANCEL_RECOVERY_AGENT_UPDATE_TYPEHASH(), abi.encode(leafIndex, nonce), AUTH1_PRIVATE_KEY
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
        uint256 size = worldIDRegistry.getNextLeafIndex();
        uint256 startGas = gasleft();
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        uint256 endGas = gasleft();
        console.log("Gas used per create account:", (startGas - endGas));
        assertEq(worldIDRegistry.getNextLeafIndex(), size + 1);
    }

    function test_CreateManyAccounts() public {
        uint256 size = worldIDRegistry.getNextLeafIndex();
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
        assertEq(worldIDRegistry.getNextLeafIndex(), size + numAccounts);
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
        uint256 packed1 = worldIDRegistry.getPackedAccountData(authenticatorAddress1);
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
        assertEq(worldIDRegistry.getPackedAccountData(authenticatorAddress1), 0);
        // authenticatorAddress2 has been added
        uint256 packed2 = worldIDRegistry.getPackedAccountData(authenticatorAddress2);
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

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.AccountDoesNotExist.selector, leafIndex));

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
        uint256 packed = worldIDRegistry.getPackedAccountData(authenticatorAddress1);
        assertEq(uint192(packed), leafIndex);

        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(leafIndex, 0, newCommitment, nonce);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.MismatchedSignatureNonce.selector, leafIndex, 0, 1));

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
        assertEq(uint192(worldIDRegistry.getPackedAccountData(authenticatorAddress1)), leafIndex);
        assertEq(uint192(worldIDRegistry.getPackedAccountData(authenticatorAddress2)), leafIndex);
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

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.PubkeyIdInUse.selector));
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

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.PubkeyIdInUse.selector));
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
        assertEq(worldIDRegistry.getPackedAccountData(authenticatorAddress2), 0);
        assertEq(uint192(worldIDRegistry.getPackedAccountData(authenticatorAddress1)), leafIndex);
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
        assertEq(uint192(worldIDRegistry.getPackedAccountData(authenticatorAddress1)), uint192(leafIndex));
        // Recovery counter is 0 as it will only be incremented on the NEW_AUTHENTICATOR
        assertEq(PackedAccountData.recoveryCounter(worldIDRegistry.getPackedAccountData(authenticatorAddress1)), 0);

        // New authenticator added with higher recovery counter
        assertEq(uint192(worldIDRegistry.getPackedAccountData(newAuthenticatorAddress)), uint192(leafIndex));
        assertEq(PackedAccountData.recoveryCounter(worldIDRegistry.getPackedAccountData(newAuthenticatorAddress)), 1);

        // Check that we can create a new account with authenticatorAddress1 after recovery
        address[] memory authenticatorAddressesNew = new address[](1);
        authenticatorAddressesNew[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeysNew = new uint256[](1);
        authenticatorPubkeysNew[0] = 0;

        worldIDRegistry.createAccount(
            recoverySigner, authenticatorAddressesNew, authenticatorPubkeysNew, OFFCHAIN_SIGNER_COMMITMENT
        );

        // authenticatorAddress1 now associated with leafIndex = 2
        assertEq(PackedAccountData.leafIndex(worldIDRegistry.getPackedAccountData(authenticatorAddress1)), 2);
        // Recovery counter is 0 for leafIndex = 2
        assertEq(PackedAccountData.recoveryCounter(worldIDRegistry.getPackedAccountData(authenticatorAddress1)), 0);
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
            abi.encodeWithSelector(IWorldIDRegistry.AuthenticatorAddressAlreadyInUse.selector, authenticatorAddress1)
        );
        authenticatorPubkeys[0] = 2;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        assertEq(worldIDRegistry.getPackedAccountData(authenticatorAddress1), 1);
    }

    function test_TreeDepth() public view {
        assertEq(worldIDRegistry.getTreeDepth(), 30);
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
        assertEq(uint192(worldIDRegistry.getPackedAccountData(newAuthenticatorAddress)), uint192(leafIndex));
        assertEq(PackedAccountData.recoveryCounter(worldIDRegistry.getPackedAccountData(newAuthenticatorAddress)), 1);
        assertEq(worldIDRegistry.getRecoveryCounter(leafIndex), 1);
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

    function test_GetRecoveryAgent() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        address retrievedRecoveryAgent = worldIDRegistry.getRecoveryAgent(1);
        assertEq(retrievedRecoveryAgent, recoveryAddress);
    }

    function test_CreateAccountWithNoRecoveryAgent() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            address(0), authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
        assertEq(worldIDRegistry.getPackedAccountData(authenticatorAddress1), 1);
        assertEq(worldIDRegistry.getRecoveryAgent(1), address(0));

        // Now test that we can update the recovery agent to a non-zero address
        uint256 nonce = 0;
        bytes memory signature = initiateRecoveryAgentUpdateSignature(1, alternateRecoveryAddress, nonce);
        worldIDRegistry.initiateRecoveryAgentUpdate(1, alternateRecoveryAddress, signature, nonce);

        // Fast forward and execute
        uint256 cooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        vm.warp(block.timestamp + cooldown);
        worldIDRegistry.executeRecoveryAgentUpdate(1);

        assertEq(worldIDRegistry.getRecoveryAgent(1), alternateRecoveryAddress);
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

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.RecoveryNotEnabled.selector));
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
        assertEq(worldIDRegistry.getMaxAuthenticators(), 1);

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

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.PubkeyIdOutOfBounds.selector));
        worldIDRegistry.createAccount(
            alternateRecoveryAddress, twoAuthenticators, twoAuthenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );
    }

    function test_SetMaxAuthenticators_RevertWhen_ValueAboveLimit() public {
        // Should revert when trying to set maxAuthenticators above 96 (the limit)
        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.OwnerMaxAuthenticatorsOutOfBounds.selector));
        worldIDRegistry.setMaxAuthenticators(97);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.OwnerMaxAuthenticatorsOutOfBounds.selector));
        worldIDRegistry.setMaxAuthenticators(type(uint256).max);
    }

    function test_SetMaxAuthenticators_SucceedsAtMaxValidValue() public {
        // Should succeed when setting to 96 (the maximum allowed value, matching 96-bit bitmap)
        worldIDRegistry.setMaxAuthenticators(96);
        assertEq(worldIDRegistry.getMaxAuthenticators(), 96);
    }

    function test_SetMaxAuthenticators_SucceedsBelowMaxValue() public {
        // Should succeed when setting to values below 96
        worldIDRegistry.setMaxAuthenticators(95);
        assertEq(worldIDRegistry.getMaxAuthenticators(), 95);

        worldIDRegistry.setMaxAuthenticators(50);
        assertEq(worldIDRegistry.getMaxAuthenticators(), 50);

        worldIDRegistry.setMaxAuthenticators(1);
        assertEq(worldIDRegistry.getMaxAuthenticators(), 1);
    }

    ////////////////////////////////////////////////////////////
    //              Tests for Getter Functions                //
    ////////////////////////////////////////////////////////////

    function test_GetPackedAccountData() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 packedData = worldIDRegistry.getPackedAccountData(authenticatorAddress1);
        assertGt(packedData, 0, "Packed data should be non-zero for registered authenticator");

        // Test non-existent authenticator returns 0
        uint256 nonExistentData = worldIDRegistry.getPackedAccountData(address(0xdead));
        assertEq(nonExistentData, 0, "Packed data should be zero for non-existent authenticator");
    }

    function test_GetSignatureNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = worldIDRegistry.getSignatureNonce(leafIndex);
        assertEq(nonce, 0, "Initial nonce should be 0");

        // Update authenticator to increment nonce
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;
        (bytes memory signature, uint256[] memory proof) =
            updateAuthenticatorProofAndSignature(leafIndex, 0, newCommitment, nonce);

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

        uint256 newNonce = worldIDRegistry.getSignatureNonce(leafIndex);
        assertEq(newNonce, 1, "Nonce should increment after operation");
    }

    function test_GetRecoveryCounter() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 counter = worldIDRegistry.getRecoveryCounter(leafIndex);
        assertEq(counter, 0, "Initial recovery counter should be 0");
    }

    function test_GetNextLeafIndex() public {
        uint256 initialIndex = worldIDRegistry.getNextLeafIndex();
        assertEq(initialIndex, 1, "Initial next leaf index should be 1");

        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 newIndex = worldIDRegistry.getNextLeafIndex();
        assertEq(newIndex, initialIndex + 1, "Next leaf index should increment after account creation");
    }

    function test_GetTreeDepth() public {
        uint256 depth = worldIDRegistry.getTreeDepth();
        assertEq(depth, 30, "Tree depth should match initialization value");
    }

    function test_GetMaxAuthenticators() public {
        uint256 maxAuth = worldIDRegistry.getMaxAuthenticators();
        assertEq(maxAuth, 7, "Default max authenticators should be 7");

        worldIDRegistry.setMaxAuthenticators(10);
        maxAuth = worldIDRegistry.getMaxAuthenticators();
        assertEq(maxAuth, 10, "Max authenticators should update after setter is called");
    }

    function test_GetRootTimestamp() public {
        uint256 currentRoot = worldIDRegistry.currentRoot();
        uint256 timestamp = worldIDRegistry.getRootTimestamp(currentRoot);
        assertEq(timestamp, block.timestamp, "Current root timestamp should match block timestamp");

        // Test non-existent root returns 0
        uint256 nonExistentTimestamp = worldIDRegistry.getRootTimestamp(12345);
        assertEq(nonExistentTimestamp, 0, "Non-existent root should have timestamp of 0");
    }

    function test_GetLatestRoot() public {
        uint256 latestRoot = worldIDRegistry.getLatestRoot();
        uint256 currentRoot = worldIDRegistry.currentRoot();
        assertEq(latestRoot, currentRoot, "Latest root should match current root");

        // Create an account to generate a new root
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 newLatestRoot = worldIDRegistry.getLatestRoot();
        assertNotEq(newLatestRoot, latestRoot, "Latest root should change after account creation");
    }

    function test_GetRootValidityWindow() public {
        uint256 window = worldIDRegistry.getRootValidityWindow();
        assertEq(window, 3600, "Default root validity window should be 3600 seconds");

        worldIDRegistry.setRootValidityWindow(7200);
        window = worldIDRegistry.getRootValidityWindow();
        assertEq(window, 7200, "Root validity window should update after setter is called");
    }

    function test_isValidRoot_latestRootAlwaysValid() public {
        // The latest root should always be valid, regardless of validity window
        uint256 root = worldIDRegistry.currentRoot();
        assertTrue(worldIDRegistry.isValidRoot(root));

        // Even with zero validity window, latest root is still valid
        worldIDRegistry.setRootValidityWindow(0);
        assertTrue(worldIDRegistry.isValidRoot(root));

        // Warp far into the future - latest root still valid
        vm.warp(block.timestamp + 365 days);
        assertTrue(worldIDRegistry.isValidRoot(root));
    }

    function test_isValidRoot_expiresAfterWindow() public {
        // Record initial root
        uint256 initialRoot = worldIDRegistry.currentRoot();

        // Create an account to change the root
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        // Now we have a new root, and the initial root is historical
        uint256 newRoot = worldIDRegistry.currentRoot();
        assertTrue(initialRoot != newRoot, "Root should have changed");

        // Initial root should still be valid (within default 1 hour window)
        assertTrue(worldIDRegistry.isValidRoot(initialRoot));

        // Warp time to just before expiration (default is 3600 seconds)
        vm.warp(block.timestamp + 3599);
        assertTrue(worldIDRegistry.isValidRoot(initialRoot), "Root should still be valid before window expires");

        // Warp time past the validity window
        vm.warp(block.timestamp + 2);
        assertFalse(worldIDRegistry.isValidRoot(initialRoot), "Root should be invalid after window expires");

        // Latest root should still be valid
        assertTrue(worldIDRegistry.isValidRoot(newRoot));
    }

    function test_isValidRoot_zeroWindowMakesHistoricalRootsInvalid() public {
        // Record initial root and its timestamp
        uint256 initialRoot = worldIDRegistry.currentRoot();

        // Create an account to change the root
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 newRoot = worldIDRegistry.currentRoot();

        // Initially, the old root should be valid (default 3600s window)
        assertTrue(worldIDRegistry.isValidRoot(initialRoot));

        // Set validity window to 0
        worldIDRegistry.setRootValidityWindow(0);

        // Historical root should now be invalid immediately (since block.timestamp > ts + 0)
        // Note: At the exact same timestamp it would still be valid, but any time advancement makes it invalid
        vm.warp(block.timestamp + 1);
        assertFalse(worldIDRegistry.isValidRoot(initialRoot), "Historical root should be invalid with zero window");

        // Latest root should still be valid
        assertTrue(worldIDRegistry.isValidRoot(newRoot), "Latest root should always be valid");
    }

    function test_isValidRoot_unknownRootReturnsFalse() public {
        // A root that was never recorded should return false
        uint256 unknownRoot = 0x1234567890abcdef;
        assertFalse(worldIDRegistry.isValidRoot(unknownRoot));
    }

    function test_isValidRoot_customValidityWindow() public {
        // Set a custom validity window of 1 day
        uint256 oneDay = 86400;
        worldIDRegistry.setRootValidityWindow(oneDay);

        // Record initial root
        uint256 initialRoot = worldIDRegistry.currentRoot();

        // Create an account to change the root
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        // Warp 23 hours - should still be valid
        vm.warp(block.timestamp + 23 hours);
        assertTrue(worldIDRegistry.isValidRoot(initialRoot), "Root should be valid within 1 day window");

        // Warp past 1 day total
        vm.warp(block.timestamp + 2 hours);
        assertFalse(worldIDRegistry.isValidRoot(initialRoot), "Root should be invalid after 1 day");
    }

    function test_setRootValidityWindow_emitsEvent() public {
        uint256 oldWindow = worldIDRegistry.getRootValidityWindow();
        uint256 newWindow = 7200;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistry.RootValidityWindowUpdated(oldWindow, newWindow);

        worldIDRegistry.setRootValidityWindow(newWindow);
        assertEq(worldIDRegistry.getRootValidityWindow(), newWindow);
    }

    function test_setRootValidityWindow_onlyOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert();
        worldIDRegistry.setRootValidityWindow(100);
    }

    ////////////////////////////////////////////////////////////
    //                   Fee Tests                            //
    ////////////////////////////////////////////////////////////

    function test_SetFeeRecipient() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 100e18);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        address newRecipient = vm.addr(0xAAAA);

        vm.expectEmit();
        emit WorldIDBase.FeeRecipientUpdated(feeRecipient, newRecipient);

        registry.setFeeRecipient(newRecipient);

        assertEq(registry.getFeeRecipient(), newRecipient);
    }

    function test_CannotSetFeeRecipientToZeroAddress() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 100e18);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        vm.expectRevert(abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector));
        registry.setFeeRecipient(address(0));
    }

    function test_OnlyOwnerCanSetFeeRecipient() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 100e18);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        address newRecipient = vm.addr(0xAAAA);

        vm.prank(address(0xBEEF));
        vm.expectRevert();
        registry.setFeeRecipient(newRecipient);
        assertEq(registry.getFeeRecipient(), feeRecipient);
    }

    function test_SetRegistrationFee() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 0);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        uint256 newFee = 1 ether;

        vm.expectEmit();
        emit WorldIDBase.RegistrationFeeUpdated(0, newFee);

        registry.setRegistrationFee(newFee);

        assertEq(registry.getRegistrationFee(), newFee);
    }

    function test_OnlyOwnerCanSetRegistrationFee() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 0);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        uint256 newFee = 1 ether;

        vm.prank(address(0xBEEF));
        vm.expectRevert();
        registry.setRegistrationFee(newFee);
    }

    function test_SetFeeToken() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 100e18);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        ERC20Mock newToken = new ERC20Mock();

        vm.expectEmit();
        emit WorldIDBase.FeeTokenUpdated(address(feeToken), address(newToken));

        registry.setFeeToken(address(newToken));

        assertEq(registry.getFeeToken(), address(newToken));
    }

    function test_CannotSetFeeTokenToZeroAddress() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 100e18);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        vm.expectRevert(abi.encodeWithSelector(WorldIDBase.ZeroAddress.selector));
        registry.setFeeToken(address(0));
    }

    function test_OnlyOwnerCanSetFeeToken() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), 100e18);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        ERC20Mock newToken = new ERC20Mock();

        vm.prank(address(0xBEEF));
        vm.expectRevert();
        registry.setFeeToken(address(newToken));

        assertEq(registry.getFeeToken(), address(feeToken));
    }

    function test_CreateAccountWithFee() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        uint256 fee = 100e18;
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), fee);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        address user = vm.addr(0x1111);
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(0x123);
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        // Mint tokens to user and approve registry
        feeToken.mint(user, fee);
        vm.prank(user);
        feeToken.approve(address(registry), fee);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(user);
        registry.createAccount(address(0xABCD), authenticatorAddresses, authenticatorPubkeys, 0x1234567890);

        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee);
        assertEq(feeToken.balanceOf(user), 0);
    }

    function test_CreateAccountWithExcessFee() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        uint256 fee = 100e18;
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), fee);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        address user = vm.addr(0x1111);
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(0x123);
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        // Mint more tokens than required and approve registry
        feeToken.mint(user, fee * 2);
        vm.prank(user);
        feeToken.approve(address(registry), fee * 2);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(user);
        registry.createAccount(address(0xABCD), authenticatorAddresses, authenticatorPubkeys, 0x1234567890);

        // Only the fee amount should be transferred
        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee);
        assertEq(feeToken.balanceOf(user), fee);
    }

    function test_CannotCreateAccountWithInsufficientFee() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        uint256 fee = 100e18;
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), fee);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        address user = vm.addr(0x1111);
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(0x123);
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        // Mint insufficient tokens
        feeToken.mint(user, fee - 1);
        vm.prank(user);
        feeToken.approve(address(registry), fee - 1);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.InsufficientFunds.selector));
        vm.prank(user);
        registry.createAccount(address(0xABCD), authenticatorAddresses, authenticatorPubkeys, 0x1234567890);
    }

    function test_CreateManyAccountsWithFee() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        uint256 fee = 100e18;
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), fee);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        address user = vm.addr(0x1111);

        address[] memory recoveryAddresses = new address[](3);
        recoveryAddresses[0] = address(uint160(0x1000));
        recoveryAddresses[1] = address(uint160(0x1001));
        recoveryAddresses[2] = address(uint160(0x1002));

        address[][] memory authenticatorAddresses = new address[][](3);
        uint256[][] memory authenticatorPubkeys = new uint256[][](3);
        uint256[] memory offchainSignerCommitments = new uint256[](3);

        for (uint256 i = 0; i < 3; i++) {
            authenticatorAddresses[i] = new address[](1);
            authenticatorAddresses[i][0] = address(uint160(i + 1));
            authenticatorPubkeys[i] = new uint256[](1);
            authenticatorPubkeys[i][0] = 0;
            offchainSignerCommitments[i] = uint256(i + 1);
        }

        // Mint tokens and approve
        feeToken.mint(user, fee * 3);
        vm.prank(user);
        feeToken.approve(address(registry), fee * 3);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(user);
        registry.createManyAccounts(
            recoveryAddresses, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitments
        );

        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee * 3);
        assertEq(feeToken.balanceOf(user), 0);
    }

    function test_CannotCreateManyAccountsWithInsufficientFee() public {
        WorldIDRegistry implementation = new WorldIDRegistry();
        address feeRecipient = vm.addr(0x9999);
        ERC20Mock feeToken = new ERC20Mock();
        uint256 fee = 100e18;
        bytes memory initData =
            abi.encodeWithSelector(WorldIDRegistry.initialize.selector, 30, feeRecipient, address(feeToken), fee);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        WorldIDRegistry registry = WorldIDRegistry(address(proxy));

        address user = vm.addr(0x1111);

        address[] memory recoveryAddresses = new address[](3);
        recoveryAddresses[0] = address(uint160(0x1000));
        recoveryAddresses[1] = address(uint160(0x1001));
        recoveryAddresses[2] = address(uint160(0x1002));

        address[][] memory authenticatorAddresses = new address[][](3);
        uint256[][] memory authenticatorPubkeys = new uint256[][](3);
        uint256[] memory offchainSignerCommitments = new uint256[](3);

        for (uint256 i = 0; i < 3; i++) {
            authenticatorAddresses[i] = new address[](1);
            authenticatorAddresses[i][0] = address(uint160(i + 1));
            authenticatorPubkeys[i] = new uint256[](1);
            authenticatorPubkeys[i][0] = 0;
            offchainSignerCommitments[i] = uint256(i + 1);
        }

        // Mint insufficient tokens (3 * fee - 1)
        feeToken.mint(user, fee * 3 - 1);
        vm.prank(user);
        feeToken.approve(address(registry), fee * 3 - 1);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.InsufficientFunds.selector));
        vm.prank(user);
        registry.createManyAccounts(
            recoveryAddresses, authenticatorAddresses, authenticatorPubkeys, offchainSignerCommitments
        );
    }

    ////////////////////////////////////////////////////////////
    //       Tests for Recovery Agent Update with Cooldown   //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Tests the entire flow of initiating recovery, cooldown period, and executing the recovery
     */
    function test_UpdateRecoveryAgentFullFlow() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        address newRecovery = alternateRecoveryAddress;

        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, newRecovery, nonce);

        uint256 cooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        uint256 expectedExecuteAfter = block.timestamp + cooldown;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistry.RecoveryAgentUpdateInitiated(
            leafIndex, recoveryAddress, newRecovery, expectedExecuteAfter
        );

        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, newRecovery, signature, nonce);

        // Check that pending update was created
        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, newRecovery);
        assertEq(executeAfter, expectedExecuteAfter);

        // Original recovery agent should still be set
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), recoveryAddress);

        // Nonce should be incremented
        assertEq(worldIDRegistry.getSignatureNonce(leafIndex), 1);

        // Fast forward past cooldown
        vm.warp(block.timestamp + cooldown);

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistry.RecoveryAgentUpdateExecuted(leafIndex, recoveryAddress, newRecovery);

        vm.prank(address(0xDDD)); // to ensure anyone can call it
        worldIDRegistry.executeRecoveryAgentUpdate(leafIndex);

        // Check that recovery agent was updated
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), newRecovery);

        // Check that pending update was cleared
        (address pendingAgentAfter, uint256 executeAfterCleared) =
            worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgentAfter, address(0));
        assertEq(executeAfterCleared, 0);
    }

    function test_InitiateRecoveryAgentUpdate_RevertInvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 1;
        address newRecovery = alternateRecoveryAddress;

        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, newRecovery, nonce);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.MismatchedSignatureNonce.selector, leafIndex, 0, 1));
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, newRecovery, signature, nonce);
    }

    function test_InitiateRecoveryAgentUpdate_Success() public {
        // Create account
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;
        address newRecoveryAgent = alternateRecoveryAddress;

        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, newRecoveryAgent, nonce);

        uint256 cooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        uint256 expectedExecuteAfter = block.timestamp + cooldown;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistry.RecoveryAgentUpdateInitiated(
            leafIndex, recoveryAddress, newRecoveryAgent, expectedExecuteAfter
        );

        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, newRecoveryAgent, signature, nonce);

        // Check pending update
        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, newRecoveryAgent);
        assertEq(executeAfter, expectedExecuteAfter);

        // Original recovery agent should still be set
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), recoveryAddress);

        // Nonce should be incremented
        assertEq(worldIDRegistry.getSignatureNonce(leafIndex), 1);
    }

    function test_InitiateRecoveryAgentUpdate_InvalidLeafIndex() public {
        uint256 leafIndex = 999;
        uint256 nonce = 0;
        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, nonce);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.AccountDoesNotExist.selector, leafIndex));
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature, nonce);
    }

    function test_InitiateRecoveryAgentUpdate_InvalidSignature() public {
        // Create account with authenticator1
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        uint256 nonce = 0;

        // Sign with authenticator3 which is NOT part of this account
        bytes memory invalidSignature = eip712Sign(
            worldIDRegistry.INITIATE_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, alternateRecoveryAddress, nonce),
            AUTH3_PRIVATE_KEY // Invalid authenticator
        );

        vm.expectRevert(
            abi.encodeWithSelector(IWorldIDRegistry.AuthenticatorDoesNotExist.selector, authenticatorAddress3)
        );
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, invalidSignature, nonce);
    }

    function test_InitiateRecoveryAgentUpdate_CanOverwritePending() public {
        // Create account and initiate first update
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        bytes memory signature1 = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature1, 0);

        uint256 newTime = block.timestamp + 400;
        vm.warp(newTime);

        // Initiate another update to overwrite
        address thirdRecoveryAgent = address(0xC11CE);
        bytes memory signature2 = initiateRecoveryAgentUpdateSignature(leafIndex, thirdRecoveryAgent, 1);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, thirdRecoveryAgent, signature2, 1);

        // Check that the pending update was overwritten
        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, thirdRecoveryAgent);

        // Assert the cooldown period is restarted
        uint256 cooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        assertEq(executeAfter, newTime + cooldown);
    }

    /**
     * @dev Tests that we can update the recovery agent to the zero address, i.e. unsetting/disabling the Recovery Agent.
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
        bytes memory signature = initiateRecoveryAgentUpdateSignature(1, address(0), nonce);
        worldIDRegistry.initiateRecoveryAgentUpdate(1, address(0), signature, nonce);

        // Fast forward and execute
        uint256 cooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        vm.warp(block.timestamp + cooldown);
        worldIDRegistry.executeRecoveryAgentUpdate(1);

        assertEq(worldIDRegistry.getRecoveryAgent(1), address(0));
    }

    function test_ExecuteRecoveryAgentUpdate_StillInCooldown() public {
        // Create account and initiate update
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature, 0);

        // Try to execute before cooldown expires
        (, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);

        vm.expectRevert(
            abi.encodeWithSelector(
                IWorldIDRegistry.RecoveryAgentUpdateStillInCooldown.selector, leafIndex, executeAfter
            )
        );
        worldIDRegistry.executeRecoveryAgentUpdate(leafIndex);
    }

    function test_ExecuteRecoveryAgentUpdate_NoPendingUpdate() public {
        // Create account without initiating update
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.NoPendingRecoveryAgentUpdate.selector, leafIndex));
        worldIDRegistry.executeRecoveryAgentUpdate(leafIndex);
    }

    function test_CancelRecoveryAgentUpdate_Success() public {
        // Create account with 2 authenticators
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
        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature, 0);

        // Cancel with a different authenticator (AUTH2)
        bytes memory cancelSignature = eip712Sign(
            worldIDRegistry.CANCEL_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, uint256(1)),
            AUTH2_PRIVATE_KEY
        );

        vm.expectEmit(true, true, false, true);
        emit IWorldIDRegistry.RecoveryAgentUpdateCancelled(leafIndex, alternateRecoveryAddress);

        worldIDRegistry.cancelRecoveryAgentUpdate(leafIndex, cancelSignature, 1);

        // Check that pending update was cleared
        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, address(0));
        assertEq(executeAfter, 0);

        // Original recovery agent should still be set
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), recoveryAddress);
    }

    function test_CancelRecoveryAgentUpdate_NoPendingUpdate() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        bytes memory signature = cancelRecoveryAgentUpdateSignature(leafIndex, 0);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.NoPendingRecoveryAgentUpdate.selector, leafIndex));
        worldIDRegistry.cancelRecoveryAgentUpdate(leafIndex, signature, 0);
    }

    function test_CancelRecoveryAgentUpdate_InvalidNonce() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature, 0);

        // Try to cancel with wrong nonce
        bytes memory cancelSignature = cancelRecoveryAgentUpdateSignature(leafIndex, 5);

        vm.expectRevert(abi.encodeWithSelector(IWorldIDRegistry.MismatchedSignatureNonce.selector, leafIndex, 1, 5));
        worldIDRegistry.cancelRecoveryAgentUpdate(leafIndex, cancelSignature, 5);
    }

    function test_CancelRecoveryAgentUpdate_InvalidSignature() public {
        // Create account with authenticator1
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature, 0);

        // Try to cancel with authenticator3 which is NOT part of this account
        bytes memory invalidCancelSignature = eip712Sign(
            worldIDRegistry.CANCEL_RECOVERY_AGENT_UPDATE_TYPEHASH(),
            abi.encode(leafIndex, uint256(1)),
            AUTH3_PRIVATE_KEY // Invalid authenticator
        );

        vm.expectRevert(
            abi.encodeWithSelector(IWorldIDRegistry.AuthenticatorDoesNotExist.selector, authenticatorAddress3)
        );
        worldIDRegistry.cancelRecoveryAgentUpdate(leafIndex, invalidCancelSignature, 1);
    }

    function test_RecoverAccount_AppliesPendingUpdate() public {
        uint256 recoveryPrivateKey = RECOVERY_PRIVATE_KEY;
        address recoverySigner = vm.addr(recoveryPrivateKey);

        // Create account
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoverySigner, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;

        // Initiate recovery agent update
        bytes memory initiateSignature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, initiateSignature, 0);

        // Fast forward past cooldown
        uint256 cooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        vm.warp(block.timestamp + cooldown);

        // Perform recovery - should auto-apply pending update first, so sign with NEW recovery agent
        address newAuthenticatorAddress = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory recoverSignature = eip712Sign(
            worldIDRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(leafIndex, newAuthenticatorAddress, newCommitment, newCommitment, 1),
            RECOVERY_PRIVATE_KEY_ALT // Use alternate key since recovery agent will be updated
        );

        worldIDRegistry.recoverAccount(
            leafIndex,
            newAuthenticatorAddress,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            recoverSignature,
            emptyProof(),
            1
        );

        // Check that recovery agent was updated
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), alternateRecoveryAddress);

        // Check that pending update was cleared
        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, address(0));
        assertEq(executeAfter, 0);

        // Check recovery worked
        assertEq(uint192(worldIDRegistry.getPackedAccountData(newAuthenticatorAddress)), uint192(leafIndex));
    }

    function test_RecoverAccount_DoesNotApplyPendingUpdateIfStillInCooldown() public {
        uint256 recoveryPrivateKey = RECOVERY_PRIVATE_KEY;
        address recoverySigner = vm.addr(recoveryPrivateKey);

        // Create account
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoverySigner, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;

        // Initiate recovery agent update
        bytes memory initiateSignature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, initiateSignature, 0);

        // Perform recovery - should NOT apply pending update (still in cooldown)
        address newAuthenticatorAddress = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        bytes memory recoverSignature = eip712Sign(
            worldIDRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(leafIndex, newAuthenticatorAddress, newCommitment, newCommitment, 1),
            recoveryPrivateKey
        );

        worldIDRegistry.recoverAccount(
            leafIndex,
            newAuthenticatorAddress,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            recoverSignature,
            emptyProof(),
            1
        );

        // Check that recovery agent was NOT updated (still original)
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), recoverySigner);

        // Pending update should be cleared after recovery
        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, address(0));
        assertEq(executeAfter, 0);
    }

    function test_SetRecoveryAgentUpdateCooldown_Success() public {
        uint256 oldCooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        uint256 newCooldown = 14 days;

        vm.expectEmit(true, true, true, true);
        emit IWorldIDRegistry.RecoveryAgentUpdateCooldownUpdated(oldCooldown, newCooldown);

        worldIDRegistry.setRecoveryAgentUpdateCooldown(newCooldown);

        assertEq(worldIDRegistry.getRecoveryAgentUpdateCooldown(), newCooldown);
    }

    function test_SetRecoveryAgentUpdateCooldown_OnlyOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert();
        worldIDRegistry.setRecoveryAgentUpdateCooldown(1 days);
    }

    function test_SetRecoveryAgentUpdateCooldown_CanSetToZero() public {
        worldIDRegistry.setRecoveryAgentUpdateCooldown(0);
        assertEq(worldIDRegistry.getRecoveryAgentUpdateCooldown(), 0);

        // With zero cooldown, update should be executable immediately
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature, 0);

        // Should be executable immediately
        worldIDRegistry.executeRecoveryAgentUpdate(leafIndex);
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), alternateRecoveryAddress);
    }

    function test_GetRecoveryAgentUpdateCooldown_DefaultValue() public {
        uint256 cooldown = worldIDRegistry.getRecoveryAgentUpdateCooldown();
        assertEq(cooldown, 14 days, "Default cooldown should be 14 days");
    }

    function test_GetPendingRecoveryAgentUpdate_NoPending() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, address(0));
        assertEq(executeAfter, 0);
    }

    function test_GetPendingRecoveryAgentUpdate_WithPending() public {
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoveryAddress, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;
        bytes memory signature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, signature, 0);

        (address pendingAgent, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, alternateRecoveryAddress);
        assertEq(executeAfter, block.timestamp + 14 days);
    }

    function test_CannotRecoverWithPendingRecoveryAgent() public {
        uint256 recoveryPrivateKey = RECOVERY_PRIVATE_KEY;
        address recoverySigner = vm.addr(recoveryPrivateKey);

        // Create account with current recovery agent
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = authenticatorAddress1;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;
        worldIDRegistry.createAccount(
            recoverySigner, authenticatorAddresses, authenticatorPubkeys, OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 leafIndex = 1;

        // Initiate recovery agent update to alternateRecoveryAddress
        bytes memory initiateSignature = initiateRecoveryAgentUpdateSignature(leafIndex, alternateRecoveryAddress, 0);
        worldIDRegistry.initiateRecoveryAgentUpdate(leafIndex, alternateRecoveryAddress, initiateSignature, 0);

        // Verify that pending recovery agent is set
        (address pendingAgent,) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(pendingAgent, alternateRecoveryAddress);

        // Verify that CURRENT recovery agent is still the original
        assertEq(worldIDRegistry.getRecoveryAgent(leafIndex), recoverySigner);

        // Now verify that only the CURRENT recovery agent can perform recovery, not the pending one
        address newAuthenticatorAddress = address(0xBEEF);
        uint256 newCommitment = OFFCHAIN_SIGNER_COMMITMENT + 1;

        // This should succeed - using CURRENT recovery agent
        bytes memory validRecoverSignature = eip712Sign(
            worldIDRegistry.RECOVER_ACCOUNT_TYPEHASH(),
            abi.encode(leafIndex, newAuthenticatorAddress, newCommitment, newCommitment, 1),
            recoveryPrivateKey // Current recovery agent
        );

        worldIDRegistry.recoverAccount(
            leafIndex,
            newAuthenticatorAddress,
            newCommitment,
            OFFCHAIN_SIGNER_COMMITMENT,
            newCommitment,
            validRecoverSignature,
            emptyProof(),
            1
        );

        // Recovery should have succeeded using current recovery agent
        assertEq(uint192(worldIDRegistry.getPackedAccountData(newAuthenticatorAddress)), uint192(leafIndex));

        // Pending update should be cleared after recovery (even though it wasn't past cooldown)
        (address stillPending, uint256 executeAfter) = worldIDRegistry.getPendingRecoveryAgentUpdate(leafIndex);
        assertEq(stillPending, address(0));
        assertEq(executeAfter, 0);
    }
}
