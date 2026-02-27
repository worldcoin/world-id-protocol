// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AddressBook} from "../../src/address-book/AddressBook.sol";
import {IAddressBook} from "../../src/address-book/interfaces/IAddressBook.sol";

contract MockWorldIDVerifierUpgrade {
    bool public shouldRevert;

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function verify(uint256, uint256, uint64, uint256, uint256, uint64, uint64, uint256, uint256[5] calldata)
        external
        view
    {
        if (shouldRevert) {
            revert("proof-invalid");
        }
    }
}

contract AddressBookV2Mock is AddressBook {
    uint256 public newFeature;

    function version() external pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 value) external {
        newFeature = value;
    }
}

contract AddressBookUpgradeTest is Test {
    uint64 internal constant RP_ID = 42;
    uint256 internal constant ACTION = 12345;
    uint64 internal constant PERIOD_LENGTH_SECONDS = 30 days;

    AddressBook internal addressBook;
    MockWorldIDVerifierUpgrade internal verifier;

    address internal user1 = address(0x1001);

    function setUp() public {
        vm.warp(1_000_000);

        verifier = new MockWorldIDVerifierUpgrade();
        AddressBook implementation = new AddressBook();

        bytes memory initData = abi.encodeWithSelector(
            AddressBook.initialize.selector, address(verifier), uint64(block.timestamp), PERIOD_LENGTH_SECONDS, true
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        addressBook = AddressBook(address(proxy));
    }

    function _epoch() internal pure returns (IAddressBook.EpochData memory) {
        return IAddressBook.EpochData({rpId: RP_ID, action: ACTION});
    }

    function _proof(uint256 nullifier) internal view returns (IAddressBook.RegistrationProof memory) {
        uint256[5] memory zkProof;
        zkProof[0] = 1;
        zkProof[1] = 2;
        zkProof[2] = 3;
        zkProof[3] = 4;
        zkProof[4] = 5;

        return IAddressBook.RegistrationProof({
            nullifier: nullifier,
            nonce: 77,
            expiresAtMin: uint64(block.timestamp + 1 days),
            issuerSchemaId: 8,
            credentialGenesisIssuedAtMin: 0,
            zeroKnowledgeProof: zkProof
        });
    }

    function testUpgradePreservesState() public {
        uint32 currentPeriod = addressBook.getCurrentPeriod();
        IAddressBook.EpochData memory epoch = _epoch();

        vm.prank(user1);
        addressBook.register(user1, currentPeriod, epoch, _proof(111));
        assertTrue(addressBook.verify(epoch, user1));

        AddressBookV2Mock implementationV2 = new AddressBookV2Mock();
        addressBook.upgradeToAndCall(address(implementationV2), "");

        AddressBookV2Mock upgraded = AddressBookV2Mock(address(addressBook));

        assertTrue(upgraded.verify(epoch, user1));
        assertEq(upgraded.getWorldIDVerifier(), address(verifier));
        assertEq(upgraded.getCurrentPeriod(), currentPeriod);

        upgraded.setNewFeature(42);
        assertEq(upgraded.newFeature(), 42);
        assertEq(upgraded.version(), "V2");
    }

    function testUpgradeFailsForNonOwner() public {
        AddressBookV2Mock implementationV2 = new AddressBookV2Mock();

        vm.prank(address(0xBEEF));
        vm.expectRevert();
        addressBook.upgradeToAndCall(address(implementationV2), "");
    }
}
