// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {CredentialSchemaIssuerRegistry} from "../src/CredentialSchemaIssuerRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MockERC1271Wallet} from "./Mock1271Wallet.t.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract MockOprfKeyRegistry {
    function initKeyGen(uint160 oprfKeyId) external {}
}

contract CredentialIssuerRegistryTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    CredentialSchemaIssuerRegistry private registry;
    ERC20Mock private feeToken;
    address private feeRecipient;

    function setUp() public {
        feeRecipient = vm.addr(0x9999);

        // Deploy mock ERC20 token
        feeToken = new ERC20Mock();

        // Deploy implementation
        CredentialSchemaIssuerRegistry implementation = new CredentialSchemaIssuerRegistry();

        // Deploy mock OPRF key registry
        address oprfKeyRegistry = address(new MockOprfKeyRegistry());

        // Deploy proxy with fee recipient, fee token, and zero fee
        bytes memory initData = abi.encodeWithSelector(
            CredentialSchemaIssuerRegistry.initialize.selector, feeRecipient, address(feeToken), 0, oprfKeyRegistry
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        registry = CredentialSchemaIssuerRegistry(address(proxy));
    }

    function _generatePubkey(string memory str) public pure returns (CredentialSchemaIssuerRegistry.Pubkey memory) {
        return CredentialSchemaIssuerRegistry.Pubkey(uint256(keccak256(bytes(str))), uint256(keccak256(bytes(str))));
    }

    function _domainSeparator() internal view returns (bytes32) {
        bytes32 nameHash = keccak256(bytes(registry.EIP712_NAME()));
        bytes32 versionHash = keccak256(bytes(registry.EIP712_VERSION()));
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, address(registry)));
    }

    function _signRemove(uint256 pk, uint256 id) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(registry.REMOVE_ISSUER_SCHEMA_TYPEHASH(), id, registry.nonceOf(id)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdatePubkey(
        uint256 pk,
        uint256 id,
        CredentialSchemaIssuerRegistry.Pubkey memory newPubkey,
        CredentialSchemaIssuerRegistry.Pubkey memory oldPubkey
    ) internal view returns (bytes memory) {
        bytes32 oldPubkeyHash = keccak256(abi.encode(registry.PUBKEY_TYPEHASH(), oldPubkey.x, oldPubkey.y));
        bytes32 newPubkeyHash = keccak256(abi.encode(registry.PUBKEY_TYPEHASH(), newPubkey.x, newPubkey.y));

        bytes32 structHash = keccak256(
            abi.encode(registry.UPDATE_PUBKEY_TYPEHASH(), id, newPubkeyHash, oldPubkeyHash, registry.nonceOf(id))
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signUpdateSigner(uint256 pk, uint256 id, address newSigner) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_SIGNER_TYPEHASH(), id, newSigner, registry.nonceOf(id)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _isEq(CredentialSchemaIssuerRegistry.Pubkey memory a, CredentialSchemaIssuerRegistry.Pubkey memory b)
        public
        pure
        returns (bool)
    {
        return a.x == b.x && a.y == b.y;
    }

    function testRegisterAndGetters() public {
        uint256 signerPk = 0xAAA1;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("pubkey-issuer-1");

        // Calculate expected oprfKeyId: OPRF_KEY_SHIFTER + issuerSchemaId (which is 1)
        uint160 expectedOprfKeyId = uint160(type(uint64).max) + uint160(1);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaRegistered(1, pubkey, signer, expectedOprfKeyId);
        uint256 issuerSchemaId = registry.register(pubkey, signer);
        assertEq(issuerSchemaId, 1);

        assertEq(registry.nextIssuerSchemaId(), 2);
        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), pubkey));
        assertEq(registry.getSignerForIssuerSchemaId(1), signer);
    }

    function testCannotRegisterWithEmptyPubkey() public {
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidPubkey.selector));
        registry.register(CredentialSchemaIssuerRegistry.Pubkey(0, 0), vm.addr(0xAAA1));

        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidPubkey.selector));
        registry.register(CredentialSchemaIssuerRegistry.Pubkey(0, 1), vm.addr(0xAAA1));

        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidPubkey.selector));
        registry.register(CredentialSchemaIssuerRegistry.Pubkey(1, 0), vm.addr(0xAAA1));
    }

    function testUpdatePubkeyFlow() public {
        uint256 signerPk = 0xAAA2;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("old");
        registry.register(pubkey, signer);

        CredentialSchemaIssuerRegistry.Pubkey memory newPubkey = _generatePubkey("new");
        bytes memory sig = _signUpdatePubkey(signerPk, 1, newPubkey, pubkey);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaPubkeyUpdated(1, pubkey, newPubkey);
        registry.updatePubkey(1, newPubkey, sig);

        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), newPubkey));
    }

    function testUpdateSignerFlow() public {
        uint256 oldPk = 0xAAA3;
        address oldSigner = vm.addr(oldPk);
        registry.register(_generatePubkey("k"), oldSigner);

        address newSigner = vm.addr(0xAAA4);
        bytes memory sig = _signUpdateSigner(oldPk, 1, newSigner);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaSignerUpdated(1, oldSigner, newSigner);
        registry.updateSigner(1, newSigner, sig);

        assertEq(registry.getSignerForIssuerSchemaId(1), newSigner);
    }

    function testUpdateSignerToSameSigner() public {
        uint256 signerPk = 0xAAA3;
        address signer = vm.addr(signerPk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory sig = _signUpdateSigner(signerPk, 1, signer);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.SignerAlreadyAssigned.selector));
        registry.updateSigner(1, signer, sig);
        assertEq(registry.getSignerForIssuerSchemaId(1), signer);
    }

    function testRemoveFlow() public {
        uint256 signerPk = 0xAAA5;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("k");
        registry.register(pubkey, signer);

        bytes memory sig = _signRemove(signerPk, 1);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaRemoved(1, pubkey, signer);
        registry.remove(1, sig);

        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), CredentialSchemaIssuerRegistry.Pubkey(0, 0)));
        assertEq(registry.getSignerForIssuerSchemaId(1), address(0));
    }

    function _signUpdateIssuerSchemaUri(uint256 sk, uint256 issuerSchemaId, string memory schemaUri, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 schemaUriHash = keccak256(bytes(schemaUri));
        bytes32 structHash =
            keccak256(abi.encode(registry.UPDATE_ISSUER_SCHEMA_URI_TYPEHASH(), issuerSchemaId, schemaUriHash, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sk, digest);
        return abi.encodePacked(r, s, v);
    }

    function testUpdateIssuerSchemaUriFlow() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb.json", 0);
        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaUpdated(1, "", "https://world.org/schemas/orb.json");
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");
        assertEq(registry.nonceOf(1), 1);

        updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb_new.json", 1);
        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaUpdated(
            1, "https://world.org/schemas/orb.json", "https://world.org/schemas/orb_new.json"
        );
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_new.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb_new.json");
        assertEq(registry.nonceOf(1), 2);
    }

    function testOnlyIssuerCanUpdateSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        uint256 badSk = 0xAAA7;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(badSk, 1, "https://world.org/schemas/malicious.json", 0);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/malicious.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "");
    }

    /**
     * @dev Ensures that a previously valid message cannot be replayed to revert to a previous schema URI.
     */
    function testCannotReplayIssuerSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb_old.json", 0);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_old.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb_old.json");

        bytes memory updateSigNew = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb_new.json", 1);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_new.json", updateSigNew);
        assertEq(registry.nonceOf(1), 2);

        // Replay the old update
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb_old.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb_new.json");
        assertEq(registry.nonceOf(1), 2);
    }

    function testCannotUpdateSchemaUriToSameSchemaUri() public {
        uint256 signerSk = 0xAAA6;
        address signer = vm.addr(signerSk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb.json", 0);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");

        updateSig = _signUpdateIssuerSchemaUri(signerSk, 1, "https://world.org/schemas/orb.json", 1);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.SchemaUriIsTheSameAsCurrentOne.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");
    }

    function testRemoveDeletesSchemaUri() public {
        uint256 signerPk = 0xAAA8;
        address signer = vm.addr(signerPk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerPk, 1, "https://world.org/schemas/orb.json", 0);
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
        assertEq(registry.getIssuerSchemaUri(1), "https://world.org/schemas/orb.json");

        bytes memory removeSig = _signRemove(signerPk, 1);
        registry.remove(1, removeSig);

        assertEq(registry.getIssuerSchemaUri(1), "");
    }

    function testCannotUpdateSchemaUriAfterRemoval() public {
        uint256 signerPk = 0xAAA9;
        address signer = vm.addr(signerPk);
        registry.register(_generatePubkey("k"), signer);

        bytes memory removeSig = _signRemove(signerPk, 1);
        registry.remove(1, removeSig);

        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerPk, 1, "https://world.org/schemas/orb.json", 1);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(1, "https://world.org/schemas/orb.json", updateSig);
    }

    function testCannotUpdateSchemaUriForNonExistentIssuer() public {
        uint256 signerPk = 0xAAAA;
        bytes memory updateSig = _signUpdateIssuerSchemaUri(signerPk, 999, "https://world.org/schemas/orb.json", 0);
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InvalidSignature.selector));
        registry.updateIssuerSchemaUri(999, "https://world.org/schemas/orb.json", updateSig);
    }

    function testRemoveWithERC1271Wallet() public {
        // Create a mock ERC-1271 wallet controlled by a signer
        uint256 signerPk = 0xBBB1;
        address signerAddress = vm.addr(signerPk);
        MockERC1271Wallet wallet = new MockERC1271Wallet(signerAddress);

        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("erc1271-pubkey");
        uint256 issuerSchemaId = registry.register(pubkey, address(wallet));
        assertEq(issuerSchemaId, 1);
        bytes memory sig = _signRemove(signerPk, 1);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaRemoved(1, pubkey, address(wallet));
        registry.remove(1, sig);
        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), CredentialSchemaIssuerRegistry.Pubkey(0, 0)));
        assertEq(registry.getSignerForIssuerSchemaId(1), address(0));
    }

    function testUpdatePubkeyWithERC1271Wallet() public {
        // Create a mock ERC-1271 wallet controlled by a signer
        uint256 signerPk = 0xBBB2;
        address signerAddress = vm.addr(signerPk);
        MockERC1271Wallet wallet = new MockERC1271Wallet(signerAddress);

        CredentialSchemaIssuerRegistry.Pubkey memory oldPubkey = _generatePubkey("old-erc1271");
        uint256 issuerSchemaId = registry.register(oldPubkey, address(wallet));
        assertEq(issuerSchemaId, 1);

        CredentialSchemaIssuerRegistry.Pubkey memory newPubkey = _generatePubkey("new-erc1271");
        bytes memory sig = _signUpdatePubkey(signerPk, 1, newPubkey, oldPubkey);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaPubkeyUpdated(1, oldPubkey, newPubkey);
        registry.updatePubkey(1, newPubkey, sig);
        assertTrue(_isEq(registry.issuerSchemaIdToPubkey(1), newPubkey));
    }

    function testUpdateSignerWithERC1271Wallet() public {
        // Create a mock ERC-1271 wallet controlled by a signer
        uint256 signerPk = 0xBBB3;
        address signerAddress = vm.addr(signerPk);
        MockERC1271Wallet wallet = new MockERC1271Wallet(signerAddress);

        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("signer-erc1271");
        uint256 issuerSchemaId = registry.register(pubkey, address(wallet));
        assertEq(issuerSchemaId, 1);

        address newSigner = vm.addr(0xBBB4);
        bytes memory sig = _signUpdateSigner(signerPk, 1, newSigner);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaSignerUpdated(1, address(wallet), newSigner);
        registry.updateSigner(1, newSigner, sig);
        assertEq(registry.getSignerForIssuerSchemaId(1), newSigner);
    }

    function testUpdateIssuerSchemaUriWithERC1271Wallet() public {
        // Create a mock ERC-1271 wallet controlled by a signer
        uint256 signerPk = 0xBBB5;
        address signerAddress = vm.addr(signerPk);
        MockERC1271Wallet wallet = new MockERC1271Wallet(signerAddress);

        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("uri-erc1271");
        uint256 issuerSchemaId = registry.register(pubkey, address(wallet));
        assertEq(issuerSchemaId, 1);

        string memory schemaUri = "https://world.org/schemas/erc1271.json";
        bytes memory sig = _signUpdateIssuerSchemaUri(signerPk, 1, schemaUri, 0);

        vm.expectEmit();
        emit CredentialSchemaIssuerRegistry.IssuerSchemaUpdated(1, "", schemaUri);
        registry.updateIssuerSchemaUri(1, schemaUri, sig);
        assertEq(registry.getIssuerSchemaUri(1), schemaUri);
        assertEq(registry.nonceOf(1), 1);
    }

    // Fee Management Tests

    function testSetFeeRecipient() public {
        address newRecipient = vm.addr(0xAAAA);

        vm.expectEmit(true, true, false, true);
        emit CredentialSchemaIssuerRegistry.FeeRecipientUpdated(feeRecipient, newRecipient);

        registry.setFeeRecipient(newRecipient);

        assertEq(registry.getFeeRecipient(), newRecipient);
    }

    function testCannotSetFeeRecipientToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.ZeroAddress.selector));
        registry.setFeeRecipient(address(0));
    }

    function testOnlyOwnerCanSetFeeRecipient() public {
        address newRecipient = vm.addr(0xAAAA);
        address nonOwner = vm.addr(0xBBBB);

        vm.prank(nonOwner);
        vm.expectRevert();
        registry.setFeeRecipient(newRecipient);
        assertEq(registry.getFeeRecipient(), feeRecipient);
    }

    function testSetRegistrationFee() public {
        uint256 newFee = 0.01 ether;

        vm.expectEmit(false, false, false, true);
        emit CredentialSchemaIssuerRegistry.RegistrationFeeUpdated(0, newFee);

        registry.setRegistrationFee(newFee);

        assertEq(registry.getRegistrationFee(), newFee);
    }

    function testOnlyOwnerCanSetRegistrationFee() public {
        uint256 newFee = 1 ether;
        address nonOwner = vm.addr(0xCCCC);

        vm.prank(nonOwner);
        vm.expectRevert();
        registry.setRegistrationFee(newFee);
    }

    function testSetFeeToken() public {
        ERC20Mock newToken = new ERC20Mock();

        vm.expectEmit(true, true, false, true);
        emit CredentialSchemaIssuerRegistry.FeeTokenUpdated(address(feeToken), address(newToken));

        registry.setFeeToken(address(newToken));

        assertEq(registry.getFeeToken(), address(newToken));
    }

    function testCannotSetFeeTokenToZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.ZeroAddress.selector));
        registry.setFeeToken(address(0));
    }

    function testOnlyOwnerCanSetFeeToken() public {
        ERC20Mock newToken = new ERC20Mock();
        address nonOwner = vm.addr(0xDDDD);

        vm.prank(nonOwner);
        vm.expectRevert();
        registry.setFeeToken(address(newToken));

        assertEq(registry.getFeeToken(), address(feeToken));
    }

    function testRegisterWithFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint256 signerPk = 0xCCC1;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("fee-test");

        // Mint tokens to signer and approve registry
        feeToken.mint(signer, fee);
        vm.prank(signer);
        feeToken.approve(address(registry), fee);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(signer);
        uint256 issuerSchemaId = registry.register(pubkey, signer);

        assertEq(issuerSchemaId, 1);
        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee);
        assertEq(feeToken.balanceOf(signer), 0);
    }

    function testRegisterWithExcessFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint256 signerPk = 0xCCC2;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("excess-fee-test");

        // Mint more tokens than required and approve registry
        feeToken.mint(signer, fee * 2);
        vm.prank(signer);
        feeToken.approve(address(registry), fee * 2);

        uint256 recipientBalanceBefore = feeToken.balanceOf(feeRecipient);

        vm.prank(signer);
        uint256 issuerSchemaId = registry.register(pubkey, signer);

        assertEq(issuerSchemaId, 1);
        // Only the fee amount should be transferred
        assertEq(feeToken.balanceOf(feeRecipient), recipientBalanceBefore + fee);
        assertEq(feeToken.balanceOf(signer), fee);
    }

    function testCannotRegisterWithInsufficientFee() public {
        uint256 fee = 100e18;
        registry.setRegistrationFee(fee);

        uint256 signerPk = 0xCCC3;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("insufficient-fee-test");

        // Mint insufficient tokens
        feeToken.mint(signer, fee - 1);
        vm.prank(signer);
        feeToken.approve(address(registry), fee - 1);

        vm.expectRevert(abi.encodeWithSelector(CredentialSchemaIssuerRegistry.InsufficientFunds.selector));
        vm.prank(signer);
        registry.register(pubkey, signer);
    }

    function testRegisterWithZeroFee() public {
        // Fee is already 0 from setUp
        assertEq(registry.getRegistrationFee(), 0);

        uint256 signerPk = 0xCCC4;
        address signer = vm.addr(signerPk);
        CredentialSchemaIssuerRegistry.Pubkey memory pubkey = _generatePubkey("zero-fee-test");

        // No need to mint or approve tokens when fee is 0
        vm.prank(signer);
        uint256 issuerSchemaId = registry.register(pubkey, signer);

        assertEq(issuerSchemaId, 1);
        assertEq(feeToken.balanceOf(feeRecipient), 0);
    }
}
