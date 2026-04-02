// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

// --- Interfaces & constants ---

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

// --- Contracts ---

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
        bytes calldata data
    ) external pure override returns (bytes4) {
        if (data.length == 3) {
            return WIP101_MAGIC_VALUE;
        }
        revert IWIP101.RpInvalidRequest(1);
    }
}

// --- Script ---

contract DeployWIP101 is Script {
    function run() external {

        vm.startBroadcast();

        WIP101Correct correct = new WIP101Correct();
        WIP101CorrectWhenAuxData conditional = new WIP101CorrectWhenAuxData();

        vm.stopBroadcast();

        console.log("WIP101Correct deployed at:", address(correct));
        console.log("WIP101CorrectWhenAuxData deployed at:", address(conditional));
    }
}