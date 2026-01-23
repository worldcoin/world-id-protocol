// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/// @title Base Upgradeable Implementation Contract
/// @author World Contributors
abstract contract BaseUpgradeable is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    ////////////////////////////////////////////////////////////
    //                         ERRORS                         //
    ////////////////////////////////////////////////////////////

    /// @notice Thrown when a function is called on an uninitialized implementation.
    error ImplementationNotInitialized();

    ////////////////////////////////////////////////////////////
    //                        MODIFIERS                       //
    ////////////////////////////////////////////////////////////

    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    function _onlyInitialized() internal view {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
    }

    ////////////////////////////////////////////////////////////
    //                       CONSTRUCTOR                      //
    ////////////////////////////////////////////////////////////

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function __BaseUpgradeable_init() internal onlyInitializing {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
    }

    ////////////////////////////////////////////////////////////
    //                   UPGRADE AUTHORIZATION                //
    ////////////////////////////////////////////////////////////

    /// @notice Is called when upgrading the contract to check whether it should be performed.
    /// @param newImplementation The address of the implementation being upgraded to.
    /// @custom:reverts string If called by any account other than the proxy owner.
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyProxy onlyOwner {}

    ////////////////////////////////////////////////////////////
    //                       STORAGE GAP                      //
    ////////////////////////////////////////////////////////////

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}

/// @title Base Upgradeable Implementation Contract with EIP712 support
/// @author World Contributors
abstract contract BaseUpgradeable712 is BaseUpgradeable, EIP712Upgradeable {
    function __BaseUpgradeable712_init(string memory name, string memory version) internal onlyInitializing {
        __BaseUpgradeable_init();
        __EIP712_init(name, version);
    }
}
