// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title WorldIDBase - Upgradeable Implementation Contract with EIP712 support and FeeManager logic
/// @author World Contributors
abstract contract WorldIDBase is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable, EIP712Upgradeable {
    using SafeERC20 for IERC20;

    ////////////////////////////////////////////////////////////
    //                         ERRORS                         //
    ////////////////////////////////////////////////////////////

    /// @notice Thrown when a function is called on an uninitialized implementation.
    error ImplementationNotInitialized();

    /**
     * @dev Thrown when attempting to set an address parameter to the zero address.
     */
    error ZeroAddress();

    ////////////////////////////////////////////////////////////
    //                         EVENTS                         //
    ////////////////////////////////////////////////////////////

    /**
     * @dev Emitted when the fee recipient address is updated.
     * @param oldRecipient The previous fee recipient address.
     * @param newRecipient The new fee recipient address.
     */
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    /**
     * @dev Emitted when the registration fee amount is updated.
     * @param oldFee The previous registration fee.
     * @param newFee The new registration fee.
     */
    event RegistrationFeeUpdated(uint256 oldFee, uint256 newFee);

    /**
     * @dev Emitted when the fee token address is updated.
     * @param oldToken The previous fee token address.
     * @param newToken The new fee token address.
     */
    event FeeTokenUpdated(address indexed oldToken, address indexed newToken);

    ////////////////////////////////////////////////////////////
    //                        STORAGE                         //
    ////////////////////////////////////////////////////////////

    /// @dev Address receiving collected fees.
    address internal _feeRecipient;

    /// @dev ERC20 token used for fee collection.
    IERC20 internal _feeToken;

    /// @dev Registration fee amount (0 disables fees).
    uint256 internal _registrationFee;

    ////////////////////////////////////////////////////////////
    //                        MODIFIERS                       //
    ////////////////////////////////////////////////////////////

    /// @notice Ensures the implementation has been initialized (via proxy initialization).
    /// @dev Reverts if `_getInitializedVersion() == 0`.
    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    /// @dev Reverts if `_getInitializedVersion() == 0`.
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

    /// @notice Initializes base upgradeable state (ownership + EIP-712 domain + fee config).
    /// @dev Must be called from the inheriting contract's initializer.
    /// @param name The EIP-712 signing domain name.
    /// @param version The EIP-712 signing domain version.
    /// @param feeRecipient The initial fee recipient.
    /// @param feeToken The initial ERC20 token used for fees.
    /// @param registrationFee The initial fee amount.
    function __BaseUpgradeable_init(
        string memory name,
        string memory version,
        address feeRecipient,
        address feeToken,
        uint256 registrationFee
    ) internal onlyInitializing {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        __EIP712_init(name, version);
        __UUPSUpgradeable_init();

        if (feeRecipient == address(0)) revert ZeroAddress();
        if (feeToken == address(0)) revert ZeroAddress();
        _feeRecipient = feeRecipient;
        _feeToken = IERC20(feeToken);
        _registrationFee = registrationFee;
    }

    /**
     * @dev Collects the registration fee from the caller and forwards it to `_feeRecipient`.
     */
    function _collectFee() internal virtual onlyInitialized {
        if (_registrationFee > 0) {
            _feeToken.safeTransferFrom(msg.sender, _feeRecipient, _registrationFee);
        }
    }

    /// @notice Updates the fee recipient address.
    /// @dev Restricted to the proxy owner; callable only through the proxy; requires initialization.
    /// @param newFeeRecipient The new fee recipient address.
    function setFeeRecipient(address newFeeRecipient) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newFeeRecipient == address(0)) revert ZeroAddress();
        address oldRecipient = _feeRecipient;
        _feeRecipient = newFeeRecipient;
        emit FeeRecipientUpdated(oldRecipient, newFeeRecipient);
    }

    /// @notice Updates the registration fee amount.
    /// @dev Restricted to the proxy owner; callable only through the proxy; requires initialization.
    /// @param newFee The new registration fee amount (0 disables fees).
    function setRegistrationFee(uint256 newFee) external virtual onlyOwner onlyProxy onlyInitialized {
        uint256 oldFee = _registrationFee;
        _registrationFee = newFee;
        emit RegistrationFeeUpdated(oldFee, newFee);
    }

    /// @notice Updates the fee token address.
    /// @dev Restricted to the proxy owner; callable only through the proxy; requires initialization.
    /// @param newFeeToken The new ERC20 token address used for fees.
    function setFeeToken(address newFeeToken) external virtual onlyOwner onlyProxy onlyInitialized {
        if (newFeeToken == address(0)) revert ZeroAddress();
        address oldToken = address(_feeToken);
        _feeToken = IERC20(newFeeToken);
        emit FeeTokenUpdated(oldToken, newFeeToken);
    }

    /**
     * @notice Returns the current registration fee.
     * @dev Callable only through the proxy; requires initialization.
     */
    function getRegistrationFee() external view virtual onlyProxy onlyInitialized returns (uint256) {
        return _registrationFee;
    }

    /**
     * @notice Returns the current fee recipient address.
     */
    function getFeeRecipient() external view virtual onlyProxy onlyInitialized returns (address) {
        return _feeRecipient;
    }

    /**
     * @dev Returns the current token with which fees are paid.
     */
    function getFeeToken() external view virtual onlyProxy onlyInitialized returns (address) {
        return address(_feeToken);
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
