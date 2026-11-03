// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IChainlinkAggregator} from "./interfaces/IChainlinkAggregator.sol";

/// @title OwnerPriceSource
/// @author World Contributors
/// @notice WLD/USD rate set by the owner, scaled by 1e18, for the Billing Contract until the Data Streams adapter
///  of WIP-107 §4.9 is deployed.
/// @dev Not upgradeable: it holds only the latest rate, so it is replaced through `WorldIDBilling.setPriceSource`.
///  `updatedAt` is the time the owner set the rate, so the Billing Contract's `maxPriceAge` is the maximum time
///  between updates; purchases fail closed with `StalePrice` once it passes.
/// @custom:security-contact security@toolsforhumanity.com
contract OwnerPriceSource is Ownable2Step, IChainlinkAggregator {
    ////////////////////////////////////////////////////////////
    //                        ERRORS                          //
    ////////////////////////////////////////////////////////////

    /// @notice No rate was ever set.
    error PriceNotSet();

    /// @notice The rate is zero or does not fit in `int256`.
    error InvalidPrice();

    ////////////////////////////////////////////////////////////
    //                        EVENTS                          //
    ////////////////////////////////////////////////////////////

    event PriceUpdated(uint80 indexed roundId, uint256 usdPerWld, uint256 updatedAt);

    ////////////////////////////////////////////////////////////
    //                       CONSTANTS                        //
    ////////////////////////////////////////////////////////////

    /// @notice Decimals of `answer`; the Billing Contract requires 18.
    uint8 public constant decimals = 18;

    ////////////////////////////////////////////////////////////
    //                        MEMBERS                         //
    ////////////////////////////////////////////////////////////

    /// @dev Latest rate, USD per WLD scaled by 1e18; zero until the first `setPrice`.
    int256 internal _answer;

    /// @dev Time of the latest `setPrice`.
    uint64 internal _updatedAt;

    /// @dev Number of `setPrice` calls.
    uint80 internal _roundId;

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @inheritdoc IChainlinkAggregator
    /// @dev Reverts until a rate is set, which the Billing Contract reports as `PriceUnavailable`.
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        if (_roundId == 0) revert PriceNotSet();
        return (_roundId, _answer, _updatedAt, _updatedAt, _roundId);
    }

    /// @notice Sets the USD per WLD rate, scaled by 1e18, observed now.
    function setPrice(uint256 usdPerWld) external onlyOwner {
        if (usdPerWld == 0 || usdPerWld > uint256(type(int256).max)) revert InvalidPrice();
        uint80 roundId = _roundId + 1;
        _answer = int256(usdPerWld);
        _updatedAt = uint64(block.timestamp);
        _roundId = roundId;
        emit PriceUpdated(roundId, usdPerWld, block.timestamp);
    }
}
