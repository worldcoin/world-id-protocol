// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IChainlinkAggregator} from "./interfaces/IChainlinkAggregator.sol";

/// @title FixedPriceSource
/// @author World Contributors
/// @notice FOR TESTING ONLY. Fixed WLD/USD rate set by the owner, scaled by 1e18, for the Billing Contract until the
///  Data Streams adapter of WIP-107 §4.9 is deployed.
/// @dev Every read reports the current block time as `updatedAt`, so the rate never trips the Billing Contract's
///  `maxPriceAge` and stays in force until the owner changes it. It therefore says nothing about the rate's age.
///  Not upgradeable: it holds only the rate, so it is replaced through `WorldIDBilling.setPriceSource`.
/// @custom:security-contact security@toolsforhumanity.com
contract FixedPriceSource is Ownable2Step, IChainlinkAggregator {
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

    event PriceUpdated(uint256 oldUsdPerWld, uint256 newUsdPerWld);

    ////////////////////////////////////////////////////////////
    //                       CONSTANTS                        //
    ////////////////////////////////////////////////////////////

    /// @notice Decimals of `answer`; the Billing Contract requires 18.
    uint8 public constant decimals = 18;

    ////////////////////////////////////////////////////////////
    //                        MEMBERS                         //
    ////////////////////////////////////////////////////////////

    /// @dev USD per WLD scaled by 1e18; zero until the first `setPrice`.
    int256 internal _answer;

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @inheritdoc IChainlinkAggregator
    /// @dev Reverts until a rate is set, which the Billing Contract reports as `PriceUnavailable`.
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        if (_answer == 0) revert PriceNotSet();
        return (1, _answer, block.timestamp, block.timestamp, 1);
    }

    /// @notice Sets the fixed USD per WLD rate, scaled by 1e18.
    function setPrice(uint256 usdPerWld) external onlyOwner {
        if (usdPerWld == 0 || usdPerWld > uint256(type(int256).max)) revert InvalidPrice();
        emit PriceUpdated(uint256(_answer), usdPerWld);
        _answer = int256(usdPerWld);
    }
}
