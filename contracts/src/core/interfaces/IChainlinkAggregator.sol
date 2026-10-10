// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title IChainlinkAggregator
 * @author World Contributors
 * @notice Chainlink `AggregatorV3Interface` subset read by the Billing Contract for WLD/USD (WIP-107 §4.8).
 */
interface IChainlinkAggregator {
    function decimals() external view returns (uint8);

    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
