// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";
import {Poseidon2T2} from "../src/hash/Poseidon2.sol";
import {Poseidon2T2Reference} from "../src/hash/Poseidon2Reference.sol";
import {Skyscraper} from "../src/hash/Skyscraper.sol";

contract LeanIMTTest is Test {
    uint256 constant HASH_COUNT = 1000;

    function setUp() public {}

    function test_Skyscraper() public {
        uint256 startGas = gasleft();
        uint256 l = 1337;
        uint256 r = 42;
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            l = Skyscraper.compress(l, r);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_PoseidonT3() public {
        uint256 startGas = gasleft();
        uint256 l = 1337;
        uint256 r = 42;
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            l = PoseidonT3.hash([l, r]);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_PoseidonT4() public {
        uint256 startGas = gasleft();
        uint256 l = 1337;
        uint256 r = 42;
        uint256 s = 1234;
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            l = PoseidonT4.hash([l, r, s]);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_Poseidon2T2() public {
        uint256 l = 1337;
        uint256 r = 42;
        uint256 startGas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            l = Poseidon2T2.compress([l, r]);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_Poseidon2T2Reference() public {
        uint256 l = 1337;
        uint256 r = 42;
        uint256 startGas = gasleft();
        for (uint256 i = 0; i < HASH_COUNT; i++) {
            l = Poseidon2T2Reference.compress([l, r]);
        }
        uint256 endGas = gasleft();
        console.log("Gas used: %s", (startGas - endGas) / HASH_COUNT);
    }

    function test_Poseidon2T2EqualsReference() public {
        for (uint256 i = 0; i < 100; i++) {
            uint256[2] memory inputs = [uint256(0xDEADBEEF) + i, uint256(0x12345678) + i];
            uint256 result = Poseidon2T2.compress(inputs);
            uint256 resultReference = Poseidon2T2Reference.compress(inputs);
            assertEq(result, resultReference);
        }
    }
}
