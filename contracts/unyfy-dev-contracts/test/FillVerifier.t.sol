// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {FillVerifier} from "../src/FillVerifier.sol";

contract TestContract is Test {
    FillVerifier c;

    function setUp() public {
        c = new FillVerifier();
    }

    function testBar() public {
        assertEq(uint256(1), uint256(1), "ok");
    }

    function testFoo(uint256 x) public {
        vm.assume(x < type(uint128).max);
        assertEq(x + x, x * 2);
    }
}
