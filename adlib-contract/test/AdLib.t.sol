// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {AdLib} from "../src/AdLib.sol";


contract AdLibTest is Test {
    AdLib public adLib;

    function setUp() public {
        adLib = new AdLib();
        adLib.place(1);
        // assertEq(adLib.orderhash(), 1);
    }

   /* function test_Increment() public {
        counter.increment();
        assertEq(counter.number(), 1);
    } */

    function testFuzz_PlaceOrder(uint256 x) public {
        adLib.place(x);
        assertEq(adLib.orderhash(), x);
    }
}
