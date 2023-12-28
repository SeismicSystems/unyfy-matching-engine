// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {UnyfyDev} from "../src/UnyfyDev.sol";



contract UnyfyDevTest is Test {
    UnyfyDev public unyfyDev;

     event orderPlaced(address indexed pubaddr, uint256 indexed orderhash);

    event orderCancelled(address indexed pubaddr, uint256 indexed orderhash);

    event orderDelete(uint256 indexed orderhash);

    event orderFilled(address indexed pubaddr, uint256 indexed orderhash, uint256[] indexed filledorderhashes);


    function setUp() public {
        unyfyDev = new UnyfyDev();
    }


}