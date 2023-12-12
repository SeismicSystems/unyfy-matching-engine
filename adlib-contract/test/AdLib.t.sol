// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {AdLib} from "../src/AdLib.sol";



contract AdLibTest is Test {
    AdLib public adLib;

     event orderPlaced(address indexed pubaddr, uint256 indexed orderhash);

    event orderCancelled(address indexed pubaddr, uint256 indexed orderhash);

    event orderDelete(uint256 indexed orderhash);

    event orderFilled(address indexed pubaddr, uint256 indexed orderhash, uint256[] indexed filledorderhashes);


    function setUp() public {
        adLib = new AdLib();
    }

    function testPlacedEvent() public {
        vm.expectEmit(true, false, false, false);
        emit orderPlaced(address(this), 0xa1);
        adLib.place(0xa1);
    }

    function testCancelledEvent() public {
        vm.expectEmit(true, true, false, false);
        emit orderCancelled(address(this), 0xa1);
        adLib.cancel(0xa1);
    }

    function testDeleteEvent() public {
        vm.expectEmit(true, false, false, false);
        emit orderDelete(0xa1);
        adLib.deleteOrderFromTree(0xa1);
    }

    function testFilledEvent() public {
        uint256[] memory filledorderhashes = new uint256[](2);
        filledorderhashes[0] = 0xa2;
        filledorderhashes[1] = 0xa3;
        vm.expectEmit(true, true, true, false);
        emit orderFilled(address(this), 0xa1, filledorderhashes);
        adLib.fill(0xa1, filledorderhashes);
    }

}