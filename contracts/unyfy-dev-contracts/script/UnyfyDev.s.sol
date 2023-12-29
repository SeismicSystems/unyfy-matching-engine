// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {UnyfyDev} from "../src/UnyfyDev.sol";
contract UnyfyDevScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();        
        new UnyfyDev();
        vm.stopBroadcast();
    }
}
