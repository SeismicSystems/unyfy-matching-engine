// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {AdLib} from "../src/AdLib.sol";
contract AdLibScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();        
        new AdLib();
        vm.stopBroadcast();
    }
}
