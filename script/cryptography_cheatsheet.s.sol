// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {cryptography_cheatsheet} from "../src/cryptography_cheatsheet.sol";

contract cryptography_cheatsheetScript is Script {
    cryptography_cheatsheet public c;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        c = new cryptography_cheatsheet();

        vm.stopBroadcast();
    }
}
