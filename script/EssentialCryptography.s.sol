// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "src/EssentialCryptography.sol";

contract cryptographyScript is Script {
    EssentialCryptography public c;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // c = new EssentialCryptography();

        vm.stopBroadcast();
    }
}
