// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "../src/EssentialCryptography.sol";

contract cryptographyTest is Test {
    EssentialCryptography public c;

    function setUp() public {
        c = new EssentialCryptography(bytes32(0x00));
    }

    function testFail_is_hash_case_sensitive() public {
        assertEq(c.real_name(), c.small_mistake_in_name());
    }

}
