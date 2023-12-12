// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/Test.sol";

import { Rev3al_Locker } from "../src/Locker.sol";
import { MockToken } from "./Mocks/Token.sol";

import "forge-std/Vm.sol";

contract LockerTest is Test {

    address public owner = address(11111);
    address public user = address(22222);


    Rev3al_Locker public locker;
    MockToken public token;

    function setUp() public {
        locker = new Rev3al_Locker(0.01 ether, owner);
        token = new MockToken(owner, "Test Token", "TEST");

        vm.deal(user, 100 ether);
        token.mint(user, 100 ether);
    }

    function testTokenDeployed() public {
        assertTrue(address(token) != address(0));
        assertTrue(token.owner() == owner);

        uint256 _balance = token.balanceOf(user);
        assertTrue(_balance == 100 ether);
    }
    
    function testLockerDeployed() public {
        assertTrue(address(locker) != address(0));
        assertTrue(locker.getOwner() == owner);
        assertTrue(locker.fee() == 0.01 ether);
    }
}
