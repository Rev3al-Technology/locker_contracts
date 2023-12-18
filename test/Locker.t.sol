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
        token.mint(user, 200 ether);
    }

    function testTokenDeployed() public {
        assertTrue(address(token) != address(0));
        assertTrue(token.owner() == owner);

        uint256 _balance = token.balanceOf(user);
        assertTrue(_balance == 200 ether);
    }
    
    function testLockerDeployed() public {
        assertTrue(address(locker) != address(0));
        assertTrue(locker.getOwner() == owner);
        assertTrue(locker.fee() == 0.01 ether);
    }

    function testLock() public {
        vm.startPrank(user);

        token.approve(address(locker), 0.01 ether);
        uint256 lockerBalanceBefore = address(locker).balance;
        locker.lock{value: 0.01 ether}(address(token), 0.01 ether, 45);
        uint256 lockerBalanceAfter = address(locker).balance;

        vm.stopPrank();

        assertTrue(lockerBalanceAfter - lockerBalanceBefore == 0.01 ether);
    }

    function test_fuzz_Lock_Period(uint64 daysToLock) public {
        vm.assume(daysToLock <= 1825 && daysToLock >= 1);
        vm.startPrank(user);

        token.approve(address(locker), 0.01 ether);
        uint256 lockerBalanceBefore = address(locker).balance;
        locker.lock{value: 0.01 ether}(address(token), 0.01 ether, daysToLock);
        uint256 lockerBalanceAfter = address(locker).balance;

        vm.stopPrank();

        assertTrue(lockerBalanceAfter - lockerBalanceBefore == 0.01 ether);
    }

    function test_fuzz_Lock_Amount(uint128 amount) public {
        vm.assume(amount >= 1);
        vm.startPrank(user);

        token.mint(user, amount);

        token.approve(address(locker), amount);

        uint256 lockerBalanceBefore = token.balanceOf(address(locker));
        locker.lock{value: 0.01 ether}(address(token), amount, 45);
        uint256 lockerBalanceAfter = token.balanceOf(address(locker));

        vm.stopPrank();

        assertTrue(lockerBalanceAfter - lockerBalanceBefore == amount);
    }

    function testFail_fuzz_Lock_TokenAddress(address tokenAddress) public {
        vm.startPrank(user);

        MockToken _token = MockToken(tokenAddress);

        _token.mint(user, 1 ether);

        _token.approve(address(locker), 1 ether);

        uint256 lockerBalanceBefore = _token.balanceOf(address(locker));
        locker.lock{value: 0.01 ether}(address(_token), 1 ether, 45);
        console2.log("Failing for token: ", address(_token));
        uint256 lockerBalanceAfter = _token.balanceOf(address(locker));

        vm.stopPrank();

        assertTrue(lockerBalanceAfter - lockerBalanceBefore == 1 ether);
    }

    function testFail_UnlockEarly() public {
        testLock();

        vm.startPrank(user);
        vm.warp(block.timestamp + 10 days);

        vm.expectRevert();
        locker.unlock(0);

        vm.stopPrank();

    }

    function testUnlockNormal() public {
        testLock();

        vm.startPrank(user);
        vm.warp(block.timestamp + 100);

        uint256 lockerBalanceBefore = token.balanceOf(address(locker));
        console2.log("Locker balance before:    ", lockerBalanceBefore);
        locker.unlock(0);
        uint256 lockerBalanceAfter = token.balanceOf(address(locker));
        console2.log("Locker balance after:     ", lockerBalanceAfter);

        vm.stopPrank();

        assertTrue(lockerBalanceAfter == lockerBalanceBefore - 0.01 ether);
    }
}
