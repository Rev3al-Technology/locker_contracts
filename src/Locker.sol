// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/*
*  .+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+. 
* (                                                                                                                         )
*  )                                                                                                                       ( 
* (                                                                                                                         )
*  )       ____    _____  __     __  _____      _      _               _        ___     ____   _  __  _____   ____         ( 
* (       |  _ \  | ____| \ \   / / |___ /     / \    | |             | |      / _ \   / ___| | |/ / | ____| |  _ \         )
*  )      | |_) | |  _|    \ \ / /    |_ \    / _ \   | |      _____  | |     | | | | | |     | ' /  |  _|   | |_) |       ( 
* (       |  _ <  | |___    \ V /    ___) |  / ___ \  | |___  |_____| | |___  | |_| | | |___  | . \  | |___  |  _ <         )
*  )      |_| \_\ |_____|    \_/    |____/  /_/   \_\ |_____|         |_____|  \___/   \____| |_|\_\ |_____| |_| \_\       ( 
* (                                                                                                                         )
*  )                                                                                                                       ( 
* (                                                                                                                         )
*  )                                                                                                                       ( 
* (                                                                                                                         )
*  "+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+"+.+" 
*
* @note Liquidity Locker / ERC20 Token Locker Created for Rev3al
* @author Paul Socarde
*/                                     

contract Rev3al_Locker is ReentrancyGuard {
    /**
     * 'paused' and 'owner' can be packed in a single slot
     * (uint64 + address = 64 + 160 = 224 bits = 28 bytes) out of 32.
     */
    uint64 private paused; // Slot v | 1 = paused AND 2 = unpaused
    address private owner; // Slot v

    address private pendingOwner; // Slot w;

    /** Lock Fee
     * lockFee (uint128) can be packed with lockId (uint128) in a single slot (uint256)
     */
    uint128 private lockFee; // Slot x | Max value: uint128(-1) = 340282366920938463463374607431768211455 = 340,282,366,920,938,463,463 eth
    uint128 private lockId; // Slot x  | Max value: uint128(-1) = 340282366920938463463374607431768211455 = 340,282,366,920,938,463,463 eth

    struct LockInfo {
        /**
         * 'lockTime' and 'token' can be packed in a single slot
         * (uint64 + address = 64 + 160 = 224 bits = 28 bytes) out of 32.
         */
        address token; // Slot y
        uint64 lockTime; // Slot y

        /**
         * 'amount' and 'locked' can be packed in a single slot
         * (uint128 + uint128 = 128 + 128 = 256 bits = 32 bytes) out of 32.
         */
        uint128 amount; // Slot z | Max value: uint128(-1) = 340282366920938463463374607431768211455 = 340,282,366,920,938,463,463 eth
        uint128 locked; // Slot z | 1 - Locked AND 0 - Unlocked | Max value: uint128(-1) = 340282366920938463463374607431768211455 = 340,282,366,920,938,463,463 eth

        address owner; // 160 bits = 20 bytes
    }

    /**
     * Id => LockInfo
     * We don't use an array here to avoid length checks.
     */
    mapping(uint128 => LockInfo) public locks;

    /** User => local id */
    mapping(address => uint128) public userId;

    /** Token => local id */
    mapping(address => uint128) public tokenId;

    /** User => local id => token lock */
    mapping(address => mapping(uint128 => uint128)) public userLock;

    /** Token => local id => token lock */
    mapping(address => mapping(uint128 => uint128)) public tokenLock;

    /** Token => total locked for token */
    mapping(address => uint128) public totalLocked;

    /** EMERGENCY WITHDRAWAL 
     * Users requiring early token withdrawal can notify the contract.
     * Proof of their community announcement regarding the intent to withdraw off-chain is mandatory.
     * Upon contract notification, we will initiate the transfer of locked tokens to their address.
     */
    mapping(uint128 => uint8) public pinged;

    /** Events */
    event Pinged(uint128 indexed lockId);
    event SetPendingAdmin(address indexed admin);
    event LockFeeChanged(uint128 indexed newLockFee);
    event Unlock(uint128 indexed lockId, address indexed token, uint128 amount);
    event NewLock(address indexed owner, uint128 indexed lockId, address indexed token, uint128 amount, uint64 lockTime);

    /** Errors */
    error NotOwner();
    error FeeNotPaid();
    error CantUnlock();
    error OutOfRange();
    error InvalidAmount();
    error InvalidAddress();
    error ContractPaused();
    error NotPendingOwner();
    error InvalidLockTime();

    /** Modifiers */
    modifier onlyOwner() {
        if(msg.sender != owner) revert NotOwner();
        _;
    }

    modifier isPaused() {
        if(paused == 1) revert ContractPaused();
        _;
    }

    /** Constructor 
     * @dev We make the constructor payable to reduce the gas fees;
     */
    constructor(uint128 _lockFee, address _owner) payable {
        isValidAddress(_owner);

        owner = _owner;

        lockFee = _lockFee;
        paused = 2; // Unpaused
    }

    /** Receive function */
    receive() external payable {}

    /** Owner Functions */
    function transferOwnership(address _pendingOwner) external payable onlyOwner {
        isValidAddress(_pendingOwner);
        pendingOwner = _pendingOwner;

        emit SetPendingAdmin(_pendingOwner);
    }

    function acceptOwnership() external payable {
        if(msg.sender != pendingOwner) {
            revert NotPendingOwner();
        }

        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function changeLockFee(uint128 _lockFee) external payable onlyOwner {
        lockFee = _lockFee;

        emit LockFeeChanged(_lockFee);
    }

    function pause() external payable onlyOwner {
        paused = 1; // Paused
    }

    function unpause() external payable onlyOwner {
        paused = 2; // Unpaused
    }

    function withdrawERC20(address token) external payable onlyOwner {
        // Check token balance
        uint256 _balance = IERC20(token).balanceOf(address(this));

        // If token balanace > total locked, we can withdraw
        uint256 _delta = _balance - uint256(totalLocked[token]);

        if(_delta == 0) {
            revert InvalidAmount();
        }

        // The owner can withdraw only the extra amount of any ERC20 token OR 
        // any ERC20 token that was sent by mistake to the smart contract
        safeTransfer(token, msg.sender, _delta);
    }

    function withdrawFromPinged(uint128 _lockId, address _receiver) external payable onlyOwner {
        if(_lockId >= lockId) {
            revert OutOfRange();
        }

        if(pinged[_lockId] == 0) {
            revert CantUnlock();
        }

        pinged[_lockId] = 0;

        LockInfo storage _lock = locks[_lockId];

        if(_lock.locked != 1) {
            revert CantUnlock();
        }

        if(_lock.amount == 0) {
            revert CantUnlock();
        }

        uint128 _amount = _lock.amount;

        _lock.amount = 0;
        _lock.locked = 0;

        safeTransfer(_lock.token, _receiver, _amount);

        unchecked {
            totalLocked[_lock.token] -= _amount;
        }

        emit Unlock(lockId, _lock.token, _amount);
    }

    function withdrawFees() external onlyOwner {
        safeTransferAllETH(owner);
    }

    /** User functions */
    function lock(address token, uint128 amount, uint64 daysToLock) external payable isPaused nonReentrant {
        if(msg.value != lockFee) {
            revert("FeeNotPaid");
        }

        isValidAddress(address(token));

        if(daysToLock < 1) {
            revert InvalidLockTime();
        }

        if(daysToLock > 1825) { // 1825 days = 5 years | To avoid overflows
            revert InvalidLockTime();
        }

        if(amount == 0) {
            revert InvalidAmount();
        }

        // Check balance before
        uint256 _balanceBefore = IERC20(token).balanceOf(address(this));

        safeTransferFrom(token, msg.sender, address(this), amount);

        // Check balance after
        uint256 _balanceAfter = IERC20(token).balanceOf(address(this));

        // Compute the delta to support tokens wiht transfer fees
        uint256 _delta = _balanceAfter - _balanceBefore;

        // Check if delta <= type(uint64).max | To avoid overflows
        if(_delta > type(uint128).max) {
            revert InvalidAmount();
        }

        // Check if delta > 0 | To avoid zero value locks
        if(_delta == 0) {
            revert InvalidAmount();
        }

        // Check if we can compute total tokens locked safely
        if(uint256(totalLocked[address(token)]) + _delta > type(uint128).max) {
            revert InvalidAmount();
        }

        LockInfo memory newLock = LockInfo({
            token: address(token),
            lockTime: uint64(block.timestamp + (daysToLock * 1 days)),
            amount: uint128(_delta),
            locked: 1,
            owner: msg.sender
        });

        locks[lockId] = newLock;
        userLock[msg.sender][userId[msg.sender]] = lockId;
        tokenLock[address(token)][tokenId[address(token)]] = lockId;

        unchecked {
            ++lockId;
            ++userId[msg.sender];
            ++tokenId[address(token)];

            totalLocked[address(token)] += uint128(_delta);
        }

        emit NewLock(msg.sender, lockId - 1, address(token), uint128(_delta), uint64(block.timestamp + (daysToLock * 1 days)));
    }

    function unlock(uint128 _lockId) external payable isPaused nonReentrant {
        if(_lockId >= lockId) {
            revert OutOfRange();
        }

        LockInfo storage _lock = locks[_lockId];

        if(_lock.locked != 1) {
            revert CantUnlock();
        }

        if(_lock.owner != msg.sender) {
            revert CantUnlock();
        }

        if(_lock.lockTime < uint64(block.timestamp)) {
            revert CantUnlock();
        }

        if(_lock.amount == 0) {
            revert CantUnlock();
        }

        uint128 _amount = _lock.amount;

        _lock.amount = 0;
        _lock.locked = 0;

        safeTransfer(_lock.token, msg.sender, _amount);

        unchecked {
            totalLocked[_lock.token] -= _amount;
        }

        emit Unlock(lockId, _lock.token, _amount);
    }

    function pingContract(uint128 _lockId) external payable {
        if(_lockId >= lockId) {
            revert OutOfRange();
        }

        // We read from storag instead of memory because it's cheaper
        // Read from storage => direct read
        // Read from memory => read from storage + copy to memory
        LockInfo storage _lock = locks[_lockId];

        if(_lock.owner != msg.sender) {
            revert NotOwner();
        }

        pinged[_lockId] = 1;

        emit Pinged(_lockId);
    }

    /** Public view functions */
    function getMyLocks(address _owner) public view returns(uint256[] memory lockIds) {
        uint256 _length = userId[_owner];

        lockIds = new uint256[](_length);

        for(uint128 i = 0; i < _length; i++) {
            lockIds[i] = userLock[_owner][i];
        }
    }

    function getTokenLocks(address _token) public view returns(uint256[] memory lockIds) {
        uint256 _length = tokenId[_token];

        lockIds = new uint256[](_length);

        for(uint128 i = 0; i < _length; i++) {
            lockIds[i] = tokenLock[_token][i];
        }
    }

    function lockInfo(uint128 _lockId) public view returns(LockInfo memory) {
        return locks[_lockId];
    }

    function getOwner() public view returns(address) {
        return owner;
    }

    function getPendingOwner() public view returns(address) {
        return pendingOwner;
    }

    function fee() public view returns(uint128) {
        return lockFee;
    }

    function getLockId() public view returns(uint128) {
        return lockId;
    }

    /** Internal functions */

    /**
     * IMPORTED FROM: https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol
     * NO ADDITIONAL EDITS HAVE BEEN MADE
     */
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x60, amount) // Store the `amount` argument.
            mstore(0x40, to) // Store the `to` argument.
            mstore(0x2c, shl(96, from)) // Store the `from` argument.
            mstore(0x0c, 0x23b872dd000000000000000000000000) // `transferFrom(address,address,uint256)`.
            // Perform the transfer, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x1c, 0x64, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x7939f424) // `TransferFromFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) // Restore the zero slot to zero.
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /**
     * IMPORTED FROM: https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol
     * NO ADDITIONAL EDITS HAVE BEEN MADE
     */
    function safeTransfer(address token, address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x14, to) // Store the `to` argument.
            mstore(0x34, amount) // Store the `amount` argument.
            mstore(0x00, 0xa9059cbb000000000000000000000000) // `transfer(address,uint256)`.
            // Perform the transfer, reverting upon failure.
            if iszero(
                and( // The arguments of `and` are evaluated from right to left.
                    or(eq(mload(0x00), 1), iszero(returndatasize())), // Returned 1 or nothing.
                    call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
                )
            ) {
                mstore(0x00, 0x90b8ec18) // `TransferFailed()`.
                revert(0x1c, 0x04)
            }
            mstore(0x34, 0) // Restore the part of the free memory pointer that was overwritten.
        }
    }

    /**
     * IMPORTED FROM: https://github.com/Vectorized/solady/blob/main/src/utils/SafeTransferLib.sol
     * NO ADDITIONAL EDITS HAVE BEEN MADE
     */
    /// @dev Sends all the ETH in the current contract to `to`.
    function safeTransferAllETH(address to) internal {
        /// @solidity memory-safe-assembly
        assembly {
            // Transfer all the ETH and check if it succeeded or not.
            if iszero(call(gas(), to, selfbalance(), codesize(), 0x00, codesize(), 0x00)) {
                mstore(0x00, 0xb12d13eb) // `ETHTransferFailed()`.
                revert(0x1c, 0x04)
            }
        }
    }

    /** Pure functions */
    function isValidAddress(address wallet) internal pure {
        if (wallet == address(0) || wallet == address(0xdead)) {
            revert InvalidAddress();
        }
    }
}
