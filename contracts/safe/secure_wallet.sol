// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/PullPayment.sol";

/**
 * @title SecureWallet
 * @notice Example of a properly secured wallet contract
 * @dev Demonstrates multiple reentrancy protection patterns
 */
contract SecureWallet is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    /**
     * @notice Deposit ETH into the wallet
     */
    function deposit() public payable {
        require(msg.value >= 0.01 ether, "Minimum deposit is 0.01 ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice SECURE: Withdraw all funds using Checks-Effects-Interactions
     * @dev Protected by:
     *      1. nonReentrant modifier from OpenZeppelin
     *      2. Checks-Effects-Interactions pattern
     */
    function withdraw() public nonReentrant {
        // CHECKS: Validate conditions first
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // EFFECTS: Update state BEFORE external call
        balances[msg.sender] = 0;
        
        // INTERACTIONS: External call LAST
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, balance);
    }
    
    /**
     * @notice Alternative: Withdraw specific amount
     * @param amount Amount to withdraw
     */
    function withdrawAmount(uint256 amount) public nonReentrant {
        // CHECKS
        require(amount > 0, "Amount must be positive");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // EFFECTS
        balances[msg.sender] -= amount;
        
        // INTERACTIONS
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, amount);
    }
    
    /**
     * @notice Get contract balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}


/**
 * @title SecureWalletWithPullPayment
 * @notice Even more secure using pull-over-push pattern
 * @dev Uses OpenZeppelin's PullPayment for maximum safety
 */
contract SecureWalletWithPullPayment is ReentrancyGuard, PullPayment {
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event WithdrawalPending(address indexed user, uint256 amount);
    
    /**
     * @notice Deposit ETH
     */
    function deposit() public payable {
        require(msg.value >= 0.01 ether, "Minimum deposit is 0.01 ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice Request withdrawal - funds are escrowed
     * @dev Uses pull-over-push pattern:
     *      1. User calls requestWithdrawal() - funds moved to escrow
     *      2. User calls withdrawPayments() - funds sent to user
     *      This completely eliminates reentrancy risk
     */
    function requestWithdrawal() public nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // Update state
        balances[msg.sender] = 0;
        
        // Use PullPayment's async transfer (no external call here)
        _asyncTransfer(msg.sender, balance);
        
        emit WithdrawalPending(msg.sender, balance);
    }
    
    /**
     * @notice Check pending withdrawal amount
     * @param payee Address to check
     */
    function pendingWithdrawal(address payee) public view returns (uint256) {
        return payments(payee);
    }
    
    // User calls inherited withdrawPayments(payee) to receive funds
}


/**
 * @title SecureWalletManualLock
 * @notice Manual reentrancy lock implementation
 * @dev Shows how ReentrancyGuard works internally
 */
contract SecureWalletManualLock {
    mapping(address => uint256) public balances;
    
    // Manual reentrancy lock
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    constructor() {
        _status = _NOT_ENTERED;
    }
    
    /**
     * @dev Manual nonReentrant modifier
     */
    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
    
    function deposit() public payable {
        require(msg.value >= 0.01 ether, "Minimum deposit is 0.01 ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw() public nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // CEI Pattern
        balances[msg.sender] = 0;
        
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, balance);
    }
}
