# ReGuardian Architecture

## Overview

ReGuardian is a modular, extensible smart contract security analysis tool focused on detecting reentrancy vulnerabilities. It combines multiple analysis techniques for comprehensive coverage.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        ReGuardian CLI                           │
│                     (reguardian.py)                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Core Engine                                │
│                  (src/core/reguardian.py)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Config    │  │  Orchestr.  │  │   Report    │             │
│  │  Manager    │  │             │  │  Generator  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│    Custom       │ │    External     │ │      AI/ML      │
│   Detectors     │ │   Analyzers     │ │    (Future)     │
│                 │ │                 │ │                 │
│ • Mono-function │ │ • Slither       │ │ • Pattern       │
│ • Cross-func    │ │ • Mythril       │ │   Recognition   │
│ • Cross-contract│ │ • Echidna       │ │ • Bytecode      │
│ • Read-only     │ │                 │ │   Analysis      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Vulnerability Results                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  • ID, Type, Severity                                   │   │
│  │  • Location (file, contract, function, lines)           │   │
│  │  • Description, Attack Vector                           │   │
│  │  • Recommendation, Suggested Fix                        │   │
│  │  • OpenZeppelin Integration Status                      │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. CLI Layer (`reguardian.py`)

The command-line interface provides:
- `analyze` - Single contract analysis
- `scan` - Project-wide scanning
- `report` - HTML report generation

Uses Click for argument parsing and Rich for beautiful console output.

### 2. Core Engine (`src/core/`)

**ReGuardian Class**
- Orchestrates all analysis components
- Manages configuration
- Deduplicates and filters results
- Generates summaries

**Configuration**
- YAML-based configuration
- Analysis mode selection (quick/standard/deep/full)
- Detector enable/disable
- Severity filtering

### 3. Detectors (`src/detectors/reentrancy/`)

**Base Detector** (`base.py`)
- Abstract base class for all detectors
- Common data structures (Vulnerability, Location, etc.)
- OpenZeppelin detection utilities
- Fix suggestion generation

**Mono-Function Detector** (`mono_function.py`)
- Detects classic reentrancy (The DAO pattern)
- Pattern: External call before state update
- Source code and bytecode analysis

**Cross-Function Detector** (`cross_function.py`)
- Detects shared state vulnerabilities
- Analyzes function interactions
- Identifies unprotected state access

**Cross-Contract Detector** (`cross_contract.py`)
- ERC777/ERC721/ERC1155 callback detection
- Flash loan callback analysis
- Custom interface vulnerability detection

**Read-Only Detector** (`read_only.py`)
- Pricing function analysis
- View function state dependency tracking
- Oracle manipulation detection

### 4. External Analyzers (`src/analyzers/`)

**Slither Integration** (`slither_analyzer.py`)
- Static analysis wrapper
- 5 reentrancy-specific detectors
- Project-wide scanning
- JSON output parsing

**Mythril Integration** (`mythril_analyzer.py`)
- Symbolic execution wrapper
- Bytecode analysis
- On-chain contract analysis
- Transaction sequence generation

### 5. Data Layer (`data/`)

**Attack Database** (`attacks/attack_database.json`)
- Historical attack records
- Vulnerability patterns
- Statistics and trends

## Analysis Modes

| Mode | Detectors | Slither | Mythril | AI | Use Case |
|------|-----------|---------|---------|-----|----------|
| Quick | ✓ | ✗ | ✗ | ✗ | Fast feedback during development |
| Standard | ✓ | ✓ | ✗ | ✗ | Regular security checks |
| Deep | ✓ | ✓ | ✓ | ✗ | Pre-deployment audit |
| Full | ✓ | ✓ | ✓ | ✓ | Comprehensive security review |

## Reentrancy Types Detected

### 1. Mono-Function Reentrancy
```solidity
function withdraw() {
    (bool s,) = msg.sender.call{value: bal}(""); // External call
    balances[msg.sender] = 0; // State update AFTER - VULNERABLE
}
```

### 2. Cross-Function Reentrancy
```solidity
function withdraw() {
    (bool s,) = msg.sender.call{value: bal}("");
    balances[msg.sender] = 0;
}

function transfer(address to, uint amt) {
    balances[msg.sender] -= amt; // Shares state with withdraw
    balances[to] += amt;
}
```

### 3. Cross-Contract Reentrancy
```solidity
function tokensReceived(...) external {
    // ERC777 callback - can re-enter
    deposits[from] += amount;
}
```

### 4. Read-Only Reentrancy
```solidity
function getPrice() view returns (uint) {
    return totalAssets / totalSupply; // Can return stale value
}

function withdraw() {
    (bool s,) = msg.sender.call{value: assets}("");
    // getPrice() returns wrong value during callback
    totalAssets -= assets;
}
```

## OpenZeppelin Integration

ReGuardian specifically checks for and recommends OpenZeppelin patterns:

1. **ReentrancyGuard** - `nonReentrant` modifier
2. **PullPayment** - Pull-over-push pattern
3. **Checks-Effects-Interactions** - Code pattern

## Extension Points

### Adding New Detectors

1. Create new class inheriting from `ReentrancyDetector`
2. Implement `analyze()` and `analyze_bytecode()` methods
3. Register in `__init__.py`
4. Add to core engine detector list

### Adding New Analyzers

1. Create wrapper class in `src/analyzers/`
2. Implement analysis methods
3. Convert output to `ReentrancyVulnerability` format
4. Integrate with core engine

## Future Enhancements

1. **AI/ML Detection**
   - Deep learning on bytecode patterns
   - Graph neural networks for CFG analysis
   - LLM-based code review

2. **Real-time Monitoring**
   - Mempool transaction analysis
   - Attack detection and alerting

3. **IDE Integration**
   - VS Code extension
   - Real-time feedback during coding

4. **CI/CD Integration**
   - GitHub Actions
   - Pre-commit hooks
