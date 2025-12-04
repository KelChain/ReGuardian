# ReGuardian 🛡️

AI-Powered Smart Contract Reentrancy Vulnerability Detection

[![Security Scan](https://img.shields.io/badge/security-scan-green)](https://github.com/YOUR_USERNAME/ReGuardian/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

ReGuardian is a comprehensive security analysis tool designed to detect reentrancy vulnerabilities in smart contracts. It combines traditional static analysis with modern AI/ML techniques to provide thorough security assessments.

**Total losses from reentrancy attacks: $879M+** (Euler Finance, Cream Finance, Vyper/Curve, Radiant Capital, KyberSwap, The DAO, etc.)

## 🎯 Features

- **Multi-Type Reentrancy Detection**
  - Mono-function reentrancy
  - Cross-function reentrancy
  - Cross-contract reentrancy
  - Read-only reentrancy
  
- **Integration with Industry Tools**
  - Slither static analysis
  - Mythril symbolic execution
  - Echidna fuzzing
  - OpenZeppelin security patterns

- **AI-Enhanced Analysis**
  - Pattern recognition in bytecode
  - Control flow graph analysis
  - Natural language vulnerability reports

## 📊 Notable Attacks Database

| Protocol | Date | Loss | Attack Type |
|----------|------|------|-------------|
| Euler Finance | Mar 2023 | $197M | Cross-function reentrancy |
| Cream Finance | Oct 2021 | $130M | ERC777 cross-contract |
| Vyper/Curve | Jul 2023 | $73M | Compiler bug |
| The DAO | Jun 2016 | $60M | Classic reentrancy |
| Radiant Capital | Oct 2024 | $51M | Cross-contract callback |
| KyberSwap | Nov 2023 | $49M | Cross-function tick manipulation |
| Hedgey Finance | Apr 2024 | $45M | Token approval callback |
| Penpie | Sep 2024 | $27M | Pendle market callback |
| Sonne Finance | May 2024 | $20M | Compound V2 fork donation |

*Database includes 39 documented attacks from 2016-2024. See `/data/attacks/attack_database.json` for full details.*

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements-minimal.txt

# Option 1: Web Interface (Recommended for users)
python3 server.py
# Open http://localhost:8000 in your browser

# Option 2: Unified CLI Scanner (All tools in one command)
python3 scan.py contracts/examples/vulnerable_wallet.sol

# Option 3: Individual CLI commands
python3 reguardian.py analyze contracts/examples/vulnerable_wallet.sol --mode standard
python3 reguardian.py report contracts/examples/vulnerable_wallet.sol -o report.html
python3 reguardian.py scan /path/to/project
```

## 🖥️ Web Interface

The easiest way to use ReGuardian is through the web interface:

```bash
python3 server.py
```

Then open **http://localhost:8000** in your browser.

**Features:**
- 📝 Paste or upload Solidity/Vyper code
- 🔍 One-click analysis with all tools
- 📊 Visual severity breakdown
- 📈 Risk score visualization  
- 💡 Detailed findings with fix suggestions
- 📥 Export to JSON or HTML report
- 📚 Historical attack database

![ReGuardian Web Interface](docs/screenshot.png)

## 🌐 API Endpoints

```bash
# Health check
curl http://localhost:8000/health

# Analyze contract source
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"source_code": "contract Test { ... }", "mode": "standard"}'

# Get attack database
curl http://localhost:8000/attacks
```

## 📁 Project Structure

```
ReGuardian/
├── src/
│   ├── analyzers/           # Core analysis engines
│   │   ├── static/          # Static analysis (Slither integration)
│   │   ├── symbolic/        # Symbolic execution (Mythril)
│   │   ├── fuzzing/         # Fuzz testing (Echidna/Foundry)
│   │   └── ai/              # ML-based detection
│   ├── detectors/           # Vulnerability detectors
│   │   ├── reentrancy/      # Reentrancy-specific detectors
│   │   └── patterns/        # Known attack patterns
│   ├── reporters/           # Report generation
│   └── utils/               # Utility functions
├── contracts/
│   ├── examples/            # Example vulnerable contracts
│   ├── safe/                # OpenZeppelin-protected examples
│   └── tests/               # Test contracts
├── data/
│   ├── attacks/             # Historical attack data
│   └── patterns/            # Vulnerability patterns
├── tests/                   # Unit and integration tests
├── docs/                    # Documentation
└── config/                  # Configuration files
```

## 🔧 Configuration

Create a `config.yaml` file:

```yaml
analysis:
  engines:
    - slither
    - mythril
    - custom_ai
  
  reentrancy:
    check_cross_function: true
    check_cross_contract: true
    check_read_only: true
    
  severity_threshold: medium
  
openzeppelin:
  check_reentrancy_guard: true
  suggest_fixes: true
```

## 🛠️ Tech Stack

- **Python 3.10+** - Core analysis engine
- **Solidity** - Smart contract analysis
- **Slither** - Static analysis framework
- **Mythril** - Security analysis tool
- **OpenZeppelin** - Security patterns & guards
- **PyTorch/TensorFlow** - ML models (optional)
- **React/Next.js** - Web dashboard (optional)

## 📖 Documentation

- [Installation Guide](docs/installation.md)
- [Usage Guide](docs/usage.md)
- [API Reference](docs/api.md)
- [Contributing](docs/contributing.md)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](docs/contributing.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

ReGuardian is a security analysis tool and should be used as part of a comprehensive security audit process. No automated tool can guarantee 100% vulnerability detection. Always combine automated analysis with manual code review.
