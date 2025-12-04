#!/usr/bin/env python3
"""
ReGuardian Quick Scanner

Single command to run all security analysis tools and get a unified report.

Usage:
    python3 scan.py <contract_path>
    python3 scan.py <contract_path> --json results.json
    python3 scan.py <contract_path> --html report.html
    python3 scan.py <contract_path> --all  # Include Mythril (slow)
    
Examples:
    python3 scan.py contracts/examples/vulnerable_wallet.sol
    python3 scan.py contracts/examples/erc777_vuln.sol --json results.json --html report.html
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.runner import scan, ReGuardianRunner


def main():
    parser = argparse.ArgumentParser(
        description="ReGuardian - Unified Smart Contract Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scan.py contracts/examples/vulnerable_wallet.sol
  python3 scan.py contract.sol --json results.json
  python3 scan.py contract.sol --html report.html --json results.json
  python3 scan.py contract.sol --all  # Include Mythril (slower but thorough)
  python3 scan.py contract.sol --quiet  # Minimal output
        """
    )
    
    parser.add_argument(
        "contract",
        help="Path to the smart contract file (.sol or .vy)"
    )
    
    parser.add_argument(
        "--json", "-j",
        metavar="FILE",
        help="Export results to JSON file"
    )
    
    parser.add_argument(
        "--html", "-o",
        metavar="FILE", 
        help="Export results to HTML report"
    )
    
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Run all tools including Mythril (slower)"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output (no progress indicators)"
    )
    
    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Skip ML-based detection"
    )
    
    parser.add_argument(
        "--no-slither",
        action="store_true",
        help="Skip Slither analysis"
    )
    
    args = parser.parse_args()
    
    # Validate contract path
    contract_path = Path(args.contract)
    if not contract_path.exists():
        print(f"Error: Contract not found: {args.contract}")
        sys.exit(1)
    
    if not contract_path.suffix in ['.sol', '.vy']:
        print(f"Warning: Unexpected file extension: {contract_path.suffix}")
    
    # Run scanner
    try:
        runner = ReGuardianRunner(verbose=not args.quiet)
        
        result = runner.run(
            str(contract_path),
            include_ml=not args.no_ml,
            include_slither=not args.no_slither,
            include_mythril=args.all,
        )
        
        # Print report
        runner.print_report(result)
        
        # Export if requested
        if args.json:
            runner.export_json(result, args.json)
        
        if args.html:
            runner.export_html(result, args.html)
        
        # Exit code based on findings
        if result.critical_count > 0 or result.high_count > 0:
            sys.exit(2)  # Critical/High issues found
        elif result.medium_count > 0:
            sys.exit(1)  # Medium issues found
        else:
            sys.exit(0)  # Clean or only low/info
            
    except KeyboardInterrupt:
        print("\nScan cancelled.")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
