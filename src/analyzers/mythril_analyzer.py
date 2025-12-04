"""
Mythril Integration

Integrates with Mythril symbolic execution tool for deep
vulnerability analysis including reentrancy detection.
"""

import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import uuid

from ..detectors.reentrancy.base import (
    ReentrancyVulnerability,
    ReentrancyType,
    Severity,
    VulnerabilityLocation,
)


@dataclass
class MythrilConfig:
    """Configuration for Mythril analysis."""
    execution_timeout: int = 600  # seconds (10 minutes)
    max_depth: int = 50
    solver_timeout: int = 25000  # milliseconds
    transaction_count: int = 3
    enable_physics: bool = False
    
    
class MythrilAnalyzer:
    """
    Wrapper for Mythril security analysis tool.
    
    Mythril uses symbolic execution to detect vulnerabilities including:
    - SWC-107: Reentrancy
    - SWC-104: Unchecked Call Return Value
    - SWC-106: Unprotected SELFDESTRUCT
    """
    
    # SWC IDs related to reentrancy
    REENTRANCY_SWC_IDS = [
        'SWC-107',  # Reentrancy
        'SWC-104',  # Unchecked Call Return Value (often related)
    ]
    
    SEVERITY_MAP = {
        'High': Severity.HIGH,
        'Medium': Severity.MEDIUM,
        'Low': Severity.LOW,
    }
    
    def __init__(self, config: Optional[MythrilConfig] = None):
        self.config = config or MythrilConfig()
        self._check_mythril_installed()
    
    def _check_mythril_installed(self) -> bool:
        """Check if Mythril is installed."""
        try:
            result = subprocess.run(
                ['myth', 'version'],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            raise RuntimeError(
                "Mythril is not installed. Install with: pip install mythril"
            )
    
    def analyze(
        self,
        contract_path: Path,
        reentrancy_only: bool = True,
    ) -> List[ReentrancyVulnerability]:
        """
        Run Mythril analysis on a contract.
        
        Args:
            contract_path: Path to the Solidity contract
            reentrancy_only: If True, only return reentrancy findings
            
        Returns:
            List of detected vulnerabilities
        """
        cmd = [
            'myth', 'analyze',
            str(contract_path),
            '-o', 'json',
            '--execution-timeout', str(self.config.execution_timeout),
            '--max-depth', str(self.config.max_depth),
            '--solver-timeout', str(self.config.solver_timeout),
            '-t', str(self.config.transaction_count),
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout + 60,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Mythril analysis timed out")
        
        # Parse results
        if result.stdout:
            return self._parse_results(
                result.stdout, 
                str(contract_path),
                reentrancy_only,
            )
        
        return []
    
    def analyze_bytecode(
        self,
        bytecode: str,
        reentrancy_only: bool = True,
    ) -> List[ReentrancyVulnerability]:
        """
        Analyze EVM bytecode directly.
        
        Args:
            bytecode: Hex-encoded bytecode
            reentrancy_only: If True, only return reentrancy findings
            
        Returns:
            List of detected vulnerabilities
        """
        if not bytecode.startswith('0x'):
            bytecode = '0x' + bytecode
        
        cmd = [
            'myth', 'analyze',
            '-c', bytecode,
            '-o', 'json',
            '--execution-timeout', str(self.config.execution_timeout),
            '--max-depth', str(self.config.max_depth),
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout + 60,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Mythril bytecode analysis timed out")
        
        if result.stdout:
            return self._parse_results(
                result.stdout,
                "bytecode",
                reentrancy_only,
            )
        
        return []
    
    def analyze_address(
        self,
        address: str,
        rpc_url: str,
        reentrancy_only: bool = True,
    ) -> List[ReentrancyVulnerability]:
        """
        Analyze a deployed contract by address.
        
        Args:
            address: Contract address
            rpc_url: Ethereum RPC URL
            reentrancy_only: If True, only return reentrancy findings
            
        Returns:
            List of detected vulnerabilities
        """
        cmd = [
            'myth', 'analyze',
            '-a', address,
            '--rpc', rpc_url,
            '-o', 'json',
            '--execution-timeout', str(self.config.execution_timeout),
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout + 60,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Mythril on-chain analysis timed out")
        
        if result.stdout:
            return self._parse_results(
                result.stdout,
                address,
                reentrancy_only,
            )
        
        return []
    
    def _parse_results(
        self,
        json_output: str,
        source: str,
        reentrancy_only: bool,
    ) -> List[ReentrancyVulnerability]:
        """Parse Mythril JSON output."""
        vulnerabilities = []
        
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return vulnerabilities
        
        if not data.get('success', True):
            return vulnerabilities
        
        issues = data.get('issues', [])
        
        for issue in issues:
            swc_id = issue.get('swc-id', '')
            
            # Filter for reentrancy if requested
            if reentrancy_only and swc_id not in self.REENTRANCY_SWC_IDS:
                continue
            
            vuln = self._convert_issue(issue, source)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _convert_issue(
        self,
        issue: Dict[str, Any],
        source: str,
    ) -> Optional[ReentrancyVulnerability]:
        """Convert Mythril issue to our vulnerability format."""
        
        swc_id = issue.get('swc-id', '')
        severity_str = issue.get('severity', 'Medium')
        title = issue.get('title', 'Unknown Issue')
        description = issue.get('description', '')
        
        # Extract location
        lineno = issue.get('lineno', 0)
        filename = issue.get('filename', source)
        function = issue.get('function', 'Unknown')
        
        location = VulnerabilityLocation(
            file_path=filename,
            contract_name="Unknown",
            function_name=function,
            line_start=lineno,
            line_end=lineno,
            source_snippet=issue.get('code', None),
        )
        
        # Map severity
        severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
        
        # Determine reentrancy type
        if swc_id == 'SWC-107':
            reentrancy_type = ReentrancyType.MONO_FUNCTION
        else:
            reentrancy_type = ReentrancyType.MONO_FUNCTION
        
        return ReentrancyVulnerability(
            id=str(uuid.uuid4()),
            type=reentrancy_type,
            severity=severity,
            title=f"Mythril: {title}",
            description=description,
            location=location,
            attack_vector=self._get_attack_vector(issue),
            recommendation=(
                "1. Use OpenZeppelin's ReentrancyGuard\n"
                "2. Follow Checks-Effects-Interactions pattern\n"
                "3. Update state before external calls"
            ),
            references=[
                f"https://swcregistry.io/docs/{swc_id}",
            ],
            confidence=0.85,
        )
    
    def _get_attack_vector(self, issue: Dict[str, Any]) -> str:
        """Extract attack vector from Mythril issue."""
        # Mythril provides transaction sequences
        tx_sequence = issue.get('tx_sequence', {})
        
        if tx_sequence:
            steps = []
            for i, tx in enumerate(tx_sequence.get('steps', []), 1):
                steps.append(
                    f"{i}. Call {tx.get('function', 'unknown')} "
                    f"with value {tx.get('value', '0')}"
                )
            return '\n'.join(steps)
        
        return issue.get('description', 'See Mythril output for details.')
    
    def get_disassembly(self, contract_path: Path) -> str:
        """
        Get disassembled bytecode for manual analysis.
        
        Args:
            contract_path: Path to contract
            
        Returns:
            Disassembled bytecode
        """
        cmd = ['myth', 'disassemble', str(contract_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return result.stdout
        except Exception:
            return ""
    
    def get_control_flow_graph(
        self,
        contract_path: Path,
        output_path: Optional[Path] = None,
    ) -> Optional[str]:
        """
        Generate control flow graph visualization.
        
        Args:
            contract_path: Path to contract
            output_path: Optional path for output file
            
        Returns:
            Path to generated graph or None
        """
        if output_path is None:
            output_path = contract_path.with_suffix('.html')
        
        cmd = [
            'myth', 'analyze',
            str(contract_path),
            '-o', 'html',
            '--output-file', str(output_path),
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout,
            )
            
            if result.returncode == 0:
                return str(output_path)
        except Exception:
            pass
        
        return None
