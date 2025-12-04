"""
Slither Integration

Integrates with Slither static analysis tool for comprehensive
vulnerability detection, including reentrancy.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..detectors.reentrancy.base import (
    ReentrancyVulnerability,
    ReentrancyType,
    Severity,
    VulnerabilityLocation,
)


@dataclass
class SlitherConfig:
    """Configuration for Slither analysis."""
    solc_version: Optional[str] = None
    exclude_detectors: List[str] = None
    include_detectors: List[str] = None
    filter_paths: List[str] = None
    compile_force_framework: Optional[str] = None
    
    def __post_init__(self):
        if self.exclude_detectors is None:
            self.exclude_detectors = []
        if self.include_detectors is None:
            self.include_detectors = []
        if self.filter_paths is None:
            self.filter_paths = []


class SlitherAnalyzer:
    """
    Wrapper for Slither static analysis tool.
    
    Slither provides 92+ built-in detectors including:
    - reentrancy-eth
    - reentrancy-no-eth
    - reentrancy-benign
    - reentrancy-events
    - reentrancy-unlimited-gas
    """
    
    # Slither reentrancy detector IDs
    REENTRANCY_DETECTORS = [
        'reentrancy-eth',           # Reentrancy with ETH transfer
        'reentrancy-no-eth',        # Reentrancy without ETH
        'reentrancy-benign',        # Benign reentrancy (events only)
        'reentrancy-events',        # Reentrancy with event emission
        'reentrancy-unlimited-gas', # Reentrancy with unlimited gas
    ]
    
    # Severity mapping from Slither to our format
    SEVERITY_MAP = {
        'High': Severity.HIGH,
        'Medium': Severity.MEDIUM,
        'Low': Severity.LOW,
        'Informational': Severity.INFORMATIONAL,
        'Optimization': Severity.INFORMATIONAL,
    }
    
    def __init__(self, config: Optional[SlitherConfig] = None):
        self.config = config or SlitherConfig()
        self._check_slither_installed()
    
    def _check_slither_installed(self) -> bool:
        """Check if Slither is installed and accessible."""
        try:
            result = subprocess.run(
                ['slither', '--version'],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            raise RuntimeError(
                "Slither is not installed. Install with: pip install slither-analyzer"
            )
    
    def analyze(
        self, 
        contract_path: Path,
        reentrancy_only: bool = True,
    ) -> List[ReentrancyVulnerability]:
        """
        Run Slither analysis on a contract.
        
        Args:
            contract_path: Path to the Solidity contract
            reentrancy_only: If True, only run reentrancy detectors
            
        Returns:
            List of detected vulnerabilities
        """
        # Build command
        cmd = ['slither', str(contract_path), '--json', '-']
        
        # Add detector filters
        if reentrancy_only:
            detectors = ','.join(self.REENTRANCY_DETECTORS)
            cmd.extend(['--detect', detectors])
        elif self.config.include_detectors:
            cmd.extend(['--detect', ','.join(self.config.include_detectors)])
        
        if self.config.exclude_detectors:
            cmd.extend(['--exclude', ','.join(self.config.exclude_detectors)])
        
        # Add solc version if specified
        if self.config.solc_version:
            cmd.extend(['--solc-solcs-select', self.config.solc_version])
        
        # Run Slither
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Slither analysis timed out")
        
        # Parse results
        if result.stdout:
            return self._parse_results(result.stdout, str(contract_path))
        
        return []
    
    def analyze_project(
        self,
        project_path: Path,
        reentrancy_only: bool = True,
    ) -> Dict[str, List[ReentrancyVulnerability]]:
        """
        Analyze an entire project directory.
        
        Args:
            project_path: Path to the project root
            reentrancy_only: If True, only run reentrancy detectors
            
        Returns:
            Dictionary mapping contract paths to vulnerabilities
        """
        results = {}
        
        # Find all Solidity files
        sol_files = list(project_path.glob('**/*.sol'))
        
        for sol_file in sol_files:
            # Skip test files and mocks
            if any(skip in str(sol_file) for skip in ['test', 'mock', 'Mock']):
                continue
            
            try:
                vulns = self.analyze(sol_file, reentrancy_only)
                if vulns:
                    results[str(sol_file)] = vulns
            except Exception as e:
                print(f"Error analyzing {sol_file}: {e}")
        
        return results
    
    def _parse_results(
        self, 
        json_output: str,
        contract_path: str,
    ) -> List[ReentrancyVulnerability]:
        """Parse Slither JSON output into our vulnerability format."""
        vulnerabilities = []
        
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            return vulnerabilities
        
        if not data.get('success', False):
            return vulnerabilities
        
        detectors = data.get('results', {}).get('detectors', [])
        
        for detector in detectors:
            check = detector.get('check', '')
            
            # Only process reentrancy findings
            if not check.startswith('reentrancy'):
                continue
            
            vuln = self._convert_finding(detector, contract_path)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _convert_finding(
        self,
        finding: Dict[str, Any],
        contract_path: str,
    ) -> Optional[ReentrancyVulnerability]:
        """Convert a Slither finding to our vulnerability format."""
        
        check = finding.get('check', '')
        impact = finding.get('impact', 'Medium')
        description = finding.get('description', '')
        
        # Determine reentrancy type based on detector
        if 'eth' in check:
            reentrancy_type = ReentrancyType.MONO_FUNCTION
        elif 'no-eth' in check:
            reentrancy_type = ReentrancyType.CROSS_FUNCTION
        else:
            reentrancy_type = ReentrancyType.MONO_FUNCTION
        
        # Extract location from elements
        elements = finding.get('elements', [])
        location = self._extract_location(elements, contract_path)
        
        if not location:
            return None
        
        # Map severity
        severity = self.SEVERITY_MAP.get(impact, Severity.MEDIUM)
        
        # Generate unique ID
        import uuid
        vuln_id = str(uuid.uuid4())
        
        return ReentrancyVulnerability(
            id=vuln_id,
            type=reentrancy_type,
            severity=severity,
            title=f"Slither: {check}",
            description=description,
            location=location,
            attack_vector=self._generate_attack_vector(check),
            recommendation=self._generate_recommendation(check),
            references=[
                f"https://github.com/crytic/slither/wiki/Detector-Documentation#{check}",
            ],
            confidence=0.9 if impact == 'High' else 0.7,
        )
    
    def _extract_location(
        self,
        elements: List[Dict[str, Any]],
        default_path: str,
    ) -> Optional[VulnerabilityLocation]:
        """Extract location information from Slither elements."""
        
        if not elements:
            return VulnerabilityLocation(
                file_path=default_path,
                contract_name="Unknown",
                function_name="Unknown",
                line_start=0,
                line_end=0,
            )
        
        # Find the most relevant element (usually a function)
        for element in elements:
            if element.get('type') == 'function':
                source_mapping = element.get('source_mapping', {})
                return VulnerabilityLocation(
                    file_path=source_mapping.get('filename_relative', default_path),
                    contract_name=element.get('type_specific_fields', {}).get(
                        'parent', {}
                    ).get('name', 'Unknown'),
                    function_name=element.get('name', 'Unknown'),
                    line_start=source_mapping.get('lines', [0])[0],
                    line_end=source_mapping.get('lines', [0])[-1] if source_mapping.get('lines') else 0,
                )
        
        # Fallback to first element
        element = elements[0]
        source_mapping = element.get('source_mapping', {})
        
        return VulnerabilityLocation(
            file_path=source_mapping.get('filename_relative', default_path),
            contract_name=element.get('name', 'Unknown'),
            function_name="Unknown",
            line_start=source_mapping.get('lines', [0])[0] if source_mapping.get('lines') else 0,
            line_end=source_mapping.get('lines', [0])[-1] if source_mapping.get('lines') else 0,
        )
    
    def _generate_attack_vector(self, check: str) -> str:
        """Generate attack vector description based on detector type."""
        vectors = {
            'reentrancy-eth': (
                "1. Attacker calls vulnerable function\n"
                "2. Function sends ETH to attacker\n"
                "3. Attacker's receive/fallback re-enters\n"
                "4. State not yet updated, allowing repeated withdrawals"
            ),
            'reentrancy-no-eth': (
                "1. Attacker calls vulnerable function\n"
                "2. Function makes external call (not ETH transfer)\n"
                "3. External contract re-enters\n"
                "4. State manipulation before update"
            ),
            'reentrancy-benign': (
                "This reentrancy only affects event ordering and is generally "
                "not exploitable for financial gain, but may cause issues for "
                "off-chain systems relying on event order."
            ),
        }
        return vectors.get(check, "See Slither documentation for details.")
    
    def _generate_recommendation(self, check: str) -> str:
        """Generate recommendation based on detector type."""
        return (
            "1. Use OpenZeppelin's ReentrancyGuard\n"
            "2. Follow Checks-Effects-Interactions pattern\n"
            "3. Update state before external calls\n"
            "4. Consider using pull-over-push for payments"
        )
    
    def get_contract_info(self, contract_path: Path) -> Dict[str, Any]:
        """
        Get contract information using Slither's analysis.
        
        Returns contract structure, functions, state variables, etc.
        """
        cmd = [
            'slither', str(contract_path),
            '--print', 'contract-summary',
            '--json', '-'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            if result.stdout:
                return json.loads(result.stdout)
        except Exception:
            pass
        
        return {}
