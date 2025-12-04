"""
ReGuardian Core Engine

Main orchestrator for reentrancy vulnerability detection.
Combines multiple analysis engines and detectors.
"""

import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from ..detectors.reentrancy import (
    MonoFunctionReentrancyDetector,
    CrossFunctionReentrancyDetector,
    CrossContractReentrancyDetector,
    ReadOnlyReentrancyDetector,
)
from ..detectors.reentrancy.base import (
    ReentrancyVulnerability,
    AnalysisResult,
    Severity,
)
from ..analyzers.slither_analyzer import SlitherAnalyzer, SlitherConfig
from ..analyzers.mythril_analyzer import MythrilAnalyzer, MythrilConfig


class AnalysisMode(Enum):
    """Analysis depth modes."""
    QUICK = "quick"      # Custom detectors only
    STANDARD = "standard"  # Custom + Slither
    DEEP = "deep"        # Custom + Slither + Mythril
    FULL = "full"        # All engines + AI analysis


@dataclass
class ReGuardianConfig:
    """Configuration for ReGuardian analysis."""
    mode: AnalysisMode = AnalysisMode.STANDARD
    
    # Detection options
    check_mono_function: bool = True
    check_cross_function: bool = True
    check_cross_contract: bool = True
    check_read_only: bool = True
    
    # Severity filter
    min_severity: Severity = Severity.LOW
    
    # External tool configs
    slither_config: Optional[SlitherConfig] = None
    mythril_config: Optional[MythrilConfig] = None
    
    # Output options
    generate_fixes: bool = True
    include_references: bool = True
    
    # OpenZeppelin
    check_oz_patterns: bool = True
    suggest_oz_fixes: bool = True


class ReGuardian:
    """
    Main ReGuardian analysis engine.
    
    Orchestrates multiple detection methods:
    1. Custom pattern-based detectors
    2. Slither static analysis
    3. Mythril symbolic execution
    4. (Future) AI-based detection
    
    Usage:
        rg = ReGuardian()
        result = rg.analyze("path/to/contract.sol")
        print(result.vulnerabilities)
    """
    
    VERSION = "0.1.0"
    
    def __init__(self, config: Optional[ReGuardianConfig] = None):
        self.config = config or ReGuardianConfig()
        self._init_detectors()
        self._init_analyzers()
    
    def _init_detectors(self):
        """Initialize custom reentrancy detectors."""
        self.detectors = []
        
        if self.config.check_mono_function:
            self.detectors.append(MonoFunctionReentrancyDetector())
        
        if self.config.check_cross_function:
            self.detectors.append(CrossFunctionReentrancyDetector())
        
        if self.config.check_cross_contract:
            self.detectors.append(CrossContractReentrancyDetector())
        
        if self.config.check_read_only:
            self.detectors.append(ReadOnlyReentrancyDetector())
    
    def _init_analyzers(self):
        """Initialize external analysis tools."""
        self.slither = None
        self.mythril = None
        
        if self.config.mode in (AnalysisMode.STANDARD, AnalysisMode.DEEP, AnalysisMode.FULL):
            try:
                self.slither = SlitherAnalyzer(self.config.slither_config)
            except RuntimeError as e:
                print(f"Warning: Slither not available: {e}")
        
        if self.config.mode in (AnalysisMode.DEEP, AnalysisMode.FULL):
            try:
                self.mythril = MythrilAnalyzer(self.config.mythril_config)
            except RuntimeError as e:
                print(f"Warning: Mythril not available: {e}")
    
    def analyze(self, contract_path: str) -> AnalysisResult:
        """
        Analyze a smart contract for reentrancy vulnerabilities.
        
        Args:
            contract_path: Path to the Solidity/Vyper contract
            
        Returns:
            AnalysisResult containing all findings
        """
        path = Path(contract_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Contract not found: {contract_path}")
        
        start_time = time.time()
        all_vulnerabilities: List[ReentrancyVulnerability] = []
        warnings: List[str] = []
        
        # Run custom detectors
        for detector in self.detectors:
            try:
                vulns = detector.analyze(path)
                all_vulnerabilities.extend(vulns)
            except Exception as e:
                warnings.append(f"{detector.name} failed: {e}")
        
        # Run Slither if available
        if self.slither:
            try:
                slither_vulns = self.slither.analyze(path, reentrancy_only=True)
                all_vulnerabilities.extend(slither_vulns)
            except Exception as e:
                warnings.append(f"Slither analysis failed: {e}")
        
        # Run Mythril if available (deep/full mode)
        if self.mythril:
            try:
                mythril_vulns = self.mythril.analyze(path, reentrancy_only=True)
                all_vulnerabilities.extend(mythril_vulns)
            except Exception as e:
                warnings.append(f"Mythril analysis failed: {e}")
        
        # Deduplicate findings
        all_vulnerabilities = self._deduplicate(all_vulnerabilities)
        
        # Filter by severity
        all_vulnerabilities = self._filter_by_severity(all_vulnerabilities)
        
        # Generate fixes if requested
        if self.config.generate_fixes:
            self._generate_fixes(all_vulnerabilities)
        
        elapsed = time.time() - start_time
        
        return AnalysisResult(
            contract_path=str(path),
            vulnerabilities=all_vulnerabilities,
            analysis_time_seconds=elapsed,
            analyzer_version=self.VERSION,
            warnings=warnings,
        )
    
    def analyze_bytecode(self, bytecode: str) -> AnalysisResult:
        """
        Analyze EVM bytecode for reentrancy vulnerabilities.
        
        Args:
            bytecode: Hex-encoded bytecode
            
        Returns:
            AnalysisResult containing findings
        """
        start_time = time.time()
        all_vulnerabilities: List[ReentrancyVulnerability] = []
        warnings: List[str] = []
        
        # Run custom bytecode analysis
        for detector in self.detectors:
            try:
                vulns = detector.analyze_bytecode(bytecode)
                all_vulnerabilities.extend(vulns)
            except Exception as e:
                warnings.append(f"{detector.name} bytecode analysis failed: {e}")
        
        # Run Mythril bytecode analysis
        if self.mythril:
            try:
                mythril_vulns = self.mythril.analyze_bytecode(bytecode)
                all_vulnerabilities.extend(mythril_vulns)
            except Exception as e:
                warnings.append(f"Mythril bytecode analysis failed: {e}")
        
        elapsed = time.time() - start_time
        
        return AnalysisResult(
            contract_path="bytecode",
            vulnerabilities=all_vulnerabilities,
            analysis_time_seconds=elapsed,
            analyzer_version=self.VERSION,
            warnings=warnings,
        )
    
    def analyze_project(self, project_path: str) -> Dict[str, AnalysisResult]:
        """
        Analyze an entire project directory.
        
        Args:
            project_path: Path to project root
            
        Returns:
            Dictionary mapping contract paths to results
        """
        path = Path(project_path)
        results = {}
        
        # Find all Solidity files
        sol_files = list(path.glob('**/*.sol'))
        vyper_files = list(path.glob('**/*.vy'))
        
        all_files = sol_files + vyper_files
        
        for contract_file in all_files:
            # Skip common non-production directories
            skip_patterns = ['node_modules', 'test', 'tests', 'mock', 'Mock', 'lib']
            if any(pattern in str(contract_file) for pattern in skip_patterns):
                continue
            
            try:
                result = self.analyze(str(contract_file))
                if result.has_vulnerabilities:
                    results[str(contract_file)] = result
            except Exception as e:
                print(f"Error analyzing {contract_file}: {e}")
        
        return results
    
    def _deduplicate(
        self, 
        vulnerabilities: List[ReentrancyVulnerability]
    ) -> List[ReentrancyVulnerability]:
        """Remove duplicate findings based on location."""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create a key based on location
            key = (
                vuln.location.file_path,
                vuln.location.function_name,
                vuln.location.line_start,
                vuln.type.value,
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    def _filter_by_severity(
        self,
        vulnerabilities: List[ReentrancyVulnerability]
    ) -> List[ReentrancyVulnerability]:
        """Filter vulnerabilities by minimum severity."""
        severity_order = [
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        
        min_index = severity_order.index(self.config.min_severity)
        
        return [
            v for v in vulnerabilities
            if severity_order.index(v.severity) >= min_index
        ]
    
    def _generate_fixes(
        self,
        vulnerabilities: List[ReentrancyVulnerability]
    ):
        """Generate fix suggestions for vulnerabilities."""
        for vuln in vulnerabilities:
            if vuln.suggested_fix:
                continue
            
            # Find the appropriate detector to generate fix
            for detector in self.detectors:
                if detector.reentrancy_type == vuln.type:
                    vuln.suggested_fix = detector.generate_fix_suggestion(vuln)
                    break
    
    def get_summary(self, result: AnalysisResult) -> Dict[str, Any]:
        """
        Generate a summary of analysis results.
        
        Args:
            result: Analysis result
            
        Returns:
            Summary dictionary
        """
        return {
            "contract": result.contract_path,
            "total_vulnerabilities": len(result.vulnerabilities),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": sum(1 for v in result.vulnerabilities if v.severity == Severity.MEDIUM),
            "low": sum(1 for v in result.vulnerabilities if v.severity == Severity.LOW),
            "analysis_time": f"{result.analysis_time_seconds:.2f}s",
            "warnings": len(result.warnings),
            "by_type": {
                "mono_function": sum(1 for v in result.vulnerabilities if v.type.value == "mono_function"),
                "cross_function": sum(1 for v in result.vulnerabilities if v.type.value == "cross_function"),
                "cross_contract": sum(1 for v in result.vulnerabilities if v.type.value == "cross_contract"),
                "read_only": sum(1 for v in result.vulnerabilities if v.type.value == "read_only"),
            }
        }
