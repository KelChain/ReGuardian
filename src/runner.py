"""
ReGuardian Unified Test Runner

Runs all analysis tools in a single suite and presents
consolidated results in a clean, easy-to-read format.

Usage:
    from src.runner import ReGuardianRunner
    
    runner = ReGuardianRunner()
    results = runner.run("path/to/contract.sol")
    runner.print_report(results)
"""

import time
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.layout import Layout
from rich.text import Text
from rich.syntax import Syntax
from rich.tree import Tree
from rich.markdown import Markdown

from .core.reguardian import ReGuardian, ReGuardianConfig, AnalysisMode
from .detectors.reentrancy.base import Severity, ReentrancyType
from .ml.features import FeatureExtractor
from .ml.detector import MLReentrancyDetector


console = Console()


@dataclass
class ToolResult:
    """Result from a single analysis tool."""
    tool_name: str
    success: bool
    duration: float
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    

@dataclass 
class UnifiedResult:
    """Consolidated results from all analysis tools."""
    contract_path: str
    contract_name: str
    timestamp: str
    total_duration: float
    
    # Tool results
    tool_results: Dict[str, ToolResult] = field(default_factory=dict)
    
    # Aggregated findings
    all_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    unique_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    # Summary counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Feature analysis
    features: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)


class ReGuardianRunner:
    """
    Unified test runner for ReGuardian.
    
    Runs all analysis tools in sequence and consolidates results
    into a single, easy-to-read report.
    
    Features:
    - Single command to run all tests
    - Progress tracking with rich UI
    - Deduplicated findings across tools
    - Severity-sorted results
    - Executive summary
    - Detailed findings with fix suggestions
    - Export to JSON/HTML
    
    Usage:
        runner = ReGuardianRunner()
        results = runner.run("contract.sol")
        runner.print_report(results)
    """
    
    def __init__(self, verbose: bool = True):
        """
        Initialize the runner.
        
        Args:
            verbose: Show progress during analysis
        """
        self.verbose = verbose
        self.feature_extractor = FeatureExtractor()
    
    def run(
        self,
        contract_path: str,
        include_ml: bool = True,
        include_slither: bool = True,
        include_mythril: bool = False,  # Slower, optional
    ) -> UnifiedResult:
        """
        Run all analysis tools on a contract.
        
        Args:
            contract_path: Path to the contract file
            include_ml: Include ML-based detection
            include_slither: Include Slither analysis
            include_mythril: Include Mythril analysis (slow)
            
        Returns:
            UnifiedResult with all findings
        """
        path = Path(contract_path)
        if not path.exists():
            raise FileNotFoundError(f"Contract not found: {contract_path}")
        
        start_time = time.time()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        result = UnifiedResult(
            contract_path=str(path.absolute()),
            contract_name=path.name,
            timestamp=timestamp,
            total_duration=0,
        )
        
        # Read source for feature extraction
        with open(path, 'r') as f:
            source_code = f.read()
        
        # Extract features
        features = self.feature_extractor.extract_from_source(source_code)
        result.features = {
            "num_functions": features.num_functions,
            "num_external_calls": features.num_external_calls,
            "num_low_level_calls": features.num_low_level_calls,
            "state_write_after_call": features.state_write_after_call,
            "has_reentrancy_guard": features.has_reentrancy_guard,
            "has_erc777": features.has_erc777_interaction,
            "has_flash_loan": features.has_flash_loan_callback,
            "risk_indicators": features.vulnerability_indicators,
        }
        result.risk_score = features.risk_score
        
        # Define analysis tasks
        tasks = []
        
        # Custom detectors (always run)
        tasks.append(("Custom Detectors", self._run_custom_detectors, {"path": path}))
        
        # ML detector
        if include_ml:
            tasks.append(("ML Analysis", self._run_ml_detector, {"path": path}))
        
        # Slither
        if include_slither:
            tasks.append(("Slither", self._run_slither, {"path": path}))
        
        # Mythril (optional, slow)
        if include_mythril:
            tasks.append(("Mythril", self._run_mythril, {"path": path}))
        
        # Run all tasks with progress
        if self.verbose:
            self._print_header(path.name)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            ) as progress:
                task_id = progress.add_task("Running analysis...", total=len(tasks))
                
                for task_name, task_func, task_args in tasks:
                    progress.update(task_id, description=f"Running {task_name}...")
                    tool_result = task_func(**task_args)
                    result.tool_results[task_name] = tool_result
                    result.all_vulnerabilities.extend(tool_result.vulnerabilities)
                    progress.advance(task_id)
        else:
            for task_name, task_func, task_args in tasks:
                tool_result = task_func(**task_args)
                result.tool_results[task_name] = tool_result
                result.all_vulnerabilities.extend(tool_result.vulnerabilities)
        
        # Deduplicate and sort findings
        result.unique_vulnerabilities = self._deduplicate_findings(result.all_vulnerabilities)
        result.unique_vulnerabilities = self._sort_by_severity(result.unique_vulnerabilities)
        
        # Count by severity
        for vuln in result.unique_vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity == "critical":
                result.critical_count += 1
            elif severity == "high":
                result.high_count += 1
            elif severity == "medium":
                result.medium_count += 1
            elif severity == "low":
                result.low_count += 1
            else:
                result.info_count += 1
        
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)
        
        result.total_duration = time.time() - start_time
        
        return result
    
    def _run_custom_detectors(self, path: Path) -> ToolResult:
        """Run custom reentrancy detectors."""
        start = time.time()
        vulnerabilities = []
        
        try:
            config = ReGuardianConfig(mode=AnalysisMode.QUICK)
            rg = ReGuardian(config)
            analysis_result = rg.analyze(str(path))
            
            for vuln in analysis_result.vulnerabilities:
                vulnerabilities.append({
                    "tool": "Custom",
                    "title": vuln.title,
                    "type": vuln.type.value,
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "description": vuln.description,
                    "attack_vector": vuln.attack_vector,
                    "recommendation": vuln.recommendation,
                    "suggested_fix": vuln.suggested_fix,
                    "function": vuln.location.function_name,
                    "lines": f"{vuln.location.line_start}-{vuln.location.line_end}",
                    "references": vuln.references,
                })
            
            return ToolResult(
                tool_name="Custom Detectors",
                success=True,
                duration=time.time() - start,
                vulnerabilities=vulnerabilities,
            )
        except Exception as e:
            return ToolResult(
                tool_name="Custom Detectors",
                success=False,
                duration=time.time() - start,
                error=str(e),
            )
    
    def _run_ml_detector(self, path: Path) -> ToolResult:
        """Run ML-based detector."""
        start = time.time()
        vulnerabilities = []
        
        try:
            detector = MLReentrancyDetector()
            vulns = detector.analyze(path)
            
            for vuln in vulns:
                vulnerabilities.append({
                    "tool": "ML",
                    "title": vuln.title,
                    "type": vuln.type.value,
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "description": vuln.description,
                    "attack_vector": vuln.attack_vector,
                    "recommendation": vuln.recommendation,
                    "suggested_fix": vuln.suggested_fix,
                    "function": vuln.location.function_name,
                    "lines": f"{vuln.location.line_start}-{vuln.location.line_end}",
                    "references": vuln.references,
                })
            
            return ToolResult(
                tool_name="ML Analysis",
                success=True,
                duration=time.time() - start,
                vulnerabilities=vulnerabilities,
            )
        except Exception as e:
            return ToolResult(
                tool_name="ML Analysis",
                success=False,
                duration=time.time() - start,
                error=str(e),
            )
    
    def _run_slither(self, path: Path) -> ToolResult:
        """Run Slither analysis."""
        start = time.time()
        vulnerabilities = []
        
        try:
            from .analyzers.slither_analyzer import SlitherAnalyzer
            
            analyzer = SlitherAnalyzer()
            vulns = analyzer.analyze(path, reentrancy_only=True)
            
            for vuln in vulns:
                vulnerabilities.append({
                    "tool": "Slither",
                    "title": vuln.title,
                    "type": vuln.type.value,
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "description": vuln.description,
                    "attack_vector": vuln.attack_vector,
                    "recommendation": vuln.recommendation,
                    "suggested_fix": vuln.suggested_fix,
                    "function": vuln.location.function_name,
                    "lines": f"{vuln.location.line_start}-{vuln.location.line_end}",
                    "references": vuln.references,
                })
            
            return ToolResult(
                tool_name="Slither",
                success=True,
                duration=time.time() - start,
                vulnerabilities=vulnerabilities,
            )
        except Exception as e:
            return ToolResult(
                tool_name="Slither",
                success=False,
                duration=time.time() - start,
                error=str(e),
            )
    
    def _run_mythril(self, path: Path) -> ToolResult:
        """Run Mythril analysis."""
        start = time.time()
        vulnerabilities = []
        
        try:
            from .analyzers.mythril_analyzer import MythrilAnalyzer
            
            analyzer = MythrilAnalyzer()
            vulns = analyzer.analyze(path, reentrancy_only=True)
            
            for vuln in vulns:
                vulnerabilities.append({
                    "tool": "Mythril",
                    "title": vuln.title,
                    "type": vuln.type.value,
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "description": vuln.description,
                    "attack_vector": vuln.attack_vector,
                    "recommendation": vuln.recommendation,
                    "suggested_fix": vuln.suggested_fix,
                    "function": vuln.location.function_name,
                    "lines": f"{vuln.location.line_start}-{vuln.location.line_end}",
                    "references": vuln.references,
                })
            
            return ToolResult(
                tool_name="Mythril",
                success=True,
                duration=time.time() - start,
                vulnerabilities=vulnerabilities,
            )
        except Exception as e:
            return ToolResult(
                tool_name="Mythril",
                success=False,
                duration=time.time() - start,
                error=str(e),
            )
    
    def _deduplicate_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on location and type."""
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create key from function, lines, and type
            key = (
                vuln.get("function", ""),
                vuln.get("lines", ""),
                vuln.get("type", ""),
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
            else:
                # Merge tools that found the same issue
                for existing in unique:
                    existing_key = (
                        existing.get("function", ""),
                        existing.get("lines", ""),
                        existing.get("type", ""),
                    )
                    if existing_key == key:
                        existing_tools = existing.get("tool", "")
                        new_tool = vuln.get("tool", "")
                        if new_tool not in existing_tools:
                            existing["tool"] = f"{existing_tools}, {new_tool}"
                        break
        
        return unique
    
    def _sort_by_severity(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Sort vulnerabilities by severity (critical first)."""
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "informational": 4,
        }
        
        return sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "").lower(), 5)
        )
    
    def _generate_recommendations(self, result: UnifiedResult) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        # Check for missing reentrancy guard
        if not result.features.get("has_reentrancy_guard"):
            if result.features.get("num_external_calls", 0) > 0:
                recommendations.append(
                    "🛡️ **Add ReentrancyGuard**: Import and use OpenZeppelin's ReentrancyGuard "
                    "with the `nonReentrant` modifier on all state-changing external functions."
                )
        
        # Check for state write after call
        if result.features.get("state_write_after_call", 0) > 0:
            recommendations.append(
                "⚠️ **Fix CEI Pattern**: State modifications detected after external calls. "
                "Refactor to follow Checks-Effects-Interactions pattern."
            )
        
        # ERC777 warning
        if result.features.get("has_erc777"):
            recommendations.append(
                "🔔 **ERC777 Caution**: Contract interacts with ERC777 tokens. "
                "Ensure all token-receiving functions have reentrancy protection."
            )
        
        # Flash loan warning
        if result.features.get("has_flash_loan"):
            recommendations.append(
                "⚡ **Flash Loan Protection**: Flash loan callbacks detected. "
                "Validate callback callers and use reentrancy guards."
            )
        
        # High severity findings
        if result.critical_count > 0 or result.high_count > 0:
            recommendations.append(
                "🚨 **Critical/High Issues**: Address critical and high severity "
                "findings immediately before deployment."
            )
        
        # General recommendation
        if not recommendations:
            if result.unique_vulnerabilities:
                recommendations.append(
                    "📋 **Review Findings**: Review the detected issues and apply "
                    "suggested fixes where applicable."
                )
            else:
                recommendations.append(
                    "✅ **Good Practices**: No major reentrancy issues detected. "
                    "Continue following security best practices."
                )
        
        return recommendations
    
    def _print_header(self, contract_name: str):
        """Print analysis header."""
        header = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    🛡️  ReGuardian Analysis                       ║
║                    Unified Security Scanner                      ║
╠══════════════════════════════════════════════════════════════════╣
║  Contract: {contract_name:<52} ║
╚══════════════════════════════════════════════════════════════════╝
"""
        console.print(header, style="cyan")
    
    def print_report(self, result: UnifiedResult):
        """
        Print a comprehensive, easy-to-read report.
        
        Args:
            result: UnifiedResult from run()
        """
        console.print()
        
        # ═══════════════════════════════════════════════════════════════
        # EXECUTIVE SUMMARY
        # ═══════════════════════════════════════════════════════════════
        
        total_vulns = len(result.unique_vulnerabilities)
        
        if total_vulns == 0:
            summary_style = "green"
            summary_icon = "✅"
            summary_text = "No reentrancy vulnerabilities detected!"
        elif result.critical_count > 0 or result.high_count > 0:
            summary_style = "red"
            summary_icon = "🚨"
            summary_text = f"Found {total_vulns} potential vulnerabilities"
        else:
            summary_style = "yellow"
            summary_icon = "⚠️"
            summary_text = f"Found {total_vulns} potential issues"
        
        console.print(Panel(
            f"[bold]{summary_icon} {summary_text}[/bold]",
            title="Executive Summary",
            border_style=summary_style,
        ))
        
        # ═══════════════════════════════════════════════════════════════
        # SEVERITY BREAKDOWN
        # ═══════════════════════════════════════════════════════════════
        
        severity_table = Table(title="Severity Breakdown", show_header=True)
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="center")
        severity_table.add_column("Status", justify="center")
        
        severity_table.add_row(
            "🔴 Critical", 
            str(result.critical_count),
            "⚠️ ACTION REQUIRED" if result.critical_count > 0 else "✅"
        )
        severity_table.add_row(
            "🟠 High",
            str(result.high_count),
            "⚠️ ACTION REQUIRED" if result.high_count > 0 else "✅"
        )
        severity_table.add_row(
            "🟡 Medium",
            str(result.medium_count),
            "Review recommended" if result.medium_count > 0 else "✅"
        )
        severity_table.add_row(
            "🔵 Low",
            str(result.low_count),
            "Consider fixing" if result.low_count > 0 else "✅"
        )
        severity_table.add_row(
            "⚪ Info",
            str(result.info_count),
            "For reference" if result.info_count > 0 else "✅"
        )
        
        console.print(severity_table)
        console.print()
        
        # ═══════════════════════════════════════════════════════════════
        # TOOL RESULTS
        # ═══════════════════════════════════════════════════════════════
        
        tools_table = Table(title="Analysis Tools", show_header=True)
        tools_table.add_column("Tool", style="cyan")
        tools_table.add_column("Status", justify="center")
        tools_table.add_column("Findings", justify="center")
        tools_table.add_column("Duration", justify="right")
        
        for tool_name, tool_result in result.tool_results.items():
            status = "✅ Success" if tool_result.success else f"❌ {tool_result.error[:20]}..."
            findings = str(len(tool_result.vulnerabilities))
            duration = f"{tool_result.duration:.2f}s"
            tools_table.add_row(tool_name, status, findings, duration)
        
        console.print(tools_table)
        console.print()
        
        # ═══════════════════════════════════════════════════════════════
        # RISK ASSESSMENT
        # ═══════════════════════════════════════════════════════════════
        
        risk_score = result.risk_score
        if risk_score < 0.3:
            risk_level = "LOW"
            risk_color = "green"
            risk_bar = "█" * 3 + "░" * 7
        elif risk_score < 0.6:
            risk_level = "MEDIUM"
            risk_color = "yellow"
            risk_bar = "█" * 6 + "░" * 4
        else:
            risk_level = "HIGH"
            risk_color = "red"
            risk_bar = "█" * 9 + "░" * 1
        
        risk_panel = f"""
[bold]Risk Level:[/bold] [{risk_color}]{risk_level}[/{risk_color}]
[bold]Risk Score:[/bold] [{risk_color}]{risk_bar}[/{risk_color}] {risk_score:.0%}

[bold]Key Indicators:[/bold]
  • External Calls: {result.features.get('num_external_calls', 0)}
  • Low-Level Calls: {result.features.get('num_low_level_calls', 0)}
  • State Write After Call: {result.features.get('state_write_after_call', 0)}
  • Has ReentrancyGuard: {'✅ Yes' if result.features.get('has_reentrancy_guard') else '❌ No'}
  • ERC777 Interaction: {'⚠️ Yes' if result.features.get('has_erc777') else '✅ No'}
  • Flash Loan Callback: {'⚠️ Yes' if result.features.get('has_flash_loan') else '✅ No'}
"""
        console.print(Panel(risk_panel, title="Risk Assessment", border_style=risk_color))
        console.print()
        
        # ═══════════════════════════════════════════════════════════════
        # DETAILED FINDINGS
        # ═══════════════════════════════════════════════════════════════
        
        if result.unique_vulnerabilities:
            console.print(Panel("[bold]Detailed Findings[/bold]", border_style="blue"))
            
            for i, vuln in enumerate(result.unique_vulnerabilities, 1):
                severity = vuln.get("severity", "unknown").upper()
                severity_colors = {
                    "CRITICAL": "red bold",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                }
                color = severity_colors.get(severity, "white")
                
                # Finding header
                console.print(f"\n[{color}]{'═' * 70}[/{color}]")
                console.print(f"[{color}]Finding #{i}: {vuln.get('title', 'Unknown')}[/{color}]")
                console.print(f"[{color}]{'═' * 70}[/{color}]")
                
                # Metadata
                console.print(f"[bold]Severity:[/bold]    [{color}]{severity}[/{color}]")
                console.print(f"[bold]Type:[/bold]        {vuln.get('type', 'unknown')}")
                console.print(f"[bold]Confidence:[/bold]  {vuln.get('confidence', 0):.0%}")
                console.print(f"[bold]Function:[/bold]    {vuln.get('function', 'unknown')}")
                console.print(f"[bold]Lines:[/bold]       {vuln.get('lines', 'unknown')}")
                console.print(f"[bold]Found by:[/bold]    {vuln.get('tool', 'unknown')}")
                
                # Description
                console.print(f"\n[bold]Description:[/bold]")
                console.print(f"  {vuln.get('description', 'No description')[:500]}")
                
                # Attack vector
                if vuln.get('attack_vector'):
                    console.print(f"\n[bold]Attack Vector:[/bold]")
                    for line in vuln['attack_vector'].split('\n')[:5]:
                        console.print(f"  {line}")
                
                # Recommendation
                if vuln.get('recommendation'):
                    console.print(f"\n[bold]Recommendation:[/bold]")
                    console.print(f"  {vuln.get('recommendation', '')[:300]}")
                
                # Suggested fix (collapsed)
                if vuln.get('suggested_fix'):
                    console.print(f"\n[bold]Suggested Fix:[/bold]")
                    console.print(Syntax(
                        vuln['suggested_fix'][:500], 
                        "solidity", 
                        theme="monokai",
                        line_numbers=False
                    ))
        
        # ═══════════════════════════════════════════════════════════════
        # RECOMMENDATIONS
        # ═══════════════════════════════════════════════════════════════
        
        console.print()
        recommendations_text = "\n".join(f"  {r}" for r in result.recommendations)
        console.print(Panel(
            recommendations_text,
            title="📋 Recommendations",
            border_style="cyan"
        ))
        
        # ═══════════════════════════════════════════════════════════════
        # FOOTER
        # ═══════════════════════════════════════════════════════════════
        
        console.print()
        console.print(f"[dim]Analysis completed in {result.total_duration:.2f}s[/dim]")
        console.print(f"[dim]Report generated: {result.timestamp}[/dim]")
        console.print(f"[dim]Contract: {result.contract_path}[/dim]")
        console.print()
    
    def export_json(self, result: UnifiedResult, output_path: str):
        """Export results to JSON file."""
        data = {
            "contract": result.contract_name,
            "path": result.contract_path,
            "timestamp": result.timestamp,
            "duration": result.total_duration,
            "summary": {
                "total": len(result.unique_vulnerabilities),
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "info": result.info_count,
            },
            "risk_score": result.risk_score,
            "features": result.features,
            "tools": {
                name: {
                    "success": tr.success,
                    "duration": tr.duration,
                    "findings": len(tr.vulnerabilities),
                    "error": tr.error,
                }
                for name, tr in result.tool_results.items()
            },
            "vulnerabilities": result.unique_vulnerabilities,
            "recommendations": result.recommendations,
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        console.print(f"[green]Results exported to {output_path}[/green]")
    
    def export_html(self, result: UnifiedResult, output_path: str):
        """Export results to HTML report."""
        # Generate HTML (simplified version)
        html = self._generate_html_report(result)
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        console.print(f"[green]HTML report exported to {output_path}[/green]")
    
    def _generate_html_report(self, result: UnifiedResult) -> str:
        """Generate HTML report."""
        vuln_rows = ""
        for vuln in result.unique_vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            vuln_rows += f"""
            <tr class="{severity}">
                <td><span class="severity {severity}">{severity.upper()}</span></td>
                <td>{vuln.get('title', 'Unknown')}</td>
                <td>{vuln.get('type', 'unknown')}</td>
                <td>{vuln.get('function', 'unknown')}</td>
                <td>{vuln.get('tool', 'unknown')}</td>
            </tr>
            """
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ReGuardian Security Report - {result.contract_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; text-align: center; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; }}
        .critical .stat-value {{ color: #ff4757; }}
        .high .stat-value {{ color: #ff6b6b; }}
        .medium .stat-value {{ color: #ffa502; }}
        .low .stat-value {{ color: #70a1ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; }}
        .severity {{ padding: 5px 15px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }}
        .severity.critical {{ background: #ff4757; }}
        .severity.high {{ background: #ff6b6b; }}
        .severity.medium {{ background: #ffa502; color: #000; }}
        .severity.low {{ background: #70a1ff; }}
        .risk-bar {{ background: #333; border-radius: 10px; height: 20px; overflow: hidden; }}
        .risk-fill {{ height: 100%; background: linear-gradient(90deg, #2ed573, #ffa502, #ff4757); }}
        footer {{ text-align: center; padding: 40px; opacity: 0.5; }}
    </style>
</head>
<body>
    <header>
        <h1>🛡️ ReGuardian Security Report</h1>
        <p>{result.contract_name}</p>
    </header>
    
    <div class="container">
        <div class="summary">
            <div class="stat">
                <div class="stat-value">{len(result.unique_vulnerabilities)}</div>
                <div>Total Issues</div>
            </div>
            <div class="stat critical">
                <div class="stat-value">{result.critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-value">{result.high_count}</div>
                <div>High</div>
            </div>
            <div class="stat medium">
                <div class="stat-value">{result.medium_count}</div>
                <div>Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-value">{result.low_count}</div>
                <div>Low</div>
            </div>
        </div>
        
        <h2>Risk Score</h2>
        <div class="risk-bar">
            <div class="risk-fill" style="width: {result.risk_score * 100}%"></div>
        </div>
        <p style="text-align: center; margin: 10px 0;">{result.risk_score:.0%}</p>
        
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Type</th>
                    <th>Function</th>
                    <th>Tool</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows}
            </tbody>
        </table>
        
        <h2>Recommendations</h2>
        <ul>
            {"".join(f"<li>{r}</li>" for r in result.recommendations)}
        </ul>
    </div>
    
    <footer>
        <p>Generated by ReGuardian v0.1.0 | {result.timestamp}</p>
        <p>Analysis completed in {result.total_duration:.2f}s</p>
    </footer>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTION - Single call to run everything
# ═══════════════════════════════════════════════════════════════════════════

def scan(
    contract_path: str,
    output_json: Optional[str] = None,
    output_html: Optional[str] = None,
    include_mythril: bool = False,
    verbose: bool = True,
) -> UnifiedResult:
    """
    One-liner to scan a contract with all tools.
    
    Usage:
        from src.runner import scan
        result = scan("contract.sol")
        
        # Or with exports
        scan("contract.sol", output_json="results.json", output_html="report.html")
    
    Args:
        contract_path: Path to contract file
        output_json: Optional JSON output path
        output_html: Optional HTML output path
        include_mythril: Include slow Mythril analysis
        verbose: Show progress
        
    Returns:
        UnifiedResult with all findings
    """
    runner = ReGuardianRunner(verbose=verbose)
    result = runner.run(contract_path, include_mythril=include_mythril)
    runner.print_report(result)
    
    if output_json:
        runner.export_json(result, output_json)
    
    if output_html:
        runner.export_html(result, output_html)
    
    return result
