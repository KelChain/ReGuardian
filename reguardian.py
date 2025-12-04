#!/usr/bin/env python3
"""
ReGuardian CLI

Command-line interface for ReGuardian reentrancy vulnerability detection.

Usage:
    python reguardian.py analyze <contract_path>
    python reguardian.py analyze <contract_path> --mode deep
    python reguardian.py report <contract_path> --output report.html
    python reguardian.py scan <project_path>
"""

import sys
import json
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.core.reguardian import ReGuardian, ReGuardianConfig, AnalysisMode
from src.detectors.reentrancy.base import Severity


console = Console()


def severity_color(severity: Severity) -> str:
    """Get color for severity level."""
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFORMATIONAL: "dim",
    }
    return colors.get(severity, "white")


def print_banner():
    """Print ReGuardian banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗   ║
║   ██╔══██╗██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗  ║
║   ██████╔╝█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║  ║
║   ██╔══██╗██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║  ║
║   ██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝  ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝   ║
║                                                               ║
║          AI-Powered Reentrancy Vulnerability Detection        ║
║                         v0.1.0                                ║
╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="cyan")


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """ReGuardian - Smart Contract Reentrancy Detection Tool"""
    pass


@cli.command()
@click.argument('contract_path', type=click.Path(exists=True))
@click.option('--mode', '-m', type=click.Choice(['quick', 'standard', 'deep', 'full']),
              default='standard', help='Analysis depth mode')
@click.option('--min-severity', '-s', type=click.Choice(['low', 'medium', 'high', 'critical']),
              default='low', help='Minimum severity to report')
@click.option('--json-output', '-j', is_flag=True, help='Output results as JSON')
@click.option('--no-fixes', is_flag=True, help='Skip fix suggestions')
def analyze(contract_path, mode, min_severity, json_output, no_fixes):
    """Analyze a smart contract for reentrancy vulnerabilities."""
    
    if not json_output:
        print_banner()
        console.print(f"\n[bold]Analyzing:[/bold] {contract_path}")
        console.print(f"[bold]Mode:[/bold] {mode}\n")
    
    # Configure analysis
    severity_map = {
        'low': Severity.LOW,
        'medium': Severity.MEDIUM,
        'high': Severity.HIGH,
        'critical': Severity.CRITICAL,
    }
    
    mode_map = {
        'quick': AnalysisMode.QUICK,
        'standard': AnalysisMode.STANDARD,
        'deep': AnalysisMode.DEEP,
        'full': AnalysisMode.FULL,
    }
    
    config = ReGuardianConfig(
        mode=mode_map[mode],
        min_severity=severity_map[min_severity],
        generate_fixes=not no_fixes,
    )
    
    # Run analysis
    rg = ReGuardian(config)
    
    with console.status("[bold green]Analyzing contract...") as status:
        try:
            result = rg.analyze(contract_path)
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    # Output results
    if json_output:
        output = {
            "contract": result.contract_path,
            "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
            "summary": rg.get_summary(result),
            "warnings": result.warnings,
        }
        print(json.dumps(output, indent=2))
        return
    
    # Rich console output
    if not result.has_vulnerabilities:
        console.print(Panel(
            "[green]✓ No reentrancy vulnerabilities detected![/green]",
            title="Analysis Complete",
            border_style="green",
        ))
    else:
        # Summary table
        summary = rg.get_summary(result)
        
        summary_table = Table(title="Analysis Summary", show_header=False)
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value")
        
        summary_table.add_row("Total Vulnerabilities", str(summary['total_vulnerabilities']))
        summary_table.add_row("Critical", f"[red]{summary['critical']}[/red]")
        summary_table.add_row("High", f"[red]{summary['high']}[/red]")
        summary_table.add_row("Medium", f"[yellow]{summary['medium']}[/yellow]")
        summary_table.add_row("Low", f"[blue]{summary['low']}[/blue]")
        summary_table.add_row("Analysis Time", summary['analysis_time'])
        
        console.print(summary_table)
        console.print()
        
        # Detailed findings
        for i, vuln in enumerate(result.vulnerabilities, 1):
            color = severity_color(vuln.severity)
            
            console.print(Panel(
                f"[{color}]{vuln.severity.value.upper()}[/{color}] - {vuln.title}",
                title=f"Finding #{i}",
                border_style=color.split()[0],
            ))
            
            console.print(f"[bold]Type:[/bold] {vuln.type.value}")
            console.print(f"[bold]Location:[/bold] {vuln.location.file_path}")
            console.print(f"[bold]Function:[/bold] {vuln.location.function_name}")
            console.print(f"[bold]Lines:[/bold] {vuln.location.line_start}-{vuln.location.line_end}")
            console.print(f"[bold]Confidence:[/bold] {vuln.confidence:.0%}")
            console.print()
            
            console.print("[bold]Description:[/bold]")
            console.print(vuln.description)
            console.print()
            
            console.print("[bold]Attack Vector:[/bold]")
            console.print(vuln.attack_vector)
            console.print()
            
            console.print("[bold]Recommendation:[/bold]")
            console.print(vuln.recommendation)
            console.print()
            
            if vuln.suggested_fix and not no_fixes:
                console.print("[bold]Suggested Fix:[/bold]")
                console.print(Syntax(vuln.suggested_fix, "solidity", theme="monokai"))
            
            if vuln.references:
                console.print("[bold]References:[/bold]")
                for ref in vuln.references:
                    console.print(f"  • {ref}")
            
            console.print()
    
    # Warnings
    if result.warnings:
        console.print("[yellow]Warnings:[/yellow]")
        for warning in result.warnings:
            console.print(f"  ⚠ {warning}")


@cli.command()
@click.argument('project_path', type=click.Path(exists=True))
@click.option('--mode', '-m', type=click.Choice(['quick', 'standard', 'deep']),
              default='standard', help='Analysis depth mode')
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
def scan(project_path, mode, output):
    """Scan an entire project for reentrancy vulnerabilities."""
    
    print_banner()
    console.print(f"\n[bold]Scanning project:[/bold] {project_path}")
    console.print(f"[bold]Mode:[/bold] {mode}\n")
    
    mode_map = {
        'quick': AnalysisMode.QUICK,
        'standard': AnalysisMode.STANDARD,
        'deep': AnalysisMode.DEEP,
    }
    
    config = ReGuardianConfig(mode=mode_map[mode])
    rg = ReGuardian(config)
    
    with console.status("[bold green]Scanning project...") as status:
        results = rg.analyze_project(project_path)
    
    if not results:
        console.print(Panel(
            "[green]✓ No reentrancy vulnerabilities found in project![/green]",
            title="Scan Complete",
            border_style="green",
        ))
        return
    
    # Summary
    total_vulns = sum(len(r.vulnerabilities) for r in results.values())
    
    table = Table(title=f"Project Scan Results - {total_vulns} Vulnerabilities Found")
    table.add_column("Contract", style="cyan")
    table.add_column("Critical", style="red")
    table.add_column("High", style="red")
    table.add_column("Medium", style="yellow")
    table.add_column("Low", style="blue")
    
    for contract_path, result in results.items():
        summary = rg.get_summary(result)
        table.add_row(
            Path(contract_path).name,
            str(summary['critical']),
            str(summary['high']),
            str(summary['medium']),
            str(summary['low']),
        )
    
    console.print(table)
    
    if output:
        output_data = {
            contract: {
                "vulnerabilities": [v.to_dict() for v in result.vulnerabilities],
                "summary": rg.get_summary(result),
            }
            for contract, result in results.items()
        }
        
        with open(output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        console.print(f"\n[green]Results saved to {output}[/green]")


@cli.command()
@click.argument('contract_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), default='report.html',
              help='Output file for HTML report')
def report(contract_path, output):
    """Generate an HTML report for a contract analysis."""
    
    print_banner()
    console.print(f"\n[bold]Generating report for:[/bold] {contract_path}")
    
    config = ReGuardianConfig(mode=AnalysisMode.STANDARD)
    rg = ReGuardian(config)
    
    with console.status("[bold green]Analyzing and generating report..."):
        result = rg.analyze(contract_path)
        summary = rg.get_summary(result)
    
    # Generate HTML report
    html = generate_html_report(result, summary)
    
    with open(output, 'w') as f:
        f.write(html)
    
    console.print(f"\n[green]✓ Report generated: {output}[/green]")


def generate_html_report(result, summary) -> str:
    """Generate HTML report from analysis results."""
    
    vuln_rows = ""
    for vuln in result.vulnerabilities:
        severity_class = vuln.severity.value.lower()
        vuln_rows += f"""
        <tr class="{severity_class}">
            <td><span class="severity {severity_class}">{vuln.severity.value.upper()}</span></td>
            <td>{vuln.title}</td>
            <td>{vuln.type.value}</td>
            <td>{vuln.location.function_name}</td>
            <td>{vuln.location.line_start}</td>
        </tr>
        """
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReGuardian Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; text-align: center; }}
        h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .subtitle {{ opacity: 0.8; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ opacity: 0.7; margin-top: 5px; }}
        .critical .stat-value {{ color: #ff4757; }}
        .high .stat-value {{ color: #ff6b6b; }}
        .medium .stat-value {{ color: #ffa502; }}
        .low .stat-value {{ color: #70a1ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; }}
        .severity {{ padding: 5px 10px; border-radius: 5px; font-size: 0.8em; font-weight: bold; }}
        .severity.critical {{ background: #ff4757; }}
        .severity.high {{ background: #ff6b6b; }}
        .severity.medium {{ background: #ffa502; color: #000; }}
        .severity.low {{ background: #70a1ff; }}
        .finding {{ background: #16213e; padding: 20px; border-radius: 10px; margin: 20px 0; }}
        .finding h3 {{ margin-bottom: 15px; }}
        .finding-meta {{ display: flex; gap: 20px; margin-bottom: 15px; opacity: 0.7; }}
        pre {{ background: #0f0f23; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        footer {{ text-align: center; padding: 40px; opacity: 0.5; }}
    </style>
</head>
<body>
    <header>
        <h1>🛡️ ReGuardian Security Report</h1>
        <p class="subtitle">Reentrancy Vulnerability Analysis</p>
    </header>
    
    <div class="container">
        <h2>Contract: {result.contract_path}</h2>
        <p>Analysis completed in {summary['analysis_time']}</p>
        
        <div class="summary">
            <div class="stat">
                <div class="stat-value">{summary['total_vulnerabilities']}</div>
                <div class="stat-label">Total Issues</div>
            </div>
            <div class="stat critical">
                <div class="stat-value">{summary['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-value">{summary['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat medium">
                <div class="stat-value">{summary['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-value">{summary['low']}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Type</th>
                    <th>Function</th>
                    <th>Line</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows}
            </tbody>
        </table>
        
        <h2>Detailed Findings</h2>
        {"".join(f'''
        <div class="finding">
            <h3><span class="severity {v.severity.value.lower()}">{v.severity.value.upper()}</span> {v.title}</h3>
            <div class="finding-meta">
                <span>Type: {v.type.value}</span>
                <span>Function: {v.location.function_name}</span>
                <span>Lines: {v.location.line_start}-{v.location.line_end}</span>
            </div>
            <p><strong>Description:</strong> {v.description}</p>
            <p><strong>Attack Vector:</strong></p>
            <pre>{v.attack_vector}</pre>
            <p><strong>Recommendation:</strong> {v.recommendation}</p>
        </div>
        ''' for v in result.vulnerabilities)}
    </div>
    
    <footer>
        <p>Generated by ReGuardian v0.1.0</p>
    </footer>
</body>
</html>
    """
    
    return html


if __name__ == '__main__':
    cli()
