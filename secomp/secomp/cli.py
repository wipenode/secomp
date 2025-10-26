"""
Command Line Interface for Secomp using Click and Rich.
"""
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns

try:
    # Try relative import first (when used as module)
    from .scanner import create_scanner, create_azure_scanner, create_gcp_scanner
    from .models import ComplianceReport, ScanConfig
    from .compliance import load_rego_policy
except ImportError:
    # Fall back to absolute import (when run directly)
    from scanner import create_scanner, create_azure_scanner, create_gcp_scanner
    from models import ComplianceReport, ScanConfig
    from compliance import load_rego_policy

# Initialize Rich console
console = Console()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Secomp - Revolutionary CLI for compliance and risk assessment in multi-cloud environments.

    Secomp scans your cloud resources for compliance violations and security risks,
    providing actionable insights to strengthen your security posture.

    Examples:

        secomp scan --cloud aws --compliance gdpr --output report.json

        secomp scan --cloud aws --compliance gdpr --debug

        secomp scan --help
    """
    pass


@cli.command()
@click.option('--cloud', required=True, type=click.Choice(['aws', 'azure', 'gcp']),
              help='Cloud provider to scan')
@click.option('--compliance', required=True, type=click.Choice(['gdpr', 'nis2', 'soc2']),
              help='Compliance framework to check')
@click.option('--region', default='us-east-1', help='Region/resource group/project ID to scan (default: us-east-1)')
@click.option('--output', help='Output file path for JSON report')
@click.option('--debug', is_flag=True, help='Enable debug mode with detailed output')
@click.option('--format', 'output_format', default='table', type=click.Choice(['table', 'json']),
              help='Output format (default: table)')
def scan(cloud: str, compliance: str, region: str, output: Optional[str],
         debug: bool, output_format: str):
    """Scan cloud resources for compliance violations and security risks.

    This command will:

    1. Connect to your cloud provider using configured credentials

    2. Scan resources for compliance violations

    3. Calculate risk scores using AI-driven analysis

    4. Generate detailed reports with remediation steps

    For AWS, ensure your credentials are configured:

        export AWS_ACCESS_KEY_ID=your_key

        export AWS_SECRET_ACCESS_KEY=your_secret

        # Or use AWS CLI: aws configure

    For Azure, set up your credentials:

        export AZURE_CLIENT_ID=your_client_id

        export AZURE_CLIENT_SECRET=your_client_secret

        export AZURE_TENANT_ID=your_tenant_id

    For GCP, authenticate with:

        export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

        # Or use: gcloud auth application-default login
    """
    try:
        # Create scan configuration
        config = ScanConfig(
            cloud_provider=cloud,
            compliance_framework=compliance,
            regions=[region],
            debug=debug
        )

        if debug:
            console.print(Panel.fit(
                "[bold blue]🔍 Debug Mode Enabled[/bold blue]\n"
                f"Configuration: {config.dict()}",
                title="Secomp Debug"
            ))

        # Show progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Initializing scanner...", total=1)
            progress.update(task, completed=1)

        # Create and run scanner
        if cloud.lower() == 'aws':
            scanner = create_scanner(region=region, debug=debug)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning AWS resources...", total=1)

                findings = scanner.scan_s3_buckets()
                progress.update(task, completed=1)

        elif cloud.lower() == 'azure':
            scanner = create_azure_scanner(resource_group=region, debug=debug)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning Azure resources...", total=1)

                findings = scanner.scan_blob_containers()
                progress.update(task, completed=1)

        elif cloud.lower() == 'gcp':
            scanner = create_gcp_scanner(project_id=region, debug=debug)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning GCP resources...", total=1)

                findings = scanner.scan_storage_buckets()
                progress.update(task, completed=1)

        else:
            console.print(f"[red]❌ Cloud provider '{cloud}' not supported[/red]")
            return

        # Generate compliance report
        total_resources = len(findings)
        compliant_resources = len([f for f in findings if f.compliance_status.value == 'compliant'])
        non_compliant_resources = total_resources - compliant_resources

        # Calculate overall risk score (weighted average)
        if findings:
            overall_risk_score = sum(f.risk_score for f in findings) // len(findings)
        else:
            overall_risk_score = 0

        report = ComplianceReport(
            scan_id=f"secomp-{cloud}-{compliance}-{int(__import__('time').time())}",
            cloud_provider=cloud,
            compliance_framework=compliance,
            total_resources=total_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
            overall_risk_score=overall_risk_score,
            findings=findings,
            summary={
                "scan_duration_seconds": 0,  # Placeholder
                "resources_per_second": 0,   # Placeholder
            }
        )

        # Display results
        if output_format == 'table':
            display_table_report(report, debug)
        else:
            display_json_report(report, output)

        # Save to file if requested
        if output:
            save_report_to_file(report, output)

        # Show next steps
        display_next_steps(compliance, non_compliant_resources)

    except Exception as e:
        if debug:
            console.print_exception()
        else:
            console.print(f"[red]❌ Error: {str(e)}[/red]")
            console.print("[yellow]💡 Try --debug for detailed error information[/yellow]")
        sys.exit(1)


def display_table_report(report: ComplianceReport, debug: bool):
    """Display scan results in a beautiful table format."""
    console.print()
    console.print(Panel.fit(
        f"[bold green]Secomp Compliance Report[/bold green]\n"
        f"Cloud: {report.cloud_provider.upper()} | Framework: {report.compliance_framework.upper()}\n"
        f"Risk Score: [bold {'red' if report.overall_risk_score > 60 else 'yellow' if report.overall_risk_score > 30 else 'green'}]{report.overall_risk_score}/100[/bold]",
        title="📊 Scan Results"
    ))

    # Summary statistics
    summary_table = Table(title="📈 Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Total Resources", str(report.total_resources))
    summary_table.add_row("✅ Compliant", str(report.compliant_resources))
    summary_table.add_row("❌ Non-Compliant", str(report.non_compliant_resources))
    summary_table.add_row("🔍 Overall Risk", f"{report.overall_risk_score}/100")

    console.print(summary_table)
    console.print()

    # Findings table
    if report.findings:
        findings_table = Table(title="🔍 Resource Findings")
        findings_table.add_column("Resource", style="cyan", no_wrap=True)
        findings_table.add_column("Status", style="white")
        findings_table.add_column("Risk Score", style="red")
        findings_table.add_column("Risk Level", style="yellow")
        findings_table.add_column("Issues", style="white")

        for finding in report.findings:
            issues = [rule.rule_name for rule in finding.rules_checked
                     if rule.status.value == 'non_compliant']

            findings_table.add_row(
                finding.resource_id,
                "✅ Compliant" if finding.compliance_status.value == 'compliant' else "❌ Non-Compliant",
                f"{finding.risk_score}/100",
                finding.risk_level.value.upper(),
                ", ".join(issues) if issues else "None"
            )

        console.print(findings_table)
    else:
        console.print("[yellow]⚠️  No resources found to scan[/yellow]")

    # Recommendations
    if report.findings:
        recommendations = []
        for finding in report.findings:
            if finding.recommendations:
                recommendations.extend(finding.recommendations)

        if recommendations:
            console.print()
            console.print(Panel.fit(
                "\n".join(set(recommendations)),  # Remove duplicates
                title="💡 Security Recommendations"
            ))


def display_json_report(report: ComplianceReport, output_file: Optional[str]):
    """Display or save JSON report."""
    json_output = report.json(indent=2)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(json_output)
        console.print(f"[green]✅ Report saved to {output_file}[/green]")
    else:
        console.print(json_output)


def save_report_to_file(report: ComplianceReport, output_file: str):
    """Save report to JSON file."""
    try:
        output_path = Path(output_file)
        with open(output_path, 'w') as f:
            json.dump(report.dict(), f, indent=2, default=str)
        console.print(f"[green]✅ Report saved to {output_file}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Failed to save report: {e}[/red]")


def display_next_steps(compliance: str, violations: int):
    """Display next steps and recommendations."""
    console.print()
    console.print(Panel.fit(
        "[bold]🚀 Next Steps[/bold]\n\n"
        f"• Review the {violations} non-compliant resources above\n"
        "• Implement the security recommendations provided\n"
        "• Run regular scans to monitor compliance posture\n"
        "• Consider automated remediation for critical issues\n\n"
        "[dim]💡 Pro tip: Use --debug for detailed scanning information[/dim]",
        title="What to do next?"
    ))


@cli.command()
def plugins():
    """List available plugins and their status."""
    console.print(Panel.fit(
        "[bold yellow]🔌 Plugin System[/bold yellow]\n\n"
        "Available plugins:\n"
        "• AWS S3 Scanner (built-in)\n"
        "• Azure Blob Storage Scanner (built-in)\n"
        "• GCP Cloud Storage Scanner (built-in)\n"
        "• GDPR Compliance Rules (built-in)\n\n"
        "Coming soon:\n"
        "• NIS2 Compliance Framework\n"
        "• SOC2 Compliance Framework\n"
        "• Open Policy Agent (OPA) Integration\n"
        "• Real-time monitoring mode\n\n"
        "[dim]Create your own plugins in the plugins/ directory![/dim]",
        title="Secomp Plugins"
    ))


if __name__ == "__main__":
    cli()
