"""
Command Line Interface for Secomp using Click and Rich.
"""
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

from .scanner import create_scanner, create_azure_scanner, create_gcp_scanner
from .models import ComplianceReport, ScanConfig

# Legacy Windows consoles default to cp1252, which cannot render the emoji
# used in the output; fall back to replacement characters instead of crashing.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, 'reconfigure'):
        try:
            _stream.reconfigure(errors='replace')
        except (OSError, ValueError):
            pass

console = Console()
logger = logging.getLogger(__name__)

# Frameworks with implemented rule engines
IMPLEMENTED_FRAMEWORKS = {'gdpr'}


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Secomp - CLI for compliance and risk assessment in multi-cloud environments.

    Secomp scans your cloud resources for compliance violations and security risks,
    providing actionable insights to strengthen your security posture.

    Examples:

        secomp scan --cloud aws --compliance gdpr --output report.json

        secomp scan --cloud aws --compliance gdpr --debug

        secomp scan --help
    """
    pass


def _run_scan(cloud: str, region: str, debug: bool):
    """Create the right scanner and return findings for the given cloud."""
    scanners = {
        'aws': lambda: (create_scanner(region=region, debug=debug), 'scan_s3_buckets'),
        'azure': lambda: (create_azure_scanner(resource_group=region, debug=debug), 'scan_blob_containers'),
        'gcp': lambda: (create_gcp_scanner(project_id=region, debug=debug), 'scan_storage_buckets'),
    }

    scanner, method_name = scanners[cloud]()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {cloud.upper()} resources...", total=1)
        findings = getattr(scanner, method_name)()
        progress.update(task, completed=1)

    return findings


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

    3. Calculate risk scores

    4. Generate detailed reports with remediation steps

    For AWS, ensure your credentials are configured:

        export AWS_ACCESS_KEY_ID=your_key

        export AWS_SECRET_ACCESS_KEY=your_secret

        # Or use AWS CLI: aws configure

    For Azure, set up your credentials:

        export AZURE_STORAGE_ACCOUNT_URL=https://youraccount.blob.core.windows.net

        # Or: export AZURE_STORAGE_CONNECTION_STRING=your_connection_string

    For GCP, authenticate with:

        export GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

        # Or use: gcloud auth application-default login
    """
    logging.basicConfig(level=logging.DEBUG if debug else logging.WARNING)

    if compliance not in IMPLEMENTED_FRAMEWORKS:
        console.print(
            f"[red]❌ Compliance framework '{compliance}' is not implemented yet. "
            f"Available: {', '.join(sorted(IMPLEMENTED_FRAMEWORKS))}[/red]"
        )
        sys.exit(2)

    try:
        config = ScanConfig(
            cloud_provider=cloud,
            compliance_framework=compliance,
            regions=[region],
            debug=debug
        )

        if debug:
            console.print(Panel.fit(
                "[bold blue]🔍 Debug Mode Enabled[/bold blue]\n"
                f"Configuration: {config.model_dump()}",
                title="Secomp Debug"
            ))

        scan_start = time.monotonic()
        findings = _run_scan(cloud, region, debug)
        scan_duration = time.monotonic() - scan_start

        total_resources = len(findings)
        compliant_resources = len([f for f in findings if f.compliance_status.value == 'compliant'])
        non_compliant_resources = total_resources - compliant_resources

        if findings:
            overall_risk_score = sum(f.risk_score for f in findings) // len(findings)
        else:
            overall_risk_score = 0

        report = ComplianceReport(
            scan_id=f"secomp-{cloud}-{compliance}-{int(time.time())}",
            cloud_provider=cloud,
            compliance_framework=compliance,
            total_resources=total_resources,
            compliant_resources=compliant_resources,
            non_compliant_resources=non_compliant_resources,
            overall_risk_score=overall_risk_score,
            findings=findings,
            summary={
                "scan_duration_seconds": round(scan_duration, 2),
                "resources_per_second": round(total_resources / scan_duration, 2) if scan_duration > 0 else 0,
            }
        )

        # Display results
        if output_format == 'table':
            display_table_report(report, debug)
        else:
            console.print(report.model_dump_json(indent=2))

        # Save to file if requested
        if output:
            save_report_to_file(report, output)

        display_next_steps(compliance, non_compliant_resources)

    except Exception as e:
        if debug:
            console.print_exception()
        else:
            console.print(f"[red]❌ Error: {str(e)}[/red]")
            console.print("[yellow]💡 Try --debug for detailed error information[/yellow]")
        sys.exit(1)


def display_table_report(report: ComplianceReport, debug: bool):
    """Display scan results in a table format."""
    risk_color = 'red' if report.overall_risk_score > 60 else 'yellow' if report.overall_risk_score > 30 else 'green'

    console.print()
    console.print(Panel.fit(
        f"[bold green]Secomp Compliance Report[/bold green]\n"
        f"Cloud: {report.cloud_provider.upper()} | Framework: {report.compliance_framework.upper()}\n"
        f"Risk Score: [bold {risk_color}]{report.overall_risk_score}/100[/]",
        title="📊 Scan Results"
    ))

    summary_table = Table(title="📈 Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Total Resources", str(report.total_resources))
    summary_table.add_row("✅ Compliant", str(report.compliant_resources))
    summary_table.add_row("❌ Non-Compliant", str(report.non_compliant_resources))
    summary_table.add_row("🔍 Overall Risk", f"{report.overall_risk_score}/100")

    console.print(summary_table)
    console.print()

    if not report.findings:
        console.print("[yellow]⚠️  No resources found to scan[/yellow]")
        return

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

    recommendations = []
    for finding in report.findings:
        recommendations.extend(finding.recommendations)

    if recommendations:
        console.print()
        console.print(Panel.fit(
            "\n".join(dict.fromkeys(recommendations)),  # Remove duplicates, keep order
            title="💡 Security Recommendations"
        ))


def save_report_to_file(report: ComplianceReport, output_file: str):
    """Save report to JSON file."""
    try:
        output_path = Path(output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report.model_dump(mode='json'), f, indent=2)
        console.print(f"[green]✅ Report saved to {output_file}[/green]")
    except OSError as e:
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
