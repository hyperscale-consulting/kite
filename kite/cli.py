"""Main CLI module for Kite."""

import yaml
from datetime import datetime
import os
import shutil
import logging

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

from kite.config import Config
from kite.check_themes import CHECK_THEMES, ALL_CHECKS
from kite.organizations import get_account_details
from kite.helpers import assume_organizational_role, get_prowler_output, assume_role
from kite.collect import collect_data
from kite.organizations import fetch_account_ids
from kite.data import save_collection_metadata, verify_collection_status
from kite.accessanalyzer import list_analyzers
from kite.s3 import get_buckets


logger = logging.getLogger(__name__)
console = Console()


def display_finding(finding: dict):
    """
    Display a finding in a consistent format.

    Args:
        finding: The finding dictionary to display.
    """
    status = finding["status"]
    check_name = finding["check_name"]

    if status == "FAIL":
        console.print(
            Panel(
                f"❌  {check_name} check failed.",
                title=f"{check_name} Check",
                border_style="red",
            )
        )
    elif status == "PASS":
        console.print(
            Panel(
                f"✅  {check_name} check passed.",
                title=f"{check_name} Check",
                border_style="green",
            )
        )
    elif status == "ERROR":
        console.print(
            Panel(
                f"⚠️  {check_name} check encountered an error.",
                title=f"{check_name} Check",
                border_style="yellow",
            )
        )


def display_theme_results(theme: str, findings: list):
    """
    Display results for a theme in a table format.

    Args:
        theme: The theme name
        findings: List of findings for the theme
    """
    table = Table(title=f"{theme} Results")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="white")

    for finding in findings:
        status_emoji = {
            "PASS": "✅",
            "FAIL": "❌",
            "ERROR": "⚠️",
        }.get(finding["status"], "❓")

        # Safely get the message from details, with a fallback if it doesn't exist
        details = finding.get("details", {})
        message = details.get("message", "No details provided")

        table.add_row(
            finding["check_name"],
            f"{status_emoji} {finding['status']}",
            message,
        )

    console.print(table)
    console.print()


def find_check_by_id(check_id: str):
    """Find a check function by its ID."""
    for check in ALL_CHECKS:
        if hasattr(check, "_CHECK_ID") and check._CHECK_ID == check_id:
            return check
    return None


@click.group()
@click.version_option()
def main():
    """Kite - AWS Security Assessment CLI."""
    pass


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
def start(config: str):
    """Start a security assessment using the specified config file."""
    config_data = Config.load(config)

    # Verify collection status
    verify_collection_status()

    # Format account IDs for display
    account_ids_str = (
        ", ".join(config_data.account_ids) if config_data.account_ids else "ALL"
    )

    console.print(
        Panel(
            f"Starting AWS security assessment\n"
            f"Management Account: {config_data.management_account_id}\n"
            f"Target Accounts: {account_ids_str}\n"
            f"Regions: {', '.join(config_data.active_regions)}\n"
            f"Role Name: {config_data.role_name}",
            title="Kite Assessment",
            border_style="blue",
        )
    )

    try:
        # Initialize results dictionary
        results = {
            "timestamp": datetime.now().isoformat(),
            "config_file": config,
            "themes": {},
        }

        # Run checks by theme
        for theme_name, theme_data in CHECK_THEMES.items():
            console.print(
                Panel(
                    theme_data["description"],
                    title=theme_name,
                    border_style="blue",
                )
            )

            theme_findings = []
            for check in theme_data["checks"]:
                finding = check()
                theme_findings.append(finding)
                display_finding(finding)

            results["themes"][theme_name] = theme_findings
            display_theme_results(theme_name, theme_findings)

        # Save results to file
        with open("kite-results.yaml", "w") as f:
            yaml.dump(results, f, default_flow_style=False)

        console.print(
            Panel(
                "Assessment results saved to kite-results.yaml",
                title="Results",
                border_style="blue",
            )
        )

    except Exception as e:
        logger.error("Error during assessment: %s", e, exc_info=True)
        raise click.ClickException(f"Error during assessment: {str(e)}")


@main.command()
def list_checks():
    """List all available security checks."""
    table = Table(title="Available Security Checks")
    table.add_column("Theme", style="yellow")
    table.add_column("Check ID", style="cyan")
    table.add_column("Check Name", style="green")

    for theme in CHECK_THEMES:

        for check in CHECK_THEMES[theme]["checks"]:
            if hasattr(check, "_CHECK_ID") and hasattr(check, "_CHECK_NAME"):
                table.add_row(theme, check._CHECK_ID, check._CHECK_NAME)

    console.print(table)


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("check_id", required=True)
def run_check(config, check_id):
    """Run a specific security check by ID."""
    Config.load(config)

    # Verify collection status
    verify_collection_status()

    check = find_check_by_id(check_id)
    if not check:
        console.print(f"[red]Error: No check found with ID {check_id}[/red]")
        return

    console.print(f"\n[bold]Running check: {check._CHECK_NAME} ({check_id})[/bold]")
    result = check()

    # Display the result
    status_color = {"PASS": "green", "FAIL": "red", "ERROR": "yellow"}.get(
        result["status"], "white"
    )

    console.print(f"\nStatus: [{status_color}]{result['status']}[/{status_color}]")
    if "details" in result:
        console.print("\nDetails:")
        console.print(result["details"])


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("account_id", required=True)
def get_organization_account_details(account_id: str, config: str):
    """Get details about an account in the organization."""
    try:
        Config.load(config)
        session = assume_organizational_role()
        account = get_account_details(session, account_id)

        if not account:
            console.print(f"[red]Error: Account {account_id} not found in the organization[/red]")
            return

        # Create a table to display account details
        table = Table(title=f"Account Details for {account.name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Account ID", account.id)
        table.add_row("Name", account.name)
        table.add_row("Email", account.email)
        table.add_row("Status", account.status)
        table.add_row("Joined Method", account.joined_method)
        table.add_row("Joined Timestamp", account.joined_timestamp)

        # Add SCPs if any exist
        if account.scps:
            scp_names = "\n".join([scp.name for scp in account.scps])
            table.add_row("Service Control Policies", scp_names)

        console.print(table)

    except Exception as e:
        raise click.ClickException(f"Error fetching account details: {str(e)}")


@main.command()
def configure():
    """Configure the Kite CLI."""

    # Check if kite.yaml exists
    if os.path.exists("kite.yaml"):
        if not Confirm.ask("kite.yaml already exists. Overwrite?"):
            return

    # Ask the user for the management account ID, if they have one
    management_account_id = Prompt.ask(
        "Management Account ID",
        default="",
        show_default=False,
    ).strip()

    # Ask the user for the list of account IDs to include in the assessment
    while True:
        account_ids_input = Prompt.ask(
            "Account IDs (comma separated) - leave blank for all accounts in an AWS Organization",
            default="",
            show_default=False,
        ).strip()

        if not management_account_id and not account_ids_input:
            console.print(
                "[yellow]Account IDs are required when no management account is provided[/yellow]"
            )
            continue

        # Convert account IDs to list, filtering out empty strings
        account_ids = [
            aid.strip() for aid in account_ids_input.split(",") if aid.strip()
        ] if account_ids_input else []
        break

    # Ask the user for the list of regions to include in the assessment
    while True:
        active_regions_input = Prompt.ask(
            "Active Regions (comma separated)",
            default="",
            show_default=False,
        ).strip()

        if not active_regions_input:
            console.print("[yellow]Active regions are required[/yellow]")
            continue

        # Convert regions to list, filtering out empty strings
        active_regions = [
            region.strip() for region in active_regions_input.split(",") if region.strip()
        ]
        break

    # Ask the user for the name of the role to use for the assessment
    role_name = Prompt.ask(
        "Role Name",
        default="KiteAssessmentRole",
    ).strip() or "KiteAssessmentRole"

    # Ask for the external ID
    while True:
        external_id = Prompt.ask(
            "External ID",
            show_default=False,
        ).strip()
        if external_id:
            break
        else:
            console.print("[yellow]External ID is required[/yellow]")

    # Ask for the prowler output directory
    prowler_output_dir = Prompt.ask(
        "Prowler Output Directory",
        default="output",
    ).strip() or "output"

    # Ask for the data directory
    data_dir = Prompt.ask(
        "Data Directory",
        default=".kite/audit",
    ).strip() or ".kite/audit"

    # Create the config
    config = Config.create(
        management_account_id=management_account_id,
        account_ids=account_ids,
        active_regions=active_regions,
        role_name=role_name,
        prowler_output_dir=prowler_output_dir,
        external_id=external_id,
        data_dir=data_dir,
    )

    config.save("kite.yaml")


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
def list_accounts(config: str):
    """List all accounts in the organization."""
    Config.load(config)
    config = Config.get()
    account_ids = set()

    # Add management account if provided
    if config.management_account_id:
        # Normalize to string to avoid duplicates
        account_ids.add(str(config.management_account_id))

    # Add account IDs from config if provided
    if config.account_ids:
        # Normalize all account IDs to strings
        account_ids.update(str(account_id) for account_id in config.account_ids)

    # If we have a management account but no specific account IDs,
    # get all accounts in the organization
    if config.management_account_id and not config.account_ids:
        session = assume_organizational_role()
        org_account_ids = fetch_account_ids(session)

        # Normalize all account IDs to strings
        account_ids.update(org_account_ids)

    for acc_id in account_ids:
        console.print(acc_id)


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("check_id", required=True)
def get_prowler_check_status(config: str, check_id: str):
    """Get the status of a prowler check across all accounts."""
    try:
        Config.load(config)
        prowler_results = get_prowler_output()

        if check_id not in prowler_results:
            error_msg = f"No prowler check found with ID {check_id}"
            console.print(f"[red]Error: {error_msg}[/red]")
            return

        # Create a table to display check statuses
        table_title = f"Prowler Check Status for {check_id}"
        table = Table(title=table_title)
        table.add_column("Account ID", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Region", style="blue")
        table.add_column("Resource", style="green")

        # Track if we found any failures
        has_failures = False

        # Add each failing resource to the table
        for result in prowler_results[check_id]:
            if result.status in ["FAIL", "ERROR"]:
                has_failures = True
                status_emoji = {
                    "FAIL": "❌",
                    "ERROR": "⚠️",
                }.get(result.status, "❓")

                resource_name = result.resource_name or result.resource_uid
                status_text = f"{status_emoji} {result.status}"
                table.add_row(
                    result.account_id,
                    status_text,
                    result.region,
                    resource_name
                )

        if not has_failures:
            console.print("[green]✅ All resources passed this check[/green]")
        else:
            console.print(table)

    except Exception as e:
        raise click.ClickException(
            f"Error getting prowler check status: {str(e)}"
        )


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
def collect(config: str):
    """
    Collect data from AWS for assessment.

    This command collects all necessary data from AWS and saves it to the
    local filesystem for later analysis. The data is stored in the configured
    data directory, organized by account ID.
    """
    try:
        Config.load(config)

        # Make sure we start with a clean slate
        if os.path.exists(Config.get().data_dir):
            shutil.rmtree(Config.get().data_dir)
        os.makedirs(Config.get().data_dir, exist_ok=True)

        collect_data()

        # Save collection metadata
        save_collection_metadata()
        console.print("[green]✓ Saved collection metadata[/green]")

    except Exception as e:
        console.print(f"[red]Error collecting data: {str(e)}[/red]")
        raise click.Abort()


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("account_id", required=True)
def list_access_analyzers(config: str, account_id: str):
    Config.load(config)
    session = assume_role(account_id)
    console.print(list_analyzers(session))


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("account_id", required=True)
def get_s3_bucket_metadata(config: str, account_id: str):
    Config.load(config)
    session = assume_role(account_id)
    console.print(get_buckets(session))


if __name__ == "__main__":
    main()
