import os
import shutil
import subprocess
from collections import defaultdict
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from pathlib import Path

import click
import yaml
from botocore.exceptions import ClientError
from botocore.exceptions import TokenRetrievalError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hyperscale.kite.accessanalyzer import list_analyzers
from hyperscale.kite.check_themes import CHECK_THEMES
from hyperscale.kite.check_themes import find_check_by_id
from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks import make_finding
from hyperscale.kite.cloudfront import get_distributions_by_web_acl
from hyperscale.kite.collect import collect_data
from hyperscale.kite.collect import CollectException
from hyperscale.kite.config import Config
from hyperscale.kite.data import save_collection_metadata
from hyperscale.kite.data import verify_collection_status
from hyperscale.kite.helpers import assume_organizational_role
from hyperscale.kite.helpers import assume_role
from hyperscale.kite.helpers import prompt_user_with_panel
from hyperscale.kite.organizations import fetch_account_ids
from hyperscale.kite.organizations import get_account_details
from hyperscale.kite.prowler import get_prowler_output
from hyperscale.kite.s3 import get_buckets
from hyperscale.kite.ui import confirm
from hyperscale.kite.ui import prompt
from hyperscale.kite.wafv2 import get_web_acls

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


@click.group()
@click.version_option(package_name="hyperscale.kite")
def main():
    """Kite - AWS Security Assessment CLI."""
    pass


@dataclass
class Assessment:
    timestamp: str = datetime.now().isoformat()
    config_file: str = "kite.yaml"
    themes: dict = field(default_factory=lambda: defaultdict(list))

    @classmethod
    def load(cls) -> "Assessment | None":
        try:
            with open("kite-results.yaml") as f:
                data = yaml.safe_load(f)
                data["themes"] = defaultdict(list, data.get("themes", {}))
                return Assessment(**data)
        except FileNotFoundError:
            return None

    def record(self, theme_name: str, finding):
        self.themes[theme_name].append(finding)

    def save(self):
        with open("kite-results.yaml", "w") as f:
            data = asdict(self)
            data["themes"] = dict(
                self.themes
            )  # Convert defaultdict to dict for YAML serialization
            yaml.dump(data, f, default_flow_style=False)

    def has_finding(self, check_id: str) -> bool:
        return self._get_finding(check_id) is not None

    def _get_finding(self, check_id: str) -> dict | None:
        for _, findings in self.themes.items():
            for f in findings:
                if f["check_id"] == check_id:
                    return f
        return None

    def get_finding(self, check_id: str) -> dict:
        finding = self._get_finding(check_id)
        if finding is None:
            raise ValueError(f"No finding found for check ID: {check_id}")
        return finding


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
    type=click.Path(exists=True),
)
@click.option(
    "--auto-save/--no-auto-save", default=True, help="Enable or disable auto-saving"
)
def assess(config: str, auto_save: bool = True):
    """Start a security assessment using the specified config file."""
    config_data = Config.load(config)

    # Verify collection status
    verify_collection_status()

    # Format account IDs for display
    account_ids_str = (
        ", ".join(config_data.account_ids) if config_data.account_ids else "ALL"
    )

    assessment = Assessment.load()
    if assessment:
        progress_msg = (
            "Continuing AWS security assessment using results from ./kite-results.yaml"
        )
    else:
        progress_msg = "Starting new AWS security assessment"
        assessment = Assessment()

    console.print(
        Panel(
            f"{progress_msg}\n"
            f"Management Account: {config_data.management_account_id}\n"
            f"Target Accounts: {account_ids_str}\n"
            f"Regions: {', '.join(config_data.active_regions)}\n"
            f"Role Name: {config_data.role_name}",
            title="Kite Assessment",
            border_style="blue",
        )
    )

    for theme in CHECK_THEMES:
        console.print(
            Panel(
                theme.description,
                title=theme.name,
                border_style="blue",
            )
        )

        for check in theme.checks:
            check_id = check.check_id

            if assessment.has_finding(check_id):
                console.print(
                    f"[yellow]Skipping {check_id} - already assessed[/yellow]"
                )
                continue

            finding = _run_check(check)
            assessment.record(theme.name, finding)
            display_finding(finding)

            if auto_save:
                assessment.save()

        display_theme_results(theme.name, assessment.themes[theme.name])

    assessment.save()
    console.print(
        Panel(
            "Assessment results saved to kite-results.yaml",
            title="Results",
            border_style="blue",
        )
    )


def save_assessment(assessment):
    with open("kite-results.yaml", "w") as f:
        yaml.dump(assessment, f, default_flow_style=False)


@main.command()
def list_checks():
    """List all available security checks."""
    table = Table(title="Available Security Checks")
    table.add_column("Theme", style="yellow")
    table.add_column("Check ID", style="cyan")
    table.add_column("Check Name", style="green")

    for theme in CHECK_THEMES:
        for check in theme.checks:
            table.add_row(theme.name, check.check_id, check.check_name)

    console.print(table)


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
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

    finding = _run_check(check)

    # Display the result
    status_color = {"PASS": "green", "FAIL": "red", "ERROR": "yellow"}.get(
        finding["status"], "white"
    )

    console.print(f"\nStatus: [{status_color}]{finding['status']}[/{status_color}]")
    if "details" in finding:
        console.print("\nDetails:")
        console.print(finding["details"])


def _run_check(check):
    result = check.run()
    if result.status == CheckStatus.MANUAL:
        description = check.description
        context = result.context
        question = check.question
        pass_, reason = prompt_user_with_panel(
            check_name=check.check_name,
            message="\n\n".join([description, context]),
            prompt=question,
        )
        finding = make_finding(
            check_id=check.check_id,
            check_name=check.check_name,
            description=check.description,
            status="PASS" if pass_ else "FAIL",
            reason=reason,
            details=result.details,
        )
    else:
        finding = make_finding(
            check_id=check.check_id,
            check_name=check.check_name,
            description=check.description,
            status=result.status.value,
            reason=result.reason,
            details=result.details,
        )
    return finding


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
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
            console.print(
                f"[red]Error: Account {account_id} not found in the organization[/red]"
            )
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
        raise click.ClickException(f"Error fetching account details: {str(e)}") from e


@main.command()
def configure():
    """Configure the Kite CLI."""

    # Check if hyperscale.kite.yaml exists
    if os.path.exists("kite.yaml"):
        if not confirm("kite.yaml already exists. Overwrite?"):
            return

    # Ask the user for the management account ID, if they have one
    management_account_id = prompt(
        "Management Account ID (if using AWS Organizations)"
    ).strip()

    # Ask the user for the list of account IDs to include in the assessment
    while True:
        account_ids_input = prompt(
            "Account IDs (comma separated) - leave blank for all accounts in an AWS "
            "Organization",
        ).strip()

        if not management_account_id and not account_ids_input:
            console.print(
                "[yellow]Account IDs are required when no management account is "
                "provided[/yellow]"
            )
            continue

        # Convert account IDs to list, filtering out empty strings
        account_ids = (
            [aid.strip() for aid in account_ids_input.split(",") if aid.strip()]
            if account_ids_input
            else []
        )
        break

    # Ask the user for the list of regions to include in the assessment
    while True:
        active_regions_input = prompt(
            "Active Regions (comma separated)",
        ).strip()

        if not active_regions_input:
            console.print("[yellow]Active regions are required[/yellow]")
            continue

        # Convert regions to list, filtering out empty strings
        active_regions = [
            region.strip()
            for region in active_regions_input.split(",")
            if region.strip()
        ]
        break

    # Ask the user for the name of the role to use for the assessment
    role_name = (
        prompt(
            "Role Name",
            default="KiteAssessmentRole",
        ).strip()
        or "KiteAssessmentRole"
    )

    # Ask for the external ID
    while True:
        external_id = prompt("External ID").strip()
        if external_id:
            break
        else:
            console.print("[yellow]External ID is required[/yellow]")

    # Ask for the prowler output directory
    prowler_output_dir = (
        prompt(
            "Prowler Output Directory",
            default="output",
        ).strip()
        or "output"
    )

    # Ask for the data directory
    data_dir = (
        prompt(
            "Data Directory",
            default=".kite/audit",
        ).strip()
        or ".kite/audit"
    )

    # Create the config
    config = Config.create(
        management_account_id=management_account_id,
        account_ids=account_ids,
        active_regions=active_regions,
        role_name=role_name,
        prowler_output_dir=Path(prowler_output_dir),
        external_id=external_id,
        data_dir=Path(data_dir),
    )

    config.save("kite.yaml")


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
    type=click.Path(exists=True),
)
def list_accounts(config: str):
    Config.load(config)
    config_obj = Config.get()
    account_ids = set()

    # Add management account if provided
    if config_obj.management_account_id:
        # Normalize to string to avoid duplicates
        account_ids.add(str(config_obj.management_account_id))

    # Add account IDs from config if provided
    if config_obj.account_ids:
        # Normalize all account IDs to strings
        account_ids.update(str(account_id) for account_id in config_obj.account_ids)

    # If we have a management account but no specific account IDs,
    # get all accounts in the organization
    if config_obj.management_account_id and not config_obj.account_ids:
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
    help="Path to config file (default: hyperscale.kite.yaml)",
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
                    result.account_id, status_text, result.region, resource_name
                )

        if not has_failures:
            console.print("[green]✅ All resources passed this check[/green]")
        else:
            console.print(table)

    except Exception as e:
        raise click.ClickException(
            f"Error getting prowler check status: {str(e)}"
        ) from e


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
    type=click.Path(exists=True),
)
def collect(config: str):
    """
    Collect data from AWS for assessment.

    This command collects all necessary data from AWS and saves it to the
    local filesystem for later analysis. The data is stored in the configured
    data directory, organized by account ID.
    """
    Config.load(config)

    # Make sure we start with a clean slate
    if os.path.exists(Config.get().data_dir):
        shutil.rmtree(Config.get().data_dir)
    os.makedirs(Config.get().data_dir, exist_ok=True)

    try:
        collect_data()
        save_collection_metadata()
        console.print("[green]✓ Saved collection metadata[/green]")
    except TokenRetrievalError:
        raise click.ClickException(
            "Unable to retrieve token from sso - try running `aws sso login`"
        ) from None
    except CollectException as e:
        raise click.ClickException(str(e)) from e
    except ClientError as e:
        msg = str(e)
        if e.response["Error"]["Code"] == "ExpiredToken":
            msg = "AWS credentials have expired - please re-authenticate."
        raise click.ClickException(msg) from e


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
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
    help="Path to config file (default: hyperscale.kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("account_id", required=True)
def get_s3_bucket_metadata(config: str, account_id: str):
    Config.load(config)
    session = assume_role(account_id)
    console.print(get_buckets(session))


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("account_id", required=True)
@click.argument("region", required=True)
@click.argument("scope", required=True)
def list_web_acls(config: str, account_id: str, region: str, scope: str):
    Config.load(config)
    session = assume_role(account_id)
    console.print(get_web_acls(session, scope, region))


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("account_id", required=True)
@click.argument("web_acl_arn", required=True)
def list_distributions_by_web_acl(config: str, account_id: str, web_acl_arn: str):
    Config.load(config)
    session = assume_role(account_id)
    console.print(get_distributions_by_web_acl(session, web_acl_arn))


@main.command()
@click.option(
    "--config",
    "-c",
    default="kite.yaml",
    help="Path to config file (default: hyperscale.kite.yaml)",
    type=click.Path(exists=True),
)
@click.argument("account_id")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def exec(config: str, account_id: str, command: list[str]):
    """Assume role in ACCOUNT_ID and run COMMAND"""
    if not command:
        raise click.ClickException("No command provided to run.")
    cmd = list(command)
    if cmd[0] != "aws":
        cmd.insert(0, "aws")

    Config.load(config)
    session = assume_role(account_id)
    creds = session.get_credentials().get_frozen_credentials()
    env = os.environ.copy()
    env.update(
        {
            "AWS_ACCESS_KEY_ID": creds.access_key,
            "AWS_SECRET_ACCESS_KEY": creds.secret_key,
            "AWS_SESSION_TOKEN": creds.token,
        }
    )
    subprocess.run(cmd, env=env)


if __name__ == "__main__":
    main()
