from typing import Any

import boto3
import click
from rich.console import Console
from rich.tree import Tree

from hyperscale.kite.config import Config
from hyperscale.kite.data import get_cloudtrail_trails
from hyperscale.kite.data import get_cognito_user_pool
from hyperscale.kite.data import (
    get_customer_managed_policies as get_saved_customer_managed_policies,
)
from hyperscale.kite.data import get_identity_center_instances
from hyperscale.kite.data import get_key_pairs as get_saved_key_pairs
from hyperscale.kite.data import get_organization
from hyperscale.kite.data import get_password_policy as get_saved_password_policy
from hyperscale.kite.data import get_roles as get_saved_roles
from hyperscale.kite.data import get_secrets as get_saved_secrets
from hyperscale.kite.data import get_virtual_mfa_devices

from . import sts
from . import ui

console = Console()


def prompt_user_with_panel(
    check_name: str,
    message: str,
    prompt: str,
    default: bool = True,
    info_required: bool = True,
) -> tuple[bool, str]:
    """
    Display a panel with context and prompt the user for a response.

    This function follows the pattern used in the ou_structure and
    account_separation checks.

    Args:
        check_name: The name of the check.
        message: The message to display in the panel.
        prompt: The prompt to ask the user.
        default: The default value for the yes/no prompt.
        info_required: Whether to ask for additional information

    Returns:
        A tuple containing:
            - A boolean indicating if the user answered yes.
            - A dictionary containing the responses to additional prompts.
    """
    # Display the panel with context
    ui.print("\n")
    ui.print_panel(message, title=check_name, border_style="blue")

    # Prompt the user
    response = ui.confirm(prompt, default=default)

    if info_required:
        value = ui.prompt("Please provide details explaining your answer")
        info = value

    return response, info


def assume_role(account_id: str) -> boto3.Session:
    """
    Assume a role in the specified account.

    Args:
        account_id: The AWS account ID to assume the role in.

    Returns:
        A boto3 session with the assumed role credentials.

    Raises:
        ClickException: If role assumption fails.
    """
    config = Config.get()
    return sts.assume_role(account_id, config.role_name, config.external_id)


def assume_organizational_role() -> boto3.Session:
    """
    Assume a role in the organization, preferably in the management account.

    Returns:
        A boto3 session with the assumed role credentials.

    Raises:
        ClickException: If no account ID is available or role assumption fails.
    """
    config = Config.get()

    # Determine which account to use for assuming the role
    account_id = config.management_account_id
    if not account_id and config.account_ids:
        account_id = config.account_ids[0]

    if not account_id:
        raise click.ClickException(
            "No account ID available. Please provide either management_account_id "
            "or at least one account_id in the config file."
        )

    return assume_role(account_id)


def get_organization_structure_str(org) -> str:
    """
    Get the organization structure as a formatted string.

    Args:
        org: The Organization object.

    Returns:
        A string containing the formatted organization structure.
    """
    # Create a tree representation of the organization structure
    scp_names = [f"{scp.name}" for scp in org.root.scps]
    scp_str = f" [SCPs: {', '.join(scp_names)}]" if scp_names else ""
    tree = Tree(f"Root: {org.root.name} ({org.root.id}){scp_str}")

    def add_ou_to_tree(ou, parent_node):
        # Add accounts to this OU
        for account in ou.accounts:
            scp_names = [f"{scp.name}" for scp in account.scps]
            scp_str = f" [SCPs: {', '.join(scp_names)}]" if scp_names else ""
            parent_node.add(f"Account: {account.name} ({account.id}){scp_str}")

        # Add child OUs
        for child_ou in ou.child_ous:
            scp_names = [f"{scp.name}" for scp in child_ou.scps]
            scp_str = f" [SCPs: {', '.join(scp_names)}]" if scp_names else ""
            child_node = parent_node.add(
                f"OU: {child_ou.name} ({child_ou.id}){scp_str}"
            )
            add_ou_to_tree(child_ou, child_node)

    # Build the tree starting from the root
    add_ou_to_tree(org.root, tree)

    # Use Rich's console to render the tree to a string
    from io import StringIO

    string_buffer = StringIO()
    console = Console(file=string_buffer, force_terminal=True)
    console.print(tree)
    return string_buffer.getvalue()


def get_account_ids_in_scope() -> set[str]:
    """
    Get all account IDs in scope of the assessment.

    This includes:
    1. The management account if provided in the config
    2. All account IDs provided in the config
    3. If only a management account is provided, all accounts in the organization

    Returns:
        Set of account IDs in scope.

    Raises:
        ClickException: If no account ID is available or role assumption fails.
    """
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
        org = get_organization()
        if not org:
            raise ValueError(
                "Management account ID configured, but no organization found"
            )
        org_account_ids = [account.id for account in org.get_accounts()]
        # Normalize all account IDs to strings
        account_ids.update(str(account_id) for account_id in org_account_ids)

    # If we still have no account IDs, we can't proceed
    if not account_ids:
        raise click.ClickException(
            "No account IDs in scope. Please provide either management_account_id "
            "or at least one account_id in the config file."
        )

    return account_ids


def get_root_virtual_mfa_device(account_id: str) -> str | None:
    """
    Get the virtual MFA device for the root user in the specified account.

    Args:
        account_id: The AWS account ID to check.

    Returns:
        The serial number of the root user's virtual MFA device, or None if not found.

    Raises:
        ClickException: If data collection hasn't been run.
    """
    # Get virtual MFA devices from data module
    devices = get_virtual_mfa_devices(account_id)
    if not devices:
        return None

    # Look for root user's virtual MFA device
    for device in devices:
        if "User" in device and "Arn" in device["User"]:
            if "root" in device["User"]["Arn"]:
                return device.get("SerialNumber")

    return None


def is_identity_center_enabled() -> bool:
    """
    Check if AWS Identity Center is enabled by checking the collected data.

    This function checks if:
    1. The account is part of an organization (using Organizations data)
    2. There are any Identity Center instances (using Identity Center data)

    Returns:
        bool: True if Identity Center is enabled and in use, False otherwise.

    """
    # Get organization data to check if we're in an organization
    org = get_organization()
    if org is None:
        return False

    # Get Identity Center instances
    instances = get_identity_center_instances()
    return instances is not None and len(instances) > 0


def get_password_policy(account_id: str) -> dict[str, Any] | None:
    """
    Get the IAM password policy for the specified account.

    Args:
        account_id: The AWS account ID to get the password policy for.

    Returns:
        Dict containing the password policy settings if one exists, None otherwise.

    """
    return get_saved_password_policy(account_id)


def is_complex(policy: dict[str, Any] | None) -> bool:
    """
    Determine if the given password policy meets complexity requirements.

    A password policy is considered complex if all of the following are true:
    - MinimumPasswordLength >= 8
    - RequireNumbers = true
    - RequireLowercaseCharacters = true
    - RequireUppercaseCharacters = true
    - RequireSymbols = true

    Args:
        password_policy: The password policy to check, or None if no policy exists.

    Returns:
        bool: True if the policy meets all complexity requirements, False otherwise.
    """
    if not policy:
        return False

    return (
        policy.get("MinimumPasswordLength", 0) >= 8
        and policy.get("RequireNumbers", False) is True
        and policy.get("RequireLowercaseCharacters", False) is True
        and policy.get("RequireUppercaseCharacters", False) is True
        and policy.get("RequireSymbols", False) is True
    )


def is_identity_center_identity_store_used() -> bool:
    """
    Check if the Identity Center identity store is being used.
    """
    return any(
        instance["IdentityStoreUsers"] for instance in get_identity_center_instances()
    )


def is_cognito_password_policy_complex(policy: dict[str, Any]) -> bool:
    """
    Determine if the given Cognito password policy meets complexity requirements.

    A Cognito password policy is considered complex if all of the following are true:
    - MinimumLength >= 8
    - RequireNumbers = true
    - RequireLowercase = true
    - RequireUppercase = true
    - RequireSymbols = true

    Args:
        policy: The password policy to check.

    Returns:
        bool: True if the policy meets all complexity requirements, False otherwise.
    """
    return (
        policy.get("MinimumLength", 0) >= 8
        and policy.get("RequireNumbers", False) is True
        and policy.get("RequireLowercase", False) is True
        and policy.get("RequireUppercase", False) is True
        and policy.get("RequireSymbols", False) is True
    )


def get_user_pool_password_policy(
    account_id: str, region: str, user_pool_id: str
) -> dict[str, Any]:
    """
    Get the password policy for a Cognito user pool.

    Args:
        account_id: The AWS account ID containing the user pool.
        region: The AWS region containing the user pool.
        user_pool_id: The ID of the user pool to check.

    Returns:
        Dict containing the password policy settings.

    Raises:
        ClickException: If data collection hasn't been run.
    """
    return (
        get_cognito_user_pool(account_id, region, user_pool_id)
        .get("Policies", {})
        .get("PasswordPolicy", {})
    )


def get_user_pool_mfa_config(account_id: str, region: str, user_pool_id: str) -> str:
    """
    Get the MFA configuration for a Cognito user pool.

    Args:
        account_id: The AWS account ID containing the user pool.
        region: The AWS region containing the user pool.
        user_pool_id: The ID of the user pool to check.

    Returns:
        str: The MFA configuration ("ON", "OFF", or "OPTIONAL").

    Raises:
        ClickException: If data collection hasn't been run.
    """
    return get_cognito_user_pool(account_id, region, user_pool_id).get(
        "MfaConfiguration", "OFF"
    )


def get_account_key_pairs(account_id: str) -> list[dict[str, Any]]:
    """
    Get all EC2 key pairs in the specified account from saved data.

    Args:
        account_id: AWS account ID to check

    Returns:
        List of dictionaries containing key pair information

    Raises:
        ClickException: If data collection hasn't been run
    """
    return get_saved_key_pairs(account_id)


def get_secrets(account_id: str, region: str) -> list[dict[str, Any]]:
    """
    Get secrets from AWS Secrets Manager from saved data.

    Args:
        account_id: The AWS account ID to get secrets from.
        region: The AWS region to get secrets from.

    Returns:
        List of dictionaries containing secret details and resource policies.

    Raises:
        ClickException: If data collection hasn't been run
    """
    return get_saved_secrets(account_id, region)


def get_account_roles(account_id: str) -> list[dict[str, Any]]:
    """
    Get all IAM roles in the specified account from saved data.

    Args:
        account_id: AWS account ID to check

    Returns:
        List of dictionaries containing role information

    Raises:
        ClickException: If data collection hasn't been run
    """
    return get_saved_roles(account_id)


def get_customer_managed_policies(account_id: str) -> list[dict[str, Any]]:
    """
    Get all customer managed policies in the specified account from saved data.

    Args:
        account_id: AWS account ID to check

    Returns:
        List of dictionaries containing policy information

    Raises:
        ClickException: If data collection hasn't been run
    """
    return get_saved_customer_managed_policies(account_id)


def get_organizational_trail() -> tuple[dict[str, Any] | None, str | None, str | None]:
    """
    Get the organizational trail for the account.
    """
    config = Config.get()
    for account in get_account_ids_in_scope():
        for region in config.active_regions:
            trails = get_cloudtrail_trails(account, region)
            if not trails:
                continue

            for trail in trails:
                if trail.get("IsOrganizationTrail", False):
                    return trail, account, region
    return None, None, None
