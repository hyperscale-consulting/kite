"""Helper functions for Kite."""

import boto3
import click
import glob
from rich.console import Console
from rich.tree import Tree
from typing import Optional, Dict, List, Any, Set, Tuple, Callable
from dataclasses import dataclass

from . import ui, sts
from kite.config import Config
from kite.data import (
    get_organization,
    get_identity_center_instances,
    get_virtual_mfa_devices,
    get_password_policy as get_saved_password_policy,
)
from kite.cognito import (
    list_user_pools,
    fetch_cognito_user_pool,
)
from kite.ec2 import get_key_pairs
from kite.secretsmanager import fetch_secrets, SecretDetails

console = Console()


def prompt_user_with_panel(
    check_name: str,
    message: str,
    prompt: str,
    default: bool = True,
    info_required: bool = True,
) -> Tuple[bool, Dict[str, Any]]:
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


def manual_check(
    check_id: str,
    check_name: str,
    message: str,
    prompt: str,
    pass_message: str,
    fail_message: str,
    default: bool = True,
    pre_check: Optional[Callable[[], Tuple[bool, Dict[str, Any]]]] = None,
    error_message_prefix: str = "Error checking",
) -> Dict[str, Any]:
    """
    Generic function for manual checks that need to ask the user questions.

    This function handles the common pattern of:
    1. Running an optional pre-check function
    2. Displaying a panel with context
    3. Prompting the user for a response
    4. Returning a standardized result dictionary

    Args:
        check_id: The ID of the check.
        check_name: The name of the check.
        message: The message to display in the panel.
        prompt: The prompt to ask the user.
        pass_message: The message to return if the user answers yes.
        fail_message: The message to return if the user answers no.
        default: The default value for the yes/no prompt.
        pre_check: Optional function to run before prompting the user.
            Should return a tuple of (should_continue, result_dict).
            If should_continue is False, the function will return result_dict
            without prompting the user.
        error_message_prefix: The prefix for the error message if an exception occurs.

    Returns:
        A dictionary containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - Additional keys from additional_prompts if provided
    """
    try:
        # Run pre-check if provided
        if pre_check:
            should_continue, result = pre_check()
            if not should_continue:
                return result

        # Use prompt_user_with_panel to get the user's response
        response, info = prompt_user_with_panel(
            check_name=check_name,
            message=message,
            prompt=prompt,
            default=default,
        )

        # Create the result dictionary
        result = {
            "check_id": check_id,
            "check_name": check_name,
            "status": "PASS" if response else "FAIL",
            "details": {
                "message": pass_message if response else fail_message,
            },
        }

        # Add additional responses to the details
        if info:
            result["details"]["info"] = info

        return result

    except Exception as e:
        return {
            "check_id": check_id,
            "check_name": check_name,
            "status": "ERROR",
            "details": {
                "message": f"{error_message_prefix} {check_name.lower()}: {str(e)}",
            },
        }


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


def get_account_ids_in_scope() -> Set[str]:
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
        org_account_ids = [
            account.id for account in get_organization().get_accounts()
        ]
        # Normalize all account IDs to strings
        account_ids.update(str(account_id) for account_id in org_account_ids)

    # If we still have no account IDs, we can't proceed
    if not account_ids:
        raise click.ClickException(
            "No account IDs in scope. Please provide either management_account_id "
            "or at least one account_id in the config file."
        )

    return account_ids


def get_root_virtual_mfa_device(account_id: str) -> Optional[str]:
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


def get_password_policy(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Get the IAM password policy for the specified account.

    Args:
        account_id: The AWS account ID to get the password policy for.

    Returns:
        Dict containing the password policy settings if one exists, None otherwise.

    """
    return get_saved_password_policy(account_id)


def is_complex(policy: Optional[Dict[str, Any]]) -> bool:
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
        instance["HasIdentityStoreUsers"]
        for instance in get_identity_center_instances()
    )


def get_cognito_user_pools(account_id: str) -> List[Dict[str, Any]]:
    """
    Lazily load and cache the list of Cognito user pools for the specified account.

    Args:
        account_id: The AWS account ID to check.

    Returns:
        List of dictionaries containing user pool information.

    Raises:
        ClickException: If role assumption fails or the API call fails.
    """
    # Initialize the cache if it doesn't exist
    if not hasattr(get_cognito_user_pools, "_pools"):
        get_cognito_user_pools._pools = {}

    # Check if we already have the pools for this account
    if account_id not in get_cognito_user_pools._pools:
        try:
            # Assume role in the specified account
            session = assume_role(account_id)
            # Fetch and cache the pools
            get_cognito_user_pools._pools[account_id] = list_user_pools(session)
        except Exception as e:
            raise click.ClickException(
                f"Failed to get Cognito user pools for account {account_id}: {str(e)}"
            )

    return get_cognito_user_pools._pools[account_id]


def get_cognito_user_pool(account_id: str, user_pool_id: str) -> Dict[str, Any]:
    """
    Lazily load and cache the Cognito user pool for the specified account and user pool
    ID.

    Args:
        account_id: The AWS account ID containing the user pool.
    Returns:
        Dict containing the user pool information.

    Raises:
        ClickException: If role assumption fails or the API call fails.
    """
    # Initialize the cache if it doesn't exist
    if not hasattr(get_cognito_user_pool, "_pools"):
        get_cognito_user_pool._pools = {}

    # Check if we already have the pool for this account and user pool ID
    if (account_id, user_pool_id) not in get_cognito_user_pool._pools:
        try:
            # Assume role in the specified account
            session = assume_role(account_id)
            # Fetch and cache the pool
            get_cognito_user_pool._pools[(account_id, user_pool_id)] = (
                fetch_cognito_user_pool(session, user_pool_id)
            )
        except Exception as e:
            raise click.ClickException(
                f"Failed to get Cognito user pool {user_pool_id} for account "
                f"{account_id}: {str(e)}"
            )

    return get_cognito_user_pool._pools[(account_id, user_pool_id)]


def is_cognito_password_policy_complex(policy: Dict[str, Any]) -> bool:
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


def get_user_pool_password_policy(account_id: str, user_pool_id: str) -> Dict[str, Any]:
    """
    Get the password policy for a Cognito user pool.

    Args:
        account_id: The AWS account ID containing the user pool.
        user_pool_id: The ID of the user pool to check.

    Returns:
        Dict containing the password policy settings.

    Raises:
        ClickException: If role assumption fails or the API call fails.
    """
    return get_cognito_user_pool(account_id, user_pool_id).get('Policies', {}).get(
        "PasswordPolicy", {}
    )


def get_user_pool_mfa_config(account_id: str, user_pool_id: str) -> str:
    """
    Get the MFA configuration for a Cognito user pool.

    Args:
        account_id: The AWS account ID containing the user pool.
        user_pool_id: The ID of the user pool to check.

    Returns:
        str: The MFA configuration ("ON", "OFF", or "OPTIONAL").

    Raises:
        ClickException: If role assumption fails or the API call fails.
    """
    return get_cognito_user_pool(account_id, user_pool_id).get("MfaConfiguration",
                                                               "OFF")


@dataclass
class ProwlerResult:
    """Represents a single prowler check result."""
    account_id: str
    status: str
    extended_status: str
    resource_uid: str
    resource_name: str
    resource_details: str
    region: str


def get_prowler_output() -> Dict[str, List[ProwlerResult]]:
    """
    Read and cache prowler output files.

    Returns:
        A dictionary mapping check IDs to a list of ProwlerResult objects.

    Raises:
        ClickException: If no prowler output files are found.
    """
    if not hasattr(get_prowler_output, "_cache"):
        config = Config.get()
        prowler_files = glob.glob(f"{config.prowler_output_dir}/prowler-output-*.csv")

        if not prowler_files:
            raise click.ClickException(
                f"No prowler output files found in {config.prowler_output_dir}"
            )

        results = {}
        for file_path in prowler_files:
            with open(file_path, "r") as f:
                # Skip header line
                next(f)
                for line in f:
                    records = line.strip().split(";")
                    if len(records) >= 26:  # Ensure we have enough fields
                        check_id = records[10]
                        result = ProwlerResult(
                            account_id=records[2],
                            status=records[13],
                            extended_status=records[14],
                            resource_uid=records[20],
                            resource_name=records[21],
                            resource_details=records[22],
                            region=records[25]
                        )

                        if check_id not in results:
                            results[check_id] = []
                        results[check_id].append(result)

        get_prowler_output._cache = results

    return get_prowler_output._cache


def get_account_key_pairs(account_id: str) -> List[Dict[str, Any]]:
    """
    Get all EC2 key pairs in the specified account.

    Args:
        account_id: AWS account ID to check

    Returns:
        List of dictionaries containing key pair information
    """
    # Initialize the cache if it doesn't exist
    if not hasattr(get_account_key_pairs, "_key_pairs"):
        get_account_key_pairs._key_pairs = {}

    # Check if we already have the key pairs for this account
    if account_id not in get_account_key_pairs._key_pairs:
        try:
            # Assume role in the specified account
            session = assume_role(account_id)
            # Fetch and cache the key pairs
            get_account_key_pairs._key_pairs[account_id] = get_key_pairs(session)
        except Exception as e:
            raise click.ClickException(
                f"Failed to get EC2 key pairs for account {account_id}: {str(e)}"
            )

    return get_account_key_pairs._key_pairs[account_id]


def get_secrets(account_id: str, region: str) -> List[SecretDetails]:
    """
    Get all secrets from AWS Secrets Manager for a given account and region.

    Args:
        account_id: The AWS account ID to get secrets from.
        region: The AWS region to get secrets from.

    Returns:
        List of SecretDetails objects containing secret details and resource policies.

    Raises:
        ClientError: If the Secrets Manager API calls fail.
    """
    # Initialize the cache if it doesn't exist
    if not hasattr(get_secrets, "_secrets"):
        get_secrets._secrets = {}

    # Check if we already have the secrets for this account and region
    cache_key = f"{account_id}:{region}"
    if cache_key not in get_secrets._secrets:
        try:
            # Assume role in the specified account
            session = assume_role(account_id)
            # Fetch and cache the secrets
            get_secrets._secrets[cache_key] = fetch_secrets(session, region)
        except Exception as e:
            raise click.ClickException(
                f"Failed to get secrets for account {account_id} in region {region}: {str(e)}"
            )

    return get_secrets._secrets[cache_key]
