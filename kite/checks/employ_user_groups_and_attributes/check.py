"""Check for use of user groups and attributes."""

import json
import os
from typing import Dict, Any

from rich.console import Console
from kite.helpers import (
    get_account_ids_in_scope,
    manual_check,
    assume_role,
)
from kite.config import Config


CHECK_ID = "employ-user-groups-and-attributes"
CHECK_NAME = "Employ User Groups and Attributes"

console = Console()


def _save_iam_data(account_id: str, data: Dict[str, Any], data_type: str) -> str:
    """
    Save IAM data to a file in the data directory.

    Args:
        account_id: The AWS account ID
        data: The IAM data to save
        data_type: The type of IAM data (users, groups, roles, or policies)

    Returns:
        The path to the saved file
    """
    # Create data directory if it doesn't exist
    os.makedirs(Config.get().data_dir, exist_ok=True)

    # Create account-specific directory
    account_dir = f"{Config.get().data_dir}/{account_id}"
    os.makedirs(account_dir, exist_ok=True)

    # Save data to file
    file_path = f"{account_dir}/{data_type}.json"
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return file_path


def _get_identity_center_data(session) -> Dict[str, Any]:
    """
    Get Identity Center users and permission sets.

    Args:
        session: The boto3 session to use

    Returns:
        Dict containing Identity Center data
    """
    identity_center_client = session.client("sso-admin")
    identity_store_client = session.client("identitystore")

    # Get the Identity Store ID
    identity_store_id = identity_center_client.list_instances()["Instances"][0]["IdentityStoreId"]

    data = {
        "users": {},
        "permission_sets": {}
    }

    # Get all users
    paginator = identity_store_client.get_paginator("list_users")
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for user in page["Users"]:
            # Get user's groups
            groups = []
            group_paginator = identity_store_client.get_paginator("list_group_memberships_for_member")
            for group_page in group_paginator.paginate(
                IdentityStoreId=identity_store_id,
                MemberId={"UserId": user["UserId"]}
            ):
                for membership in group_page["GroupMemberships"]:
                    group = identity_store_client.describe_group(
                        IdentityStoreId=identity_store_id,
                        GroupId=membership["GroupId"]
                    )["Group"]
                    groups.append(group["DisplayName"])

            data["users"][user["UserName"]] = {
                "user_id": user["UserId"],
                "display_name": user.get("DisplayName"),
                "email": user.get("Emails", [{}])[0].get("Value"),
                "groups": groups
            }

    # Get all permission sets
    paginator = identity_center_client.get_paginator("list_permission_sets")
    for page in paginator.paginate(InstanceArn=identity_center_client.list_instances()["Instances"][0]["InstanceArn"]):
        for permission_set_arn in page["PermissionSets"]:
            permission_set = identity_center_client.describe_permission_set(
                InstanceArn=identity_center_client.list_instances()["Instances"][0]["InstanceArn"],
                PermissionSetArn=permission_set_arn
            )["PermissionSet"]

            # Get permission set's managed policies
            managed_policies = []
            for policy in identity_center_client.list_managed_policies_in_permission_set(
                InstanceArn=identity_center_client.list_instances()["Instances"][0]["InstanceArn"],
                PermissionSetArn=permission_set_arn
            )["AttachedManagedPolicies"]:
                managed_policies.append(policy["Name"])

            # Get permission set's inline policy
            try:
                inline_policy = identity_center_client.get_inline_policy_for_permission_set(
                    InstanceArn=identity_center_client.list_instances()["Instances"][0]["InstanceArn"],
                    PermissionSetArn=permission_set_arn
                )["InlinePolicy"]
            except identity_center_client.exceptions.ResourceNotFoundException:
                inline_policy = None

            data["permission_sets"][permission_set["Name"]] = {
                "arn": permission_set_arn,
                "description": permission_set.get("Description"),
                "managed_policies": managed_policies,
                "inline_policy": inline_policy
            }

    return data


def _get_iam_data(session, data_type: str) -> Dict[str, Any]:
    """
    Get IAM data from AWS.

    Args:
        session: The boto3 session to use
        data_type: The type of IAM data to get (users, groups, roles, or policies)

    Returns:
        Dict containing the IAM data
    """
    iam_client = session.client("iam")
    data = {}

    if data_type == "users":
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                # Get user's groups
                groups = []
                for group in iam_client.list_groups_for_user(
                    UserName=user["UserName"]
                )["Groups"]:
                    groups.append(group["GroupName"])

                # Get user's policies
                policies = []
                for policy in iam_client.list_attached_user_policies(
                    UserName=user["UserName"]
                )["AttachedPolicies"]:
                    policies.append(policy["PolicyName"])

                # Get user's inline policy
                try:
                    inline_policy = iam_client.get_user_policy(
                        UserName=user["UserName"],
                        PolicyName="inline-policy"
                    )["PolicyDocument"]
                except iam_client.exceptions.NoSuchEntityException:
                    inline_policy = None

                data[user["UserName"]] = {
                    "arn": user["Arn"],
                    "create_date": user["CreateDate"],
                    "groups": groups,
                    "policies": policies,
                    "inline_policy": inline_policy
                }

    elif data_type == "groups":
        paginator = iam_client.get_paginator("list_groups")
        for page in paginator.paginate():
            for group in page["Groups"]:
                # Get group's policies
                policies = []
                for policy in iam_client.list_attached_group_policies(
                    GroupName=group["GroupName"]
                )["AttachedPolicies"]:
                    policies.append(policy["PolicyName"])

                # Get group's inline policies
                inline_policies = {}
                try:
                    for policy_name in iam_client.list_group_policies(
                        GroupName=group["GroupName"]
                    )["PolicyNames"]:
                        inline_policies[policy_name] = iam_client.get_group_policy(
                            GroupName=group["GroupName"],
                            PolicyName=policy_name
                        )["PolicyDocument"]
                except iam_client.exceptions.NoSuchEntityException:
                    pass

                data[group["GroupName"]] = {
                    "arn": group["Arn"],
                    "create_date": group["CreateDate"],
                    "policies": policies,
                    "inline_policies": inline_policies
                }

    elif data_type == "roles":
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                # Get role's policies
                policies = []
                for policy in iam_client.list_attached_role_policies(
                    RoleName=role["RoleName"]
                )["AttachedPolicies"]:
                    policies.append(policy["PolicyName"])

                # Get role's inline policies
                inline_policies = {}
                try:
                    for policy_name in iam_client.list_role_policies(
                        RoleName=role["RoleName"]
                    )["PolicyNames"]:
                        inline_policies[policy_name] = iam_client.get_role_policy(
                            RoleName=role["RoleName"],
                            PolicyName=policy_name
                        )["PolicyDocument"]
                except iam_client.exceptions.NoSuchEntityException:
                    pass

                data[role["RoleName"]] = {
                    "arn": role["Arn"],
                    "create_date": role["CreateDate"],
                    "policies": policies,
                    "inline_policies": inline_policies,
                    "assume_role_policy": role["AssumeRolePolicyDocument"]
                }

    elif data_type == "policies":
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                # Get policy version
                version = iam_client.get_policy(
                    PolicyArn=policy["Arn"]
                )["Policy"]["DefaultVersionId"]
                policy_doc = iam_client.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=version
                )["PolicyVersion"]["Document"]

                data[policy["PolicyName"]] = {
                    "arn": policy["Arn"],
                    "create_date": policy["CreateDate"],
                    "update_date": policy["UpdateDate"],
                    "document": policy_doc
                }

    return data


def check_employ_user_groups_and_attributes() -> Dict[str, Any]:
    """
    Check if permissions are defined according to user groups and attributes.

    This check:
    1. Gathers information about IAM users, groups, roles, and policies
    2. Gathers information about Identity Center users and permission sets
    3. Saves the data to .kite/audit/{account_id}/ for review
    4. Asks the user to consider:
       - Are permissions defined and duplicated individually for users?
       - Are groups defined at too high a level, granting overly broad permissions?
       - Are groups too granular, creating duplication and confusion?
       - Do groups have duplicate permissions where attributes could be used instead?
       - Are groups based on function, rather than resource access?

    Returns:
        Dict containing the check results.
    """
    try:
        # Get in-scope accounts
        account_ids = get_account_ids_in_scope()

        # Track saved files for each account
        saved_files = {}

        # Gather and save IAM data for each account
        for account_id in account_ids:
            try:
                console.print(
                    f"\n[bold blue]Gathering IAM data for account {account_id}...[/]"
                )

                # Assume role in the account
                session = assume_role(account_id)

                # Get and save IAM data
                saved_files[account_id] = {}
                for data_type in ["users", "groups", "roles", "policies"]:
                    console.print(f"  [yellow]Fetching {data_type}...[/]")
                    data = _get_iam_data(session, data_type)
                    file_path = _save_iam_data(account_id, data, data_type)
                    saved_files[account_id][data_type] = file_path
                    console.print(
                        f"  [green]✓ Saved {data_type} to {file_path}[/]"
                    )

                # Get and save Identity Center data
                console.print("  [yellow]Fetching Identity Center data...[/]")
                try:
                    identity_center_data = _get_identity_center_data(session)
                    file_path = _save_iam_data(
                        account_id, identity_center_data, "identity_center"
                    )
                    saved_files[account_id]["identity_center"] = file_path
                    console.print(
                        f"  [green]✓ Saved Identity Center data to {file_path}[/]"
                    )
                except Exception as e:
                    console.print(
                        f"  [yellow]⚠ Could not fetch Identity Center data: {str(e)}[/]"
                    )

                console.print(
                    f"[bold green]✓ Completed gathering IAM data for account "
                    f"{account_id}[/]"
                )
            except Exception as e:
                return {
                    "check_id": CHECK_ID,
                    "check_name": CHECK_NAME,
                    "status": "ERROR",
                    "details": {
                        "message": (
                            f"Error gathering IAM data for account {account_id}: "
                            f"{str(e)}"
                        ),
                    },
                }

        # Build message for manual check
        message = (
            "IAM data has been saved to .kite/audit/{account_id}/ for review.\n\n"
            "Please review the following files for each account:\n"
        )

        for account_id, files in saved_files.items():
            message += f"\nAccount {account_id}:\n"
            for data_type, file_path in files.items():
                message += f"- {data_type}: {file_path}\n"

        message += "\nConsider the following questions:\n"
        message += (
            "1. Are permissions defined and duplicated individually for users?\n"
            "2. Are groups defined at too high a level, granting overly broad "
            "permissions?\n"
            "3. Are groups too granular, creating duplication and confusion?\n"
            "4. Do groups have duplicate permissions where attributes could be "
            "used instead?\n"
            "5. Are groups based on function, rather than resource access?\n\n"
            "Tip: focus on users, groups, and roles that can be assumed by humans, "
            "and look for condition clauses that constrain access based on tags.\n"
        )

        return manual_check(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            message=message,
            prompt=(
                "Are permissions defined according to user groups and "
                "attributes?"
            ),
            pass_message=(
                "Permissions are defined according to user groups and "
                "attributes"
            ),
            fail_message=(
                "Permissions should be defined according to user groups and "
                "attributes"
            ),
            default=True,
        )

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking IAM permissions: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_employ_user_groups_and_attributes._CHECK_ID = CHECK_ID
check_employ_user_groups_and_attributes._CHECK_NAME = CHECK_NAME
