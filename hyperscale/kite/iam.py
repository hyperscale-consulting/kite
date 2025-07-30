"""IAM module for Kite."""

import csv
import io
import time
from typing import Any

from botocore.exceptions import ClientError


def fetch_credentials_report(session) -> dict[str, Any]:
    """
    Fetch the IAM credentials report.

    Args:
        session: The boto3 session to use.

    Returns:
        Dict containing the credentials report data, with root account information
        separated from user accounts.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    # Generate the credentials report
    try:
        iam_client.generate_credential_report()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ReportInProgress":
            raise

    # Wait for the report to be ready (with timeout)
    max_attempts = 10
    attempt = 0
    while attempt < max_attempts:
        try:
            response = iam_client.get_credential_report()
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "ReportInProgress":
                attempt += 1
                if attempt < max_attempts:
                    # Wait 5 seconds before trying again
                    time.sleep(5)
                else:
                    raise TimeoutError(
                        "Credential report generation timed out"
                    ) from None
            else:
                raise

    # Parse the CSV report
    report_csv = response["Content"].decode("utf-8")
    report_reader = csv.DictReader(io.StringIO(report_csv))

    # Separate root account from user accounts
    root_account = None
    user_accounts = []

    for row in report_reader:
        if row["user"] == "<root_account>":
            root_account = row
        else:
            user_accounts.append(row)

    # Return the report data
    return {"root": root_account, "users": user_accounts}


def fetch_organization_features(session) -> list[str]:
    """
    Fetch the IAM organization features.

    Args:
        session: The boto3 session to use.

    Returns:
        List of enabled organization features.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    try:
        response = iam_client.list_organizations_features()
        return response.get("EnabledFeatures", [])
    except ClientError as e:
        # If Organizations is not in use, return an empty list
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return []
        raise


def fetch_account_summary(session) -> dict[str, Any]:
    """
    Fetch the IAM account summary.

    Args:
        session: The boto3 session to use.

    Returns:
        Dict containing the account summary data, including quotas and current
        usage for various IAM resources.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    try:
        response = iam_client.get_account_summary()
        return response.get("SummaryMap", {})
    except ClientError:
        # If the API call fails, raise the exception
        raise


def fetch_virtual_mfa_devices(session) -> list[dict[str, Any]]:
    """
    Fetch all virtual MFA devices in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing virtual MFA device information, including:
        - SerialNumber: The serial number of the virtual MFA device
        - User: The IAM user associated with the virtual MFA device
        - EnableDate: The date and time when the virtual MFA device was enabled

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")
    virtual_mfa_devices = []
    paginator = iam_client.get_paginator("list_virtual_mfa_devices")

    for page in paginator.paginate():
        virtual_mfa_devices.extend(page.get("VirtualMFADevices", []))

    return virtual_mfa_devices


def list_saml_providers(session) -> list[dict[str, Any]]:
    """
    List all SAML providers in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing SAML provider information, including:
        - Arn: The Amazon Resource Name (ARN) of the SAML provider
        - ValidUntil: The expiration date and time for the SAML provider
        - CreateDate: The date and time when the SAML provider was created

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    response = iam_client.list_saml_providers()
    return response.get("SAMLProviderList", [])


def list_oidc_providers(session) -> list[dict[str, Any]]:
    """
    List all OpenID Connect (OIDC) providers in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing OIDC provider information, including:
        - Arn: The Amazon Resource Name (ARN) of the OIDC provider
        - CreateDate: The date and time when the OIDC provider was created
        - Url: The URL of the OIDC provider
        - ClientIDList: The list of client IDs associated with the OIDC provider
        - ThumbprintList: The list of thumbprints associated with the OIDC provider

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    response = iam_client.list_open_id_connect_providers()
    providers = response.get("OpenIDConnectProviderList", [])

    # Get detailed information for each provider
    detailed_providers = []
    for provider in providers:
        try:
            provider_info = iam_client.get_open_id_connect_provider(
                OpenIDConnectProviderArn=provider["Arn"]
            )
            detailed_providers.append(
                {
                    "Arn": provider["Arn"],
                    "CreateDate": provider.get("CreateDate"),
                    "Url": provider_info.get("Url"),
                    "ClientIDList": provider_info.get("ClientIDList", []),
                    "ThumbprintList": provider_info.get("ThumbprintList", []),
                }
            )
        except ClientError:
            # If we can't get detailed info for a provider, just include basic info
            detailed_providers.append(
                {"Arn": provider["Arn"], "CreateDate": provider.get("CreateDate")}
            )

    return detailed_providers


def get_password_policy(session) -> dict[str, Any]:
    """
    Fetch the IAM password policy for the account.

    Args:
        session: The boto3 session to use.

    Returns:
        Dict containing the password policy settings, including:
        - MinimumPasswordLength: The minimum number of characters allowed in a password
        - RequireSymbols: Whether passwords must include symbols
        - RequireNumbers: Whether passwords must include numbers
        - RequireUppercaseCharacters: Whether passwords must include uppercase letters
        - RequireLowercaseCharacters: Whether passwords must include lowercase letters
        - AllowUsersToChangePassword: Whether users can change their own passwords
        - ExpirePasswords: Whether passwords expire
        - PasswordReusePrevention: The number of previous passwords to prevent reuse

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    try:
        response = iam_client.get_account_password_policy()
        return response.get("PasswordPolicy", {})
    except ClientError as e:
        # If no password policy exists, return None
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return {}
        raise


def _get_role_attached_policies(client, role_name: str) -> list[dict[str, Any]]:
    policies = []
    paginator = client.get_paginator("list_attached_role_policies")

    for page in paginator.paginate(RoleName=role_name):
        policies.extend(page.get("AttachedPolicies", []))

    return policies


def _get_role_inline_policy_document(
    client, role_name: str, policy_name: str
) -> dict[str, Any]:
    response = client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    return response.get("PolicyDocument", {})


def _get_role_inline_policies(client, role_name: str) -> list[str]:
    policy_names = []
    paginator = client.get_paginator("list_role_policies")

    for page in paginator.paginate(RoleName=role_name):
        policy_names.extend(page.get("PolicyNames", []))

    return policy_names


def get_roles(session) -> list[dict[str, Any]]:
    """
    Get all IAM roles in the account with their attached and inline policies.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing role information.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")
    roles = []
    paginator = iam_client.get_paginator("list_roles")

    for page in paginator.paginate():
        for role in page.get("Roles", []):
            # Get attached policies for the role
            try:
                attached_policies = _get_role_attached_policies(
                    iam_client, role["RoleName"]
                )
                role["AttachedPolicies"] = attached_policies
            except ClientError:
                role["AttachedPolicies"] = []

            # Get inline policy names for the role
            try:
                inline_policy_names = _get_role_inline_policies(
                    iam_client, role["RoleName"]
                )
                inline_policies = []
                for policy_name in inline_policy_names:
                    doc = _get_role_inline_policy_document(
                        iam_client, role["RoleName"], policy_name
                    )
                    inline_policies.append(
                        {
                            "PolicyName": policy_name,
                            "PolicyDocument": doc,
                        }
                    )
                role["InlinePolicies"] = inline_policies
            except ClientError:
                role["InlinePolicies"] = []

            roles.append(role)

    return roles


def get_customer_managed_policies(session) -> list[dict[str, Any]]:
    """
    Get all customer managed policies in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing policy information.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")
    policies = []
    paginator = iam_client.get_paginator("list_policies")

    # Only list customer managed policies (Scope=Local)
    for page in paginator.paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            policy["PolicyDocument"] = _get_policy_document(iam_client, policy["Arn"])
            policies.append(policy)

    return policies


def _get_policy_document(client, policy_arn: str) -> dict[str, Any]:
    """
    Get policy details and the policy document for a customer managed policy.

    Args:
        session: The boto3 session to use.
        policy_arn: The ARN of the customer managed policy.

    Returns:
        Dict containing the policy details and policy document.

    Raises:
        ClientError: If the IAM API call fails.
    """

    # Get policy details, including the default version ID
    policy_details = client.get_policy(PolicyArn=policy_arn)
    policy = policy_details.get("Policy", {})

    # Get the policy document
    version_id = policy.get("DefaultVersionId")
    if version_id:
        policy_version = client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        policy_document = policy_version.get("PolicyVersion", {}).get("Document", {})
    else:
        policy_document = {}

    policy["PolicyDocument"] = policy_document
    return policy


def list_users(session) -> list[dict[str, Any]]:
    """
    List all IAM users in the account with their groups, policies, and inline policies.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing user information
    """
    iam_client = session.client("iam")
    users = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            # Get user's groups
            groups = []
            for group in iam_client.list_groups_for_user(UserName=user["UserName"])[
                "Groups"
            ]:
                groups.append(group["GroupName"])
            user["Groups"] = groups

            # Get user's policies
            attached_policies = []
            paginator = iam_client.get_paginator("list_attached_user_policies")
            for attached_user_policy_page in paginator.paginate(
                UserName=user["UserName"]
            ):
                attached_policies.extend(
                    attached_user_policy_page.get("AttachedPolicies", [])
                )
            user["AttachedPolicies"] = attached_policies

            # Get user's inline policies
            inline_policies = []
            paginator = iam_client.get_paginator("list_user_policies")
            for user_policy_page in paginator.paginate(UserName=user["UserName"]):
                for policy_name in user_policy_page.get("PolicyNames", []):
                    doc = _get_user_inline_policy_document(
                        iam_client, user["UserName"], policy_name
                    )
                    inline_policies.append(
                        {
                            "PolicyName": policy_name,
                            "PolicyDocument": doc,
                        }
                    )
            user["InlinePolicies"] = inline_policies
            users.append(user)

    return users


def _get_user_inline_policy_document(
    client, user_name: str, policy_name: str
) -> dict[str, Any]:
    response = client.get_user_policy(UserName=user_name, PolicyName=policy_name)
    return response.get("PolicyDocument", {})


def list_groups(session) -> list[dict[str, Any]]:
    """
    List all IAM groups in the account with their attached policies.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing group information,
    """
    iam_client = session.client("iam")
    groups = []
    paginator = iam_client.get_paginator("list_groups")
    for group_page in paginator.paginate():
        for group in group_page["Groups"]:
            # Get group's policies
            attached_policies = []
            paginator = iam_client.get_paginator("list_attached_group_policies")
            for agp_page in paginator.paginate(GroupName=group["GroupName"]):
                attached_policies.extend(agp_page.get("AttachedPolicies", []))

            # Get group's inline policies
            inline_policies = []
            paginator = iam_client.get_paginator("list_group_policies")
            for gp_page in paginator.paginate(GroupName=group["GroupName"]):
                for policy_name in gp_page.get("PolicyNames", []):
                    doc = _get_group_inline_policy_document(
                        iam_client, group["GroupName"], policy_name
                    )
                    inline_policies.append(
                        {
                            "PolicyName": policy_name,
                            "PolicyDocument": doc,
                        }
                    )
            group["AttachedPolicies"] = attached_policies
            group["InlinePolicies"] = inline_policies
            groups.append(group)

    return groups


def _get_group_inline_policy_document(
    client, group_name: str, policy_name: str
) -> dict[str, Any]:
    response = client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
    return response.get("PolicyDocument", {})
