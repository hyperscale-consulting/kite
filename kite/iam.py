"""IAM module for Kite."""

import csv
import io
import time
from typing import Dict, Any, List
from botocore.exceptions import ClientError


def fetch_credentials_report(session) -> Dict[str, Any]:
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
                    raise ClientError(
                        {
                            "Error": {
                                "Code": "Timeout",
                                "Message": "Report generation timed out",
                            }
                        },
                        "get_credential_report",
                    )
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


def fetch_organization_features(session) -> List[str]:
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


def fetch_account_summary(session) -> Dict[str, Any]:
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


def fetch_virtual_mfa_devices(session) -> List[Dict[str, Any]]:
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
    paginator = iam_client.get_paginator('list_virtual_mfa_devices')

    for page in paginator.paginate():
        virtual_mfa_devices.extend(page.get("VirtualMFADevices", []))

    return virtual_mfa_devices


def list_saml_providers(session) -> List[Dict[str, Any]]:
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

    try:
        response = iam_client.list_saml_providers()
        return response.get("SAMLProviderList", [])
    except ClientError:
        # If the API call fails, raise the exception
        raise


def list_oidc_providers(session) -> List[Dict[str, Any]]:
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

    try:
        response = iam_client.list_open_id_connect_providers()
        providers = response.get("OpenIDConnectProviderList", [])

        # Get detailed information for each provider
        detailed_providers = []
        for provider in providers:
            try:
                provider_info = iam_client.get_open_id_connect_provider(
                    OpenIDConnectProviderArn=provider["Arn"]
                )
                detailed_providers.append({
                    "Arn": provider["Arn"],
                    "CreateDate": provider.get("CreateDate"),
                    "Url": provider_info.get("Url"),
                    "ClientIDList": provider_info.get("ClientIDList", []),
                    "ThumbprintList": provider_info.get("ThumbprintList", [])
                })
            except ClientError:
                # If we can't get detailed info for a provider, just include basic info
                detailed_providers.append({
                    "Arn": provider["Arn"],
                    "CreateDate": provider.get("CreateDate")
                })

        return detailed_providers
    except ClientError:
        # If the API call fails, raise the exception
        raise


def get_password_policy(session) -> Dict[str, Any]:
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
            return None
        raise


def get_role_attached_policies(session, role_name: str) -> List[Dict[str, Any]]:
    """
    Get all attached managed policies for an IAM role.

    Args:
        session: The boto3 session to use.
        role_name: The name of the IAM role.

    Returns:
        List of dictionaries containing attached policy information.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")
    policies = []
    paginator = iam_client.get_paginator('list_attached_role_policies')

    for page in paginator.paginate(RoleName=role_name):
        policies.extend(page.get("AttachedPolicies", []))

    return policies


def get_role_inline_policy_document(session, role_name: str, policy_name: str) -> Dict[str, Any]:
    """
    Get the policy document for an inline policy attached to a role.

    Args:
        session: The boto3 session to use.
        role_name: The name of the IAM role.
        policy_name: The name of the inline policy.

    Returns:
        Dict containing the policy document.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    response = iam_client.get_role_policy(
        RoleName=role_name,
        PolicyName=policy_name
    )
    return {
        "PolicyName": policy_name,
        "RoleName": role_name,
        "PolicyDocument": response.get("PolicyDocument", {})
    }


def get_role_inline_policies(session, role_name: str) -> List[str]:
    """
    Get all inline policy names for an IAM role.

    Args:
        session: The boto3 session to use.
        role_name: The name of the IAM role.

    Returns:
        List of inline policy names.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")
    policy_names = []
    paginator = iam_client.get_paginator('list_role_policies')

    for page in paginator.paginate(RoleName=role_name):
        policy_names.extend(page.get("PolicyNames", []))

    return policy_names


def list_roles(session) -> List[Dict[str, Any]]:
    """
    List all IAM roles in the account with their attached and inline policies.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing role information, including:
        - RoleName: The name of the role
        - RoleId: The ID of the role
        - Arn: The Amazon Resource Name (ARN) of the role
        - Path: The path to the role
        - AssumeRolePolicyDocument: The trust policy document for assuming the role
        - CreateDate: The date and time when the role was created
        - MaxSessionDuration: The maximum session duration in seconds
        - PermissionsBoundary: The ARN of the policy used as permissions boundary
        - Tags: The list of tags attached to the role
        - AttachedPolicies: List of attached managed policies
        - InlinePolicyNames: List of inline policy names

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")
    roles = []
    paginator = iam_client.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page.get("Roles", []):
            # Get attached policies for the role
            try:
                attached_policies = get_role_attached_policies(
                    session, role["RoleName"]
                )
                role["AttachedPolicies"] = attached_policies
            except ClientError:
                role["AttachedPolicies"] = []

            # Get inline policy names for the role
            try:
                inline_policy_names = get_role_inline_policies(
                    session, role["RoleName"]
                )
                role["InlinePolicyNames"] = inline_policy_names
            except ClientError:
                role["InlinePolicyNames"] = []

            roles.append(role)

    return roles


def list_customer_managed_policies(session) -> List[Dict[str, Any]]:
    """
    List all customer managed policies in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing policy information, including:
        - PolicyName: The name of the policy
        - PolicyId: The ID of the policy
        - Arn: The Amazon Resource Name (ARN) of the policy
        - Path: The path to the policy
        - DefaultVersionId: The ID of the default version of the policy
        - AttachmentCount: The number of entities (users, groups, roles) to which the policy is attached
        - CreateDate: The date and time when the policy was created
        - UpdateDate: The date and time when the policy was last updated
        - Description: The description of the policy

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")
    policies = []
    paginator = iam_client.get_paginator('list_policies')

    # Only list customer managed policies (Scope=Local)
    for page in paginator.paginate(Scope='Local'):
        policies.extend(page.get("Policies", []))

    return policies


def get_policy_and_document(session, policy_arn: str) -> Dict[str, Any]:
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
    iam_client = session.client("iam")

    # Get policy details, including the default version ID
    policy_details = iam_client.get_policy(PolicyArn=policy_arn)
    policy = policy_details.get("Policy", {})

    # Get the policy document
    version_id = policy.get("DefaultVersionId")
    if version_id:
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        policy_document = policy_version.get("PolicyVersion", {}).get("Document", {})
    else:
        policy_document = {}

    return {
        "PolicyDetails": policy,
        "PolicyDocument": policy_document
    }


def list_users(session) -> List[Dict[str, Any]]:
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
            for group in iam_client.list_groups_for_user(
                UserName=user["UserName"]
            )["Groups"]:
                groups.append(group["GroupName"])

            # Get user's policies
            attached_policies = []
            paginator = iam_client.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user["UserName"]):
                attached_policies.extend(page.get("AttachedPolicies", []))

            # Get user's inline policies
            inline_policies = []
            paginator = iam_client.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user["UserName"]):
                inline_policies.extend(page.get("PolicyNames", []))

            users.append({
                "UserName": user["UserName"],
                "Arn": user["Arn"],
                "CreateDate": user["CreateDate"],
                "Groups": groups,
                "AttachedPolicies": attached_policies,
                "InlinePolicyNames": inline_policies
            })

    return users


def list_groups(session) -> List[Dict[str, Any]]:
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
    for page in paginator.paginate():
        for group in page["Groups"]:
            # Get group's policies
            attached_policies = []
            paginator = iam_client.get_paginator("list_attached_group_policies")
            for page in paginator.paginate(GroupName=group["GroupName"]):
                attached_policies.extend(page.get("AttachedPolicies", []))

            # Get group's inline policies
            inline_policies = []
            paginator = iam_client.get_paginator("list_group_policies")
            for page in paginator.paginate(GroupName=group["GroupName"]):
                inline_policies.extend(page.get("PolicyNames", []))

            groups.append({
                "Arn": group["Arn"],
                "Name": group["GroupName"],
                "CreateDate": group["CreateDate"],
                "AttachedPolicies": attached_policies,
                "InlinePolicyNames": inline_policies
            })

    return groups
