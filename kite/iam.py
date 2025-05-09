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


def fetch_root_virtual_mfa_device(session) -> str:
    """
    Fetch the virtual MFA device for the root user.

    Args:
        session: The boto3 session to use.

    Returns:
        The serial number of the root user's virtual MFA device, or None if not found.

    Raises:
        ClientError: If the IAM API call fails.
    """
    iam_client = session.client("iam")

    try:
        response = iam_client.list_virtual_mfa_devices()

        # Iterate through virtual MFA devices looking for root user
        for device in response.get("VirtualMFADevices", []):
            if "User" in device and "Arn" in device["User"]:
                if "root" in device["User"]["Arn"]:
                    return device.get("SerialNumber")

        # No virtual MFA device found for root user
        return None
    except ClientError:
        # If the API call fails, raise the exception
        raise


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
