"""Identity Center module for Kite."""

from botocore.exceptions import ClientError


def list_identity_center_instances(session) -> list:
    """
    List all instances of Identity Center.

    Args:
        session: The boto3 session to use.

    Returns:
        list: List of Identity Center instances.

    Raises:
        ClientError: If the API call fails.
    """
    sso_client = session.client("sso-admin")
    instances = []
    paginator = sso_client.get_paginator("list_instances")

    for page in paginator.paginate():
        instances.extend(page.get("Instances", []))

    return instances


def is_identity_center_used(session) -> bool:
    """
    Check if AWS Identity Center is being used in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        bool: True if Identity Center is being used, False otherwise.

    Raises:
        ClientError: If the API calls fail.
    """
    # First check if the account is part of an organization
    orgs_client = session.client("organizations")
    try:
        orgs_client.describe_organization()
    except ClientError as e:
        if e.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
            return False
        raise

    return len(list_identity_center_instances(session)) > 0
