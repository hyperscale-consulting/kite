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
