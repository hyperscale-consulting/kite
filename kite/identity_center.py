"""Identity Center module for Kite."""

from botocore.exceptions import ClientError


def is_identity_center_used(session) -> bool:
    """
    Check if AWS Identity Center is being used in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        bool: True if Identity Center is being used, False otherwise.

    Raises:
        ClientError: If the Identity Center API call fails.
    """
    sso_client = session.client("sso-admin")

    try:
        # List all instances of Identity Center
        response = sso_client.list_instances()
        return len(response.get("Instances", [])) > 0
    except ClientError as e:
        # If the error is that Identity Center is not enabled, return False
        if e.response["Error"]["Code"] == "AccessDeniedException":
            return False
        # For any other error, raise the exception
        raise
