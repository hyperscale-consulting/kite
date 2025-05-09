"""Identity Store module for Kite."""

from botocore.exceptions import ClientError


def is_identity_store_used(session) -> bool:
    """
    Check if the Identity Store is being used by attempting to list users.

    Args:
        session: The boto3 session to use.

    Returns:
        bool: True if the Identity Store is being used (has users), False otherwise.

    Raises:
        ClientError: If the Identity Store API call fails.
    """
    identity_store_client = session.client("identitystore")
    sso_admin_client = session.client("sso-admin")

    try:
        # Try to list users - if we get any response, the store is being used
        identity_store_id = sso_admin_client.list_instances()["Instances"][0][
            "IdentityStoreId"
        ]
        response = identity_store_client.list_users(
            IdentityStoreId=identity_store_id,
            MaxResults=1,  # We only need to know if there are any users
        )
        return bool(response.get("Users", []))
    except ClientError as e:
        # If we get a ResourceNotFoundException, the store is not being used
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
