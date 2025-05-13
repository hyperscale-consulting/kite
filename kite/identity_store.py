"""Identity Store module for Kite."""


def has_users(session, identity_store_id: str) -> bool:
    """
    Check if the Identity Store has users.
    """
    identity_store_client = session.client("identitystore")
    response = identity_store_client.list_users(
        IdentityStoreId=identity_store_id,
        MaxResults=1,  # We only need to know if there are any users
    )
    return bool(response.get("Users", []))
