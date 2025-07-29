"""Identity Store module for Kite."""

from typing import Any


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


def get_users(session, identity_store_id: str) -> list[dict[str, Any]]:
    """
    Get all users from the Identity Store.
    """
    identity_store_client = session.client("identitystore")
    users = []
    paginator = identity_store_client.get_paginator("list_users")
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for user in page["Users"]:
            # Get user's groups
            groups = []
            group_paginator = identity_store_client.get_paginator(
                "list_group_memberships_for_member"
            )
            for group_page in group_paginator.paginate(
                IdentityStoreId=identity_store_id, MemberId={"UserId": user["UserId"]}
            ):
                groups.extend(group_page["GroupMemberships"])

            user["Groups"] = groups
            users.append(user)

    return users


def get_groups(session, identity_store_id: str) -> list[dict[str, Any]]:
    """
    Get all groups from the Identity Store.
    """
    identity_store_client = session.client("identitystore")
    groups = []
    paginator = identity_store_client.get_paginator("list_groups")
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        groups.extend(page["Groups"])

    return groups
