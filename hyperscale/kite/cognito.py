from typing import Any


def get_user_pools(session, region: str) -> list[dict[str, Any]]:
    """
    Get all Cognito user pools.

    Args:
        session: The boto3 session to use.
        region: The region to get the user pools from.
    Returns:
        List of dictionaries containing user pool information.

    Raises:
        ClientError: If the Cognito API call fails.
    """
    cognito_client = session.client("cognito-idp", region_name=region)

    paginator = cognito_client.get_paginator("list_user_pools")
    user_pools = []
    for page in paginator.paginate(MaxResults=60):
        for user_pool in page.get("UserPools", []):
            details = _get_user_pool(cognito_client, user_pool["Id"])
            user_pools.append(details)
    return user_pools


def _get_user_pool(cognito_client, user_pool_id: str) -> dict[str, Any]:
    return cognito_client.describe_user_pool(UserPoolId=user_pool_id).get(
        "UserPool", {}
    )
