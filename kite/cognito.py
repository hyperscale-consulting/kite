"""Cognito module for Kite."""

from typing import Dict, Any, List
from botocore.exceptions import ClientError


def list_user_pools(session) -> List[Dict[str, Any]]:
    """
    List all Cognito user pools in the account.

    Args:
        session: The boto3 session to use.

    Returns:
        List of dictionaries containing user pool information.

    Raises:
        ClientError: If the Cognito API call fails.
    """
    cognito_client = session.client("cognito-idp")

    try:
        response = cognito_client.list_user_pools(MaxResults=60)
        return response.get("UserPools", [])
    except ClientError:
        raise


def fetch_cognito_user_pool(session, user_pool_id: str) -> Dict[str, Any]:
    """
    Describe a Cognito user pool.
    """
    cognito_client = session.client("cognito-idp")
    return cognito_client.describe_user_pool(UserPoolId=user_pool_id).get(
        "UserPool", {}
    )
