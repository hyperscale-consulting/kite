from typing import Any

from botocore.exceptions import ClientError


def fetch_secrets(session, region: str | None = None) -> list[dict[str, Any]]:
    """
    Fetch all secrets from AWS Secrets Manager, including their resource policies.

    Args:
        session: The boto3 session to use.
        region: Optional AWS region name. If not specified, uses the session's default
        region.

    Returns:
        List of SecretDetails objects containing secret details and resource policies.

    Raises:
        ClientError: If the Secrets Manager API calls fail.
    """
    secrets_client = session.client("secretsmanager", region_name=region)
    secrets = []

    # Get all secrets
    paginator = secrets_client.get_paginator("list_secrets")
    for page in paginator.paginate():
        for secret in page["SecretList"]:
            # Get the resource policy for this secret
            try:
                policy_response = secrets_client.get_resource_policy(
                    SecretId=secret["ARN"]
                )
                resource_policy = policy_response.get("ResourcePolicy")
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    # No resource policy exists
                    resource_policy = {}
                else:
                    raise
            secret["ResourcePolicy"] = resource_policy
            secrets.append(secret)

    return secrets
