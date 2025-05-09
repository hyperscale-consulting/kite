"""Secrets Manager module for Kite."""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional
from botocore.exceptions import ClientError


@dataclass
class SecretDetails:
    """Details of a secret in AWS Secrets Manager."""
    name: str
    description: Optional[str]
    last_accessed_date: Optional[datetime]
    last_changed_date: Optional[datetime]
    resource_policy: Optional[str]
    tags: List[Dict[str, str]]
    version_ids_to_stages: Dict[str, List[str]]
    created_date: datetime
    arn: str


def fetch_secrets(session, region: Optional[str] = None) -> List[SecretDetails]:
    """
    Fetch all secrets from AWS Secrets Manager, including their resource policies.

    Args:
        session: The boto3 session to use.
        region: Optional AWS region name. If not specified, uses the session's default region.

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
                    resource_policy = None
                else:
                    raise

            # Create a SecretDetails object
            secret_details = SecretDetails(
                name=secret["Name"],
                description=secret.get("Description"),
                last_accessed_date=secret.get("LastAccessedDate"),
                last_changed_date=secret.get("LastChangedDate"),
                resource_policy=resource_policy,
                tags=secret.get("Tags", []),
                version_ids_to_stages=secret.get("VersionIdsToStages", {}),
                created_date=secret["CreatedDate"],
                arn=secret["ARN"]
            )
            secrets.append(secret_details)

    return secrets
