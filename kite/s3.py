"""S3 service module for Kite."""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from botocore.exceptions import ClientError


@dataclass
class S3Bucket:
    """S3 bucket data class."""

    bucket_name: str
    policy: Optional[Dict[str, Any]] = None


def get_buckets(session) -> List[S3Bucket]:
    """
    Get all S3 buckets.

    Args:
        session: The boto3 session to use

    Returns:
        List of S3 buckets
    """
    s3_client = session.client("s3")
    buckets = []

    response = s3_client.list_buckets()
    for bucket in response.get("Buckets", []):
        bucket_name = bucket.get("Name")
        # Get bucket policy
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = policy_response.get("Policy")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                policy = None
            else:
                raise

        buckets.append(
            S3Bucket(
                bucket_name=bucket_name,
                policy=policy,
            )
        )

    return buckets
