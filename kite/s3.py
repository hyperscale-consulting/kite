"""S3 service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class S3Bucket:
    """S3 bucket data class."""

    bucket_name: str


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
        buckets.append(
            S3Bucket(
                bucket_name=bucket.get("Name"),
            )
        )

    return buckets
