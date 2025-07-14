"""S3 service module for Kite."""

from typing import Any

from botocore.exceptions import ClientError


def get_bucket_names(session) -> list[dict[str, Any]]:
    """
    Get all S3 bucket names.
    """
    s3_client = session.client("s3")
    paginator = s3_client.get_paginator("list_buckets")
    page_iterator = paginator.paginate()
    return [
        bucket.get("Name")
        for page in page_iterator
        for bucket in page.get("Buckets", [])
    ]


def get_buckets(session) -> list[dict[str, Any]]:
    """
    Get all S3 buckets.

    Args:
        session: The boto3 session to use

    Returns:
        List of S3 buckets
    """
    s3_client = session.client("s3")
    buckets = []

    paginator = s3_client.get_paginator("list_buckets")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for bucket in page.get("Buckets", []):
            bucket_name = bucket.get("Name")
            # Get bucket policy
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = policy_response.get("Policy")
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    policy = None
                else:
                    raise e
            bucket["Policy"] = policy

            # Get lifecycle configuration
            try:
                lifecycle_response = s3_client.get_bucket_lifecycle(Bucket=bucket_name)
                lifecycle_rules = lifecycle_response.get("Rules")
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                    lifecycle_rules = None
                else:
                    raise e
            bucket["LifecycleRules"] = lifecycle_rules

            # Get versioning configuration
            versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_configuration = versioning_response.get("Status")
            bucket["Versioning"] = versioning_configuration

            # Get logging configuration
            logging_response = s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_configuration = logging_response.get("LoggingEnabled")
            bucket["Logging"] = logging_configuration

            # Get object lock configuration
            try:
                object_lock_response = s3_client.get_object_lock_configuration(
                    Bucket=bucket_name
                )
                object_lock_configuration = object_lock_response.get(
                    "ObjectLockConfiguration"
                )
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ObjectLockConfigurationNotFoundError"
                ):
                    object_lock_configuration = None
                else:
                    raise e
            bucket["ObjectLockConfiguration"] = object_lock_configuration

            buckets.append(bucket)

    return buckets
