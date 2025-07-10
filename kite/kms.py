import json

import boto3


def get_keys(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all KMS keys and their policies in the specified region.

    Args:
        session: A boto3 session with credentials for the target account
        region: The AWS region

    Returns:
        List of dictionaries containing key information and policies
    """
    kms = session.client("kms", region_name=region)
    keys = []

    # List all keys
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            key_id = key["KeyId"]

            # Get the key policy
            policy = kms.get_key_policy(KeyId=key_id, PolicyName="default")
            policy = json.loads(policy["Policy"])

            rotation_status = {}
            rotation_status_response = kms.get_key_rotation_status(KeyId=key_id)
            rotation_status = dict(
                RotationEnabled=rotation_status_response["KeyRotationEnabled"],
                RotationPeriodInDays=rotation_status_response.get(
                    "RotationPeriodInDays", None
                ),
            )

            details = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            details["Policy"] = policy
            details["RotationStatus"] = rotation_status
            keys.append(details)
    return keys


def get_custom_key_stores(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    """
    Get all custom key stores in the specified region.

    Args:
        session: A boto3 session with credentials for the target account
        region: The AWS region
    """
    kms = session.client("kms", region_name=region)
    custom_key_stores = []

    paginator = kms.get_paginator("describe_custom_key_stores")
    for page in paginator.paginate():
        for store in page["CustomKeyStores"]:
            custom_key_stores.append(store)

    return custom_key_stores
