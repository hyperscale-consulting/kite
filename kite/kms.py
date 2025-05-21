"""AWS KMS functionality module."""

import json
from typing import Dict, Any, List

import boto3


def get_keys(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
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

            keys.append({
                "key_id": key_id,
                "key_arn": key["KeyArn"],
                "policy": policy,
                "description": key.get("Description", "No description")
            })

    return keys
