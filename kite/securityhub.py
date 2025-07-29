from typing import Any

import boto3
from botocore.exceptions import ClientError


def get_action_targets(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """
    Get the action targets for a given region.

    Args:
        session: The session to use for the API call.
        region: The region to get the action targets for.
    """
    try:
        client = session.client("securityhub", region_name=region)
        paginator = client.get_paginator("describe_action_targets")
        action_targets = []
        for page in paginator.paginate():
            action_targets.extend(page["ActionTargets"])
        return action_targets
    except ClientError as e:
        if e.response["Error"]["Code"] == "SubscriptionRequiredException":
            return []
        raise e


def get_automation_rules(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """
    Get the automation rules for a given region.

    Args:
        session: The session to use for the API call.
        region: The region to get the automation rules for.
    """
    try:
        client = session.client("securityhub", region_name=region)
        return client.list_automation_rules().get("AutomationRulesMetadata", [])
    except ClientError as e:
        if e.response["Error"]["Code"] == "SubscriptionRequiredException":
            return []
        raise e
