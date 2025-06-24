from typing import List, Dict, Any

import boto3


def get_action_targets(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
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
    except (
        client.exceptions.InvalidAccessException,
        client.exceptions.ResourceNotFoundException,
    ):
        return []


def get_automation_rules(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
    """
    Get the automation rules for a given region.

    Args:
        session: The session to use for the API call.
        region: The region to get the automation rules for.
    """
    try:
        client = session.client("securityhub", region_name=region)
        response = client.list_automation_rules()
        return response["AutomationRulesMetadata"]
    except (
        client.exceptions.InvalidAccessException,
        client.exceptions.ResourceNotFoundException,
    ):
        return []
