"""AWS SQS functionality module."""

import json
from typing import Dict, Any, List

import boto3


def get_queues(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
    """
    Get all SQS queues and their policies in the specified region.

    Args:
        session: A boto3 session with credentials for the target account
        region: The AWS region

    Returns:
        List of dictionaries containing queue information and policies
    """
    sqs = session.client("sqs", region_name=region)
    queues = []

    # List all queues
    response = sqs.list_queues()
    queue_urls = response.get("QueueUrls", [])

    # Get attributes for each queue
    for queue_url in queue_urls:
        attributes = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn", "Policy"]
        )

        queue_arn = attributes["Attributes"]["QueueArn"]
        policy = attributes["Attributes"].get("Policy")

        if policy:
            policy = json.loads(policy)

        queues.append({
            "queue_url": queue_url,
            "queue_arn": queue_arn,
            "policy": policy,
            "region": region,
        })

    return queues
