"""SQS service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class SQSQueue:
    """SQS queue data class."""

    queue_url: str
    region: str


def get_queues(session, region: str) -> List[SQSQueue]:
    """
    Get all SQS queues in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of SQS queues
    """
    sqs_client = session.client("sqs", region_name=region)
    queues = []

    response = sqs_client.list_queues()
    for queue_url in response.get("QueueUrls", []):
        queues.append(
            SQSQueue(
                queue_url=queue_url,
                region=region,
            )
        )

    return queues
