"""SNS service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class SNSTopic:
    """SNS topic data class."""

    topic_arn: str
    region: str


def get_topics(session, region: str) -> List[SNSTopic]:
    """
    Get all SNS topics in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of SNS topics
    """
    sns_client = session.client("sns", region_name=region)
    topics = []

    response = sns_client.list_topics()
    for topic in response.get("Topics", []):
        topics.append(
            SNSTopic(
                topic_arn=topic.get("TopicArn"),
                region=region,
            )
        )

    return topics
