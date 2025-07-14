"""SNS service module for Kite."""

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class SNSTopic:
    """SNS topic data class."""

    topic_arn: str
    region: str
    policy: dict[str, Any] | None = None


def get_topics(session, region: str) -> list[SNSTopic]:
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
        topic_arn = topic.get("TopicArn")

        attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
        policy = attributes.get("Attributes", {}).get("Policy")
        policy_dict = json.loads(policy) if policy else None

        topics.append(
            SNSTopic(
                topic_arn=topic_arn,
                region=region,
                policy=policy_dict,
            )
        )

    return topics
