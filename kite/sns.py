import json
from typing import Any


def get_topics(session, region: str) -> list[dict[str, Any]]:
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
        topic["Policy"] = policy_dict
        topics.append(topic)

    return topics
