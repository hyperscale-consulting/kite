"""ECS service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class ECSCluster:
    """ECS cluster data class."""

    cluster_arn: str
    region: str


def get_clusters(session, region: str) -> List[ECSCluster]:
    """
    Get all ECS clusters in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of ECS clusters
    """
    ecs_client = session.client("ecs", region_name=region)
    clusters = []

    response = ecs_client.list_clusters()
    for cluster_arn in response.get("clusterArns", []):
        clusters.append(
            ECSCluster(
                cluster_arn=cluster_arn,
                region=region,
            )
        )

    return clusters
