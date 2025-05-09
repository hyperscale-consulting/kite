"""Redshift service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class RedshiftCluster:
    """Redshift cluster data class."""

    cluster_id: str
    region: str


def get_clusters(session, region: str) -> List[RedshiftCluster]:
    """
    Get all Redshift clusters in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of Redshift clusters
    """
    redshift_client = session.client("redshift", region_name=region)
    clusters = []

    response = redshift_client.describe_clusters()
    for cluster in response.get("Clusters", []):
        clusters.append(
            RedshiftCluster(
                cluster_id=cluster.get("ClusterIdentifier"),
                region=region,
            )
        )

    return clusters
