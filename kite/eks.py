"""EKS service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class EKSCluster:
    """EKS cluster data class."""

    cluster_name: str
    region: str


def get_clusters(session, region: str) -> List[EKSCluster]:
    """
    Get all EKS clusters in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of EKS clusters
    """
    eks_client = session.client("eks", region_name=region)
    clusters = []

    response = eks_client.list_clusters()
    for cluster_name in response.get("clusters", []):
        clusters.append(
            EKSCluster(
                cluster_name=cluster_name,
                region=region,
            )
        )

    return clusters
