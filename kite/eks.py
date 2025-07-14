"""EKS service module for Kite."""

from typing import Any


def get_cluster_names(session, region: str) -> list[str]:
    """
    Get all EKS cluster names in a region.
    """
    eks_client = session.client("eks", region_name=region)
    paginator = eks_client.get_paginator("list_clusters")
    clusters = []
    for page in paginator.paginate():
        clusters.extend(page.get("clusters", []))
    return clusters


def get_clusters(session, region: str) -> list[dict[str, Any]]:
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
    for name in get_cluster_names(session, region):
        response = eks_client.describe_cluster(name=name)
        clusters.append(response["cluster"])

    return clusters
