"""ECS service module for Kite."""

from typing import List, Dict, Any
import boto3


def get_clusters(session: boto3.Session, region: str) -> List[str]:
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
    paginator = ecs_client.get_paginator("list_clusters")
    for page in paginator.paginate():
        for cluster_arn in page.get("clusterArns", []):
            cluster = get_cluster(ecs_client, cluster_arn)
            cluster["services"] = get_services(ecs_client, cluster_arn)
            clusters.append(cluster)

    return clusters


def get_cluster(client: boto3.client, name: str) -> Dict[str, Any]:
    """
    Get an ECS cluster by name.
    """
    return client.describe_clusters(clusters=[name])["clusters"][0]


def get_services(client: boto3.client, cluster_arn: str) -> List[str]:
    """
    Get all services in an ECS cluster.
    """
    paginator = client.get_paginator("list_services")
    services = []
    for page in paginator.paginate(cluster=cluster_arn):
        for service_arn in page.get("serviceArns", []):
            service = get_service(client, service_arn, cluster_arn)
            services.append(service)
    return services


def get_service(client: boto3.client, service_arn: str, cluster_arn: str) -> Dict[str, Any]:
    """
    Get an ECS service by ARN.
    """
    return client.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
