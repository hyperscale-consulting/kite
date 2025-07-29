from typing import Any

import boto3


def get_clusters(session: boto3.Session, region: str) -> list[str]:
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
            cluster = _get_cluster(ecs_client, cluster_arn)
            cluster["services"] = _get_services(ecs_client, cluster_arn)
            clusters.append(cluster)

    return clusters


def _get_cluster(client, name) -> dict[str, Any]:
    return client.describe_clusters(clusters=[name])["clusters"][0]


def _get_services(client, cluster_arn: str) -> list[str]:
    paginator = client.get_paginator("list_services")
    services = []
    for page in paginator.paginate(cluster=cluster_arn):
        for service_arn in page.get("serviceArns", []):
            service = _get_service(client, service_arn, cluster_arn)
            services.append(service)
    return services


def _get_service(client, service_arn: str, cluster_arn: str) -> dict[str, Any]:
    return client.describe_services(cluster=cluster_arn, services=[service_arn])[
        "services"
    ][0]
