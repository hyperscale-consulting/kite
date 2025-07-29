from dataclasses import dataclass

from botocore.exceptions import ClientError


@dataclass
class RedshiftCluster:
    """Redshift cluster data class."""

    cluster_id: str
    region: str


def get_clusters(session, region: str) -> list[RedshiftCluster]:
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

    try:
        response = redshift_client.describe_clusters()
        for cluster in response.get("Clusters", []):
            clusters.append(
                RedshiftCluster(
                    cluster_id=cluster.get("ClusterIdentifier"),
                    region=region,
                )
            )
    except ClientError as e:
        if e.response["Error"]["Code"] == "OptInRequired":
            return []
        else:
            raise e

    return clusters
